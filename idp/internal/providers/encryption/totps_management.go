// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package encryption

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"log/slog"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

type TotpType string

const (
	totpsManagementLocation string = "totps_management"

	TotpTypeAccount TotpType = "account"
	TotpTypeUser    TotpType = "user"

	recoveryCodeBytesLength int = 10
	recoveryCodesCount      int = 8
	chunkSize               int = 4
	reLoopCountMax          int = 4
)

func generateBaseTotpKey(issuer, email string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

func base64EncodeKeyQRCode(key *otp.Key) (string, error) {
	img, err := key.Image(200, 200)
	if err != nil {
		return "", err
	}

	var imgBuf bytes.Buffer
	if err := jpeg.Encode(&imgBuf, img, &jpeg.Options{Quality: 90}); err != nil {
		return "", err
	}

	base64Img := base64.StdEncoding.EncodeToString(imgBuf.Bytes())
	return fmt.Sprintf("data:image/jpeg;base64,%s", base64Img), nil
}

type recoveryCode struct {
	HashedCode string `json:"hashed_code"`
	Used       bool   `json:"used"`
}

func formatRecoveryCode(code string) string {
	codeLen := len(code)

	parts := make([]string, 0, codeLen/chunkSize)
	for i := 0; i < codeLen; i += chunkSize {
		end := min(i+chunkSize, codeLen)
		parts = append(parts, code[i:end])
	}

	return strings.Join(parts, "-")
}

func generateRecoveryCode() (string, error) {
	code, err := utils.GenerateBase32Secret(recoveryCodeBytesLength)
	if err != nil {
		return "", err
	}

	return formatRecoveryCode(code), nil
}

func getRecoveryCodeID(code string) string {
	return utils.ExtractSecretID([]byte(code[:chunkSize]))
}

func generateRecoveryCodes() (string, []byte, error) {
	codes := make([]string, recoveryCodesCount)
	hashedCodes := make(map[string]recoveryCode, recoveryCodesCount)
	reLoopCount := 0

	for i := 0; i < recoveryCodesCount; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return "", nil, err
		}

		codeID := getRecoveryCodeID(code)
		if _, ok := hashedCodes[codeID]; ok {
			if reLoopCount == reLoopCountMax {
				return "", nil, fmt.Errorf("re-looping count reached max of %d", reLoopCountMax)
			}

			i--
			reLoopCount++
			continue
		}

		hashedCode, err := utils.Argon2HashString(code)
		if err != nil {
			return "", nil, err
		}

		hashedCodes[codeID] = recoveryCode{
			HashedCode: hashedCode,
			Used:       false,
		}
		codes[i] = code
	}

	codesJson, err := json.Marshal(hashedCodes)
	if err != nil {
		return "", nil, err
	}

	return strings.Join(codes, "\n"), codesJson, nil
}

func isHashCodesFullyUsed(
	hashedCodes map[string]recoveryCode,
) bool {
	count := 0

	for _, code := range hashedCodes {
		if code.Used {
			count++
		}
	}

	return count == len(hashedCodes)
}

type TotpKey struct {
	url             string
	img             string
	codes           string
	hashedCodes     []byte
	newDEK          string
	encryptedSecret string
}

func (t *TotpKey) URL() string {
	return t.url
}

func (t *TotpKey) Img() string {
	return t.img
}

func (t *TotpKey) Codes() string {
	return t.codes
}

func (t *TotpKey) HashedCodes() []byte {
	return t.hashedCodes
}

func (t *TotpKey) EncryptedSecret() string {
	return t.encryptedSecret
}

func (t *TotpKey) NewDEK() string {
	return t.newDEK
}

type generateTotpKeyOptions struct {
	requestID   string
	email       string
	issuer      string
	dek         string
	totpType    TotpType
	hashedCodes map[string]recoveryCode
}

func (e *Encryption) generateTotpKey(
	logger *slog.Logger,
	ctx context.Context,
	opts generateTotpKeyOptions,
) (TotpKey, error) {
	key, err := generateBaseTotpKey(opts.issuer, opts.email)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate TOP key", "error", err)
		return TotpKey{}, err
	}

	img64, err := base64EncodeKeyQRCode(key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encode key QR code", "error", err)
		return TotpKey{}, err
	}

	var dek []byte
	var isOld bool
	var newDEK string
	switch opts.totpType {
	case TotpTypeAccount:
		dek, isOld, err = e.decryptAccountDEK(ctx, opts.requestID, opts.dek)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
			return TotpKey{}, err
		}
		if isOld {
			newDEK, err = reEncryptDEK(isOld, dek, e.accountSecretKey.key)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to re-encrypt StoredDEK", "error", err)
				return TotpKey{}, err
			}
		}
	case TotpTypeUser:
		dek, isOld, err = e.decryptUserDEK(ctx, opts.requestID, opts.dek)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
			return TotpKey{}, err
		}
		if isOld {
			newDEK, err = reEncryptDEK(isOld, dek, e.userSecretKey.key)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to re-encrypt StoredDEK", "error", err)
				return TotpKey{}, err
			}
		}
	default:
		logger.ErrorContext(ctx, "Invalid TOTP type", "type", opts.totpType)
		return TotpKey{}, fmt.Errorf("invalid TOTP type: %s", opts.totpType)
	}

	secret, err := utils.Encrypt(key.Secret(), dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt secret", "error", err)
		return TotpKey{}, err
	}

	if opts.hashedCodes != nil && !isHashCodesFullyUsed(opts.hashedCodes) {
		logger.DebugContext(ctx, "Using provided hashed codes")
		hashedCodes, err := json.Marshal(opts.hashedCodes)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to marshal hashed codes", "error", err)
			return TotpKey{}, err
		}

		return TotpKey{
			url:             key.URL(),
			img:             img64,
			hashedCodes:     hashedCodes,
			newDEK:          newDEK,
			encryptedSecret: secret,
		}, nil

	}

	codes, hashedCodes, err := generateRecoveryCodes()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate recovery codes", "error", err)
		return TotpKey{}, err
	}

	return TotpKey{
		url:             key.URL(),
		img:             img64,
		codes:           codes,
		hashedCodes:     hashedCodes,
		newDEK:          newDEK,
		encryptedSecret: secret,
	}, err
}

type verifyTotpCodeOptions struct {
	dek             []byte
	encryptedSecret string
	code            string
}

func verifyTotpCode(
	logger *slog.Logger,
	ctx context.Context,
	opts verifyTotpCodeOptions,
) (bool, error) {
	secret, err := utils.Decrypt(opts.encryptedSecret, opts.dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt secret", "error", err)
		return false, err
	}

	return totp.Validate(opts.code, secret), nil
}

type GenerateTotpKeyOptions struct {
	RequestID string
	Email     string
	Issuer    string
	StoredDEK string
	TotpType  TotpType
}

func (e *Encryption) GenerateTotpKey(
	ctx context.Context,
	opts GenerateTotpKeyOptions,
) (TotpKey, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  totpsManagementLocation,
		Method:    "GenerateTotpKey",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generate TOTP key...")

	issuer := opts.Issuer
	if issuer == "" {
		issuer = e.serviceName
	}

	return e.generateTotpKey(logger, ctx, generateTotpKeyOptions{
		email:    opts.Email,
		issuer:   issuer,
		dek:      opts.StoredDEK,
		totpType: opts.TotpType,
	})
}

type ProcessTotpDEKOptions struct {
	RequestID string
	TotpType  TotpType
	StoredDEK string
}

func (e *Encryption) ProcessTotpDEK(
	ctx context.Context,
	opts ProcessTotpDEKOptions,
) ([]byte, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  totpsManagementLocation,
		Method:    "ProcessTotpDEK",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Processing TOTP DEK...")

	switch opts.TotpType {
	case TotpTypeAccount:
		dek, isOldKey, err := e.decryptAccountDEK(ctx, opts.RequestID, opts.StoredDEK)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
			return nil, "", err
		}
		newDEK, err := reEncryptDEK(isOldKey, dek, e.accountSecretKey.key)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to re-encrypt StoredDEK", "error", err)
			return nil, "", err
		}
		return dek, newDEK, nil
	case TotpTypeUser:
		dek, isOldKey, err := e.decryptUserDEK(ctx, opts.RequestID, opts.StoredDEK)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
			return nil, "", err
		}
		newDEK, err := reEncryptDEK(isOldKey, dek, e.userSecretKey.key)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to re-encrypt StoredDEK", "error", err)
			return nil, "", err
		}
		return dek, newDEK, nil
	default:
		logger.ErrorContext(ctx, "Invalid TOTP type", "type", opts.TotpType)
		return nil, "", fmt.Errorf("invalid TOTP type: %s", opts.TotpType)
	}
}

type VerifyAccountTotpCodeOptions struct {
	RequestID       string
	EncryptedSecret string
	StoredDEK       string
	Code            string
	TotpType        TotpType
}

func (e *Encryption) VerifyTotpCode(
	ctx context.Context,
	opts VerifyAccountTotpCodeOptions,
) (bool, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  totpsManagementLocation,
		Method:    "VerifyTotpCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying account TOTP code...")

	dek, newDEK, err := e.ProcessTotpDEK(ctx, ProcessTotpDEKOptions{
		RequestID: opts.RequestID,
		TotpType:  opts.TotpType,
		StoredDEK: opts.StoredDEK,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to process TOTP DEK", "error", err)
		return false, "", err
	}

	verified, err := verifyTotpCode(logger, ctx, verifyTotpCodeOptions{
		dek:             dek,
		encryptedSecret: opts.EncryptedSecret,
		code:            opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP code", "error", err)
		return false, "", err
	}

	return verified, newDEK, nil
}

type VerifyTotpRecoveryCodeOptions struct {
	RequestID   string
	RecoverCode string
	HashedCodes []byte
	StoredDEK   string
	Issuer      string
	Email       string
	TotpType    TotpType
}

func (e *Encryption) VerifyTotpRecoveryCode(
	ctx context.Context,
	opts VerifyTotpRecoveryCodeOptions,
) (bool, TotpKey, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  totpsManagementLocation,
		Method:    "VerifyTotpRecoveryCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying user TOTP recovery code...")

	hashedCodes := make(map[string]recoveryCode, recoveryCodesCount)
	if err := json.Unmarshal(opts.HashedCodes, &hashedCodes); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal hashed codes", "error", err)
		return false, TotpKey{}, err
	}

	codeID := getRecoveryCodeID(opts.RecoverCode)
	hashedCode, ok := hashedCodes[codeID]
	if !ok {
		logger.DebugContext(ctx, "Recovery code not found", "code_id", codeID)
		return false, TotpKey{}, nil
	}

	ok, err := utils.Argon2CompareHash(opts.RecoverCode, hashedCode.HashedCode)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare hash", "error", err)
		return false, TotpKey{}, err
	}
	if !ok {
		logger.DebugContext(ctx, "Recovery code does not match")
		return false, TotpKey{}, nil
	}
	if hashedCode.Used {
		logger.DebugContext(ctx, "Recovery code already used")
		return false, TotpKey{}, nil
	}

	hashedCode.Used = true
	hashedCodes[codeID] = hashedCode

	issuer := opts.Issuer
	if issuer == "" {
		issuer = e.serviceName
	}

	totpKey, err := e.generateTotpKey(logger, ctx, generateTotpKeyOptions{
		email:    opts.Email,
		issuer:   issuer,
		dek:      opts.StoredDEK,
		totpType: opts.TotpType,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate TOTP key", "error", err)
		return false, TotpKey{}, err
	}

	return true, totpKey, nil
}
