// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"log/slog"
	"strconv"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	totpLocation string = "totp"

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
	url   string
	img   string
	codes string
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

type StoreTOTP = func(dekKID, encSecret string, hashedCode []byte, url string) *exceptions.ServiceError

type generateTotpKeyOptions struct {
	requestID   string
	issuer      string
	email       string
	getEncDEKfn GetDEKtoEncrypt
	storeTOTPfn StoreTOTP
	hashedCodes map[string]recoveryCode
}

func (e *Crypto) generateTotpKey(
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

	dekID, secret, serviceErr := e.EncryptWithDEK(
		ctx,
		EncryptWithDEKOptions{
			RequestID: opts.requestID,
			GetDEKfn:  opts.getEncDEKfn,
			PlainText: key.Secret(),
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to encrypt TOTP secret", "error", serviceErr)
		return TotpKey{}, serviceErr
	}

	if opts.hashedCodes != nil && !isHashCodesFullyUsed(opts.hashedCodes) {
		logger.DebugContext(ctx, "Using provided hashed codes")
		jsonCodes, err := json.Marshal(opts.hashedCodes)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to marshal hashed codes", "error", err)
			return TotpKey{}, err
		}

		if serviceErr := opts.storeTOTPfn(dekID, secret, jsonCodes, key.URL()); serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to store TOTP", "error", serviceErr)
			return TotpKey{}, serviceErr
		}

		return TotpKey{
			url: key.URL(),
			img: img64,
		}, nil

	}

	codes, jsonCodes, err := generateRecoveryCodes()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate recovery codes", "error", err)
		return TotpKey{}, err
	}

	if serviceErr := opts.storeTOTPfn(dekID, secret, jsonCodes, key.URL()); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to store TOTP with recovery codes", "error", serviceErr)
		return TotpKey{}, serviceErr
	}

	return TotpKey{
		url:   key.URL(),
		img:   img64,
		codes: codes,
	}, err
}

type GenerateTotpKeyOptions struct {
	RequestID   string
	Email       string
	Issuer      string
	GetDEKfn    GetDEKtoEncrypt
	StoreTOTPfn StoreTOTP
}

func (e *Crypto) GenerateTotpKey(
	ctx context.Context,
	opts GenerateTotpKeyOptions,
) (TotpKey, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  totpLocation,
		Method:    "GenerateTotpKey",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generate TOTP key...")

	issuer := opts.Issuer
	if issuer == "" {
		issuer = e.serviceName
	}

	return e.generateTotpKey(logger, ctx, generateTotpKeyOptions{
		requestID:   opts.RequestID,
		issuer:      issuer,
		email:       opts.Email,
		getEncDEKfn: opts.GetDEKfn,
		storeTOTPfn: opts.StoreTOTPfn,
		hashedCodes: nil,
	})
}

type GetTOTPSecret = func(ownerID int32) (DEKCiphertext, *exceptions.ServiceError)

type VerifyTotpCodeOptions struct {
	RequestID       string
	Code            string
	OwnerID         int32
	GetSecret       GetTOTPSecret
	GetDecryptDEKFN GetDEKtoDecrypt
	GetEncryptDEKFN GetDEKtoEncrypt
	StoreFN         StoreReEncryptedData
}

func (e *Crypto) VerifyTotpCode(
	ctx context.Context,
	opts VerifyTotpCodeOptions,
) (bool, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  totpLocation,
		Method:    "VerifyTotpCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying account TOTP code...")

	encSecret, serviceErr := opts.GetSecret(opts.OwnerID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get TOTP secret", "error", serviceErr)
		return false, serviceErr
	}

	secret, serviceErr := e.DecryptWithDEK(
		ctx,
		DecryptWithDEKOptions{
			RequestID:              opts.RequestID,
			GetDecryptDEKfn:        opts.GetDecryptDEKFN,
			GetEncryptDEKfn:        opts.GetEncryptDEKFN,
			Ciphertext:             encSecret,
			EntityID:               strconv.Itoa(int(opts.OwnerID)),
			StoreReEncryptedDataFn: opts.StoreFN,
		},
	)

	return totp.Validate(opts.Code, secret), nil
}

type GetTOTPRecoveryCodes = func(ownerID int32) ([]byte, *exceptions.ServiceError)

type VerifyTotpRecoveryCodeOptions struct {
	RequestID    string
	Issuer       string
	Email        string
	RecoveryCode string
	OwnerID      int32
	GetCodes     GetTOTPRecoveryCodes
	GetDEKfn     GetDEKtoEncrypt
	StoreTOTPfn  StoreTOTP
}

func (e *Crypto) VerifyTotpRecoveryCode(
	ctx context.Context,
	opts VerifyTotpRecoveryCodeOptions,
) (bool, TotpKey, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  totpLocation,
		Method:    "VerifyTotpRecoveryCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying user TOTP recovery code...")

	hashedCodesJson, serviceErr := opts.GetCodes(opts.OwnerID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get TOTP recovery codes", "error", serviceErr)
		return false, TotpKey{}, serviceErr
	}

	hashedCodes := make(map[string]recoveryCode, recoveryCodesCount)
	if err := json.Unmarshal(hashedCodesJson, &hashedCodes); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal hashed codes", "error", err)
		return false, TotpKey{}, exceptions.NewServerError()
	}

	codeID := getRecoveryCodeID(opts.RecoveryCode)
	hashedCode, ok := hashedCodes[codeID]
	if !ok {
		logger.DebugContext(ctx, "Recovery code not found", "code_id", codeID)
		return false, TotpKey{}, nil
	}

	ok, err := utils.Argon2CompareHash(opts.RecoveryCode, hashedCode.HashedCode)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare hash", "error", err)
		return false, TotpKey{}, exceptions.NewServerError()
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
		requestID:   opts.RequestID,
		issuer:      issuer,
		email:       opts.Email,
		getEncDEKfn: opts.GetDEKfn,
		storeTOTPfn: opts.StoreTOTPfn,
		hashedCodes: hashedCodes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate TOTP key", "error", err)
		return false, TotpKey{}, exceptions.NewServerError()
	}

	return true, totpKey, nil
}
