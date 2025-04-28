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

const totpsManagementLocation string = "totps_management"

func generateBaseTotpKey(backendDomain, subDomain, email string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      fmt.Sprintf("%s%s", subDomain, backendDomain),
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

func formatRecoveryCode(code string) string {
	var parts []string
	for i := 0; i < len(code); i += 4 {
		end := i + 4
		if end > len(code) {
			end = len(code)
		}
		parts = append(parts, code[i:end])
	}
	return strings.Join(parts, "-")
}

func generateRecoveryCodes() (string, []byte, error) {
	codes := make([]string, 8)
	hashedCodes := make(map[string]bool)

	for i := range codes {
		code, err := utils.GenerateBase32Secret(7)
		if err != nil {
			return "", nil, err
		}

		code = fmt.Sprintf("%012s", code)
		hashedCode, err := utils.BcryptHashString(code)
		if err != nil {
			return "", nil, err
		}

		codes[i] = formatRecoveryCode(code)
		hashedCodes[hashedCode] = false
	}

	codesJson, err := json.Marshal(hashedCodes)
	if err != nil {
		return "", nil, err
	}

	return strings.Join(codes, "\n"), codesJson, nil
}

type TotpKey struct {
	url             string
	img             string
	codes           string
	hashedCodes     []byte
	encryptedDEK    string
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

func (t *TotpKey) EncryptedDEK() string {
	return t.encryptedDEK
}

func (t *TotpKey) EncryptedSecret() string {
	return t.encryptedSecret
}

type generateTotpKeyOptions struct {
	secretKID     string
	secretKey     []byte
	email         string
	backendDomain string
	subDomain     string
}

func generateTotpKey(
	logger *slog.Logger,
	ctx context.Context,
	opts generateTotpKeyOptions,
) (TotpKey, error) {
	key, err := generateBaseTotpKey(opts.backendDomain, opts.subDomain, opts.email)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate TOP key", "error", err)
		return TotpKey{}, err
	}

	img64, err := base64EncodeKeyQRCode(key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encode key QR code", "error", err)
		return TotpKey{}, err
	}

	codes, hashedCodes, err := generateRecoveryCodes()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate recovery codes", "error", err)
		return TotpKey{}, err
	}

	dek, encryptedDEK, err := generateDEK(opts.secretKID, opts.secretKey)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate DEK", "error", err)
		return TotpKey{}, err
	}

	secret, err := utils.Encrypt(key.Secret(), dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt secret", "error", err)
		return TotpKey{}, err
	}

	return TotpKey{
		url:             key.URL(),
		img:             img64,
		codes:           codes,
		hashedCodes:     hashedCodes,
		encryptedDEK:    encryptedDEK,
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

type GenerateAccountTotpKeyOptions struct {
	RequestID string
	Email     string
}

func (e *Encryption) GenerateAccountTotpKey(
	ctx context.Context,
	opts GenerateAccountTotpKeyOptions,
) (TotpKey, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  totpsManagementLocation,
		Method:    "GenerateAccountTotpKey",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generate account TOTP key...")
	return generateTotpKey(logger, ctx, generateTotpKeyOptions{
		secretKID:     e.appSecretKey.kid,
		secretKey:     e.accountSecretKey.key,
		email:         opts.Email,
		backendDomain: e.backendDomain,
		subDomain:     "",
	})
}

type VerifyAccountTotpCodeOptions struct {
	RequestID       string
	EncryptedSecret string
	StoredDEK       string
	Code            string
}

func (e *Encryption) VerifyAccountTotpCode(
	ctx context.Context,
	opts VerifyAccountTotpCodeOptions,
) (bool, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  totpsManagementLocation,
		Method:    "VerifyAccountTotpCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying account TOTP code...")
	dek, isOldKey, err := e.decryptAccountDEK(ctx, opts.RequestID, opts.StoredDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
		return false, "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.appSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to re-encrypt DEK", "error", err)
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
