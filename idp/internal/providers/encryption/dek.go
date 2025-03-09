package encryption

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const dekLocation string = "dek"

func generateDEK(keyID string, key []byte) ([]byte, string, error) {
	base64DEK, err := utils.GenerateBase64Secret(32)
	if err != nil {
		return nil, "", err
	}

	encryptedDEK, err := utils.Encrypt(base64DEK, key)
	if err != nil {
		return nil, "", err
	}

	dek, err := utils.DecodeBase64Secret(base64DEK)
	if err != nil {
		return nil, "", err
	}

	return dek, fmt.Sprintf("%s:%s", keyID, encryptedDEK), nil
}

func splitDEK(encryptedDEK string) (string, string, error) {
	dekSlice := strings.Split(encryptedDEK, ":")
	if len(dekSlice) != 2 {
		return "", "", errors.New("invalid DEK")
	}

	return dekSlice[0], dekSlice[1], nil
}

type decryptDEKOptions struct {
	storedDEK  string
	secret     *Secret
	oldSecrets map[string][]byte
}

func decryptDEK(
	logger *slog.Logger,
	ctx context.Context,
	opts decryptDEKOptions,
) ([]byte, bool, error) {
	dekID, encryptedDEK, err := splitDEK(opts.storedDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to split DEK", "error", err)
		return nil, false, err
	}

	key := opts.secret.key
	oldKey := dekID != opts.secret.kid
	if oldKey {
		var ok bool
		key, ok = opts.oldSecrets[dekID]
		if !ok {
			logger.ErrorContext(ctx, "DEK key ID not found")
			return nil, false, errors.New("secret key not found")
		}
	}

	base64DEK, err := utils.Decrypt(encryptedDEK, key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
		return nil, false, err
	}

	dek, err := utils.DecodeBase64Secret(base64DEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode DEK", "error", err)
		return nil, false, err
	}

	return dek, oldKey, nil
}

func reEncryptDEK(isOldKey bool, dek, key []byte) (string, error) {
	if !isOldKey {
		return "", nil
	}

	return utils.Encrypt(base64.RawURLEncoding.EncodeToString(dek), key)
}

func (e *Encryption) decryptAccountDEK(ctx context.Context, requestID, storedDEK string) ([]byte, bool, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "decryptAccountDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Decrypting Account DEK...")
	return decryptDEK(logger, ctx, decryptDEKOptions{
		storedDEK:  storedDEK,
		secret:     &e.accountSecretKey,
		oldSecrets: e.oldSecrets,
	})
}

func (e *Encryption) decryptAppDEK(ctx context.Context, requestID, storedDEK string) ([]byte, bool, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "decryptAppDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Decrypting App DEK...")
	return decryptDEK(logger, ctx, decryptDEKOptions{
		storedDEK:  storedDEK,
		secret:     &e.appSecretKey,
		oldSecrets: e.oldSecrets,
	})
}

func (e *Encryption) decryptUserDEK(ctx context.Context, requestID, storedDEK string) ([]byte, bool, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "decryptUserDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Decrypting User DEK...")
	return decryptDEK(logger, ctx, decryptDEKOptions{
		storedDEK:  storedDEK,
		secret:     &e.userSecretKey,
		oldSecrets: e.oldSecrets,
	})
}
