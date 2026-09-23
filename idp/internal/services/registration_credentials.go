package services

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
	"time"
)

func (s *Services) replaceRegistrationSecret(ctx context.Context, requestID string, accountID int32, publicID uuid.UUID, clientID int32, app bool) (string, time.Time, utils.JWK, *exceptions.ServiceError) {
	usage := database.CredentialsUsageAccount
	ttl := s.accountCCExpDays
	dek := s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{RequestID: requestID, Queries: s.database.Queries})
	if app {
		usage = database.CredentialsUsageApp
		ttl = s.appCCExpDays
		dek = s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{RequestID: requestID, AccountID: accountID})
	}
	id, secretID, secret, exp, serviceErr := s.clientCredentialsSecret(ctx, s.database.Queries, clientCredentialsSecretOptions{requestID: requestID, accountID: accountID, expiresIn: ttl, usage: usage, dekFN: dek})
	if serviceErr != nil {
		return "", time.Time{}, nil, serviceErr
	}
	var err error
	if app {
		err = s.database.CreateAppSecret(ctx, database.CreateAppSecretParams{AppID: clientID, AccountID: accountID, CredentialsSecretID: id})
	} else {
		err = s.database.CreateAccountCredentialSecret(ctx, database.CreateAccountCredentialSecretParams{AccountCredentialsID: clientID, AccountID: accountID, AccountPublicID: publicID, CredentialsSecretID: id, SecretID: secretID})
	}
	if err != nil {
		return "", time.Time{}, nil, exceptions.FromDBError(err)
	}
	return fmt.Sprintf("%s.%s", secretID, secret), exp, nil, nil
}

// Server-generated credential keys use the global DEK in clientCredentialsKey.
func (s *Services) registrationPrivateKey(ctx context.Context, requestID string, key database.CredentialsKey) (utils.JWK, *exceptions.ServiceError) {
	if key.IsExternal {
		return nil, nil
	}
	plaintext, serviceErr := s.crypto.DecryptWithDEK(ctx, crypto.DecryptWithDEKOptions{
		RequestID:       requestID,
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{RequestID: requestID}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{RequestID: requestID, Queries: s.database.Queries}),
		StoreReEncryptedDataFn: func(_ crypto.EntityID, dek crypto.DEKID, ciphertext crypto.DEKCiphertext) *exceptions.ServiceError {
			if err := s.database.UpdateCredentialsKeyPrivateKey(ctx, database.UpdateCredentialsKeyPrivateKeyParams{ID: key.ID, PrivateKey: ciphertext, DekKid: dek}); err != nil {
				return exceptions.FromDBError(err)
			}
			return nil
		}, EntityID: key.PublicKid, Ciphertext: key.PrivateKey,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	jwk, err := utils.JsonToJWK([]byte(plaintext))
	if err != nil {
		return nil, exceptions.NewInternalServerError()
	}
	if _, err = jwk.ToPrivateKey(); err != nil {
		return nil, exceptions.NewInternalServerError()
	}
	return jwk, nil
}
