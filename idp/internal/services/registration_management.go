package services

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

// Keep every client mutation and its registration state in the same transaction.
func registrationTransaction[T any](
	s *Services,
	ctx context.Context,
	requestID string,
	fn func(queries *database.Queries) (T, *exceptions.ServiceError),
) (T, *exceptions.ServiceError) {
	logger := s.buildLogger(requestID, "registration", "registrationTransaction")
	logger.InfoContext(ctx, "Starting registration transaction")

	var zero T
	var serviceErr *exceptions.ServiceError

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return zero, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	result, serviceErr := fn(qrs)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to execute transaction function", "serviceError", serviceErr)
		return zero, serviceErr
	}

	logger.DebugContext(ctx, "Transaction function executed successfully")
	return result, nil
}

func registrationLookupError(err error) *exceptions.ServiceError {
	if errors.Is(err, pgx.ErrNoRows) {
		return exceptions.NewError(exceptions.OAuthErrorInvalidToken, "client not found")
	}
	return exceptions.FromDBError(err)
}

func registrationVerificationError(err error) *exceptions.ServiceError {
	var serviceErr *exceptions.ServiceError
	if errors.As(err, &serviceErr) {
		return serviceErr
	}
	return exceptions.NewError(exceptions.OAuthErrorInvalidToken, "invalid registration token")
}

func validateRegistrationID(stored pgtype.UUID, presented string, hasExpiry bool) error {
	if !stored.Valid {
		if !hasExpiry {
			return exceptions.NewError(exceptions.OAuthErrorInvalidToken, "legacy token requires expiration")
		}
		return nil
	}
	id, err := uuid.Parse(presented)
	if err != nil || id.Version() != 7 || id != uuid.UUID(stored.Bytes) {
		return exceptions.NewError(exceptions.OAuthErrorInvalidToken, "registration token has been superseded")
	}
	return nil
}

func (s *Services) registrationTokenValidator(ctx context.Context, app bool) func(string, tokens.AccountClaims, string, bool) error {
	return func(clientID string, account tokens.AccountClaims, jti string, hasExpiry bool) error {
		var stored pgtype.UUID
		if app {
			row, err := s.database.FindAppByClientIDAndAccountPublicID(ctx, database.FindAppByClientIDAndAccountPublicIDParams{ClientID: clientID, AccountPublicID: account.AccountID})
			if err != nil {
				return registrationLookupError(err)
			}
			stored = row.RegistrationTokenJti
		} else {
			row, err := s.database.FindAccountCredentialsByAccountPublicIDAndClientID(ctx, database.FindAccountCredentialsByAccountPublicIDAndClientIDParams{ClientID: clientID, AccountPublicID: account.AccountID})
			if err != nil {
				return registrationLookupError(err)
			}
			stored = row.RegistrationTokenJti
		}
		return validateRegistrationID(stored, jti, hasExpiry)
	}
}

// Bypass the JWK cache for registration authentication: explicit revocation must
// take effect immediately. Signing-key expiry does not retire verification keys.
func (s *Services) registrationPublicKey(ctx context.Context, accountID int32) tokens.GetPublicJWK {
	return func(kid string, suite utils.SupportedCryptoSuite) (utils.JWK, error) {
		var row database.TokenSigningKey
		var err error
		usage := database.TokenKeyUsageGlobal
		if accountID == 0 {
			row, err = s.database.FindTokenSigningKeyByKID(ctx, kid)
		} else {
			usage = database.TokenKeyUsageAccount
			row, err = s.database.FindAccountTokenSigningKeyByAccountIDAndKID(ctx, database.FindAccountTokenSigningKeyByAccountIDAndKIDParams{AccountID: accountID, Kid: kid})
		}
		if err != nil {
			return nil, registrationLookupError(err)
		}
		if row.IsRevoked || row.Usage != usage || row.KeyType != database.TokenKeyTypeDynamicRegistration || string(row.CryptoSuite) != string(suite) {
			return nil, exceptions.NewUnauthorizedError()
		}
		key, err := utils.JsonToJWK(row.PublicKey)
		if err != nil {
			return nil, exceptions.NewInternalServerError()
		}
		return key, nil
	}
}

type registrationStateOptions struct {
	RequestID, ClientID, BackendDomain, HostUsername, Token, Statement string
	AccountPublicID                                                    uuid.UUID
	AccountID, AccountVersion, ID                                      int32
	Stored                                                             pgtype.UUID
	App                                                                bool
}

// Call with the client row locked (or freshly inserted). Reauthenticate after
// locking so concurrent legacy upgrades cannot both succeed.
func (s *Services) registrationResponseToken(ctx context.Context, o registrationStateOptions) (string, *exceptions.ServiceError) {
	if o.Token != "" {
		var serviceErr *exceptions.ServiceError
		var clientID string
		var account tokens.AccountClaims
		if o.App {
			clientID, account, serviceErr = s.ProcessAppDynamicRegistrationAccessToken(ctx, ProcessAppDynamicRegistrationAccessTokenOptions{RequestID: o.RequestID, AuthHeader: "Bearer " + o.Token, AccountID: o.AccountID, IssuerDomain: dynamicRegistrationIssuerDomain(o.HostUsername, o.BackendDomain)})
		} else {
			clientID, account, serviceErr = s.ProcessAccountCredentialsRegistrationAccessToken(ctx, ProcessAccountCredentialsRegistrationAccessTokenOptions{RequestID: o.RequestID, AuthHeader: "Bearer " + o.Token, IssuerDomain: o.BackendDomain})
		}
		if serviceErr != nil {
			return "", serviceErr
		}
		if clientID != o.ClientID || account.AccountID != o.AccountPublicID {
			return "", exceptions.NewError(exceptions.OAuthErrorInvalidToken, "registration token binding mismatch")
		}
	} else if o.Stored.Valid {
		return "", exceptions.NewError(exceptions.OAuthErrorInvalidToken, "missing registration token")
	}
	token := o.Token
	jti := o.Stored
	if !jti.Valid {
		id, err := uuid.NewV7()
		if err != nil {
			return "", exceptions.NewInternalServerError()
		}
		jti = pgtype.UUID{Bytes: id, Valid: true}
		var serviceErr *exceptions.ServiceError
		if o.App {
			token, serviceErr = s.CreateAppCredentialsRegistrationAccessToken(ctx, CreateAppCredentialsRegistrationAccessTokenOptions{RequestID: o.RequestID, AccountPublicID: o.AccountPublicID, AccountVersion: o.AccountVersion, ClientID: o.ClientID, BackendDomain: o.BackendDomain, JTI: id})
		} else {
			token, serviceErr = s.CreateAccountCredentialsRegistrationAccessToken(ctx, CreateAccountCredentialsRegistrationAccessTokenOptions{RequestID: o.RequestID, AccountPublicID: o.AccountPublicID, AccountVersion: o.AccountVersion, ClientID: o.ClientID, BackendDomain: o.BackendDomain, JTI: id})
		}
		if serviceErr != nil {
			return "", serviceErr
		}
	}
	var err error
	if o.App {
		err = s.database.SetAppRegistrationState(ctx, database.SetAppRegistrationStateParams{ID: o.ID, RegistrationTokenJti: jti, SoftwareStatement: o.Statement})
	} else {
		err = s.database.SetAccountCredentialsRegistrationState(ctx, database.SetAccountCredentialsRegistrationStateParams{ID: o.ID, RegistrationTokenJti: jti, SoftwareStatement: o.Statement})
	}
	if err != nil {
		return "", exceptions.FromDBError(err)
	}
	return token, nil
}
