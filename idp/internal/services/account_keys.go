package services

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountKeysLocation string = "account_keys"

	accountSecretBytes int = 32
)

func mapAndEncodeAccountScopes(
	logger *slog.Logger,
	ctx context.Context,
	scopes []tokens.AccountScope,
) ([]byte, *exceptions.ServiceError) {
	scopesMap := make(map[string]bool)
	for _, s := range scopes {
		scopesMap[s] = true
	}

	scopesJson, err := json.Marshal(scopesMap)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal the scopes map", "error", err)
		return nil, exceptions.NewServerError()
	}

	return scopesJson, nil
}

type CreateAccountKeysOptions struct {
	RequestID string
	AccountID int32
	Scopes    []tokens.AccountScope
}

func (s *Services) CreateAccountKeys(
	ctx context.Context,
	opts CreateAccountKeysOptions,
) (dtos.AccountKeysDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountKeysLocation, "CreateAccountKeys").With(
		"accountId", opts.AccountID,
		"scopes", opts.Scopes,
	)
	logger.InfoContext(ctx, "Creating account keys...")

	clientID, err := utils.Base62UUID()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client id", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.NewServerError()
	}

	clientSecret, err := utils.GenerateBase64Secret(accountSecretBytes)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client secret", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.NewServerError()
	}

	hashedSecret, err := utils.HashString(clientSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash client secret", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.NewServerError()
	}

	scopesJson, serviceErr := mapAndEncodeAccountScopes(logger, ctx, opts.Scopes)
	if serviceErr != nil {
		return dtos.AccountKeysDTO{}, serviceErr
	}

	accountKeys, err := s.database.CreateAccountKeys(ctx, database.CreateAccountKeysParams{
		ClientID:     clientID,
		ClientSecret: hashedSecret,
		AccountID:    opts.AccountID,
		Scopes:       scopesJson,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account keys", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account keys created successfully")
	return dtos.MapAccountKeysToDTOWithSecret(&accountKeys, clientSecret)
}

type GetAccountKeysByClientIDOptions struct {
	RequestID string
	ClientID  string
}

func (s *Services) GetAccountKeysByClientID(
	ctx context.Context,
	opts GetAccountKeysByClientIDOptions,
) (dtos.AccountKeysDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountKeysLocation, "GetAccountKeysByClientID").With(
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Getting account keys by client id...")

	accountKeys, err := s.database.FindAccountKeysByClientID(ctx, opts.ClientID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account keys not found", "error", err)
			return dtos.AccountKeysDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account keys", "error", err)
		return dtos.AccountKeysDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account keys by client id successfully")
	return dtos.MapAccountKeysToDTO(&accountKeys)
}

type GetAccountKeysByClientIDAndAccountIDOptions struct {
	RequestID string
	AccountID int
	ClientID  string
}

func (s *Services) GetAccountKeysByClientIDAndAccountID(
	ctx context.Context,
	opts GetAccountKeysByClientIDAndAccountIDOptions,
) (dtos.AccountKeysDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountKeysLocation, "GetAccountKeysByClientIDAndAccountID").With(
		"clientId", opts.ClientID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting account keys by client id and account id...")

	accountKeysDTO, serviceErr := s.GetAccountKeysByClientID(ctx, GetAccountKeysByClientIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ClientID,
	})
	if serviceErr != nil {
		return dtos.AccountKeysDTO{}, serviceErr
	}

	akAccountID := accountKeysDTO.AccountID()
	if akAccountID != opts.AccountID {
		logger.WarnContext(ctx, "Account keys is not owned by the account",
			"accountKeysAccountId", akAccountID,
		)
		return dtos.AccountKeysDTO{}, exceptions.NewNotFoundError()
	}

	logger.InfoContext(ctx, "Got account keys by client id and account id successfully")
	return accountKeysDTO, nil
}

type ListAccountKeyByAccountID struct {
	RequestID string
	AccountID int
	Offset    int
	Limit     int
}

func (s *Services) ListAccountKeysByAccountID(
	ctx context.Context,
	opts ListAccountKeyByAccountID,
) ([]dtos.AccountKeysDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountKeysLocation, "ListAccountKeysByAccountID").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Listing account keys by account id...")

	accountID := int32(opts.AccountID)
	accountKeys, err := s.database.FindPaginatedAccountKeysByAccountID(
		ctx,
		database.FindPaginatedAccountKeysByAccountIDParams{
			AccountID: accountID,
			Offset:    int32(opts.Offset),
			Limit:     int32(opts.Limit),
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to list account keys", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	count, err := s.database.CountAccountKeysByAccountID(ctx, accountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account keys", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	accountKeysDTOs, serviceErr := utils.MapSliceWithErr(accountKeys, dtos.MapAccountKeysToDTO)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map account keys to DTOs", "error", serviceErr)
		return nil, 0, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Successfully listed account keys by account id")
	return accountKeysDTOs, count, nil
}

type UpdateAccountKeysSecretOptions struct {
	RequestID string
	AccountID int
	ClientID  string
}

func (s *Services) UpdateAccountKeysSecret(
	ctx context.Context,
	opts UpdateAccountKeysSecretOptions,
) (dtos.AccountKeysDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountKeysLocation, "UpdateAccountKeysSecret").With(
		"clientId", opts.ClientID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Updating account keys secret...")

	accountKeysDTO, serviceErr := s.GetAccountKeysByClientIDAndAccountID(
		ctx,
		GetAccountKeysByClientIDAndAccountIDOptions(opts),
	)
	if serviceErr != nil {
		return dtos.AccountKeysDTO{}, serviceErr
	}

	clientSecret, err := utils.GenerateBase64Secret(accountSecretBytes)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client secret", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.NewServerError()
	}

	hashedSecret, err := utils.HashString(clientSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash client secret", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.NewServerError()
	}

	accountKeys, err := s.database.UpdateAccountKeysClientSecret(ctx, database.UpdateAccountKeysClientSecretParams{
		ClientSecret: hashedSecret,
		ClientID:     accountKeysDTO.ClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account keys secret", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Successfully updated account keys secret")
	return dtos.MapAccountKeysToDTOWithSecret(&accountKeys, clientSecret)
}

type UpdateAccountKeysScopesOptions struct {
	RequestID string
	AccountID int
	ClientID  string
	Scopes    []tokens.AccountScope
}

func (s *Services) UpdateAccountKeysScopes(
	ctx context.Context,
	opts UpdateAccountKeysScopesOptions,
) (dtos.AccountKeysDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountKeysLocation, "UpdateAccountKeysScopes").With(
		"clientId", opts.ClientID,
		"accountId", opts.AccountID,
		"scopes", opts.Scopes,
	)
	logger.InfoContext(ctx, "Updating account keys scopes...")

	accountKeysDTO, serviceErr := s.GetAccountKeysByClientIDAndAccountID(
		ctx,
		GetAccountKeysByClientIDAndAccountIDOptions{
			RequestID: opts.RequestID,
			AccountID: opts.AccountID,
			ClientID:  opts.ClientID,
		},
	)
	if serviceErr != nil {
		return dtos.AccountKeysDTO{}, serviceErr
	}

	scopesJson, serviceErr := mapAndEncodeAccountScopes(logger, ctx, opts.Scopes)
	if serviceErr != nil {
		return dtos.AccountKeysDTO{}, serviceErr
	}

	accountKeys, err := s.database.UpdateAccountKeysScope(ctx, database.UpdateAccountKeysScopeParams{
		Scopes:   scopesJson,
		ClientID: accountKeysDTO.ClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account keys scopes", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.FromDBError(err)
	}

	return dtos.MapAccountKeysToDTO(&accountKeys)
}

type DeleteAccountKeysOptions struct {
	RequestID string
	AccountID int
	ClientID  string
}

func (s *Services) DeleteAccountKeys(ctx context.Context, opts DeleteAccountKeysOptions) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountKeysLocation, "DeleteAccountKeys").With(
		"clientId", opts.ClientID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Deleting account keys...")

	accountKeysDTO, serviceErr := s.GetAccountKeysByClientIDAndAccountID(
		ctx,
		GetAccountKeysByClientIDAndAccountIDOptions(opts),
	)
	if serviceErr != nil {
		return serviceErr
	}

	if err := s.database.DeleteAccountKeys(ctx, accountKeysDTO.ClientID); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account keys", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Successfully deleted account keys")
	return nil
}
