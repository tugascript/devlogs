package services

import (
	"context"

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

	accountKeys, err := s.database.CreateAccountKeys(ctx, database.CreateAccountKeysParams{
		ClientID:     clientID,
		ClientSecret: hashedSecret,
		AccountID:    opts.AccountID,
		Scopes:       opts.Scopes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account keys", "error", err)
		return dtos.AccountKeysDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account keys created successfully")
	return dtos.MapAccountKeysToDTOWithSecret(&accountKeys, clientSecret), nil
}

type GetAccountKeysByIDOptions struct {
	RequestID string
	ClientID  string
}

func (s *Services) GetAccountKeysByID(
	ctx context.Context,
	opts GetAccountKeysByIDOptions,
) (dtos.AccountKeysDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountKeysLocation, "GetAccountKeysByID").With(
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Getting account keys by id...")

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

	logger.InfoContext(ctx, "Got account keys by id successfully")
	return dtos.MapAccountKeysToDTO(&accountKeys), nil
}
