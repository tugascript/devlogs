package services

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const accountsLocation string = "accounts"

type CreateAccountOptions struct {
	RequestID string
	FirstName string
	LastName  string
	Email     string
	Password  string
	Provider  string
}

func (s *Services) CreateAccount(
	ctx context.Context,
	opts CreateAccountOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "CreateAccount").With(
		"firstName", opts.FirstName,
		"lastName", opts.LastName,
		"provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Creating account...")

	var provider string
	var password pgtype.Text
	switch opts.Provider {
	case AuthProviderEmail:
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required for email auth provider")
			return dtos.AccountDTO{}, exceptions.NewValidationError("password is required")
		}

		hashedPassword, err := utils.HashString(opts.Password)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to hash password", "error", err)
			return dtos.AccountDTO{}, exceptions.NewServerError()
		}

		if err := password.Scan(hashedPassword); err != nil {
			logger.ErrorContext(ctx, "Failed pass password to text", "error", err)
			return dtos.AccountDTO{}, exceptions.NewServerError()
		}

		provider = AuthProviderEmail
	case AuthProviderApple, AuthProviderFacebook, AuthProviderGoogle, AuthProviderGitHub, AuthProviderMicrosoft:
		provider = opts.Provider
	default:
		logger.ErrorContext(ctx, "Provider must be 'email', 'apple', 'facebook', 'github', 'google' or 'microsoft'")
		return dtos.AccountDTO{}, exceptions.NewServerError()
	}

	email := utils.Lowered(opts.Email)
	if _, err := s.database.FindAccountByEmail(ctx, email); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account by email", "error", serviceErr)
			return dtos.AccountDTO{}, serviceErr
		}
	} else {
		logger.WarnContext(ctx, "Account already exists for given email")
		return dtos.AccountDTO{}, exceptions.NewConflictError("Email already in use")
	}

	firstName := utils.Capitalized(opts.FirstName)
	lastName := utils.Capitalized(opts.LastName)
	username := utils.Slugify(fmt.Sprintf("%s %s", firstName, lastName))
	count, err := s.database.CountAccountAlikeUsernames(ctx, utils.DbSearchEnd(username))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count usernames that are alike", "error", err)
		return dtos.AccountDTO{}, exceptions.NewServerError()
	}
	if count > 0 {
		username = fmt.Sprintf("%s%d", username, count+1)
	}

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AccountDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	var account database.Account
	if provider == AuthProviderEmail {
		account, err = qrs.CreateAccountWithPassword(ctx, database.CreateAccountWithPasswordParams{
			FirstName: firstName,
			LastName:  lastName,
			Username:  username,
			Email:     email,
			Password:  password,
		})
	} else {
		account, err = qrs.CreateAccountWithoutPassword(ctx, database.CreateAccountWithoutPasswordParams{
			FirstName: firstName,
			LastName:  lastName,
			Username:  username,
			Email:     email,
		})
	}

	if err := qrs.CreateAuthProvider(ctx, database.CreateAuthProviderParams{
		Email:    email,
		Provider: provider,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create auth provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AccountDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created account successfully")
	return dtos.MapAccountToDTO(&account), nil
}

type GetAccountByEmailOptions struct {
	RequestID string
	Email     string
}

func (s *Services) GetAccountByEmail(
	ctx context.Context,
	opts GetAccountByEmailOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "GetAccountByEmail")
	logger.InfoContext(ctx, "Getting account by email...")

	account, err := s.database.FindAccountByEmail(ctx, utils.Lowered(opts.Email))
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account not found", "error", err)
			return dtos.AccountDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account", "error", err)
		return dtos.AccountDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account by email successfully")
	return dtos.MapAccountToDTO(&account), nil
}

type GetAccountByIDOptions struct {
	RequestID string
	ID        int32
}

func (s *Services) GetAccountByID(
	ctx context.Context,
	opts GetAccountByIDOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "GetAccountByID").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Getting account by AccountID...")

	account, err := s.database.FindAccountById(ctx, opts.ID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account not found", "error", err)
			return dtos.AccountDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account", "error", err)
		return dtos.AccountDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account by AccountID successfully")
	return dtos.MapAccountToDTO(&account), nil
}

func (s *Services) UpdateAccountEmail() {

}
