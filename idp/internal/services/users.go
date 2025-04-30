// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"reflect"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const usersLocation string = "users"

func (s *Services) setUserUsername(
	ctx context.Context,
	logger *slog.Logger,
	accountID int32,
	username string,
) (string, *exceptions.ServiceError) {
	if username == "" {
		return uuid.NewString(), nil
	}

	fmtUsername := utils.Lowered(username)
	count, err := s.database.CountUsersByUsernameAndAccountID(ctx, database.CountUsersByUsernameAndAccountIDParams{
		Username:  fmtUsername,
		AccountID: accountID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count users by username", "error", err)
		return "", exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.WarnContext(ctx, "Username already in use")
		return "", exceptions.NewConflictError("Username already in use")
	}

	return fmtUsername, nil
}

type CreateUserOptions struct {
	RequestID string
	AccountID int32
	Email     string
	Username  string
	Password  string
	UserData  reflect.Value
}

func (s *Services) CreateUser(
	ctx context.Context,
	opts CreateUserOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "CreateUser").With(
		"accountID", opts.AccountID,
		"email", opts.Email,
		"username", opts.Username,
	)
	logger.InfoContext(ctx, "Creating user...")

	email := utils.Lowered(opts.Email)
	count, err := s.database.CountUsersByEmailAndAccountID(ctx, database.CountUsersByEmailAndAccountIDParams{
		Email:     email,
		AccountID: opts.AccountID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count user by email", "error", err)
		return dtos.UserDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.WarnContext(ctx, "Email already in use")
		return dtos.UserDTO{}, exceptions.NewConflictError("Email already in use")
	}

	username, serviceErr := s.setUserUsername(ctx, logger, opts.AccountID, opts.Username)
	if serviceErr != nil {
		return dtos.UserDTO{}, serviceErr
	}

	data, err := json.Marshal(opts.UserData)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user data", "error", err)
		return dtos.UserDTO{}, exceptions.NewServerError()
	}

	var password pgtype.Text
	hashedPassword, err := utils.HashString(opts.Password)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash password", "error", err)
		return dtos.UserDTO{}, exceptions.NewServerError()
	}
	if err := password.Scan(hashedPassword); err != nil {
		logger.ErrorContext(ctx, "Failed to set password", "error", err)
		return dtos.UserDTO{}, exceptions.NewServerError()
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.UserDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	user, err := qrs.CreateUserWithPassword(ctx, database.CreateUserWithPasswordParams{
		AccountID: opts.AccountID,
		Email:     email,
		Username:  username,
		Password:  password,
		UserData:  data,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create user", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	if err := qrs.CreateUserAuthProvider(ctx, database.CreateUserAuthProviderParams{
		AccountID: opts.AccountID,
		UserID:    user.ID,
		Email:     email,
		Provider:  AuthProviderEmail,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create user auth provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created user successfully")
	return dtos.MapUserToDTO(&user)
}
