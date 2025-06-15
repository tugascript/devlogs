// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const appUsersLocation string = "app_users"

type CreateAppUserOptions struct {
	RequestID string
	AccountID int32
	AppID     int32
	Email     string
	Username  string
	Password  string
	Provider  string
	UserData  reflect.Value
}

func (s *Services) CreateAppUser(
	ctx context.Context,
	opts CreateAppUserOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appUsersLocation, "CreateAppUser").With(
		"appID", opts.AppID,
		"AccountID", opts.AccountID,
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Creating app user...")

	authProvider, serviceErr := mapAuthProvider(opts.Provider)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth provider", "serviceError", serviceErr)
		return dtos.UserDTO{}, serviceErr
	}

	var password pgtype.Text
	if authProvider == database.AuthProviderUsernamePassword {
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required")
			return dtos.UserDTO{}, exceptions.NewValidationError("Password is required")
		}

		hashedPassword, err := utils.Argon2HashString(opts.Password)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to hash password", "error", err)
			return dtos.UserDTO{}, exceptions.NewServerError()
		}

		if err := password.Scan(hashedPassword); err != nil {
			logger.ErrorContext(ctx, "Failed pass password to text", "error", err)
			return dtos.UserDTO{}, exceptions.NewServerError()
		}
	}

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

	data, err := json.Marshal(opts.UserData.Interface())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user data", "error", err)
		return dtos.UserDTO{}, exceptions.NewServerError()
	}

	dek, err := s.encrypt.GenerateUserDEK(ctx, opts.RequestID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate user DEK", "error", err)
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

	publicID := uuid.New()
	var user database.User
	if authProvider == database.AuthProviderUsernamePassword {
		user, err = qrs.CreateUserWithPassword(ctx, database.CreateUserWithPasswordParams{
			PublicID:  publicID,
			AccountID: opts.AccountID,
			Email:     email,
			Username:  username,
			Password:  password,
			UserData:  data,
			Dek:       dek,
		})
	} else {
		user, err = qrs.CreateUserWithoutPassword(ctx, database.CreateUserWithoutPasswordParams{
			PublicID:  publicID,
			AccountID: opts.AccountID,
			Email:     email,
			Username:  username,
			UserData:  data,
			Dek:       dek,
		})
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create user", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	if err := qrs.CreateUserAuthProvider(ctx, database.CreateUserAuthProviderParams{
		AccountID: opts.AccountID,
		UserID:    user.ID,
		Provider:  authProvider,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create user auth Provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	if err := qrs.CreateAppProfile(ctx, database.CreateAppProfileParams{
		AccountID: opts.AccountID,
		UserID:    user.ID,
		AppID:     opts.AppID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create app profile", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	userDTO, serviceErr := dtos.MapUserToDTO(&user)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user to DTO", "error", serviceErr)
		return dtos.UserDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created user successfully")
	return userDTO, nil
}

type ConfirmAppUserOptions struct {
	RequestID    string
	AccountID    int32
	AppID        int32
	UserPublicID uuid.UUID
	UserVersion  int32
}

func (s *Services) ConfirmAppUser(
	ctx context.Context,
	opts ConfirmAppUserOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appUsersLocation, "ConfirmAppUser").With(
		"userPublicID", opts.UserPublicID,
		"accountId", opts.AccountID,
		"appId", opts.AppID,
		"userVersion", opts.UserVersion,
	)
	logger.InfoContext(ctx, "Confirming app user...")

	userDTO, serviceErr := s.GetUserByPublicIDAndVersion(ctx, GetUserByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		PublicID:  opts.UserPublicID,
		Version:   opts.UserVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.UserDTO{}, serviceErr
	}

	user, err := s.database.ConfirmUser(ctx, userDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to confirm user", "error", err)
		return dtos.UserDTO{}, exceptions.FromDBError(err)
	}

	if _, err := s.database.FindAppProfileIDByAppIDAndUserID(ctx, database.FindAppProfileIDByAppIDAndUserIDParams{
		AppID:  opts.AppID,
		UserID: userDTO.ID(),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to find app profile by app ID and user ID", "error", err)
		return dtos.UserDTO{}, exceptions.FromDBError(err)
	}

	userDTO, serviceErr = dtos.MapUserToDTO(&user)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user to DTO", "error", serviceErr)
		return dtos.UserDTO{}, serviceErr
	}

	return userDTO, nil
}
