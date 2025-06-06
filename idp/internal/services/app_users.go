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
) (dtos.UserDTO, dtos.AppProfileDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appUsersLocation, "CreateAppUser").With(
		"appID", opts.AppID,
		"AccountID", opts.AccountID,
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Creating app user...")

	var password pgtype.Text
	if opts.Provider == AuthProviderUsernamePassword {
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required")
			return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.NewValidationError("Password is required")
		}

		hashedPassword, err := utils.HashString(opts.Password)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to hash password", "error", err)
			return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.NewServerError()
		}

		if err := password.Scan(hashedPassword); err != nil {
			logger.ErrorContext(ctx, "Failed pass password to text", "error", err)
			return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.NewServerError()
		}
	}

	email := utils.Lowered(opts.Email)
	count, err := s.database.CountUsersByEmailAndAccountID(ctx, database.CountUsersByEmailAndAccountIDParams{
		Email:     email,
		AccountID: opts.AccountID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count user by email", "error", err)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.WarnContext(ctx, "Email already in use")
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.NewConflictError("Email already in use")
	}

	username, serviceErr := s.setUserUsername(ctx, logger, opts.AccountID, opts.Username)
	if serviceErr != nil {
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	data, err := json.Marshal(opts.UserData)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user data", "error", err)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.NewServerError()
	}

	dek, err := s.encrypt.GenerateUserDEK(ctx, opts.RequestID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate user DEK", "error", err)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.NewServerError()
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	var user database.User
	if opts.Provider == AuthProviderUsernamePassword {
		user, err = qrs.CreateUserWithPassword(ctx, database.CreateUserWithPasswordParams{
			AccountID: opts.AccountID,
			Email:     email,
			Username:  username,
			Password:  password,
			UserData:  data,
			Dek:       dek,
		})
	} else {
		user, err = qrs.CreateUserWithoutPassword(ctx, database.CreateUserWithoutPasswordParams{
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
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	if err := qrs.CreateUserAuthProvider(ctx, database.CreateUserAuthProviderParams{
		AccountID: opts.AccountID,
		UserID:    user.ID,
		Provider:  opts.Provider,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create user auth Provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	appProfile, err := qrs.CreateAppProfile(ctx, database.CreateAppProfileParams{
		AccountID: opts.AccountID,
		UserID:    user.ID,
		AppID:     opts.AppID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app profile", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	userDTO, serviceErr := dtos.MapUserToDTO(&user)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user to DTO", "error", serviceErr)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	appProfileDTO, serviceErr := dtos.MapAppProfileToDTO(&appProfile)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app profile to DTO", "error", serviceErr)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created user successfully")
	return userDTO, appProfileDTO, nil
}

type ConfirmAppUserOptions struct {
	RequestID string
	AccountID int32
	AppID     int32
	UserID    int32
	Version   int32
}

func (s *Services) ConfirmAppUser(
	ctx context.Context,
	opts ConfirmAppUserOptions,
) (dtos.UserDTO, dtos.AppProfileDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appUsersLocation, "ConfirmAppUser").With(
		"userId", opts.UserID,
		"accountId", opts.AccountID,
		"appId", opts.AppID,
		"version", opts.Version,
	)
	logger.InfoContext(ctx, "Confirming app user...")

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		UserID:    opts.UserID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	userVersion := userDTO.Version()
	if userVersion != opts.Version {
		logger.WarnContext(ctx, "User version mismatch",
			"currentVersion", userVersion,
			"expectedVersion", opts.Version,
		)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.NewUnauthorizedError()
	}

	user, err := s.database.ConfirmUser(ctx, opts.UserID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to confirm user", "error", err)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.FromDBError(err)
	}

	appProfile, err := s.database.FindAppProfileByAppIDAndUserID(ctx, database.FindAppProfileByAppIDAndUserIDParams{
		AppID:  opts.AppID,
		UserID: opts.UserID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find app profile by app ID and user ID", "error", err)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, exceptions.FromDBError(err)
	}

	userDTO, serviceErr = dtos.MapUserToDTO(&user)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user to DTO", "error", serviceErr)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	appProfileDTO, serviceErr := dtos.MapAppProfileToDTO(&appProfile)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app profile to DTO", "error", serviceErr)
		return dtos.UserDTO{}, dtos.AppProfileDTO{}, serviceErr
	}

	return userDTO, appProfileDTO, nil
}
