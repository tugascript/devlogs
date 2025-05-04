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
	"slices"

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

	user, err := qrs.CreateUserWithPassword(ctx, database.CreateUserWithPasswordParams{
		AccountID: opts.AccountID,
		Email:     email,
		Username:  username,
		Password:  password,
		UserData:  data,
		Dek:       dek,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create user", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	if err := qrs.CreateUserAuthProvider(ctx, database.CreateUserAuthProviderParams{
		AccountID: opts.AccountID,
		UserID:    user.ID,
		Provider:  AuthProviderEmail,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create user auth provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created user successfully")
	return dtos.MapUserToDTO(&user)
}

type CreateAppUserOptions struct {
	RequestID        string
	AccountID        int32
	AppID            int32
	Email            string
	Username         string
	Password         string
	Provider         string
	AllowedProviders []string
	UserData         reflect.Value
	AppData          reflect.Value
	AppDataMap       map[string]any
}

func (s *Services) CreateAppUser(
	ctx context.Context,
	opts CreateAppUserOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "CreateAppUser").With(
		"appID", opts.AppID,
		"accountID", opts.AccountID,
		"provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Registering user...")

	if !slices.Contains(opts.AllowedProviders, opts.Provider) {
		logger.WarnContext(ctx, "Invalid provider")
		return dtos.UserDTO{}, exceptions.NewForbiddenError()
	}

	var password pgtype.Text
	if opts.Provider == AuthProviderUsernamePassword {
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required")
			return dtos.UserDTO{}, exceptions.NewValidationError("Password is required")
		}

		hashedPassword, err := utils.HashString(opts.Password)
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

	data, err := json.Marshal(opts.UserData)
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
		return dtos.UserDTO{}, serviceErr
	}

	if err := qrs.CreateUserAuthProvider(ctx, database.CreateUserAuthProviderParams{
		AccountID: opts.AccountID,
		UserID:    user.ID,
		Provider:  opts.Provider,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create user auth provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	if !opts.AppData.IsZero() || len(opts.AppDataMap) > 0 {
		appData, err := json.Marshal(opts.AppData)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to marshal app data", "error", err)
			return dtos.UserDTO{}, exceptions.NewServerError()
		}

		if err := qrs.CreateAppProfileWithData(ctx, database.CreateAppProfileWithDataParams{
			AccountID:   opts.AccountID,
			UserID:      user.ID,
			AppID:       opts.AppID,
			ProfileData: appData,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app profile", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.UserDTO{}, serviceErr
		}
	} else {
		if err := qrs.CreateAppProfileWithoutData(ctx, database.CreateAppProfileWithoutDataParams{
			AccountID: opts.AccountID,
			UserID:    user.ID,
			AppID:     opts.AppID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app profile", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.UserDTO{}, serviceErr
		}
	}

	logger.InfoContext(ctx, "Created user successfully")
	return dtos.MapUserToDTO(&user)
}

type GetUserByIDOptions struct {
	RequestID string
	UserID    int32
	AccountID int32
}

func (s *Services) GetUserByID(
	ctx context.Context,
	opts GetUserByIDOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "GetUserByID").With(
		"userId", opts.UserID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting user by ID...")

	user, err := s.database.FindUserByID(ctx, opts.UserID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find user by ID", "error", err)
		return dtos.UserDTO{}, exceptions.FromDBError(err)
	}

	if user.AccountID != opts.AccountID {
		logger.WarnContext(ctx, "User does not belong to account")
		return dtos.UserDTO{}, exceptions.NewNotFoundError()
	}

	logger.InfoContext(ctx, "Got user by ID successfully")
	return dtos.MapUserToDTO(&user)
}

type ConfirmUserOptions struct {
	RequestID string
	AccountID int32
	UserID    int32
	Version   int32
}

func (s *Services) ConfirmUser(
	ctx context.Context,
	opts ConfirmUserOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "ConfirmUser").With(
		"userId", opts.UserID,
		"accountId", opts.AccountID,
		"version", opts.Version,
	)
	logger.InfoContext(ctx, "Confirming user...")

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		UserID:    opts.UserID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.UserDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.UserDTO{}, serviceErr
	}

	userVersion := userDTO.Version()
	if userVersion != int(opts.Version) {
		logger.WarnContext(ctx, "User version mismatch", "currentVersion", userVersion)
		return dtos.UserDTO{}, exceptions.NewUnauthorizedError()
	}

	user, err := s.database.ConfirmUser(ctx, opts.UserID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to confirm user", "error", err)
		return dtos.UserDTO{}, exceptions.FromDBError(err)
	}
	logger.InfoContext(ctx, "Confirmed user successfully")
	return dtos.MapUserToDTO(&user)
}
