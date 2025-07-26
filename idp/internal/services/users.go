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
		"AccountID", opts.AccountID,
		"email", opts.Email,
		"username", opts.Username,
	)
	logger.InfoContext(ctx, "Creating user...")

	publicID, err := uuid.NewRandom()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate user public ID", "error", err)
		return dtos.UserDTO{}, exceptions.NewInternalServerError()
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
		return dtos.UserDTO{}, exceptions.NewInternalServerError()
	}

	var password pgtype.Text
	hashedPassword, err := utils.Argon2HashString(opts.Password)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash password", "error", err)
		return dtos.UserDTO{}, exceptions.NewInternalServerError()
	}
	if err := password.Scan(hashedPassword); err != nil {
		logger.ErrorContext(ctx, "Failed to set password", "error", err)
		return dtos.UserDTO{}, exceptions.NewInternalServerError()
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
		PublicID:  publicID,
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
		Provider:  database.AuthProviderUsernamePassword,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create user auth Provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.UserDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created user successfully")
	return dtos.MapUserToDTO(&user)
}

type ListUsersOptions struct {
	RequestID string
	AccountID int32
	Offset    int32
	Limit     int32
	Order     string
}

func (s *Services) ListUsers(
	ctx context.Context,
	opts ListUsersOptions,
) ([]dtos.UserDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "ListUsers").With(
		"AccountID", opts.AccountID,
		"offset", opts.Offset,
		"limit", opts.Limit,
		"order", opts.Order,
	)
	logger.InfoContext(ctx, "Listing users...")

	order := utils.Lowered(opts.Order)
	var users []database.User
	var err error

	switch order {
	case "date":
		users, err = s.database.FindPaginatedUsersByAccountIDOrderedByID(ctx,
			database.FindPaginatedUsersByAccountIDOrderedByIDParams{
				AccountID: opts.AccountID,
				Offset:    opts.Offset,
				Limit:     opts.Limit,
			},
		)
	case "email":
		users, err = s.database.FindPaginatedUsersByAccountIDOrderedByEmail(ctx,
			database.FindPaginatedUsersByAccountIDOrderedByEmailParams{
				AccountID: opts.AccountID,
				Offset:    opts.Offset,
				Limit:     opts.Limit,
			},
		)
	case "username":
		users, err = s.database.FindPaginatedUsersByAccountIDOrderedByUsername(ctx,
			database.FindPaginatedUsersByAccountIDOrderedByUsernameParams{
				AccountID: opts.AccountID,
				Offset:    opts.Offset,
				Limit:     opts.Limit,
			},
		)
	default:
		logger.WarnContext(ctx, "Unknown order type, failing", "order", order)
		return nil, 0, exceptions.NewValidationError("Unknown order type")
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to list users", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	count, err := s.database.CountUsersByAccountID(ctx, opts.AccountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count users", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	userDTOs, serviceErr := utils.MapSliceWithErr(users, dtos.MapUserToDTO)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map users to DTOs", "error", serviceErr)
		return nil, 0, exceptions.NewInternalServerError()
	}

	logger.InfoContext(ctx, "Listed users successfully")
	return userDTOs, count, nil
}

type FilterUsersOptions struct {
	RequestID string
	AccountID int32
	Offset    int32
	Limit     int32
	Order     string
	Search    string
}

func (s *Services) FilterUsers(
	ctx context.Context,
	opts FilterUsersOptions,
) ([]dtos.UserDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "FilterUsers").With(
		"accountId", opts.AccountID,
		"search", opts.Search,
		"order", opts.Order,
	)
	logger.InfoContext(ctx, "Filtering users...")

	search := utils.DbSearch(opts.Search)
	var users []database.User
	var err error

	switch opts.Order {
	case "id":
		users, err = s.database.FilterUsersByEmailOrUsernameAndByAccountIDOrderedByID(ctx,
			database.FilterUsersByEmailOrUsernameAndByAccountIDOrderedByIDParams{
				AccountID: opts.AccountID,
				Email:     search,
				Username:  search,
				Offset:    opts.Offset,
				Limit:     opts.Limit,
			},
		)
	case "email":
		users, err = s.database.FilterUsersByEmailOrUsernameAndByAccountIDOrderedByEmail(ctx,
			database.FilterUsersByEmailOrUsernameAndByAccountIDOrderedByEmailParams{
				AccountID: opts.AccountID,
				Email:     search,
				Username:  search,
				Offset:    opts.Offset,
				Limit:     opts.Limit,
			},
		)
	case "username":
		users, err = s.database.FilterUsersByEmailOrUsernameAndByAccountIDOrderedByUsername(ctx,
			database.FilterUsersByEmailOrUsernameAndByAccountIDOrderedByUsernameParams{
				AccountID: opts.AccountID,
				Email:     search,
				Username:  search,
				Offset:    opts.Offset,
				Limit:     opts.Limit,
			},
		)
	default:
		logger.WarnContext(ctx, "Unknown order type, failing", "order", opts.Order)
		return nil, 0, exceptions.NewValidationError("Unknown order type")
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to filter users", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	count, err := s.database.CountFilteredUsersByEmailOrUsernameAndByAccountID(ctx,
		database.CountFilteredUsersByEmailOrUsernameAndByAccountIDParams{
			AccountID: opts.AccountID,
			Email:     search,
			Username:  search,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count filtered users", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	userDTOs, serviceErr := utils.MapSliceWithErr(users, dtos.MapUserToDTO)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map users to DTOs", "error", serviceErr)
		return nil, 0, exceptions.NewInternalServerError()
	}

	logger.InfoContext(ctx, "Filtered users successfully")
	return userDTOs, count, nil
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
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found", "error", err)
			return dtos.UserDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to find user by ID", "error", err)
		return dtos.UserDTO{}, serviceErr
	}

	if user.AccountID != opts.AccountID {
		logger.WarnContext(ctx, "User does not belong to account")
		return dtos.UserDTO{}, exceptions.NewNotFoundError()
	}

	logger.InfoContext(ctx, "Got user by ID successfully")
	return dtos.MapUserToDTO(&user)
}

type GetUserByPublicIDAndVersionOptions struct {
	RequestID string
	PublicID  uuid.UUID
	AccountID int32
	Version   int32
}

func (s *Services) GetUserByPublicIDAndVersion(
	ctx context.Context,
	opts GetUserByPublicIDAndVersionOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "GetUserByPublicIDAndVersion").With(
		"publicId", opts.PublicID,
		"accountId", opts.AccountID,
		"version", opts.Version,
	)
	logger.InfoContext(ctx, "Getting user by public ID and version...")

	user, err := s.database.FindUserByPublicIDAndVersion(ctx, database.FindUserByPublicIDAndVersionParams{
		PublicID: opts.PublicID,
		Version:  opts.Version,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found", "error", err)
			return dtos.UserDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to find user by public ID", "error", err)
		return dtos.UserDTO{}, serviceErr
	}

	if user.AccountID != opts.AccountID {
		logger.WarnContext(ctx, "User does not belong to account")
		return dtos.UserDTO{}, exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "Got user by public ID and version successfully")
	return dtos.MapUserToDTO(&user)
}

type GetUserByUsernameOptions struct {
	RequestID string
	AccountID int32
	Username  string
}

func (s *Services) GetUserByUsername(
	ctx context.Context,
	opts GetUserByUsernameOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "GetUserByUsername").With(
		"accountId", opts.AccountID,
		"username", opts.Username,
	)
	logger.InfoContext(ctx, "Getting user by username...")

	username := utils.Lowered(opts.Username)
	user, err := s.database.FindUserByUsernameAndAccountID(ctx, database.FindUserByUsernameAndAccountIDParams{
		Username:  username,
		AccountID: opts.AccountID,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.UserDTO{}, exceptions.NewNotFoundError()
		}

		logger.ErrorContext(ctx, "Failed to find user by username", "error", err)
		return dtos.UserDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got user by username successfully")
	return dtos.MapUserToDTO(&user)
}

type UpdateUserOptions struct {
	RequestID     string
	AccountID     int32
	UserID        int32
	Email         string
	Username      string
	UserData      reflect.Value
	IsActive      bool
	EmailVerified bool
}

func (s *Services) UpdateUser(
	ctx context.Context,
	opts UpdateUserOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "UpdateUser").With(
		"userId", opts.UserID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Updating user...")

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		UserID:    opts.UserID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.UserDTO{}, exceptions.NewNotFoundError()
		}

		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.UserDTO{}, serviceErr
	}

	email := utils.Lowered(opts.Email)
	if email != userDTO.Email {
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
	}

	username := utils.Lowered(opts.Username)
	if username != userDTO.Username {
		count, err := s.database.CountUsersByUsernameAndAccountID(ctx, database.CountUsersByUsernameAndAccountIDParams{
			Username:  username,
			AccountID: opts.AccountID,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to count users by username", "error", err)
			return dtos.UserDTO{}, exceptions.FromDBError(err)
		}
		if count > 0 {
			logger.WarnContext(ctx, "Username already in use")
			return dtos.UserDTO{}, exceptions.NewConflictError("Username already in use")
		}
	}

	data, err := json.Marshal(opts.UserData.Interface())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user data", "error", err)
		return dtos.UserDTO{}, exceptions.NewInternalServerError()
	}

	user, err := s.database.UpdateUser(ctx, database.UpdateUserParams{
		ID:            opts.UserID,
		Email:         email,
		Username:      username,
		UserData:      data,
		IsActive:      opts.IsActive,
		EmailVerified: opts.EmailVerified,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update user", "error", err)
		return dtos.UserDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Updated user successfully")
	return dtos.MapUserToDTO(&user)
}

type UpdateUserPasswordOptions struct {
	RequestID string
	AccountID int32
	UserID    int32
	Password  string
}

func (s *Services) UpdateUserPassword(
	ctx context.Context,
	opts UpdateUserPasswordOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "UpdateUserPassword").With(
		"userId", opts.UserID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Updating user password...")

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		UserID:    opts.UserID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.UserDTO{}, exceptions.NewNotFoundError()
		}

		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.UserDTO{}, serviceErr
	}

	var password pgtype.Text
	hashedPassword, err := utils.Argon2HashString(opts.Password)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash password", "error", err)
		return dtos.UserDTO{}, exceptions.NewInternalServerError()
	}
	if err := password.Scan(hashedPassword); err != nil {
		logger.ErrorContext(ctx, "Failed to set password", "error", err)
		return dtos.UserDTO{}, exceptions.NewInternalServerError()
	}

	user, err := s.database.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
		Password: password,
		ID:       userDTO.ID(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update user password", "error", err)
		return dtos.UserDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Updated user password successfully")
	return dtos.MapUserToDTO(&user)
}

type DeleteUserOptions struct {
	RequestID string
	AccountID int32
	UserID    int32
}

func (s *Services) DeleteUser(
	ctx context.Context,
	opts DeleteUserOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, usersLocation, "DeleteUser").With(
		"userId", opts.UserID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Deleting user...")

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		UserID:    opts.UserID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return exceptions.NewNotFoundError()
		}

		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return serviceErr
	}

	if err := s.database.DeleteUser(ctx, userDTO.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete user", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Deleted user successfully")
	return nil
}

type GetUserByEmailOptions struct {
	RequestID string
	AccountID int32
	Email     string
}

func (s *Services) GetUserByEmail(
	ctx context.Context,
	opts GetUserByEmailOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "GetUserByEmail").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting user by email...")

	email := utils.Lowered(opts.Email)
	user, err := s.database.FindUserByEmailAndAccountID(ctx, database.FindUserByEmailAndAccountIDParams{
		Email:     email,
		AccountID: opts.AccountID,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.UserDTO{}, exceptions.NewNotFoundError()
		}

		logger.ErrorContext(ctx, "Failed to find user by email", "error", err)
		return dtos.UserDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got user by email successfully")
	return dtos.MapUserToDTO(&user)
}
