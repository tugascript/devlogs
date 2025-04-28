package services

import (
	"context"
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const userSchemasLocation string = "user_schemas"

type UserSchemaField struct {
	Type     string `json:"type"`
	Unique   bool   `json:"unique"`
	Required bool   `json:"required"`
	Default  any    `json:"default,omitempty"`
}

type CreateUserSchemaOptions struct {
	RequestID string
	AccountID int32
	Schema    map[string]UserSchemaField
}

func (s *Services) CreateUserSchema(
	ctx context.Context,
	opts CreateUserSchemaOptions,
) (dtos.UserSchemaDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, userSchemasLocation, "CreateUserSchema").With(
		"accountId", opts.AccountID,
	)
	logger.Info("Creating user schema...")

	count, err := s.database.CountUserSchemasByAccountID(ctx, opts.AccountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count user schemas by account id", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.ErrorContext(ctx, "User schema already exists", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.NewConflictError("User schema already exists")
	}

	schemaData, err := json.Marshal(opts.Schema)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user schema", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.NewServerError()
	}

	schema, err := s.database.CreateUserSchema(ctx, database.CreateUserSchemaParams{
		AccountID:  opts.AccountID,
		SchemaData: schemaData,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create user schema", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "User schema created successfully")
	return dtos.MapUserSchemaToDTO(&schema)
}

type GetOrCreateUserSchemaOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetUserSchemaByAccountID(
	ctx context.Context,
	opts GetOrCreateUserSchemaOptions,
) (dtos.UserSchemaDTO, int32, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, userSchemasLocation, "GetUserSchemaByAccountID").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting user schema...")

	schema, err := s.database.FindUserSchemaByAccountID(ctx, opts.AccountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find user schema", "error", err)
		return dtos.UserSchemaDTO{}, 0, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "User schema found")
	schemaDTO, serviceErr := dtos.MapUserSchemaToDTO(&schema)
	return schemaDTO, schema.ID, serviceErr
}

func (s *Services) createDefaultUserSchema(
	ctx context.Context,
	opts GetOrCreateUserSchemaOptions,
) (dtos.UserSchemaDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, userSchemasLocation, "createDefaultUserSchema").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Creating default user schema...")

	schema, err := s.database.CreateDefaultUserSchema(ctx, opts.AccountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create default user schema", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Default user schema created successfully")
	return dtos.MapUserSchemaToDTO(&schema)
}

func (s *Services) GetOrCreateUserSchema(
	ctx context.Context,
	opts GetOrCreateUserSchemaOptions,
) (dtos.UserSchemaDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, userSchemasLocation, "GetOrCreateUserSchema").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting or creating user schema...")

	schemaDto, _, serviceErr := s.GetUserSchemaByAccountID(ctx, opts)
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get user schema", "error", serviceErr)
			return dtos.UserSchemaDTO{}, serviceErr
		}

		logger.DebugContext(ctx, "User schema not found, creating new one")
		return s.createDefaultUserSchema(ctx, opts)
	}

	logger.InfoContext(ctx, "User schema found")
	return schemaDto, nil
}

type UpdateUserSchemaOptions struct {
	RequestID string
	AccountID int32
	Schema    map[string]UserSchemaField
}

func getRemovedFields(
	schemaDTO dtos.UserSchemaDTO,
	newSchema map[string]UserSchemaField,
) []string {
	removedFields := make([]string, 0)
	for fieldName := range schemaDTO {
		if _, ok := newSchema[fieldName]; !ok {
			removedFields = append(removedFields, fieldName)
		}
	}
	return removedFields
}

func getModifiedUniqueAndRequiredFields(
	schemaDTO dtos.UserSchemaDTO,
	newSchema map[string]UserSchemaField,
) []string {
	modifiedUniqueAndRequiredFields := make([]string, 0)
	for fieldName, field := range newSchema {
		if oldField, ok := schemaDTO[fieldName]; ok {
			if oldField.Required && oldField.Unique && (!field.Unique || !field.Required) {
				modifiedUniqueAndRequiredFields = append(modifiedUniqueAndRequiredFields, fieldName)
			}
		}
	}
	return modifiedUniqueAndRequiredFields
}

func getUniqueRequiredFields(schemaDTO dtos.UserSchemaDTO, removedFields []string) []string {
	uniqueRequiredFields := make([]string, 0)
	for _, field := range removedFields {
		if schemaDTO[field].Unique && schemaDTO[field].Required {
			uniqueRequiredFields = append(uniqueRequiredFields, field)
		}
	}
	return uniqueRequiredFields
}

func getUsernameCandidateFields(
	removedUniqueRequiredFields []string,
	modifiedUniqueAndRequiredFields []string,
) []string {
	usernameColumns := make([]string, 0, len(removedUniqueRequiredFields)+len(modifiedUniqueAndRequiredFields))
	usernameColumns = append(usernameColumns, removedUniqueRequiredFields...)
	usernameColumns = append(usernameColumns, modifiedUniqueAndRequiredFields...)
	return usernameColumns
}

func (s *Services) validateUsernameCandidateFieldsWithRemoved(
	ctx context.Context,
	opts UpdateUserSchemaOptions,
	schemaDTO dtos.UserSchemaDTO,
) ([]string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.RequestID,
		userSchemasLocation,
		"validateUsernameCandidateFieldsWithRemoved",
	).With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Validating removed and username candidate fields...")

	// Check if the new schema has removed fields
	removedFields := getRemovedFields(schemaDTO, opts.Schema)
	if len(removedFields) == 0 {
		logger.InfoContext(ctx, "No removed fields found")
		return removedFields, nil
	}

	logger.InfoContext(ctx, "Removed fields found", "removedFields", removedFields)
	removedUniqueRequiredFields := getUniqueRequiredFields(schemaDTO, removedFields)
	modifiedUniqueAndRequiredFields := getModifiedUniqueAndRequiredFields(schemaDTO, opts.Schema)
	if len(removedUniqueRequiredFields) == 0 && len(modifiedUniqueAndRequiredFields) == 0 {
		logger.InfoContext(ctx, "No unique required fields found")
		return removedFields, nil
	}

	count, err := s.database.CountAppsByUsernameColumns(ctx, database.CountAppsByUsernameColumnsParams{
		AccountID: opts.AccountID,
		UsernameColumns: getUsernameCandidateFields(
			removedUniqueRequiredFields,
			modifiedUniqueAndRequiredFields,
		),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count apps by username columns", "error", err)
		return nil, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.ErrorContext(ctx, "Cannot fields that are used as username columns",
			"removedFields", removedUniqueRequiredFields,
		)
		return nil, exceptions.NewConflictError("Cannot fields that are used as username columns")
	}

	logger.InfoContext(ctx, "Removed fields validated successfully")
	return removedFields, nil
}

func (s *Services) validateNewFields(
	ctx context.Context,
	opts UpdateUserSchemaOptions,
	schemaDTO dtos.UserSchemaDTO,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, userSchemasLocation, "validateNewFields").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Validating new fields...")

	for fieldName, v := range opts.Schema {
		if _, ok := schemaDTO[fieldName]; !ok {
			if v.Unique {
				logger.WarnContext(ctx, "Can't make new fields unique", "fieldName", fieldName)
				return exceptions.NewConflictError("Can't make new fields unique")
			}
			if v.Required && utils.IsEmptyInterface(v.Default) {
				logger.WarnContext(ctx, "Users already exit. Can't make new fields required without defaults", "fieldName", fieldName)
				return exceptions.NewConflictError("Users already exit. Can't make new fields required without defaults")
			}
		}
	}

	logger.InfoContext(ctx, "New fields validated successfully")
	return nil
}

type updateUserSchemaAndUserOptions struct {
	requestID     string
	accountID     int32
	schemaID      int32
	schema        map[string]UserSchemaField
	removedFields []string
}

func (s *Services) updateUserSchemaAndUser(
	ctx context.Context,
	opts updateUserSchemaAndUserOptions,
) (dtos.UserSchemaDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, userSchemasLocation, "updateUserSchemaAndUser").With(
		"accountId", opts.accountID,
		"schemaId", opts.schemaID,
	)
	logger.InfoContext(ctx, "Updating user schema and users...")

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	schemaJSON, err := json.Marshal(opts.schema)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user schema", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.NewServerError()
	}

	schema, err := qrs.UpdateUserSchema(ctx, database.UpdateUserSchemaParams{
		ID:         opts.schemaID,
		SchemaData: schemaJSON,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update user schema", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.FromDBError(err)
	}
	if err := qrs.RemoveUserUserDataFields(ctx, database.RemoveUserUserDataFieldsParams{
		AccountID: opts.accountID,
		Fields:    opts.removedFields,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to remove user data fields", "error", err)
	}

	return dtos.MapUserSchemaToDTO(&schema)
}

func (s *Services) UpdateUserSchema(
	ctx context.Context,
	opts UpdateUserSchemaOptions,
) (dtos.UserSchemaDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, userSchemasLocation, "UpdateUserSchema").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Updating user schema...")

	schemaDTO, schemaID, serviceErr := s.GetUserSchemaByAccountID(ctx, GetOrCreateUserSchemaOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		return dtos.UserSchemaDTO{}, serviceErr
	}

	removedFields, serviceErr := s.validateUsernameCandidateFieldsWithRemoved(ctx, opts, schemaDTO)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to validate removed fields", "error", serviceErr)
		return dtos.UserSchemaDTO{}, serviceErr
	}

	count, err := s.database.CountUsersByAccountID(ctx, opts.AccountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count users by account id", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.InfoContext(ctx, "User schema has users, validating removed fields")
		if serviceErr := s.validateNewFields(ctx, opts, schemaDTO); serviceErr != nil {
			return dtos.UserSchemaDTO{}, serviceErr
		}
		if len(removedFields) > 0 {
			return s.updateUserSchemaAndUser(ctx, updateUserSchemaAndUserOptions{
				requestID:     opts.RequestID,
				accountID:     opts.AccountID,
				schemaID:      schemaID,
				schema:        opts.Schema,
				removedFields: removedFields,
			})
		}
	}

	schemaJSON, err := json.Marshal(opts.Schema)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user schema", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.NewServerError()
	}

	schema, err := s.database.UpdateUserSchema(ctx, database.UpdateUserSchemaParams{
		SchemaData: schemaJSON,
		ID:         schemaID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update user schema", "error", err)
		return dtos.UserSchemaDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "User schema updated successfully")
	return dtos.MapUserSchemaToDTO(&schema)
}
