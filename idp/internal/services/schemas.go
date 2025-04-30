// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"reflect"
	"strings"
	"unicode"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	schemaLocation string = "schema"

	dataSchemaErrorMessage = "data does not match schema"
)

type SchemaField struct {
	Type     string `json:"type"`
	Unique   bool   `json:"unique"`
	Required bool   `json:"required"`
	Default  any    `json:"default,omitempty"`
	Validate string `json:"validate,omitempty"`
}

func GetSchemaFieldType(fieldType string) reflect.Type {
	switch fieldType {
	case "string":
		return reflect.TypeOf("")
	case "int":
		return reflect.TypeOf(0)
	case "float":
		return reflect.TypeOf(0.0)
	case "bool":
		return reflect.TypeOf(false)
	default:
		return reflect.TypeOf(new(interface{})).Elem()
	}
}

func GetSchemaFieldStructName(fieldName string) string {
	words := strings.Split(fieldName, "_")
	var result strings.Builder
	for _, word := range words {
		if len(word) > 0 {
			runes := []rune(word)
			runes[0] = unicode.ToUpper(runes[0])
			result.WriteString(string(runes))
		}
	}
	return result.String()
}

type UnmarshalSchemaBodyOptions struct {
	RequestID  string
	SchemaDTO  dtos.SchemaDTO
	SchemaType reflect.Type
	Data       map[string]any
}

func (s *Services) UnmarshalSchemaBody(
	ctx context.Context,
	opts UnmarshalSchemaBodyOptions,
) (reflect.Value, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, schemaLocation, "UnmarshalSchemaBody")
	logger.DebugContext(ctx, "Unmarshalling schema body")

	value := reflect.New(opts.SchemaType).Elem()
	for fieldName, fieldValue := range opts.Data {
		field := value.FieldByName(GetSchemaFieldStructName(fieldName))
		if !(field.IsValid() && field.CanSet()) {
			logger.WarnContext(ctx, "Invalid field name: %s", fieldName)
			return reflect.Value{}, exceptions.NewValidationError(dataSchemaErrorMessage)
		}

		schemaField, ok := opts.SchemaDTO[fieldName]
		if !ok {
			logger.WarnContext(ctx, "Field not found in schema: %s", fieldName)
			return reflect.Value{}, exceptions.NewValidationError(dataSchemaErrorMessage)
		}

		expectedType := GetSchemaFieldType(schemaField.Type)
		valueType := reflect.TypeOf(fieldValue)
		if valueType != expectedType {
			convertedVal, err := utils.ConvertType(fieldValue, expectedType)
			if err != nil {
				logger.WarnContext(ctx, "Failed to convert field value: %s", err)
				return reflect.Value{}, exceptions.NewValidationError(dataSchemaErrorMessage)
			}
			field.Set(reflect.ValueOf(convertedVal))
			continue
		}

		field.Set(reflect.ValueOf(fieldValue))
	}

	return value, nil
}
