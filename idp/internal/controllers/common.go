// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"context"
	"fmt"
	"regexp"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
)

var snakeCaseRegexCompiled = regexp.MustCompile(snakeCaseRegex)

func isValidSchemaFieldName(s string) bool {
	length := len(s)
	return length > 0 && length < 51 && snakeCaseRegexCompiled.MatchString(s)
}

func validateSchemaDefaultValue(field bodies.SchemaFieldBody) error {
	// If no default value is set, it's valid
	if field.Default == nil {
		return nil
	}

	switch field.Type {
	case "string":
		if _, ok := field.Default.(string); !ok {
			return fmt.Errorf("default value must be a string")
		}
	case "int":
		// Check for float64 since JSON unmarshaling typically converts numbers to float64
		if f, ok := field.Default.(float64); ok {
			if f != float64(int(f)) {
				return fmt.Errorf("default value must be an integer")
			}
		} else if _, ok := field.Default.(int); !ok {
			return fmt.Errorf("default value must be an integer")
		}
	case "float":
		if _, ok := field.Default.(float64); !ok {
			// Also accept int as valid for float
			if _, ok := field.Default.(int); !ok {
				return fmt.Errorf("default value must be a float")
			}
		}
	case "bool":
		if _, ok := field.Default.(bool); !ok {
			return fmt.Errorf("default value must be a boolean")
		}
	default:
		return fmt.Errorf("unknown field type: %s", field.Type)
	}

	return nil
}

func (c *Controllers) ValidateSchemaBody(
	ctx context.Context,
	body map[string]bodies.SchemaFieldBody,
) (map[string]services.SchemaField, *exceptions.ValidationErrorResponse) {
	if len(body) == 0 {
		return nil, exceptions.NewEmptyValidationErrorResponse(exceptions.ValidationResponseLocationBody)
	}

	schema := make(map[string]services.SchemaField, len(body))
	fieldErrors := make([]exceptions.FieldError, 0)

	for fieldName, field := range body {
		if !isValidSchemaFieldName(fieldName) {
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   fieldName,
				Value:   fieldName,
				Message: snakeCaseErrorMessage,
			})
		}
		if err := c.validate.StructCtx(ctx, field); err != nil {
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   fmt.Sprintf("%s.type", fieldName),
				Value:   field.Type,
				Message: userSchemaFieldErrorMessage,
			})
		}
		if err := validateSchemaDefaultValue(field); err != nil {
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   fmt.Sprintf("%s.default", fieldName),
				Value:   fmt.Sprintf("%v", field.Default),
				Message: defaultValueErrorMessage,
			})
		}

		if len(fieldErrors) == 0 {
			schema[fieldName] = services.SchemaField{
				Type:     field.Type,
				Unique:   field.Unique,
				Required: field.Required,
				Default:  field.Default,
			}
		}
	}

	if len(fieldErrors) > 0 {
		return nil, exceptions.NewValidationErrorResponse(exceptions.ValidationResponseLocationBody, fieldErrors)
	}

	return schema, nil
}
