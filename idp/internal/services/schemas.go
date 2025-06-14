// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"reflect"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

const (
	schemaLocation string = "schema"

	invalidBodyMsg  string = "invalid body"
	unkwonFieldMsg  string = "unknown field"
	invalidFieldMsg string = "invalid field"
)

type AddressClaim struct {
	Formatted     string `json:"formatted" validate:"omitempty,min=1,max=1000"`
	StreetAddress string `json:"street_address" validate:"omitempty,min=1,max=500"`
	PostalCode    string `json:"postal_code" validate:"omitempty,min=1,max=11"`
	Country       string `json:"country" validate:"omitempty,min=2,max=2,iso3166_1_alpha2"`
	Region        string `json:"region" validate:"omitempty,min=1,max=150"`
	Locality      string `json:"locality" validate:"omitempty,min=1,max=255"`
}

type schemaField struct {
	name      string
	fieldType reflect.Type
	tag       reflect.StructTag
}

var schemaMapping = map[database.Claims]schemaField{
	database.ClaimsName: {
		name:      "Name",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"name" validate:"omitempty,min=1,max=150"`),
	},
	database.ClaimsGivenName: {
		name:      "GivenName",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"given_name" validate:"omitempty,min=1,max=50"`),
	},
	database.ClaimsFamilyName: {
		name:      "FamilyName",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"family_name" validate:"omitempty,min=1,max=50"`),
	},
	database.ClaimsMiddleName: {
		name:      "MiddleName",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"middle_name" validate:"omitempty,min=1,max=50"`),
	},
	database.ClaimsNickname: {
		name:      "Nickname",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"nickname" validate:"omitempty,min=1,max=150"`),
	},
	database.ClaimsProfile: {
		name:      "Profile",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"profile" validate:"omitempty,url"`),
	},
	database.ClaimsPicture: {
		name:      "Picture",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"picture" validate:"omitempty,url"`),
	},
	database.ClaimsWebsite: {
		name:      "Website",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"website" validate:"omitempty,url"`),
	},
	database.ClaimsGender: {
		name:      "Gender",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"gender" validate:"omitempty,oneof=male female other unknown"`),
	},
	database.ClaimsBirthdate: {
		name:      "Birthdate",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"birthdate" validate:"omitempty,datetime=2006-01-02"`),
	},
	database.ClaimsZoneinfo: {
		name:      "Zoneinfo",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"zoneinfo" validate:"omitempty,tzdata"`),
	},
	database.ClaimsLocale: {
		name:      "Locale",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"locale" validate:"omitempty,bcp47_language_tag"`),
	},
	database.ClaimsPhoneNumber: {
		name:      "PhoneNumber",
		fieldType: reflect.TypeOf(""),
		tag:       reflect.StructTag(`json:"phone_number" validate:"omitempty,e164"`),
	},
	database.ClaimsAddress: {
		name:      "Address",
		fieldType: reflect.TypeOf(AddressClaim{}),
		tag:       reflect.StructTag(`json:"address" validate:"omitempty"`),
	},
}

func BuildClaimSchema(claims []database.Claims) reflect.Type {

	fields := make([]reflect.StructField, 0, len(claims))

	for _, claim := range claims {
		schemaField, ok := schemaMapping[claim]
		if !ok {
			continue
		}

		field := reflect.StructField{
			Name:      schemaField.name,
			Type:      schemaField.fieldType,
			Tag:       schemaField.tag,
			Anonymous: false,
		}
		fields = append(fields, field)
	}

	return reflect.StructOf(fields)
}

type UnmarshalSchemaBodyOptions struct {
	RequestID  string
	SchemaType reflect.Type
	Data       map[string]any
}

func (s *Services) UnmarshalSchemaBody(
	ctx context.Context,
	opts UnmarshalSchemaBodyOptions,
) (reflect.Value, *exceptions.ServicErrorWithFields) {
	logger := s.buildLogger(opts.RequestID, schemaLocation, "UnmarshalSchemaBody")
	logger.DebugContext(ctx, "Unmarshalling schema body")

	fieldErrors := make([]exceptions.FieldError, 0)
	value := reflect.New(opts.SchemaType).Elem()
	for fieldName, fieldValue := range opts.Data {
		schemaMap, ok := schemaMapping[database.Claims(fieldName)]
		if !ok {
			logger.WarnContext(ctx, "Field not found in schema", "fieldName", fieldName)
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   string(fieldName),
				Message: unkwonFieldMsg,
				Value:   fieldValue,
			})
			continue
		}

		field := value.FieldByName(schemaMap.name)
		if !(field.IsValid() && field.CanSet()) {
			logger.WarnContext(ctx, "Invalid field name", "fieldName", fieldName)
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   string(fieldName),
				Message: invalidFieldMsg,
				Value:   fieldValue,
			})
			continue
		}

		field.Set(reflect.ValueOf(fieldValue))
	}

	if len(fieldErrors) > 0 {
		return reflect.Value{}, exceptions.NewErrorWithFields(invalidBodyMsg, fieldErrors)
	}

	return value, nil
}
