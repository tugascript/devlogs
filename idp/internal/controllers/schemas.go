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
	"strconv"
	"strings"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const (
	snakeCaseRegex = `^[a-z]+(_[a-z]+)*$`

	snakeCaseErrorMessage       = "must be in snake_case format"
	userSchemaFieldErrorMessage = "must be either string, int, float or bool"
	defaultValueErrorMessage    = "default value must be of the same type as the field type"
	validateErrorMessage        = "one or more validation rules are invalid"
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

var allowedSingleCommonValidateTags = [2]string{
	"required",
	"optional",
}

var allowedSingleStringValidateTags = [104]string{
	"slug",
	"cidr",
	"cidrv4",
	"cidrv6",
	"datauri",
	"fqdn",
	"hostname",
	"hostname_port",
	"hostname_rfc1123",
	"ip",
	"ip4_addr",
	"ip6_addr",
	"ip_addr",
	"ipv4",
	"ipv6",
	"mac",
	"tcp4_addr",
	"tcp6_addr",
	"tcp_addr",
	"udp4_addr",
	"udp6_addr",
	"udp_addr",
	"unix_addr",
	"uri",
	"url",
	"http_url",
	"url_encoded",
	"urn_rfc2141",
	"alpha",
	"alphanum",
	"alphanumunicode",
	"alphaunicode",
	"ascii",
	"boolean",
	"number",
	"numeric",
	"lowercase",
	"uppercase",
	"base64",
	"base64url",
	"base64rawurl",
	"bic",
	"bcp47_language_tag",
	"btc_addr",
	"btc_addr_bech32",
	"credit_card",
	"mongodb",
	"mongodb_connection_string",
	"cron",
	"spicedb",
	"datetime",
	"e164",
	"ein",
	"email",
	"eth_addr",
	"hexadecimal",
	"hexcolor",
	"hsl",
	"hsla",
	"html",
	"html_encoded",
	"isbn",
	"isbn10",
	"isbn13",
	"issn",
	"iso3166_1_alpha2",
	"iso3166_1_alpha3",
	"iso3166_1_alpha_numeric",
	"iso3166_2",
	"iso4217",
	"json",
	"jwt",
	"latitude",
	"longitude",
	"luhn_checksum",
	"postcode_iso3166_alpha2",
	"postcode_iso3166_alpha2_field",
	"rgb",
	"rgba",
	"ssn",
	"timezone",
	"uuid",
	"uuid3",
	"uuid3_rfc4122",
	"uuid4",
	"uuid4_rfc4122",
	"uuid5",
	"uuid5_rfc4122",
	"uuid_rfc4122",
	"md4",
	"md5",
	"sha256",
	"sha384",
	"sha512",
	"ripemd128",
	"ripemd160",
	"tiger128",
	"tiger160",
	"tiger192",
	"semver",
	"ulid",
	"cve",
	"iscolor",
	"country_code",
}

var allowedNumericNumericValidateTags = [2]string{
	"max",
	"min",
}

var allowedStringNumericValidateTags = [3]string{
	"len",
	"max",
	"min",
}

var allowedStringStringValidateTags = [2]string{"oneof", "regex"}

func isValidValidateTag(val string, fieldType string) bool {
	for _, allowedTag := range allowedSingleCommonValidateTags {
		if val == allowedTag {
			return true
		}
	}

	switch fieldType {
	case "string":
		for _, allowedTag := range allowedSingleStringValidateTags {
			if val == allowedTag {
				return true
			}
		}

		arr := strings.Split(val, "=")
		if len(arr) != 2 {
			return false
		}

		for _, allowedTag := range allowedStringStringValidateTags {
			if arr[0] == allowedTag {
				return true
			}
		}
		for _, allowedTag := range allowedStringNumericValidateTags {
			if arr[0] == allowedTag {
				if _, err := strconv.Atoi(arr[1]); err != nil {
					return false
				}
				return true
			}
		}
	case "int", "float":
		arr := strings.Split(val, "=")
		for _, allowedTag := range allowedNumericNumericValidateTags {
			if arr[0] == allowedTag {
				if _, err := strconv.Atoi(arr[1]); err != nil {
					return false
				}
				return true
			}
		}
	default:
		return false
	}
	return false
}

type ValidateBuilder map[string]bool

func (v ValidateBuilder) AddValidateTag(tag string) {
	if tag == "optional" {
		if _, ok := (v)["required"]; ok {
			return
		}
	} else if tag == "required" {
		if _, ok := (v)["optional"]; ok {
			return
		}
	}

	if _, ok := (v)[tag]; !ok {
		(v)[tag] = true
	}
}

func (v ValidateBuilder) ValidateTags(fieldType string) error {
	for tag := range v {
		if !isValidValidateTag(tag, fieldType) {
			return fmt.Errorf("invalid validate tag: %s for field type: %s", tag, fieldType)
		}
	}
	return nil
}

func (v ValidateBuilder) Build() string {
	if len(v) == 0 {
		return ""
	}

	var sb strings.Builder
	for tag := range v {
		if sb.Len() > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(tag)
	}

	return sb.String()
}

func newValidateTags(field *bodies.SchemaFieldBody) (string, error) {
	validateBuilder := make(ValidateBuilder)
	if field.Required {
		validateBuilder.AddValidateTag("required")
	} else {
		validateBuilder.AddValidateTag("optional")
	}

	if len(field.Validate) > 0 {
		for _, tag := range field.Validate {
			validateBuilder.AddValidateTag(tag)
		}
	}

	if err := validateBuilder.ValidateTags(field.Type); err != nil {
		return "", err
	}

	return validateBuilder.Build(), nil
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

		validateTags, err := newValidateTags(&field)
		if err != nil {
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   fmt.Sprintf("%s.validate", fieldName),
				Value:   field.Validate,
				Message: validateErrorMessage,
			})
		}

		if len(fieldErrors) == 0 {
			schema[fieldName] = services.SchemaField{
				Type:     field.Type,
				Unique:   field.Unique,
				Required: field.Required,
				Default:  field.Default,
				Validate: validateTags,
			}
		}
	}

	if len(fieldErrors) > 0 {
		return nil, exceptions.NewValidationErrorResponse(exceptions.ValidationResponseLocationBody, fieldErrors)
	}

	return schema, nil
}
