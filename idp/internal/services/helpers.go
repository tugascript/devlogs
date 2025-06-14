// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"log/slog"
	"strings"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	AuthMethodBothClientSecrets string = "both_client_secrets"
	AuthMethodPrivateKeyJwt     string = "private_key_jwt"
	AuthMethodClientSecretBasic string = "client_secret_basic"
	AuthMethodClientSecretPost  string = "client_secret_post"
	AuthMethodNone              string = "none"

	AuthProviderGoogle           string = "google"
	AuthProviderGitHub           string = "github"
	AuthProviderApple            string = "apple"
	AuthProviderMicrosoft        string = "microsoft"
	AuthProviderFacebook         string = "facebook"
	AuthProviderUsernamePassword string = "username_password"

	TwoFactorNone  string = "none"
	TwoFactorEmail string = "email"
	TwoFactorTotp  string = "totp"

	UsernameColumnEmail    string = "email"
	UsernameColumnUsername string = "username"
	UsernameColumnBoth     string = "both"
)

func (s *Services) buildLogger(requestID, location, function string) *slog.Logger {
	return utils.BuildLogger(s.logger, utils.LoggerOptions{
		Layer:     utils.ServicesLogLayer,
		Location:  location,
		Method:    function,
		RequestID: requestID,
	})
}

func extractAuthHeaderToken(ah string) (string, *exceptions.ServiceError) {
	if ah == "" {
		return "", exceptions.NewUnauthorizedError()
	}

	ahSlice := strings.Split(strings.TrimSpace(ah), " ")
	if len(ahSlice) != 2 {
		return "", exceptions.NewUnauthorizedError()
	}
	if utils.Lowered(ahSlice[0]) != "bearer" {
		return "", exceptions.NewUnauthorizedError()
	}

	return ahSlice[1], nil
}

func mapAuthMethod(authMethod string) ([]database.AuthMethod, *exceptions.ServiceError) {
	if authMethod == AuthMethodBothClientSecrets {
		return []database.AuthMethod{
			database.AuthMethodClientSecretBasic,
			database.AuthMethodClientSecretPost,
		}, nil
	}

	am := database.AuthMethod(authMethod)
	switch am {
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost,
		database.AuthMethodPrivateKeyJwt, database.AuthMethodNone:
		return []database.AuthMethod{am}, nil
	default:
		return nil, exceptions.NewValidationError("invalid auth method")
	}
}

func mapClaim(claim string) (database.Claims, *exceptions.ServiceError) {
	if len(claim) < 3 {
		return "", exceptions.NewValidationError("invalid claim")
	}

	dbClaim := database.Claims(claim)
	switch dbClaim {
	case database.ClaimsSub, database.ClaimsName, database.ClaimsGivenName,
		database.ClaimsFamilyName, database.ClaimsMiddleName, database.ClaimsNickname,
		database.ClaimsPreferredUsername, database.ClaimsProfile, database.ClaimsPicture,
		database.ClaimsWebsite, database.ClaimsEmail, database.ClaimsEmailVerified,
		database.ClaimsGender, database.ClaimsBirthdate, database.ClaimsZoneinfo,
		database.ClaimsLocale, database.ClaimsPhoneNumber, database.ClaimsPhoneNumberVerified,
		database.ClaimsAddress, database.ClaimsUpdatedAt, database.ClaimsUserRoles:
		return dbClaim, nil
	default:
		return "", exceptions.NewValidationError("invalid claim")
	}
}

func mapAuthProvider(provider string) (database.AuthProvider, *exceptions.ServiceError) {
	if len(provider) < 5 {
		return "", exceptions.NewValidationError("invalid provider")
	}

	authProvider := database.AuthProvider(provider)
	switch authProvider {
	case database.AuthProviderUsernamePassword, database.AuthProviderApple, database.AuthProviderGithub,
		database.AuthProviderGoogle, database.AuthProviderMicrosoft, database.AuthProviderCustom:
		return authProvider, nil
	default:
		return "", exceptions.NewValidationError("invalid provider")
	}
}

func mapScope(scope string) (database.Scopes, *exceptions.ServiceError) {
	if len(scope) < 4 {
		return "", exceptions.NewValidationError("invalid scope")
	}

	dbScope := database.Scopes(scope)
	switch dbScope {
	case database.ScopesOpenid, database.ScopesEmail, database.ScopesProfile,
		database.ScopesAddress, database.ScopesPhone, database.ScopesUserRoles:
		return dbScope, nil
	default:
		return "", exceptions.NewValidationError("invalid scope")
	}
}

func mapTwoFactorType(twoFactorType string) (database.TwoFactorType, *exceptions.ServiceError) {
	if len(twoFactorType) < 4 {
		return "", exceptions.NewValidationError("invalid two factor type")
	}

	dbTwoFactorType := database.TwoFactorType(twoFactorType)
	switch dbTwoFactorType {
	case database.TwoFactorTypeNone, database.TwoFactorTypeEmail, database.TwoFactorTypeTotp:
		return dbTwoFactorType, nil
	default:
		return "", exceptions.NewValidationError("invalid two factor type")
	}
}

// func mapTokenCryptoSuite[T string](cryptoSuite T) (database.TokenCryptoSuite, *exceptions.ServiceError) {
// 	if len(cryptoSuite) != 5 {
// 		return "", exceptions.NewValidationError("invalid crypto suite")
// 	}

// 	dbCryptoSuite := database.TokenCryptoSuite(cryptoSuite)
// 	switch dbCryptoSuite {
// 	case database.TokenCryptoSuiteES256, database.TokenCryptoSuiteEdDSA:
// 		return dbCryptoSuite, nil
// 	default:
// 		return "", exceptions.NewValidationError("invalid crypto suite")
// 	}
// }
