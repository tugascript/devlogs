// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

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
	AuthProviderCustom           string = "custom"

	TwoFactorNone  string = "none"
	TwoFactorEmail string = "email"
	TwoFactorTotp  string = "totp"

	UsernameColumnEmail    string = "email"
	UsernameColumnUsername string = "username"
	UsernameColumnBoth     string = "both"

	ChallengeMethodPlain = "plain"
	ChallengeMethodS256  = "s256"
)

func (s *Services) buildLogger(requestID, location, function string) *slog.Logger {
	return utils.BuildLogger(s.logger, utils.LoggerOptions{
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
		database.ClaimsAddress, database.ClaimsUpdatedAt:
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
	case database.AuthProviderUsernamePassword,
		database.AuthProviderApple, database.AuthProviderFacebook, database.AuthProviderGithub,
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
		database.ScopesAddress, database.ScopesPhone:
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

func hashChallenge(challenge, challengeMethod string) (string, *exceptions.ServiceError) {
	if challengeMethod == "" {
		return utils.Sha256HashBase64([]byte(challenge)), nil
	}
	switch utils.Lowered(challengeMethod) {
	case ChallengeMethodS256:
		return challenge, nil
	case ChallengeMethodPlain:
		return utils.Sha256HashBase64([]byte(challenge)), nil
	default:
		return "", exceptions.NewValidationError("Invalid challenge method: " + challengeMethod)
	}
}

func mapEmptyURL(url string) pgtype.Text {
	if url == "" {
		return pgtype.Text{Valid: false}
	}

	return pgtype.Text{String: utils.ProcessURL(url), Valid: true}
}

func mapEmptyString(str string) pgtype.Text {
	if str == "" {
		return pgtype.Text{Valid: false}
	}

	return pgtype.Text{String: strings.TrimSpace(str), Valid: true}
}
