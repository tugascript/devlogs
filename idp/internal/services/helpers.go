// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"log/slog"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	AuthMethodPrivateKeyJwt     string = "private_key_jwt"
	AuthMethodClientSecretBasic string = "client_secret_basic"
	AuthMethodClientSecretPost  string = "client_secret_post"
	AuthMethodClientSecretJWT   string = "client_secret_jwt"
	AuthMethodNone              string = "none"

	AuthProviderGoogle    string = "google"
	AuthProviderGitHub    string = "github"
	AuthProviderApple     string = "apple"
	AuthProviderMicrosoft string = "microsoft"
	AuthProviderFacebook  string = "facebook"
	AuthProviderLocal     string = "local"

	TwoFactorNone  string = "none"
	TwoFactorEmail string = "email"
	TwoFactorTotp  string = "totp"

	ResponseTypeCode        string = "code"
	ResponseTypeIdToken     string = "id_token"
	ResponseTypeCodeIdToken string = "code id_token"

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

func mapAuthMethod(authMethod string) (database.AuthMethod, *exceptions.ServiceError) {
	switch authMethod {
	case AuthMethodPrivateKeyJwt:
		return database.AuthMethodPrivateKeyJwt, nil
	case AuthMethodClientSecretBasic:
		return database.AuthMethodClientSecretBasic, nil
	case AuthMethodClientSecretPost:
		return database.AuthMethodClientSecretPost, nil
	case AuthMethodClientSecretJWT:
		return database.AuthMethodClientSecretJwt, nil
	case AuthMethodNone, "":
		return database.AuthMethodNone, nil
	default:
		return "", exceptions.NewValidationError("invalid auth method")
	}
}

func mapResponseTypes(responseTypes []string) ([]database.ResponseType, *exceptions.ServiceError) {
	if len(responseTypes) == 0 {
		return []database.ResponseType{
			database.ResponseTypeCode,
			database.ResponseTypeIDToken,
			database.ResponseTypeCodeidToken,
		}, nil
	}

	var dbResponseTypes []database.ResponseType
	for _, rt := range responseTypes {
		switch utils.Lowered(rt) {
		case ResponseTypeCode:
			dbResponseTypes = append(dbResponseTypes, database.ResponseTypeCode)
		case ResponseTypeIdToken:
			dbResponseTypes = append(dbResponseTypes, database.ResponseTypeIDToken)
		case ResponseTypeCodeIdToken:
			dbResponseTypes = append(dbResponseTypes, database.ResponseTypeCodeidToken)
		default:
			return nil, exceptions.NewValidationError("invalid response type: " + rt)
		}
	}

	return dbResponseTypes, nil
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
	case database.AuthProviderLocal, database.AuthProviderApple, database.AuthProviderFacebook,
		database.AuthProviderGithub, database.AuthProviderGoogle, database.AuthProviderMicrosoft:
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

func mapDomain(baseURI string, domain string) (string, *exceptions.ServiceError) {
	trimmed := strings.TrimSpace(domain)
	if trimmed != "" {
		return trimmed, nil
	}

	parsed, err := url.Parse(strings.TrimSpace(baseURI))
	if err != nil || parsed == nil {
		return "", exceptions.NewValidationError("Invalid client URI")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", exceptions.NewValidationError("Invalid client URI")
	}

	host := parsed.Hostname()
	if strings.TrimSpace(host) == "" {
		return "", exceptions.NewValidationError("Invalid client URI")
	}
	return host, nil
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

func mapCCSecretStorageMode(authMethod string) database.SecretStorageMode {
	if authMethod == AuthMethodClientSecretJWT {
		return database.SecretStorageModeEncrypted
	}

	return database.SecretStorageModeHashed
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
