// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	helpersLocation string = "helpers"

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
	ResponseTypeCodeIdToken string = "code id_token"

	UsernameColumnEmail    string = "email"
	UsernameColumnUsername string = "username"
	UsernameColumnBoth     string = "both"

	GrantTypeAuthorizationCode string = "authorization_code"
	GrantTypeRefreshToken      string = "refresh_token"
	GrantTypeClientCredentials string = "client_credentials"
	GrantTypeDeviceCode        string = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTypeJwtBearer         string = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	SubjectTypePublic   string = "public"
	SubjectTypePairwise string = "pairwise"

	ChallengeMethodPlain = "plain"
	ChallengeMethodS256  = "s256"

	TokenEncryptionAlgorithmRSAOAEP256   string = "RSA-OAEP-256"
	TokenEncryptionAlgorithmECDHES       string = "ECDH-ES"
	TokenEncryptionAlgorithmECDHESA256KW string = "ECDH-ES+A256KW"

	TokenEncryptionEncodingA128CBCHS256 string = "A128CBC-HS256"
	TokenEncryptionEncodingA192CBCHS384 string = "A192CBC-HS384"
	TokenEncryptionEncodingA256CBCHS512 string = "A256CBC-HS512"
	TokenEncryptionEncodingA128GCM      string = "A128GCM"
	TokenEncryptionEncodingA192GCM      string = "A192GCM"
	TokenEncryptionEncodingA256GCM      string = "A256GCM"
)

func (s *Services) buildLogger(requestID, location, function string) *slog.Logger {
	return utils.BuildLogger(s.logger, utils.LoggerOptions{
		Location:  location,
		Method:    function,
		RequestID: requestID,
	})
}

func (s *Services) mapQueries(qrs *database.Queries) *database.Queries {
	if qrs != nil {
		return qrs
	}
	return s.database.Queries
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

func mapResponseTypesWithDefault(responseTypes []string) ([]database.ResponseType, *exceptions.ServiceError) {
	if len(responseTypes) == 0 {
		return []database.ResponseType{
			database.ResponseTypeCode,
			database.ResponseTypeCodeidToken,
		}, nil
	}

	var dbResponseTypes []database.ResponseType
	for _, rt := range responseTypes {
		switch utils.Lowered(rt) {
		case ResponseTypeCode:
			dbResponseTypes = append(dbResponseTypes, database.ResponseTypeCode)
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

func mapCCSecretStorageMode(authMethod string) database.SecretStorageMode {
	if authMethod == AuthMethodClientSecretJWT {
		return database.SecretStorageModeEncrypted
	}

	return database.SecretStorageModeHashed
}

func hashChallenge(challenge, challengeMethod string) (string, *exceptions.ServiceError) {
	if challengeMethod == "" {
		return utils.Sha256HashBase64(challenge), nil
	}
	switch utils.Lowered(challengeMethod) {
	case ChallengeMethodS256:
		return challenge, nil
	case ChallengeMethodPlain:
		return utils.Sha256HashBase64(challenge), nil
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

func mapEmptyBigInt(bigInt int64) pgtype.Int8 {
	if bigInt == 0 {
		return pgtype.Int8{Valid: false}
	}

	return pgtype.Int8{Int64: bigInt, Valid: true}
}

func mapEmptySubjectType(subjectType string) (database.NullClientSubjectType, *exceptions.ServiceError) {
	if subjectType == "" {
		return database.NullClientSubjectType{Valid: false}, nil
	}

	switch utils.Lowered(subjectType) {
	case SubjectTypePublic:
		return database.NullClientSubjectType{ClientSubjectType: database.ClientSubjectTypePublic, Valid: true}, nil
	case SubjectTypePairwise:
		return database.NullClientSubjectType{ClientSubjectType: database.ClientSubjectTypePairwise, Valid: true}, nil
	default:
		return database.NullClientSubjectType{Valid: false}, exceptions.NewValidationError("invalid subject type: " + subjectType)
	}
}

func mapEmptyTokenCryptoSuite(tokenCryptoSuite string) (database.NullTokenCryptoSuite, *exceptions.ServiceError) {
	if tokenCryptoSuite == "" {
		return database.NullTokenCryptoSuite{Valid: false}, nil
	}

	cryptoSuite, err := mapCryptoSuite(utils.SupportedCryptoSuite(tokenCryptoSuite))
	if err != nil {
		return database.NullTokenCryptoSuite{Valid: false}, exceptions.NewValidationError("invalid token crypto suite: " + tokenCryptoSuite)
	}

	return database.NullTokenCryptoSuite{TokenCryptoSuite: cryptoSuite, Valid: true}, nil
}

func mapTokenCryptoSuiteWithDefault(tokenCryptoSuite string) (database.TokenCryptoSuite, *exceptions.ServiceError) {
	if tokenCryptoSuite == "" {
		return database.TokenCryptoSuiteES256, nil
	}

	cryptoSuite, err := mapCryptoSuite(utils.SupportedCryptoSuite(tokenCryptoSuite))
	if err != nil {
		return "", exceptions.NewValidationError("invalid token crypto suite: " + tokenCryptoSuite)
	}

	return cryptoSuite, nil
}

func mapEmptyTokenEncryptionAlgorithm(tokenEncryptionAlgorithm string) (database.NullTokenEncryptionAlgorithm, *exceptions.ServiceError) {
	if tokenEncryptionAlgorithm == "" {
		return database.NullTokenEncryptionAlgorithm{Valid: false}, nil
	}

	switch utils.Lowered(tokenEncryptionAlgorithm) {
	case TokenEncryptionAlgorithmRSAOAEP256:
		return database.NullTokenEncryptionAlgorithm{TokenEncryptionAlgorithm: database.TokenEncryptionAlgorithmRSAOAEP256, Valid: true}, nil
	case TokenEncryptionAlgorithmECDHES:
		return database.NullTokenEncryptionAlgorithm{TokenEncryptionAlgorithm: database.TokenEncryptionAlgorithmECDHES, Valid: true}, nil
	case TokenEncryptionAlgorithmECDHESA256KW:
		return database.NullTokenEncryptionAlgorithm{TokenEncryptionAlgorithm: database.TokenEncryptionAlgorithmECDHESA256KW, Valid: true}, nil
	default:
		return database.NullTokenEncryptionAlgorithm{Valid: false}, exceptions.NewValidationError("invalid token encryption algorithm: " + tokenEncryptionAlgorithm)
	}
}

func mapEmptyTokenEncryptionEncoding(
	nullTokenEncryptionAlgorithm database.NullTokenEncryptionAlgorithm,
	tokenEncryptionEncoding string,
) (database.NullTokenEncryptionEncoding, *exceptions.ServiceError) {
	if !nullTokenEncryptionAlgorithm.Valid {
		return database.NullTokenEncryptionEncoding{Valid: false}, nil
	}
	if tokenEncryptionEncoding == "" {
		return database.NullTokenEncryptionEncoding{Valid: true, TokenEncryptionEncoding: database.TokenEncryptionEncodingA128CBCHS256}, nil
	}

	switch utils.Lowered(tokenEncryptionEncoding) {
	case TokenEncryptionEncodingA128CBCHS256:
		return database.NullTokenEncryptionEncoding{Valid: true, TokenEncryptionEncoding: database.TokenEncryptionEncodingA128CBCHS256}, nil
	case TokenEncryptionEncodingA192CBCHS384:
		return database.NullTokenEncryptionEncoding{Valid: true, TokenEncryptionEncoding: database.TokenEncryptionEncodingA192CBCHS384}, nil
	case TokenEncryptionEncodingA256CBCHS512:
		return database.NullTokenEncryptionEncoding{Valid: true, TokenEncryptionEncoding: database.TokenEncryptionEncodingA256CBCHS512}, nil
	case TokenEncryptionEncodingA128GCM:
		return database.NullTokenEncryptionEncoding{Valid: true, TokenEncryptionEncoding: database.TokenEncryptionEncodingA128GCM}, nil
	case TokenEncryptionEncodingA192GCM:
		return database.NullTokenEncryptionEncoding{Valid: true, TokenEncryptionEncoding: database.TokenEncryptionEncodingA192GCM}, nil
	case TokenEncryptionEncodingA256GCM:
		return database.NullTokenEncryptionEncoding{Valid: true, TokenEncryptionEncoding: database.TokenEncryptionEncodingA256GCM}, nil
	default:
		return database.NullTokenEncryptionEncoding{Valid: false}, exceptions.NewValidationError("invalid token encryption encoding: " + tokenEncryptionEncoding)
	}
}

type verifyTXTRecordOptions struct {
	requestID string
	host      string
	domain    string
	prefix    string
	code      string
}

func (s *Services) verifyTXTRecord(
	ctx context.Context,
	opts verifyTXTRecordOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, helpersLocation, "verifyTXTRecord").With(
		"host", opts.host,
		"domain", opts.domain,
		"prefix", opts.prefix,
	)
	logger.InfoContext(ctx, "Verifying TXT record...")

	records, err := net.LookupTXT(fmt.Sprintf("%s.%s", opts.host, opts.domain))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to lookup TXT record", "error", err)
		return exceptions.NewValidationError("TXT record not found")
	}

	hashSet := utils.SliceToHashSet(records)
	value := fmt.Sprintf("%s=%s", opts.prefix, opts.code)
	if !hashSet.Contains(value) {
		logger.InfoContext(ctx, "TXT code not found in records")
		return exceptions.NewValidationError("TXT code not found in records")
	}

	logger.InfoContext(ctx, "TXT code found in records")
	return nil
}

func mapEmptyJWKs(logger *slog.Logger, ctx context.Context, jsonJWKs []string) ([]byte, *exceptions.ServiceError) {
	var jwks []byte

	if len(jsonJWKs) > 0 {
		rawJWKs := make([]json.RawMessage, 0, len(jsonJWKs))
		for _, jwk := range jsonJWKs {
			jwk, err := utils.JsonToJWK([]byte(jwk))
			if err != nil {
				logger.ErrorContext(ctx, "Failed to parse JWK", "error", err)
				return nil, exceptions.NewInternalServerError()
			}
			jwkBytes, err := jwk.MarshalJSON()
			if err != nil {
				logger.ErrorContext(ctx, "Failed to marshal JWK", "error", err)
				return nil, exceptions.NewInternalServerError()
			}
			rawJWKs = append(rawJWKs, jwkBytes)
		}

		var err error
		jwks, err = json.Marshal(rawJWKs)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to marshal JWKS", "error", err)
			return nil, exceptions.NewInternalServerError()
		}
	}

	return jwks, nil
}

func mapGrantType(grantType string) (database.GrantType, *exceptions.ServiceError) {
	switch utils.Lowered(grantType) {
	case GrantTypeAuthorizationCode:
		return database.GrantTypeAuthorizationCode, nil
	case GrantTypeRefreshToken:
		return database.GrantTypeRefreshToken, nil
	case GrantTypeClientCredentials:
		return database.GrantTypeClientCredentials, nil
	case GrantTypeDeviceCode:
		return database.GrantTypeUrnIetfParamsOauthGrantTypeDeviceCode, nil
	case GrantTypeJwtBearer:
		return database.GrantTypeUrnIetfParamsOauthGrantTypeJwtBearer, nil
	default:
		return "", exceptions.NewValidationError("invalid grant type: " + grantType)
	}
}
