// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oauth

import (
	"context"
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/exceptions"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	microsoftLocation string = "microsoft"

	microsoftUserURL string = "https://graph.microsoft.com/v1.0/me"
)

var microsoftScopes = oauthScopes{
	email:   "User.Read",
	profile: "User.ReadBasic.All",
}

type MicrosoftUserResponse struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName,omitempty"`
	GivenName         string `json:"givenName,omitempty"`
	Surname           string `json:"surname,omitempty"`
	JobTitle          string `json:"jobTitle,omitempty"`
	Mail              string `json:"mail"`
	MobilePhone       string `json:"mobilePhone,omitempty"`
	OfficeLocation    string `json:"officeLocation,omitempty"`
	PreferredLanguage string `json:"preferredLanguage,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
}

func (mu *MicrosoftUserResponse) ToUserData() UserData {
	return UserData{
		Name:       mu.DisplayName,
		FirstName:  mu.GivenName,
		LastName:   mu.Surname,
		Username:   utils.Slugify(mu.DisplayName),
		Email:      utils.Lowered(mu.Mail),
		IsVerified: true,
	}
}

func (p *Providers) GetMicrosoftAuthorizationURL(
	ctx context.Context,
	opts AuthorizationURLOptions,
) (string, string, *exceptions.ServiceError) {
	return getAuthorizationURL(ctx, getAuthorizationURLOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Layer:     logLayer,
			Location:  microsoftLocation,
			Method:    "GetMicrosoftAuthorizationURL",
			RequestID: opts.RequestID,
		}),
		cfg:         p.microsoft,
		redirectURL: opts.RedirectURL,
		oas:         microsoftScopes,
		scopes:      opts.Scopes,
	})
}

func (p *Providers) GetMicrosoftAccessToken(
	ctx context.Context,
	opts AccessTokenOptions,
) (string, *exceptions.ServiceError) {
	return getAccessToken(ctx, getAccessTokenOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Layer:     logLayer,
			Location:  googleLocation,
			Method:    "GetMicrosoftAccessToken",
			RequestID: opts.RequestID,
		}),
		cfg:         p.microsoft,
		redirectURL: opts.RedirectURL,
		oas:         microsoftScopes,
		scopes:      opts.Scopes,
		code:        opts.Code,
	})
}

func (p *Providers) GetMicrosoftUserData(
	ctx context.Context,
	opts UserDataOptions,
) (UserData, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  microsoftLocation,
		Method:    "GetMicrosoftUserData",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting Microsoft user data...")

	body, status, err := getUserResponse(logger, ctx, microsoftUserURL, opts.Token)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get Microsoft user data", "error", err)

		if status > 0 && status < 500 {
			return UserData{}, exceptions.NewUnauthorizedError()
		}

		return UserData{}, exceptions.NewServerError()
	}

	userRes := MicrosoftUserResponse{}
	if err := json.Unmarshal(body, &userRes); err != nil {
		logger.ErrorContext(ctx, "Failed to parse Microsoft user data", "error", err)
		return UserData{}, exceptions.NewServerError()
	}

	return userRes.ToUserData(), nil
}

func (p *Providers) GetMicrosoftUserMap(
	ctx context.Context,
	opts UserDataOptions,
) (string, map[string]any, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  microsoftLocation,
		Method:    "GetMicrosoftUserMap",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting Microsoft user map...")

	body, status, err := getUserResponse(logger, ctx, microsoftUserURL, opts.Token)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get Microsoft user data", "error", err)

		if status > 0 && status < 500 {
			return "", nil, exceptions.NewUnauthorizedError()
		}

		return "", nil, exceptions.NewServerError()
	}

	userMap := map[string]any{}
	if err := json.Unmarshal(body, &userMap); err != nil {
		logger.ErrorContext(ctx, "Failed to parse Microsoft user data", "error", err)
		return "", nil, exceptions.NewServerError()
	}

	email, ok := userMap["mail"].(string)
	if !ok {
		email, ok = userMap["userPrincipalName"].(string)
		if !ok {
			logger.ErrorContext(ctx, "Failed to get email from Microsoft user data")
			return "", nil, exceptions.NewServerError()
		}
	}
	if email == "" {
		logger.WarnContext(ctx, "Email is empty in Microsoft user data")
		return "", nil, exceptions.NewUnauthorizedError()
	}

	return email, userMap, nil
}
