// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oauth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tugascript/devlogs/idp/internal/exceptions"

	"google.golang.org/api/people/v1"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	googleLocation string = "google"

	googleUserURL string = "https://www.googleapis.com/oauth2/v3/userinfo"
	googleMeURL   string = "https://people.googleapis.com/v1/me"
)

var googleScopes = oauthScopes{
	email:    "https://www.googleapis.com/auth/userinfo.email",
	profile:  "https://www.googleapis.com/auth/userinfo.profile",
	birthday: "https://www.googleapis.com/auth/user.birthday.read",
	location: "https://www.googleapis.com/auth/user.addresses.read",
	gender:   "https://www.googleapis.com/auth/user.gender.read",
}

type GoogleUserResponse struct {
	Sub           string `json:"sub"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale,omitempty"`
	HD            string `json:"hd"`
	gender        string
	location      people.Address
	birthday      string
}

func (ur *GoogleUserResponse) setLocation(loc people.Address) {
	ur.location = loc
}

func (ur *GoogleUserResponse) Location() people.Address {
	return ur.location
}

func (ur *GoogleUserResponse) setGender(g people.Gender) {
	ur.gender = g.Value
}

func (ur *GoogleUserResponse) Gender() string {
	return ur.gender
}

func (ur *GoogleUserResponse) setBirthday(bd people.Birthday) {
	if bd.Date != nil {
		ur.birthday = fmt.Sprintf("%d-%s-%s",
			bd.Date.Year,
			utils.AppendZeroToDecades(bd.Date.Month),
			utils.AppendZeroToDecades(bd.Date.Day),
		)
		return
	}

	ur.birthday = bd.Text
}

func (ur *GoogleUserResponse) Birthday() string {
	return ur.birthday
}

func (ur *GoogleUserResponse) ToUserData() UserData {
	address := ur.Location()
	return UserData{
		Name:       ur.Name,
		FirstName:  ur.GivenName,
		LastName:   ur.FamilyName,
		Username:   utils.Slugify(ur.Name),
		Picture:    ur.Picture,
		Email:      utils.Lowered(ur.Email),
		IsVerified: ur.EmailVerified,
		Gender:     ur.Gender(),
		BirthDate:  ur.Birthday(),
		Location: UserLocation{
			City:    address.City,
			Region:  address.Region,
			Country: address.CountryCode,
		},
	}
}

type GoogleMeResponse struct {
	Addresses []people.Address  `json:"addresses,omitempty"`
	Birthdays []people.Birthday `json:"birthdays,omitempty"`
	Genders   []people.Gender   `json:"genders,omitempty"`
}

func (p *Providers) GetGoogleAuthorizationURL(
	ctx context.Context,
	opts AuthorizationURLOptions,
) (string, string, *exceptions.ServiceError) {
	return getAuthorizationURL(ctx, getAuthorizationURLOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Layer:     logLayer,
			Location:  googleLocation,
			Method:    "GetGoogleAuthorizationURL",
			RequestID: opts.RequestID,
		}),
		cfg:         p.google,
		redirectURL: opts.RedirectURL,
		oas:         googleScopes,
		scopes:      opts.Scopes,
	})
}

func (p *Providers) GetGoogleAccessToken(
	ctx context.Context,
	opts AccessTokenOptions,
) (string, *exceptions.ServiceError) {
	return getAccessToken(ctx, getAccessTokenOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Layer:     logLayer,
			Location:  googleLocation,
			Method:    "GetGoogleAccessToken",
			RequestID: opts.RequestID,
		}),
		cfg:         p.google,
		redirectURL: opts.RedirectURL,
		oas:         googleScopes,
		scopes:      opts.Scopes,
		code:        opts.Code,
	})
}

func (p *Providers) GetGoogleUserData(
	ctx context.Context,
	opts UserDataOptions,
) (UserData, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  googleLocation,
		Method:    "GetGoogleUserData",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting Google user data...")

	body, status, err := getUserResponse(logger, ctx, googleUserURL, opts.Token)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get Google user data", "error", err)
		return UserData{}, exceptions.NewServerError()
	}

	userRes := GoogleUserResponse{}
	if err := json.Unmarshal(body, &userRes); err != nil {
		logger.ErrorContext(ctx, "Failed to parse Google user data", "error", err)

		if status > 0 && status < 500 {
			return UserData{}, exceptions.NewUnauthorizedError()
		}

		return UserData{}, exceptions.NewServerError()
	}

	if opts.Scopes != nil {
		var extPrms extraParams
		for _, s := range opts.Scopes {
			switch s {
			case ScopeGender:
				extPrms.addParam("genders")
			case ScopeLocation:
				extPrms.addParam("addresses")
			case ScopeBirthday:
				extPrms.addParam("birthdays")
			}
		}

		if !extPrms.isEmpty() {
			body, status, err := getUserResponse(logger, ctx, googleMeURL, opts.Token)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to get ME data", "error", err)

				if status > 0 && status < 500 {
					return UserData{}, exceptions.NewForbiddenError()
				}

				return UserData{}, exceptions.NewServerError()
			}

			meRes := GoogleMeResponse{}
			if err := json.Unmarshal(body, &meRes); err != nil {
				logger.ErrorContext(ctx, "Failed to parse Google ME data", "error", err)
				return UserData{}, exceptions.NewServerError()
			}

			if len(meRes.Addresses) > 0 {
				userRes.setLocation(meRes.Addresses[0])
			}
			if len(meRes.Birthdays) > 0 {
				userRes.setBirthday(meRes.Birthdays[0])
			}
			if len(meRes.Genders) > 0 {
				userRes.setGender(meRes.Genders[0])
			}
		}
	}

	return userRes.ToUserData(), nil
}
