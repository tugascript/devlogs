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
	"strings"

	"github.com/tugascript/devlogs/idp/internal/exceptions"

	"github.com/biter777/countries"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	facebookLocation string = "facebook"

	facebookUserURL string = "https://graph.facebook.com/v22.0/me"
)

var facebookScopes = oauthScopes{
	email:    "email",
	profile:  "public_profile",
	birthday: "user_birthday",
	location: "user_location",
	gender:   "gender",
}

type FacebookPictureData struct {
	Height       int    `json:"height,omitempty"`
	Width        int    `json:"width,omitempty"`
	URL          string `json:"url"`
	IsSilhouette bool   `json:"is_silhouette,omitempty"`
}

type FacebookPicture struct {
	Data FacebookPictureData `json:"data,omitempty"`
}

type FacebookLocation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type FacebookUserResponse struct {
	ID         string           `json:"id,omitempty"`
	FirstName  string           `json:"first_name,omitempty"`
	LastName   string           `json:"last_name,omitempty"`
	MiddleName string           `json:"middle_name,omitempty"`
	Name       string           `json:"name,omitempty"`
	NameFormat string           `json:"name_format,omitempty"`
	ShortName  string           `json:"short_name,omitempty"`
	Email      string           `json:"email"`
	Gender     string           `json:"gender,omitempty"`
	Picture    FacebookPicture  `json:"picture,omitempty"`
	Birthday   string           `json:"birthday,omitempty"`
	Location   FacebookLocation `json:"location,omitempty"`
}

func processFacebookBirthDate(birthday string) string {
	if birthday == "" {
		return birthday
	}

	bdSlice := strings.Split(birthday, "/")
	return fmt.Sprintf("%s-%s-%s", bdSlice[2], bdSlice[0], bdSlice[1])
}

func processFacebookLocation(location string) UserLocation {
	if location == "" {
		return UserLocation{}
	}

	locSlice := strings.Split(location, ", ")
	country := countries.ByName(locSlice[1])
	var region string
	if country == countries.Unknown {
		country = countries.US
		region = locSlice[1]
	}

	return UserLocation{
		City:    locSlice[0],
		Region:  region,
		Country: country.Alpha2(),
	}
}

func (fu *FacebookUserResponse) ToUserData() UserData {
	return UserData{
		Name:       fu.Name,
		FirstName:  fu.FirstName,
		LastName:   fu.LastName,
		Username:   utils.Slugify(fu.Name),
		Picture:    fu.Picture.Data.URL,
		Email:      utils.Lowered(fu.Email),
		Gender:     fu.Gender,
		BirthDate:  processFacebookBirthDate(fu.Birthday),
		Location:   processFacebookLocation(fu.Location.Name),
		IsVerified: true,
	}
}

var facebookProfileParams = [8]string{
	"id",
	"first_name",
	"last_name",
	"middle_name",
	"name",
	"name_format",
	"picture",
	"short_name",
}

func (p *Providers) GetFacebookAuthorizationURL(
	ctx context.Context,
	opts AuthorizationURLOptions,
) (string, string, *exceptions.ServiceError) {
	return getAuthorizationURL(ctx, getAuthorizationURLOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Location:  facebookLocation,
			Method:    "GetFacebookAuthorizationURL",
			RequestID: opts.RequestID,
		}),
		cfg:         p.facebook,
		redirectURL: opts.RedirectURL,
		oas:         facebookScopes,
		scopes:      opts.Scopes,
	})
}

func (p *Providers) GetFacebookAccessToken(
	ctx context.Context,
	opts AccessTokenOptions,
) (string, *exceptions.ServiceError) {
	return getAccessToken(ctx, getAccessTokenOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Location:  facebookLocation,
			Method:    "GetFacebookAccessToken",
			RequestID: opts.RequestID,
		}),
		cfg:         p.facebook,
		redirectURL: opts.RedirectURL,
		oas:         facebookScopes,
		scopes:      opts.Scopes,
		code:        opts.Code,
	})
}

func buildFacebookParams(scopes []string) extraParams {
	extPrms := extraParams{params: "email"}

	if len(scopes) == 0 {
		return extPrms
	}

	for _, s := range scopes {
		switch s {
		case ScopeProfile:
			for _, sp := range facebookProfileParams {
				extPrms.addParam(sp)
			}
		case ScopeBirthday:
			extPrms.addParam("birthday")
		case ScopeGender:
			extPrms.addParam("gender")
		case ScopeLocation:
			extPrms.addParam("location")
		}
	}

	return extPrms
}

func (p *Providers) GetFacebookUserData(
	ctx context.Context,
	opts UserDataOptions,
) (UserData, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Location:  facebookLocation,
		Method:    "GetFacebookUserData",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting Facebook user data...")

	extPrms := buildFacebookParams(opts.Scopes)

	body, status, err := getUserResponse(
		logger,
		ctx,
		fmt.Sprintf("%s?fields=%s", facebookUserURL, extPrms),
		opts.Token,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get Facebook user data", "error", err)

		if status > 0 && status < 500 {
			return UserData{}, exceptions.NewUnauthorizedError()
		}

		return UserData{}, exceptions.NewServerError()
	}

	userRes := FacebookUserResponse{}
	if err := json.Unmarshal(body, &userRes); err != nil {
		logger.ErrorContext(ctx, "Failed to parse Facebook user data", "error", err)
		return UserData{}, exceptions.NewServerError()
	}

	return userRes.ToUserData(), nil
}

func (p *Providers) GetFacebookUserMap(
	ctx context.Context,
	opts UserDataOptions,
) (string, map[string]any, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Location:  facebookLocation,
		Method:    "GetFacebookUserMap",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting Facebook user map...")

	extPrms := buildFacebookParams(opts.Scopes)
	body, status, err := getUserResponse(
		logger,
		ctx,
		fmt.Sprintf("%s?fields=%s", facebookUserURL, extPrms),
		opts.Token,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get Facebook user data", "error", err)

		if status > 0 && status < 500 {
			return "", nil, exceptions.NewUnauthorizedError()
		}

		return "", nil, exceptions.NewServerError()
	}

	userRes := make(map[string]any)
	if err := json.Unmarshal(body, &userRes); err != nil {
		logger.ErrorContext(ctx, "Failed to parse Facebook user data", "error", err)
		return "", nil, exceptions.NewServerError()
	}

	if len(userRes) == 0 {
		logger.WarnContext(ctx, "Empty user data")
		return "", nil, exceptions.NewUnauthorizedError()
	}

	email, ok := userRes["email"].(string)
	if !ok {
		logger.ErrorContext(ctx, "Failed to get email from user data")
		return "", nil, exceptions.NewServerError()
	}
	if email == "" {
		logger.WarnContext(ctx, "Empty email in user data")
		return "", nil, exceptions.NewUnauthorizedError()
	}

	logger.DebugContext(ctx, "Successfully retrieved Facebook user data")
	return utils.Lowered(email), userRes, nil
}
