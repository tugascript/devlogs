// Copyright (	c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oauth

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/biter777/countries"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	githubLocation string = "github"

	githubUserURL string = "https://api.github.com/user"
)

var gitHubScopes = oauthScopes{
	email:   "user:email",
	profile: "read:user",
}

type GitHubUserResponse struct {
	AvatarURL         string `json:"avatar_url"`
	EventsURL         string `json:"events_url"`
	FollowersURL      string `json:"followers_url"`
	FollowingURL      string `json:"following_url"`
	GistsURL          string `json:"gists_url"`
	GravatarID        string `json:"gravatar_id"`
	HTMLURL           string `json:"html_url"`
	ID                int64  `json:"id"`
	NodeID            string `json:"node_id"`
	Login             string `json:"login"`
	OrganizationsURL  string `json:"organizations_url"`
	ReceivedEventsURL string `json:"received_events_url"`
	ReposURL          string `json:"repos_url"`
	SiteAdmin         bool   `json:"site_admin"`
	StarredURL        string `json:"starred_url"`
	SubscriptionsURL  string `json:"subscriptions_url"`
	Type              string `json:"type"`
	URL               string `json:"url"`
	Bio               string `json:"bio"`
	Blog              string `json:"blog"`
	Company           string `json:"company"`
	Email             string `json:"email"`
	Followers         int    `json:"followers"`
	Following         int    `json:"following"`
	Hireable          bool   `json:"hireable"`
	Location          string `json:"location"`
	Name              string `json:"name"`
	PublicGists       int    `json:"public_gists"`
	PublicRepos       int    `json:"public_repos"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

func processGithubName(name string) (string, string) {
	nameSplit := strings.Fields(strings.TrimSpace(name))
	if len(nameSplit) > 1 {
		return nameSplit[0], strings.Join(nameSplit[1:], " ")
	}

	return nameSplit[0], ""
}

func processGithubLocation(location string) UserLocation {
	locSplit := strings.Split(strings.TrimSpace(location), ",")

	if len(locSplit) == 3 {
		country := countries.ByName(strings.TrimSpace(locSplit[2]))
		city := strings.TrimSpace(locSplit[0])
		region := strings.TrimSpace(locSplit[1])

		if country != countries.Unknown {
			return UserLocation{
				City:    city,
				Region:  region,
				Country: country.Alpha2(),
			}
		}

		return UserLocation{
			City:    city,
			Region:  region,
			Country: countries.US.Alpha2(),
		}
	}
	if len(locSplit) == 2 {
		countryOrRegion := strings.TrimSpace(locSplit[1])
		country := countries.ByName(countryOrRegion)
		city := strings.TrimSpace(locSplit[0])

		if country != countries.Unknown {
			return UserLocation{
				City:    city,
				Country: country.Alpha2(),
			}
		}

		return UserLocation{
			City:    city,
			Region:  countryOrRegion,
			Country: countries.US.Alpha2(),
		}
	}

	countryOrRegion := strings.TrimSpace(location)
	country := countries.ByName(countryOrRegion)
	if country != countries.Unknown {
		return UserLocation{
			Country: country.Alpha2(),
		}
	}

	return UserLocation{
		Region:  countryOrRegion,
		Country: countries.US.Alpha2(),
	}
}

func (gu *GitHubUserResponse) ToUserData() UserData {
	firstName, lastName := processGithubName(gu.Name)
	return UserData{
		Name:       gu.Name,
		FirstName:  firstName,
		LastName:   lastName,
		Username:   utils.Slugify(gu.Name),
		Picture:    gu.AvatarURL,
		Email:      utils.Lowered(gu.Email),
		Location:   processGithubLocation(gu.Location),
		IsVerified: true,
	}
}

func (p *Providers) GetGithubAuthorizationURL(
	ctx context.Context,
	opts AuthorizationURLOptions,
) (string, string, *exceptions.ServiceError) {
	return getAuthorizationURL(ctx, getAuthorizationURLOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Location:  githubLocation,
			Method:    "GetGithubAuthorizationURL",
			RequestID: opts.RequestID,
		}),
		cfg:         p.gitHub,
		redirectURL: opts.RedirectURL,
		oas:         gitHubScopes,
		scopes:      opts.Scopes,
	})
}

func (p *Providers) GetGithubAccessToken(
	ctx context.Context,
	opts AccessTokenOptions,
) (string, *exceptions.ServiceError) {
	return getAccessToken(ctx, getAccessTokenOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Location:  githubLocation,
			Method:    "GetGithubAccessToken",
			RequestID: opts.RequestID,
		}),
		cfg:         p.gitHub,
		redirectURL: opts.RedirectURL,
		oas:         gitHubScopes,
		scopes:      opts.Scopes,
		code:        opts.Code,
	})
}

func (p *Providers) GetGithubUserData(
	ctx context.Context,
	opts UserDataOptions,
) (UserData, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Location:  githubLocation,
		Method:    "GetGithubUserData",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting GitHub user data...")

	body, status, err := getUserResponse(logger, ctx, githubUserURL, opts.Token)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get GitHub user data", "error", err)

		if status > 0 && status < 500 {
			return UserData{}, exceptions.NewUnauthorizedError()
		}

		return UserData{}, exceptions.NewServerError()
	}

	userRes := GitHubUserResponse{}
	if err := json.Unmarshal(body, &userRes); err != nil {
		logger.ErrorContext(ctx, "Failed to parse GitHub user data", "error", err)
		return UserData{}, exceptions.NewServerError()
	}

	return userRes.ToUserData(), nil
}

func (p *Providers) GetGithubUserMap(
	ctx context.Context,
	opts UserDataOptions,
) (string, map[string]any, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Location:  githubLocation,
		Method:    "GetGithubUserMap",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting GitHub user map...")

	body, status, err := getUserResponse(logger, ctx, githubUserURL, opts.Token)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get GitHub user data", "error", err)

		if status > 0 && status < 500 {
			return "", nil, exceptions.NewUnauthorizedError()
		}

		return "", nil, exceptions.NewServerError()
	}

	userMap := make(map[string]any)
	if err = json.Unmarshal(body, &userMap); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal user data", "error", err)
		return "", nil, exceptions.NewServerError()
	}

	if len(userMap) == 0 {
		logger.WarnContext(ctx, "Empty user data")
		return "", nil, exceptions.NewUnauthorizedError()
	}

	email, ok := userMap["email"].(string)
	if !ok {
		logger.WarnContext(ctx, "Email not found in user data")
		return "", nil, exceptions.NewUnauthorizedError()
	}
	if email == "" {
		logger.WarnContext(ctx, "Empty email in user data")
		return "", nil, exceptions.NewUnauthorizedError()
	}

	return utils.Lowered(email), userMap, nil
}
