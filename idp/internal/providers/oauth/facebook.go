package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
) (string, string, error) {
	return getAuthorizationURL(ctx, getAuthorizationURLOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Layer:     logLayer,
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

func (p *Providers) GetFacebookAccessToken(ctx context.Context, opts AccessTokenOptions) (string, error) {
	return getAccessToken(ctx, getAccessTokenOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Layer:     logLayer,
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

func (p *Providers) GetFacebookUserData(ctx context.Context, opts UserDataOptions) (UserData, int, error) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  facebookLocation,
		Method:    "GetFacebookUserData",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting Facebook user data...")

	extPrms := extraParams{params: "email"}
	for _, s := range opts.Scopes {
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

	body, status, err := getUserResponse(
		logger,
		ctx,
		fmt.Sprintf("%s?fields=%s", facebookUserURL, extPrms),
		opts.Token,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get Facebook user data", "error", err)
		return UserData{}, status, err
	}

	userRes := FacebookUserResponse{}
	if err := json.Unmarshal(body, &userRes); err != nil {
		logger.ErrorContext(ctx, "Failed to parse Facebook user data", "error", err)
		return UserData{}, status, err
	}

	return userRes.ToUserData(), status, nil
}
