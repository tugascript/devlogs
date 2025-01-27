package services

import (
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	AuthProviderEmail     string = "email"
	AuthProviderGoogle    string = "google"
	AuthProviderGitHub    string = "github"
	AuthProviderApple     string = "apple"
	AuthProviderMicrosoft string = "microsoft"
	AuthProviderFacebook  string = "facebook"

	TwoFactorNone  string = "none"
	TwoFactorEmail string = "email"
	TwoFactorTotp  string = "totp"
)

func (s *Services) buildLogger(requestID, location, function string) *slog.Logger {
	return utils.BuildLogger(s.logger, utils.LoggerOptions{
		Layer:     utils.ServicesLogLayer,
		Location:  location,
		Method:    function,
		RequestID: requestID,
	})
}
