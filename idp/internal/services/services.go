package services

import (
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/providers/vault"
)

type Services struct {
	logger         *slog.Logger
	database       *database.Database
	cache          *cache.Cache
	mail           *mailer.EmailPublisher
	jwt            *tokens.Tokens
	vault          *vault.Vault
	oauthProviders *oauth.Providers
}

func NewServices(
	logger *slog.Logger,
	database *database.Database,
	cache *cache.Cache,
	mail *mailer.EmailPublisher,
	jwt *tokens.Tokens,
	vault *vault.Vault,
	oauthProv *oauth.Providers,
) *Services {
	return &Services{
		logger:         logger,
		database:       database,
		cache:          cache,
		mail:           mail,
		jwt:            jwt,
		vault:          vault,
		oauthProviders: oauthProv,
	}
}
