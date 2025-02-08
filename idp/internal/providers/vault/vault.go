package vault

import (
	"context"
	"log/slog"

	infisical "github.com/infisical/go-sdk"

	"github.com/tugascript/devlogs/idp/internal/config"
)

const logLayer string = "vault"

type Vault struct {
	logger *slog.Logger
	client infisical.InfisicalClientInterface
	env    string
	url    string
}

func NewVault(
	ctx context.Context,
	logger *slog.Logger,
	config config.VaultConfig,
) *Vault {
	url := config.Url()
	client := infisical.NewInfisicalClient(ctx, infisical.Config{
		SiteUrl:          url,
		AutoTokenRefresh: true,
	})

	_, err := client.Auth().UniversalAuthLogin(config.ClientID(), config.ClientSecret())
	if err != nil {
		logger.ErrorContext(ctx, "failed to login to vault", "error", err)
		panic(err)
	}

	env := config.Env()
	if !(env == "prod" || env == "production") {
		env = "development"
	}

	return &Vault{
		logger: logger,
		client: client,
		url:    url,
		env:    env,
	}
}
