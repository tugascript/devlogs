package vault

import (
	"context"
	"log/slog"

	infisical "github.com/infisical/go-sdk"

	"github.com/tugascript/devlogs/idp/internal/config"
)

type Vault struct {
	logger *slog.Logger
	client infisical.InfisicalClientInterface
	env    string
}

func NewVault(
	ctx context.Context,
	logger *slog.Logger,
	config config.VaultConfig,
) *Vault {
	client := infisical.NewInfisicalClient(ctx, infisical.Config{
		SiteUrl:          config.Url(),
		AutoTokenRefresh: true,
	})

	_, err := client.Auth().UniversalAuthLogin(config.ClientID(), config.ClientSecret())
	if err != nil {
		logger.ErrorContext(ctx, "failed to login to vault", "error", err)
		panic(err)
	}

	return &Vault{
		logger: logger,
		client: client,
		env:    config.Env(),
	}
}
