package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/encryptcookie"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	fiberRedis "github.com/gofiber/storage/redis/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/controllers"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/providers/vault"
	"github.com/tugascript/devlogs/idp/internal/server/routes"
	"github.com/tugascript/devlogs/idp/internal/services"
)

type FiberServer struct {
	*fiber.App
	routes *routes.Routes
}

func New(
	ctx context.Context,
	logger *slog.Logger,
	cfg config.Config,
) *FiberServer {
	logger.InfoContext(ctx, "Building redis storage...")
	cacheStorage := fiberRedis.New(fiberRedis.Config{
		URL: cfg.RedisURL(),
	})
	cc := cache.NewCache(
		logger,
		cacheStorage,
	)
	logger.InfoContext(ctx, "Finished building redis storage")

	logger.InfoContext(ctx, "Building database connection pool...")
	dbConnPool, err := pgxpool.New(ctx, cfg.DatabaseURL())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to connect to database", "error", err)
		panic(err)
	}
	db := database.NewDatabase(dbConnPool)
	logger.InfoContext(ctx, "Finished building database connection pool")

	logger.InfoContext(ctx, "Building mailer...")
	mail := mailer.NewEmailPublisher(
		cc.Client(),
		cfg.EmailPubChannel(),
		cfg.FrontendDomain(),
		logger,
	)
	logger.InfoContext(ctx, "Finished building mailer")

	logger.InfoContext(ctx, "Building JWT token keys...")
	tokensCfg := cfg.TokensConfig()
	jwts := tokens.NewTokens(
		tokensCfg.Access(),
		tokensCfg.AccountKeys(),
		tokensCfg.Refresh(),
		tokensCfg.Confirm(),
		tokensCfg.Reset(),
		tokensCfg.OAuth(),
		tokensCfg.TwoFA(),
		cfg.FrontendDomain(),
		cfg.BackendDomain(),
	)
	logger.InfoContext(ctx, "Finished building JWT tokens keys")

	logger.InfoContext(ctx, "Building vault...")
	vaultStg := vault.NewVault(ctx, logger, cfg.VaultConfig())
	logger.InfoContext(ctx, "Finished building vault")

	logger.InfoContext(ctx, "Building OAuth provider...")
	oauthProvidersCfg := cfg.OAuthProvidersConfig()
	oauthProviders := oauth.NewProviders(
		logger,
		oauthProvidersCfg.GitHub(),
		oauthProvidersCfg.Google(),
		oauthProvidersCfg.Facebook(),
		oauthProvidersCfg.Apple(),
		oauthProvidersCfg.Microsoft(),
	)
	logger.InfoContext(ctx, "Finished building OAuth provider")

	logger.InfoContext(ctx, "Building newServices...")
	newServices := services.NewServices(
		logger,
		db,
		cc,
		mail,
		jwts,
		vaultStg,
		oauthProviders,
	)
	logger.InfoContext(ctx, "Finished building newServices")

	server := &FiberServer{
		App: fiber.New(fiber.Config{
			ServerHeader: "idp",
			AppName:      "idp",
		}),
		routes: routes.NewRoutes(controllers.NewControllers(
			logger,
			newServices,
			validator.New(),
			cfg.FrontendDomain(),
			cfg.BackendDomain(),
			cfg.CookieName(),
		)),
	}

	logger.InfoContext(ctx, "Loading middleware...")
	server.Use(helmet.New())
	server.Use(requestid.New(requestid.Config{
		Header: fiber.HeaderXRequestID,
		Generator: func() string {
			return uuid.NewString()
		},
	}))
	rateLimitCfg := cfg.RateLimiterConfig()
	server.Use(limiter.New(limiter.Config{
		Max:               int(rateLimitCfg.Max()),
		Expiration:        time.Duration(rateLimitCfg.ExpSec()) * time.Second,
		LimiterMiddleware: limiter.SlidingWindow{},
		Storage:           cacheStorage,
	}))
	server.Use(encryptcookie.New(encryptcookie.Config{
		Key: cfg.CookieSecret(),
	}))
	server.App.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS,PATCH,HEAD",
		AllowHeaders:     "Accept,Authorization,Content-Type",
		AllowCredentials: false, // credentials require explicit origins
		MaxAge:           300,
	}))
	logger.Info("Finished loading common middlewares")

	return server
}
