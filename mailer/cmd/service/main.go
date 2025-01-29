package main

import (
	"context"
	"log/slog"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/go-playground/validator/v10"
	r "github.com/redis/go-redis/v9"

	"github.com/tugascript/devlogs/mailer/internal/email"
	"github.com/tugascript/devlogs/mailer/internal/queue"
	"github.com/tugascript/devlogs/mailer/internal/redis"
	"github.com/tugascript/devlogs/mailer/internal/utils"
)

func gracefullyShutdown(
	logger *slog.Logger,
	ctx context.Context,
	queueService *queue.Queue,
	done chan bool,
) {
	// Listen for the interrupt signal.
	<-ctx.Done()

	logger.InfoContext(ctx, "shutting down gracefully, press Ctrl+C again to force")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := queueService.Stop(ctx); err != nil {
		logger.ErrorContext(ctx, "Service forced to shutdown with error", "error", err)
	}

	logger.InfoContext(ctx, "Service exiting")

	// Notify the main goroutine that the shutdown is complete
	done <- true
}

func main() {
	logger := utils.DefaultLogger()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.InfoContext(ctx, "Loading configuration...")

	config := utils.NewConfig(logger, "./.env")
	logger = utils.InitialLogger(config.Logger.Env, config.Logger.Debug)

	// Set maximum CPU usage
	logger.InfoContext(ctx, "Setting GOMAXPROCS...", "maxProcs", config.MaxProcs)
	runtime.GOMAXPROCS(int(config.MaxProcs))
	logger.Info("Finished setting GOMAXPROCS")

	// Initialize Redis client
	logger.InfoContext(ctx, "Initializing Redis client...")
	options, err := r.ParseURL(config.Redis.URL)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse Redis URL", "error", err)
		panic(err)
	}

	rClient := r.NewClient(options)
	redisClient := redis.NewRedisClient(rClient, config.Redis.PubChannel)
	logger.InfoContext(ctx, "Redis client initialized")

	// Initialize email client
	logger.InfoContext(ctx, "Initializing email client...")
	mail := email.NewMail(config.Email.Username, config.Email.Password, config.Email.Host, config.Email.Port, config.Email.Name)
	logger.InfoContext(ctx, "Email client initialized")

	// Initialize queue
	logger.InfoContext(ctx, "Initializing queue...")
	queueService := queue.NewQueue(redisClient, mail, logger, validator.New())
	logger.InfoContext(ctx, "Queue initialized")

	done := make(chan bool, 1)

	go func() {
		queueService.Start(ctx)
	}()

	go gracefullyShutdown(logger, ctx, queueService, done)

	<-done
	logger.Info("Graceful shutdown complete.")
}
