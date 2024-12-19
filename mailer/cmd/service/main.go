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

func gracefulShutdown(ctx context.Context, logger *slog.Logger, done chan bool) {
	logger.InfoContext(ctx, "Starting graceful shutdown...")

	// Create context that listens for the interrupt signal from the OS.
	c, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-c.Done()

	logger.InfoContext(c, "Shutting down gracefully, press Ctrl+C again to force...")

	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logger.InfoContext(c, "Service exiting")
	done <- true
}

func main() {
	logger := utils.DefaultLogger()
	ctx := context.Background()
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

	// Create a done channel to signal when the shutdown is complete
	done := make(chan bool, 1)

	go func() {
		queueService.Start(ctx)
	}()

	go gracefulShutdown(ctx, logger, done)

	<-done
	logger.InfoContext(ctx, "Service stopped")
}
