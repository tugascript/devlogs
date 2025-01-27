package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/server"
)

func gracefulShutdown(
	logger *slog.Logger,
	fiberServer *server.FiberServer,
	done chan bool,
) {
	// Create context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Listen for the interrupt signal.
	<-ctx.Done()

	logger.InfoContext(ctx, "shutting down gracefully, press Ctrl+C again to force")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fiberServer.ShutdownWithContext(ctx); err != nil {
		logger.ErrorContext(ctx, "Server forced to shutdown with error", "error", err)
	}

	logger.InfoContext(ctx, "Server exiting")

	// Notify the main goroutine that the shutdown is complete
	done <- true
}

func main() {
	logger := server.DefaultLogger()
	ctx := context.Background()
	logger.InfoContext(ctx, "Loading configuration...")
	cfg := config.NewConfig(logger, "./.env")

	logger = server.ConfigLogger(cfg.LoggerConfig())
	logger.InfoContext(ctx, "Setting GOMAXPROCS...", "maxProcs", cfg.MaxProcs())
	runtime.GOMAXPROCS(int(cfg.MaxProcs()))
	logger.InfoContext(ctx, "Finished setting GOMAXPROCS")

	logger.InfoContext(ctx, "Building server...")
	server := server.New(ctx, logger, cfg)
	logger.InfoContext(ctx, "Server built")

	server.RegisterFiberRoutes()

	// Create a done channel to signal when the shutdown is complete
	done := make(chan bool, 1)

	go func() {
		err := server.Listen(fmt.Sprintf(":%d", cfg.Port()))
		if err != nil {
			logger.ErrorContext(ctx, "http server error", "error", err)
			panic(fmt.Sprintf("http server error: %s", err))
		}
	}()

	// Run graceful shutdown in a separate goroutine
	go gracefulShutdown(logger, server, done)

	// Wait for the graceful shutdown to complete
	<-done
	logger.InfoContext(ctx, "Graceful shutdown complete.")
}
