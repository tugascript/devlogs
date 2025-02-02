package vault

import (
	"context"
	"fmt"
	"github.com/tugascript/devlogs/idp/internal/utils"
	"net/http"
)

const pingLocation string = "ping"

func (v *Vault) Ping(ctx context.Context, requestID string) error {
	logger := utils.BuildLogger(v.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  pingLocation,
		Method:    "Ping",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Pinging vault...")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/status", v.url), nil)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build status request", "error", err)
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to execute ping request", "error", err)
		return err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			logger.WarnContext(ctx, "Failed to close response body", "error", err)
			return
		}
	}()

	if res.StatusCode != http.StatusOK {
		logger.ErrorContext(ctx, "Ping request responded with non 200 OK status code",
			"statusCode", res.StatusCode,
		)
		return fmt.Errorf("ping responded with %d status code", res.StatusCode)
	}

	return nil
}
