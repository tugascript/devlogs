package cache

import (
	"context"
	"idp/internal/utils"
	"time"
)

const (
	oauthStatePrefix   string = "oauth_state"
	oauthStateLocation string = "oauth_state"
	oauthStateSeconds  int    = 120
)

type AddOAuthStateOptions struct {
	RequestID string
	State     string
	Provider  string
}

func (c *Cache) AddOAuthState(ctx context.Context, opts AddOAuthStateOptions) error {
	logger := utils.BuildLogger(c.log, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthStateLocation,
		Function:  "AddOAuthState",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Adding OAuth state...")
	return c.storage.Set(
		oauthStatePrefix+":"+opts.State,
		[]byte(opts.Provider),
		time.Duration(oauthStateSeconds)*time.Second,
	)
}

type VerifyOAuthStateOptions struct {
	RequestID string
	State     string
	Provider  string
}

func (c *Cache) VerifyOAuthState(ctx context.Context, opts VerifyOAuthStateOptions) (bool, error) {
	logger := utils.BuildLogger(c.log, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthStateLocation,
		Function:  "VerifyOAuthState",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying OAuth state...")
	valByte, err := c.storage.Get(oauthStatePrefix + ":" + opts.State)

	if err != nil {
		logger.ErrorContext(ctx, "Error verifying OAuth state", "error", err)
		return false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "OAuth state not found")
		return false, nil
	}

	return string(valByte) == opts.Provider, nil
}
