package controllers

import "github.com/gofiber/fiber/v2"

func (c *Controllers) HealthCheck(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, "health", "HealthCheck")
	logRequest(logger, ctx)

	if serviceErr := c.services.HealthCheck(ctx.UserContext(), requestID); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	return ctx.SendStatus(fiber.StatusOK)
}
