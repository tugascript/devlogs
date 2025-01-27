package controllers

import "github.com/gofiber/fiber/v2"

func (c *Controllers) HealthCheck(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), "health", "HealthCheck")
	logRequest(logger, ctx)
	return ctx.SendStatus(fiber.StatusOK)
}
