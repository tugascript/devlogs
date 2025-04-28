package services

import (
	"context"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

type CreateUserOptions struct {
	RequestID   string
	AccountID   int32
	AppClientID string
	Email       string
	Password    string
	UserData    map[string]string
}

func (s *Services) CreateUser(ctx context.Context, opts CreateUserOptions) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersLocation, "CreateUser").With(
		"email", opts.Email,
	)
	logger.InfoContext(ctx, "Creating user...")

	logger.InfoContext(ctx, "User created successfully")
	return dtos.MapUserToDTO(&user)
}
