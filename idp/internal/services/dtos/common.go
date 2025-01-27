package dtos

import (
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type MessageDTO struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

func NewMessageDTO(msg string) MessageDTO {
	return MessageDTO{
		ID:      uuid.NewString(),
		Message: msg,
	}
}

type JWKsDTO struct {
	Keys []utils.P256JWK `json:"keys"`
}

func NewJWKsDTO(jwks []utils.P256JWK) JWKsDTO {
	return JWKsDTO{Keys: jwks}
}
