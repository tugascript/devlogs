package dtos

import (
	"fmt"
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

type PaginationDTO[T any] struct {
	Total    int64  `json:"total"`
	Next     string `json:"next,omitempty"`
	Previous string `json:"previous,omitempty"`
	Items    []T    `json:"items"`
}

func formatPaginationURL(backendDomain, route string, offset, limit int) string {
	return fmt.Sprintf("https://%s/%s?offset=%d&limit=%d", backendDomain, route, offset, limit)
}

func newPaginationNextURL(backendDomain, route string, limit, offset int, count int64) string {
	newOffset := offset + limit
	if int64(newOffset) < count {
		return formatPaginationURL(backendDomain, route, newOffset, limit)
	}

	return ""
}

func newPaginationPreviousURL(backendDomain, route string, limit, offset int) string {
	if offset == 0 {
		return ""
	}

	newOffset := offset - limit
	if newOffset < 0 {
		return formatPaginationURL(backendDomain, route, 0, limit)
	}

	return formatPaginationURL(backendDomain, route, newOffset, limit)
}

func NewPaginationDTO[T any](items []T, count int64, backendDomain, route string, limit, offset int) PaginationDTO[T] {
	return PaginationDTO[T]{
		Total:    count,
		Next:     newPaginationNextURL(backendDomain, route, limit, offset, count),
		Previous: newPaginationPreviousURL(backendDomain, route, limit, offset),
		Items:    items,
	}
}
