package dtos

import (
	"fmt"
	"net/url"

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

func processExtraParams(extraParams []string) string {
	length := len(extraParams)
	if length == 0 || length%2 != 0 {
		return ""
	}

	urlParams := make(url.Values)
	for i := 0; i < length; i += 2 {
		key := extraParams[i]
		value := extraParams[i+1]
		if key != "" && value != "" {
			urlParams.Add(key, value)
		}
	}

	return "&" + urlParams.Encode()
}

func formatPaginationURL(backendDomain, route string, offset, limit int, extraParams string) string {
	return fmt.Sprintf("https://%s/%s?offset=%d&limit=%d%s", backendDomain, route, offset, limit, extraParams)
}

func newPaginationNextURL(backendDomain, route string, limit, offset int, count int64, extraParams string) string {
	newOffset := offset + limit
	if int64(newOffset) < count {
		return formatPaginationURL(backendDomain, route, newOffset, limit, extraParams)
	}

	return ""
}

func newPaginationPreviousURL(backendDomain, route string, limit, offset int, extraParams string) string {
	if offset == 0 {
		return ""
	}

	newOffset := offset - limit
	if newOffset < 0 {
		return formatPaginationURL(backendDomain, route, 0, limit, extraParams)
	}

	return formatPaginationURL(backendDomain, route, newOffset, limit, extraParams)
}

func NewPaginationDTO[T any](
	items []T,
	count int64,
	backendDomain,
	route string,
	limit,
	offset int,
	extraParams ...string,
) PaginationDTO[T] {
	extraParamsStr := processExtraParams(extraParams)
	return PaginationDTO[T]{
		Total:    count,
		Next:     newPaginationNextURL(backendDomain, route, limit, offset, count, extraParamsStr),
		Previous: newPaginationPreviousURL(backendDomain, route, limit, offset, extraParamsStr),
		Items:    items,
	}
}
