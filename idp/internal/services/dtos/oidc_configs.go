package dtos

import (
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type OIDCConfigDTO struct {
	ClaimsSupported    []database.Claims `json:"claims_supported"`
	ScopesSupported    []database.Scopes `json:"scopes_supported"`
	UserRolesSupported []string          `json:"user_roles_supported"`

	id int32
}

func (u *OIDCConfigDTO) ID() int32 {
	return u.id
}

func MapOIDCConfigToDTO(oidcConfig *database.OidcConfig) (OIDCConfigDTO, *exceptions.ServiceError) {
	return OIDCConfigDTO{
		ClaimsSupported:    oidcConfig.ClaimsSupported,
		ScopesSupported:    oidcConfig.ScopesSupported,
		UserRolesSupported: oidcConfig.UserRolesSupported,
		id:                 oidcConfig.ID,
	}, nil
}
