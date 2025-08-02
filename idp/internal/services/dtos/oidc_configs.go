package dtos

import (
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type OIDCConfigDTO struct {
	ClaimsSupported []database.Claims `json:"claims_supported"`
	ScopesSupported []database.Scopes `json:"scopes_supported"`
	CustomClaims    []string          `json:"custom_claims"`
	CustomScopes    []string          `json:"custom_scopes"`

	id int32
}

func (u *OIDCConfigDTO) ID() int32 {
	return u.id
}

func MapOIDCConfigToDTO(oidcConfig *database.OidcConfig) (OIDCConfigDTO, *exceptions.ServiceError) {
	return OIDCConfigDTO{
		ClaimsSupported: oidcConfig.ClaimsSupported,
		ScopesSupported: oidcConfig.ScopesSupported,
		CustomClaims:    oidcConfig.CustomClaims,
		CustomScopes:    oidcConfig.CustomScopes,
		id:              oidcConfig.ID,
	}, nil
}
