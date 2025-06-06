package dtos

import (
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type OIDCConfigDTO struct {
	Claims         []string `json:"claims"`
	Scopes         []string `json:"scopes"`
	JwtCryptoSuite string   `json:"jwt_crypto_suite"`

	id  int32
	dek string
}

func (u *OIDCConfigDTO) ID() int32 {
	return u.id
}

func (u *OIDCConfigDTO) DEK() string {
	return u.dek
}

func MapOIDCConfigToDTO(oidcConfig *database.OidcConfig) (OIDCConfigDTO, *exceptions.ServiceError) {
	claims := []string{"email", "email_verified"}
	claimSlice, serviceErr := jsonHashMapToSlice(oidcConfig.Claims)
	if serviceErr != nil {
		return OIDCConfigDTO{}, serviceErr
	}

	scopes, serviceErr := jsonHashMapToSlice(oidcConfig.Scopes)
	if serviceErr != nil {
		return OIDCConfigDTO{}, serviceErr
	}

	return OIDCConfigDTO{
		Claims:         append(claims, claimSlice...),
		Scopes:         scopes,
		JwtCryptoSuite: oidcConfig.JwtCryptoSuite,
		id:             oidcConfig.ID,
		dek:            oidcConfig.Dek,
	}, nil
}
