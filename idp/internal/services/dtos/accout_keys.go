package dtos

import (
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type AccountKeysDTO struct {
	ClientID     string   `json:"id"`
	ClientSecret string   `json:"secret,omitempty"`
	Scopes       []string `json:"scopes"`

	accountId    int
	hashedSecret string
}

func (ak *AccountKeysDTO) HashedSecret() string {
	return ak.hashedSecret
}

func (ak *AccountKeysDTO) AccountID() int {
	return ak.accountId
}

func MapAccountKeysToDTO(accountKeys *database.AccountKey) AccountKeysDTO {
	return AccountKeysDTO{
		ClientID:     accountKeys.ClientID,
		Scopes:       accountKeys.Scopes,
		hashedSecret: accountKeys.ClientSecret,
		accountId:    int(accountKeys.AccountID),
	}
}

func MapAccountKeysToDTOWithSecret(accountKeys *database.AccountKey, secret string) AccountKeysDTO {
	return AccountKeysDTO{
		ClientID:     accountKeys.ClientID,
		ClientSecret: secret,
		Scopes:       accountKeys.Scopes,
		hashedSecret: accountKeys.ClientSecret,
		accountId:    int(accountKeys.AccountID),
	}
}
