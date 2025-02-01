package dtos

import (
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
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

func mapAccountKeysScopes(jsonScopes []byte) ([]string, *exceptions.ServiceError) {
	scopesMap := make(map[string]bool)
	if err := json.Unmarshal(jsonScopes, &scopesMap); err != nil {
		return nil, exceptions.NewServerError()
	}

	scopes := make([]string, 0, len(scopesMap))
	for k, v := range scopesMap {
		if v {
			scopes = append(scopes, k)
		}
	}

	return scopes, nil
}

func MapAccountKeysToDTO(accountKeys *database.AccountKey) (AccountKeysDTO, *exceptions.ServiceError) {
	scopes, serviceErr := mapAccountKeysScopes(accountKeys.Scopes)
	if serviceErr != nil {
		return AccountKeysDTO{}, serviceErr
	}

	return AccountKeysDTO{
		ClientID:     accountKeys.ClientID,
		Scopes:       scopes,
		hashedSecret: accountKeys.ClientSecret,
		accountId:    int(accountKeys.AccountID),
	}, nil
}

func MapAccountKeysToDTOWithSecret(
	accountKeys *database.AccountKey,
	secret string,
) (AccountKeysDTO, *exceptions.ServiceError) {
	scopes, serviceErr := mapAccountKeysScopes(accountKeys.Scopes)
	if serviceErr != nil {
		return AccountKeysDTO{}, serviceErr
	}

	return AccountKeysDTO{
		ClientID:     accountKeys.ClientID,
		ClientSecret: secret,
		Scopes:       scopes,
		hashedSecret: accountKeys.ClientSecret,
		accountId:    int(accountKeys.AccountID),
	}, nil
}
