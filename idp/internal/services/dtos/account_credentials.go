package dtos

import (
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type AccountCredentialsDTO struct {
	ClientID     string   `json:"id"`
	ClientSecret string   `json:"secret,omitempty"`
	Alias        string   `json:"alias"`
	Scopes       []string `json:"scopes"`

	id           int
	accountId    int
	hashedSecret string
}

func (ak *AccountCredentialsDTO) HashedSecret() string {
	return ak.hashedSecret
}

func (ak *AccountCredentialsDTO) AccountID() int {
	return ak.accountId
}

func (ak *AccountCredentialsDTO) ID() int {
	return ak.id
}

func mapAccountCredentialsScopes(jsonScopes []byte) ([]string, *exceptions.ServiceError) {
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

func MapAccountCredentialsToDTO(
	accountKeys *database.AccountCredential,
) (AccountCredentialsDTO, *exceptions.ServiceError) {
	scopes, serviceErr := mapAccountCredentialsScopes(accountKeys.Scopes)
	if serviceErr != nil {
		return AccountCredentialsDTO{}, serviceErr
	}

	return AccountCredentialsDTO{
		id:           int(accountKeys.ID),
		ClientID:     accountKeys.ClientID,
		Scopes:       scopes,
		hashedSecret: accountKeys.ClientSecret,
		accountId:    int(accountKeys.AccountID),
	}, nil
}

func MapAccountCredentialsToDTOWithSecret(
	accountKeys *database.AccountCredential,
	secret string,
) (AccountCredentialsDTO, *exceptions.ServiceError) {
	scopes, serviceErr := mapAccountCredentialsScopes(accountKeys.Scopes)
	if serviceErr != nil {
		return AccountCredentialsDTO{}, serviceErr
	}

	return AccountCredentialsDTO{
		id:           int(accountKeys.ID),
		ClientID:     accountKeys.ClientID,
		ClientSecret: secret,
		Scopes:       scopes,
		hashedSecret: accountKeys.ClientSecret,
		accountId:    int(accountKeys.AccountID),
	}, nil
}
