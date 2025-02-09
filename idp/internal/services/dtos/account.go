package dtos

import "github.com/tugascript/devlogs/idp/internal/providers/database"

type AccountDTO struct {
	ID            int    `json:"id"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Email         string `json:"email"`
	TwoFactorType string `json:"two_factor_type"`

	version     int
	isConfirmed bool
	password    string
}

func (a *AccountDTO) Version() int {
	return a.version
}

func (a *AccountDTO) Password() string {
	return a.password
}

func (a *AccountDTO) IsConfirmed() bool {
	return a.isConfirmed
}

func MapAccountToDTO(account *database.Account) AccountDTO {
	return AccountDTO{
		ID:            int(account.ID),
		version:       int(account.Version),
		FirstName:     account.FirstName,
		LastName:      account.LastName,
		Email:         account.Email,
		TwoFactorType: account.TwoFactorType,
		isConfirmed:   account.IsConfirmed,
		password:      account.Password.String,
	}
}
