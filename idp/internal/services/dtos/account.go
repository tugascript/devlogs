package dtos

import "github.com/tugascript/devlogs/idp/internal/providers/database"

type AccountDTO struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`

	version       int
	isConfirmed   bool
	password      string
	twoFactorType string
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

func (a *AccountDTO) TwoFactorType() string {
	return a.twoFactorType
}

func MapAccountToDTO(account *database.Account) AccountDTO {
	return AccountDTO{
		ID:            int(account.ID),
		version:       int(account.Version),
		FirstName:     account.FirstName,
		LastName:      account.LastName,
		Email:         account.Email,
		isConfirmed:   account.IsConfirmed,
		password:      account.Password.String,
		twoFactorType: account.TwoFactorType,
	}
}
