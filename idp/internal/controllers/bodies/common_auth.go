// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type RefreshTokenBody struct {
	RefreshToken string `json:"refresh_token" validate:"required,jwt"`
}

type ConfirmationTokenBody struct {
	ConfirmationToken string `json:"confirmation_token" validate:"required,jwt"`
}

type LoginBody struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
}

type TwoFactorLoginBody struct {
	Code string `json:"code" validate:"required,min=6,max=6,numeric"`
}

type RecoverBody struct {
	RecoveryCode string `json:"recovery_code" validate:"required,min=1"`
}

type ForgoutPasswordBody struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordBody struct {
	Password   string `json:"password" validate:"required,min=8,max=100,password"`
	Password2  string `json:"password2" validate:"required,eqfield=Password"`
	ResetToken string `json:"reset_token" validate:"required,jwt"`
}

type GrantRefreshTokenBody struct {
	GrantType    string `json:"grant_type" validate:"required,eq=refresh_token"`
	RefreshToken string `json:"refresh_token" validate:"required,jwt"`
}

type AuthCodeLoginBody struct {
	GrantType   string `json:"grant_type" validate:"required,eq=authorization_code"`
	RedirectURI string `json:"redirect_uri" validate:"required,url"`
	Code        string `json:"code" validate:"required,min=1,max=30,alphanum"`
}

type ClientCredentialsBody struct {
	GrantType string `json:"grant_type" validate:"required,eq=client_credentials"`
	Scope     string `json:"scopes,omitempty" validate:"omitempty,scopes"`
}

type AppleLoginBody struct {
	Code  string `json:"code" validate:"required,min=1"`
	State string `json:"state" validate:"required,min=1"`
	User  string `json:"user" validate:"required,json"`
}

type AppleUserName struct {
	FirstName string `json:"firstName" validate:"required,min=1"`
	LastName  string `json:"lastName" validate:"required,min=1"`
}

type AppleUser struct {
	Name  AppleUserName `json:"name" validate:"required"`
	Email string        `json:"email" validate:"required,email"`
}

type UpdateEmailBody struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
}

type UpdatePasswordBody struct {
	OldPassword string `json:"old_password" validate:"required,min=1"`
	Password    string `json:"password" validate:"required,min=8,max=100,password"`
	Password2   string `json:"password2" validate:"required,eqfield=Password"`
}

type CreatePasswordBody struct {
	Password  string `json:"password" validate:"required,min=8,max=100,password"`
	Password2 string `json:"password2" validate:"required,eqfield=Password"`
}

type DeleteWithPasswordBody struct {
	Password string `json:"password,omitempty" validate:"omitempty,min=1"`
}

type UpdateTwoFactorBody struct {
	TwoFactorType string `json:"two_factor_type" validate:"required,two_factor_type"`
	Password      string `json:"password,omitempty" validate:"omitempty,min=1"`
}
