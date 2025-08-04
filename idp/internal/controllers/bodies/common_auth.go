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

type ForgotPasswordBody struct {
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

type ClientCredentialsBody struct {
	GrantType    string `json:"grant_type" validate:"required,eq=client_credentials"`
	Scope        string `json:"scope,omitempty" validate:"omitempty,scopes"`
	Audience     string `json:"audience,omitempty" validate:"omitempty,url"`
	ClientID     string `json:"client_id,omitempty" validate:"omitempty,min=1"`
	ClientSecret string `json:"client_secret,omitempty" validate:"omitempty,min=1"`
}

type JWTGrantBody struct {
	GrantType string `json:"grant_type" validate:"required,eq=urn:ietf:params:oauth:grant-type:jwt-bearer"`
	Scope     string `json:"scope,omitempty" validate:"omitempty,scopes"`
	Assertion string `json:"assertion" validate:"required,jwt"`
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

type Update2FABody struct {
	TwoFactorType string `json:"two_factor_type" validate:"required,oneof=none totp email"`
	Password      string `json:"password,omitempty" validate:"omitempty,min=1"`
}
