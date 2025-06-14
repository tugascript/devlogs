// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

type AuthDTO struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	ExpiresIn    int64             `json:"expires_in"`
	TokenType    string            `json:"token_type"`
	Message      string            `json:"message,omitempty"`
	Data         map[string]string `json:"data,omitempty"`
}

const tokenType string = "Bearer"

func NewAuthDTO(accessToken string, expiresIn int64) AuthDTO {
	return AuthDTO{
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
		TokenType:   tokenType,
	}
}

func NewFullAuthDTO(accessToken, refreshToken string, expiresIn int64) AuthDTO {
	return AuthDTO{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    tokenType,
	}
}

func NewTempAuthDTO(accessToken, message string, expiresIn int64) AuthDTO {
	return AuthDTO{
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
		TokenType:   tokenType,
		Message:     message,
	}
}

func NewAuthDTOWithData(accessToken, message string, data map[string]string, expiresIn int64) AuthDTO {
	return AuthDTO{
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
		TokenType:   tokenType,
		Message:     message,
		Data:        data,
	}
}
