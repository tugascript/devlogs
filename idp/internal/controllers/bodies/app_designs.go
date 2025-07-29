// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type ColorsOptions struct {
	PrimaryColor    string `json:"primary_color" validate:"required,hexadecimal,len=6"`
	SecondaryColor  string `json:"secondary_color" validate:"required,hexadecimal,len=6"`
	BackgroundColor string `json:"background_color" validate:"required,hexadecimal,len=6"`
	TextColor       string `json:"text_color" validate:"required,hexadecimal,len=6"`
}

type AppDesignBody struct {
	LogoURL     string         `json:"logo_url,omitempty" validate:"omitempty,url"`
	FaviconURL  string         `json:"favicon_url,omitempty" validate:"omitempty,url"`
	LightColors ColorsOptions  `json:"light_colors" validate:"required"`
	DarkColors  *ColorsOptions `json:"dark_colors,omitempty" validate:"omitempty"`
}
