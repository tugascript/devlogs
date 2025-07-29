// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type ColorsDTO struct {
	PrimaryColor    string `json:"primary_color"`
	SecondaryColor  string `json:"secondary_color"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
}

type AppDesignDTO struct {
	LightColors ColorsDTO  `json:"light_colors"`
	DarkColors  *ColorsDTO `json:"dark_colors,omitempty"`
	LogoURL     string     `json:"logo_url,omitempty"`
	FaviconURL  string     `json:"favicon_url,omitempty"`

	id int32
}

func (a *AppDesignDTO) ID() int32 {
	return a.id
}

func MapAppDesignToDTO(appDesign *database.AppDesign) (AppDesignDTO, *exceptions.ServiceError) {
	var colorsDTO ColorsDTO
	if err := json.Unmarshal(appDesign.LightColors, &colorsDTO); err != nil {
		return AppDesignDTO{}, exceptions.NewInternalServerError()
	}

	var darkColorsDTO *ColorsDTO
	if appDesign.DarkColors != nil {
		darkColorsDTO = new(ColorsDTO)
		if err := json.Unmarshal(appDesign.DarkColors, darkColorsDTO); err != nil {
			return AppDesignDTO{}, exceptions.NewInternalServerError()
		}
	}

	return AppDesignDTO{
		LightColors: colorsDTO,
		DarkColors:  darkColorsDTO,
		LogoURL:     appDesign.LogoUrl.String,
		FaviconURL:  appDesign.FaviconUrl.String,
		id:          appDesign.ID,
	}, nil
}
