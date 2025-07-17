// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var titleCaser = cases.Title(language.English)
var lowerCaser = cases.Lower(language.English)
var upperCaser = cases.Upper(language.English)

func Capitalized(s string) string {
	s = strings.TrimSpace(s)

	if len(s) == 0 {
		return s
	}

	return titleCaser.String(s)
}

func CapitalizedFirst(s string) string {
	s = strings.TrimSpace(s)

	if len(s) == 0 {
		return s
	}

	var formated strings.Builder
	for i, char := range s {
		if i == 0 {
			formated.WriteRune(unicode.ToUpper(char))
		} else {
			formated.WriteRune(char)
		}
	}

	return formated.String()
}

func Lowered(s string) string {
	s = strings.TrimSpace(s)

	if len(s) == 0 {
		return s
	}

	return lowerCaser.String(s)
}

func Uppercased(s string) string {
	s = strings.TrimSpace(s)

	if len(s) == 0 {
		return s
	}

	return upperCaser.String(s)
}

func DbSearch(s string) string {
	return "%" + Lowered(s) + "%"
}

func DbSearchEnd(s string) string {
	return Lowered(s) + "%"
}

var nonAlphaNumRgx = regexp.MustCompile(`[^a-zA-Z0-9\s]+`)

func Slugify(s string) string {
	return strings.Join(
		strings.Fields(
			Lowered(
				nonAlphaNumRgx.ReplaceAllString(s, ""),
			),
		),
		"-",
	)
}

var slugRegex = regexp.MustCompile(`^[a-z\d]+(?:(-)[a-z\d]+)*$`)

func IsValidSlug(s string) bool {
	return len(s) > 0 && slugRegex.MatchString(s)
}

func IsValidSubdomain(s string) bool {
	length := len(s)
	if length < 1 || length > 63 {
		return false
	}

	return IsValidSlug(s)
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func IsValidEmail(email string) bool {
	length := len(email)
	return length >= 6 && length <= 255 && emailRegex.MatchString(email)
}

func AppendZeroToDecades(n int64) string {
	if n < 10 {
		return fmt.Sprintf("0%d", n)
	}

	return strconv.Itoa(int(n))
}

func IsValidURL(s string) bool {
	length := len(s)
	if length < 10 || length > 250 {
		return false
	}

	parsed, err := url.Parse(s)
	if err != nil {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

func ProcessURL(url string) string {
	lastLoc := len(url) - 1
	if url[lastLoc] == '/' {
		return url[:lastLoc]
	}

	return url
}
