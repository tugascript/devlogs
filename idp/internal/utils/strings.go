package utils

import (
	"fmt"
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

func AppendZeroToDecades(n int64) string {
	if n < 10 {
		return fmt.Sprintf("0%d", n)
	}

	return strconv.Itoa(int(n))
}
