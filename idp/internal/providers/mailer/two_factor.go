// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mailer

import (
	"bytes"
	"context"
	"fmt"
	"html/template"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const twoFactorTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Access Code</title>
</head>
<body>
	<h1>Access Code</h1>
	<br/>
	<p>Hello {{.Name}}</p>
	<br/>
	<p>Your access code is: <strong>{{.Code}}</strong></p>
	<br/>
	<p>Thank you,</p>
	<p>DevLogs Team</p>
</body>
`

type twoFactorEmailData struct {
	Name string
	Code string
}

const userTwoFactorTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Access Code</title>
</head>
<body>
	<h1>Access Code</h1>
	<br/>
	<p>Hello from {{.AppName}}</p>
	<br/>
	<p>Your access code is: <strong>{{.Code}}</strong></p>
	<br/>
	<p>Thank you,</p>
	<p>{{.AppName}} Team</p>
</body>
`

type userTwoFactorEmailData struct {
	AppName string
	Code    string
}

type TwoFactorEmailOptions struct {
	RequestID string
	Email     string
	Name      string
	Code      string
}

func (e *EmailPublisher) Publish2FAEmail(ctx context.Context, opts TwoFactorEmailOptions) error {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  "two_factor",
		Method:    "Publish2FAEmail",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Publishing 2FA email...")

	t, err := template.New("2FA").Parse(twoFactorTemplate)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse 2FA template")
		return err
	}

	data := twoFactorEmailData{
		Name: opts.Name,
		Code: opts.Code,
	}
	var emailContent bytes.Buffer
	if err := t.Execute(&emailContent, data); err != nil {
		logger.ErrorContext(ctx, "Failed to execute 2FA email template", "error", err)
		return err
	}

	return e.publishEmail(ctx, PublishEmailOptions{
		To:        opts.Email,
		Subject:   "DevLogs Access Code",
		Body:      emailContent.String(),
		RequestID: opts.RequestID,
	})
}

type User2FAEmailOptions struct {
	RequestID string
	AppName   string
	Email     string
	Code      string
}

func (e *EmailPublisher) PublishUser2FAEmail(ctx context.Context, opts User2FAEmailOptions) error {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  "two_factor",
		Method:    "PublishUser2FAEmail",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Publishing user 2FA email...")

	t, err := template.New("user_2fa").Parse(userTwoFactorTemplate)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse user 2FA template", "error", err)
		return err
	}

	data := userTwoFactorEmailData{
		AppName: opts.AppName,
		Code:    opts.Code,
	}
	var emailContent bytes.Buffer
	if err := t.Execute(&emailContent, data); err != nil {
		logger.ErrorContext(ctx, "Failed to execute user 2FA email template", "error", err)
		return err
	}

	return e.publishEmail(ctx, PublishEmailOptions{
		To:        opts.Email,
		Subject:   fmt.Sprintf("%s Access Code", opts.AppName),
		Body:      emailContent.String(),
		RequestID: opts.RequestID,
	})
}
