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

const resetPath = "auth/password-reset"

const resetTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>DevLogs Password Reset</title>
</head>
<body>
	<h1>Password Reset</h1>
	<br/>
	<p>Hello {{.Name}}</p>
	<br/>
	<p>We received a request to reset your password. Please click the link below to reset your password.</p>
	<a href="{{.ResetURL}}">Reset Password</a>
	<p><small>Or copy this link: {{.ResetURL}}</small></p>
	<br/>
	<p>If you did not request a password reset, please ignore this email.</p>
	<br/>
	<p>Thank you,</p>
	<p>DevLogs Team</p>
</body>
`

type resetEmailData struct {
	Name     string
	ResetURL string
}

type ResetEmailOptions struct {
	RequestID  string
	Email      string
	Name       string
	ResetToken string
}

func (e *EmailPublisher) PublishResetEmail(ctx context.Context, opts ResetEmailOptions) error {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  "reset",
		Method:    "PublishResetEmail",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Publishing reset email...")

	t, err := template.New("reset").Parse(resetTemplate)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse reset email template", "error", err)
		return err
	}

	data := resetEmailData{
		Name:     opts.Name,
		ResetURL: fmt.Sprintf("https://%s/%s/%s", e.frontendDomain, resetPath, opts.ResetToken),
	}
	var emailContent bytes.Buffer
	if err := t.Execute(&emailContent, data); err != nil {
		logger.ErrorContext(ctx, "Failed to execute reset email template", "error", err)
		return err
	}

	return e.publishEmail(ctx, PublishEmailOptions{
		To:        opts.Email,
		Subject:   "DevLogs Password Reset",
		Body:      emailContent.String(),
		RequestID: opts.RequestID,
	})
}
