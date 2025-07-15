// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mailer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	confirmationPath = "auth/confirm"
)

const confirmationTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>DevLogs Confirm Confirmation</title>
</head>
<body>
	<h1>Confirm Confirmation</h1>
	<br/>
	<p>Welcome {{.Name}}</p>
	<br/>
	<p>Thank you for signing up to DevLogs. Please click the link below to confirm your email address.</p>
	<a href="{{.ConfirmationURL}}">Confirm Confirm</a>
	<p><small>Or copy this link: {{.ConfirmationURL}}</small></p>
	<br/>
	<p>Thank you,</p>
	<p>DevLogs Team</p>
</body>
`

type confirmationEmailData struct {
	Name            string
	ConfirmationURL string
}

const userConfirmationTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>DevLogs Confirm Confirmation</title>
</head>
<body>
	<h1>Confirm Confirmation</h1>
	<br/>
	<p>Welcome to {{.AppName}}</p>
	<br/>
	<p>Thank you for signing up to DevLogs. Please click the link below to confirm your email address.</p>
	<a href="{{.ConfirmationURL}}">Confirm Confirm</a>
	<p><small>Or copy this link: {{.ConfirmationURL}}</small></p>
	<br/>
	<p>Thank you,</p>
	<p>{{.AppName}} Team</p>
</body>
`

type userConfirmationEmailData struct {
	AppName         string
	ConfirmationURL string
}

type ConfirmationEmailOptions struct {
	RequestID         string
	Email             string
	Name              string
	ConfirmationToken string
}

func (e *EmailPublisher) PublishConfirmationEmail(ctx context.Context, opts ConfirmationEmailOptions) error {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  "confirmation",
		Method:    "PublishConfirmationEmail",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Publishing confirmation email...")

	t, err := template.New("confirmation").Parse(confirmationTemplate)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse confirmation email template", "error", err)
		return err
	}

	data := confirmationEmailData{
		Name:            opts.Name,
		ConfirmationURL: fmt.Sprintf("https://%s/%s/%s", e.frontendDomain, confirmationPath, opts.ConfirmationToken),
	}
	var emailContent bytes.Buffer
	if err := t.Execute(&emailContent, data); err != nil {
		logger.ErrorContext(ctx, "Failed to execute email template", "error", err)
		return err
	}

	return e.publishEmail(ctx, PublishEmailOptions{
		To:        opts.Email,
		Subject:   "DevLogs Confirm Confirmation",
		Body:      emailContent.String(),
		RequestID: opts.RequestID,
	})
}

type UserConfirmationEmailOptions struct {
	RequestID         string
	AppName           string
	Email             string
	ConfirmationURI   string
	ConfirmationToken string
}

func (e *EmailPublisher) PublishUserConfirmationEmail(ctx context.Context, opts UserConfirmationEmailOptions) error {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  "confirmation",
		Method:    "PublishUserConfirmationEmail",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Publishing user confirmation email...")

	if opts.ConfirmationURI == "" {
		logger.ErrorContext(ctx, "Confirmation URI is empty")
		return errors.New("confirmation URI is empty")
	}

	var confirmationURL string
	lastIndex := len(opts.ConfirmationURI) - 1
	if opts.ConfirmationURI[lastIndex] == '/' {
		confirmationURL = fmt.Sprintf("%s%s", opts.ConfirmationURI, opts.ConfirmationToken)
	} else {
		confirmationURL = fmt.Sprintf("%s/%s", opts.ConfirmationURI, opts.ConfirmationToken)
	}

	t, err := template.New("user_confirmation").Parse(userConfirmationTemplate)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse user confirmation email template", "error", err)
		return err
	}

	data := userConfirmationEmailData{
		AppName:         opts.AppName,
		ConfirmationURL: confirmationURL,
	}
	var emailContent bytes.Buffer
	if err := t.Execute(&emailContent, data); err != nil {
		logger.ErrorContext(ctx, "Failed to execute email template", "error", err)
		return err
	}

	return e.publishEmail(ctx, PublishEmailOptions{
		To:        opts.Email,
		Subject:   fmt.Sprintf("%s Confirmation", opts.AppName),
		Body:      emailContent.String(),
		RequestID: opts.RequestID,
	})
}
