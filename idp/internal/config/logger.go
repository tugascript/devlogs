// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type LoggerConfig struct {
	isDebug     bool
	env         string
	serviceName string
}

func NewLoggerConfig(isDebug bool, env, serviceName string) LoggerConfig {
	return LoggerConfig{
		isDebug:     isDebug,
		env:         env,
		serviceName: serviceName,
	}
}

func (l *LoggerConfig) IsDebug() bool {
	return l.isDebug
}

func (l *LoggerConfig) Env() string {
	return l.env
}

func (l *LoggerConfig) ServiceName() string {
	return l.serviceName
}
