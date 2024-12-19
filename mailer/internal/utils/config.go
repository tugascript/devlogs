package utils

import (
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

var variables = [10]string{
	"ENV",
	"DEBUG",
	"MAX_PROCS",
	"REDIS_URL",
	"REDIS_PUB_CHANNEL",
	"EMAIL_HOST",
	"EMAIL_PORT",
	"EMAIL_USERNAME",
	"EMAIL_PASSWORD",
	"EMAIL_NAME",
}

var numericVariables = [2]string{
	"MAX_PROCS",
	"EMAIL_PORT",
}

type LoggerConfig struct {
	Env   string
	Debug bool
}

type EmailConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	Name     string
}

type RedisConfig struct {
	URL        string
	PubChannel string
}

type Config struct {
	MaxProcs int64
	Redis    RedisConfig
	Logger   LoggerConfig
	Email    EmailConfig
}

func NewConfig(log *slog.Logger, envPath string) *Config {
	err := godotenv.Load(envPath)
	if err != nil {
		log.Error("Error loading .env file")
	}

	variablesMap := make(map[string]string)
	for _, variable := range variables {
		value := os.Getenv(variable)
		if value == "" {
			log.Error(variable + " is not set")
			panic(variable + " is not set")
		}
		variablesMap[variable] = value
	}

	numericVariablesMap := make(map[string]int64)
	for _, variable := range numericVariables {
		value, err := strconv.ParseInt(variablesMap[variable], 10, 64)
		if err != nil {
			log.Error(variable + " is not a number")
			panic(variable + " is not a number")
		}
		numericVariablesMap[variable] = value
	}

	return &Config{
		MaxProcs: numericVariablesMap["MAX_PROCS"],
		Redis: RedisConfig{
			URL:        variablesMap["REDIS_URL"],
			PubChannel: variablesMap["REDIS_PUB_CHANNEL"],
		},
		Logger: LoggerConfig{
			Env:   strings.ToLower(variablesMap["ENV"]),
			Debug: strings.ToLower(variablesMap["DEBUG"]) == "true",
		},
		Email: EmailConfig{
			Host:     variablesMap["EMAIL_HOST"],
			Port:     variablesMap["EMAIL_PORT"],
			Username: variablesMap["EMAIL_USERNAME"],
			Password: variablesMap["EMAIL_PASSWORD"],
			Name:     variablesMap["EMAIL_NAME"],
		},
	}
}
