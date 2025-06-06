// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func getLog() *slog.Logger {
	if os.Getenv("DEBUG") == "true" {
		return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	return slog.Default()
}

func createDirectory(logger *slog.Logger, name string) {
	logger = logger.With("name", name)
	loc := fmt.Sprintf("../%s", name)

	logger.Debug("Checking if directory exists")
	if _, err := os.Stat(loc); os.IsNotExist(err) {
		logger.Debug("Directory does not exist, creating it...")
		err := os.Mkdir(loc, 0755)

		if err != nil {
			logger.Error("Failed to create directory", "error", err)
			fmt.Println(err)
			return
		}
		logger.Debug("Directory created")
	} else {
		logger.Debug("Keys directory already exists")
	}
}

func encodePublicKey(logger *slog.Logger, publicKey interface{}) pem.Block {
	logger.Debug("Encoding the public key to PEM format...")
	pubKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		logger.Error("Failed to encode the public key to PEM format", "error", err)
		panic(err)
	}

	logger.Debug("Public key encoded to PEM format")
	return pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKey,
	}
}

func encodePrivateKey(logger *slog.Logger, privateKey interface{}) pem.Block {
	logger.Debug("Encoding the private key to PEM format...")
	privKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		logger.Error("Failed to encode the private key to PEM format", "error", err)
		panic(err)
	}
	return pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKey,
	}
}

func generateEd25519KeyPair(logger *slog.Logger) (pem.Block, pem.Block) {
	logger.Debug("Generating a new ED25519 key pair...")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		logger.Error("Failed to generate a new ED25519 key pair", "error", err)
		panic(err)
	}

	logger.Debug("ED25519 key pair generated")
	return encodePublicKey(logger, pub), encodePrivateKey(logger, priv)
}

func generateEs256KeyPair(logger *slog.Logger) (pem.Block, pem.Block) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		logger.Error("Failed to generate a new ES256 key pair", "error", err)
		panic(err)
	}

	return encodePublicKey(logger, &priv.PublicKey), encodePrivateKey(logger, priv)
}

func writeKeyToFile(logger *slog.Logger, name string, block *pem.Block) {
	logger = logger.With("name", name)
	loc := fmt.Sprintf("../keys/%s.key", name)

	logger.Debug("Writing key")
	file, err := os.Create(loc)
	if err != nil {
		logger.Error("Failed to key file", "error", err)
		return
	}

	defer file.Close()
	pem.Encode(file, block)
	logger.Debug("Public key written")
}

func encodeKeyPemToJson(logger *slog.Logger, block *pem.Block) string {
	logger.Debug("Encoding key pem into json")
	keyPEM := pem.EncodeToMemory(block)

	jsonKey, err := json.Marshal(string(keyPEM))
	if err != nil {
		logger.Error("Failed to encoding pem into json", "error", err)
		panic(err)
	}

	return string(jsonKey)
}

func generateSecret(logger *slog.Logger) string {
	logger.Debug("Generating base64 encoded 32 byte secret")
	bytes := make([]byte, 32)

	_, err := rand.Read(bytes)
	if err != nil {
		logger.Error("Failed to generate secret bytes", "error", err)
		panic(err)
	}

	logger.Debug("Secret generated successfully")
	return base64.StdEncoding.EncodeToString(bytes)
}

func writeSecretToFile(logger *slog.Logger, name, secret string) {
	logger = logger.With("name", name)
	loc := fmt.Sprintf("../keys/%s.txt", name)
	logger.Debug("Writing secret to file")

	file, err := os.Create(loc)
	if err != nil {
		logger.Error("Failed to create secret file", "error", err)
		panic(err)
	}
	defer file.Close()

	file.Write([]byte(secret))
}

func createEnvFile(
	logger *slog.Logger,
	accessPubKey,
	accessPrivKey,
	accountKeysPubKey,
	accountKeysPrivKey,
	appsPubKey,
	appsPrivKey,
	refreshPubKey,
	refreshPrivKey,
	confirmPubKey,
	confirmPrivKey,
	resetPubKey,
	resetPrivKey,
	oauthPubKey,
	oauthPrivKey,
	twoFAPubKey,
	twoFAPrivKey,
	cookieSecret,
	accountSecret,
	oidcSecret,
	userSecret string,
) {
	logger.Debug("Creating .env file")

	file, err := os.Create("../keys/.env")
	if err != nil {
		logger.Error("Failed to key file", "error", err)
		panic(err)
	}
	defer file.Close()

	envVars := []string{
		fmt.Sprintf("JWT_ACCESS_PUBLIC_KEY=%s", accessPubKey),
		fmt.Sprintf("JWT_ACCESS_PRIVATE_KEY=%s", accessPrivKey),
		fmt.Sprintf("JWT_ACCOUNT_CREDENTIALS_PUBLIC_KEY=%s", accountKeysPubKey),
		fmt.Sprintf("JWT_ACCOUNT_CREDENTIALS_PRIVATE_KEY=%s", accountKeysPrivKey),
		fmt.Sprintf("JWT_APPS_PUBLIC_KEY=%s", appsPubKey),
		fmt.Sprintf("JWT_APPS_PRIVATE_KEY=%s", appsPrivKey),
		fmt.Sprintf("JWT_REFRESH_PUBLIC_KEY=%s", refreshPubKey),
		fmt.Sprintf("JWT_REFRESH_PRIVATE_KEY=%s", refreshPrivKey),
		fmt.Sprintf("JWT_CONFIRM_PUBLIC_KEY=%s", confirmPubKey),
		fmt.Sprintf("JWT_CONFIRM_PRIVATE_KEY=%s", confirmPrivKey),
		fmt.Sprintf("JWT_RESET_PUBLIC_KEY=%s", resetPubKey),
		fmt.Sprintf("JWT_RESET_PRIVATE_KEY=%s", resetPrivKey),
		fmt.Sprintf("JWT_OAUTH_PUBLIC_KEY=%s", oauthPubKey),
		fmt.Sprintf("JWT_OAUTH_PRIVATE_KEY=%s", oauthPrivKey),
		fmt.Sprintf("JWT_2FA_PUBLIC_KEY=%s", twoFAPubKey),
		fmt.Sprintf("JWT_2FA_PRIVATE_KEY=%s", twoFAPrivKey),
		fmt.Sprintf("COOKIE_SECRET=\"%s\"", cookieSecret),
		fmt.Sprintf("ACCOUNT_SECRET=\"%s\"", accountSecret),
		fmt.Sprintf("OIDC_SECRET=\"%s\"", oidcSecret),
		fmt.Sprintf("USER_SECRET=\"%s\"", userSecret),
	}
	file.Write([]byte(strings.Join(envVars, "\n")))
	logger.Debug("Wrote env")
}

func main() {
	logger := getLog()
	// Check if the keys directory exists
	createDirectory(logger, "keys")
	accessPubKey, accessPrivKey := generateEs256KeyPair(logger)
	accountCredsPubKey, accountKeysPrivKey := generateEs256KeyPair(logger)
	appsPubKey, appsPrivKey := generateEs256KeyPair(logger)
	refreshPubKey, refreshPrivKey := generateEd25519KeyPair(logger)
	confirmPubKey, confirmPrivKey := generateEd25519KeyPair(logger)
	resetPubKey, resetPrivKey := generateEd25519KeyPair(logger)
	oauthPubKey, oauthPrivKey := generateEd25519KeyPair(logger)
	twoFactorPubKey, twoFactorPrivKey := generateEd25519KeyPair(logger)
	writeKeyToFile(logger, "access_public", &accessPubKey)
	writeKeyToFile(logger, "access_private", &accessPrivKey)
	writeKeyToFile(logger, "account_keys_public", &accountCredsPubKey)
	writeKeyToFile(logger, "account_keys_private", &accountKeysPrivKey)
	writeKeyToFile(logger, "apps_public", &appsPubKey)
	writeKeyToFile(logger, "apps_private", &appsPrivKey)
	writeKeyToFile(logger, "refresh_public", &refreshPubKey)
	writeKeyToFile(logger, "refresh_private", &refreshPrivKey)
	writeKeyToFile(logger, "confirm_public", &confirmPubKey)
	writeKeyToFile(logger, "confirm_private", &confirmPrivKey)
	writeKeyToFile(logger, "reset_public", &resetPubKey)
	writeKeyToFile(logger, "reset_private", &resetPrivKey)
	writeKeyToFile(logger, "oauth_public", &oauthPubKey)
	writeKeyToFile(logger, "oauth_private", &oauthPrivKey)
	writeKeyToFile(logger, "two_factor_public", &twoFactorPubKey)
	writeKeyToFile(logger, "two_factor_private", &twoFactorPrivKey)

	cookieSecret := generateSecret(logger)
	writeSecretToFile(logger, "cookie_secret", cookieSecret)
	accountSecret := generateSecret(logger)
	writeSecretToFile(logger, "account_secret", accountSecret)
	oidcSecret := generateSecret(logger)
	writeSecretToFile(logger, "oidc_secret", oidcSecret)
	userSecret := generateSecret(logger)
	writeSecretToFile(logger, "user_secret", userSecret)

	createEnvFile(
		logger,
		encodeKeyPemToJson(logger, &accessPubKey),
		encodeKeyPemToJson(logger, &accessPrivKey),
		encodeKeyPemToJson(logger, &accountCredsPubKey),
		encodeKeyPemToJson(logger, &accountKeysPrivKey),
		encodeKeyPemToJson(logger, &appsPubKey),
		encodeKeyPemToJson(logger, &appsPrivKey),
		encodeKeyPemToJson(logger, &refreshPubKey),
		encodeKeyPemToJson(logger, &refreshPrivKey),
		encodeKeyPemToJson(logger, &confirmPubKey),
		encodeKeyPemToJson(logger, &confirmPrivKey),
		encodeKeyPemToJson(logger, &resetPubKey),
		encodeKeyPemToJson(logger, &resetPrivKey),
		encodeKeyPemToJson(logger, &oauthPubKey),
		encodeKeyPemToJson(logger, &oauthPrivKey),
		encodeKeyPemToJson(logger, &twoFactorPubKey),
		encodeKeyPemToJson(logger, &twoFactorPrivKey),
		cookieSecret,
		accountSecret,
		oidcSecret,
		userSecret,
	)
}
