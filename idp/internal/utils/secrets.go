package utils

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

func generateRandomBytes(byteLen int) ([]byte, error) {
	bytes := make([]byte, byteLen)

	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func GenerateBase64Secret(byteLen int) (string, error) {
	bytes, err := generateRandomBytes(byteLen)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func GenerateBase62Secret(byteLen int) (string, error) {
	bytes, err := generateRandomBytes(byteLen)
	if err != nil {
		return "", err
	}

	randomInt := new(big.Int).SetBytes(bytes)
	return randomInt.Text(62), nil
}
