// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

type JWK interface {
	GetKeyType() string
	GetKeyID() string
	ToUsableKey() (any, error)
	ToJSON() ([]byte, error)
}

type Ed25519JWK struct {
	Kty    string   `json:"kty"`     // Key Type (OKP for Ed25519)
	Crv    string   `json:"crv"`     // Curve (Ed25519)
	X      string   `json:"x"`       // Public Key
	Use    string   `json:"use"`     // Usage (e.g., "sig" for signing)
	Alg    string   `json:"alg"`     // Algorithm (EdDSA for Ed25519)
	Kid    string   `json:"kid"`     // Key AccountID
	KeyOps []string `json:"key_ops"` // Key Operations
}

func (j *Ed25519JWK) GetKeyType() string {
	return j.Kty
}

func (j *Ed25519JWK) GetKeyID() string {
	return j.Kid
}

func (j *Ed25519JWK) ToUsableKey() (any, error) {
	return DecodeEd25519Jwk(*j)
}

func (j *Ed25519JWK) ToJSON() ([]byte, error) {
	return json.Marshal(j)
}

type ES256JWK struct {
	Kty    string   `json:"kty"`     // Key Type (EC for Elliptic Curve)
	Crv    string   `json:"crv"`     // Curve (P-256)
	X      string   `json:"x"`       // X Coordinate
	Y      string   `json:"y"`       // Y Coordinate
	Use    string   `json:"use"`     // Usage (e.g., "sig" for signing)
	Alg    string   `json:"alg"`     // Algorithm (ES256 for P-256)
	Kid    string   `json:"kid"`     // Key AccountID
	KeyOps []string `json:"key_ops"` // Key Operations
}

func (j *ES256JWK) GetKeyType() string {
	return j.Kty
}

func (j *ES256JWK) GetKeyID() string {
	return j.Kid
}

func (j *ES256JWK) ToUsableKey() (any, error) {
	return DecodeP256Jwk(*j)
}

func (j *ES256JWK) ToJSON() ([]byte, error) {
	return json.Marshal(j)
}

type RS256JWK struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	KeyOps []string `json:"key_ops,omitempty"`
}

const (
	kty    string = "OKP"
	crv    string = "Ed25519"
	use    string = "sig"
	alg    string = "EdDSA"
	verify string = "verify"

	p256Kty string = "EC"
	p256Crv string = "P-256"
)

func ExtractKeyID(keyBytes []byte) string {
	hash := sha256.Sum256(keyBytes)
	return Base62Encode(hash[:12])
}

func EncodeEd25519Jwk(publicKey ed25519.PublicKey, kid string) Ed25519JWK {
	return Ed25519JWK{
		Kty:    kty,
		Crv:    crv,
		X:      base64.RawURLEncoding.EncodeToString(publicKey),
		Use:    use,
		Alg:    alg,
		Kid:    kid,
		KeyOps: []string{verify},
	}
}

func DecodeEd25519Jwk(jwk Ed25519JWK) (ed25519.PublicKey, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func EncodeP256Jwk(publicKey *ecdsa.PublicKey, kid string) ES256JWK {
	return ES256JWK{
		Kty:    p256Kty,
		Crv:    p256Crv,
		X:      base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
		Y:      base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
		Use:    use,
		Alg:    alg,
		Kid:    kid,
		KeyOps: []string{verify},
	}
}

func DecodeP256Jwk(jwk ES256JWK) (ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	return ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func DecodeRS256Jwk(jwk RS256JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	e := big.NewInt(0).SetBytes(eBytes).Int64()

	if e <= 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}
