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
	Kty    string   `json:"kty"`         // Key Type (OKP for Ed25519)
	Crv    string   `json:"crv"`         // Curve (Ed25519)
	X      string   `json:"x"`           // Public Key
	D      string   `json:"d,omitempty"` // Private Key, omit if public key jwt
	Use    string   `json:"use"`         // Usage (e.g., "sig" for signing)
	Alg    string   `json:"alg"`         // Algorithm (EdDSA for Ed25519)
	Kid    string   `json:"kid"`         // Key AccountID
	KeyOps []string `json:"key_ops"`     // Key Operations
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
	Kty    string   `json:"kty"`         // Key Type (EC for Elliptic Curve)
	Crv    string   `json:"crv"`         // Curve (P-256)
	X      string   `json:"x"`           // X Coordinate
	Y      string   `json:"y"`           // Y Coordinate
	D      string   `json:"d,omitempty"` // Private Key, omit if public key jwt
	Use    string   `json:"use"`         // Usage (e.g., "sig" for signing)
	Alg    string   `json:"alg"`         // Algorithm (ES256 for P-256)
	Kid    string   `json:"kid"`         // Key AccountID
	KeyOps []string `json:"key_ops"`     // Key Operations
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
	okpKty     string = "OKP"
	ed25519Crv string = "Ed25519"

	ecKty   string = "EC"
	p256Crv string = "P-256"

	use    string = "sig"
	alg    string = "EdDSA"
	verify string = "verify"
	sign   string = "sign"
)

func bigIntToPaddedBytes(n *big.Int, length int) []byte {
	bytes := n.Bytes()
	if len(bytes) >= length {
		return bytes
	}

	paddedBytes := make([]byte, length)
	copy(paddedBytes[length-len(bytes):], bytes)
	return paddedBytes
}

func ExtractECDSAKeyID(pub *ecdsa.PublicKey) string {
	curveBits := pub.Curve.Params().BitSize
	byteLen := (curveBits + 7) / 8

	xBytes := bigIntToPaddedBytes(pub.X, byteLen)
	yBytes := bigIntToPaddedBytes(pub.Y, byteLen)
	keyBytes := append(xBytes, yBytes...)

	return extractKeyID(keyBytes)
}

func ExtractEd25519KeyID(pub ed25519.PublicKey) string {
	return extractKeyID(pub)
}

func EncodeEd25519Jwk(publicKey ed25519.PublicKey, kid string) Ed25519JWK {
	return Ed25519JWK{
		Kty:    okpKty,
		Crv:    ed25519Crv,
		X:      base64.RawURLEncoding.EncodeToString(publicKey),
		Use:    use,
		Alg:    alg,
		Kid:    kid,
		KeyOps: []string{verify},
	}
}

func EncodeEd25519JwkPrivate(
	privateKey ed25519.PrivateKey,
	publicKey ed25519.PublicKey,
	kid string,
) Ed25519JWK {
	return Ed25519JWK{
		Kty:    okpKty,
		Crv:    ed25519Crv,
		X:      base64.RawURLEncoding.EncodeToString(publicKey),
		Use:    use,
		Alg:    alg,
		Kid:    kid,
		D:      base64.RawURLEncoding.EncodeToString(privateKey),
		KeyOps: []string{sign, verify},
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
		Kty:    ecKty,
		Crv:    p256Crv,
		X:      base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
		Y:      base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
		Use:    use,
		Alg:    alg,
		Kid:    kid,
		KeyOps: []string{verify},
	}
}

func EncodeP256JwkPrivate(privateKey *ecdsa.PrivateKey, kid string) ES256JWK {
	publicKey := privateKey.Public().(*ecdsa.PublicKey)

	return ES256JWK{
		Kty:    ecKty,
		Crv:    p256Crv,
		D:      base64.RawURLEncoding.EncodeToString(privateKey.D.Bytes()),
		X:      base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
		Y:      base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
		Use:    use,
		Alg:    alg,
		Kid:    kid,
		KeyOps: []string{sign, verify},
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

func JsonToJWK(jsonBytes []byte) (JWK, error) {
	// First, unmarshal into a map to inspect the 'kty' (Key Type) field.
	var keyTypeMap map[string]json.RawMessage
	if err := json.Unmarshal(jsonBytes, &keyTypeMap); err != nil {
		return nil, fmt.Errorf("failed to peek into json for key type: %w", err)
	}

	ktyRaw, ok := keyTypeMap["kty"]
	if !ok {
		return nil, fmt.Errorf("json is not a JWK: missing 'kty' field")
	}

	var kty string
	if err := json.Unmarshal(ktyRaw, &kty); err != nil {
		return nil, fmt.Errorf("failed to unmarshal 'kty' field: %w", err)
	}

	switch kty {
	case ecKty:
		var jwk ES256JWK
		if err := json.Unmarshal(jsonBytes, &jwk); err != nil {
			return nil, err
		}
		return &jwk, nil
	case okpKty:
		var jwk Ed25519JWK
		if err := json.Unmarshal(jsonBytes, &jwk); err != nil {
			return nil, err
		}
		return &jwk, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}
