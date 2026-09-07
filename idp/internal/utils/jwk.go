// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"unsafe"
)

type SupportedCryptoSuite string

const (
	SupportedCryptoSuiteEd25519 SupportedCryptoSuite = "EdDSA"
	SupportedCryptoSuiteES256   SupportedCryptoSuite = "ES256"
	SupportedCryptoSuiteHS256   SupportedCryptoSuite = "HS256"
	SupportedCryptoSuiteRS256   SupportedCryptoSuite = "RS256"
)

func GetSupportedCryptoSuite(cryptoSuite string) (SupportedCryptoSuite, error) {
	switch cryptoSuite {
	case string(SupportedCryptoSuiteEd25519):
		return SupportedCryptoSuiteEd25519, nil
	case string(SupportedCryptoSuiteES256):
		return SupportedCryptoSuiteES256, nil
	default:
		return "", fmt.Errorf("unsupported crypto suite: %s", cryptoSuite)
	}
}

type JWK interface {
	GetKeyType() string
	GetKeyID() string
	ToUsableKey() (any, error)
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
	Validate() error
	ToPrivateKey() (any, error)
	ComparePublicKey(other JWK) bool
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func (j *JWKSet) Validate() error {
	if j == nil {
		return fmt.Errorf("JWK set is nil")
	}

	for _, jwk := range j.Keys {
		if jwk == nil {
			return fmt.Errorf("One jwk is nil")
		}
		if err := jwk.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (j *JWKSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(*j)
}

func (j *JWKSet) UnmarshalJSON(data []byte) error {
	type Alias JWKSet
	aux := &struct {
		Keys []json.RawMessage `json:"keys"`
		*Alias
	}{
		Alias: (*Alias)(j),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Keys != nil {
		j.Keys = make([]JWK, len(aux.Keys))
		for i, rawKey := range aux.Keys {
			key, err := JsonToJWK(rawKey)
			if err != nil {
				return err
			}
			j.Keys[i] = key
		}
	}

	return nil
}

const (
	okpKty         string = "OKP"
	ed25519Crv     string = "Ed25519"
	ed25519CharLen int    = 43

	ecKty       string = "EC"
	p256Crv     string = "P-256"
	algES256    string = "ES256"
	p256CharLen int    = 43

	useSig   string = "sig"
	algEdDSA string = "EdDSA"
	verify   string = "verify"
	sign     string = "sign"

	rsaKty   string = "RSA"
	algRS256 string = "RS256"
)

func validateCommonJWKFields(kid, use string, keyOps []string) error {
	if kid == "" {
		return fmt.Errorf("kid is required")
	}
	if use != "" && use != useSig {
		return fmt.Errorf("use must be 'sig' or 'enc'")
	}
	if keyOps != nil && (slices.ContainsFunc(keyOps, func(keyOp string) bool {
		return keyOp == sign || keyOp == verify
	})) {
		return fmt.Errorf("key operation should be sign or verify")
	}

	return nil
}

type Ed25519JWK struct {
	Kty    string   `json:"kty"`               // Key Type (OKP for Ed25519)
	Crv    string   `json:"crv"`               // Curve (Ed25519)
	X      string   `json:"x"`                 // Public Key
	D      string   `json:"d,omitempty"`       // Private Key, omit if public key jwt
	Use    string   `json:"use,omitempty"`     // Usage (e.g., "sig" for signing)
	Alg    string   `json:"alg"`               // Algorithm (EdDSA for Ed25519)
	Kid    string   `json:"kid"`               // Key ID
	KeyOps []string `json:"key_ops,omitempty"` // Key Operations
}

func (j *Ed25519JWK) GetKeyType() string {
	return j.Kty
}

func (j *Ed25519JWK) GetKeyID() string {
	return j.Kid
}

func (j *Ed25519JWK) ToUsableKey() (any, error) {
	return DecodeEd25519Jwk(j)
}

func (j *Ed25519JWK) MarshalJSON() ([]byte, error) {
	return json.Marshal(*j)
}

func (j *Ed25519JWK) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, j)
}

func (j *Ed25519JWK) ToPrivateKey() (any, error) {
	return DecodeEd25519JwkPrivate(j)
}

func (j *Ed25519JWK) ComparePublicKey(other JWK) bool {
	otherEdJwk, ok := other.(*Ed25519JWK)
	if !ok {
		return false
	}

	return otherEdJwk.X == j.X && otherEdJwk.Kty == j.Kty && otherEdJwk.Crv == j.Crv && otherEdJwk.Alg == j.Alg
}

func (j *Ed25519JWK) Validate() error {
	if j == nil {
		return fmt.Errorf("JWK is nil")
	}

	if err := validateCommonJWKFields(j.Kid, j.Use, j.KeyOps); err != nil {
		return err
	}

	if j.Alg != algEdDSA || j.Kty != okpKty || j.Crv != ed25519Crv {
		return fmt.Errorf("invalid algorithm, key type or curve")
	}
	if len(j.X) != ed25519CharLen || !BasicBase64URLValidator(j.X) {
		return fmt.Errorf("invalid x")
	}
	if j.D != "" && (len(j.D) != ed25519CharLen || !BasicBase64URLValidator(j.D)) {
		return fmt.Errorf("invalid d")
	}

	return nil
}

type ES256JWK struct {
	Kty    string   `json:"kty"`         // Key Type (EC for Elliptic Curve)
	Crv    string   `json:"crv"`         // Curve (P-256)
	X      string   `json:"x"`           // X Coordinate
	Y      string   `json:"y"`           // Y Coordinate
	D      string   `json:"d,omitempty"` // Private Key, omit if public key jwt
	Use    string   `json:"use"`         // Usage (e.g., "sig" for signing)
	Alg    string   `json:"alg"`         // Algorithm (ES256 for P-256)
	Kid    string   `json:"kid"`         // Key ID
	KeyOps []string `json:"key_ops"`     // Key Operations
}

func (j *ES256JWK) GetKeyType() string {
	return j.Kty
}

func (j *ES256JWK) GetKeyID() string {
	return j.Kid
}

func (j *ES256JWK) ToUsableKey() (any, error) {
	return DecodeP256Jwk(j)
}

func (j *ES256JWK) MarshalJSON() ([]byte, error) {
	return json.Marshal(*j)
}

func (j *ES256JWK) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, j)
}

func (j *ES256JWK) ToPrivateKey() (any, error) {
	return DecodeP256JwkPrivate(j)
}

func (j *ES256JWK) Validate() error {
	if j == nil {
		return fmt.Errorf("JWK is nil")
	}
	if err := validateCommonJWKFields(j.Kid, j.Use, j.KeyOps); err != nil {
		return err
	}
	if j.Alg != algES256 || j.Kty != ecKty || j.Crv != p256Crv {
		return fmt.Errorf("invalid algorithm, key type or curve")
	}
	if len(j.X) != p256CharLen || !BasicBase64URLValidator(j.X) {
		return fmt.Errorf("invalid x")
	}
	if len(j.Y) != p256CharLen || !BasicBase64URLValidator(j.Y) {
		return fmt.Errorf("invalid y")
	}
	if j.D != "" && (len(j.D) != p256CharLen || !BasicBase64URLValidator(j.D)) {
		return fmt.Errorf("invalid d")
	}

	return nil
}

func (j *ES256JWK) ComparePublicKey(other JWK) bool {
	otherESJwk, ok := other.(*ES256JWK)
	if !ok {
		return false
	}

	return otherESJwk.X == j.X && otherESJwk.Y == j.Y && otherESJwk.Kty == j.Kty &&
		otherESJwk.Crv == j.Crv && otherESJwk.Alg == j.Alg
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

func (j *RS256JWK) ComparePublicKey(other JWK) bool {
	otherRSJwk, ok := other.(*RS256JWK)
	if !ok {
		return false
	}

	return otherRSJwk.N == j.N && otherRSJwk.E == j.E && otherRSJwk.Kty == j.Kty && otherRSJwk.Alg == j.Alg
}

func (j *RS256JWK) GetKeyType() string {
	return j.Kty
}

func (j *RS256JWK) GetKeyID() string {
	return j.Kid
}

func (j *RS256JWK) ToUsableKey() (any, error) {
	return DecodeRS256Jwk(j)
}

func (j *RS256JWK) MarshalJSON() ([]byte, error) {
	return json.Marshal(*j)
}

func (j *RS256JWK) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, j)
}

func (j *RS256JWK) ToPrivateKey() (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (j *RS256JWK) Validate() error {
	if j == nil {
		return fmt.Errorf("JWK is nil")
	}
	if err := validateCommonJWKFields(j.Kid, j.Use, j.KeyOps); err != nil {
		return err
	}
	if j.Alg != algRS256 || j.Kty != ecKty {
		return fmt.Errorf("invalid algorithm or key type")
	}
	if !BasicBase64URLValidator(j.N) {
		return fmt.Errorf("invalid N")
	}
	if !BasicBase64URLValidator(j.E) {
		return fmt.Errorf("invalid E")
	}

	return nil
}

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
		Use:    useSig,
		Alg:    algEdDSA,
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
		Use:    useSig,
		Alg:    algEdDSA,
		Kid:    kid,
		D:      base64.RawURLEncoding.EncodeToString(privateKey),
		KeyOps: []string{sign, verify},
	}
}

func DecodeEd25519Jwk(jwk *Ed25519JWK) (ed25519.PublicKey, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func DecodeEd25519JwkPrivate(jwk *Ed25519JWK) (ed25519.PrivateKey, error) {
	if jwk.D == "" {
		return nil, fmt.Errorf("private key not available in JWK")
	}

	privateKey, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	return privateKey, nil
}

func EncodeP256Jwk(publicKey *ecdsa.PublicKey, kid string) (ES256JWK, error) {
	if publicKey == nil || publicKey.Curve != elliptic.P256() {
		return ES256JWK{}, fmt.Errorf("expected a P-256 public key")
	}

	raw, err := publicKey.Bytes()
	if err != nil {
		return ES256JWK{}, fmt.Errorf("encode P-256 public key: %w", err)
	}

	return ES256JWK{
		Kty:    ecKty,
		Crv:    p256Crv,
		X:      base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y:      base64.RawURLEncoding.EncodeToString(raw[33:65]),
		Use:    useSig,
		Alg:    algES256,
		Kid:    kid,
		KeyOps: []string{verify},
	}, nil
}

func EncodeP256JwkPrivate(privateKey *ecdsa.PrivateKey, kid string) (ES256JWK, error) {
	if privateKey == nil {
		return ES256JWK{}, fmt.Errorf("private key is nil")
	}

	jwk, err := EncodeP256Jwk(&privateKey.PublicKey, kid)
	if err != nil {
		return ES256JWK{}, err
	}

	d, err := privateKey.Bytes()
	if err != nil {
		return ES256JWK{}, fmt.Errorf("encode P-256 private key: %w", err)
	}

	jwk.D = base64.RawURLEncoding.EncodeToString(d)
	jwk.KeyOps = []string{sign, verify}
	return jwk, nil
}

func DecodeP256Jwk(jwk *ES256JWK) (*ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}

	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}

	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("P-256 coordinates must each be 32 bytes")
	}

	raw := make([]byte, 65)
	raw[0] = 0x04
	copy(raw[1:33], x)
	copy(raw[33:65], y)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
}

func DecodeP256JwkPrivate(jwk *ES256JWK) (*ecdsa.PrivateKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("JWK is nil")
	}
	if jwk.Kty != ecKty || jwk.Crv != p256Crv {
		return nil, fmt.Errorf("expected an EC P-256 JWK")
	}
	if jwk.D == "" {
		return nil, fmt.Errorf("private key not available in JWK")
	}

	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(d) != 32 {
		return nil, fmt.Errorf("P-256 private key must be 32 bytes")
	}

	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, fmt.Errorf("invalid P-256 private key: %w", err)
	}

	publicKey, err := DecodeP256Jwk(jwk)
	if err != nil {
		return nil, err
	}
	if !privateKey.PublicKey.Equal(publicKey) {
		return nil, fmt.Errorf("JWK public key does not match private key")
	}

	return privateKey, nil
}

func DecodeRS256Jwk(jwk *RS256JWK) (*rsa.PublicKey, error) {
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
	case rsaKty:
		var jwk RS256JWK
		if err := json.Unmarshal(jsonBytes, &jwk); err != nil {
			return nil, err
		}
		return &jwk, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

// TODO: fix me

//go:noinline
func WipeBytes(ctx context.Context, logger *slog.Logger, data []byte) {
	if len(data) == 0 {
		return
	}
	if _, err := rand.Read(data); err != nil {
		logger.WarnContext(ctx, "Failed to randomize bytes, wiping only", "error", err)
	}
	for i := range data {
		data[i] = 0
	}
}

func WipeBigInt(ctx context.Context, logger *slog.Logger, bi *big.Int) {
	if bi == nil {
		return
	}

	words := bi.Bits()
	if len(words) == 0 {
		return
	}

	byteSlice := (*[1 << 30]byte)(unsafe.Pointer(&words[0]))[:len(words)*int(unsafe.Sizeof(words[0]))]
	WipeBytes(ctx, logger, byteSlice)
	bi.SetInt64(0)
}

func WipeES256PrivateKey(ctx context.Context, logger *slog.Logger, privKey *ecdsa.PrivateKey) {
	if privKey != nil {
		WipeBigInt(ctx, logger, privKey.D)
		WipeBigInt(ctx, logger, privKey.X)
		WipeBigInt(ctx, logger, privKey.Y)
		privKey.PublicKey = ecdsa.PublicKey{}
		privKey.Curve = nil
		privKey.X = nil
		privKey.Y = nil
		privKey.D = nil
	}
}
