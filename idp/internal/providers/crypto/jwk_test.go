package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

func TestPrivateJWKJSONRoundTrip(t *testing.T) {
	t.Run("ES256", func(t *testing.T) {
		// Scalar 1 exercises fixed-width encoding with leading zeroes.
		scalar := make([]byte, 32)
		scalar[31] = 1
		original, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
		if err != nil {
			t.Fatal(err)
		}
		kid := utils.ExtractECDSAKeyID(&original.PublicKey)
		jwk, err := utils.EncodeP256JwkPrivate(original, kid)
		if err != nil {
			t.Fatal(err)
		}
		if err := jwk.Validate(); err != nil {
			t.Fatal(err)
		}
		data, err := jwk.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		key, err := decodeES256PrivateKeyJSON(string(data))
		if err != nil {
			t.Fatal(err)
		}
		if !key.Equal(original) {
			t.Fatal("private key changed")
		}
		digest := sha256.Sum256([]byte("round trip"))
		signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(&original.PublicKey, digest[:], signature) {
			t.Fatal("signature verification failed")
		}
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		otherJWK, err := utils.EncodeP256JwkPrivate(other, kid)
		if err != nil {
			t.Fatal(err)
		}
		jwk.D = otherJWK.D
		bad, _ := jwk.MarshalJSON()
		if _, err := decodeES256PrivateKeyJSON(string(bad)); err == nil {
			t.Fatal("accepted mismatched public and private keys")
		}
	})
	t.Run("Ed25519", func(t *testing.T) {
		pub, original, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwk := utils.EncodeEd25519JwkPrivate(original, pub, utils.ExtractEd25519KeyID(pub))
		seed, err := base64.RawURLEncoding.DecodeString(jwk.D)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatal("JWK must contain a 32-byte seed")
		}
		if err := jwk.Validate(); err != nil {
			t.Fatal(err)
		}
		data, err := jwk.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		key, err := decodeEd25519PrivateKeyJSON(string(data))
		if err != nil {
			t.Fatal(err)
		}
		if !key.Equal(original) {
			t.Fatal("private key changed")
		}
		message := []byte("round trip")
		if !ed25519.Verify(pub, message, ed25519.Sign(key, message)) {
			t.Fatal("signature verification failed")
		}
		other, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwk.X = base64.RawURLEncoding.EncodeToString(other)
		bad, _ := jwk.MarshalJSON()
		if _, err := decodeEd25519PrivateKeyJSON(string(bad)); err == nil {
			t.Fatal("accepted mismatched public and private keys")
		}
	})
}

func TestPrivateJWKRejectsInvalidData(t *testing.T) {
	for _, data := range []string{"", "{}", "{", "a.b.c", "AA.AA.AA"} {
		if _, err := decodeES256PrivateKeyJSON(data); err == nil {
			t.Errorf("ES256 accepted %q", data)
		}
		if _, err := decodeEd25519PrivateKeyJSON(data); err == nil {
			t.Errorf("Ed25519 accepted %q", data)
		}
	}
}
