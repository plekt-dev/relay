// Package hmac provides HMAC-SHA256 signing and verification for webhook
// payloads exchanged between Plekt core and relay receivers.
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignatureHeader is the HTTP header that carries the HMAC signature.
const SignatureHeader = "X-MC-Signature"

// SignaturePrefix is the algorithm tag prepended to the hex digest.
const SignaturePrefix = "sha256="

// Sign returns "sha256=<hex>" of HMAC-SHA256(secret, body).
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return SignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether sig matches the HMAC of body under secret using a
// constant-time comparison.
func Verify(secret string, body []byte, sig string) bool {
	if sig == "" {
		return false
	}
	expected := Sign(secret, body)
	if len(sig) >= len(SignaturePrefix) && sig[:len(SignaturePrefix)] == SignaturePrefix {
		return hmac.Equal([]byte(sig), []byte(expected))
	}
	return hmac.Equal([]byte(sig), []byte(expected[len(SignaturePrefix):]))
}
