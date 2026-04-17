package hmac

import "testing"

func TestSignDeterministic(t *testing.T) {
	body := []byte(`{"job_id":1}`)
	a := Sign("secret-1", body)
	b := Sign("secret-1", body)
	if a != b {
		t.Fatalf("Sign not deterministic: %q vs %q", a, b)
	}
	if a[:7] != "sha256=" {
		t.Fatalf("missing sha256= prefix: %q", a)
	}
}

func TestSignDifferentSecret(t *testing.T) {
	body := []byte("payload")
	if Sign("a", body) == Sign("b", body) {
		t.Fatal("different secrets must produce different signatures")
	}
}

func TestVerifyHappy(t *testing.T) {
	body := []byte(`{"x":42}`)
	sig := Sign("topsecret", body)
	if !Verify("topsecret", body, sig) {
		t.Fatal("Verify failed for valid signature")
	}
}

func TestVerifyBareDigest(t *testing.T) {
	body := []byte(`{"x":42}`)
	sig := Sign("topsecret", body)
	bare := sig[len(SignaturePrefix):]
	if !Verify("topsecret", body, bare) {
		t.Fatal("Verify must accept bare hex digest form")
	}
}

func TestVerifyRejects(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		body   []byte
		sig    string
	}{
		{"empty sig", "s", []byte("b"), ""},
		{"wrong secret", "right", []byte("b"), Sign("wrong", []byte("b"))},
		{"tampered body", "s", []byte("b"), Sign("s", []byte("c"))},
		{"junk", "s", []byte("b"), "sha256=garbage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if Verify(tc.secret, tc.body, tc.sig) {
				t.Fatal("Verify must reject")
			}
		})
	}
}
