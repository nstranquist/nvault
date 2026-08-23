package identity

import (
	"bytes"
	"testing"

	"github.com/nstranquist/nvault/crypto"
)

func TestWrapUnwrap(t *testing.T) {
	original, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Wrap(original, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, original.Private()) {
		t.Fatal("identity file contains raw private key")
	}
	restored, err := Unwrap(raw, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if restored.Public != original.Public || !bytes.Equal(restored.Private(), original.Private()) {
		t.Fatal("restored identity differs")
	}
}

func TestWrongPassphraseAndTamperingFail(t *testing.T) {
	original, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Wrap(original, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unwrap(raw, []byte("wrong passphrase")); err == nil {
		t.Fatal("wrong passphrase succeeded")
	}
	tampered := bytes.Replace(raw, []byte(original.Public.String()), []byte("nvpub_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 1)
	if _, err := Unwrap(tampered, []byte("correct horse battery staple")); err == nil {
		t.Fatal("tampered public key succeeded")
	}
}

func TestPassphraseBounds(t *testing.T) {
	value, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Wrap(value, []byte("too short")); err == nil {
		t.Fatal("short passphrase succeeded")
	}
}

func TestUnwrapRejectsAmbiguousJSON(t *testing.T) {
	value, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Wrap(value, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate top-level": bytes.Replace(raw, []byte(`"format":`), []byte(`"format":"nvault.identity.v1","format":`), 1),
		"duplicate nested":    bytes.Replace(raw, []byte(`"name": "argon2id"`), []byte(`"name": "argon2id", "name": "argon2id"`), 1),
		"unknown":             bytes.Replace(raw, []byte(`"format":`), []byte(`"unknown":true,"format":`), 1),
		"trailing":            append(append([]byte(nil), raw...), []byte(` {}`)...),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Unwrap(input, []byte("correct horse battery staple")); err == nil {
				t.Fatal("ambiguous identity JSON was accepted")
			}
		})
	}
}
