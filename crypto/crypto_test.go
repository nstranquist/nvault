package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func mustIdentity(t *testing.T) Identity {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	alice := mustIdentity(t)
	plaintext := []byte("super-secret-value")
	env, err := Encrypt(plaintext, []Recipient{alice.Recipient("alice")}, "org/proj/dev/DB_URL")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if env.Version != FormatV1 || env.Alg != AlgV1 {
		t.Fatalf("envelope header = %s/%s", env.Version, env.Alg)
	}
	if bytes.Contains(env.Ciphertext, plaintext) {
		t.Fatalf("ciphertext contains plaintext (not encrypted)")
	}
	got, err := Decrypt(env, alice, "org/proj/dev/DB_URL")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt = %q want %q", got, plaintext)
	}
}

func TestMultiRecipientEachCanDecrypt(t *testing.T) {
	alice, bob, carol := mustIdentity(t), mustIdentity(t), mustIdentity(t)
	recipients := []Recipient{alice.Recipient("alice"), bob.Recipient("bob"), carol.Recipient("carol")}
	env, err := Encrypt([]byte("shared"), recipients, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(env.Stanzas) != 3 {
		t.Fatalf("want 3 stanzas, got %d", len(env.Stanzas))
	}
	for _, id := range []Identity{alice, bob, carol} {
		got, err := Decrypt(env, id, "")
		if err != nil {
			t.Fatalf("Decrypt for recipient: %v", err)
		}
		if string(got) != "shared" {
			t.Fatalf("got %q", got)
		}
	}
}

func TestNonRecipientCannotDecrypt(t *testing.T) {
	alice := mustIdentity(t)
	mallory := mustIdentity(t)
	env, err := Encrypt([]byte("secret"), []Recipient{alice.Recipient("alice")}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(env, mallory, ""); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Fatalf("non-recipient Decrypt err = %v, want ErrNoMatchingRecipient", err)
	}
}

func TestTamperDetection(t *testing.T) {
	alice := mustIdentity(t)
	env, err := Encrypt([]byte("integrity-matters"), []Recipient{alice.Recipient("alice")}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	env.Ciphertext[0] ^= 0x01
	if _, err := Decrypt(env, alice, ""); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered Decrypt err = %v, want ErrTampered", err)
	}
}

func TestAADBinding(t *testing.T) {
	alice := mustIdentity(t)
	env, err := Encrypt([]byte("located"), []Recipient{alice.Recipient("alice")}, "org/proj/prod/KEY")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(env, alice, "org/proj/dev/KEY"); !errors.Is(err, ErrAADMismatch) {
		t.Fatalf("relocated envelope Decrypt err = %v, want ErrAADMismatch", err)
	}
	if got, err := Decrypt(env, alice, "org/proj/prod/KEY"); err != nil || string(got) != "located" {
		t.Fatalf("original slot Decrypt: got=%q err=%v", got, err)
	}

	// Changing only embedded AAD also fails authentication when the caller asks
	// for the forged slot. This is distinct from relocating the whole envelope.
	env.AAD = "org/proj/dev/KEY"
	if _, err := Decrypt(env, alice, "org/proj/dev/KEY"); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered AAD Decrypt err = %v, want ErrTampered", err)
	}
}

func TestRewrapRotation(t *testing.T) {
	alice, bob, carol := mustIdentity(t), mustIdentity(t), mustIdentity(t)
	env, err := Encrypt([]byte("rotate-me"), []Recipient{alice.Recipient("alice"), bob.Recipient("bob")}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rewrapped, err := Rewrap(env, alice, "", []Recipient{alice.Recipient("alice"), carol.Recipient("carol")})
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if !bytes.Equal(rewrapped.Ciphertext, env.Ciphertext) {
		t.Fatalf("rewrap changed ciphertext body")
	}
	if got, err := Decrypt(rewrapped, carol, ""); err != nil || string(got) != "rotate-me" {
		t.Fatalf("carol Decrypt after rewrap: got=%q err=%v", got, err)
	}
	if _, err := Decrypt(rewrapped, bob, ""); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Fatalf("removed member bob err = %v, want ErrNoMatchingRecipient", err)
	}
}

func TestRecoveryKeyIsJustARecipient(t *testing.T) {
	member := mustIdentity(t)
	recovery := mustIdentity(t)
	env, err := Encrypt([]byte("breakglass"), []Recipient{
		member.Recipient("member"),
		recovery.Recipient("recovery"),
	}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(env, recovery, "")
	if err != nil || string(got) != "breakglass" {
		t.Fatalf("recovery Decrypt: got=%q err=%v", got, err)
	}
}

func TestIdentityFromPrivateRoundTrip(t *testing.T) {
	orig := mustIdentity(t)
	restored, err := IdentityFromPrivate(orig.Private())
	if err != nil {
		t.Fatalf("IdentityFromPrivate: %v", err)
	}
	if restored.Public != orig.Public {
		t.Fatalf("derived public key mismatch:\n  orig=%s\n  rest=%s", orig.Public, restored.Public)
	}
	env, err := Encrypt([]byte("x"), []Recipient{orig.Recipient("me")}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got, err := Decrypt(env, restored, ""); err != nil || string(got) != "x" {
		t.Fatalf("restored identity Decrypt: got=%q err=%v", got, err)
	}
}

func TestIdentityFromPrivateRejectsAllZeroKey(t *testing.T) {
	if _, err := IdentityFromPrivate(make([]byte, 32)); err == nil {
		t.Fatal("IdentityFromPrivate accepted an all-zero private key")
	}
}

func TestPublicKeyEncodeParseRoundTrip(t *testing.T) {
	id := mustIdentity(t)
	s := id.Public.String()
	parsed, err := ParsePublicKey(s)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if parsed != id.Public {
		t.Fatalf("public key round-trip mismatch")
	}
	if _, err := ParsePublicKey("garbage"); err == nil {
		t.Fatalf("ParsePublicKey(garbage) should fail")
	}
	if _, err := ParsePublicKey((PublicKey{}).String()); err == nil {
		t.Fatal("ParsePublicKey accepted an all-zero X25519 key")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, s[len(s)-1])
	if last < 0 || last%4 != 0 || last == len(alphabet)-1 {
		t.Fatalf("unexpected canonical base64 tail in %q", s)
	}
	nonCanonical := s[:len(s)-1] + string(alphabet[last+1])
	if _, err := ParsePublicKey(nonCanonical); err == nil {
		t.Fatal("ParsePublicKey accepted non-canonical base64 trailing bits")
	}
	if id.Public.Fingerprint() == "" {
		t.Fatalf("fingerprint empty")
	}
}

func TestUnmarshalRejectsAmbiguousJSON(t *testing.T) {
	alice := mustIdentity(t)
	env, err := Encrypt([]byte("json-me"), []Recipient{alice.Recipient("alice")}, "aad-here")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate top-level field": bytes.Replace(raw, []byte(`{"v":`), []byte(`{"v":"nvault.enc.v1","v":`), 1),
		"duplicate stanza field":    bytes.Replace(raw, []byte(`"recipient_id":`), []byte(`"recipient_id":"other","recipient_id":`), 1),
		"unknown field":             bytes.Replace(raw, []byte(`{"v":`), []byte(`{"unknown":true,"v":`), 1),
		"trailing value":            append(append([]byte(nil), raw...), []byte(` {}`)...),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Unmarshal(input); err == nil {
				t.Fatal("ambiguous envelope was accepted")
			}
		})
	}
}

func TestEnvelopeJSONRoundTrip(t *testing.T) {
	alice := mustIdentity(t)
	env, err := Encrypt([]byte("json-me"), []Recipient{alice.Recipient("alice")}, "aad-here")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	plain, err := Decrypt(got, alice, "aad-here")
	if err != nil || string(plain) != "json-me" {
		t.Fatalf("decrypt after JSON round-trip: got=%q err=%v", plain, err)
	}
}

func TestEncryptRequiresRecipient(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil, ""); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("Encrypt with no recipients err = %v, want ErrNoRecipients", err)
	}
}

func TestUnsupportedFormatRejected(t *testing.T) {
	alice := mustIdentity(t)
	env, _ := Encrypt([]byte("x"), []Recipient{alice.Recipient("a")}, "")
	env.Version = "nvault.enc.v99"
	if _, err := Decrypt(env, alice, ""); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("future-version Decrypt err = %v, want ErrUnsupportedFormat", err)
	}
}

func TestMalformedEnvelopeNeverPanics(t *testing.T) {
	alice := mustIdentity(t)
	valid, err := Encrypt([]byte("x"), []Recipient{alice.Recipient("alice")}, "slot")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Envelope){
		"nil nonce":          func(e *Envelope) { e.Nonce = nil },
		"short nonce":        func(e *Envelope) { e.Nonce = []byte{1} },
		"short ciphertext":   func(e *Envelope) { e.Ciphertext = []byte{1} },
		"no recipients":      func(e *Envelope) { e.Stanzas = nil },
		"short wrapped key":  func(e *Envelope) { e.Stanzas[0].WrappedKey = []byte{1} },
		"empty recipient id": func(e *Envelope) { e.Stanzas[0].RecipientID = "" },
		"duplicate id": func(e *Envelope) {
			e.Stanzas = append(e.Stanzas, e.Stanzas[0])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			clone := *valid
			clone.Nonce = append([]byte(nil), valid.Nonce...)
			clone.Ciphertext = append([]byte(nil), valid.Ciphertext...)
			clone.Stanzas = append([]Stanza(nil), valid.Stanzas...)
			clone.Stanzas[0].WrappedKey = append([]byte(nil), valid.Stanzas[0].WrappedKey...)
			mutate(&clone)
			if _, err := Decrypt(&clone, alice, "slot"); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("Decrypt err = %v, want ErrInvalidEnvelope", err)
			}
		})
	}
	if _, err := Decrypt(nil, alice, "slot"); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Decrypt(nil) err = %v, want ErrInvalidEnvelope", err)
	}
}

func TestRecipientValidation(t *testing.T) {
	alice := mustIdentity(t)
	if _, err := Encrypt([]byte("x"), []Recipient{alice.Recipient("same"), alice.Recipient("same")}, ""); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("duplicate recipient err = %v, want ErrInvalidRecipient", err)
	}
	if _, err := Encrypt([]byte("x"), []Recipient{{ID: "zero"}}, ""); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("zero public key err = %v, want ErrInvalidRecipient", err)
	}
}

func TestRewrapRejectsWrongSlotAndTamperedBody(t *testing.T) {
	alice, bob := mustIdentity(t), mustIdentity(t)
	env, err := Encrypt([]byte("x"), []Recipient{alice.Recipient("alice")}, "slot-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rewrap(env, alice, "slot-b", []Recipient{bob.Recipient("bob")}); !errors.Is(err, ErrAADMismatch) {
		t.Fatalf("wrong-slot Rewrap err = %v, want ErrAADMismatch", err)
	}
	env.Ciphertext[0] ^= 1
	if _, err := Rewrap(env, alice, "slot-a", []Recipient{bob.Recipient("bob")}); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered Rewrap err = %v, want ErrTampered", err)
	}
}

func FuzzUnmarshalDecryptNeverPanics(f *testing.F) {
	id, err := GenerateIdentity()
	if err != nil {
		f.Fatal(err)
	}
	env, err := Encrypt([]byte("seed"), []Recipient{id.Recipient("seed")}, "slot")
	if err != nil {
		f.Fatal(err)
	}
	wire, err := Marshal(env)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(`{"v":"nvault.enc.v1"}`))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, input []byte) {
		parsed, err := Unmarshal(input)
		if err != nil {
			return
		}
		_, _ = Decrypt(parsed, id, "slot")
	})
}
