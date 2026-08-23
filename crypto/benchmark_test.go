package crypto

import (
	"fmt"
	"testing"
)

var benchmarkEnvelope *Envelope

func benchmarkRecipients(b *testing.B, count int) ([]Identity, []Recipient) {
	b.Helper()
	identities := make([]Identity, count)
	recipients := make([]Recipient, count)
	for index := range count {
		identity, err := GenerateIdentity()
		if err != nil {
			b.Fatalf("GenerateIdentity: %v", err)
		}
		identities[index] = identity
		recipients[index] = identity.Recipient(fmt.Sprintf("member-%03d", index))
	}
	return identities, recipients
}

func benchmarkEncrypt(b *testing.B, plaintextBytes, recipientCount int) {
	_, recipients := benchmarkRecipients(b, recipientCount)
	plaintext := make([]byte, plaintextBytes)
	b.ReportAllocs()
	b.SetBytes(int64(plaintextBytes))
	b.ResetTimer()
	for range b.N {
		envelope, err := Encrypt(plaintext, recipients, "benchmark/scope/KEY")
		if err != nil {
			b.Fatal(err)
		}
		benchmarkEnvelope = envelope
	}
}

func BenchmarkEncrypt1KiBOneRecipient(b *testing.B) {
	benchmarkEncrypt(b, 1<<10, 1)
}

func BenchmarkEncrypt256KiBOneRecipient(b *testing.B) {
	benchmarkEncrypt(b, 256<<10, 1)
}

func BenchmarkEncrypt1KiBTwentyFiveRecipients(b *testing.B) {
	benchmarkEncrypt(b, 1<<10, 25)
}

func BenchmarkDecrypt256KiB(b *testing.B) {
	identities, recipients := benchmarkRecipients(b, 1)
	envelope, err := Encrypt(make([]byte, 256<<10), recipients, "benchmark/scope/KEY")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(256 << 10)
	b.ResetTimer()
	for range b.N {
		plaintext, err := Decrypt(envelope, identities[0], "benchmark/scope/KEY")
		if err != nil {
			b.Fatal(err)
		}
		clear(plaintext)
	}
}

func BenchmarkRewrapTwentyFiveRecipients(b *testing.B) {
	identities, current := benchmarkRecipients(b, 1)
	_, next := benchmarkRecipients(b, 25)
	envelope, err := Encrypt([]byte("benchmark"), current, "benchmark/scope/KEY")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rewrapped, err := Rewrap(
			envelope,
			identities[0],
			"benchmark/scope/KEY",
			next,
		)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkEnvelope = rewrapped
	}
}
