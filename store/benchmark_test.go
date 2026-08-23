package store

import (
	"fmt"
	"os"
	"testing"

	"github.com/nstranquist/nvault/crypto"
)

func benchmarkVault(b *testing.B) *Vault {
	b.Helper()
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		b.Fatalf("GenerateIdentity: %v", err)
	}
	directory := b.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		b.Fatalf("Chmod: %v", err)
	}
	vault, err := Open(directory, identity)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	return vault
}

func BenchmarkSet1KiB(b *testing.B) {
	vault := benchmarkVault(b)
	value := make([]byte, 1<<10)
	b.ReportAllocs()
	b.SetBytes(int64(len(value)))
	b.ResetTimer()
	for range b.N {
		if err := vault.Set(DefaultScope, "BENCHMARK", "secret", value); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGet1KiB(b *testing.B) {
	vault := benchmarkVault(b)
	if err := vault.Set(DefaultScope, "BENCHMARK", "secret", make([]byte, 1<<10)); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(1 << 10)
	b.ResetTimer()
	for range b.N {
		value, _, err := vault.Get(DefaultScope, "BENCHMARK")
		if err != nil {
			b.Fatal(err)
		}
		clear(value)
	}
}

func BenchmarkList100(b *testing.B) {
	vault := benchmarkVault(b)
	for index := range 100 {
		if err := vault.Set(
			DefaultScope,
			fmt.Sprintf("KEY_%03d", index),
			"secret",
			[]byte("value"),
		); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		items, err := vault.List(DefaultScope)
		if err != nil {
			b.Fatal(err)
		}
		if len(items) != 100 {
			b.Fatalf("List returned %d items", len(items))
		}
	}
}
