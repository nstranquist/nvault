package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIEncryptDecryptRoundTrip(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "nvault")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	idPath := filepath.Join(t.TempDir(), "id.json")
	keygen := exec.Command(bin, "keygen")
	idRaw, err := keygen.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idPath, idRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	enc := exec.Command(bin, "encrypt", "--identity", idPath)
	enc.Stdin = strings.NewReader("hello-extract")
	envelope, err := enc.Output()
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Contains(envelope, []byte("nvault.enc.v1")) {
		t.Fatalf("envelope=%s", envelope)
	}
	dec := exec.Command(bin, "decrypt", "--identity", idPath)
	dec.Stdin = bytes.NewReader(envelope)
	plain, err := dec.Output()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != "hello-extract" {
		t.Fatalf("plain=%q", plain)
	}
}
