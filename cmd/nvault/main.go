// Command nvault is the extracted CLI face of the envelope crypto core.
// Local Keychain inject (`run`) still lives in nicos-tools until this
// extract owns a store backend.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/nstranquist/nvault/crypto"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprint(os.Stdout, `nvault — extracted zero-knowledge envelope CLI

USAGE
  nvault version
  nvault keygen
  nvault encrypt --identity FILE   seal stdin; write envelope JSON
  nvault decrypt --identity FILE   open envelope JSON from stdin

This extract is not public yet. nicos-tools ndev vault remains the
operator inject path (ndev vault run --only KEY -- <cmd>).
`)
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Fprintln(os.Stdout, "nvault 0.1.0-extract")
	case "keygen":
		id, err := crypto.GenerateIdentity()
		if err != nil {
			fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
			"public":  id.Public.String(),
			"private": "nvpriv_" + base64.RawURLEncoding.EncodeToString(id.Private()),
		}); err != nil {
			fatal(err)
		}
	case "encrypt":
		id := mustIdentity(os.Args[2:])
		plain, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal(err)
		}
		env, err := crypto.Encrypt(plain, []crypto.Recipient{id.Recipient("self")}, "nvault-extract")
		if err != nil {
			fatal(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(env); err != nil {
			fatal(err)
		}
	case "decrypt":
		id := mustIdentity(os.Args[2:])
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal(err)
		}
		var env crypto.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			fatal(err)
		}
		plain, err := crypto.Decrypt(&env, id)
		if err != nil {
			fatal(err)
		}
		if _, err := os.Stdout.Write(plain); err != nil {
			fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "nvault: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func mustIdentity(args []string) crypto.Identity {
	var path string
	for i := 0; i < len(args); i++ {
		if args[i] == "--identity" {
			if i+1 >= len(args) {
				fatal(fmt.Errorf("--identity requires a file"))
			}
			path = args[i+1]
			i++
			continue
		}
		fatal(fmt.Errorf("unexpected arg %q", args[i]))
	}
	if path == "" {
		fatal(fmt.Errorf("--identity FILE is required"))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	var wire struct {
		Private string `json:"private"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		fatal(err)
	}
	const prefix = "nvpriv_"
	if len(wire.Private) <= len(prefix) || wire.Private[:len(prefix)] != prefix {
		fatal(fmt.Errorf("private key must start with %q", prefix))
	}
	priv, err := base64.RawURLEncoding.DecodeString(wire.Private[len(prefix):])
	if err != nil {
		fatal(err)
	}
	id, err := crypto.IdentityFromPrivate(priv)
	if err != nil {
		fatal(err)
	}
	return id
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "nvault:", err)
	os.Exit(1)
}
