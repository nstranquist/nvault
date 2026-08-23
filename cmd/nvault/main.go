// Command nvault is the CLI for the local secrets core.
// Local encrypted-store commands are implemented in this repository.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nstranquist/nvault/crypto"
	versionpkg "github.com/nstranquist/nvault/version"
)

var version = versionpkg.Current

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		if _, err := fmt.Fprint(os.Stdout, `nvault — local zero-knowledge secrets CLI

USAGE
  nvault version
  nvault init [--config FILE] [--identity FILE] [--store DIR] [--scope NAME] [--passphrase-file FILE] [--no-config] [--json]
  nvault doctor [--config FILE] [--passphrase-file FILE] [--json]
  nvault config show [--config FILE] [--identity FILE] [--store DIR] [--scope NAME] [--passphrase-file FILE] [--json]
  nvault config path [--config FILE]
  nvault set KEY [--scope NAME] [--kind secret|param] [COMMON OPTIONS]
  nvault get KEY [--scope NAME] [COMMON OPTIONS]
  nvault list [--scope NAME] [--json] [COMMON OPTIONS]
  nvault delete KEY [--scope NAME] [COMMON OPTIONS]
  nvault run [--scope NAME] (--only KEY,... | --all) [COMMON OPTIONS] -- COMMAND [ARG...]
  nvault keygen
  nvault encrypt (--identity FILE | --recipient ID=NVPUB) [--passphrase-file FILE] [--aad SLOT]
  nvault decrypt [--identity FILE] [--passphrase-file FILE] [--aad SLOT]

COMMON OPTIONS
  --config FILE --identity FILE --store DIR --passphrase-file FILE

set and encrypt read from stdin. get and decrypt write plaintext to stdout.
init is an interactive first-run wizard when a passphrase source is not set. It
creates a strict, non-secret configuration file, a passphrase-protected identity,
and an encrypted store. run injects selected values only into its child process.
NVAULT_IDENTITY_KEY can provide nvpriv_... when --identity is omitted.
`); err != nil {
			fatal(fmt.Errorf("write help: %w", err))
		}
		return
	}
	switch os.Args[1] {
	case "version":
		if _, err := fmt.Fprintf(os.Stdout, "nvault %s\n", version); err != nil {
			fatal(fmt.Errorf("write version: %w", err))
		}
	case "init":
		if err := initLocal(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "doctor":
		if err := doctorLocal(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "config":
		if err := configLocal(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "set":
		if err := setLocal(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "get":
		if err := getLocal(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "list":
		if err := listLocal(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "delete":
		if err := deleteLocal(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "run":
		if err := runLocal(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "keygen":
		id, err := crypto.GenerateIdentity()
		if err != nil {
			fatal(err)
		}
		privateKey := id.Private()
		privateEncoded := "nvpriv_" + base64.RawURLEncoding.EncodeToString(privateKey)
		clear(privateKey)
		if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
			"public":  id.Public.String(),
			"private": privateEncoded,
		}); err != nil {
			fatal(err)
		}
	case "encrypt":
		opts, err := parseCryptoOptions(os.Args[2:], true)
		if err != nil {
			fatal(err)
		}
		plain, err := io.ReadAll(io.LimitReader(os.Stdin, crypto.MaxPlaintextSize+1))
		if err != nil {
			fatal(err)
		}
		if len(plain) > crypto.MaxPlaintextSize {
			fatal(fmt.Errorf("plaintext exceeds %d bytes", crypto.MaxPlaintextSize))
		}
		recipients := opts.recipients
		if len(recipients) == 0 {
			id := mustIdentity(opts.identityPath, opts.passphraseFile)
			recipients = []crypto.Recipient{id.Recipient("self")}
		}
		env, err := crypto.Encrypt(plain, recipients, opts.aad)
		clear(plain)
		if err != nil {
			fatal(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(env); err != nil {
			fatal(err)
		}
	case "decrypt":
		opts, err := parseCryptoOptions(os.Args[2:], false)
		if err != nil {
			fatal(err)
		}
		id := mustIdentity(opts.identityPath, opts.passphraseFile)
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
		if err != nil {
			fatal(err)
		}
		env, err := crypto.Unmarshal(raw)
		if err != nil {
			fatal(err)
		}
		plain, err := crypto.Decrypt(env, id, opts.aad)
		if err != nil {
			fatal(err)
		}
		_, writeErr := os.Stdout.Write(plain)
		clear(plain)
		if writeErr != nil {
			fatal(writeErr)
		}
	default:
		fmt.Fprintf(os.Stderr, "nvault: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

type cryptoOptions struct {
	identityPath   string
	passphraseFile string
	aad            string
	recipients     []crypto.Recipient
}

func parseCryptoOptions(args []string, allowRecipients bool) (cryptoOptions, error) {
	var opts cryptoOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--identity":
			if i+1 >= len(args) {
				return cryptoOptions{}, fmt.Errorf("--identity requires a file")
			}
			opts.identityPath = args[i+1]
			i++
		case "--aad":
			if i+1 >= len(args) {
				return cryptoOptions{}, fmt.Errorf("--aad requires a slot")
			}
			opts.aad = args[i+1]
			i++
		case "--passphrase-file":
			if i+1 >= len(args) {
				return cryptoOptions{}, fmt.Errorf("--passphrase-file requires a file")
			}
			opts.passphraseFile = args[i+1]
			i++
		case "--recipient":
			if !allowRecipients {
				return cryptoOptions{}, fmt.Errorf("--recipient is valid only for encrypt")
			}
			if i+1 >= len(args) {
				return cryptoOptions{}, fmt.Errorf("--recipient requires ID=NVPUB")
			}
			label, encoded, ok := strings.Cut(args[i+1], "=")
			if !ok || label == "" || encoded == "" {
				return cryptoOptions{}, fmt.Errorf("--recipient requires ID=NVPUB")
			}
			publicKey, err := crypto.ParsePublicKey(encoded)
			if err != nil {
				return cryptoOptions{}, err
			}
			opts.recipients = append(opts.recipients, crypto.Recipient{ID: label, PublicKey: publicKey})
			i++
		default:
			return cryptoOptions{}, fmt.Errorf("unexpected arg %q", args[i])
		}
	}
	return opts, nil
}

func mustIdentity(path, passphraseFile string) crypto.Identity {
	id, err := loadIdentity(path, false, passphraseFile)
	if err != nil {
		fatal(err)
	}
	return id
}

func parsePrivate(encoded string) (crypto.Identity, error) {
	const prefix = "nvpriv_"
	encoded = strings.TrimPrefix(encoded, prefix)
	var priv []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		var candidate []byte
		candidate, err = encoding.DecodeString(encoded)
		if err == nil {
			priv = candidate
			break
		}
		clear(candidate)
	}
	if err != nil {
		return crypto.Identity{}, fmt.Errorf("decode private key: %w", err)
	}
	defer clear(priv)
	id, err := crypto.IdentityFromPrivate(priv)
	if err != nil {
		return crypto.Identity{}, err
	}
	return id, nil
}

func fatal(err error) {
	if exited, ok := err.(interface{ ExitCode() int }); ok {
		if code := exited.ExitCode(); code >= 0 {
			os.Exit(code)
		}
	}
	fmt.Fprintln(os.Stderr, "nvault:", err)
	os.Exit(1)
}
