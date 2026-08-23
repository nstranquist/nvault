package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/nstranquist/nvault/config"
	"github.com/nstranquist/nvault/crypto"
	identityfile "github.com/nstranquist/nvault/identity"
	"github.com/nstranquist/nvault/store"
	"golang.org/x/term"
)

var environmentKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type localOptions struct {
	configPath       string
	configExists     bool
	storeDir         string
	storeSource      string
	identityPath     string
	identityEnv      bool
	identitySource   string
	passphraseFile   string
	passphraseSource string
	scope            string
	scopeSource      string
	kind             string
	only             []string
	all              bool
	json             bool
	noConfig         bool
}

const (
	settingSourceDefault           = "default"
	settingSourceConfig            = "config"
	settingSourceEnvironment       = "environment"
	settingSourceEnvironmentKey    = "environment-key"
	settingSourceEnvironmentSecret = "environment-secret"
	settingSourceFlag              = "flag"
	settingSourceInteractive       = "interactive"
)

func defaultStoreDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(dir, "nvault", "store"), nil
}

func defaultIdentityPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(dir, "nvault", "identity.json"), nil
}

type localParseMode struct {
	allowKind          bool
	allowOnly          bool
	allowAll           bool
	allowJSON          bool
	allowNoConfig      bool
	allowMissingConfig bool
}

func selectedConfigPath(args []string) (string, bool, error) {
	path := os.Getenv("NVAULT_CONFIG_FILE")
	explicit := path != ""
	seen := false
	for index := 0; index < len(args); index++ {
		if args[index] == "--" {
			break
		}
		if args[index] != "--config" {
			continue
		}
		if seen {
			return "", false, errors.New("--config can be set only once")
		}
		if index+1 >= len(args) {
			return "", false, errors.New("--config requires a file")
		}
		path = args[index+1]
		explicit = true
		seen = true
		index++
	}
	if path == "" {
		var err error
		path, err = config.DefaultPath()
		if err != nil {
			return "", false, err
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", false, fmt.Errorf("resolve config path: %w", err)
	}
	return filepath.Clean(absolute), explicit, nil
}

func localDefaults(args []string, allowMissingConfig bool) (localOptions, error) {
	storeDir, err := defaultStoreDir()
	if err != nil {
		return localOptions{}, err
	}
	identityPath, err := defaultIdentityPath()
	if err != nil {
		return localOptions{}, err
	}
	configPath, explicitConfig, err := selectedConfigPath(args)
	if err != nil {
		return localOptions{}, err
	}
	opts := localOptions{
		configPath:       configPath,
		storeDir:         storeDir,
		storeSource:      settingSourceDefault,
		identityPath:     identityPath,
		identitySource:   settingSourceDefault,
		passphraseSource: settingSourceInteractive,
		scope:            store.DefaultScope,
		scopeSource:      settingSourceDefault,
		kind:             "secret",
	}
	ignoreConfig := false
	for _, argument := range args {
		if argument == "--" {
			break
		}
		if argument == "--no-config" {
			ignoreConfig = true
			break
		}
	}
	if !ignoreConfig {
		configured, loadErr := config.Load(configPath)
		if loadErr == nil {
			opts.configExists = true
			if configured.IdentityFile != "" {
				opts.identityPath = configured.IdentityFile
				opts.identitySource = settingSourceConfig
			}
			if configured.StoreDir != "" {
				opts.storeDir = configured.StoreDir
				opts.storeSource = settingSourceConfig
			}
			if configured.PassphraseFile != "" {
				opts.passphraseFile = configured.PassphraseFile
				opts.passphraseSource = settingSourceConfig
			}
			if configured.DefaultScope != "" {
				opts.scope = configured.DefaultScope
				opts.scopeSource = settingSourceConfig
			}
		} else if !errors.Is(loadErr, os.ErrNotExist) || (explicitConfig && !allowMissingConfig) {
			return localOptions{}, loadErr
		}
	}
	if value := os.Getenv("NVAULT_IDENTITY_FILE"); value != "" {
		opts.identityPath = value
		opts.identitySource = settingSourceEnvironment
	}
	if os.Getenv("NVAULT_IDENTITY_KEY") != "" {
		opts.identityPath = ""
		opts.identityEnv = true
		opts.identitySource = settingSourceEnvironmentKey
	}
	if value := os.Getenv("NVAULT_STORE_DIR"); value != "" {
		opts.storeDir = value
		opts.storeSource = settingSourceEnvironment
	}
	if value := os.Getenv("NVAULT_PASSPHRASE_FILE"); value != "" {
		opts.passphraseFile = value
		opts.passphraseSource = settingSourceEnvironment
	} else if opts.passphraseFile == "" && os.Getenv("NVAULT_PASSPHRASE") != "" {
		opts.passphraseSource = settingSourceEnvironmentSecret
	}
	if value := os.Getenv("NVAULT_SCOPE"); value != "" {
		opts.scope = value
		opts.scopeSource = settingSourceEnvironment
	}
	return opts, nil
}

func parseLocalOptions(args []string, mode localParseMode) (localOptions, []string, error) {
	opts, err := localDefaults(args, mode.allowMissingConfig)
	if err != nil {
		return localOptions{}, nil, err
	}
	positionals := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		next := func() (string, error) {
			if index+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", argument)
			}
			index++
			return args[index], nil
		}
		switch argument {
		case "--config":
			_, err = next()
		case "--store":
			opts.storeDir, err = next()
			opts.storeSource = settingSourceFlag
		case "--identity":
			opts.identityPath, err = next()
			opts.identityEnv = false
			opts.identitySource = settingSourceFlag
		case "--passphrase-file":
			opts.passphraseFile, err = next()
			opts.passphraseSource = settingSourceFlag
		case "--scope":
			opts.scope, err = next()
			opts.scopeSource = settingSourceFlag
		case "--kind":
			if !mode.allowKind {
				return localOptions{}, nil, fmt.Errorf("--kind is not valid for this command")
			}
			opts.kind, err = next()
		case "--only":
			if !mode.allowOnly {
				return localOptions{}, nil, fmt.Errorf("--only is not valid for this command")
			}
			var value string
			value, err = next()
			if err == nil {
				for _, key := range strings.Split(value, ",") {
					key = strings.TrimSpace(key)
					if key == "" {
						return localOptions{}, nil, errors.New("--only contains an empty key")
					}
					opts.only = append(opts.only, key)
				}
			}
		case "--all":
			if !mode.allowAll {
				return localOptions{}, nil, fmt.Errorf("--all is not valid for this command")
			}
			opts.all = true
		case "--json":
			if !mode.allowJSON {
				return localOptions{}, nil, fmt.Errorf("--json is not valid for this command")
			}
			opts.json = true
		case "--no-config":
			if !mode.allowNoConfig {
				return localOptions{}, nil, fmt.Errorf("--no-config is not valid for this command")
			}
			opts.noConfig = true
		default:
			if strings.HasPrefix(argument, "-") {
				return localOptions{}, nil, fmt.Errorf("unexpected option %q", argument)
			}
			positionals = append(positionals, argument)
		}
		if err != nil {
			return localOptions{}, nil, err
		}
	}
	if err := store.ValidateSlot(opts.scope, "PLACEHOLDER"); err != nil {
		return localOptions{}, nil, err
	}
	if opts.noConfig {
		for index, argument := range args {
			if argument == "--config" && index+1 < len(args) {
				return localOptions{}, nil, errors.New("--config and --no-config cannot be used together")
			}
		}
	}
	if opts.all && len(opts.only) != 0 {
		return localOptions{}, nil, errors.New("--all and --only cannot be used together")
	}
	for name, value := range map[string]*string{
		"identity":        &opts.identityPath,
		"store":           &opts.storeDir,
		"passphrase file": &opts.passphraseFile,
	} {
		if *value == "" {
			continue
		}
		absolute, err := filepath.Abs(*value)
		if err != nil {
			return localOptions{}, nil, fmt.Errorf("resolve %s path: %w", name, err)
		}
		*value = filepath.Clean(absolute)
	}
	return opts, positionals, nil
}

func configuredPassphrase(path string) ([]byte, bool, error) {
	if path != "" {
		raw, err := readPrivateRegularFile(path, identityfile.MaximumPassphrase+2, "passphrase file")
		if err != nil {
			return nil, true, fmt.Errorf("read passphrase file %s: %w", path, err)
		}
		if len(raw) > identityfile.MaximumPassphrase+2 {
			return nil, true, fmt.Errorf("passphrase file exceeds %d bytes", identityfile.MaximumPassphrase)
		}
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		raw = bytes.TrimSuffix(raw, []byte("\r"))
		return raw, true, nil
	}
	if passphrase := os.Getenv("NVAULT_PASSPHRASE"); passphrase != "" {
		return []byte(passphrase), true, nil
	}
	return nil, false, nil
}

func readPrivateRegularFile(path string, maximum int64, label string) (result []byte, returnErr error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s %s: %w", label, path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %s is not a regular file", label, path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s %s permissions are %#o; remove group and other access", label, path, info.Mode().Perm())
	}
	if maximum > 0 && info.Size() > maximum {
		return nil, fmt.Errorf("%s %s exceeds %d bytes", label, path, maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s %s: %w", label, path, err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, wrapOperationError("close "+label, file.Close()))
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened %s %s: %w", label, path, err)
	}
	if !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("%s %s changed while it was opened", label, path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s %s: %w", label, path, err)
	}
	if maximum > 0 && int64(len(raw)) > maximum {
		clear(raw)
		return nil, fmt.Errorf("%s %s exceeds %d bytes", label, path, maximum)
	}
	return raw, nil
}

func openVerifiedDirectory(path, label string) (*os.Root, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", label, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", label)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("inspect opened %s: %w", label, err),
			wrapOperationError("close "+label, root.Close()),
		)
	}
	if !os.SameFile(info, openedInfo) {
		return nil, errors.Join(
			fmt.Errorf("%s changed while it was opened", label),
			wrapOperationError("close "+label, root.Close()),
		)
	}
	return root, nil
}

func syncOpenedDirectory(root *os.Root) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(
		wrapOperationError("sync directory", syncErr),
		wrapOperationError("close directory", closeErr),
	)
}

func wrapOperationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

var (
	isTerminal   = term.IsTerminal
	readPassword = term.ReadPassword
)

func promptHidden(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !isTerminal(fd) {
		return nil, errors.New("a passphrase source is required in non-interactive mode; use --passphrase-file or NVAULT_PASSPHRASE_FILE")
	}
	fmt.Fprint(os.Stderr, label)
	value, err := readPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read hidden passphrase: %w", err)
	}
	return value, nil
}

func readPassphrase(path string) ([]byte, error) {
	value, configured, err := configuredPassphrase(path)
	if err != nil || configured {
		return value, err
	}
	return promptHidden("nvault passphrase: ")
}

func readNewPassphrase(path string) ([]byte, error) {
	value, configured, err := configuredPassphrase(path)
	if err != nil || configured {
		return value, err
	}
	first, err := promptHidden("Create a long, unique nvault passphrase: ")
	if err != nil {
		return nil, err
	}
	second, err := promptHidden("Confirm the nvault passphrase: ")
	if err != nil {
		clear(first)
		return nil, err
	}
	defer clear(second)
	if !bytes.Equal(first, second) {
		clear(first)
		return nil, errors.New("passphrases do not match")
	}
	return first, nil
}

func loadIdentity(path string, useDefault bool, passphraseFile string) (crypto.Identity, error) {
	if path == "" {
		if encoded := os.Getenv("NVAULT_IDENTITY_KEY"); encoded != "" {
			return parsePrivate(encoded)
		}
		if !useDefault {
			return crypto.Identity{}, errors.New("--identity FILE or NVAULT_IDENTITY_KEY is required")
		}
		var err error
		path, err = defaultIdentityPath()
		if err != nil {
			return crypto.Identity{}, err
		}
	}
	raw, err := readPrivateRegularFile(path, 16<<10, "identity file")
	if err != nil {
		return crypto.Identity{}, err
	}
	defer clear(raw)
	var wire struct {
		Format  string `json:"format"`
		Public  string `json:"public"`
		Private string `json:"private"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return crypto.Identity{}, fmt.Errorf("inspect identity %s: %w", path, err)
	}
	if wire.Format == identityfile.FormatV1 {
		passphrase, err := readPassphrase(passphraseFile)
		if err != nil {
			return crypto.Identity{}, err
		}
		defer clear(passphrase)
		id, err := identityfile.Unwrap(raw, passphrase)
		if err != nil {
			return crypto.Identity{}, fmt.Errorf("unlock identity %s: %w", path, err)
		}
		return id, nil
	}
	id, err := parsePrivate(wire.Private)
	if err != nil {
		return crypto.Identity{}, fmt.Errorf("decode identity %s: %w", path, err)
	}
	if wire.Public != "" && wire.Public != id.Public.String() {
		return crypto.Identity{}, fmt.Errorf("identity %s public key does not match its private key", path)
	}
	return id, nil
}

func openLocal(opts localOptions) (*store.Vault, error) {
	id, err := loadIdentity(opts.identityPath, true, opts.passphraseFile)
	if err != nil {
		return nil, err
	}
	return store.Open(opts.storeDir, id)
}

func validateExistingConfigSelection(opts localOptions) error {
	if !opts.configExists || opts.noConfig {
		return nil
	}
	configured, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	identityPath, err := defaultIdentityPath()
	if err != nil {
		return err
	}
	storeDir, err := defaultStoreDir()
	if err != nil {
		return err
	}
	scope := store.DefaultScope
	if configured.IdentityFile != "" {
		identityPath = configured.IdentityFile
	}
	if configured.StoreDir != "" {
		storeDir = configured.StoreDir
	}
	if configured.DefaultScope != "" {
		scope = configured.DefaultScope
	}
	if opts.identityPath != identityPath || opts.storeDir != storeDir || opts.scope != scope {
		return errors.New("init selections conflict with the existing config; edit the config first or use --no-config for a one-off setup")
	}
	return nil
}

func initLocal(args []string) (returnErr error) {
	opts, positionals, err := parseLocalOptions(args, localParseMode{
		allowJSON:          true,
		allowNoConfig:      true,
		allowMissingConfig: true,
	})
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return errors.New("init does not accept positional arguments")
	}
	if err := validateExistingConfigSelection(opts); err != nil {
		return err
	}
	if opts.identityPath == "" {
		return errors.New("init cannot use NVAULT_IDENTITY_KEY; select a new identity file with --identity or NVAULT_IDENTITY_FILE")
	}
	identityPath := opts.identityPath
	if _, err := os.Lstat(identityPath); err == nil {
		return fmt.Errorf("identity %s already exists", identityPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect identity %s: %w", identityPath, err)
	}
	if !opts.json && isTerminal(int(os.Stdout.Fd())) && isTerminal(int(os.Stdin.Fd())) {
		if _, err := fmt.Fprintf(os.Stderr, "nvault first-run setup\n  Config:   %s\n  Identity: %s\n  Store:    %s\n  Scope:    %s\n\n", opts.configPath, identityPath, opts.storeDir, opts.scope); err != nil {
			return fmt.Errorf("write setup summary: %w", err)
		}
	}
	passphrase, err := readNewPassphrase(opts.passphraseFile)
	if err != nil {
		return err
	}
	defer clear(passphrase)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	raw, err := identityfile.Wrap(id, passphrase)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err := os.MkdirAll(opts.storeDir, 0o700); err != nil {
		return fmt.Errorf("create store: %w", err)
	}
	if _, err := store.Open(opts.storeDir, id); err != nil {
		return fmt.Errorf("validate store: %w", err)
	}
	identityRoot, err := openVerifiedDirectory(filepath.Dir(identityPath), "identity directory")
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, wrapOperationError("close identity directory", identityRoot.Close()))
	}()
	identityName := filepath.Base(filepath.Clean(identityPath))
	file, err := identityRoot.OpenFile(identityName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create identity %s: %w", identityPath, err)
	}
	keepIdentity := false
	fileClosed := false
	defer func() {
		if !fileClosed {
			returnErr = errors.Join(returnErr, wrapOperationError("close identity", file.Close()))
		}
		if !keepIdentity {
			if err := identityRoot.Remove(identityName); err != nil && !errors.Is(err, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove incomplete identity: %w", err))
			}
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync identity: %w", err)
	}
	closeErr := file.Close()
	fileClosed = true
	if closeErr != nil {
		return fmt.Errorf("close identity: %w", closeErr)
	}
	if err := syncOpenedDirectory(identityRoot); err != nil {
		return fmt.Errorf("sync identity directory: %w", err)
	}
	if !opts.noConfig && !opts.configExists {
		value := config.File{
			Format:         config.FormatV1,
			IdentityFile:   identityPath,
			StoreDir:       opts.storeDir,
			PassphraseFile: opts.passphraseFile,
			DefaultScope:   opts.scope,
		}
		if err := config.WriteExclusive(opts.configPath, value); err != nil {
			return err
		}
		opts.configExists = true
	}
	result := map[string]any{
		"config":     nil,
		"identity":   identityPath,
		"public_key": id.Public.String(),
		"scope":      opts.scope,
		"store":      opts.storeDir,
	}
	if opts.configExists && !opts.noConfig {
		result["config"] = opts.configPath
	}
	keepIdentity = true
	if opts.json || !isTerminal(int(os.Stdout.Fd())) {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	var output strings.Builder
	fmt.Fprintf(&output, "nvault is ready.\n\nIdentity: %s\nStore:    %s\nScope:    %s\n", identityPath, opts.storeDir, opts.scope)
	if configPath, ok := result["config"].(string); ok {
		fmt.Fprintf(&output, "Config:   %s\n", configPath)
	}
	output.WriteString("\nBack up the protected identity file separately from the store.\nKeep the passphrase outside nvault. Losing either one makes stored values unrecoverable.\nRun `nvault doctor`, then add a value with `nvault set NAME`.\n")
	if _, err := io.WriteString(os.Stdout, output.String()); err != nil {
		return fmt.Errorf("write setup result: %w", err)
	}
	return nil
}

func setLocal(args []string) error {
	opts, positionals, err := parseLocalOptions(args, localParseMode{allowKind: true})
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("set requires one KEY")
	}
	var plaintext []byte
	if isTerminal(int(os.Stdin.Fd())) {
		plaintext, err = promptHidden(fmt.Sprintf("Value for %s: ", positionals[0]))
	} else {
		plaintext, err = io.ReadAll(io.LimitReader(os.Stdin, crypto.MaxPlaintextSize+1))
	}
	if err != nil {
		return err
	}
	defer clear(plaintext)
	if len(plaintext) > crypto.MaxPlaintextSize {
		return fmt.Errorf("plaintext exceeds %d bytes", crypto.MaxPlaintextSize)
	}
	vault, err := openLocal(opts)
	if err != nil {
		return err
	}
	return vault.Set(opts.scope, positionals[0], opts.kind, plaintext)
}

func getLocal(args []string) error {
	opts, positionals, err := parseLocalOptions(args, localParseMode{})
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("get requires one KEY")
	}
	vault, err := openLocal(opts)
	if err != nil {
		return err
	}
	plaintext, _, err := vault.Get(opts.scope, positionals[0])
	if err != nil {
		return err
	}
	defer clear(plaintext)
	_, err = os.Stdout.Write(plaintext)
	return err
}

func listLocal(args []string) error {
	opts, positionals, err := parseLocalOptions(args, localParseMode{allowJSON: true})
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return errors.New("list does not accept positional arguments")
	}
	vault, err := openLocal(opts)
	if err != nil {
		return err
	}
	items, err := vault.List(opts.scope)
	if err != nil {
		return err
	}
	if opts.json {
		return json.NewEncoder(os.Stdout).Encode(items)
	}
	var output strings.Builder
	for _, item := range items {
		fmt.Fprintf(&output, "%s\t%s\t%s\t%s\n", item.Scope, item.Kind, item.Key, item.UpdatedAt.Format("2006-01-02T15:04:05Z"))
	}
	_, err = io.WriteString(os.Stdout, output.String())
	return err
}

func deleteLocal(args []string) error {
	opts, positionals, err := parseLocalOptions(args, localParseMode{})
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("delete requires one KEY")
	}
	vault, err := openLocal(opts)
	if err != nil {
		return err
	}
	return vault.Delete(opts.scope, positionals[0])
}

func runLocal(args []string) error {
	opts, command, err := parseLocalOptions(args, localParseMode{allowOnly: true, allowAll: true})
	if err != nil {
		return err
	}
	if len(command) == 0 {
		return errors.New("run requires -- COMMAND [ARG...]")
	}
	vault, err := openLocal(opts)
	if err != nil {
		return err
	}
	selected := make(map[string]bool)
	for _, key := range opts.only {
		selected[key] = true
	}
	if opts.all {
		items, err := vault.List(opts.scope)
		if err != nil {
			return err
		}
		for _, item := range items {
			selected[item.Key] = true
		}
	}
	if len(selected) == 0 {
		return errors.New("run requires --only KEY,... or explicit --all")
	}
	keys := make([]string, 0, len(selected))
	for key := range selected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := removeEnvironment(os.Environ(), "NVAULT_IDENTITY_KEY", "NVAULT_PASSPHRASE")
	for _, key := range keys {
		if !environmentKey.MatchString(key) {
			return fmt.Errorf("run key %q is not a valid environment variable name", key)
		}
		plaintext, _, err := vault.Get(opts.scope, key)
		if err != nil {
			return err
		}
		if bytes.IndexByte(plaintext, 0) >= 0 {
			clear(plaintext)
			return fmt.Errorf("run value %q contains a NUL byte", key)
		}
		value := string(plaintext)
		clear(plaintext)
		environment = setEnvironment(environment, key, value)
	}
	child := exec.Command(command[0], command[1:]...)
	child.Env = environment
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return child.Run()
}

func setEnvironment(environment []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	return append(out, prefix+value)
}

func removeEnvironment(environment []string, keys ...string) []string {
	blocked := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		blocked[key+"="] = struct{}{}
	}
	out := make([]string, 0, len(environment))
	for _, entry := range environment {
		keep := true
		for prefix := range blocked {
			if strings.HasPrefix(entry, prefix) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, entry)
		}
	}
	return out
}

func configLocal(args []string) error {
	if len(args) == 0 {
		return errors.New("config requires show or path")
	}
	switch args[0] {
	case "path":
		path, _, err := selectedConfigPath(args[1:])
		if err != nil {
			return err
		}
		if len(args) > 1 {
			for index := 1; index < len(args); index++ {
				if args[index] == "--config" && index+1 < len(args) {
					index++
					continue
				}
				return fmt.Errorf("unexpected config path argument %q", args[index])
			}
		}
		_, err = fmt.Fprintln(os.Stdout, path)
		return err
	case "show":
		opts, positionals, err := parseLocalOptions(args[1:], localParseMode{
			allowJSON:          true,
			allowMissingConfig: true,
		})
		if err != nil {
			return err
		}
		if len(positionals) != 0 {
			return errors.New("config show does not accept positional arguments")
		}
		view := struct {
			Format           string `json:"format"`
			ConfigFile       string `json:"config_file"`
			ConfigExists     bool   `json:"config_exists"`
			IdentityFile     string `json:"identity_file,omitempty"`
			IdentitySource   string `json:"identity_source"`
			StoreDir         string `json:"store_dir"`
			StoreSource      string `json:"store_source"`
			PassphraseFile   string `json:"passphrase_file,omitempty"`
			PassphraseSource string `json:"passphrase_source"`
			DefaultScope     string `json:"default_scope"`
			ScopeSource      string `json:"scope_source"`
		}{
			Format:           config.FormatV1,
			ConfigFile:       opts.configPath,
			ConfigExists:     opts.configExists,
			IdentityFile:     opts.identityPath,
			IdentitySource:   opts.identitySource,
			StoreDir:         opts.storeDir,
			StoreSource:      opts.storeSource,
			PassphraseFile:   opts.passphraseFile,
			PassphraseSource: opts.passphraseSource,
			DefaultScope:     opts.scope,
			ScopeSource:      opts.scopeSource,
		}
		if opts.json || !isTerminal(int(os.Stdout.Fd())) {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(view)
		}
		var output strings.Builder
		fmt.Fprintf(&output, "Config:     %s", view.ConfigFile)
		if !view.ConfigExists {
			output.WriteString(" (not created; defaults are active)")
		}
		if view.IdentitySource == settingSourceEnvironmentKey {
			output.WriteString("\nIdentity:   NVAULT_IDENTITY_KEY (environment-key)\n")
		} else {
			fmt.Fprintf(&output, "\nIdentity:   %s (%s)\n", view.IdentityFile, view.IdentitySource)
		}
		fmt.Fprintf(&output, "Store:      %s (%s)\nScope:      %s (%s)\n", view.StoreDir, view.StoreSource, view.DefaultScope, view.ScopeSource)
		if view.PassphraseFile != "" {
			fmt.Fprintf(&output, "Passphrase: %s (%s)\n", view.PassphraseFile, view.PassphraseSource)
		} else if view.PassphraseSource == settingSourceEnvironmentSecret {
			output.WriteString("Passphrase: NVAULT_PASSPHRASE (environment-secret)\n")
		} else {
			output.WriteString("Passphrase: interactive prompt (interactive)\n")
		}
		_, err = io.WriteString(os.Stdout, output.String())
		return err
	default:
		return fmt.Errorf("unknown config command %q", args[0])
	}
}

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func doctorLocal(args []string) error {
	opts, positionals, err := parseLocalOptions(args, localParseMode{
		allowJSON:          true,
		allowMissingConfig: true,
	})
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return errors.New("doctor does not accept positional arguments")
	}
	checks := make([]doctorCheck, 0, 7)
	failed := false
	add := func(name, status, detail string) {
		checks = append(checks, doctorCheck{Name: name, Status: status, Detail: detail})
		if status == "fail" {
			failed = true
		}
	}
	checkOwnerOnly := func(name, path string, wantDir bool) {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			add(name, "fail", statErr.Error())
			return
		}
		if (wantDir && !info.IsDir()) || (!wantDir && !info.Mode().IsRegular()) {
			add(name, "fail", "unexpected file type at "+path)
			return
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			add(name, "fail", fmt.Sprintf("%s permissions are %#o; remove group and other access", path, info.Mode().Perm()))
			return
		}
		add(name, "pass", path)
	}
	if opts.configExists {
		checkOwnerOnly("config", opts.configPath, false)
	} else {
		add("config", "warn", "no config file; built-in defaults and environment settings are active")
	}
	if opts.identityEnv {
		add("identity source", "warn", "NVAULT_IDENTITY_KEY holds a raw private key in the process environment")
	} else {
		checkOwnerOnly("identity permissions", opts.identityPath, false)
		identityRaw, readErr := readPrivateRegularFile(opts.identityPath, 16<<10, "identity file")
		if readErr != nil {
			add("identity format", "fail", readErr.Error())
		} else {
			defer clear(identityRaw)
			var header struct {
				Format string `json:"format"`
			}
			if json.Unmarshal(identityRaw, &header) != nil || header.Format != identityfile.FormatV1 {
				add("identity format", "fail", "the configured local identity is not passphrase-protected nvault.identity.v1")
			} else {
				add("identity format", "pass", identityfile.FormatV1)
			}
		}
	}
	if opts.passphraseFile != "" {
		checkOwnerOnly("passphrase file", opts.passphraseFile, false)
	}
	checkOwnerOnly("store permissions", opts.storeDir, true)
	id, unlockErr := loadIdentity(opts.identityPath, true, opts.passphraseFile)
	if unlockErr != nil {
		add("identity unlock", "fail", unlockErr.Error())
	} else {
		add("identity unlock", "pass", id.Public.String())
		vault, openErr := store.Open(opts.storeDir, id)
		if openErr != nil {
			add("store validation", "fail", openErr.Error())
		} else if items, listErr := vault.List(opts.scope); listErr != nil {
			add("store validation", "fail", listErr.Error())
		} else {
			add("store validation", "pass", fmt.Sprintf("%d item(s) in scope %q; values were not displayed", len(items), opts.scope))
		}
	}
	status := "pass"
	if failed {
		status = "fail"
	} else {
		for _, check := range checks {
			if check.Status == "warn" {
				status = "warn"
				break
			}
		}
	}
	report := struct {
		Status string        `json:"status"`
		Checks []doctorCheck `json:"checks"`
	}{Status: status, Checks: checks}
	if opts.json || !isTerminal(int(os.Stdout.Fd())) {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return err
		}
	} else {
		var output strings.Builder
		for _, check := range checks {
			fmt.Fprintf(&output, "%-4s %-22s %s\n", strings.ToUpper(check.Status), check.Name, check.Detail)
		}
		fmt.Fprintf(&output, "\nResult: %s\n", strings.ToUpper(status))
		if _, err := io.WriteString(os.Stdout, output.String()); err != nil {
			return err
		}
	}
	if failed {
		return errors.New("doctor found unsafe or unusable configuration")
	}
	return nil
}
