package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nstranquist/nvault/config"
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
	const aad = "org/project/dev/HELLO"
	enc := exec.Command(bin, "encrypt", "--identity", idPath, "--aad", aad)
	enc.Stdin = strings.NewReader("hello-extract")
	envelope, err := enc.Output()
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Contains(envelope, []byte("nvault.enc.v1")) {
		t.Fatalf("envelope=%s", envelope)
	}
	dec := exec.Command(bin, "decrypt", "--identity", idPath, "--aad", aad)
	dec.Stdin = bytes.NewReader(envelope)
	plain, err := dec.Output()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != "hello-extract" {
		t.Fatalf("plain=%q", plain)
	}

	relocated := exec.Command(bin, "decrypt", "--identity", idPath, "--aad", "org/project/prod/HELLO")
	relocated.Stdin = bytes.NewReader(envelope)
	if output, err := relocated.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("does not match expected slot")) {
		t.Fatalf("relocated decrypt err=%v output=%q", err, output)
	}
}

func TestCLILocalStoreJourney(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "nvault")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	root := t.TempDir()
	identityPath := filepath.Join(root, "identity.json")
	passphrasePath := filepath.Join(root, "passphrase.txt")
	if err := os.WriteFile(passphrasePath, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	storeDir := filepath.Join(root, "store")
	configPath := filepath.Join(root, "config.json")
	baseArgs := []string{"--config", configPath, "--identity", identityPath, "--store", storeDir, "--passphrase-file", passphrasePath}

	initCommand := exec.Command(bin, append([]string{"init"}, baseArgs...)...)
	if output, err := initCommand.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, output)
	}
	info, err := os.Stat(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("identity mode=%#o", got)
	}
	identityRaw, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(identityRaw, []byte(`"private"`)) || !bytes.Contains(identityRaw, []byte(`"argon2id"`)) {
		t.Fatalf("identity is not passphrase-protected: %s", identityRaw)
	}
	configured, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if configured.IdentityFile != identityPath || configured.StoreDir != storeDir || configured.PassphraseFile != passphrasePath {
		t.Fatalf("config=%+v", configured)
	}
	configShow := exec.Command(bin, "config", "show", "--config", configPath, "--json")
	configShow.Env = removeEnvironment(
		os.Environ(),
		"NVAULT_IDENTITY_FILE",
		"NVAULT_IDENTITY_KEY",
		"NVAULT_STORE_DIR",
		"NVAULT_PASSPHRASE_FILE",
		"NVAULT_PASSPHRASE",
		"NVAULT_SCOPE",
	)
	configOutput, err := configShow.Output()
	if err != nil {
		t.Fatalf("config show: %v", err)
	}
	var configView struct {
		IdentitySource   string `json:"identity_source"`
		StoreSource      string `json:"store_source"`
		PassphraseSource string `json:"passphrase_source"`
		ScopeSource      string `json:"scope_source"`
	}
	if err := json.Unmarshal(configOutput, &configView); err != nil {
		t.Fatalf("decode config show: %v\n%s", err, configOutput)
	}
	if configView.IdentitySource != settingSourceConfig ||
		configView.StoreSource != settingSourceConfig ||
		configView.PassphraseSource != settingSourceConfig ||
		configView.ScopeSource != settingSourceConfig {
		t.Fatalf("config sources=%+v", configView)
	}
	doctor := exec.Command(bin, "doctor", "--config", configPath, "--json")
	doctorOutput, err := doctor.Output()
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	var doctorReport struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(doctorOutput, &doctorReport); err != nil || doctorReport.Status != "pass" {
		t.Fatalf("doctor report=%s err=%v", doctorOutput, err)
	}

	setArgs := append([]string{"set", "DB_URL"}, baseArgs...)
	setCommand := exec.Command(bin, setArgs...)
	setCommand.Stdin = strings.NewReader("postgres://test-secret")
	if output, err := setCommand.CombinedOutput(); err != nil {
		t.Fatalf("set: %v\n%s", err, output)
	}

	getArgs := append([]string{"get", "DB_URL"}, baseArgs...)
	getCommand := exec.Command(bin, getArgs...)
	plaintext, err := getCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "postgres://test-secret" {
		t.Fatalf("get=%q", plaintext)
	}

	listArgs := append([]string{"list", "--json"}, baseArgs...)
	listCommand := exec.Command(bin, listArgs...)
	listing, err := listCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(listing, []byte(`"key":"DB_URL"`)) || bytes.Contains(listing, []byte("test-secret")) {
		t.Fatalf("list=%s", listing)
	}

	printenv, err := exec.LookPath("printenv")
	if err == nil {
		runArgs := append([]string{"run", "--only", "DB_URL"}, baseArgs...)
		runArgs = append(runArgs, "--", printenv, "DB_URL")
		runCommand := exec.Command(bin, runArgs...)
		injected, runErr := runCommand.Output()
		if runErr != nil {
			t.Fatalf("run: %v", runErr)
		}
		if strings.TrimSpace(string(injected)) != "postgres://test-secret" {
			t.Fatalf("run injected=%q", injected)
		}
	}
	missingSelectionArgs := append([]string{"run"}, baseArgs...)
	missingSelectionArgs = append(missingSelectionArgs, "--", failingExecutableForTest())
	if output, err := exec.Command(bin, missingSelectionArgs...).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("requires --only")) {
		t.Fatalf("run without selection: err=%v output=%q", err, output)
	}
	if runtime.GOOS != "windows" {
		credentialCheckArgs := append([]string{"run", "--only", "DB_URL"}, baseArgs...)
		credentialCheckArgs = append(credentialCheckArgs, "--", "sh", "-c", `[ -z "$NVAULT_IDENTITY_KEY" ] && [ -z "$NVAULT_PASSPHRASE" ]`)
		credentialCheck := exec.Command(bin, credentialCheckArgs...)
		credentialCheck.Env = append(os.Environ(), "NVAULT_IDENTITY_KEY=nvpriv_must-not-leak", "NVAULT_PASSPHRASE=must-not-leak")
		if output, err := credentialCheck.CombinedOutput(); err != nil {
			t.Fatalf("run leaked nvault credentials: %v %s", err, output)
		}
	}

	var failingCommand []string
	if runtime.GOOS == "windows" {
		failingCommand = []string{"cmd", "/c", "exit", "7"}
	} else {
		failingCommand = []string{"sh", "-c", "exit 7"}
	}
	runArgs := append([]string{"run", "--only", "DB_URL"}, baseArgs...)
	runArgs = append(runArgs, "--")
	runArgs = append(runArgs, failingCommand...)
	runErr := exec.Command(bin, runArgs...).Run()
	if exited, ok := runErr.(*exec.ExitError); !ok || exited.ExitCode() != 7 {
		t.Fatalf("child exit was not propagated: %T %v", runErr, runErr)
	}

	deleteArgs := append([]string{"delete", "DB_URL"}, baseArgs...)
	if output, err := exec.Command(bin, deleteArgs...).CombinedOutput(); err != nil {
		t.Fatalf("delete: %v\n%s", err, output)
	}
	if output, err := exec.Command(bin, getArgs...).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("item not found")) {
		t.Fatalf("get deleted: err=%v output=%q", err, output)
	}

	if output, err := exec.Command(bin, append([]string{"init"}, baseArgs...)...).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("already exists")) {
		t.Fatalf("second init: err=%v output=%q", err, output)
	}
}

func failingExecutableForTest() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	return "false"
}

func TestLocalConfigPrecedenceAndStrictExplicitPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	if err := config.WriteExclusive(path, config.File{
		Format:       config.FormatV1,
		IdentityFile: "from-config-id",
		StoreDir:     "from-config-store",
		DefaultScope: "config-scope",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NVAULT_STORE_DIR", filepath.Join(root, "from-env-store"))
	t.Setenv("NVAULT_SCOPE", "env-scope")
	opts, positionals, err := parseLocalOptions([]string{
		"KEY",
		"--config", path,
		"--identity", filepath.Join(root, "from-flag-id"),
		"--scope", "flag-scope",
	}, localParseMode{})
	if err != nil {
		t.Fatal(err)
	}
	if len(positionals) != 1 || positionals[0] != "KEY" {
		t.Fatalf("positionals=%v", positionals)
	}
	if opts.identityPath != filepath.Join(root, "from-flag-id") ||
		opts.storeDir != filepath.Join(root, "from-env-store") ||
		opts.scope != "flag-scope" {
		t.Fatalf("opts=%+v", opts)
	}
	if opts.identitySource != settingSourceFlag ||
		opts.storeSource != settingSourceEnvironment ||
		opts.scopeSource != settingSourceFlag ||
		opts.passphraseSource != settingSourceInteractive {
		t.Fatalf("sources=%+v", opts)
	}
	missing := filepath.Join(root, "missing.json")
	if _, _, err := parseLocalOptions([]string{"--config", missing}, localParseMode{}); err == nil {
		t.Fatal("explicit missing config did not fail")
	}
}

func TestLocalConfigReportsSecretSourceWithoutSecret(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NVAULT_IDENTITY_KEY", "nvpriv_test-only")
	t.Setenv("NVAULT_PASSPHRASE", "must-not-appear")
	opts, _, err := parseLocalOptions([]string{
		"--store", filepath.Join(root, "store"),
		"--scope", "test",
	}, localParseMode{allowMissingConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if opts.identitySource != settingSourceEnvironmentKey ||
		opts.passphraseSource != settingSourceEnvironmentSecret ||
		opts.storeSource != settingSourceFlag ||
		opts.scopeSource != settingSourceFlag {
		t.Fatalf("sources=%+v", opts)
	}
	if strings.Contains(fmt.Sprintf("%+v", opts), "must-not-appear") {
		t.Fatal("options retained the passphrase value")
	}
}

func TestInitRejectsSelectionsThatExistingConfigWillNotPersist(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	configuredIdentity := filepath.Join(root, "configured-identity.json")
	if err := config.WriteExclusive(path, config.File{
		Format:       config.FormatV1,
		IdentityFile: configuredIdentity,
		StoreDir:     filepath.Join(root, "configured-store"),
		DefaultScope: "configured",
	}); err != nil {
		t.Fatal(err)
	}
	opts, _, err := parseLocalOptions([]string{
		"--config", path,
		"--identity", filepath.Join(root, "one-off-identity.json"),
	}, localParseMode{allowNoConfig: true, allowMissingConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExistingConfigSelection(opts); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("selection error=%v", err)
	}

	opts, _, err = parseLocalOptions([]string{"--config", path}, localParseMode{allowNoConfig: true, allowMissingConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExistingConfigSelection(opts); err != nil {
		t.Fatalf("matching config rejected: %v", err)
	}
}

func TestRawIdentityEnvironmentPrecedenceIsExplicit(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NVAULT_IDENTITY_KEY", "nvpriv_test-only")
	opts, _, err := parseLocalOptions(nil, localParseMode{allowMissingConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.identityEnv || opts.identityPath != "" {
		t.Fatalf("environment identity opts=%+v", opts)
	}
	selected := filepath.Join(root, "selected.json")
	opts, _, err = parseLocalOptions([]string{"--identity", selected}, localParseMode{allowMissingConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if opts.identityEnv || opts.identityPath != selected {
		t.Fatalf("flag identity opts=%+v", opts)
	}
}

func TestPrivateInputFilesMustBeOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not report POSIX permission bits")
	}
	root := t.TempDir()
	passphrase := filepath.Join(root, "passphrase")
	if err := os.WriteFile(passphrase, []byte("correct horse battery staple"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := configuredPassphrase(passphrase); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("passphrase err=%v", err)
	}
	identity := filepath.Join(root, "identity.json")
	if err := os.WriteFile(identity, []byte(`{"private":"nvpriv_invalid"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(identity, false, ""); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("identity err=%v", err)
	}
}

func TestOpenVerifiedDirectoryRejectsSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "identity-parent")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	root, err := openVerifiedDirectory(link, "identity directory")
	if root != nil {
		if closeErr := root.Close(); closeErr != nil {
			t.Errorf("close unexpected root: %v", closeErr)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlink directory err=%v", err)
	}
}

func TestInteractivePassphraseConfirmation(t *testing.T) {
	originalTerminal := isTerminal
	originalRead := readPassword
	t.Cleanup(func() {
		isTerminal = originalTerminal
		readPassword = originalRead
	})
	isTerminal = func(int) bool { return true }
	responses := [][]byte{[]byte("correct horse battery staple"), []byte("correct horse battery staple")}
	readPassword = func(int) ([]byte, error) {
		value := responses[0]
		responses = responses[1:]
		return value, nil
	}
	value, err := readNewPassphrase("")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if string(value) != "correct horse battery staple" {
		t.Fatal("unexpected passphrase")
	}
}
