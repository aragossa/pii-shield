package scanner

// B6 (scanner quality campaign): a malformed PII_CUSTOM_REGEX_LIST or
// PII_SAFE_REGEX_LIST entry used to log.Fatalf during loadConfig, which runs
// at package init — killing not only the CLI but any Go host embedding the
// scanner as a library, before the host's main() ever ran. The fix downgrades
// both lists to warn-and-skip, per rule. Verified pre-fix: exit status 1 with
// "PII_CUSTOM_REGEX_LIST error: invalid json format: ...".

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInvalidRegexListDoesNotKillProcess(t *testing.T) {
	// Helper mode: package init has already loaded config from the env this
	// subprocess was started with; scan the given input and exit cleanly.
	if os.Getenv("SCANNER_B6_HELPER") == "1" {
		fmt.Println(ScanAndRedact(os.Getenv("SCANNER_B6_INPUT")))
		os.Exit(0)
	}

	run := func(t *testing.T, input string, extraEnv ...string) (stdout, stderr string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=TestInvalidRegexListDoesNotKillProcess$")
		cmd.Env = append(os.Environ(),
			"SCANNER_B6_HELPER=1",
			"SCANNER_B6_INPUT="+input,
			"PII_SALT=0123456789abcdef0123456789abcdef")
		cmd.Env = append(cmd.Env, extraEnv...)
		var out, errBuf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errBuf
		if err := cmd.Run(); err != nil {
			t.Fatalf("process died on invalid regex list: %v (stderr: %s)", err, errBuf.String())
		}
		return out.String(), errBuf.String()
	}

	t.Run("invalid JSON warns and scans on", func(t *testing.T) {
		stdout, stderr := run(t, "hello", "PII_CUSTOM_REGEX_LIST=not json")
		if !strings.Contains(stdout, "hello") {
			t.Errorf("expected passthrough output, got %q", stdout)
		}
		if !strings.Contains(stderr, "WARNING") {
			t.Errorf("expected WARNING on stderr, got %q", stderr)
		}
	})

	t.Run("broken custom rule skipped, intact rule still fires", func(t *testing.T) {
		stdout, stderr := run(t, "id SEVENAB ok",
			`PII_CUSTOM_REGEX_LIST=[{"pattern":"([","name":"broken"},{"pattern":"^[A-Z]{7}$","name":"code"}]`)
		if strings.Contains(stdout, "SEVENAB") || !strings.Contains(stdout, "[HIDDEN") {
			t.Errorf("intact rule lost after skipping broken one: %q", stdout)
		}
		if !strings.Contains(stderr, "skipping invalid regex") {
			t.Errorf("expected per-rule skip WARNING, got %q", stderr)
		}
	})

	t.Run("in-process loadConfig branches", func(t *testing.T) {
		// The subprocess runs above prove survival end-to-end but execute in
		// an uninstrumented child process; these direct loadConfig calls —
		// possible at all only because loadConfig no longer terminates —
		// exercise the same branches in-process for coverage.
		t.Setenv("PII_SALT", "0123456789abcdef0123456789abcdef")

		t.Setenv("PII_CUSTOM_REGEX_LIST", "not json")
		if cfg := loadConfig(); len(cfg.CustomRegexes) != 0 {
			t.Errorf("invalid JSON should disable the custom list, got %d rules", len(cfg.CustomRegexes))
		}
		t.Setenv("PII_CUSTOM_REGEX_LIST", `[{"pattern":"([","name":"broken"},{"pattern":"^[A-Z]{7}$","name":"code"}]`)
		if cfg := loadConfig(); len(cfg.CustomRegexes) != 1 || cfg.CustomRegexes[0].Name != "code" {
			t.Errorf("expected the intact custom rule to survive, got %+v", cfg.CustomRegexes)
		}
		t.Setenv("PII_CUSTOM_REGEX_LIST", "")

		t.Setenv("PII_SAFE_REGEX_LIST", "not json")
		if cfg := loadConfig(); len(cfg.SafeRegexes) != 0 {
			t.Errorf("invalid JSON should disable the safe list, got %d rules", len(cfg.SafeRegexes))
		}
		t.Setenv("PII_SAFE_REGEX_LIST", `[{"pattern":"([","name":"broken"},{"pattern":"^ok$","name":"keep"}]`)
		if cfg := loadConfig(); len(cfg.SafeRegexes) != 1 || cfg.SafeRegexes[0].Name != "keep" {
			t.Errorf("expected the intact safe rule to survive, got %+v", cfg.SafeRegexes)
		}
		t.Setenv("PII_SAFE_REGEX_LIST", "")

		// Same warn-and-continue policy for sensitive key patterns.
		t.Setenv("PII_SENSITIVE_KEY_PATTERNS", "([")
		if cfg := loadConfig(); len(cfg.SensitiveKeys) == 0 {
			t.Errorf("bad key pattern must not wipe defaults")
		}
	})

	t.Run("broken safe rule skipped, intact safe rule still protects", func(t *testing.T) {
		// AbC9xY2kQ8pLmN0r redacts via entropy at default config; the intact
		// safe rule must keep protecting it after the broken rule is dropped.
		stdout, stderr := run(t, "value AbC9xY2kQ8pLmN0r end",
			`PII_SAFE_REGEX_LIST=[{"pattern":"([","name":"broken"},{"pattern":"^AbC9xY2kQ8pLmN0r$","name":"keep"}]`)
		if !strings.Contains(stdout, "AbC9xY2kQ8pLmN0r") {
			t.Errorf("safe whitelist lost after skipping broken rule: %q", stdout)
		}
		if !strings.Contains(stderr, "skipping invalid regex") {
			t.Errorf("expected per-rule skip WARNING, got %q", stderr)
		}
	})
}
