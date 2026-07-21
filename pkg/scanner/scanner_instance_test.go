package scanner

import (
	"strings"
	"testing"
)

// TestNewScanner_UsesOwnConfig verifies a Scanner built with a custom Config
// redacts based on its own SensitiveKeys, not the package-level default.
func TestNewScanner_UsesOwnConfig(t *testing.T) {
	const line = "token=hi"

	// Package-level default treats "token" as a sensitive key, so the value
	// is redacted regardless of its (low) entropy.
	if got := ScanAndRedact(line); !strings.Contains(got, "[HIDDEN") {
		t.Fatalf("package default: expected %q to be redacted, got %q", line, got)
	}

	cfg := DefaultConfig()
	cfg.SensitiveKeys = []string{"onlyfoo"}
	scanner := NewScanner(cfg)

	got := scanner.ScanAndRedact(line)
	if strings.Contains(got, "[HIDDEN") {
		t.Fatalf("custom scanner: expected %q to pass through unredacted, got %q", line, got)
	}
	if got != line {
		t.Fatalf("custom scanner: expected %q unchanged, got %q", line, got)
	}
}

// TestNewScanner_DoesNotMutateGlobal verifies that using a Scanner instance
// leaves the package-level default configuration (and ScanAndRedact's
// behavior) untouched.
func TestNewScanner_DoesNotMutateGlobal(t *testing.T) {
	const line = "token=hi"

	cfg := DefaultConfig()
	cfg.SensitiveKeys = []string{"onlyfoo"}
	scanner := NewScanner(cfg)

	_ = scanner.ScanAndRedact(line)

	if got := ScanAndRedact(line); !strings.Contains(got, "[HIDDEN") {
		t.Fatalf("package default after Scanner use: expected %q to still be redacted, got %q", line, got)
	}
}

// TestNewScanner_ImmutableAcrossUpdateConfig verifies a Scanner's captured
// config snapshot is frozen at construction time: a later UpdateConfig call
// (e.g. from a WASM/SDK caller sharing the same process) must not change how
// an existing Scanner instance behaves.
func TestNewScanner_ImmutableAcrossUpdateConfig(t *testing.T) {
	const line = "token=hi"

	savedCfg := activeCfg()
	defer UpdateConfig(savedCfg)

	cfg := DefaultConfig()
	cfg.SensitiveKeys = []string{"onlyfoo"}
	scanner := NewScanner(cfg)

	// Republish a different global config after the Scanner was built.
	other := DefaultConfig()
	other.SensitiveKeys = []string{"token"}
	UpdateConfig(other)

	got := scanner.ScanAndRedact(line)
	if strings.Contains(got, "[HIDDEN") {
		t.Fatalf("scanner should still use its own snapshot after a later UpdateConfig, got %q", got)
	}
}
