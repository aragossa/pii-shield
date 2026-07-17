package scanner

import "testing"

// These tests cover the shared config-compile helpers introduced so the SDK/WASM
// entrypoint derives the same matching state as the CLI (issue #48). The error
// branches matter most: an invalid pattern from an SDK caller must return an
// error rather than panic or terminate the host.

func TestCompileSensitiveKeyPatterns(t *testing.T) {
	// Empty / whitespace-only input compiles to no regex, no error.
	re, err := compileSensitiveKeyPatterns([]string{"", "   "})
	if err != nil {
		t.Fatalf("unexpected error for empty patterns: %v", err)
	}
	if re != nil {
		t.Fatalf("expected nil regex for empty patterns, got %v", re)
	}

	// Valid patterns compile, case-insensitively.
	re, err = compileSensitiveKeyPatterns([]string{"^x-secret-"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if re == nil || !re.MatchString("X-Secret-Token") {
		t.Fatalf("expected case-insensitive match for compiled pattern")
	}

	// Invalid regex returns an error instead of panicking.
	if _, err := compileSensitiveKeyPatterns([]string{"["}); err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestApplySensitiveKeyPatterns(t *testing.T) {
	originalConfig := currentConfig
	defer UpdateConfig(originalConfig)

	// Valid: patterns stored, and UpdateConfig derives the live sensitiveRegex.
	cfg := DefaultConfig()
	cfg.Salt = []byte("test-salt-000000000000000")
	if err := cfg.ApplySensitiveKeyPatterns([]string{" ^x-custom- ", ""}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.SensitiveKeyPatterns) != 1 || cfg.SensitiveKeyPatterns[0] != "^x-custom-" {
		t.Fatalf("expected trimmed single pattern, got %#v", cfg.SensitiveKeyPatterns)
	}
	UpdateConfig(cfg)
	if !isSensitiveKey("X-Custom-Header") {
		t.Fatal("expected key matching the pattern to be sensitive after UpdateConfig")
	}

	// Invalid regex returns an error.
	if err := cfg.ApplySensitiveKeyPatterns([]string{"("}); err == nil {
		t.Fatal("expected error for invalid pattern, got nil")
	}
}

func TestApplyCustomRegexes(t *testing.T) {
	cfg := DefaultConfig()

	// Valid rules populate the combined regex and names.
	err := cfg.ApplyCustomRegexes([]CustomRegexConfig{
		{Pattern: `TX-\d{5}`, Name: "TX"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CombinedCustomRegex == nil || !cfg.CombinedCustomRegex.MatchString("TX-12345") {
		t.Fatal("expected combined custom regex to match")
	}
	if len(cfg.CustomRegexNames) != 1 || cfg.CustomRegexNames[0] != "TX" {
		t.Fatalf("expected custom regex name 'TX', got %#v", cfg.CustomRegexNames)
	}
	if len(cfg.CustomRegexes) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(cfg.CustomRegexes))
	}

	// Empty input clears the derived state.
	if err := cfg.ApplyCustomRegexes(nil); err != nil {
		t.Fatalf("unexpected error clearing: %v", err)
	}
	if cfg.CombinedCustomRegex != nil || cfg.CustomRegexNames != nil {
		t.Fatal("expected combined regex and names cleared on empty input")
	}

	// Invalid pattern returns an error.
	if err := cfg.ApplyCustomRegexes([]CustomRegexConfig{{Pattern: "(", Name: "bad"}}); err == nil {
		t.Fatal("expected error for invalid custom regex, got nil")
	}
}

func TestUpdateConfigInvalidPatternWarnsNotPanics(t *testing.T) {
	originalConfig := currentConfig
	defer UpdateConfig(originalConfig)

	// A caller can set SensitiveKeyPatterns directly (bypassing Apply*), so
	// UpdateConfig must tolerate an invalid pattern: warn, leave sensitiveRegex
	// nil, and never panic.
	cfg := DefaultConfig()
	cfg.Salt = []byte("test-salt-000000000000000")
	cfg.SensitiveKeyPatterns = []string{"("}
	UpdateConfig(cfg)
	if sensitiveRegex != nil {
		t.Fatal("expected sensitiveRegex to be nil after an invalid pattern")
	}
}

func TestApplySafeRegexes(t *testing.T) {
	cfg := DefaultConfig()

	if err := cfg.ApplySafeRegexes([]CustomRegexConfig{{Pattern: `^A1b2.*`, Name: "safe"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.SafeRegexes) != 1 || !cfg.SafeRegexes[0].Regexp.MatchString("A1b2xyz") {
		t.Fatal("expected safe regex to be compiled and match")
	}

	if err := cfg.ApplySafeRegexes([]CustomRegexConfig{{Pattern: "(", Name: "bad"}}); err == nil {
		t.Fatal("expected error for invalid safe regex, got nil")
	}
}
