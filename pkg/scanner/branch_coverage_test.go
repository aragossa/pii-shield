package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// TestMaskURLNonSensitiveEntropyParam exercises the B2 URL-parameter branches
// that the acceptance test does not reach: a non-sensitive key whose value is
// high-entropy (redacted via entropy) and a bare flag parameter without '='
// (passed through unchanged).
func TestMaskURLNonSensitiveEntropyParam(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	out := ScanAndRedact("http://x.com/a?data=AbC9xY2kQ8pLmN0rZ1&low=hi")
	if strings.Contains(out, "AbC9xY2kQ8pLmN0rZ1") || !strings.Contains(out, "data=[HIDDEN") {
		t.Errorf("high-entropy URL param not redacted: %q", out)
	}
	if !strings.Contains(out, "low=hi") {
		t.Errorf("low-entropy URL param altered: %q", out)
	}

	out2 := ScanAndRedact("http://x.com/a?flagonly&foo=1")
	if !strings.Contains(out2, "flagonly") || !strings.Contains(out2, "foo=1") {
		t.Errorf("bare/low URL params altered: %q", out2)
	}
}

// TestGenericKeyPropagatesSensitivity covers the processAndAppend branch where a
// generic key ("key"/"name"/"setting") whose value is itself a sensitive keyword
// (password) marks the following pair's value as sensitive. "plaintext" is
// low-entropy and does not redact on its own, so redaction here proves the
// propagation path fired.
func TestGenericKeyPropagatesSensitivity(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	out := ScanAndRedact(`{"key": "password", "value": "plaintext"}`)
	if strings.Contains(out, "plaintext") {
		t.Errorf("generic-key sensitivity not propagated to next value: %q", out)
	}
}

// TestCustomRegexFallbackPath covers the non-combined custom-regex loop in
// processSingleToken, reached when CustomRegexes is set but CombinedCustomRegex
// is nil (the CLI normally compiles the combined mega-regex; the fallback runs
// each rule individually).
func TestCustomRegexFallbackPath(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	applyCfg(func(c *Config) {
		c.CustomRegexes = []CustomRegexRule{{Regexp: regexp.MustCompile(`^ACCT-\d{6}$`), Name: "acct"}}
		c.CombinedCustomRegex = nil
	})

	out := ScanAndRedact("id ACCT-123456 end")
	if strings.Contains(out, "ACCT-123456") || !strings.Contains(out, "[HIDDEN:acct:") {
		t.Errorf("custom-regex fallback did not redact: %q", out)
	}
}

// TestAdaptiveThresholdPath covers the AdaptiveThreshold branches in
// processSingleToken: the baseline Update on safe tokens, and — once the
// baseline is ready — the GetThreshold read that replaces the static threshold.
func TestAdaptiveThresholdPath(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.AdaptiveThreshold = true
	UpdateConfig(cfg)

	// Feed enough safe, low-entropy tokens to move the baseline past its
	// readiness sample count; every safe token hits the Update path, and once
	// the baseline is ready the GetThreshold branch is exercised too.
	for i := 0; i < 200; i++ {
		ScanAndRedact("the quick brown fox jumps over the lazy dog")
	}
	_ = ScanAndRedact("value ordinaryword end")
}
