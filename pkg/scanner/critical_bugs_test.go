package scanner

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

// campaignConfig returns a deterministic config (fixed salt) so redaction
// hashes are stable across runs. hunter2 under this salt is always
// [HIDDEN:3920d5].
func campaignConfig() Config {
	cfg := DefaultConfig()
	cfg.Salt = []byte("0123456789abcdef0123456789abcdef")
	return cfg
}

// TestNoCascadeAfterBareSensitiveWord covers B1: a bare sensitive keyword in
// prose must not force-redact the whole rest of the segment.
//
// Policy: the FIRST token after a bare sensitive key stays redacted (this is
// the "password hunter2" recall behavior, the single most important detection
// case). Only the tokens AFTER that first value are freed. So the cases below
// check that the cascade is broken — later tokens survive — without asserting
// anything about the single token immediately following the key.
func TestNoCascadeAfterBareSensitiveWord(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// 1. Bare sensitive word in prose: the tail past the first value survives.
	//    ("was" — the first token after "password" — may still be hidden.)
	out := ScanAndRedact("password was rejected for user bob")
	for _, w := range []string{"rejected", "for", "user", "bob"} {
		if !strings.Contains(out, w) {
			t.Errorf("cascade over-redaction: %q missing from %q", w, out)
		}
	}

	// 2. Regression: the value immediately after the key is still hidden.
	out2 := ScanAndRedact("password hunter2")
	if strings.Contains(out2, "hunter2") || !strings.Contains(out2, "[HIDDEN") {
		t.Errorf("key-value detection lost: %q", out2)
	}

	// 3. Second prose case. "provided" is the first token after the "token"
	//    key and may be hidden like "was" above; the cascade fix is proven by
	//    "by" and "client" surviving.
	out3 := ScanAndRedact("invalid token provided by client")
	for _, w := range []string{"by", "client"} {
		if !strings.Contains(out3, w) {
			t.Errorf("cascade over-redaction: %q missing from %q", w, out3)
		}
	}
}

// TestMaskURLPreservesAllContent covers B2: maskURLParameters must not silently
// drop bytes after a second '?', and a secret in a later section must be
// redacted in place rather than dropped.
func TestMaskURLPreservesAllContent(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// 1. Nothing lost across multiple '?'.
	in := "GET http://x.com/a?foo=1?bar=2 done"
	out := ScanAndRedact(in)
	if strings.Count(out, "?") != strings.Count(in, "?") {
		t.Errorf("'?' count changed: in=%q out=%q", in, out)
	}
	if !strings.Contains(out, "bar") || !strings.Contains(out, " done") {
		t.Errorf("URL tail dropped: %q", out)
	}

	// 2. Secret after the second '?' is redacted, not dropped.
	in2 := "http://x.com/cb?state=ok?token=AbC123XyZ987qwerty"
	out2 := ScanAndRedact(in2)
	if strings.Contains(out2, "AbC123XyZ987qwerty") {
		t.Errorf("secret leaked: %q", out2)
	}
	if !strings.Contains(out2, "token=[HIDDEN") {
		t.Errorf("secret dropped instead of redacted: %q", out2)
	}
}

// TestUnbalancedQuoteNotMangled covers B3: the scanner must never invent quote
// characters that were not in the input.
func TestUnbalancedQuoteNotMangled(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	cases := []string{`data="key=value`, `data='key=value`, `x="a=b`, `"k=v`}
	for _, in := range cases {
		out := ScanAndRedact(in)
		if strings.Count(out, `"`) != strings.Count(in, `"`) ||
			strings.Count(out, `'`) != strings.Count(in, `'`) {
			t.Errorf("quotes invented: in=%q out=%q", in, out)
		}
	}

	// Regression: balanced case keeps redaction AND both quotes.
	out := ScanAndRedact(`data="password=hunter2"`)
	if strings.Contains(out, "hunter2") || strings.Count(out, `"`) != 2 {
		t.Errorf("balanced quoted case broken: %q", out)
	}
}

// TestSingleQuoteRewritePreservesQuoteChar covers B8: a single-quoted value
// that gets redacted must keep its original quote character. processSingleToken
// used to always emit `"` regardless of the original quote, so
// token='abc123def456gh' came back as token="[HIDDEN:...]" — changing the
// quote count. This is distinct from B3 (invented/dropped quotes).
func TestSingleQuoteRewritePreservesQuoteChar(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// Entropy/forced-sensitive path (processSingleToken's main redaction branch).
	in := `msg='hello world' token='abc123def456gh'`
	out := ScanAndRedact(in)
	if strings.Contains(out, "abc123def456gh") {
		t.Fatalf("secret leaked: %q", out)
	}
	if strings.Count(out, `'`) != strings.Count(in, `'`) {
		t.Errorf("quote character changed: in=%q out=%q", in, out)
	}
	if strings.Contains(out, `"`) {
		t.Errorf("single quote rewritten to double quote: %q", out)
	}

	// Regression: a double-quoted value still gets double quotes.
	in2 := `token="abc123def456gh"`
	out2 := ScanAndRedact(in2)
	if strings.Count(out2, `"`) != 2 {
		t.Errorf("double-quoted case broken: %q", out2)
	}

	// Custom-regex path (processSingleToken's CombinedCustomRegex branch).
	cfg := campaignConfig()
	if err := cfg.ApplyCustomRegexes([]CustomRegexConfig{{Pattern: `CUST-\d{4}`, Name: "custom-id"}}); err != nil {
		t.Fatalf("ApplyCustomRegexes: %v", err)
	}
	UpdateConfig(cfg)
	in3 := `ref='CUST-1234'`
	out3 := ScanAndRedact(in3)
	if strings.Contains(out3, "CUST-1234") {
		t.Fatalf("secret leaked: %q", out3)
	}
	if strings.Count(out3, `'`) != 2 || strings.Contains(out3, `"`) {
		t.Errorf("custom-regex path rewrote quote character: %q", out3)
	}
}

// TestQuoteCharRemainingBranches closes the coverage gaps left by the B8 fix
// in all three processSingleToken redaction paths (CombinedCustomRegex, the
// CustomRegexes fallback loop, and the entropy/forced path): the
// double-quote-original branch and the autoQuote (digit/bool/null, no
// original quote) branch, each only exercised for one quote character by
// TestSingleQuoteRewritePreservesQuoteChar and TestCustomRegexFallbackPath.
func TestQuoteCharRemainingBranches(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	digitRule := CustomRegexRule{Regexp: regexp.MustCompile(`^\d{6,}$`), Name: "digits"}
	var sb strings.Builder

	// CombinedCustomRegex path (block 1): double-quote original, and autoQuote
	// on a bare digit token with no original quote.
	applyCfg(func(c *Config) {
		c.CustomRegexes = []CustomRegexRule{digitRule}
		c.CombinedCustomRegex = regexp.MustCompile(`(\d{6,})`)
		c.CustomRegexNames = []string{"digits"}
	})
	sb.Reset()
	cfgState().processSingleToken("123456", `"123456"`, false, false, false, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("CombinedCustomRegex: double-quote not preserved: %q", got)
	}
	sb.Reset()
	cfgState().processSingleToken("123456", "123456", false, false, true, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("CombinedCustomRegex: autoQuote digit not quoted: %q", got)
	}

	// Fallback CustomRegexes path (block 2): force CombinedCustomRegex nil.
	applyCfg(func(c *Config) {
		c.CustomRegexes = []CustomRegexRule{digitRule}
		c.CombinedCustomRegex = nil
	})
	sb.Reset()
	cfgState().processSingleToken("123456", `"123456"`, false, false, false, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("fallback: double-quote not preserved: %q", got)
	}
	sb.Reset()
	cfgState().processSingleToken("123456", `'123456'`, false, false, false, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `'[HIDDEN`) || !strings.HasSuffix(got, `]'`) {
		t.Errorf("fallback: single-quote not preserved: %q", got)
	}
	sb.Reset()
	cfgState().processSingleToken("123456", "123456", false, false, true, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("fallback: autoQuote digit not quoted: %q", got)
	}

	// Entropy/forced path (block 3): no custom regexes configured.
	UpdateConfig(campaignConfig())
	sb.Reset()
	cfgState().processSingleToken("999999", "999999", true, false, true, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("entropy: autoQuote digit not quoted: %q", got)
	}
}

// TestUpdateConfigConcurrent covers B4: UpdateConfig must be safe to call while
// other goroutines are scanning. It is meaningful under -race, which the CI and
// the campaign [T] gate always enable; before the atomic.Pointer snapshot the
// race detector reported writes in UpdateConfig racing reads in scanLine /
// isSensitiveKey.
func TestUpdateConfigConcurrent(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ScanAndRedact("password=hunter2 and value AbC9xY2kQ8pLmN0r")
			}
		}()
	}
	for i := 0; i < 50; i++ {
		UpdateConfig(campaignConfig())
	}
	wg.Wait()
}
