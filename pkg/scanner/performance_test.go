package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// Helper to reset config for benchmarks (simple simulation). UpdateConfig
// rebuilds the derived state (sensitiveRegex, hmacPool) from these fields.
func resetConfig() {
	UpdateConfig(Config{
		EntropyThreshold:        DefaultEntropyThreshold,
		MinSecretLength:         6,
		DisableBigramCheck:      false,
		BigramDefaultScore:      -7.0,
		AdaptiveThreshold:       false,
		AdaptiveBaselineSamples: 100,
		Salt:                    []byte("1234567890abcdef1234567890abcdef"), // Dummy salt
		SensitiveKeys: []string{
			"pass", "secret", "token", "key", "cvv", "cvc", "auth", "sign",
			"password", "passwd", "api_key", "apikey", "access_token", "client_secret",
			"aws_access_key_id", "aws_secret_access_key", "gcp_credentials", "slack_token",
		},
	})
}

// -----------------------------------------------------------------------------
// Whitelist Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkWhitelist_Static(b *testing.B) {
	resetConfig()
	// Test standard static whitelist check
	token := "2001:db8:85a3::8a2e:370:7334" // Valid IPv6

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// We use isSafe directly to isolate whitelist logic
		if !isSafe(token) {
			b.Fatal("Expected token to be safe")
		}
	}
}

func BenchmarkWhitelist_Regex(b *testing.B) {
	resetConfig()
	// Configure a Safe Regex
	safePattern := `^SAFE-ID-\d+$`
	re := regexp.MustCompile(safePattern)
	applyCfg(func(c *Config) {
		c.SafeRegexes = []CustomRegexRule{{Regexp: re, Name: "SafeID"}}
	})

	token := "SAFE-ID-987654321"

	var sb strings.Builder
	sb.Grow(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		processSingleToken(token, token, false, false, false, &sb)
		res := sb.String()
		if res != token {
			b.Fatalf("Expected token to be preserved, got %s", res)
		}
	}
}

// -----------------------------------------------------------------------------
// Blacklist Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkBlacklist_Static(b *testing.B) {
	resetConfig()
	// "password" is in default SensitiveKeys
	key := "password"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !isSensitiveKey(key) {
			b.Fatal("Expected key to be sensitive")
		}
	}
}

func BenchmarkBlacklist_Regex(b *testing.B) {
	resetConfig()
	// Configure Sensitive Key Patterns
	// We simulate what loadConfig does: combine into one regex
	// Drive the sensitive-key regex through the real config path so it is
	// published atomically like production (UpdateConfig compiles the patterns
	// into the combined case-insensitive sensitiveRegex).
	applyCfg(func(c *Config) {
		c.SensitiveKeyPatterns = []string{"custom_secret", "super_confidential"}
	})

	// A key NOT in static list, but matches regex
	key := "custom_secret"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !isSensitiveKey(key) {
			b.Fatalf("Expected key '%s' to be sensitive via regex", key)
		}
	}
}

// -----------------------------------------------------------------------------
// Regex Redaction Benchmarks (Custom Regex List)
// -----------------------------------------------------------------------------

func BenchmarkCustomRegex(b *testing.B) {
	resetConfig()
	// Configure Custom Regex for redaction (e.g. finding SSNs in values)
	pattern := `\b\d{3}-\d{2}-\d{4}\b` // SSN-like
	re := regexp.MustCompile(pattern)
	applyCfg(func(c *Config) {
		c.CustomRegexes = []CustomRegexRule{{Regexp: re, Name: "SSN"}}
	})

	token := "123-45-6789"
	var sb strings.Builder
	sb.Grow(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		processSingleToken(token, token, false, false, false, &sb)
		res := sb.String()
		if res == token {
			b.Fatalf("Expected redaction for token %s", token)
		}
	}
}

func BenchmarkCustomRegex_5Rules(b *testing.B) {
	resetConfig()
	// Configure 5 Custom Regexes
	rules := []CustomRegexRule{
		{Regexp: regexp.MustCompile(`\buser-\d+\b`), Name: "UserId"},
		{Regexp: regexp.MustCompile(`\bemail-[a-z]+\b`), Name: "EmailId"},
		{Regexp: regexp.MustCompile(`\bkb-\d{5}\b`), Name: "KB"},
		{Regexp: regexp.MustCompile(`\bticket-[a-z0-9]+\b`), Name: "Ticket"},
		{Regexp: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), Name: "SSN"}, // The one that matches
	}
	// Simulate Combined Regex Compilation (O(1) Optimization)
	var patterns []string
	var names []string
	for _, r := range rules {
		patterns = append(patterns, "("+r.Regexp.String()+")")
		names = append(names, r.Name)
	}
	combined, _ := regexp.Compile(strings.Join(patterns, "|"))
	applyCfg(func(c *Config) {
		c.CustomRegexes = rules
		c.CombinedCustomRegex = combined
		c.CustomRegexNames = names
	})

	token := "123-45-6789"
	var sb strings.Builder
	sb.Grow(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		processSingleToken(token, token, false, false, false, &sb)
		res := sb.String()
		if res == token {
			b.Fatalf("Expected redaction for token %s", token)
		}
	}
}
