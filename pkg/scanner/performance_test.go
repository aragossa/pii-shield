package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Helper to reset config for benchmarks (simple simulation)
func resetConfig() {
	// Re-load defaults
	currentConfig = Config{
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
		},
	}
	sensitiveRegex = nil

	// Reset HMAC Pool with new salt
	hmacPool = &sync.Pool{
		New: func() interface{} {
			return hmac.New(sha256.New, currentConfig.Salt)
		},
	}
}

// -----------------------------------------------------------------------------
// Whitelist Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkWhitelist_Static(b *testing.B) {
	resetConfig()
	// Test standard static whitelist check (e.g. UUID)
	token := "123e4567-e89b-12d3-a456-426614174000" // Valid UUID

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
	currentConfig.SafeRegexes = []CustomRegexRule{
		{Regexp: re, Name: "SafeID"},
	}

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
	pattern := `(?i)(custom_secret|super_confidential)`
	re := regexp.MustCompile(pattern)
	sensitiveRegex = re // Direct assignment for test
	
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
	currentConfig.CustomRegexes = []CustomRegexRule{
		{Regexp: re, Name: "SSN"},
	}

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
	currentConfig.CustomRegexes = rules

	// Simulate Combined Regex Compilation (O(1) Optimization)
	var patterns []string
	var names []string
	for _, r := range rules {
		patterns = append(patterns, "("+r.Regexp.String()+")")
		names = append(names, r.Name)
	}
	combined, _ := regexp.Compile(strings.Join(patterns, "|"))
	currentConfig.CombinedCustomRegex = combined
	currentConfig.CustomRegexNames = names

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
