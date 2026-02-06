package scanner

import (
	"testing"
	"unicode/utf8"
)

func FuzzScanner(f *testing.F) {
	// Seed corpus with some interesting values
	f.Add("normal log line")
	f.Add("key=value")
	f.Add("password=secret")
	f.Add("https://example.com?token=123")
	f.Add("{\"user\": \"admin\", \"pass\": \"12345\"}")
	f.Add("Fehler beim Verbinden mit Datenbank") // German
	f.Add("Ошибка доступа")                      // Russian
	f.Add("::1")                                 // IPv6
	f.Add(string([]byte{0xff, 0xfe, 0xfd}))      // Invalid UTF-8

	f.Fuzz(func(t *testing.T, input string) {
		// 1. Crash Check: Should not panic
		output := ScanAndRedact(input)

		// 2. Property Check: Output should be valid UTF-8
		if !utf8.ValidString(output) {
			t.Errorf("Scanner produced invalid UTF-8 for input %q", input)
		}

		// 3. Differential Check (Basic):
		// If input has no sensitive keys and low entropy, output should match input (mostly).
		// This is hard to assert generally without recreating the logic.

		// 4. Length Check: Output size shouldn't explode (e.g. infinite loop expansion)
		if len(output) > len(input)*3+100 {
			t.Errorf("Output size exploded. Input: %d, Output: %d", len(input), len(output))
		}
	})
}
