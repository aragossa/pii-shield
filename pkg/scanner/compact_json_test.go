package scanner

import (
	"strings"
	"testing"
)

// TestCompactJSONSafeValues guards a tokenizer bug where compact JSON ("k":"v")
// fed quoted values into the safety whitelist, so safe values like ISO-8601
// timestamps were redacted while the spaced form ("k": "v") kept them.
func TestCompactJSONSafeValues(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		mustKeep   []string // substrings that must survive untouched
		mustRedact []string // keys whose value must become [HIDDEN:...]
	}{
		{
			name:     "compact ISO timestamp is preserved",
			input:    `{"timestamp":"2026-06-19T10:30:00Z"}`,
			mustKeep: []string{"2026-06-19T10:30:00Z"},
		},
		{
			name:     "spaced ISO timestamp is preserved",
			input:    `{"timestamp": "2026-06-19T10:30:00Z"}`,
			mustKeep: []string{"2026-06-19T10:30:00Z"},
		},
		{
			name:     "compact IPv6 is preserved",
			input:    `{"ip":"::1"}`,
			mustKeep: []string{"::1"},
		},
		{
			name:       "email redacted, timestamp kept (article example payload)",
			input:      `{"action":"retrieve_customer","customer_email":"alice@company.com","timestamp":"2026-06-19T10:30:00Z"}`,
			mustKeep:   []string{"retrieve_customer", "2026-06-19T10:30:00Z"},
			mustRedact: []string{"customer_email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := ScanAndRedact(tt.input)
			for _, keep := range tt.mustKeep {
				if !strings.Contains(out, keep) {
					t.Errorf("expected %q to be preserved, got: %s", keep, out)
				}
			}
			for _, key := range tt.mustRedact {
				marker := `"` + key + `":"[HIDDEN`
				if !strings.Contains(out, marker) {
					t.Errorf("expected %q value to be redacted, got: %s", key, out)
				}
			}
		})
	}
}
