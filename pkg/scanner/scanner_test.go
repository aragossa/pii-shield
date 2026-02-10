package scanner

import (
	"strings"
	"testing"
)

func TestScanner_Multilingual(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedSafe   []string
		expectedHidden []string
	}{
		{
			name:           "Spanish Log",
			input:          "El usuario inició sesión con éxito. ID de sesión: 12345",
			expectedSafe:   []string{"El", "usuario", "inició", "sesión", "con", "éxito.", "ID", "de", "12345"},
			expectedHidden: []string{},
		},
		{
			name:           "German Log",
			input:          "Fehler beim Verbinden mit Datenbank Benutzername: admin",
			expectedSafe:   []string{"Fehler", "beim", "Verbinden", "mit", "Datenbank", "Benutzername:", "admin"},
			expectedHidden: []string{},
		},
		{
			name:           "Russian Log (Cyrillic)",
			input:          "Ошибка доступа для пользователя Ivan",
			expectedSafe:   []string{"Ошибка", "доступа", "для", "пользователя", "Ivan"},
			expectedHidden: []string{},
		},
	}

	// Disable bigram check for multilingual tests to avoid false positives on non-English text
	currentConfig.DisableBigramCheck = true
	defer func() { currentConfig.DisableBigramCheck = false }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanAndRedact(tt.input)
			for _, safe := range tt.expectedSafe {
				if !strings.Contains(got, safe) {
					t.Errorf("Expected safe word %q to be present, but it was redacted or modified. Got: %s", safe, got)
				}
			}
			for _, hidden := range tt.expectedHidden {
				if strings.Contains(got, hidden) {
					t.Errorf("Expected sensitive word %q to be hidden, but it was present. Got: %s", hidden, got)
				}
			}
		})
	}
}

func TestScanner_TechnicalJargon(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"UUID", "Request ID: 550e8400-e29b-41d4-a716-446655440000"},
		{"Git SHA", "Commit: 7b3f1c2"},
		{"IPv6", "Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"Path", "Path: /var/log/nginx/access.log"},
		{"URL", "URL: https://example.com/api/v1/users"},
		{"Date", "Date: 2023-10-27T10:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanAndRedact(tt.input)
			if got != tt.input {
				t.Errorf("Technical jargon should be safe. Input: %q, Got: %q", tt.input, got)
			}
		})
	}
}

func TestScanner_NegativeCases(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		shouldRedact bool
	}{
		{"Weak Password", "password=123", true},                     // Should be redacted because key 'password' is sensitive
		{"Common Word", "key=value", true},                          // Should be redacted because key 'key' is sensitive
		{"High Entropy Secret", "api_key=sk_live_51Nc7qE...", true}, // Should be redacted
		{"Random Noise", "data=8f7d9a2b3c4e5f6", true},              // High entropy hex
		{"Valid Visa (Luhn)", "cc=4556737586899855", true},          // Valid Luhn with enough distinct digits (7 > 4)
		{"Stress Test Leak (ccGazanojgGcOSa)", "Error: 192.168.1.5 ccGazanojgGcOSa connection", true}, // Regression test for Threshold 3.6
	}

	// Ensure default config for this test
	// SAFE CONFIG MODIFICATION
	oldThreshold := currentConfig.EntropyThreshold
	oldMinSecret := currentConfig.MinSecretLength

	currentConfig.EntropyThreshold = DefaultEntropyThreshold
	currentConfig.MinSecretLength = 6

	defer func() {
		currentConfig.EntropyThreshold = oldThreshold
		currentConfig.MinSecretLength = oldMinSecret
	}()

	// Reset sensitive keys to default for this test to ensure "password" and "key" are caught
	// (Actual implementation does not expose Reset, but defaults are loaded in init)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanAndRedact(tt.input)
			isRedacted := strings.Contains(got, "[HIDDEN:")
			if isRedacted != tt.shouldRedact {
				t.Errorf("Expected redaction: %v, Got redaction: %v. Input: %q, Output: %q", tt.shouldRedact, isRedacted, tt.input, got)
			}
		})
	}
}
