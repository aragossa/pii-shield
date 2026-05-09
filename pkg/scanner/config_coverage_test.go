package scanner

import (
	"os"
	"reflect"
	"testing"
)

func TestParseHelpers(t *testing.T) {
	valF, errF := parseFloat("12.34")
	if errF != nil || valF != 12.34 {
		t.Errorf("parseFloat failed: %v", errF)
	}

	valI, errI := parseInt("1234")
	if errI != nil || valI != 1234 {
		t.Errorf("parseInt failed: %v", errI)
	}
}

func TestLoadConfigEdgeCases(t *testing.T) {
	// Save environment to restore later
	oldConfig := currentConfig
	defer UpdateConfig(oldConfig)

	oldSalt := os.Getenv("PII_SALT")
	oldThreshold := os.Getenv("PII_ENTROPY_THRESHOLD")
	oldAdaptive := os.Getenv("PII_ADAPTIVE_THRESHOLD")
	oldSamples := os.Getenv("PII_ADAPTIVE_SAMPLES")
	oldKeys := os.Getenv("PII_SENSITIVE_KEYS")
	defer func() {
		os.Setenv("PII_SALT", oldSalt)
		os.Setenv("PII_ENTROPY_THRESHOLD", oldThreshold)
		os.Setenv("PII_ADAPTIVE_THRESHOLD", oldAdaptive)
		os.Setenv("PII_ADAPTIVE_SAMPLES", oldSamples)
		os.Setenv("PII_SENSITIVE_KEYS", oldKeys)
	}()

	// Apply test environment variables
	os.Setenv("PII_SALT", "short123") // Less than 16 bytes
	os.Setenv("PII_ENTROPY_THRESHOLD", "invalid_float")
	os.Setenv("PII_ADAPTIVE_THRESHOLD", "true")
	os.Setenv("PII_ADAPTIVE_SAMPLES", "50")
	os.Setenv("PII_SENSITIVE_KEYS", "custom1,custom2 ")

	cfg := loadConfig()

	if string(cfg.Salt) != "short123" {
		t.Errorf("expected salt 'short123', got %s", cfg.Salt)
	}
	if cfg.AdaptiveBaselineSamples != 50 {
		t.Errorf("expected 50 adaptive samples, got %d", cfg.AdaptiveBaselineSamples)
	}
	expectedKeys := []string{"custom1", "custom2"}
	if !reflect.DeepEqual(cfg.SensitiveKeys, expectedKeys) {
		t.Errorf("expected sensitive keys %v, got: %v", expectedKeys, cfg.SensitiveKeys)
	}

	// Ensure UpdateConfig functions well
	UpdateConfig(cfg)
}
