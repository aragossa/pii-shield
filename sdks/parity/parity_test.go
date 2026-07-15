// Package parity holds the cross-entrypoint redaction parity golden
// (cases.json) and the Go/CLI-side assertion. The Node and Python SDK tests
// load the SAME cases.json and assert byte-identical output, so every
// entrypoint (Go API, CLI, Node, Python) is proven to redact identically for a
// given input and config. See sdks/*/test.* and issue #48.
package parity

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pii-shield/pii-shield/pkg/scanner"
)

type parityCase struct {
	Name     string                 `json:"name"`
	Config   map[string]interface{} `json:"config"`
	Input    string                 `json:"input"`
	Expected string                 `json:"expected"`
}

// applyConfig mirrors the config mapping in cmd/wasm-ffi/main.go init_config,
// including the fixed default salt the WASM kernel seeds. Keep the two in sync;
// any drift makes the Node/Python SDK tests fail against this golden.
func applyConfig(c map[string]interface{}) scanner.Config {
	cfg := scanner.DefaultConfig()
	cfg.Salt = []byte("pii-shield-default-salt-12345678")
	if v, ok := c["salt"].(string); ok && v != "" {
		cfg.Salt = []byte(v)
	}
	if v, ok := c["entropy_threshold"].(float64); ok && v > 0 {
		cfg.EntropyThreshold = v
	}
	if v, ok := c["confidence_score"].(float64); ok && v > 0 {
		cfg.ConfidenceThreshold = v
	}
	if v, ok := c["min_secret_length"].(float64); ok && v > 0 {
		cfg.MinSecretLength = int(v)
	}
	if v, ok := c["sensitive_keys"].([]interface{}); ok && len(v) > 0 {
		keys := make([]string, len(v))
		for i, k := range v {
			keys[i] = strings.ToLower(strings.TrimSpace(k.(string)))
		}
		cfg.SensitiveKeys = keys
	}
	if v, ok := c["disable_bigram_check"].(bool); ok {
		cfg.DisableBigramCheck = v
	}
	if v, ok := c["adaptive_threshold"].(bool); ok {
		cfg.AdaptiveThreshold = v
	}
	return cfg
}

func loadCases(t *testing.T) []parityCase {
	t.Helper()
	raw, err := os.ReadFile("cases.json")
	if err != nil {
		t.Fatalf("read cases.json: %v", err)
	}
	var cases []parityCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("cases.json is empty")
	}
	return cases
}

// TestGoParity asserts the Go API (scanner.ScanAndRedact) reproduces the golden
// for every case. The Node and Python SDKs assert the same golden via WASM.
func TestGoParity(t *testing.T) {
	for _, tc := range loadCases(t) {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			scanner.UpdateConfig(applyConfig(tc.Config))
			got := scanner.ScanAndRedact(tc.Input)
			if got != tc.Expected {
				t.Fatalf("parity mismatch\n input:    %q\n config:   %v\n expected: %q\n got:      %q",
					tc.Input, tc.Config, tc.Expected, got)
			}
		})
	}
}
