package scanner

import (
	"strings"
	"testing"
)

func TestSafetyHeuristics(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		checkFunc func(string) bool
		expected  bool
	}{
		{"isImage_docker", "docker.io/library/nginx", isImage, true},
		{"isImage_gcr", "gcr.io/google-containers/pause:3.2", isImage, true},
		{"isImage_quay", "quay.io/coreos/etcd", isImage, true},
		{"isImage_false", "just_a_normal_string", isImage, false},

		{"isGeneratedUsername_valid", "user_1a2b3c", isGeneratedUsername, true},
		{"isGeneratedUsername_invalidChars", "user_1a2b*3c", isGeneratedUsername, false},
		{"isGeneratedUsername_tooLong", "user_12345678901234", isGeneratedUsername, false},
		{"isGeneratedUsername_false", "admin", isGeneratedUsername, false},

		{"isIPv6_valid", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", isIPv6, true},
		{"isIPv6_invalidChars", "2001:0db8::xz", isIPv6, false},
		{"isIPv6_false", "192.168.1.1", isIPv6, false},

		{"isPath_unix", "/var/log/syslog", isPath, true},
		{"isPath_windows", "C:\\Windows\\System32", isPath, true},
		{"isPath_windows_namespace", "System\\Windows\\CurrentVersion", isPath, true},
		{"isPath_windows_unc", "\\\\Server\\Share", isPath, true},
		{"isPath_false", "foo_bar", isPath, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.checkFunc(tt.input)
			if got != tt.expected {
				t.Errorf("%s(%q) = %v; expected %v", tt.name, tt.input, got, tt.expected)
			}
		})
	}
}

func TestProcessEqualPairEdgeCases(t *testing.T) {
	// Helper string builder for tests
	var sb strings.Builder

	// Test normal assignment
	isKey, _ := processEqualPair("config=safevalue", false, false, &sb)
	if isKey {
		t.Errorf("Expected config=safevalue not to be treated as a sensitive key")
	}

	sb.Reset()

	// Test quoted assignment
	sb.Reset()
	_, _ = processEqualPair(`"password=mysecret"`, false, false, &sb)
	if !strings.Contains(sb.String(), "[HIDDEN") {
		t.Errorf("Expected quoted password assignment to be identified as sensitive and redacted, got: %s", sb.String())
	}

	sb.Reset()

	// Test nested assignment (data=key=val)
	_, handled := processEqualPair("data=config=safevalue", false, false, &sb)
	if !handled {
		t.Errorf("Expected nested assignment to be handled")
	}
}
