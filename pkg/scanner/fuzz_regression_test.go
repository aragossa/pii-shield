package scanner

import (
	"testing"
	"unicode/utf8"
)

func TestReproFuzzFailure(t *testing.T) {
	// Input: "\"\\\x80"
	// quote, backslash, invalid byte (0x80)
	input := "\"\\\x80"
	
	output := ScanAndRedact(input)
	
	if !utf8.ValidString(output) {
		t.Errorf("Scanner produced invalid UTF-8 for input %q. Output byte len: %d", input, len(output))
	}
}
