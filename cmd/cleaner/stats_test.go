package main

import (
	"strings"
	"testing"
	"time"
)

func TestStatsCollectorSummary(t *testing.T) {
	s := newStatsCollector()
	// 900 entropy, 297 regex, 43 luhn, 1 unknown -> other.
	for i := 0; i < 900; i++ {
		s.recordRedaction("entropy")
	}
	for i := 0; i < 297; i++ {
		s.recordRedaction("regex")
	}
	for i := 0; i < 43; i++ {
		s.recordRedaction("luhn")
	}
	s.recordRedaction("future-detector")
	for i := 0; i < 1500; i++ {
		s.recordLine(1000)
	}

	got := s.summary()
	for _, want := range []string{
		"1,241 redactions", // 900+297+43+1
		"900 high-entropy secrets",
		"297 pattern matches",
		"43 card numbers",
		"1 other",
		"1,500 lines",
		"1.4 MB processed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q\n got: %s", want, got)
		}
	}
}

func TestStatsCollectorOmitsOtherWhenZero(t *testing.T) {
	s := newStatsCollector()
	s.recordRedaction("entropy")
	if strings.Contains(s.summary(), "other") {
		t.Errorf("summary should omit 'other' when zero: %s", s.summary())
	}
}

func TestParseStatsInterval(t *testing.T) {
	cases := map[string]time.Duration{
		"":      0,
		"   ":   0,
		"0":     0,
		"-5m":   0,
		"bogus": 0,
		"30s":   30 * time.Second,
		" 1h ":  time.Hour,
		"1h30m": 90 * time.Minute,
	}
	for in, want := range cases {
		if got := parseStatsInterval(in); got != want {
			t.Errorf("parseStatsInterval(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestWithThousands(t *testing.T) {
	cases := map[uint64]string{0: "0", 12: "12", 999: "999", 1000: "1,000", 12345: "12,345", 1000000: "1,000,000"}
	for in, want := range cases {
		if got := withThousands(in); got != want {
			t.Errorf("withThousands(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{512: "512 B", 1024: "1.0 KB", 1536: "1.5 KB", 5 * 1024 * 1024: "5.0 MB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
