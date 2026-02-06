package scanner

import (
	"testing"
)

func TestAdaptiveThreshold_Integration(t *testing.T) {
	// 1. Reset State
	globalBaseline.Reset()
	if globalBaseline.IsReady() {
		t.Error("Baseline should not be ready after reset")
	}

	// 2. Train with safe samples (low entropy)
	// We use direct Update calls to avoid ScanAndRedact overhead/complexity
	safeEntropy := 3.5
	// Feed 110 samples (default maxSamples is 100)
	for i := 0; i < 110; i++ {
		globalBaseline.Update(safeEntropy)
	}

	// 3. Verify Ready State
	if !globalBaseline.IsReady() {
		t.Error("Baseline should be ready after >100 samples")
	}

	// 4. Verify Threshold Calculation
	// With constant entropy 3.5, mean=3.5, stddev=0.
	// Threshold = mean + 2*stddev = 3.5.
	threshold, ready := globalBaseline.GetThreshold()
	if !ready {
		t.Error("GetThreshold should return ready=true")
	}

	// Floating point comparison
	if threshold < 3.49 || threshold > 3.51 {
		t.Errorf("Expected threshold ~3.5, got %f", threshold)
	}

	// 5. Verify partial update
	globalBaseline.Reset()
	globalBaseline.Update(5.0)
	_, ready = globalBaseline.GetThreshold()
	if ready {
		t.Error("Baseline should not be ready with 1 sample")
	}
}
