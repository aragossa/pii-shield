package scanner

import (
    "math"
    "sync"
)

// BaselineStats tracks statistical information for adaptive threshold calculation.
// It collects a sample of entropy values and uses them to calculate a dynamic
// threshold based on mean + 2σ (standard deviations).
type BaselineStats struct {
    mu         sync.RWMutex
    samples    []float64
    maxSamples int
    ready      bool
}

var globalBaseline *BaselineStats

func init() {
    globalBaseline = newBaselineStats(100) // Default: 100 samples
}

// newBaselineStats creates a new baseline statistics tracker
func newBaselineStats(maxSamples int) *BaselineStats {
    return &BaselineStats{
        samples:    make([]float64, 0, maxSamples),
        maxSamples: maxSamples,
    }
}

// Update adds a new entropy value to the baseline statistics.
// Once maxSamples is reached, the baseline is marked as ready.
func (bs *BaselineStats) Update(entropy float64) {
    bs.mu.Lock()
    defer bs.mu.Unlock()
    
    if len(bs.samples) < bs.maxSamples {
        bs.samples = append(bs.samples, entropy)
        if len(bs.samples) == bs.maxSamples {
            bs.ready = true
        }
    }
}

// GetThreshold calculates and returns the adaptive threshold.
// Returns (threshold, isReady) where:
// - threshold: mean + 2*stddev if ready, otherwise currentConfig.EntropyThreshold
// - isReady: true if enough samples have been collected
func (bs *BaselineStats) GetThreshold() (float64, bool) {
    bs.mu.RLock()
    defer bs.mu.RUnlock()
    
    if !bs.ready {
        return currentConfig.EntropyThreshold, false
    }
    
    // Calculate mean
    sum := 0.0
    for _, v := range bs.samples {
        sum += v
    }
    mean := sum / float64(len(bs.samples))
    
    // Calculate stddev
    variance := 0.0
    for _, v := range bs.samples {
        variance += math.Pow(v-mean, 2)
    }
    stddev := math.Sqrt(variance / float64(len(bs.samples)))
    
    // Return mean + 2σ as the threshold
    // This captures ~95% of the baseline distribution
    return mean + 2*stddev, true
}

// Reset clears all collected samples and resets the ready state.
// Useful when switching to a new log stream with different characteristics.
func (bs *BaselineStats) Reset() {
    bs.mu.Lock()
    defer bs.mu.Unlock()
    
    bs.samples = bs.samples[:0]
    bs.ready = false
}

// IsReady returns whether enough samples have been collected
func (bs *BaselineStats) IsReady() bool {
    bs.mu.RLock()
    defer bs.mu.RUnlock()
    return bs.ready
}
