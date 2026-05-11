//go:build wasm

package main

import (
	"encoding/json"
	"unsafe"

	"github.com/pii-shield/pii-shield/pkg/scanner"
)

// ConfigFromSDK represents configuration passed from Python/Node.js SDKs
type ConfigFromSDK struct {
	EntropyThreshold    float64 `json:"entropy_threshold"`
	Salt                string  `json:"salt"`
	ConfidenceThreshold float64 `json:"confidence_score"`
	FailPolicy          string  `json:"fail_policy"`
}

// We use a map to pin memory allocations. This prevents Go's Garbage Collector
// from reclaiming the memory before the WASM Host (Python/Node.js) reads it.
var allocations = make(map[uint32][]byte)

// allocate reserves memory for the host to write strings into.
//go:wasmexport allocate
func allocate(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	buf := make([]byte, size)
	ptr := uint32(uintptr(unsafe.Pointer(&buf[0])))
	allocations[ptr] = buf
	return ptr
}

// free releases memory allocated by allocate or redact.
//go:wasmexport free
func free(ptr uint32, size uint32) {
	delete(allocations, ptr)
}

// init_config receives JSON representing the config payload.
//go:wasmexport init_config
func init_config(ptr uint32, length uint32) {
	if ptr == 0 || length == 0 {
		return
	}

	// Reconstruct the byte slice from host memory
	b := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)

	// Default config
	cfg := scanner.Config{
		EntropyThreshold:    4.2,
		ConfidenceThreshold: 1.0,
		Salt:                []byte("pii-shield-default-salt-12345678"),
	}

	var sdkCfg ConfigFromSDK
	if err := json.Unmarshal(b, &sdkCfg); err == nil {
		if sdkCfg.EntropyThreshold > 0 {
			cfg.EntropyThreshold = sdkCfg.EntropyThreshold
		}
		if sdkCfg.Salt != "" {
			cfg.Salt = []byte(sdkCfg.Salt)
		}
		if sdkCfg.ConfidenceThreshold > 0 {
			cfg.ConfidenceThreshold = sdkCfg.ConfidenceThreshold
		}
		// The package doesn't have an SDK property for fail policy yet, but we have it passed.
		// Wait, package level fails are in cmd/cleaner not in scanner.Config. 
		// If SDK wants to handle Fail-Closed vs Open, we can provide it downstream at SDK wrappers.
	}

	scanner.UpdateConfig(cfg)
}

// redact reads a string from memory, redacts it, and returns a packed uint64 (ptr << 32 | length).
//go:wasmexport redact
func redact(ptr uint32, length uint32) uint64 {
	if ptr == 0 || length == 0 {
		return 0
	}

	// Read the string from host memory
	b := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
	input := unsafe.String(&b[0], length)

	// Process
	redacted := scanner.ScanAndRedact(input)
	
	outBytes := []byte(redacted)
	var ptr32 uint32
	var len32 uint32 = uint32(len(outBytes))

	if len32 > 0 {
		ptr32 = uint32(uintptr(unsafe.Pointer(&outBytes[0])))
		// Pin it!
		allocations[ptr32] = outBytes
	}

	// Pack 64-bit integer: High 32 bits = Pointer, Low 32 bits = Length
	return (uint64(ptr32) << 32) | uint64(len32)
}

// main must exist for the WebAssembly compiler to run, but is unused for library builds.
func main() {}
