package scanner

import (
	"encoding/hex"
	"hash"
	"testing"
)

func TestUpdateConfig(t *testing.T) {
	// Save current config (shallow copy is sufficient as we replace the whole struct)
	originalConfig := activeCfg()
	defer UpdateConfig(originalConfig)

	// Define two different configurations
	config1 := Config{
		EntropyThreshold: 4.0,
		MinSecretLength:  8,
		Salt:             []byte("salt_one_12345678"),
	}

	config2 := Config{
		EntropyThreshold: 2.5,
		MinSecretLength:  4,
		Salt:             []byte("salt_two_87654321"),
	}

	// Helper to calculate HMAC for a given string using the current pool
	calcHMAC := func(input string) string {
		h := cfgState().hmacPool.Get().(hash.Hash)
		defer cfgState().hmacPool.Put(h)
		h.Reset()
		h.Write([]byte(input))
		return hex.EncodeToString(h.Sum(nil))
	}

	// 1. Apply Config 1
	UpdateConfig(config1)

	// Verify global state
	if activeCfg().EntropyThreshold != 4.0 {
		t.Errorf("Expected EntropyThreshold 4.0, got %f", activeCfg().EntropyThreshold)
	}
	if activeCfg().MinSecretLength != 8 {
		t.Errorf("Expected MinSecretLength 8, got %d", activeCfg().MinSecretLength)
	}
	if string(activeCfg().Salt) != "salt_one_12345678" {
		t.Errorf("Expected Salt 'salt_one_12345678', got %s", activeCfg().Salt)
	}

	// Calculate HMAC with Config 1
	input := "test_secret_data"
	hash1 := calcHMAC(input)

	// 2. Apply Config 2
	UpdateConfig(config2)

	// Verify global state updated
	if activeCfg().EntropyThreshold != 2.5 {
		t.Errorf("Expected EntropyThreshold 2.5, got %f", activeCfg().EntropyThreshold)
	}
	if activeCfg().MinSecretLength != 4 {
		t.Errorf("Expected MinSecretLength 4, got %d", activeCfg().MinSecretLength)
	}
	if string(activeCfg().Salt) != "salt_two_87654321" {
		t.Errorf("Expected Salt 'salt_two_87654321', got %s", activeCfg().Salt)
	}

	// Calculate HMAC with Config 2
	hash2 := calcHMAC(input)

	// 3. Verify HMACs are different (proving the pool uses the new salt)
	if hash1 == hash2 {
		t.Errorf("HMACs should differ when salt changes. Got same hash: %s", hash1)
	}
}
