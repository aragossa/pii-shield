package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync"
	"unicode"
)

const (
	// EntropyThreshold is the Shannon entropy threshold for suspicious strings.
	// 4.5 is empirically good for Base64/Random strings.
	EntropyThreshold = 4.5
	
	// MinSecretLength is the minimum length for a token to be considered a secret.
	MinSecretLength = 8
)

// Salt - this should ideally be rotated or set via ENV. 
var Salt = "my-ephemeral-random-salt-2026"

// Precomputed logs for optimization
var logTable [256]float64

// Buffer pool to reduce GC pressure
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 1024)
	},
}

func init() {
	// Precompute log(i) for i=1..255. log(0) is unused.
	for i := 1; i < 256; i++ {
		logTable[i] = math.Log2(float64(i))
	}
}

// CalculateEntropy computes the Shannon entropy of a string using an optimized approach.
func CalculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	// Use stack-allocated array for frequency counting (no map = no GC)
	var frequencies [256]int
	for i := 0; i < len(data); i++ {
		frequencies[data[i]]++
	}

	var entropy float64
	lenData := float64(len(data))
	logLen := math.Log2(lenData)

	for _, count := range frequencies {
		if count > 0 {
			// Use precomputed logTable for math.Log2(count) - math.Log2(lenData)
			
			var logCount float64
			if count < 256 {
				logCount = logTable[count]
			} else {
				logCount = math.Log2(float64(count))
			}
			
			// We calculate freq * log2(freq)
			// log2(count / len) = log2(count) - log2(len)
			// term = (count / len) * (logCount - logLen)
			entropy -= (float64(count) / lenData) * (logCount - logLen)
		}
	}

	return entropy
}

// IsPotentialSecret checks if a token looks like a secret based on heuristics and entropy.
func IsPotentialSecret(token string, threshold float64) bool {
	// Heuristic 1: Length
	if len(token) < MinSecretLength {
		return false
	}

	// Heuristic: Credit Card Strings (digits only, 13-19 chars, Luhn check)
	// We check this BEFORE entropy because numbers have low entropy.
	if isCreditCard(token) {
		return true
	}

	// Heuristic: Git Hashes / UUIDs (usually safe)
	// If it matches these specific patterns, we skip entropy check to avoid false positives.
	if isGitHash(token) || isUUID(token) {
		return false
	}

	// Heuristic: File Paths and URLs (Common False Positives)
	// If token starts with '/' (Linux path) or './' (relative path), we assume it's safe.
	// NOTE: This might skip "/etc/passwd", but usually logs contain safe API paths.
	if strings.HasPrefix(token, "/") || strings.HasPrefix(token, "./") {
		return false
	}

	// Heuristic: JSON booleans and null
	if token == "true" || token == "false" || token == "null" {
		return false
	}

	// Heuristic 2: Charset Filter
	hasLetter := false
	hasNumber := false
	hasSymbol := false

	for _, r := range token {
		if unicode.IsLetter(r) {
			hasLetter = true
		} else if unicode.IsNumber(r) {
			hasNumber = true
		} else if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			hasSymbol = true
		}
	}

	typesCount := 0
	if hasLetter { typesCount++ }
	if hasNumber { typesCount++ }
	if hasSymbol { typesCount++ }

	if typesCount < 2 {
		return false // Likely just a word or number
	}
	
	// 3. Calculate Entropy
	entropy := CalculateEntropy(token)
	
	// Use Dynamic Threshold
	return entropy > threshold
}

// isCreditCard checks for 13-19 digits and valid Luhn checksum
func isCreditCard(token string) bool {
	// Check length and digit-only
	n := len(token)
	if n < 13 || n > 19 {
		return false
	}
	for i := 0; i < n; i++ {
		if token[i] < '0' || token[i] > '9' {
			return false
		}
	}
	// Luhn Algorithm
	sum := 0
	alternate := false
	for i := n - 1; i >= 0; i-- {
		digit := int(token[i] - '0')
		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		alternate = !alternate
	}
	return sum%10 == 0
}

// isGitHash checks for 32, 40, or 64 hex characters
func isGitHash(token string) bool {
	n := len(token)
	// MD5(32), SHA1(40), SHA256(64)
	if n != 32 && n != 40 && n != 64 {
		return false
	}
	return isHex(token)
}

// isUUID checks for standard UUID format: 8-4-4-4-12 hex digits
func isUUID(token string) bool {
	if len(token) != 36 {
		return false
	}
	// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	// 01234567 8 9
	for i, r := range token {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else {
			if !isHexChar(r) {
				return false
			}
		}
	}
	return true
}

func isHex(s string) bool {
	for _, r := range s {
		if !isHexChar(r) {
			return false
		}
	}
	return true
}

func isHexChar(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// calculateLineStats calculates the average entropy of the line to set a dynamic threshold.
func calculateLineStats(line string) float64 {
	var totalEntropy float64
	var count int
	
	// Use a simple split function for statistics
	f := func(c rune) bool {
		return strings.ContainsRune(" \t\"',;[]{}()<>", c)
	}
	
	tokens := strings.FieldsFunc(line, f)
	for _, t := range tokens {
		if len(t) > 3 {
			totalEntropy += CalculateEntropy(t)
			count++
		}
	}
	
	avgEntropy := 3.0 // Default for short lines
	if count > 0 {
		avgEntropy = totalEntropy / float64(count)
	}
	
	// Dynamic threshold: Avg + 1.2
	threshold := avgEntropy + 1.2
	
	// Hard limit: never below 3.8
	if threshold < 3.8 {
		threshold = 3.8
	}
	
	return threshold
}

// ScanAndRedact scans a log line and redacts potential secrets.
func ScanAndRedact(logLine string) string {
	if len(logLine) == 0 {
		return ""
	}
	
	// 1. First Pass: Calculate Dynamic Threshold
	dynamicThreshold := calculateLineStats(logLine)

	var sb strings.Builder
	sb.Grow(len(logLine) + 100) // pre-allocate
	
	start := 0
	lastCopied := 0
	
	// separators: space, tab, quote, equals, comma, etc.
	// NOTE: We REMOVED '/' and ':' from the hard list here to handle them dynamically
	// We handle ':' and '=' in the loop to support "key=value" and "http://..."
	
	isHardSeparator := func(r rune) bool {
		return strings.ContainsRune(" \t\"',;[]{}()<>", r)
	}
	
	// Scan loop
	n := len(logLine)
	for i := 0; i < n; i++ {
		r := rune(logLine[i])
		
		// 1. Hard Separators (always split)
		if isHardSeparator(r) {
			if i > start {
				token := logLine[start:i]
				processToken(&sb, logLine, token, start, &lastCopied, dynamicThreshold)
			}
			start = i + 1
			continue
		}
		
		// 2. Colon ':' handling (Context sensitive)
		if r == ':' {
			// Check for URL scheme "://"
			if i+2 < n && logLine[i+1] == '/' && logLine[i+2] == '/' {
				// We are in a URL (e.g. "http://..." or "postgres://...")
				// Consume until we hit a Hard Separator (space, quote, etc.)
				// We do this by lookahead loop
				for i < n && !isHardSeparator(rune(logLine[i])) {
					i++
				}
				// The loop overshoots by 1 (or hits end), but the main loop does i++
				// So we decrement i to let the main loop increment it correctly to the separator
				i-- 
				continue
			}
			
			// Otherwise, ':' is likely a separator (e.g. "Key:Value")
			// We treat it as a split point
			if i > start {
				token := logLine[start:i]
				processToken(&sb, logLine, token, start, &lastCopied, dynamicThreshold)
			}
			start = i + 1
			continue
		}
		
		// 3. Equals '=' handling
		if r == '=' {
			// Usually a separator "key=value"
			// But can be part of Base64 padding at the end?
			// Base64 padding "=" is usually at the end of the string/token.
			// scanning "data=...". "data" is token.
			// "..." sequence. If it ends with "==", the loop finishes and processes it.
			// So IF we encounter "=" inside a token?
			// "key=val" -> split.
			// "base64==". 
			// Check if we are at the end of a likely Base64 block?
			// If next char is space/end, keep it?
			// Or just split?
			// If we split "base64==", we get "base64", "", "".
			// "base64" (high entropy) -> Redacted.
			// So "data=[REDACTED]==". This is acceptable.
			// But for cleanliness we might want to include it.
			// Let's stick to simple behavior: '=' is a separator.
			
			if i > start {
				token := logLine[start:i]
				processToken(&sb, logLine, token, start, &lastCopied, dynamicThreshold)
			}
			start = i + 1
			continue
		}
	}
	
	// Handle last token
	if start < n {
		token := logLine[start:]
		processToken(&sb, logLine, token, start, &lastCopied, dynamicThreshold)
	}
	
	// Append remaining tail
	if lastCopied < n {
		sb.WriteString(logLine[lastCopied:])
	}
	
	return sb.String()
}

// processToken checks if a token is a secret and redacts it if necessary.
func processToken(sb *strings.Builder, fullLine, token string, tokenStart int, lastCopied *int, threshold float64) {
	// 1. Check for Dangerous Context (Force Redact)
	// If the key is explicit (e.g. "password="), we redact regardless of entropy.
	if isDangerousContext(fullLine, tokenStart) {
		// Append valid text before this token
		sb.WriteString(fullLine[*lastCopied:tokenStart])
		
		// Generate deterministic hash placeholder
		hashedPlaceholder := redactWithHash(token)
		sb.WriteString(hashedPlaceholder)
		
		*lastCopied = tokenStart + len(token)
		return
	}

	// 2. Check Heuristics & Entropy
	if IsPotentialSecret(token, threshold) {
		if !isSafeContext(fullLine, tokenStart) {
			// Append valid text before this token
			sb.WriteString(fullLine[*lastCopied:tokenStart])
			
			// Generate deterministic hash placeholder
			hashedPlaceholder := redactWithHash(token)
			sb.WriteString(hashedPlaceholder)
			
			*lastCopied = tokenStart + len(token)
		}
	}
}

// redactWithHash turns "secret123" into "[HIDDEN:a1b2]" using SHA256 + Salt
func redactWithHash(sensitiveData string) string {
	// 1. Combine with salt
	input := sensitiveData + Salt
	
	// 2. SHA256
	hash := sha256.Sum256([]byte(input))
	
	// 3. Take first 3 bytes (6 hex chars)
	shortHash := hex.EncodeToString(hash[:3])
	
	// 4. Return formatted string
	return fmt.Sprintf("[HIDDEN:%s]", shortHash)
}

// isSafeContext checks the string preceding the token at `start` index
func isSafeContext(line string, start int) bool {
	// Look backwards from start-1
	// Skip separators
	i := start - 1
	for i >= 0 && strings.ContainsRune(" \t\"'=:,;", rune(line[i])) {
		i--
	}
	// slice potential key
	if i < 0 {
		return false // No context
	}
	
	endKey := i + 1
	// Find start of key
	for i >= 0 && !strings.ContainsRune(" \t\"'=:,;", rune(line[i])) {
		i--
	}
	startKey := i + 1
	
	key := line[startKey:endKey]
	keyLower := strings.ToLower(key)
	
	// Whitelist: common high entropy but safe fields
	switch keyLower {
	case "image", "img", "uuid", "request_id", "trace_id", "span_id", "id", "guid", "sha":
		return true
	}
	
	return false
}

// isDangerousContext checks if the preceding key is a known sensitive key (password, secret, etc.)
func isDangerousContext(line string, start int) bool {
	// Look backwards from start-1
	// Skip separators
	i := start - 1
	for i >= 0 && strings.ContainsRune(" \t\"'=:,;", rune(line[i])) {
		i--
	}
	// slice potential key
	if i < 0 {
		return false // No context
	}
	
	endKey := i + 1
	// Find start of key
	for i >= 0 && !strings.ContainsRune(" \t\"'=:,;", rune(line[i])) {
		i--
	}
	startKey := i + 1
	
	key := line[startKey:endKey]
	keyLower := strings.ToLower(key)
	
	// Blacklist: explicit secrets
	switch keyLower {
	case "password", "pass", "pwd", "secret", "token", "key", "auth", "credential", "api_key", "access_key":
		return true
	}
	
	return false
}
