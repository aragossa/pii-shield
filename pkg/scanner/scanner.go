package scanner

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// Config holds scanner configuration parameters.
type Config struct {
	EntropyThreshold        float64
	MinSecretLength         int
	Salt                    []byte
	SensitiveKeys           []string
	DisableBigramCheck      bool     // Disable English bigram analysis for non-English logs
	BigramDefaultScore      float64  // Default score for unknown bigrams
	AdaptiveThreshold       bool     // Enable statistical adaptive threshold mode
	SensitiveKeyPatterns    []string // Regex patterns for sensitive key detection (stored as strings)
	AdaptiveBaselineSamples int      // Number of samples for adaptive baseline
	CustomRegexes           []CustomRegexRule
	SafeRegexes             []CustomRegexRule
}

// CustomRegexConfig is the DTO for JSON unmarshalling from environment variables.
type CustomRegexConfig struct {
	Pattern string `json:"pattern"`
	Name    string `json:"name"`
}

// CustomRegexRule holds the compiled regex and its name for runtime use.
type CustomRegexRule struct {
	Regexp *regexp.Regexp
	Name   string
}

var (
	currentConfig Config

	// Single compiled regex for all sensitive key patterns (case-insensitive)
	sensitiveRegex *regexp.Regexp

	logTable [256]float64

	bufferPool = sync.Pool{
		New: func() interface{} {
			return new(strings.Builder)
		},
	}

	// ContextKeywords trigger lower entropy thresholds for subsequent tokens
	ContextKeywords = map[string]bool{
		"error": true, "failed": true, "exception": true, "invalid": true,
		"fatal": true, "panic": true, "warning": true, "bad": true,
		"denied": true, "unauthorized": true, "broken": true,
		"password": true, "secret": true, "token": true, "key": true, "auth": true,
	}

	// DefaultEntropyThreshold is the Shannon entropy threshold for high-entropy strings.
	// Lowered from 3.8 to 3.6 to catch shorter random alphanumeric strings.
	DefaultEntropyThreshold = 3.6
)

func init() {
	// defaults
	currentConfig = loadConfig()

	for i := 1; i < 256; i++ {
		logTable[i] = math.Log2(float64(i))
	}
}

// parseFloat parses a float from string, returns error if invalid
func parseFloat(s string) (float64, error) {
	var result float64
	_, err := fmt.Sscanf(s, "%f", &result)
	return result, err
}

// parseInt parses an int from string, returns error if invalid
func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

func loadConfig() Config {
	cfg := Config{
		EntropyThreshold:        DefaultEntropyThreshold,   // Adjusted for bigrams
		MinSecretLength:         6,     // Lower minimal length as we have better context
		DisableBigramCheck:      false, // Enable bigram check by default
		BigramDefaultScore:      -7.0,  // Default for unknown bigrams
		AdaptiveThreshold:       false, // Disabled by default (User feedback)
		AdaptiveBaselineSamples: 100,   // Default baseline sample size
	}

	// Load Salt - CRITICAL SECURITY: Try secure, fallback to error log (don't panic library)
	if envSalt := os.Getenv("PII_SALT"); envSalt != "" {
		if len(envSalt) < 16 {
			fmt.Fprintf(os.Stderr, "WARNING: PII_SALT is too short (<16 bytes). Weak security.\n")
		}
		cfg.Salt = []byte(envSalt)
	} else {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			// CRITICAL SECURITY: Fail closed if we cannot generate a secure salt.
			// Do not use a fallback.
			panic(fmt.Sprintf("FATAL: Failed to generate secure random salt: %v", err))
		}
		cfg.Salt = salt
	}

	// Load entropy threshold override
	if envThreshold := os.Getenv("PII_ENTROPY_THRESHOLD"); envThreshold != "" {
		if threshold, err := parseFloat(envThreshold); err == nil {
			cfg.EntropyThreshold = threshold
		}
	}

	// Load bigram configuration
	if envDisableBigram := os.Getenv("PII_DISABLE_BIGRAM_CHECK"); envDisableBigram == "true" || envDisableBigram == "1" {
		cfg.DisableBigramCheck = true
	}

	if envBigramScore := os.Getenv("PII_BIGRAM_DEFAULT_SCORE"); envBigramScore != "" {
		if score, err := parseFloat(envBigramScore); err == nil {
			cfg.BigramDefaultScore = score
		}
	}

	// Load adaptive threshold mode
	if envAdaptive := os.Getenv("PII_ADAPTIVE_THRESHOLD"); envAdaptive == "true" || envAdaptive == "1" {
		cfg.AdaptiveThreshold = true
		if envSamples := os.Getenv("PII_ADAPTIVE_SAMPLES"); envSamples != "" {
			if samples, err := parseInt(envSamples); err == nil && samples > 0 {
				cfg.AdaptiveBaselineSamples = samples
			}
		}
	}

	// Load Sensitive Keys
	if envKeys := os.Getenv("PII_SENSITIVE_KEYS"); envKeys != "" {
		cfg.SensitiveKeys = strings.Split(envKeys, ",")
	} else {
		cfg.SensitiveKeys = []string{
			"pass", "secret", "token", "key", "cvv", "cvc", "auth", "sign",
			"password", "passwd", "api_key", "apikey", "access_token", "client_secret",
		}
	}
	// Normalized
	for i, k := range cfg.SensitiveKeys {
		cfg.SensitiveKeys[i] = strings.ToLower(strings.TrimSpace(k))
	}

	// Load Sensitive Key Patterns (regex)
	if envPatterns := os.Getenv("PII_SENSITIVE_KEY_PATTERNS"); envPatterns != "" {
		cfg.SensitiveKeyPatterns = strings.Split(envPatterns, ",")
		var validPatterns []string
		for i, p := range cfg.SensitiveKeyPatterns {
			cleaned := strings.TrimSpace(p)
			cfg.SensitiveKeyPatterns[i] = cleaned
			if cleaned != "" {
				validPatterns = append(validPatterns, cleaned)
			}
		}

		if len(validPatterns) > 0 {
			// Combine all patterns into one: (?i)(pat1|pat2|...)
			combined := "(?i)(" + strings.Join(validPatterns, "|") + ")"
			if re, err := regexp.Compile(combined); err == nil {
				sensitiveRegex = re
			} else {
				fmt.Fprintf(os.Stderr, "WARNING: Failed to compile combined sensitive key regex: %v\n", err)
			}
		}
	}

	// Load Custom Regex List
	if envCustomRegex := os.Getenv("PII_CUSTOM_REGEX_LIST"); envCustomRegex != "" {
		var rawRules []CustomRegexConfig
		if err := json.Unmarshal([]byte(envCustomRegex), &rawRules); err != nil {
			log.Fatalf("PII_CUSTOM_REGEX_LIST error: invalid json format: %v", err)
		}

		for _, rule := range rawRules {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				log.Fatalf("PII_CUSTOM_REGEX_LIST error: invalid regex '%s': %v", rule.Pattern, err)
			}
			cfg.CustomRegexes = append(cfg.CustomRegexes, CustomRegexRule{
				Regexp: compiled,
				Name:   rule.Name,
			})
		}
	}

	// Load Safe Regex List (Whitelist)
	if envSafeRegex := os.Getenv("PII_SAFE_REGEX_LIST"); envSafeRegex != "" {
		var rawRules []CustomRegexConfig
		if err := json.Unmarshal([]byte(envSafeRegex), &rawRules); err != nil {
			log.Fatalf("PII_SAFE_REGEX_LIST error: invalid json format: %v", err)
		}

		for _, rule := range rawRules {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				log.Fatalf("PII_SAFE_REGEX_LIST error: invalid regex '%s': %v", rule.Pattern, err)
			}
			cfg.SafeRegexes = append(cfg.SafeRegexes, CustomRegexRule{
				Regexp: compiled,
				Name:   rule.Name,
			})
		}
	}

	return cfg
}

// -----------------------------------------------------------------------------
// 1. Core Entropy Logic
// -----------------------------------------------------------------------------

func CalculateComplexity(token string) float64 {
	if len(token) == 0 {
		return 0
	}

	// 1. Shannon Entropy
	entropy := calculateShannon(token)

	// 2. Class Bonus
	bonus := calculateClassBonus(token)

	// 3. Bigram Check (English Likelihood)
	bigramScore := calculateBigramAdjustment(token)

	return entropy + bonus + bigramScore
}

func calculateShannon(token string) float64 {
	freq := make(map[rune]int)
	totalChars := 0
	for _, r := range token {
		freq[r]++
		totalChars++
	}

	entropy := 0.0
	logLen := math.Log2(float64(totalChars))

	for _, count := range freq {
		p := float64(count) / float64(totalChars)
		entropy -= p * (math.Log2(float64(count)) - logLen)
	}
	return entropy
}

func calculateClassBonus(token string) float64 {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false

	for _, r := range token {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			hasSymbol = true
		}
	}

	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSymbol {
		classes++
	}

	if classes > 1 {
		return float64(classes-1) * 0.5
	}
	return 0.0
}

func calculateBigramAdjustment(token string) float64 {
	// CONDITIONAL: Can be disabled for non-English logs
	if currentConfig.DisableBigramCheck || len(token) <= 3 {
		return 0.0
	}

	sumProb := 0.0
	count := 0
	sLower := strings.ToLower(token)
	for i := 0; i < len(sLower)-1; i++ {
		bg := sLower[i : i+2]
		sumProb += GetBigramProb(bg) // Using exported map/func from bigrams.go
		count++
	}

	if count > 0 {
		avgProb := sumProb / float64(count)
		// If avgProb > -5.8, it's likely English or common text.
		// We reduce complexity score to avoid false positives.
		if avgProb > -5.8 {
			return -1.5 // Penalize score (make it "safer")
		} else if avgProb < -7.0 {
			return 0.5 // Boost score (more random)
		}
	}
	return 0.0
}

func redactWithHMAC(sensitiveData string) string {
	mac := hmac.New(sha256.New, currentConfig.Salt)
	mac.Write([]byte(sensitiveData))
	hash := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("[HIDDEN:%s]", hash[:6])
}

// -----------------------------------------------------------------------------
// 2. Main Scanner (Quotes & Key-Value Aware)
// -----------------------------------------------------------------------------

func ScanAndRedact(logLine string) string {
	if len(logLine) == 0 {
		return ""
	}

	// Try robust JSON parsing first (Variant A from critique)
	trimmed := strings.TrimSpace(logLine)

	// URL Optimization: If line IS a URL (common in access logs), handle it fast.
	if strings.HasPrefix(trimmed, "GET ") || strings.HasPrefix(trimmed, "POST ") || strings.Contains(trimmed, "://") {
		// Extract URL from log line? Or just scan segment?
		// "GET /api/..." -> The whole line isn't a URL.
		// But maskURLParameters assumes input IS a URL?
		// "http://..." is a URL.
		// "GET /foo?k=v" -> "/foo?k=v" is a URL path.

		// If the whole line is "GET /foo...", we probably shouldn't call maskURLParameters on the whole line logic
		// unless maskURLParameters handles "GET " prefix?
		// No, maskURLParameters splits by "?".

		// Let's rely on scanSegment to find URLs?
	}

	if strings.HasPrefix(trimmed, "{") {
		if jsonProcessed, ok := processJSONLine(trimmed); ok {
			return jsonProcessed
		}
	}

	luhnRanges := FindLuhnSequences(logLine)

	sb := bufferPool.Get().(*strings.Builder)
	sb.Reset()
	sb.Grow(len(logLine) + 100)
	defer bufferPool.Put(sb)

	chunkStart := 0

	for _, lr := range luhnRanges {
		if lr.Start > chunkStart {
			safeSegment := logLine[chunkStart:lr.Start]
			processed := scanSegment(safeSegment)
			sb.WriteString(processed)
		}

		secret := logLine[lr.Start:lr.End]
		sb.WriteString(redactWithHMAC(secret))

		chunkStart = lr.End
	}

	if chunkStart < len(logLine) {
		safeSegment := logLine[chunkStart:]
		processed := scanSegment(safeSegment)
		sb.WriteString(processed)
	}

	return sb.String()
}

// scanSegment implements a Quote-Aware Tokenizer.
// It iterates runes and respects " and ' bounds.
// scanSegment implements a Context-Aware & Quote-Aware Tokenizer.
// It handles: escaped quotes, spaces, and sensitive key tracking.
func scanSegment(segment string) string {
	var sb strings.Builder
	runes := []rune(segment)
	n := len(runes)

	start := 0
	inQuote := false
	quoteChar := rune(0)

	state := segmentState{}

	isSep := func(r rune) bool {
		return strings.ContainsRune(" \t,;[]{}()<>", r)
	}

	for i := 0; i <= n; i++ {
		// Handle end of string
		if i == n {
			if start < n {
				token := string(runes[start:n])
				// Process final token
				processAndAppend(token, &sb, &state)
			}
			break
		}

		r := runes[i]

		// Quote Handling with Escape
		if inQuote {
			if r == '\\' {
				// Skip next char (escape)
				if i+1 < n {
					i++
				}
				continue
			}
			if r == quoteChar {
				inQuote = false
			}
			continue
		}

		if r == '"' || r == '\'' {
			inQuote = true
			quoteChar = r
			continue
		}

		if isSep(r) {
			if i > start {
				token := string(runes[start:i])
				processAndAppend(token, &sb, &state)
			}
			sb.WriteRune(r)
			start = i + 1
		}
	}

	return sb.String()
}

// processTokenLogic analyzes a token and returns (processedString, isSensitiveKey).
// forcedSensitive: if true, treat this token as a Value that MUST be protected (skips MinLength).
// contextSensitive: if true, reduce entropy threshold (Context Aware).
// isValuePos: if true, this token MUST be a value (skiye key checks).
func processTokenLogic(rawToken string, forcedSensitive bool, contextSensitive bool, isValuePos bool) (string, bool) {
	// 0. URLs First
	// Support both full URLs (http://...) and relative paths with query params (/api...?k=v)
	if strings.Contains(rawToken, "://") || (strings.Contains(rawToken, "?") && strings.Contains(rawToken, "=")) {
		return maskURLParameters(rawToken), false
	}

	// 1. Check for Key=Value
	if processed, isKey, handled := processEqualPair(rawToken); handled {
		return processed, isKey
	}

	// 2. Handle key:value
	if processed, isKey, handled := processColonPair(rawToken); handled {
		return processed, isKey
	}

	// 3. URLs (Catch-all moved down? No, already at step 0)
	// Original logic had a specific Key=Value check before URL check in one case, but URL check was moved top.
	// Step 3 in original file was "URLs (Moved to TOP)". So we are good.

	// 4. Single Token parsing (Value or Key)
	trimmed := trimQuotes(rawToken)

	// CRITICAL FIX: If we know we are in a Value position (e.g. after :),
	// do NOT treat this as a key, even if it looks like one.
	if !isValuePos {
		if isSensitiveKey(trimmed) {
			return rawToken, true
		}
	}

	// Not a key. Process as value.
	processed := processSingleToken(trimmed, rawToken, forcedSensitive, contextSensitive)

	if processed != trimmed && strings.HasPrefix(processed, "[HIDDEN:") {
		// It was redacted. If input was quoted, re-wrap it.
		if strings.HasPrefix(rawToken, "\"") && strings.HasSuffix(rawToken, "\"") {
			return "\"" + processed + "\"", false
		}
		if strings.HasPrefix(rawToken, "'") && strings.HasSuffix(rawToken, "'") {
			return "'" + processed + "'", false
		}

		// Fix for JSON Integers/Bools: If we redact a number/bool that wasn't quoted, we MUST quote it
		// to avoid invalid JSON (e.g. id: [HIDDEN] invalid, id: "[HIDDEN]" valid).
		lower := strings.ToLower(trimmed)
		if isDigits(trimmed) || lower == "true" || lower == "false" || lower == "null" {
			return "\"" + processed + "\"", false
		}
	}

	return processed, false
}

func trimQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

func processSingleToken(content, original string, forcedSensitive bool, contextSensitive bool) string {

	// 0. Whitelist Check: Safe Regexes (Top Priority)
	// This overrides everything (Custom Regex Redaction, Safety Whitelists & Entropy).
	if len(content) >= 3 { // Optimization: Skip very short tokens
		for _, rule := range currentConfig.SafeRegexes {
			if rule.Regexp.MatchString(content) {
				return original
			}
		}
	}

	// 1. Deterministic Check: Custom Regexes (High Priority)
	// This overrides everything (Safety Whitelists & Entropy).
	if len(content) >= 5 { // Optimization: Skip short tokens
		for _, rule := range currentConfig.CustomRegexes {
			if rule.Regexp.MatchString(content) {
				if rule.Name != "" {
					return fmt.Sprintf("[HIDDEN:%s]", rule.Name)
				}
				return "[HIDDEN]"
			}
		}
	}

	// 0. Safety Whitelists
	if isSafe(content) {
		return original
	}

	// 1. Heuristics Check (Length & Spaces)
	if !forcedSensitive {
		if len(content) < currentConfig.MinSecretLength {
			return original
		}
		// Avoid redacting sentences or multi-word phrases
		if strings.Contains(content, " ") {
			return original
		}
	}

	// 3. Complexity Score
	score := CalculateComplexity(content)

	threshold := currentConfig.EntropyThreshold
	if forcedSensitive {
		threshold = 1.0
	} else if contextSensitive {
		// CONTEXT BOOST: If keyword was previous, lower threshold slightly
		threshold -= 1.3 // e.g. 3.8 -> 2.5. Catches medium/high entropy.
	} else if currentConfig.AdaptiveThreshold {
		// Use adaptive threshold if baseline is ready
		if adaptiveThreshold, ready := globalBaseline.GetThreshold(); ready {
			threshold = adaptiveThreshold
		}
	}

	if score > threshold {
		return redactWithHMAC(content)
	}

	// Token is considered SAFE. Now we can safely update the baseline.
	// This prevents "poisoning" the stats with secrets.
	if !forcedSensitive && currentConfig.AdaptiveThreshold {
		globalBaseline.Update(score)
	}

	return original
}

func processEqualPair(rawToken string) (string, bool, bool) {
	if !strings.ContainsRune(rawToken, '=') {
		return "", false, false
	}
	// Handle quoted strings: "key=value"
	if strings.HasPrefix(rawToken, "\"") || strings.HasPrefix(rawToken, "'") {
		quote := string(rawToken[0])
		trimmed := trimQuotes(rawToken)

		if strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			key := parts[0]
			val := parts[1]

			keySensitive := isSensitiveKey(key)

			var processedVal string
			if keySensitive {
				processedVal = processSingleToken(val, val, true, false)
			} else {
				// Recursive scan for non-sensitive keys (e.g. "data=key=val")
				processedVal = ScanAndRedact(val)
			}

			// Fix: Only treat as "Key" (affecting next token) if Value was empty.
			// If Value was present, we consumed it, so next token is NOT the value.
			return quote + key + "=" + processedVal + quote, keySensitive && val == "", true
		}
		// Fallthrough to single token processing
	} else {
		// Unquoted Key=Value
		parts := strings.SplitN(rawToken, "=", 2)
		key := parts[0]
		val := parts[1]
		keySensitive := isSensitiveKey(key)
		var processedVal string
		if keySensitive {
			processedVal = processSingleToken(val, val, true, false)
		} else {
			processedVal = ScanAndRedact(val)
		}
		// Fix: Only return isSensitiveKey=true if val is empty
		return key + "=" + processedVal, keySensitive && val == "", true
	}
	return "", false, false
}

func processColonPair(rawToken string) (string, bool, bool) {
	if strings.ContainsRune(rawToken, ':') && !strings.Contains(rawToken, "://") {
		if isImage(rawToken) {
			return rawToken, false, true
		}
		parts := strings.SplitN(rawToken, ":", 2)
		if len(parts) == 2 {
			key := parts[0]
			val := parts[1]
			keySensitive := isSensitiveKey(key)

			// Recursively process val? Val might be empty if "key:"
			if val == "" {
				return rawToken, keySensitive, true
			}
			processedVal := processSingleToken(val, val, keySensitive, false)
			return key + ":" + processedVal, keySensitive, true
		}
	}
	return "", false, false
}

func isSensitiveKey(key string) bool {
	// 1. Check substring matching (fast path for standard keys)
	// We still need ToLower for the fixed list unless we change that too,
	// but let's keep it for backward compatibility and as a "fast filter"
	// before the regex if possible? No, user said ToLower is slow.
	// But currentConfig.SensitiveKeys are lowercase.
	// Optimization: If we trust the regex is case-insensitive, we can skip ToLower
	// for the specific regex check. For the list check, we still need it.
	// However, if we move ALL keys to regex, that would be fastest.
	// For now, let's keep the hybrid approach but optimize the Regex part.

	k := strings.ToLower(key)

	// Check substring matching (backward compatible)
	for _, sk := range currentConfig.SensitiveKeys {
		if strings.Contains(k, sk) {
			// Safety check: High entropy strings (likely secrets) should not be treated as keys
			// even if they contain the word "secret" or "key".
			if len(key) > 32 && CalculateComplexity(key) > currentConfig.EntropyThreshold {
				return false
			}
			return true
		}
	}

	// 2. Check compiled regex (single pass, case-insensitive)
	// sensitiveRegex is already (?i), so we match against original 'key'
	// to avoid relying on 'k' (result of ToLower) if we want?
	// Actually 'key' is fine.
	if sensitiveRegex != nil {
		if sensitiveRegex.MatchString(key) {
			return true
		}
	}

	return false
}

func maskURLParameters(url string) string {
	parts := strings.Split(url, "?")
	if len(parts) < 2 {
		return url
	}

	baseUrl := parts[0]
	query := parts[1]

	params := strings.Split(query, "&")
	var sb strings.Builder
	sb.WriteString(baseUrl)
	sb.WriteRune('?')

	for i, param := range params {
		if i > 0 {
			sb.WriteRune('&')
		}

		if strings.Contains(param, "=") {
			kv := strings.SplitN(param, "=", 2)
			key := kv[0]
			val := kv[1]

			if isSensitiveKey(key) {
				sb.WriteString(key)
				sb.WriteRune('=')
				sb.WriteString(redactWithHMAC(val))
			} else {
				score := CalculateComplexity(val)
				if score > currentConfig.EntropyThreshold {
					sb.WriteString(key)
					sb.WriteRune('=')
					sb.WriteString(redactWithHMAC(val))
				} else {
					sb.WriteString(param)
				}
			}
		} else {
			sb.WriteString(param)
		}
	}
	return sb.String()
}

// -----------------------------------------------------------------------------
// Safety Whitelists
// -----------------------------------------------------------------------------

func isSafe(token string) bool {
	// Note: URL check moved up to processTokenLogic to handle masking.

	// URL / Protocol (Fallback only)
	if strings.Contains(token, "://") {
		return true
	}

	// Usage of Helper Functions to reduce complexity
	if isUUID(token) || isIPv6(token) || isTimestamp(token) || isImage(token) {
		return true
	}

	if isPath(token) || isGitHash(token) || isMongoObjectID(token) {
		return true
	}

	if isSSHKey(token) || isGeneratedUsername(token) {
		return true
	}

	return false
}

func isHexStr(s string) bool {
	for _, r := range s {
		if !isHex(r) {
			return false
		}
	}
	return true
}

func isTimestamp(token string) bool {
	// Unix Timestamp (10 digits, starts with 17.., 18.., 2...)
	// 1700000000 is year 2023. ~2033 is 2000000000.
	// Check if pure digits and length 10.
	if len(token) == 10 && isDigits(token) {
		// Unix Timestamp (10 digits).
		// Current time (2023-2026) starts with 17 or 18.
		// Future proofing: also accept 19, 20 (up to year 2033+)
		if strings.HasPrefix(token, "17") || strings.HasPrefix(token, "18") ||
			strings.HasPrefix(token, "19") || strings.HasPrefix(token, "20") {
			return true
		}
	}

	// ISO8601 / RFC3339
	// 2026-01-30...
	// Req: Start with 4 digits, then -, then 2 digits.
	if len(token) >= 10 {
		if isDigits(token[0:4]) && token[4] == '-' && isDigits(token[5:7]) && token[7] == '-' {
			return true
		}
	}
	return false
}

func isImage(token string) bool {
	// common docker registries or image formats
	// e.g. docker.io/..., library/..., gcr.io/...
	if strings.Contains(token, "docker.io") || strings.Contains(token, "gcr.io") || strings.Contains(token, "quay.io") {
		return true
	}
	// common image extensions? not usually in logs unless URL.
	// common structure "name:tag" where name is alpha.
	return false
}

func isIPv6(token string) bool {
	if strings.Count(token, ":") >= 2 {
		isIPv6 := true
		for _, r := range token {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == ':') {
				isIPv6 = false
				break
			}
		}
		if isIPv6 {
			return true
		}
	}
	return false
}

func isPath(token string) bool {
	// Unix Paths
	if strings.HasPrefix(token, "/") || strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") {
		return true
	}

	// Windows Paths / Namespaces
	// 1. Drive letter (e.g. C:\...)
	if len(token) >= 3 && unicode.IsLetter(rune(token[0])) && token[1] == ':' && token[2] == '\\' {
		return true
	}

	// 2. UNC Path (e.g. \\Server\Share)
	if strings.HasPrefix(token, `\\`) {
		return true
	}

	// 3. Generic Windows Path or Namespace (contains at least two backslashes)
	// e.g. "app\modules\adaptivephishing" or "System\Windows\.."
	// We require at least 2 backslashes to avoid false positives with escaped chars in other contexts,
	// though the tokenizer handles those.
	if strings.Count(token, `\`) >= 2 {
		return true
	}

	return false
}

func isGitHash(token string) bool {
	return len(token) == 40 && isHexStr(token)
}

func isMongoObjectID(token string) bool {
	return len(token) == 24 && isHexStr(token)
}

func isSSHKey(token string) bool {
	// SSH Public Key (starts with ssh-rsa, ssh-ed25519)
	if strings.HasPrefix(token, "ssh-") {
		return true
	}

	// SSH Public Key Body (starts with AAAA, high entropy, base64)
	if strings.HasPrefix(token, "AAAA") && len(token) > 20 {
		// Minimal Base64 check (just charset)
		isBase64 := true
		for _, r := range token {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '+' || r == '/' || r == '=') {
				isBase64 = false
				break
			}
		}
		if isBase64 {
			return true
		}
	}
	return false
}

func isGeneratedUsername(token string) bool {
	if strings.HasPrefix(token, "user_") {
		// Safe if rest is just hex/digits/alpha and reasonable length
		rest := token[5:]
		if len(rest) > 0 && len(rest) < 12 {
			isSafeUser := true
			for _, r := range rest {
				if !isHex(r) && r != '_' { // Hex + maybe underscore?
					isSafeUser = false
					break
				}
			}
			if isSafeUser {
				return true
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Luhn Check (Preserved)
// -----------------------------------------------------------------------------

type Range struct {
	Start, End int
}

func FindLuhnSequences(line string) []Range {
	var ranges []Range
	n := len(line)
	if n < 13 {
		return ranges
	}

	var digitIndices []int
	for i, r := range line {
		if unicode.IsDigit(r) {
			digitIndices = append(digitIndices, i)
		}
	}

	numDigits := len(digitIndices)
	if numDigits < 13 {
		return ranges
	}

	for i := 0; i <= numDigits-13; i++ {
		maxLen := 19
		if i+maxLen > numDigits {
			maxLen = numDigits - i
		}

		for L := 13; L <= maxLen; L++ {
			startIdx := digitIndices[i]
			endIdx := digitIndices[i+L-1] + 1

			// Connectivity Check
			if !areDigitsConnected(line, digitIndices[i:i+L]) {
				continue
			}

			// Boundary Check
			if !isValidBoundary(line, startIdx, endIdx) {
				continue
			}

			if countDistinctDigits(line, digitIndices[i:i+L]) < 4 {
				continue
			}

			if validLuhnFromIndices(line, digitIndices[i:i+L]) {
				ranges = append(ranges, Range{Start: startIdx, End: endIdx})
			}
		}
	}
	return mergeRanges(ranges)
}

func countDistinctDigits(line string, indices []int) int {
	seen := 0
	mask := 0
	for _, idx := range indices {
		d := int(line[idx] - '0')
		// Safety bound check
		if d >= 0 && d <= 9 {
			if (mask & (1 << d)) == 0 {
				mask |= (1 << d)
				seen++
			}
		}
	}
	return seen
}

func validLuhnFromIndices(line string, indices []int) bool {
	n := len(indices)
	sum := 0
	alternate := false
	for i := n - 1; i >= 0; i-- {
		r := line[indices[i]]
		digit := int(r - '0')
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

func mergeRanges(ranges []Range) []Range {
	if len(ranges) == 0 {
		return ranges
	}
	var merged []Range
	current := ranges[0]
	for i := 1; i < len(ranges); i++ {
		next := ranges[i]
		if next.Start <= current.End {
			if next.End > current.End {
				current.End = next.End
			}
		} else {
			merged = append(merged, current)
			current = next
		}
	}
	merged = append(merged, current)
	return merged
}

func areDigitsConnected(line string, indices []int) bool {
	for k := 1; k < len(indices); k++ {
		currIdx := indices[k]
		prevIdx := indices[k-1]
		diff := currIdx - prevIdx

		if diff > 2 {
			return false
		}
		if diff == 2 {
			sep := line[prevIdx+1]
			if sep != ' ' && sep != '-' {
				return false
			}
		}
	}
	return true
}

func isValidBoundary(line string, startIdx, endIdx int) bool {
	// BOUNDARY CHECK: Ensure we are not inside a word or larger number
	if startIdx > 0 {
		r := rune(line[startIdx-1])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
		// UUID/Alphanumeric check: if separator is '-', check prev char
		if r == '-' || r == '.' {
			if startIdx > 1 {
				r2 := rune(line[startIdx-2])
				if unicode.IsLetter(r2) {
					return false
				}
			}
		}
	}
	if endIdx < len(line) {
		r := rune(line[endIdx])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
		// UUID/Alphanumeric check: if separator is '-', check next char
		if r == '-' || r == '.' {
			if endIdx+1 < len(line) {
				r2 := rune(line[endIdx+1])
				if unicode.IsLetter(r2) {
					return false
				}
			}
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func isDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !isHex(r) {
			return false
		}
	}
	return true
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// -----------------------------------------------------------------------------
// 3. Robust JSON Parser (using encoding/json)
// -----------------------------------------------------------------------------

func processJSONLine(line string) (string, bool) {
	var data map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.UseNumber() // Preserve large integers/IDs as json.Number

	if err := decoder.Decode(&data); err != nil {
		return "", false
	}

	redactMap(data)

	// Re-serialize
	// Note: output key order is not guaranteed, but JSON semantically the same.
	b, err := json.Marshal(data)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func redactMap(m map[string]interface{}) {
	handleGenericKVPair(m)

	for k, v := range m {
		processMapElement(k, v, m)
	}
}

func redactSlice(s []interface{}) {
	for i, v := range s {
		switch val := v.(type) {
		case map[string]interface{}:
			redactMap(val)
		case []interface{}:
			redactSlice(val)
		case string:
			// Recursive scan for array strings too
			processed := ScanAndRedact(val)
			if processed != val {
				s[i] = processed
			}
		case json.Number:
			str := val.String()
			proc := processSingleToken(str, str, false, false)
			if proc != str {
				s[i] = 0
			}
		case float64:
			str := fmt.Sprintf("%v", val)
			proc := processSingleToken(str, str, false, false)
			if proc != str {
				s[i] = 0
			}
		}
	}
}

func handleGenericKVPair(m map[string]interface{}) {
	// 0. Generic KV Pair Support (Constraint: "key": "sensitive", "value": "secret")
	// If we detect this pattern, efficiently redact the "value" field.
	if kVal, ok := m["key"].(string); ok {
		if isSensitiveKey(kVal) {
			if _, hasVal := m["value"]; hasVal {
				// Redact value regardless of type
				switch v := m["value"].(type) {
				case string:
					m["value"] = redactWithHMAC(v)
				case json.Number:
					m["value"] = 0
				case float64:
					m["value"] = 0
				}
			}
		}
	}
}

func processMapElement(k string, v interface{}, m map[string]interface{}) {
	// Calculate key sensitivity once
	isKeySensitive := isSensitiveKey(k)

	switch val := v.(type) {
	case map[string]interface{}:
		redactMap(val)
	case []interface{}:
		redactSlice(val)
	case string:
		// String redaction
		if isKeySensitive {
			m[k] = redactWithHMAC(val)
		} else {
			// Recursively scan the string value!
			// This handles:
			// 1. Nested JSON strings (e.g. "data": "{\"foo\":...}")
			// 2. Unstructured PII (Luhn/CCs) inside the string
			// 3. Key=Value pairs inside the string
			processed := ScanAndRedact(val)
			if processed != val {
				m[k] = processed
			}
		}
	case json.Number:
		// Number redaction - Preserve Type!
		if isKeySensitive {
			// E.g. "cvv": 123 -> "cvv": 0
			m[k] = 0
		} else {
			// Check Entropy (e.g. Credit Card numbers as Ints)
			s := val.String()
			// Use heuristics on string rep
			// Note: We don't recurse ScanAndRedact here to avoid parsing number as JSON/Luhn line?
			// Luhn might work on "4111..."
			// But ScanAndRedact wraps result? No.
			processed := processSingleToken(s, s, false, false)
			if processed != s {
				// It was redacted. Convert to 0.
				m[k] = 0
			}
		}
	case float64:
		if isKeySensitive {
			m[k] = 0
		} else {
			s := fmt.Sprintf("%v", val)
			processed := processSingleToken(s, s, false, false)
			if processed != s {
				m[k] = 0
			}
		}
		// bools are usually safe
	}
}

type segmentState struct {
	pendingKeySensitive     bool
	pendingContextSensitive bool // NEW: For "Error: secret"
	isInValuePos            bool // Tracks if we are physically after a ':' or '=' separator
}

func processAndAppend(token string, sb *strings.Builder, state *segmentState) {
	processed, isKey := processTokenLogic(token, state.pendingKeySensitive, state.pendingContextSensitive, state.isInValuePos)
	sb.WriteString(processed)

	// Update Context
	if isKey {
		state.pendingKeySensitive = true
		// pendingContextSensitive = false // Overwritten below by keyword check
	} else {
		if state.isInValuePos {
			state.pendingKeySensitive = false
		}
	}

	// Track Separator Tokens explicitly
	// If token was ":", ",", "=", we are in Value Pos context changes
	trimmed := strings.TrimSpace(token)

	// Check if this token is a Context Keyword (e.g. "Error", "Failed")
	lower := strings.ToLower(trimmed)
	if ContextKeywords[lower] {
		state.pendingContextSensitive = true
	} else {
		state.pendingContextSensitive = false
	}

	if trimmed == ":" || trimmed == "=" {
		state.isInValuePos = true
	} else if trimmed != "" {
		// Reset if it was a normal token (key or value)
		state.isInValuePos = false
	}
}
