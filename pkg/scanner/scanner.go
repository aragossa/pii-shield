package scanner

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
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
	CombinedCustomRegex     *regexp.Regexp    // Optimized "Mega-Regex" (O(1) match)
	CustomRegexNames        []string          // Names corresponding to CombinedCustomRegex submatches
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

var hmacPool *sync.Pool

func init() {
	// defaults
	currentConfig = loadConfig()

	// Initialize HMAC Pool
	hmacPool = &sync.Pool{
		New: func() interface{} {
			return hmac.New(sha256.New, currentConfig.Salt)
		},
	}

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

		var patterns []string
		var names []string

		for _, rule := range rawRules {
			// Validate regex individually first
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				log.Fatalf("PII_CUSTOM_REGEX_LIST error: invalid regex '%s': %v", rule.Pattern, err)
			}
			
			// Add to combined list - wrapped in capturing group to identify which one matched
			patterns = append(patterns, "("+rule.Pattern+")")
			names = append(names, rule.Name)
			
			// Keep individual rules for backward compatibility (or remove if fully fully switched)
			// processSingleToken uses CombinedCustomRegex now.
			// existing tests might check cfg.CustomRegexes?
			// Let's populate it just in case, or leave it empty?
			// To be safe and cleaner, we remove the loop over CustomRegexes in processSingleToken.
			// But Config struct still has CustomRegexes field. Let's populate it to be safe.
			compiled, _ := regexp.Compile(rule.Pattern)
			cfg.CustomRegexes = append(cfg.CustomRegexes, CustomRegexRule{
				Regexp: compiled,
				Name:   rule.Name,
			})
		}

		if len(patterns) > 0 {
			combined := strings.Join(patterns, "|")
			compiled, err := regexp.Compile(combined)
			if err != nil {
				log.Printf("WARNING: Failed to compile combined custom regex: %v. Fallback to individual checks.", err)
				cfg.CombinedCustomRegex = nil
			} else {
				cfg.CombinedCustomRegex = compiled
				cfg.CustomRegexNames = names
			}
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
	if len(token) == 0 {
		return 0
	}

	// Optimization: Stack allocation for ASCII-only tokens (common case)
	// Checks for ASCII and populates counts in one pass.
	// If non-ASCII found, falls back to map.
	var counts [256]int
	isASCII := true
	totalChars := 0

	// Use byte iteration for speed
	for i := 0; i < len(token); i++ {
		b := token[i]
		if b >= utf8.RuneSelf {
			isASCII = false
			break
		}
		counts[b]++
		totalChars++
	}

	if isASCII {
		entropy := 0.0
		logLen := math.Log2(float64(totalChars))
		for _, count := range counts {
			if count == 0 {
				continue
			}
			p := float64(count) / float64(totalChars)
			entropy -= p * (math.Log2(float64(count)) - logLen)
		}
		return entropy
	}

	// Fallback: Unicode (Allocates map)
	freq := make(map[rune]int)
	totalChars = 0
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

func redactWithHMAC(sensitiveData string, sb *strings.Builder) {
	mac := hmacPool.Get().(hash.Hash)
	defer hmacPool.Put(mac)

	mac.Reset()
	mac.Write([]byte(sensitiveData))
	// Zero-allocation hex encoding
	// We need 6 chars of hash. Sha256 is 32 bytes -> 64 hex chars.
	// We can compute just the first few bytes?
	// standard mac.Sum appends to nil. Allocates slice.
	// We can pass a buffer to Sum?
	sum := mac.Sum(nil) // this still allocates the slice [32]byte
	// To avoid alloc, we'd need a stack buffer, but Mac interface Sum requires slice.
	// Optimization: 1 alloc for Sum is better than Sprintf.

	// Write [HIDDEN:
	sb.WriteString("[HIDDEN:")
	
	// Hex encode first 3 bytes (6 chars) directly to builder
	// We can manually hex encode to avoid string conv
	dst := make([]byte, 6)
	hex.Encode(dst, sum[:3])
	sb.Write(dst)
	
	sb.WriteString("]")
}

// redactString is a helper for JSON/Map paths that require a string return.
// It uses a pooled builder to minimize allocs, but still allocates the result string.
func redactString(sensitiveData string) string {
	sb := bufferPool.Get().(*strings.Builder)
	sb.Reset()
	defer bufferPool.Put(sb)
	redactWithHMAC(sensitiveData, sb)
	return sb.String()
}

func processSingleTokenToString(content, original string, forcedSensitive, contextSensitive bool) string {
	sb := bufferPool.Get().(*strings.Builder)
	sb.Reset()
	defer bufferPool.Put(sb)
	processSingleToken(content, original, forcedSensitive, contextSensitive, false, sb)
	return sb.String()
}

// -----------------------------------------------------------------------------
// 2. Main Scanner (Quotes & Key-Value Aware)
// -----------------------------------------------------------------------------

func ScanAndRedact(logLine string) string {
	if len(logLine) == 0 {
		return ""
	}
	sb := bufferPool.Get().(*strings.Builder)
	sb.Reset()
	sb.Grow(len(logLine) + 100)
	defer bufferPool.Put(sb)

	scanLine(logLine, sb)
	return sb.String()
}

// scanLine is the zero-allocation internal version of ScanAndRedact
func scanLine(logLine string, sb *strings.Builder) {
	if len(logLine) == 0 {
		return
	}

	trimmed := strings.TrimSpace(logLine)

	// URL Optimization
	if strings.HasPrefix(trimmed, "GET ") || strings.HasPrefix(trimmed, "POST ") || strings.Contains(trimmed, "://") {
		// Rely on scanSegment
	}

	if strings.HasPrefix(trimmed, "{") {
		if jsonProcessed, ok := processJSONLine(trimmed); ok {
			sb.WriteString(jsonProcessed)
			return
		}
	}

	luhnRanges := FindLuhnSequences(logLine)
	chunkStart := 0

	for _, lr := range luhnRanges {
		if lr.Start > chunkStart {
			safeSegment := logLine[chunkStart:lr.Start]
			scanSegment(safeSegment, sb)
		}

		secret := logLine[lr.Start:lr.End]
		redactWithHMAC(secret, sb)

		chunkStart = lr.End
	}

	if chunkStart < len(logLine) {
		safeSegment := logLine[chunkStart:]
		scanSegment(safeSegment, sb)
	}
}

// scanSegment implements a Quote-Aware Tokenizer.
// It iterates runes and respects " and ' bounds.
// scanSegment implements a Context-Aware & Quote-Aware Tokenizer.
// It handles: escaped quotes, spaces, and sensitive key tracking.
func scanSegment(segment string, sb *strings.Builder) {
	n := len(segment)
	start := 0
	inQuote := false
	quoteChar := rune(0)
	seenInvalid := false // Track invalid UTF-8 sequence

	state := segmentState{}

	isSep := func(r rune) bool {
		return strings.ContainsRune(" \t,;[]{}()<>", r)
	}

	// Manual Byte Loop for precise control and skipping
	// Note: We need to decode runes to check isSep and quotes correctly?
	// strings.ContainsRune works on runes.
	// If input is valid UTF-8, we can use utf8.DecodeRune.
	
	i := 0
	for i < n {
		r, width := utf8.DecodeRuneInString(segment[i:])
		if r == utf8.RuneError {
			// Check if it's a real RuneError char or invalid byte
			if width == 1 {
				seenInvalid = true
			}
			// fallback/skip
			i++
			continue
		}

		if inQuote {
			if r == '\\' {
				// Skip next char (escape)
				i += width
				if i < n {
					_, w2 := utf8.DecodeRuneInString(segment[i:])
					i += w2
				}
				continue
			}
			if r == quoteChar {
				inQuote = false
			}
			i += width
			continue
		}

		if r == '"' || r == '\'' {
			inQuote = true
			quoteChar = r
			i += width
			continue
		}

		if isSep(r) {
			if i > start {
				token := segment[start:i]
				if seenInvalid {
					token = strings.ToValidUTF8(token, "\uFFFD")
				}
				processAndAppend(token, sb, &state)
			}
			sb.WriteRune(r)
			i += width
			start = i
			seenInvalid = false
		} else {
			i += width
		}
	}

	// Final token
	if start < n {
		token := segment[start:n]
		if seenInvalid {
			token = strings.ToValidUTF8(token, "\uFFFD")
		}
		processAndAppend(token, sb, &state)
	}
}

// processTokenLogic analyzes a token and returns (processedString, isSensitiveKey).
// forcedSensitive: if true, treat this token as a Value that MUST be protected (skips MinLength).
// contextSensitive: if true, reduce entropy threshold (Context Aware).
// isValuePos: if true, this token MUST be a value (skiye key checks).
func processTokenLogic(rawToken string, forcedSensitive bool, contextSensitive bool, isValuePos bool, sb *strings.Builder) (isKey bool) {
	// 0. URLs First
	if strings.Contains(rawToken, "://") || (strings.Contains(rawToken, "?") && strings.Contains(rawToken, "=")) {
		maskURLParameters(rawToken, sb)
		return false
	}

	// 1. Check for Key=Value
	if isKey, handled := processEqualPair(rawToken, sb); handled {
		return isKey
	}

	// 2. Handle key:value
	if isKey, handled := processColonPair(rawToken, sb); handled {
		return isKey
	}

	// 3. Single Token parsing (Value or Key)
	trimmed := trimQuotes(rawToken)

	// CRITICAL FIX: If we know we are in a Value position (e.g. after :),
	// do NOT treat this as a key, even if it looks like one.
	if !isValuePos {
		if isSensitiveKey(trimmed) {
			sb.WriteString(rawToken)
			return true
		}
	}

	// Not a key. Process as value.
	processSingleToken(trimmed, rawToken, forcedSensitive, contextSensitive, true, sb)
	return false
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

func processSingleToken(content, original string, forcedSensitive bool, contextSensitive bool, autoQuote bool, sb *strings.Builder) {
	// 0. Safety Whitelists (Static - Fastest)
	if isSafe(content) {
		sb.WriteString(original)
		return
	}

	// 1. Whitelist Check: Safe Regexes
	if len(content) >= 3 {
		for _, rule := range currentConfig.SafeRegexes {
			if rule.Regexp.MatchString(content) {
				sb.WriteString(original)
				return
			}
		}
	}

	// 2. Deterministic Check: Custom Regexes
	if len(content) >= 5 {
		if currentConfig.CombinedCustomRegex != nil {
			// Optimization: Single pass O(1)
			loc := currentConfig.CombinedCustomRegex.FindStringSubmatchIndex(content)
			if loc != nil {
				matchName := ""
				for i := 0; i < len(currentConfig.CustomRegexNames); i++ {
					idx := 2 + (i * 2)
					if idx < len(loc) && loc[idx] != -1 {
						matchName = currentConfig.CustomRegexNames[i]
						break
					}
				}

				needsQuotes := false
				if strings.HasPrefix(original, "\"") || strings.HasPrefix(original, "'") {
					needsQuotes = true
				} else if autoQuote {
					lower := strings.ToLower(content)
					if isDigits(content) || lower == "true" || lower == "false" || lower == "null" {
						needsQuotes = true
					}
				}

				if needsQuotes {
					sb.WriteRune('"')
				}
				
				sb.WriteString("[HIDDEN")
				if matchName != "" {
					sb.WriteRune(':')
					sb.WriteString(matchName)
				}
				sb.WriteRune(']')
				
				if needsQuotes {
					sb.WriteRune('"')
				}
				return
			}
		} else {
			// Fallback loop
			for _, rule := range currentConfig.CustomRegexes {
				if rule.Regexp.MatchString(content) {
					needsQuotes := false
					if strings.HasPrefix(original, "\"") || strings.HasPrefix(original, "'") {
						needsQuotes = true
					} else if autoQuote {
						lower := strings.ToLower(content)
						if isDigits(content) || lower == "true" || lower == "false" || lower == "null" {
							needsQuotes = true
						}
					}

					if needsQuotes {
						sb.WriteRune('"')
					}
					sb.WriteString("[HIDDEN")
					if rule.Name != "" {
						sb.WriteRune(':')
						sb.WriteString(rule.Name)
					}
					sb.WriteRune(']')
					if needsQuotes {
						sb.WriteRune('"')
					}
					return
				}
			}
		}
	}

	// 3. Heuristics Check (Length & Spaces)
	if !forcedSensitive {
		if len(content) < currentConfig.MinSecretLength {
			sb.WriteString(original)
			return
		}
		if strings.Contains(content, " ") {
			sb.WriteString(original)
			return
		}
	}

	// 4. Complexity Score
	score := CalculateComplexity(content)
	threshold := currentConfig.EntropyThreshold
	if forcedSensitive {
		threshold = 1.0
	} else if contextSensitive {
		threshold -= 1.3
	} else if currentConfig.AdaptiveThreshold {
		if adaptiveThreshold, ready := globalBaseline.GetThreshold(); ready {
			threshold = adaptiveThreshold
		}
	}

	if score > threshold {
		// Redaction happens
		needsQuotes := false
		if strings.HasPrefix(original, "\"") || strings.HasPrefix(original, "'") {
			needsQuotes = true
		} else if autoQuote {
			lower := strings.ToLower(content)
			if isDigits(content) || lower == "true" || lower == "false" || lower == "null" {
				needsQuotes = true
			}
		}

		if needsQuotes {
			sb.WriteRune('"')
		}
		redactWithHMAC(content, sb)
		if needsQuotes {
			sb.WriteRune('"')
		}
		return
	}

	// Token SAFE
	if !forcedSensitive && currentConfig.AdaptiveThreshold {
		globalBaseline.Update(score)
	}

	sb.WriteString(original)
}

func processEqualPair(rawToken string, sb *strings.Builder) (isKey bool, handled bool) {
	idx := strings.IndexByte(rawToken, '=')
	if idx == -1 {
		return false, false
	}
	// Handle quoted strings: "key=value"
	if strings.HasPrefix(rawToken, "\"") || strings.HasPrefix(rawToken, "'") {
		quote := string(rawToken[0])
		trimmed := trimQuotes(rawToken)

		tIdx := strings.IndexByte(trimmed, '=')
		if tIdx != -1 {
			// Logic: key is trimmed[:tIdx], val is trimmed[tIdx+1:]
			key := trimmed[:tIdx]
			val := trimmed[tIdx+1:]

			keySensitive := isSensitiveKey(key)

			sb.WriteString(quote)
			sb.WriteString(key)
			sb.WriteRune('=')
			if keySensitive {
				processSingleToken(val, val, true, false, false, sb)
			} else {
				// Recursive scan for non-sensitive keys (e.g. "data=key=val")
				scanLine(val, sb)
			}
			sb.WriteString(quote)

			return keySensitive && val == "", true
		}
		// Fallthrough to single token processing
	} else {
		// Unquoted Key=Value
		key := rawToken[:idx]
		val := rawToken[idx+1:]
		
		keySensitive := isSensitiveKey(key)
		
		sb.WriteString(key)
		sb.WriteRune('=')
		if keySensitive {
			processSingleToken(val, val, true, false, false, sb)
		} else {
			scanLine(val, sb)
		}
		return keySensitive && val == "", true
	}
	return false, false
}

func processColonPair(rawToken string, sb *strings.Builder) (isKey bool, handled bool) {
	if strings.Contains(rawToken, "://") {
		return false, false // URL-like
	}
	idx := strings.IndexByte(rawToken, ':')
	if idx != -1 {
		if isImage(rawToken) {
			sb.WriteString(rawToken)
			return false, true
		}
		
		key := rawToken[:idx]
		val := rawToken[idx+1:]
		
		// Previous logic checked len(parts) == 2. strings.Index ensures we have two parts (empty suffix OK).
		// Wait, if "key:", val is "". SplitN returns ["key", ""].
		
		keySensitive := isSensitiveKey(key)

		// Recursively process val? Val might be empty if "key:"
		if val == "" {
			sb.WriteString(rawToken)
			return keySensitive, true
		}
		
		sb.WriteString(key)
		sb.WriteRune(':')
		processSingleToken(val, val, keySensitive, false, false, sb)
		
		return keySensitive, true
	}
	return false, false
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

func maskURLParameters(url string, sb *strings.Builder) {
	parts := strings.Split(url, "?")
	if len(parts) < 2 {
		sb.WriteString(url)
		return
	}

	baseUrl := parts[0]
	query := parts[1]

	params := strings.Split(query, "&")
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
				redactWithHMAC(val, sb)
			} else {
				score := CalculateComplexity(val)
				if score > currentConfig.EntropyThreshold {
					sb.WriteString(key)
					sb.WriteRune('=')
					redactWithHMAC(val, sb)
				} else {
					sb.WriteString(param)
				}
			}
		} else {
			sb.WriteString(param)
		}
	}
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
	// Optimization: Early exit if no digits (Avoids allocating slices)
	if !strings.ContainsAny(line, "0123456789") {
		return nil
	}
	// Note: The above optimization covers ASCII digits (most common for Credit Cards).
	// If we support non-ASCII digits (e.g. Arabic-Indic), we'd need unicode check,
	// but strings.IndexFunc(line, unicode.IsDigit) is slower.
	// Given standard usage, checking ASCII digits is a massive win for 99% of logs.

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
			proc := processSingleTokenToString(str, str, false, false)
			if proc != str {
				s[i] = 0
			}
		case float64:
			str := fmt.Sprintf("%v", val)
			proc := processSingleTokenToString(str, str, false, false)
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
					m["value"] = redactString(v)
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
			m[k] = redactString(val)
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
			processed := processSingleTokenToString(s, s, false, false)
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
			processed := processSingleTokenToString(s, s, false, false)
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
	isKey := processTokenLogic(token, state.pendingKeySensitive, state.pendingContextSensitive, state.isInValuePos, sb)
	// sb is updated inside processTokenLogic

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
