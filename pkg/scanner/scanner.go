package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"unicode"
)

// Salt - this should ideally be rotated or set via ENV. 
var Salt = "my-ephemeral-random-salt-2026"

// Precomputed logs for optimization
var logTable [256]float64

func init() {
	// Precompute log(i) for i=1..255
	for i := 1; i < 256; i++ {
		logTable[i] = math.Log2(float64(i))
	}
}

// -----------------------------------------------------------------------------
// 1. Complexity Scoring (Enhanced Entropy)
// -----------------------------------------------------------------------------

// CalculateComplexity computes a score based on entropy and character classes.
// Higher score = more likely to be a secret.
// Normal word ~3.0. "SuperSecret123" ~5.8.
func CalculateComplexity(token string) float64 {
	if len(token) == 0 {
		return 0
	}
	
	// Shannon Entropy
	entropy := calculateShannonEntropy(token)
	
	// Character Class Bonus
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false
	
	for _, r := range token {
		if unicode.IsUpper(r) { hasUpper = true }
		if unicode.IsLower(r) { hasLower = true }
		if unicode.IsDigit(r) { hasDigit = true }
		if unicode.IsPunct(r) || unicode.IsSymbol(r) { hasSymbol = true }
	}
	
	classes := 0
	if hasUpper { classes++ }
	if hasLower { classes++ }
	if hasDigit { classes++ }
	if hasSymbol { classes++ }
	
	// Bonus: 0.5 per extra class
	bonus := 0.0
	if classes > 1 {
		bonus = float64(classes-1) * 0.5
	}
	
	return entropy + bonus
}

func calculateShannonEntropy(data string) float64 {
	if len(data) == 0 { return 0 }
	var frequencies [256]int
	for i := 0; i < len(data); i++ {
		frequencies[data[i]]++ // simplistic byte check
	}

	var entropy float64
	lenData := float64(len(data))
	logLen := math.Log2(lenData)

	for _, count := range frequencies {
		if count > 0 {
			var logCount float64
			if count < 256 {
				logCount = logTable[count]
			} else {
				logCount = math.Log2(float64(count))
			}
			entropy -= (float64(count) / lenData) * (logCount - logLen)
		}
	}
	return entropy
}

// -----------------------------------------------------------------------------
// 2. Statistical Key Analysis (Bigrams)
// -----------------------------------------------------------------------------

// IsTechnicalKey analyzes the "weirdness" of a key using bigram stats.
func IsTechnicalKey(key string) bool {
    key = strings.ToLower(key)
    
    totalProb := 0.0
    bigramCount := 0
    
    for i := 0; i < len(key)-1; i++ {
        rune1 := rune(key[i])
        rune2 := rune(key[i+1])
        if !unicode.IsLetter(rune1) || !unicode.IsLetter(rune2) {
            continue
        }
        bg := key[i:i+2]
        totalProb += GetBigramProb(bg)
        bigramCount++
    }
    
    if bigramCount == 0 {
        return false 
    }
    
    avgProb := totalProb / float64(bigramCount)
    
    // Threshold for "unusual" English (Technical/Abbreviated)
    // Lowered to -6.4 to avoid common words like "debug", "payload", "api"
    return avgProb < -6.4
}

// -----------------------------------------------------------------------------
// 3. Sliding Window Luhn (Global Line Check)
// -----------------------------------------------------------------------------

type Range struct {
	Start, End int // [Start, End)
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

	// Check lengths 13 to 19
	for i := 0; i <= numDigits-13; i++ {
		maxLen := 19
		if i+maxLen > numDigits {
			maxLen = numDigits - i
		}

		for L := 13; L <= maxLen; L++ {
			startIdx := digitIndices[i]
			endIdx := digitIndices[i+L-1] + 1
			
			// 1. Connectivity Check (Strict Separators)
			// Ensure digits are adjacent or separated ONLY by ' ' or '-'
			connected := true
			for k := 1; k < L; k++ {
				currIdx := digitIndices[i+k]
				prevIdx := digitIndices[i+k-1]
				diff := currIdx - prevIdx
				
				if diff > 2 {
					// Gap too large (more than 1 char between digits)
					connected = false
					break
				}
				if diff == 2 {
					// Exactly one char between digits. Must be ' ' or '-'
					sep := line[prevIdx+1]
					if sep != ' ' && sep != '-' {
						connected = false
						break
					}
				}
				// If diff == 1, they are adjacent. OK.
			}
			
			if !connected {
				continue
			}
			
			// 2. Distinct Digit Check
			// Avoids "0000000000000" or simple timestamps if they somehow pass
			if countDistinctDigits(line, digitIndices[i:i+L]) < 4 {
			    continue
			}
			
			if validLuhnFromIndices(line, digitIndices[i : i+L]) {
				ranges = append(ranges, Range{Start: startIdx, End: endIdx})
			}
		}
	}

	return mergeRanges(ranges)
}

func countDistinctDigits(line string, indices []int) int {
    seen := 0
    // simplistic bitmask for digits 0-9
    mask := 0
    for _, idx := range indices {
        d := int(line[idx] - '0')
        if (mask & (1 << d)) == 0 {
            mask |= (1 << d)
            seen++
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
	// Simple merge logic assuming sorted by Start
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

// -----------------------------------------------------------------------------
// Main Scan Logic
// -----------------------------------------------------------------------------

// ScanAndRedact scans a log line and redacts potential secrets.
func ScanAndRedact(logLine string) string {
	if len(logLine) == 0 {
		return ""
	}
	
	luhnRanges := FindLuhnSequences(logLine)
	
	var sb strings.Builder
	sb.Grow(len(logLine) + 100)
	
	// chunkStart tracks the end of the last written chunk
	chunkStart := 0
	
	// We iterate through Luhn ranges (which are sorted)
	// Anything between ranges is "Safe" (not a CC) -> Scan for other secrets
	// The range itself is "Secret" (CC) -> Redact immediately
	
	for _, lr := range luhnRanges {
		if lr.Start > chunkStart {
			safeSegment := logLine[chunkStart:lr.Start]
			processed := scanSegmentForSecrets(safeSegment)
			sb.WriteString(processed)
		}
		
		// Redact CC
		secret := logLine[lr.Start:lr.End]
		sb.WriteString(redactWithHash(secret))
		
		chunkStart = lr.End
	}
	
	// Tail
	if chunkStart < len(logLine) {
		safeSegment := logLine[chunkStart:]
		processed := scanSegmentForSecrets(safeSegment)
		sb.WriteString(processed)
	}
	
	return sb.String()
}

// scanSegmentForSecrets scans a string that is KNOWN NOT TO BE A CREDIT CARD.
func scanSegmentForSecrets(segment string) string {
    var sb strings.Builder
    start := 0
    n := len(segment)
    
    var prevToken string
    
    isSep := func(r rune) bool {
        // Removed ':' from separators to keep URLs like jdbc:mysql:// intact
        return strings.ContainsRune(" \t\"',;[]{}()<>=", r)
    }
    
    for i := 0; i <= n; i++ {
        isSeparator := false
        if i == n {
            isSeparator = true
        } else {
            if isSep(rune(segment[i])) {
                isSeparator = true
            }
        }
        
        if isSeparator {
            if i > start {
                token := segment[start:i]
                
                // DECISIONS (Pure Math)
                redact := false
                isSafe := false

                // 0. Whitelists
                // URL / Protocol (e.g. http://, jdbc:mysql://)
                if strings.Contains(token, "://") {
                    isSafe = true
                }
                // UUID Check
                if !isSafe && isUUID(token) {
                    isSafe = true
                }
                // Short words check (keep "db", "user") but check digits (CVV)
                if !isSafe && len(token) < 5 && !isDigits(token) {
                    isSafe = true
                }
                // Paths
                if !isSafe && strings.HasPrefix(token, "/") {
                    isSafe = true
                }
                // Timestamps (Simple 20xx check)
                if !isSafe && len(token) > 4 && strings.HasPrefix(token, "20") {
                     if unicode.IsDigit(rune(token[2])) && unicode.IsDigit(rune(token[3])) {
                         isSafe = true
                     }
                }
                
                if !isSafe {
                    // 1. Complexity Score
                    score := CalculateComplexity(token)
                    
                    // Threshold > 3.7
                    if score > 3.7 {
                        redact = true
                    }
                    
                    // 2. Statistical Context (Bigrams) for Low Entropy Secrets
                    if !redact && len(prevToken) > 0 {
                        if IsTechnicalKey(prevToken) {
                             if score > 1.0 { 
                                 redact = true
                             }
                        }
                    }
                }
                
                if redact {
                    sb.WriteString(redactWithHash(token))
                } else {
                    sb.WriteString(token)
                }
                
                prevToken = token
            } 
            if i < n {
                sb.WriteByte(segment[i])
            }
            start = i + 1
        }
    }
    return sb.String()
}

func redactWithHash(sensitiveData string) string {
	input := sensitiveData + Salt
	hash := sha256.Sum256([]byte(input))
	shortHash := hex.EncodeToString(hash[:3])
	return fmt.Sprintf("[HIDDEN:%s]", shortHash)
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
    // 8-4-4-4-12
    if len(s) != 36 {
        return false
    }
    // Check hyphens
    if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
        return false
    }
    // Check hex
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
