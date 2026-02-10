#!/bin/bash
# full_stress_test.sh - v5 (With Performance Metrics & macOS Support)

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

INPUT_FILE="full_test_input.log"
OUTPUT_FILE="full_test_output.log"
META_FILE="full_test_meta.txt"
COUNT=1000

# Helper function for cross-platform timing (Linux/macOS)
get_time_ms() {
    # Uses python3 for consistent millisecond precision on both Mac and Linux
    python3 -c 'import time; print(int(time.time() * 1000))'
}

# 0. Run Advanced Go Tests (Unit Tests)
echo -e "${BLUE}🧪 Running Advanced Go Unit Tests...${NC}"
go test -v ./pkg/scanner/...
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Go tests failed! Aborting stress test.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Go tests passed.${NC}\n"

echo -e "${BLUE}🚀 Running Go Benchmarks...${NC}"
go test -bench=. -benchmem -v ./pkg/scanner
echo -e "${GREEN}✅ Benchmarks complete.${NC}\n"

echo -e "${BLUE}🏗️  Building Docker Image...${NC}"
docker build -t pii-shield:local . > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Docker build failed.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Docker image updated.${NC}\n"

FAILURES=0

# ==============================================================================
# PHASE 1: Real-World Edge Cases (Static Regression)
# ==============================================================================
echo -e "${BLUE}▶️  PHASE 1: Real-World Edge Cases (Matryoshka, Quotes)${NC}"
rm -f "$INPUT_FILE"
# Standard regression cases
echo '{"key": "password", "value": "SuperSecret123"}' >> "$INPUT_FILE"
echo '{"msg": "User said \"Hello\" to admin"}' >> "$INPUT_FILE"
echo '{"data": "{\"nested_key\": \"nested_secret\"}"}' >> "$INPUT_FILE"
echo 'jdbc:mysql://db:3306?pass=SecretDBPass' >> "$INPUT_FILE"

cat "$INPUT_FILE" | docker run -i --rm pii-shield:local > "$OUTPUT_FILE"

if grep -q "SuperSecret123" "$OUTPUT_FILE"; then
    echo -e "${RED}[FAIL] Case 1: Simple Password leaked${NC}"
    ((FAILURES++))
else echo -e "${GREEN}[PASS] Case 1: Simple Password redacted${NC}"; fi

if grep -q 'User said \\"Hello\\" to admin' "$OUTPUT_FILE"; then
    echo -e "${GREEN}[PASS] Case 2: Escaped quotes preserved${NC}"
else
    echo -e "${RED}[FAIL] Case 2: Escaped quotes corrupted${NC}"
    ((FAILURES++))
fi

# ==============================================================================
# PHASE 2: The "Wild" Stress Test (Dynamic & High Entropy)
# ==============================================================================
echo -e "\n${BLUE}▶️  PHASE 2: Bulk Wild Test (${COUNT} Lines)${NC}"
echo -e "${YELLOW}   Injecting: Dynamic Secrets, Git Hashes, SSH Keys, Binary Dumps...${NC}"

TIMESTAMPS=("2026-01-30T10:00:00Z" "1706608800")
LEVELS=("INFO" "WARN" "ERROR" "DEBUG" "FATAL")
MESSAGES=("Process crash" "DB timeout" "Render complete" "Health check" "Binary dump")

# Clean files
> "$INPUT_FILE"
> "$META_FILE"

for i in $(seq 1 $COUNT); do
    TS=${TIMESTAMPS[$((RANDOM % ${#TIMESTAMPS[@]}))]}
    LVL=${LEVELS[$((RANDOM % ${#LEVELS[@]}))]}
    MSG=${MESSAGES[$((RANDOM % ${#MESSAGES[@]}))]}
    
    # Generate DYNAMIC Payload
    RAND_TYPE=$((RANDOM % 7))
    
    if [ $RAND_TYPE -eq 0 ]; then
        # === 1. REAL SECRET (Known Key) ===
        SECRET_VAL=$(openssl rand -base64 15 | tr -dc 'a-zA-Z0-9')
        PAYLOAD="api_key=${SECRET_VAL}"
        TYPE="SECRET"
        
    elif [ $RAND_TYPE -eq 1 ]; then
        # === 2. SAFE LOW ENTROPY (Standard) ===
        SAFE_VAL="user_$(openssl rand -hex 2)"
        PAYLOAD="username=${SAFE_VAL}"
        TYPE="SAFE"
        
    elif [ $RAND_TYPE -eq 2 ]; then
        # === 3. SAFE HIGH ENTROPY (The Trap) ===
        # These look like secrets but are safe. We want to ensure NO False Positives.
        SUB_TYPE=$((RANDOM % 3))
        if [ $SUB_TYPE -eq 0 ]; then
            VAL=$(openssl rand -hex 20)
            PAYLOAD="commit_sha=${VAL}"
        elif [ $SUB_TYPE -eq 1 ]; then
            VAL=$(uuidgen 2>/dev/null || echo "550e8400-e29b-41d4-a716-446655440000")
            PAYLOAD="request_id=${VAL}"
        else
            VAL="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0g+Z"
            PAYLOAD="pub_key=${VAL}"
        fi
        TYPE="SAFE"
        
    elif [ $RAND_TYPE -eq 3 ]; then
        # === 4. HEX DUMP (Textual Noise) ===
        VAL="0a 1b 3c 4d 5e 6f 90 21"
        PAYLOAD="memory_dump: [${VAL}]"
        TYPE="SAFE"

    elif [ $RAND_TYPE -eq 4 ]; then
        # === 5. UNKNOWN KEY + HIGH ENTROPY (Entropy Check) ===
        # Vulnerability Probe: Key is NOT in sensitive list. Must rely on entropy.
        UNKNOWN_KEY="custom_var_$(openssl rand -hex 2)"
        # High entropy secret (Base64-like)
        SECRET_VAL=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')
        PAYLOAD="${UNKNOWN_KEY}=${SECRET_VAL}"
        TYPE="SECRET"

    elif [ $RAND_TYPE -eq 5 ]; then
        # === 6. BINARY GARBAGE (Stability Check) ===
        # Inject invalid UTF-8/High-bit chars to test parser stability
        # Note: We escape it slightly to ensure it passes through echo/cat logic but hits Docker
        # Using printf to generate bytes. AVOID NULL (\x00) as it breaks bash variables/paste.
        VAL=$(printf "BrokenUTF8_\xFF\xFE_End")
        PAYLOAD="binary_data=${VAL}"
        TYPE="NOISE" # Garbage data. We don't care if it's redacted or not, as long as it doesn't crash.
    
    elif [ $RAND_TYPE -eq 6 ]; then
        # === 7. UNSTRUCTURED SECRET (The Gap) ===
        # Keyless secret in a sentence. Currently expected to FAIL (Leak) unless entropy is extremely high.
        # User example: "Error: 54.21.11.22 password123 failed"
        # We use a higher entropy secret to give it a chance, but without "key=", it's hard.
        SECRET_VAL=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
        PAYLOAD="Error: 192.168.1.5 ${SECRET_VAL} connection failed"
        TYPE="SECRET"
    fi
    
    echo "$TYPE" >> "$META_FILE"

    if (( i % 2 == 0 )); then
        echo "{\"time\": \"$TS\", \"lvl\": \"$LVL\", \"msg\": \"$MSG\", \"pl\": \"$PAYLOAD\", \"id\": 12345}" >> "$INPUT_FILE"
    else
        echo "$TS [$LVL] $MSG data=$PAYLOAD context_id=12345" >> "$INPUT_FILE"
    fi
done

# === PERFORMANCE RUN ===
INPUT_SIZE=$(wc -c < "$INPUT_FILE")

# Capture Start Time (ms)
START=$(get_time_ms)

# RUN
cat "$INPUT_FILE" | docker run -i --rm pii-shield:local > "$OUTPUT_FILE"

# Capture End Time (ms)
END=$(get_time_ms)

# Calculate Metrics
DURATION_MS=$(( END - START ))
if [ $DURATION_MS -le 0 ]; then DURATION_MS=1; fi # Avoid zero division

# Lines per second
LPS=$(( COUNT * 1000 / DURATION_MS ))
# Kilobytes per second (Approx)
KBPS=$(( INPUT_SIZE * 1000 / DURATION_MS / 1024 ))


# Analysis Logic
TP=0; TN=0; FP=0; FN=0
LC_ALL=C paste "$INPUT_FILE" "$OUTPUT_FILE" "$META_FILE" | while IFS=$'\t' read -r IN OUT EXPECTED_TYPE; do
    if [[ "$IN" != "$OUT" ]]; then CHANGED=true; else CHANGED=false; fi

    if [[ "$EXPECTED_TYPE" == "SECRET" ]]; then
        if [[ "$CHANGED" == "true" ]]; then 
            if [[ "$OUT" == *"[HIDDEN"* ]]; then ((TP++)); else ((TP++)); fi
        else
            echo -e "${RED}[LEAK] False Negative:${NC}\n   Input: $IN"
            ((FN++))
        fi
    elif [[ "$EXPECTED_TYPE" == "NOISE" ]]; then
         # NOISE: We accept redaction or no redaction. Both are fine "True Negatives" (no leaks, no crash).
         ((TN++))
    else
        # EXPECTED SAFE
        if [[ "$CHANGED" == "true" ]]; then
            if [[ "$OUT" == *"[HIDDEN"* ]]; then
                 echo -e "${YELLOW}[BROKEN] False Positive (Safe Data Redacted):${NC}\n   Input:  $IN\n   Output: $OUT"
                 ((FP++))
            else ((TN++)); fi
        else ((TN++)); fi
    fi
    echo "$TP $TN $FP $FN" > stats.tmp
done
read TP TN FP FN < stats.tmp; rm stats.tmp

echo -e "\n📊 Phase 2 Results (1000 items):"
echo -e "Accuracy: $(( (TP + TN) * 100 / COUNT ))%"
echo -e "True Positives (Secrets Caught): $TP"
echo -e "True Negatives (Safe Passed):    $TN"
echo -e "False Positives (Safe Broken):   $FP"
echo -e "False Negatives (Secrets Leaked): $FN"

# === DISPLAY METRICS ===
echo -e "\n🚀 PERFORMANCE METRICS:"
echo -e "Time Taken:     ${DURATION_MS} ms"
echo -e "Throughput:     ${GREEN}${LPS} lines/sec${NC}"
echo -e "Data Rate:      ${GREEN}${KBPS} KB/s${NC} (Docker overhead included)"

if [[ "$FN" -gt 0 || "$FP" -gt 0 ]]; then
    ((FAILURES++))
fi

# ==============================================================================
# PHASE 3: JSON Integrity Verification (jq)
# ==============================================================================
echo -e "\n${BLUE}▶️  PHASE 3: JSON Integrity Check${NC}"
grep "^{" "$OUTPUT_FILE" > json_output.log
cat json_output.log | jq . > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ JSON Integrity Check FAILED. Output contained invalid JSON.${NC}"
    head -n 5 json_output.log
    ((FAILURES++))
else
    echo -e "${GREEN}✅ JSON Integrity Check PASSED. All JSON lines valid.${NC}"
fi
rm json_output.log

# ==============================================================================
# SUMMARY
# ==============================================================================
echo -e "\n========================================"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED${NC}"
    rm "$INPUT_FILE" "$OUTPUT_FILE" "$META_FILE"
    exit 0
else
    echo -e "${RED}❌ FAILED with $FAILURES issues${NC}"
    rm "$INPUT_FILE" "$OUTPUT_FILE" "$META_FILE"
    exit 1
fi