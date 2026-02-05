package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/aragossa/pii-shield/pkg/scanner"
)

func main() {
	// Use buffered input for speed
	reader := bufio.NewScanner(os.Stdin)
	
	// Optional: Increase buffer if log lines can be huge
	// buf := make([]byte, 0, 64*1024)
	// reader.Buffer(buf, 1024*1024)

	for reader.Scan() {
		text := reader.Text()
		
		// Core logic
		cleaned := scanner.ScanAndRedact(text)
		
		// Write back to Stdout for Fluentd/Logstash
		fmt.Println(cleaned)
	}

	if err := reader.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading standard input:", err)
		os.Exit(1)
	}
}