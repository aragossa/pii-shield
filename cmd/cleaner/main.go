package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nxadm/tail"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aragossa/pii-shield/pkg/metrics"
	"github.com/aragossa/pii-shield/pkg/scanner"
)

func main() {
	metricsEnabled := os.Getenv("PII_METRICS_ENABLED") == "true"
	if metricsEnabled {
		port := os.Getenv("PII_METRICS_PORT")
		if port == "" {
			port = "9090"
		}
		
		// Wire metrics callback
		scanner.RedactionCallback = metrics.IncrementRedaction

		go func() {
			http.Handle("/metrics", promhttp.Handler())
			log.Printf("Starting Prometheus metrics server on :%s", port)
			if err := http.ListenAndServe(":"+port, nil); err != nil {
				log.Printf("Metrics server failed: %v", err)
			}
		}()
	}

	failPolicy := os.Getenv("PII_FAIL_POLICY")
	if failPolicy == "" {
		failPolicy = "open" // Start with fail-open by default 
	}

	var watchFile string
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--watch-file" && i+1 < len(os.Args) {
			watchFile = os.Args[i+1]
			break
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	if watchFile != "" {
		// Smart wait: poll until the target file is created by the main container
		for {
			if _, err := os.Stat(watchFile); err == nil {
				break
			}
			select {
			case <-sigChan:
				os.Exit(0)
			case <-time.After(500 * time.Millisecond):
			}
		}

		// Pipe injection mode points --watch-file at a named pipe (FIFO). The
		// tail library does not stay attached to a FIFO: it hits EOF, closes its
		// Lines channel and we exit, which crash-loops the native sidecar so the
		// pod never becomes Ready. Read the FIFO directly instead — each open
		// blocks until a writer appears and read returns EOF when all writers
		// close, so reopening in a loop keeps the agent alive across writers.
		if info, err := os.Stat(watchFile); err == nil && info.Mode()&os.ModeNamedPipe != 0 {
			go func() {
				<-sigChan
				os.Exit(0)
			}()
			for {
				f, err := os.Open(watchFile) // blocks until a writer opens the FIFO
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error opening pipe:", err)
					time.Sleep(500 * time.Millisecond)
					continue
				}
				scan := bufio.NewScanner(f)
				buf := make([]byte, 1024*1024)
				scan.Buffer(buf, 10*1024*1024)
				for scan.Scan() {
					processLine(scan.Text(), metricsEnabled, failPolicy)
				}
				f.Close()
			}
		}

		t, err := tail.TailFile(watchFile, tail.Config{
			Follow:    true,
			ReOpen:    true,
			MustExist: true,
			Logger:    tail.DiscardingLogger,
		})
		if err != nil {
			log.Fatalf("Failed to tail file: %v", err)
		}

		go func() {
			<-sigChan
			t.Stop()
		}()

		for line := range t.Lines {
			if line.Err != nil {
				continue
			}
			processLine(line.Text, metricsEnabled, failPolicy)
		}
	} else {
		// Legacy Stdin mode
		reader := bufio.NewScanner(os.Stdin)
		buf := make([]byte, 1024*1024)
		reader.Buffer(buf, 10*1024*1024)

		go func() {
			<-sigChan
			os.Exit(0)
		}()

		for reader.Scan() {
			processLine(reader.Text(), metricsEnabled, failPolicy)
		}

		if err := reader.Err(); err != nil {
			if metricsEnabled {
				metrics.ErrorsTotal.Inc()
			}
			if err == bufio.ErrTooLong {
				if failPolicy == "closed" {
					fmt.Println("[PII_SHIELD_DROP: BUFFER_OVERFLOW]")
				} else {
					fmt.Println("[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]")
				}
			}
			fmt.Fprintln(os.Stderr, "Error reading standard input:", err)
			os.Exit(1)
		}
	}
}

func processLine(text string, metricsEnabled bool, failPolicy string) {
	// Functional wrapper to catch panics per-line
	func() {
		defer func() {
			if r := recover(); r != nil {
				if metricsEnabled {
					metrics.ErrorsTotal.Inc()
				}
				// Apply Blast Radius Control Policy
				if failPolicy == "closed" {
					fmt.Println("[PII_SHIELD_DROP: FATAL_ERROR]")
				} else {
					// Fail-Open: keep the flow alive 
					fmt.Println(text)
				}
			}
		}()

		var start time.Time
		if metricsEnabled {
			start = time.Now()
			metrics.ProcessedBytesTotal.Add(float64(len(text)))
		}

		// Core logic
		cleaned := scanner.ScanAndRedact(text)

		if metricsEnabled {
			metrics.ProcessingDuration.Observe(time.Since(start).Seconds())
		}

		// Write back to Stdout for Fluentd/Logstash
		fmt.Println(cleaned)
	}()
}
