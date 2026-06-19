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

	"github.com/pii-shield/pii-shield/pkg/metrics"
	"github.com/pii-shield/pii-shield/pkg/scanner"
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

		// A FIFO (pipe injection mode) cannot be followed with tail: the tail
		// library targets regular growing files and closes its Lines channel as
		// soon as it hits EOF on the empty pipe, so the sidecar exits and
		// crash-loops before any writer connects (the pod never becomes Ready).
		// Read the named pipe directly instead.
		if isNamedPipe(watchFile) {
			go func() {
				<-sigChan
				os.Exit(0)
			}()
			readFIFO(watchFile, metricsEnabled, failPolicy)
			return
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
			if err := t.Stop(); err != nil {
				log.Printf("Failed to stop tail: %v", err)
			}
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

// isNamedPipe reports whether path is a FIFO (pipe injection mode), as opposed
// to a regular file (file injection mode).
func isNamedPipe(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeNamedPipe != 0
}

// readFIFO continuously sanitizes lines read from a named pipe. Opening the FIFO
// read-only blocks until a writer connects, which keeps the sidecar running so
// the pod reaches Ready. When the writer closes the pipe (EOF) the FIFO is
// reopened to block for the next writer; the loop ends only on SIGTERM/SIGINT
// (handled by the os.Exit goroutine installed by the caller).
func readFIFO(path string, metricsEnabled bool, failPolicy string) {
	for {
		if err := streamPipeOnce(path, metricsEnabled, failPolicy); err != nil {
			log.Fatalf("Failed to open pipe %s: %v", path, err)
		}
		// Writer closed the pipe; loop to reopen and block for the next writer.
	}
}

// streamPipeOnce opens the FIFO (blocking until a writer connects), sanitizes
// every line until the writer closes the pipe (EOF), then returns. It returns a
// non-nil error only if the pipe could not be opened.
func streamPipeOnce(path string, metricsEnabled bool, failPolicy string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	buf := make([]byte, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	for sc.Scan() {
		processLine(sc.Text(), metricsEnabled, failPolicy)
	}

	if err := sc.Err(); err != nil {
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
		fmt.Fprintln(os.Stderr, "Error reading pipe:", err)
	}

	return nil
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
