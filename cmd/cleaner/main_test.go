package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMainSuccess(t *testing.T) {
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	rStdin, wStdin, _ := os.Pipe()
	rStdout, wStdout, _ := os.Pipe()

	os.Stdin = rStdin
	os.Stdout = wStdout

	input := "hello test@example.com world\nline 2\n"
	go func() {
		wStdin.Write([]byte(input))
		wStdin.Close()
	}()

	done := make(chan struct{})
	go func() {
		main()
		wStdout.Close()
		close(done)
	}()

	<-done

	var buf bytes.Buffer
	io.Copy(&buf, rStdout)
	output := buf.String()

	if len(output) == 0 {
		t.Errorf("expected output, got empty")
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

// TestReadFIFO covers pipe injection mode: the sidecar reads a FIFO that has no
// writer until the app connects. Regression guard for the bug where tail.TailFile
// exited immediately on the empty pipe and crash-looped the sidecar. readFIFO must
// block until a writer connects, redact what it reads, and reopen after EOF so a
// second writer is still processed.
func TestReadFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "log.pipe")
	if err := syscall.Mkfifo(fifo, 0o666); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut
	defer func() { os.Stdout = oldStdout }()

	// Collect sanitized stdout lines as readFIFO emits them.
	outCh := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(rOut)
		for sc.Scan() {
			outCh <- sc.Text()
		}
		close(outCh)
	}()

	go readFIFO(fifo, false, "open")

	writeLine := func(s string) {
		w, err := os.OpenFile(fifo, os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			t.Fatalf("open pipe for write: %v", err)
		}
		if _, err := io.WriteString(w, s); err != nil {
			t.Fatalf("write pipe: %v", err)
		}
		w.Close()
	}
	nextLine := func() string {
		select {
		case line := <-outCh:
			return line
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for sanitized line from FIFO")
			return ""
		}
	}

	// First writer; reading its sanitized line back confirms readFIFO blocked on
	// the empty pipe until a writer connected, then processed the input.
	writeLine("contact john.doe@example.com now\n")
	line1 := nextLine()
	if strings.Contains(line1, "john.doe@example.com") {
		t.Errorf("email not redacted in FIFO output: %q", line1)
	}
	if !strings.Contains(line1, "[HIDDEN:") {
		t.Errorf("expected redaction marker in FIFO output, got: %q", line1)
	}

	// First writer has closed (EOF). A second writer must still be served, which
	// only works if readFIFO reopened the pipe after EOF instead of exiting.
	writeLine("second line ok\n")
	line2 := nextLine()
	if !strings.Contains(line2, "second line ok") {
		t.Errorf("second writer not processed; FIFO not reopened after EOF: %q", line2)
	}

	os.Stdout = oldStdout
	wOut.Close()
}

func TestIsNamedPipe(t *testing.T) {
	dir := t.TempDir()

	fifo := filepath.Join(dir, "log.pipe")
	if err := syscall.Mkfifo(fifo, 0o666); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if !isNamedPipe(fifo) {
		t.Errorf("expected %s to be detected as a named pipe", fifo)
	}

	regular := filepath.Join(dir, "log.txt")
	if err := os.WriteFile(regular, []byte("data\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if isNamedPipe(regular) {
		t.Errorf("expected %s to be detected as a regular file, not a pipe", regular)
	}

	if isNamedPipe(filepath.Join(dir, "missing")) {
		t.Errorf("expected a missing path to not be detected as a pipe")
	}
}

// TestReadFIFOBufferOverflow exercises the FIFO error path: a line larger than
// the scanner buffer triggers bufio.ErrTooLong, and the fail policy decides
// whether the overflow is dropped or passed through with a warning marker.
func TestReadFIFOBufferOverflow(t *testing.T) {
	cases := []struct {
		failPolicy string
		marker     string
	}{
		{"open", "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]"},
		{"closed", "[PII_SHIELD_DROP: BUFFER_OVERFLOW]"},
	}

	for _, tc := range cases {
		t.Run(tc.failPolicy, func(t *testing.T) {
			dir := t.TempDir()
			fifo := filepath.Join(dir, "log.pipe")
			if err := syscall.Mkfifo(fifo, 0o666); err != nil {
				t.Fatalf("mkfifo: %v", err)
			}

			oldStdout := os.Stdout
			rOut, wOut, _ := os.Pipe()
			os.Stdout = wOut
			defer func() { os.Stdout = oldStdout }()

			outCh := make(chan string, 8)
			go func() {
				sc := bufio.NewScanner(rOut)
				sc.Buffer(make([]byte, 1024*1024), 20*1024*1024)
				for sc.Scan() {
					outCh <- sc.Text()
				}
				close(outCh)
			}()

			go readFIFO(fifo, false, tc.failPolicy)

			// A line larger than readFIFO's 10MB buffer with no newline forces
			// bufio.ErrTooLong. Write from a goroutine: readFIFO closes the pipe
			// on the error, so the remaining bytes may fail with EPIPE.
			go func() {
				w, err := os.OpenFile(fifo, os.O_WRONLY, os.ModeNamedPipe)
				if err != nil {
					return
				}
				_, _ = io.WriteString(w, strings.Repeat("A", 10*1024*1024+1))
				_ = w.Close()
			}()

			select {
			case line := <-outCh:
				if !strings.Contains(line, tc.marker) {
					t.Errorf("expected overflow marker %q, got: %q", tc.marker, line)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("timed out waiting for buffer-overflow marker from FIFO")
			}

			os.Stdout = oldStdout
			wOut.Close()
		})
	}
}

func TestMainScannerError(t *testing.T) {
	if os.Getenv("TEST_MAIN_ERROR") == "1" {
		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainScannerError")
	cmd.Env = append(os.Environ(), "TEST_MAIN_ERROR=1")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to get stdin pipe: %v", err)
	}

	go func() {
		defer stdin.Close()
		// Default bufio.Scanner max token size is 64KB initially, bufio.ErrTooLong will be returned
		// if a token without newline exceeds 64KB (bufio.MaxScanTokenSize)
		longLine := strings.Repeat("A", 10*1024*1024+1)
		stdin.Write([]byte(longLine))
	}()

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			t.Fatalf("cmd.Run failed: %v", err)
		}
	}

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for scanner error, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "Error reading standard input:") {
		t.Errorf("expected stderr to contain 'Error reading standard input:', got: %s", stderr.String())
	}
}

func TestMainBufferOverflowFailOpen(t *testing.T) {
	stdout, stderr, exitCode := runMainWithLongLine(t, "open")

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for scanner error, got %d", exitCode)
	}
	if !strings.Contains(stdout, "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]") {
		t.Errorf("expected fail-open overflow warning marker, got stdout: %s", stdout)
	}
	if !strings.Contains(stderr, "Error reading standard input:") {
		t.Errorf("expected stderr to contain scanner error, got: %s", stderr)
	}
}

func TestMainBufferOverflowFailClosed(t *testing.T) {
	stdout, stderr, exitCode := runMainWithLongLine(t, "closed")

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for scanner error, got %d", exitCode)
	}
	if !strings.Contains(stdout, "[PII_SHIELD_DROP: BUFFER_OVERFLOW]") {
		t.Errorf("expected fail-closed overflow drop marker, got stdout: %s", stdout)
	}
	if !strings.Contains(stderr, "Error reading standard input:") {
		t.Errorf("expected stderr to contain scanner error, got: %s", stderr)
	}
}

func runMainWithLongLine(t *testing.T, failPolicy string) (string, string, int) {
	t.Helper()

	if os.Getenv("TEST_MAIN_LONG_LINE") == "1" {
		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainBufferOverflow")
	cmd.Env = append(os.Environ(), "TEST_MAIN_LONG_LINE=1", "PII_FAIL_POLICY="+failPolicy)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to get stdin pipe: %v", err)
	}

	go func() {
		defer stdin.Close()
		longLine := strings.Repeat("A", 10*1024*1024+1)
		_, _ = stdin.Write([]byte(longLine))
	}()

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			t.Fatalf("cmd.Run failed: %v", err)
		}
	}

	return stdout.String(), stderr.String(), exitCode
}
