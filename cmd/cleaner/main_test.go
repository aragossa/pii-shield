package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
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
