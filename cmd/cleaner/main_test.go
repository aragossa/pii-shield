package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// TestStreamPipeOnceBufferOverflow exercises the FIFO error path: a line larger
// than the scanner buffer triggers bufio.ErrTooLong, and the fail policy decides
// whether the overflow is dropped or passed through with a warning marker. The
// metricsEnabled case also covers the error-metric increment.
func TestStreamPipeOnceBufferOverflow(t *testing.T) {
	cases := []struct {
		name           string
		failPolicy     string
		metricsEnabled bool
		marker         string
	}{
		{"open", "open", false, "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]"},
		{"closed_with_metrics", "closed", true, "[PII_SHIELD_DROP: BUFFER_OVERFLOW]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

			done := make(chan error, 1)
			go func() { done <- streamPipeOnce(fifo, tc.metricsEnabled, tc.failPolicy) }()

			// A line larger than the 10MB buffer with no newline forces
			// bufio.ErrTooLong. streamPipeOnce closes the pipe on the error, so
			// the remaining bytes may fail with EPIPE.
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

			select {
			case err := <-done:
				if err != nil {
					t.Errorf("streamPipeOnce returned error on EOF: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("streamPipeOnce did not return after writer closed")
			}

			os.Stdout = oldStdout
			wOut.Close()
		})
	}
}

// TestStreamPipeOnceOpenError covers the open-failure path: a path that is not a
// readable pipe makes streamPipeOnce return an error (which readFIFO turns fatal).
func TestStreamPipeOnceOpenError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.pipe")
	if err := streamPipeOnce(missing, false, "open"); err == nil {
		t.Errorf("expected an error opening a nonexistent pipe, got nil")
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

func TestResolveMetricsPort(t *testing.T) {
	valid := []struct{ raw, want string }{
		{"", "9090"},
		{"1", "1"},
		{"8080", "8080"},
		{"65535", "65535"},
	}
	for _, tc := range valid {
		got, err := resolveMetricsPort(tc.raw)
		if err != nil {
			t.Errorf("resolveMetricsPort(%q): unexpected error: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Errorf("resolveMetricsPort(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	invalid := []string{"0", "-1", "65536", "abc", "80a", "8080 ", ":9090"}
	for _, raw := range invalid {
		if _, err := resolveMetricsPort(raw); err == nil {
			t.Errorf("resolveMetricsPort(%q): expected an error, got nil", raw)
		}
	}
}

// TestNewMetricsServerHandlers checks that the metrics server runs on its own
// mux (not the global default one) with /metrics and /healthz registered, an
// unknown path rejected, and bounded timeouts configured.
func TestNewMetricsServerHandlers(t *testing.T) {
	srv := newMetricsServer("9090")

	if srv.Addr != ":9090" {
		t.Errorf("expected Addr :9090, got %q", srv.Addr)
	}
	if srv.Handler == nil || srv.Handler == http.DefaultServeMux {
		t.Errorf("metrics server must use a dedicated mux, got %T", srv.Handler)
	}
	if srv.ReadTimeout == 0 || srv.ReadHeaderTimeout == 0 || srv.WriteTimeout == 0 {
		t.Errorf("metrics server must have bounded timeouts: read=%v readHeader=%v write=%v",
			srv.ReadTimeout, srv.ReadHeaderTimeout, srv.WriteTimeout)
	}

	cases := []struct {
		path     string
		wantCode int
		wantBody string
	}{
		{"/metrics", http.StatusOK, "go_goroutines"},
		{"/healthz", http.StatusOK, "ok"},
		{"/unknown", http.StatusNotFound, ""},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.wantCode {
			t.Errorf("GET %s: expected status %d, got %d", tc.path, tc.wantCode, rec.Code)
		}
		if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Errorf("GET %s: expected body to contain %q, got: %.200s", tc.path, tc.wantBody, rec.Body.String())
		}
	}
}

// TestMainInvalidMetricsPort covers the invalid-port path: the sidecar must
// log the config error, skip the metrics server, and keep sanitizing the
// stream (fail-open).
func TestMainInvalidMetricsPort(t *testing.T) {
	if os.Getenv("TEST_MAIN_BAD_PORT") == "1" {
		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainInvalidMetricsPort")
	cmd.Env = append(os.Environ(), "TEST_MAIN_BAD_PORT=1", "PII_METRICS_ENABLED=true", "PII_METRICS_PORT=notaport")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to get stdin pipe: %v", err)
	}
	go func() {
		_, _ = io.WriteString(stdin, "mail test@example.com here\n")
		stdin.Close()
	}()

	if err := cmd.Run(); err != nil {
		t.Fatalf("expected clean exit on invalid metrics port, got %v; stderr: %s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Invalid PII_METRICS_PORT") {
		t.Errorf("expected stderr to report the invalid port, got: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "test@example.com") {
		t.Errorf("email not redacted with metrics disabled by bad port: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "[HIDDEN:") {
		t.Errorf("expected redaction marker in output, got: %s", stdout.String())
	}
}

// TestMainMetricsSigterm covers graceful shutdown: with the metrics server up
// and stdin still open, SIGTERM must stop the sidecar cleanly (exit code 0).
func TestMainMetricsSigterm(t *testing.T) {
	if os.Getenv("TEST_MAIN_METRICS_SIGTERM") == "1" {
		main()
		os.Exit(0)
	}

	port := freePort(t)
	cmd := exec.Command(os.Args[0], "-test.run=TestMainMetricsSigterm")
	cmd.Env = append(os.Environ(), "TEST_MAIN_METRICS_SIGTERM=1", "PII_METRICS_ENABLED=true", "PII_METRICS_PORT="+port)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Keep stdin open so main stays blocked on the scanner until the signal.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to get stdin pipe: %v", err)
	}
	defer stdin.Close()

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start subprocess: %v", err)
	}

	up := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:" + port + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				up = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("metrics server never became ready; stderr: %s", stderr.String())
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM: %v", err)
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		if err != nil {
			t.Errorf("expected clean exit on SIGTERM, got %v; stderr: %s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("sidecar did not exit within 10s of SIGTERM")
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse reserved address: %v", err)
	}
	return port
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
