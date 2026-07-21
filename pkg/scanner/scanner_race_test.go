package scanner

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestScanner_ConcurrentDifferentConfigs proves that Scanner instances built
// with different SensitiveKeys can run concurrently, each honoring only its
// own configuration, while the package-level ScanAndRedact/UpdateConfig pair
// is simultaneously being churned on another goroutine. Run with -race: the
// engine used to read a single package-level *configState from deep inside
// the call chain, so two goroutines using different configs at once could
// observe (or corrupt) each other's snapshot. Run this test with `go test
// -race` to verify no data race is introduced by that shared engine.
func TestScanner_ConcurrentDifferentConfigs(t *testing.T) {
	savedCfg := activeCfg()
	defer UpdateConfig(savedCfg)

	const workers = 8
	const itersPerWorker = 300

	var workerWG sync.WaitGroup
	errCh := make(chan string, workers)

	for w := 0; w < workers; w++ {
		workerWG.Add(1)
		go func(id int) {
			defer workerWG.Done()

			cfg := DefaultConfig()
			myKey := fmt.Sprintf("secret%d", id)
			cfg.SensitiveKeys = []string{myKey}
			scanner := NewScanner(cfg)

			line := myKey + "=hi"
			otherKey := fmt.Sprintf("secret%d", (id+1)%workers)
			otherLine := otherKey + "=hi"

			for i := 0; i < itersPerWorker; i++ {
				if got := scanner.ScanAndRedact(line); !strings.Contains(got, "[HIDDEN") {
					select {
					case errCh <- fmt.Sprintf("worker %d: own key %q not redacted, got %q", id, myKey, got):
					default:
					}
					return
				}
				if got := scanner.ScanAndRedact(otherLine); strings.Contains(got, "[HIDDEN") {
					select {
					case errCh <- fmt.Sprintf("worker %d: other worker's key %q was wrongly redacted, got %q", id, otherKey, got):
					default:
					}
					return
				}
			}
		}(w)
	}

	// Simultaneously churn the package-level global config and call the
	// global ScanAndRedact, so the race detector also has to prove the
	// Scanners above never observe (or are observed by) this shared state.
	stop := make(chan struct{})
	var hammerWG sync.WaitGroup
	hammerWG.Add(1)
	go func() {
		defer hammerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				cfg := DefaultConfig()
				cfg.SensitiveKeys = []string{"globalkey"}
				UpdateConfig(cfg)
				ScanAndRedact("globalkey=hi")
			}
		}
	}()

	workerWG.Wait()
	close(stop)
	hammerWG.Wait()

	select {
	case msg := <-errCh:
		t.Fatal(msg)
	default:
	}
}
