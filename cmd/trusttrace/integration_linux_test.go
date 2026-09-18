//go:build linux && (amd64 || arm64)

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

func privileged(t *testing.T) {
	t.Helper()
	if os.Getenv("TRUSTTRACE_INTEGRATION") != "1" {
		t.Skip("privileged CLI integration is opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
}

func TestIntegrationCLIFormats(t *testing.T) {
	privileged(t)
	self, _ := os.Executable()
	for _, mode := range []string{"json", "ndjson"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(self, "__cli", "--output", mode, "--", "/bin/sh", "-c", "echo CHILD_STDOUT; exit 7")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			if err == nil || cmd.ProcessState.ExitCode() != 7 {
				t.Fatalf("status: %v, stderr: %s", err, &stderr)
			}
			if !strings.Contains(stderr.String(), "CHILD_STDOUT") || strings.Contains(stdout.String(), "CHILD_STDOUT\n") {
				t.Fatal("child output framing")
			}
			var r report.Report
			if mode == "json" {
				if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
					t.Fatal(err)
				}
			} else {
				lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
				if len(lines) < 3 {
					t.Fatal("missing raw events")
				}
				for i, line := range lines {
					var item struct {
						SchemaVersion int           `json:"schema_version"`
						Type          string        `json:"type"`
						Report        report.Report `json:"report"`
					}
					if err := json.Unmarshal([]byte(line), &item); err != nil {
						t.Fatal(err)
					}
					if item.SchemaVersion != 1 {
						t.Fatal("unversioned output")
					}
					if i == len(lines)-1 {
						if item.Type != "report" {
							t.Fatal("missing final receipt")
						}
						r = item.Report
					} else if item.Type != "event" {
						t.Fatal("bad event envelope")
					}
				}
			}
			if r.Summary.ExitCode != 7 || len(r.Executions) != 1 || r.Summary.Threads != 0 {
				t.Fatal(r.Summary)
			}
		})
	}
	p := filepath.Join(t.TempDir(), "report.json")
	cmd := exec.Command(self, "__cli", "--output", p, "--", "/bin/true")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("file output %v: %s", err, out)
	}
	info, err := os.Stat(p)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("file permission: %v %v", info, err)
	}
}

func TestIntegrationCtrlC(t *testing.T) {
	privileged(t)
	self, _ := os.Executable()
	cmd := exec.Command(self, "__cli", "--output", "json", "--", "/bin/sh", "-c", "echo READY >&2; while :; do :; done")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	watchdog := time.AfterFunc(90*time.Second, func() { cmd.Process.Kill() })
	defer watchdog.Stop()
	scanner := bufio.NewScanner(stderr)
	ready := false
	for scanner.Scan() {
		if scanner.Text() == "READY" {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("target did not become ready")
	}
	if err = cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	for scanner.Scan() {
	} // drain shutdown diagnostics before Wait closes pipe
	_ = cmd.Wait()
	if cmd.ProcessState.ExitCode() != 130 {
		t.Fatalf("Ctrl+C status: %d; %s", cmd.ProcessState.ExitCode(), stdout.String())
	}
	var r report.Report
	if err = json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Summary.Signal != 2 || !r.Summary.Incomplete {
		t.Fatal(r.Summary)
	}
}
