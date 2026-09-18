package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLifecycleAndEffects(t *testing.T) {
	start := time.Unix(100, 0).UTC()
	b := New([]string{"fixture"}, "test", start, 1000)
	e := Event{Kind: "start", ProcessID: "root", PID: 10, TID: 10, Time: start, MonotonicNS: 100}
	b.Add(e)
	e.Kind = "fork"
	e.ProcessID = "child"
	e.ParentID = "root"
	e.PID = 11
	e.TID = 11
	b.Add(e)
	e.Kind = "exec"
	e.Path = "/bin/fixture"
	e.Argv = []string{"fixture"}
	b.Add(e)
	e.Kind = "open"
	e.Path = "/tmp/file"
	e.Created = true
	e.Regular = true
	e.OpenFlags = 0x241
	e.Result = 3
	b.Add(e)
	e.Kind = "write"
	e.Result = 2
	b.Add(e)
	b.Add(e)
	e.Kind = "read"
	b.Add(e)
	e.Kind = "rename"
	e.Path2 = "/tmp/new"
	e.Result = 0
	e.OpenFlags = 0
	b.Add(e)
	e.Kind = "delete"
	e.Path = "/tmp/new"
	b.Add(e)
	e.Kind = "write"
	e.Path = "/denied"
	e.Result = -13
	b.Add(e)
	e.Kind = "exit"
	e.Result = 7 << 8
	e.MonotonicNS = 200
	e.Time = start.Add(time.Nanosecond * 100)
	b.Add(e)
	e.ProcessID = "root"
	e.Result = 0
	b.Add(e)
	r := b.Finish(start.Add(time.Second), 0, 0)
	if len(r.Processes) != 2 || r.Processes[1].ParentID != "root" || *r.Processes[1].ExitCode != 7 || r.Processes[1].DurationNS != 100 {
		t.Fatalf("bad lineage: %+v", r.Processes)
	}
	if r.Summary.Incomplete || r.Summary.FilesWritten != 1 || r.Summary.FilesCreated != 1 || r.Summary.FilesRead != 1 || r.Summary.FilesDeleted != 1 {
		t.Fatalf("bad summary: %+v", r.Summary)
	}
	for _, f := range r.Files {
		if f.Path == "/denied" {
			t.Fatal("failed write became an effect")
		}
	}
	var out bytes.Buffer
	if err := JSON(&out, r); err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != 1 || decoded.Summary != r.Summary {
		t.Fatal("JSON roundtrip")
	}
}

func TestOpenExistingDoesNotMeanCreateOrWrite(t *testing.T) {
	b := New(nil, "test", time.Now(), 100)
	b.Add(Event{Kind: "start", ProcessID: "1"})
	b.Add(Event{Kind: "open", ProcessID: "1", Path: "/existing", Result: 3, OpenFlags: 0x41, Regular: true})
	if len(b.Report.Files) != 0 {
		t.Fatalf("O_CREAT on existing file invented effects: %+v", b.Report.Files)
	}
}

func TestLossAndLimits(t *testing.T) {
	b := New(nil, "test", time.Now(), 1)
	b.Add(Event{Kind: "start", ProcessID: "1"})
	b.Add(Event{Kind: "write", ProcessID: "1", Path: "/x", Result: 1})
	b.Diagnostic("ring_buffer_loss", 4, "lost", true)
	b.Diagnostic("ring_buffer_loss", 3, "lost", true)
	if !b.Report.Summary.Incomplete || len(b.Report.Files) != 0 {
		t.Fatal("loss not explicit")
	}
	if b.Report.Diagnostics[1].Count != 7 {
		t.Fatal("loss count not aggregated")
	}
}

func TestExitAndNDJSON(t *testing.T) {
	for _, tc := range []struct {
		status       int64
		code, signal int
	}{{0, 0, 0}, {42 << 8, 42, 0}, {15, 143, 15}, {9 | 128, 137, 9}} {
		code, sig := DecodeExit(tc.status)
		if code != tc.code || sig != tc.signal {
			t.Fatalf("decode %+v: %d %d", tc, code, sig)
		}
	}
	var out bytes.Buffer
	n := NewNDJSON(&out)
	if err := n.Event(Event{Kind: "exec", Path: "/test\nname"}); err != nil {
		t.Fatal(err)
	}
	if err := n.Report(New(nil, "test", time.Now(), 1).Report); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("not NDJSON: %s", out.String())
	}
	for i, line := range lines {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatal(err)
		}
		if v["schema_version"] != float64(1) {
			t.Fatal("unversioned event")
		}
		if i == 0 && v["type"] != "event" {
			t.Fatal("bad event type")
		}
	}
}

func TestTableEscapesTerminalControls(t *testing.T) {
	r := New([]string{"test"}, "test", time.Now(), 10).Report
	r.Executions = []Execution{{Path: "/tmp/\x1b[2J"}}
	var out bytes.Buffer
	if err := Table(&out, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Fatal("unescaped terminal control")
	}
	for _, s := range []string{"COMMAND", "EXECUTED", "NETWORK", "FILES WRITTEN", "FILES DELETED", "SUMMARY"} {
		if !strings.Contains(out.String(), s) {
			t.Fatal("missing " + s)
		}
	}
}
