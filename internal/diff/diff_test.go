package diff

import (
	"strings"
	"testing"
	"time"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

func TestBehaviorIgnoresRuntimeMetadata(t *testing.T) {
	a := report.New([]string{"a"}, "test", time.Now(), 100).Report
	a.Executions = []report.Execution{{Path: "/bin/a", Argv: []string{"a"}, SHA256: "abc", ProcessID: "1"}}
	a.Files = []report.File{{Operation: "write", Path: "/x", ProcessID: "1"}, {Operation: "read", Path: "/y", ProcessID: "2"}}
	b := a
	b.Start = a.Start.Add(time.Hour)
	b.End = b.Start
	b.Summary.DurationNS = 19
	b.Executions = append([]report.Execution{}, a.Executions...)
	b.Executions[0].ProcessID = "99"
	b.Executions[0].Time = b.Start
	b.Files = []report.File{a.Files[1], a.Files[0], a.Files[0]}
	b.Files[0].ProcessID = "88"
	if changes := Compare(a, b, Options{}); len(changes) != 0 {
		t.Fatalf("metadata noise: %v", changes)
	}
	if len(Compare(a, b, Options{IncludeMetadata: true})) == 0 {
		t.Fatal("metadata opt-in ignored")
	}
	b.Executions[0].SHA256 = "def"
	b.Files = append(b.Files, report.File{Operation: "delete", Path: "/secret"})
	changes := strings.Join(Compare(a, b, Options{}), "\n")
	if !strings.Contains(changes, "+ DELETE /secret") || !strings.Contains(changes, "+ HASH /bin/a sha256:def") {
		t.Fatal(changes)
	}
	if changes := Compare(a, b, Options{Ignore: func(k, v string) bool { return k == "HASH" || k == "DELETE" }}); len(changes) != 0 {
		t.Fatal(changes)
	}
}

func TestLoadRejectsWrongSchemaAndTrailingData(t *testing.T) {
	for _, s := range []string{`{}`, `{"schema_version":2}`, `{"schema_version":1}`, `{} {}`} {
		if _, err := Load(strings.NewReader(s)); err == nil {
			t.Fatal("accepted " + s)
		}
	}
}

func TestLinkTargetsAreBehavior(t *testing.T) {
	a := report.Report{Files: []report.File{{Operation: "create", Kind: "symlink", Path: "/bin/tool", Target: "../safe"}}}
	b := report.Report{Files: []report.File{{Operation: "create", Kind: "symlink", Path: "/bin/tool", Target: "/tmp/loader"}}}
	changes := strings.Join(Compare(a, b, Options{}), "\n")
	if !strings.Contains(changes, "+ SYMLINK /bin/tool -> /tmp/loader") || !strings.Contains(changes, "- SYMLINK /bin/tool -> ../safe") {
		t.Fatal(changes)
	}
}
