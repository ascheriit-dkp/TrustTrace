package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ascheriit-dkp/TrustTrace/internal/collector"
	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		if os.Args[1] == "__trusttrace_launch" {
			os.Exit(collector.LaunchHelper())
		}
		if os.Args[1] == "__cli" {
			os.Exit(run(os.Args[2:], os.Stdout, os.Stderr))
		}
	}
	os.Exit(m.Run())
}

func TestCLIUsageVersionAndDiff(t *testing.T) {
	for _, args := range [][]string{nil, {"/bin/true"}, {"--output", "bad", "--", "true"}, {"diff"}} {
		var out, errout bytes.Buffer
		if code := run(args, &out, &errout); code != 2 {
			t.Fatalf("args %v: %d", args, code)
		}
	}
	var out, errout bytes.Buffer
	if code := run([]string{"--version"}, &out, &errout); code != 0 || !strings.Contains(out.String(), "trusttrace") {
		t.Fatal("version failed")
	}
	r := report.New([]string{"true"}, "test", time.Now(), 10).Report
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	write := func(path string) {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := report.JSON(f, r); err != nil {
			t.Fatal(err)
		}
	}
	write(a)
	r.Start = r.Start.Add(time.Hour)
	write(b)
	out.Reset()
	errout.Reset()
	if code := run([]string{"diff", a, b}, &out, &errout); code != 0 || out.Len() != 0 {
		t.Fatalf("diff: %d %s %s", code, &out, &errout)
	}
	r.Files = append(r.Files, report.File{Operation: "write", Path: "/new", ProcessID: "1"})
	write(b)
	if code := run([]string{"diff", a, b}, &out, &errout); code != 1 || !strings.Contains(out.String(), "+ WRITE /new") {
		t.Fatal("missing diff")
	}
}

func TestExistingReportIsNotOverwritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(p, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if code := run([]string{"--output", p, "--", "true"}, &out, &errout); code != 125 {
		t.Fatal(code)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "keep" {
		t.Fatal("overwrote existing receipt")
	}
}
