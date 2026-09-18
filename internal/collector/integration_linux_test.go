//go:build linux && (amd64 || arm64)

package collector

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		if os.Args[1] == "__trusttrace_launch" {
			os.Exit(LaunchHelper())
		}
		if os.Args[1] == "__fixture" {
			os.Exit(fixture(os.Args[2:]))
		}
	}
	os.Exit(m.Run())
}

func fixture(args []string) int {
	switch args[0] {
	case "exit":
		return 7
	case "signal":
		unix.Kill(os.Getpid(), unix.SIGTERM)
		select {}
	case "wait":
		for {
			time.Sleep(time.Second)
		}
	case "child", "lineage":
		next := "grandchild"
		if args[0] == "lineage" {
			next = "child"
		}
		self, _ := os.Executable()
		if err := exec.Command(self, "__fixture", next).Run(); err != nil {
			return 11
		}
	case "grandchild":
		return 0
	case "files":
		p := filepath.Join(args[1], "created")
		renamed := filepath.Join(args[1], "renamed")
		if err := os.WriteFile(p, []byte("initial"), 0600); err != nil {
			return 12
		}
		if _, err := os.ReadFile(p); err != nil {
			return 13
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return 14
		}
		_, err = f.WriteString("modified")
		f.Close()
		if err != nil {
			return 15
		}
		if err := os.Rename(p, renamed); err != nil {
			return 16
		}
		if err := os.Remove(renamed); err != nil {
			return 17
		}
	case "network":
		c, err := net.DialTimeout("tcp", args[1], time.Second*5)
		if err != nil {
			return 18
		}
		c.Close()
	case "orphan":
		self, _ := os.Executable()
		c := exec.Command(self, "__fixture", "delayed", args[1])
		if err := c.Start(); err != nil {
			return 19
		}
	case "delayed":
		time.Sleep(time.Millisecond * 150)
		if err := os.WriteFile(args[1], []byte("descendant"), 0600); err != nil {
			return 20
		}
	case "loss":
		self, _ := os.Executable()
		long := strings.Repeat("x", 80)
		if err := exec.Command(self, "__fixture", "grandchild", long).Run(); err != nil {
			return 21
		}
	case "load":
		p := filepath.Join(args[1], "mapped-binary")
		if err := os.WriteFile(p, make([]byte, 4096), 0600); err != nil {
			return 22
		}
		f, err := os.Open(p)
		if err != nil {
			return 23
		}
		defer f.Close()
		mem, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_EXEC, unix.MAP_PRIVATE)
		if err != nil {
			return 24
		}
		if err := unix.Munmap(mem); err != nil {
			return 25
		}
	case "vector":
		p := filepath.Join(args[1], "vector")
		fd, err := unix.Open(p, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0600)
		if err != nil {
			return 27
		}
		defer unix.Close(fd)
		if _, err := unix.Pwritev(fd, [][]byte{[]byte("first"), []byte("second")}, 0); err != nil {
			return 28
		}
		if _, err := unix.Preadv(fd, [][]byte{make([]byte, 11)}, 0); err != nil {
			return 29
		}
		if err := unix.Ftruncate(fd, 2); err != nil {
			return 30
		}
	case "links":
		dir := filepath.Join(args[1], "directory")
		if err := os.Mkdir(dir, 0700); err != nil {
			return 31
		}
		source := filepath.Join(dir, "source")
		if err := os.WriteFile(source, []byte("data"), 0600); err != nil {
			return 32
		}
		if err := os.Link(source, filepath.Join(dir, "hard")); err != nil {
			return 33
		}
		if err := os.Symlink("source", filepath.Join(dir, "symbolic")); err != nil {
			return 34
		}
		fd, err := unix.Open(source, unix.O_RDONLY, 0)
		if err != nil {
			return 35
		}
		defer unix.Close(fd)
		if err := unix.Linkat(fd, "", unix.AT_FDCWD, filepath.Join(dir, "from-fd"), unix.AT_EMPTY_PATH); err != nil {
			return 36
		}
		if err := os.Chdir(dir); err != nil {
			return 37
		}
		if err := os.Rename("hard", "moved"); err != nil {
			return 38
		}
		if err := os.Remove("moved"); err != nil {
			return 39
		}
	case "empty-arg":
		self, _ := os.Executable()
		if err := exec.Command(self, "__fixture", "grandchild", "", "tail").Run(); err != nil {
			return 26
		}
	}
	return 0
}

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("TRUSTTRACE_INTEGRATION") != "1" {
		t.Skip("set TRUSTTRACE_INTEGRATION=1 to run privileged kernel tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration tests require root")
	}
}

func traceFixture(t *testing.T, args ...string) report.Report {
	t.Helper()
	requireIntegration(t)
	self, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r, err := Run(ctx, Options{Command: append([]string{self, "__fixture"}, args...), Version: "test"})
	if err != nil {
		t.Fatalf("trace: %+v", err)
	}
	if r.Summary.ExitCode != 0 {
		t.Logf("command status %d", r.Summary.ExitCode)
	}
	return r
}

func TestIntegrationSimpleLineageAndHash(t *testing.T) {
	r := traceFixture(t, "lineage")
	if r.Summary.ExitCode != 0 {
		t.Fatal(r.Summary)
	}
	if len(r.Executions) != 3 {
		t.Fatalf("executions=%d; diagnostics=%+v", len(r.Executions), r.Diagnostics)
	}
	byID := map[string]report.Process{}
	for _, p := range r.Processes {
		byID[p.ID] = p
	}
	root, child, grand := r.Executions[0], r.Executions[1], r.Executions[2]
	if byID[child.ProcessID].ParentID != root.ProcessID || byID[grand.ProcessID].ParentID != child.ProcessID {
		t.Fatalf("incorrect lineage: %+v", r.Processes)
	}
	for _, e := range r.Executions {
		if len(e.SHA256) != 64 {
			t.Fatalf("missing hash: %+v; %+v", e, r.Diagnostics)
		}
	}
	for _, p := range r.Processes {
		if p.End == nil {
			t.Fatalf("missing exit: %+v", p)
		}
	}
}

func TestIntegrationExitCodes(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		code, signal int
	}{{"grandchild", 0, 0}, {"exit", 7, 0}, {"signal", 143, 15}} {
		t.Run(tc.mode, func(t *testing.T) {
			r := traceFixture(t, tc.mode)
			if r.Summary.ExitCode != tc.code || r.Summary.Signal != tc.signal {
				t.Fatal(r.Summary)
			}
		})
	}
}

func TestIntegrationFilesAndIsolation(t *testing.T) {
	requireIntegration(t)
	dir := t.TempDir()
	unrelated := filepath.Join(dir, "unrelated")
	stop := make(chan struct{})
	done := make(chan struct{})
	defer func() { close(stop); <-done }()
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				os.WriteFile(unrelated, []byte("outside trace"), 0600)
				time.Sleep(time.Millisecond * 5)
			}
		}
	}()
	r := traceFixture(t, "files", dir)
	if r.Summary.ExitCode != 0 {
		t.Fatal(r.Summary)
	}
	seen := map[string]bool{}
	for _, f := range r.Files {
		if f.Path == unrelated {
			t.Fatal("unrelated system activity included")
		}
		if strings.HasPrefix(f.Path, dir) {
			seen[f.Operation] = true
			t.Logf("%+v", f)
		}
	}
	for _, op := range []string{"read", "create", "write", "rename", "delete"} {
		if !seen[op] {
			t.Fatalf("missing %s: %+v; diagnostics %+v", op, r.Files, r.Diagnostics)
		}
	}
}

func TestIntegrationIPv4IPv6(t *testing.T) {
	requireIntegration(t)
	for _, ip := range []string{"127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
			if err != nil {
				t.Fatalf("loopback listener: %v", err)
			}
			defer ln.Close()
			go func() {
				c, err := ln.Accept()
				if err == nil {
					c.Close()
				}
			}()
			r := traceFixture(t, "network", ln.Addr().String())
			if r.Summary.ExitCode != 0 {
				t.Fatal(r.Summary)
			}
			for _, n := range r.Network {
				if n.IP == ip && n.Protocol == "tcp" && (n.Status == "connected" || n.Status == "in_progress") {
					return
				}
			}
			t.Fatalf("connection missing: %+v; %+v", r.Network, r.Diagnostics)
		})
	}
}

func TestIntegrationDescendantOutlivesRoot(t *testing.T) {
	requireIntegration(t)
	p := filepath.Join(t.TempDir(), "orphan-file")
	r := traceFixture(t, "orphan", p)
	for _, f := range r.Files {
		if f.Path == p && f.Operation == "write" {
			return
		}
	}
	t.Fatalf("orphan lost: %+v", r.Diagnostics)
}

func TestIntegrationShutdownAndLoss(t *testing.T) {
	requireIntegration(t)
	self, _ := os.Executable()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := Run(ctx, Options{Command: []string{self, "__fixture", "wait"}, Events: func(e report.Event) error {
		if e.Kind == "exec" {
			cancel()
		}
		return nil
	}, ShutdownGrace: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Summary.Incomplete || r.Summary.ExitCode != 143 {
		t.Fatal(r.Summary)
	}
	r = traceFixture(t, "loss")
	for _, d := range r.Diagnostics {
		if d.Code == "argv_truncation" && d.Count > 0 && d.Loss {
			return
		}
	}
	t.Fatal(fmt.Sprintf("truncation was silent: %+v", r.Diagnostics))
}

func TestIntegrationKernelLossCounters(t *testing.T) {
	requireIntegration(t)
	k, err := loadKernelSized(map[string]uint32{"events": 4096, "tracked": 1, "pending": 1})
	if err != nil {
		t.Fatal(err)
	}
	defer k.close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uint32(unix.Gettid())
	if err := k.collection.Maps["tracked"].Put(tid, identity{ID: 1, Active: 1}); err != nil {
		t.Fatal(err)
	}
	defer k.collection.Maps["tracked"].Delete(tid)
	// Fill the pending map, then make a real syscall that needs correlation.
	if err := k.collection.Maps["pending"].Put(uint32(0), WireEvent{}); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open("/proc/self/stat", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	if err := k.collection.Maps["pending"].Delete(uint32(0)); err != nil {
		t.Fatal(err)
	}
	// With no reader and a one-page ring, real open events must exhaust it.
	for i := 0; i < 32; i++ {
		fd, err := unix.Open("/proc/self/stat", unix.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		unix.Close(fd)
	}
	for _, key := range []uint32{0, 1} {
		var values []uint64
		if err := k.collection.Maps["counters"].Lookup(key, &values); err != nil {
			t.Fatal(err)
		}
		var total uint64
		for _, v := range values {
			total += v
		}
		if total == 0 {
			t.Fatalf("loss counter %d did not increase", key)
		}
		t.Logf("kernel counter %d: %d", key, total)
	}
}

func TestIntegrationExecutableMappingAndEmptyArg(t *testing.T) {
	requireIntegration(t)
	dir := t.TempDir()
	r := traceFixture(t, "load", dir)
	if r.Summary.ExitCode != 0 {
		t.Fatal(r.Summary)
	}
	loaded := false
	for _, f := range r.Files {
		if f.Operation == "load" && f.Path == filepath.Join(dir, "mapped-binary") {
			loaded = true
		}
	}
	if !loaded {
		t.Fatalf("executable file mapping was not captured: %+v", r.Diagnostics)
	}
	r = traceFixture(t, "empty-arg")
	for _, e := range r.Executions {
		if len(e.Argv) == 5 && e.Argv[3] == "" && e.Argv[4] == "tail" {
			return
		}
	}
	t.Fatalf("empty argv element lost: %+v", r.Executions)
}

func TestIntegrationVectoredIO(t *testing.T) {
	requireIntegration(t)
	dir := t.TempDir()
	r := traceFixture(t, "vector", dir)
	if r.Summary.ExitCode != 0 {
		t.Fatal(r.Summary)
	}
	seen := map[string]bool{}
	for _, f := range r.Files {
		if f.Path == filepath.Join(dir, "vector") {
			seen[f.Operation] = true
		}
	}
	if !seen["write"] || !seen["read"] || !seen["create"] {
		t.Fatalf("vectored I/O missing: %+v", r.Files)
	}
}

func TestIntegrationCompatABI(t *testing.T) {
	requireIntegration(t)
	if runtime.GOARCH != "amd64" {
		t.Skip("i386 fixture is specific to amd64")
	}
	path := os.Getenv("TRUSTTRACE_COMPAT_FIXTURE")
	if path == "" {
		t.Skip("set TRUSTTRACE_COMPAT_FIXTURE to a built testdata/compat32.S fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r, err := Run(ctx, Options{Command: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.ExitCode == 126 {
		t.Skip("kernel cannot execute i386 fixture")
	}
	if r.Summary.ExitCode != 0 || !r.Summary.Incomplete {
		t.Fatal(r.Summary)
	}
	for _, d := range r.Diagnostics {
		if d.Code == "unsupported_abi" && d.Count >= 2 {
			return
		}
	}
	t.Fatalf("compat ABI not diagnosed: %+v", r.Diagnostics)
}

func TestIntegrationLinksDirectoriesAndRelativePaths(t *testing.T) {
	requireIntegration(t)
	dir := t.TempDir()
	r := traceFixture(t, "links", dir)
	if r.Summary.ExitCode != 0 {
		t.Fatal(r.Summary)
	}
	base := filepath.Join(dir, "directory")
	seen := map[string]bool{}
	for _, f := range r.Files {
		if f.Operation == "create" && f.Path == base && f.Kind == "directory" {
			seen["directory"] = true
		}
		if f.Operation == "create" && f.Path == filepath.Join(base, "hard") && f.Kind == "hardlink" && f.Target == filepath.Join(base, "source") {
			seen["hard"] = true
		}
		if f.Operation == "create" && f.Path == filepath.Join(base, "symbolic") && f.Kind == "symlink" && f.Target == "source" {
			seen["symbolic"] = true
		}
		if f.Operation == "create" && f.Path == filepath.Join(base, "from-fd") && f.Target == filepath.Join(base, "source") {
			seen["from-fd"] = true
		}
		if f.Operation == "rename" && f.Path == filepath.Join(base, "hard") && f.Target == filepath.Join(base, "moved") {
			seen["relative-rename"] = true
		}
		if f.Operation == "delete" && f.Path == filepath.Join(base, "moved") {
			seen["relative-delete"] = true
		}
	}
	for _, key := range []string{"directory", "hard", "symbolic", "from-fd", "relative-rename", "relative-delete"} {
		if !seen[key] {
			t.Fatalf("missing %s: %+v; %+v", key, r.Files, r.Diagnostics)
		}
	}
}
