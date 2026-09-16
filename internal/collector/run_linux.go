//go:build linux && (amd64 || arm64)

package collector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Keep the launch helper on its initial thread, so the map can be seeded with
// the PID before its first target exec. No user command runs before the gate.
func init() { runtime.LockOSThread() }

func LaunchHelper() int {
	if len(os.Args) < 3 {
		return 125
	}
	// Ack from userspace proves the helper's initial sched_exec has completed.
	// exec.Cmd.Start alone doesn't: its exec-error pipe may close before that
	// tracepoint fires, letting the parent seed tracking too early.
	readyPipe := os.NewFile(4, "launch-ready")
	if _, err := readyPipe.Write([]byte{1}); err != nil {
		readyPipe.Close()
		return 125
	}
	readyPipe.Close()
	gate := os.NewFile(3, "launch-gate")
	var ready [1]byte
	_, err := io.ReadFull(gate, ready[:])
	gate.Close()
	if err != nil || ready[0] != 1 {
		return 125
	}
	path, err := exec.LookPath(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "trusttrace:", err)
		return 127
	}
	if err = syscall.Exec(path, os.Args[2:], os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "trusttrace: exec:", err)
		if errors.Is(err, os.ErrNotExist) {
			return 127
		}
		return 126
	}
	return 0
}

type identity struct {
	ID, ParentID     uint64
	Active, Reserved uint32
}

type kernel struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
}

func (k *kernel) closeLinks() {
	for _, l := range k.links {
		l.Close()
	}
	k.links = nil
}
func (k *kernel) close() {
	k.closeLinks()
	if k.reader != nil {
		k.reader.Close()
	}
	if k.collection != nil {
		k.collection.Close()
	}
}

func loadKernel() (*kernel, error) {
	return loadKernelSized(nil)
}

// Size overrides are private to real-kernel exhaustion tests.
func loadKernelSized(sizes map[string]uint32) (*kernel, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("BPF memory limit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("embedded BPF object: %w", err)
	}
	for name, size := range sizes {
		spec.Maps[name].MaxEntries = size
	}
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load eBPF (requires root/CAP_BPF+CAP_PERFMON, kernel BTF and Linux 5.15+): %w", err)
	}
	k := &kernel{collection: c}
	for _, a := range []struct {
		program, name string
		raw           bool
	}{
		{"on_fork", "sched_process_fork", true}, {"on_exec", "sched_process_exec", true}, {"on_exit", "sched_process_exit", true},
		{"on_enter", "sys_enter", false}, {"on_return", "sys_exit", false},
	} {
		var l link.Link
		if a.raw {
			l, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: a.name, Program: c.Programs[a.program]})
		} else {
			l, err = link.Tracepoint("raw_syscalls", a.name, c.Programs[a.program], nil)
		}
		if err != nil {
			k.close()
			return nil, fmt.Errorf("unsupported kernel tracepoint %s: %w", a.name, err)
		}
		k.links = append(k.links, l)
	}
	k.reader, err = ringbuf.NewReader(c.Maps["events"])
	if err != nil {
		k.close()
		return nil, fmt.Errorf("BPF ring buffer: %w", err)
	}
	return k, nil
}

func monotonic() (uint64, error) {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &t); err != nil {
		return 0, err
	}
	return uint64(t.Nano()), nil
}

func tasks(m *ebpf.Map) ([]uint32, error) {
	var key uint32
	var val identity
	out := []uint32{}
	it := m.Iterate()
	for it.Next(&key, &val) {
		out = append(out, key)
		if len(out) > 16384 {
			return nil, fmt.Errorf("tracked map iteration did not converge")
		}
	}
	return out, it.Err()
}

func signalTasks(m *ebpf.Map, sig syscall.Signal) {
	tids, _ := tasks(m)
	for _, tid := range tids {
		// pidfd pins the task for signalling; it avoids signalling a replacement
		// after the handle is opened. Thread IDs that aren't leaders fail here.
		fd, err := unix.PidfdOpen(int(tid), 0)
		if err == nil {
			unix.PidfdSendSignal(fd, unix.Signal(sig), nil, 0)
			unix.Close(fd)
		}
	}
}

func foreground(stdin *os.File, pid int) func() {
	if stdin == nil {
		return func() {}
	}
	fd := int(stdin.Fd())
	old, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return func() {}
	}
	signal.Ignore(syscall.SIGTTOU)
	if unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pid) != nil {
		signal.Reset(syscall.SIGTTOU)
		return func() {}
	}
	return func() { unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, old); signal.Reset(syscall.SIGTTOU) }
}

func run(ctx context.Context, o Options) (report.Report, error) {
	if len(o.Command) == 0 {
		return report.Report{}, fmt.Errorf("missing command after --")
	}
	if err := ctx.Err(); err != nil {
		return report.Report{}, err
	}
	k, err := loadKernel()
	if err != nil {
		return report.Report{}, err
	}
	defer k.close()
	gateR, gateW, err := os.Pipe()
	if err != nil {
		return report.Report{}, err
	}
	defer gateR.Close()
	defer gateW.Close()
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return report.Report{}, err
	}
	defer readyR.Close()
	defer readyW.Close()
	self, err := os.Executable()
	if err != nil {
		return report.Report{}, err
	}
	cmd := exec.Command(self, append([]string{"__trusttrace_launch"}, o.Command...)...)
	cmd.Stdin = o.Stdin
	cmd.Stdout = o.Stdout
	cmd.Stderr = o.Stderr
	cmd.ExtraFiles = []*os.File{gateR, readyW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err = cmd.Start(); err != nil {
		return report.Report{}, fmt.Errorf("launch: %w", err)
	}
	gateR.Close()
	readyW.Close()
	if err = readyR.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return report.Report{}, err
	}
	var acknowledged [1]byte
	if _, err = io.ReadFull(readyR, acknowledged[:]); err != nil || acknowledged[0] != 1 {
		cmd.Process.Kill()
		cmd.Wait()
		return report.Report{}, fmt.Errorf("launch helper readiness failed: %v", err)
	}
	readyR.Close()
	if err = ctx.Err(); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return report.Report{}, err
	}
	defer func() { signalTasks(k.collection.Maps["tracked"], syscall.SIGKILL) }()
	pid := uint32(cmd.Process.Pid)
	baseNS, err := monotonic()
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return report.Report{}, err
	}
	baseWall := time.Now().UTC()
	b := report.New(o.Command, o.Version, baseWall, o.RecordLimit)
	if err = k.collection.Maps["tracked"].Put(pid, identity{ID: 1}); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return report.Report{}, fmt.Errorf("seed command process: %w", err)
	}
	start := report.Event{SchemaVersion: 1, Type: "event", Kind: "start", Time: baseWall, MonotonicNS: baseNS, ProcessID: "1", PID: pid, TID: pid, PPID: uint32(os.Getpid()), UID: uint32(os.Getuid())}
	b.Add(start)
	if o.Events != nil {
		if err = o.Events(start); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return report.Report{}, err
		}
	}
	restore := foreground(o.Stdin, cmd.Process.Pid)
	defer restore()
	sigch := make(chan os.Signal, 4)
	signal.Notify(sigch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigch)
	doneReading := make(chan error, 1)
	go func() {
		hasher := NewHasher()
		for {
			rec, err := k.reader.Read()
			if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
				doneReading <- nil
				return
			}
			if err != nil {
				doneReading <- err
				return
			}
			w, err := Decode(rec.RawSample)
			if err != nil {
				b.Diagnostic("event_decode", 1, err.Error(), true)
				continue
			}
			e := w.Event(baseWall, baseNS)
			if e.Flags != w.Flags {
				b.Diagnostic("invalid_text_encoding", 1, "A path or argument is not valid UTF-8 and could not be represented reliably.", true)
			}
			if e.Kind == "exec" {
				h := hasher.executable(e, w)
				e.Hash = &h
			}
			if e.Kind == "unknown" {
				b.Diagnostic("unrepresented_event", 1, "Unknown kernel event kind.", true)
			}
			b.Add(e)
			if o.Events != nil {
				if err = o.Events(e); err != nil {
					doneReading <- err
					return
				}
			}
		}
	}()
	if _, err = gateW.Write([]byte{1}); err != nil {
		cmd.Process.Kill()
	}
	gateW.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	rootDone, readerDone := false, false
	var runErr error
	var shutdownAt time.Time
	var killAt time.Time
	code, termSignal := 125, 0
	ctxDone := ctx.Done()
	stop := func(sig syscall.Signal) {
		if shutdownAt.IsZero() {
			shutdownAt = time.Now()
			signalTasks(k.collection.Maps["tracked"], sig)
		} else {
			signalTasks(k.collection.Maps["tracked"], syscall.SIGKILL)
			killAt = time.Now()
		}
	}
loop:
	for {
		select {
		case err := <-waited:
			rootDone = true
			waited = nil
			if cmd.ProcessState != nil {
				status := cmd.ProcessState.Sys().(syscall.WaitStatus)
				code, termSignal = report.DecodeExit(int64(status))
			}
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					runErr = err
				}
			}
		case s := <-sigch:
			stop(s.(syscall.Signal))
		case <-ctxDone:
			stop(syscall.SIGTERM)
			ctxDone = nil
		case err := <-doneReading:
			readerDone = true
			doneReading = nil
			if err != nil {
				runErr = fmt.Errorf("event ingestion: %w", err)
			}
			stop(syscall.SIGTERM)
		case <-ticker.C:
			live, err := tasks(k.collection.Maps["tracked"])
			if err != nil {
				runErr = fmt.Errorf("read tracked tasks: %w", err)
				stop(syscall.SIGTERM)
			}
			if rootDone && len(live) == 0 {
				break loop
			}
			if !shutdownAt.IsZero() && time.Since(shutdownAt) > o.ShutdownGrace && killAt.IsZero() {
				signalTasks(k.collection.Maps["tracked"], syscall.SIGKILL)
				killAt = time.Now()
			}
			if !killAt.IsZero() && time.Since(killAt) > o.ShutdownGrace {
				runErr = fmt.Errorf("shutdown timed out with %d tracked tasks", len(live))
				break loop
			}
		}
	}
	// Detach producers, then explicitly drain all queued records before counters.
	k.closeLinks()
	if !readerDone {
		if err := k.reader.Flush(); err != nil {
			k.reader.Close()
			runErr = err
		}
		if err := <-doneReading; err != nil {
			runErr = err
		}
	}
	if !shutdownAt.IsZero() {
		b.Diagnostic("shutdown", 1, "Tracer received a shutdown request and forwarded it to tracked processes.", true)
	}
	if runErr != nil {
		b.Diagnostic("collector_failure", 1, runErr.Error(), true)
	}
	names := []string{"ring_buffer_loss", "map_insertion_failure", "kernel_correlation_loss", "kernel_read_failure", "path_truncation", "argv_truncation", "unsupported_operation", "unsupported_abi"}
	messages := []string{"Ring buffer was full; events were lost.", "A bounded map rejected an insertion; a subtree or operation may be missing.", "Kernel syscall correlation was unavailable.", "Kernel or userspace memory could not be read.", "A path exceeded capture bounds or could not be reconstructed.", "An argument exceeded 63 bytes or an exec had more than 8 arguments.", "An observed operation is outside the collector's supported coverage; see LIMITATIONS.md.", "Compat 32-bit or x32 syscalls were omitted instead of being decoded as native syscalls."}
	for i, name := range names {
		var perCPU []uint64
		if err := k.collection.Maps["counters"].Lookup(uint32(i), &perCPU); err != nil {
			b.Diagnostic("counter_read_failure", 1, err.Error(), true)
			continue
		}
		var total uint64
		for _, n := range perCPU {
			total += n
		}
		b.Diagnostic(name, total, messages[i], true)
	}
	// A successful hash is an identity-checked post-exec observation, not a
	// guarantee about the exact instruction bytes consumed by the CPU.
	b.Diagnostic("coverage", 1, "Native 64-bit Linux syscall coverage; DNS and unconnected UDP attribution are unavailable. See docs/LIMITATIONS.md.", false)
	r := b.Finish(time.Now().UTC(), code, termSignal)
	return r, runErr
}
