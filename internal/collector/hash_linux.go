//go:build linux

package collector

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
	"golang.org/x/sys/unix"
)

func sameVersion(a, b os.FileInfo) bool {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && os.SameFile(a, b) && a.Size() == b.Size() && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func (h *Hasher) executable(e report.Event, w WireEvent) report.ExecutableHash {
	r := report.ExecutableHash{Path: e.Path, Source: "unavailable"}
	if w.Inode == 0 {
		r.Error = "kernel executable identity unavailable"
		return r
	}
	verify := func(info os.FileInfo) bool {
		st, ok := info.Sys().(*syscall.Stat_t)
		return ok && st.Ino == w.Inode && unix.Major(uint64(st.Dev)) == uint32(w.Device>>20) && unix.Minor(uint64(st.Dev)) == uint32(w.Device&0xfffff)
	}
	candidates := []struct{ path, source string }{
		{fmt.Sprintf("/proc/%d/exe", e.PID), "proc_exe"},
	}
	if e.Path != "" {
		candidates = append(candidates, struct{ path, source string }{fmt.Sprintf("/proc/%d/root%s", e.PID, e.Path), "proc_root"}, struct{ path, source string }{e.Path, "path_after_exec"})
	}
	for _, c := range candidates {
		if !strings.HasPrefix(c.path, "/") {
			continue
		}
		fd, err := unix.Open(c.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			r.Error = err.Error()
			continue
		}
		f := os.NewFile(uintptr(fd), c.path)
		result := h.Hash(e.Path, c.source, f, verify)
		f.Close()
		if result.Error == "" {
			return result
		}
		r = result
	}
	return r
}
