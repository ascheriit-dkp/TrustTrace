//go:build linux

package collector

import (
	"os"
	"syscall"
	"testing"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
	"golang.org/x/sys/unix"
)

func TestHashWithoutResolvedPath(t *testing.T) {
	info, err := os.Stat("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	w := WireEvent{Inode: st.Ino, Device: uint64(unix.Major(uint64(st.Dev)))<<20 | uint64(unix.Minor(uint64(st.Dev)))}
	h := NewHasher().executable(report.Event{PID: uint32(os.Getpid())}, w)
	if h.Error != "" || len(h.SHA256) != 64 || h.Source != "proc_exe" {
		t.Fatalf("could not hash an unnamed but accessible executable: %+v", h)
	}
}
