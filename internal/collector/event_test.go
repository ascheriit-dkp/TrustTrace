package collector

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWireABIAndPathNormalization(t *testing.T) {
	w := WireEvent{Kind: 6, ID: 2, ParentID: 1, TimeNS: 200}
	copy(w.Path[:], "symlink/../name")
	copy(w.Path2[:], "/new")
	// Kernel path buffers are populated backwards.
	copy(w.Argv[3][58:], "/base\x00")
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, w); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 1128 {
		t.Fatalf("wire layout drift: %d", buf.Len())
	}
	decoded, err := Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	e := decoded.Event(time.Unix(1, 0), 100)
	if e.Path != "/base/symlink/../name" || e.Path2 != "/new" || e.ParentID != "1" {
		t.Fatalf("bad normalization: %+v", e)
	}
	if _, err := Decode(buf.Bytes()[:10]); err == nil {
		t.Fatal("accepted short event")
	}
	w.Flags = flagPathLoss
	e = w.Event(time.Now(), 0)
	if e.Path != "" {
		t.Fatal("partial path treated as absolute")
	}
}

func TestNetworkDecode(t *testing.T) {
	w := WireEvent{Kind: 8, Family: 10, Port: 443, Protocol: 6, Result: -115}
	w.Address[15] = 1
	e := w.Event(time.Now(), 0)
	if e.IP != "::1" || e.Protocol != "tcp" || e.Result != -115 {
		t.Fatalf("bad endpoint %+v", e)
	}
	w.Flags = flagMemoryLoss
	if w.Event(time.Now(), 0).IP != "" {
		t.Fatal("invented address after read failure")
	}
}

func TestExecutableHashAndCacheInvalidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executable")
	h := NewHasher()
	hash := func(data string) string {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0700); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		r := h.Hash(path, "test", f, nil)
		if r.Error != "" {
			t.Fatal(r.Error)
		}
		want := fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
		if r.SHA256 != want {
			t.Fatalf("got %s, want %s", r.SHA256, want)
		}
		return r.SHA256
	}
	a := hash("one")
	b := hash("a longer replacement")
	if a == b {
		t.Fatal("stale cached hash")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if r := h.Hash(path, "test", f, func(os.FileInfo) bool { return false }); r.Error == "" {
		t.Fatal("identity mismatch accepted")
	}
}
