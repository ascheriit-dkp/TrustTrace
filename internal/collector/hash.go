package collector

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

type cachedHash struct {
	info   os.FileInfo
	digest string
}
type Hasher struct{ cache map[string]cachedHash }

func NewHasher() *Hasher { return &Hasher{cache: map[string]cachedHash{}} }

// Hash checks file identity before using the cache and again after reading.
// It hashes the opened file, never a path reopened during the read.
func (h *Hasher) Hash(path, source string, f *os.File, verify func(os.FileInfo) bool) report.ExecutableHash {
	r := report.ExecutableHash{Path: path, Source: source}
	before, err := f.Stat()
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if !before.Mode().IsRegular() {
		r.Error = "executable is not a regular file"
		return r
	}
	if verify != nil && !verify(before) {
		r.Error = "file identity differs from executable observed in kernel"
		return r
	}
	if c, ok := h.cache[path]; ok && sameVersion(c.info, before) {
		r.SHA256 = c.digest
		return r
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, f); err != nil {
		r.Error = err.Error()
		return r
	}
	after, err := f.Stat()
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if !sameVersion(before, after) {
		r.Error = "executable changed while hashing"
		return r
	}
	r.SHA256 = fmt.Sprintf("%x", digest.Sum(nil))
	// Keep the hash cache bounded independently of report retention.
	if len(h.cache) < 16384 {
		h.cache[path] = cachedHash{after, r.SHA256}
	}
	return r
}
