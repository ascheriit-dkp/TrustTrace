//go:build !linux

package collector

import "os"

func sameVersion(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime() == b.ModTime()
}
