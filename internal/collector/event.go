package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"path"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

const (
	flagPathLoss       = 1
	flagArgvLoss       = 2
	flagMemoryLoss     = 4
	flagThread         = 8
	flagCreated        = 16
	flagRegular        = 32
	flagSecondPathLoss = 64
)

// WireEvent matches bpf/types.h exactly; decoding rejects ABI drift.
type WireEvent struct {
	TimeNS, ID, ParentID             uint64
	Result                           int64
	PID, TID, PPID, UID, Kind, Flags uint32
	Aux, Reserved                    uint32
	Path, Path2                      [256]byte
	Argv                             [8][64]byte
	Address                          [16]byte
	Port, Family                     uint16
	Protocol                         uint32
	Inode, Device                    uint64
}

func Decode(data []byte) (WireEvent, error) {
	var e WireEvent
	if len(data) != binary.Size(e) {
		return e, fmt.Errorf("event ABI: got %d bytes, expected %d", len(data), binary.Size(e))
	}
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e)
	return e, err
}

func cstring(b []byte) string {
	if n := bytes.IndexByte(b, 0); n >= 0 {
		b = b[:n]
	}
	return string(b)
}
func kernelPath(b []byte) string { return cstring(bytes.TrimLeft(b, "\x00")) }

func (w WireEvent) Event(baseWall time.Time, baseNS uint64) report.Event {
	kinds := []string{"unknown", "fork", "exec", "exit", "open", "write", "rename", "delete", "connect", "read", "unsupported", "load", "create"}
	kind := "unknown"
	if int(w.Kind) < len(kinds) {
		kind = kinds[w.Kind]
	}
	e := report.Event{SchemaVersion: report.SchemaVersion, Type: "event", Kind: kind, Time: baseWall.Add(time.Duration(int64(w.TimeNS) - int64(baseNS))), MonotonicNS: w.TimeNS,
		ProcessID: strconv.FormatUint(w.ID, 16), PID: w.PID, TID: w.TID, PPID: w.PPID, UID: w.UID, Thread: w.Flags&flagThread != 0,
		Result: w.Result, Flags: w.Flags, OpenFlags: w.Aux, Created: w.Flags&flagCreated != 0, Regular: w.Flags&flagRegular != 0}
	if w.ParentID != 0 {
		e.ParentID = strconv.FormatUint(w.ParentID, 16)
	}
	if w.Flags&flagPathLoss == 0 {
		e.Path = kernelPath(w.Path[:])
	}
	if w.Flags&flagSecondPathLoss == 0 {
		e.Path2 = kernelPath(w.Path2[:])
	}
	if kind == "exec" {
		for i, a := range w.Argv {
			if uint32(i) >= w.Reserved {
				break
			}
			s := cstring(a[:])
			e.Argv = append(e.Argv, s)
		}
	}
	if kind == "create" {
		switch w.Aux {
		case 1:
			e.CreateKind = "directory"
		case 2:
			e.CreateKind = "hardlink"
		case 3:
			e.CreateKind = "symlink"
		case 4:
			e.CreateKind = "node"
		}
	}
	if kind == "rename" || kind == "delete" || kind == "create" || (kind == "open" && w.Result < 0) || (kind == "write" && w.Aux == 1 && w.Flags&flagRegular == 0) {
		var bases []byte
		for _, a := range w.Argv {
			bases = append(bases, a[:]...)
		}
		normalize := func(p, base string) string {
			if p == "" {
				return ""
			}
			if !path.IsAbs(p) {
				if !path.IsAbs(base) {
					return ""
				}
				p = base + "/" + p
			}
			// Preserve '..' and symlink-sensitive spelling. Lexical cleaning can
			// change the meaning of paths traversing symlinks.
			return p
		}
		e.Path = normalize(e.Path, kernelPath(bases[:256]))
		if e.CreateKind != "symlink" {
			e.Path2 = normalize(e.Path2, kernelPath(bases[256:]))
		}
	}
	e.Truncated = kind == "write" && w.Aux == 1
	if kind == "load" {
		e.Protection = w.Aux
		e.MappingFlags = w.Reserved
	}
	if kind == "connect" && w.Flags&flagMemoryLoss == 0 {
		if w.Family == 2 {
			e.IP = net.IP(w.Address[:4]).String()
		} else if w.Family == 10 {
			e.IP = net.IP(w.Address[:]).String()
		}
		e.Port = w.Port
		e.ScopeID = w.Aux
		switch w.Protocol {
		case 6:
			e.Protocol = "tcp"
		case 17:
			e.Protocol = "udp"
		case 0:
			e.Protocol = "unknown"
		default:
			e.Protocol = fmt.Sprintf("ipproto:%d", w.Protocol)
		}
	}
	// Irrelevant union members must not leak path-base bytes into the schema.
	if kind != "exec" && kind != "rename" && kind != "create" {
		e.Path2 = ""
	}
	if kind != "open" && kind != "rename" && kind != "unsupported" {
		e.OpenFlags = 0
	}
	if !utf8.ValidString(e.Path) {
		e.Path = ""
		e.Flags |= flagPathLoss
	}
	if !utf8.ValidString(e.Path2) {
		e.Path2 = ""
		e.Flags |= flagSecondPathLoss
	}
	for i, a := range e.Argv {
		if !utf8.ValidString(a) {
			e.Argv[i] = ""
			e.Flags |= flagMemoryLoss
		}
	}
	return e
}
