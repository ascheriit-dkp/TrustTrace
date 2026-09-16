// Package report defines the versioned, collector-independent receipt model.
package report

import (
	"fmt"
	"sort"
	"time"
)

const SchemaVersion = 1

type Diagnostic struct {
	Code    string `json:"code"`
	Count   uint64 `json:"count"`
	Message string `json:"message"`
	Loss    bool   `json:"loss"`
}

type Event struct {
	SchemaVersion int             `json:"schema_version"`
	Type          string          `json:"type"`
	Kind          string          `json:"kind"`
	Time          time.Time       `json:"time"`
	MonotonicNS   uint64          `json:"monotonic_ns"`
	ProcessID     string          `json:"process_id"`
	ParentID      string          `json:"parent_id,omitempty"`
	PID           uint32          `json:"pid"`
	TID           uint32          `json:"tid"`
	PPID          uint32          `json:"ppid"`
	UID           uint32          `json:"uid"`
	Thread        bool            `json:"thread,omitempty"`
	Path          string          `json:"path,omitempty"`
	Path2         string          `json:"path2,omitempty"`
	Argv          []string        `json:"argv,omitempty"`
	Result        int64           `json:"result"`
	Flags         uint32          `json:"flags,omitempty"`
	OpenFlags     uint32          `json:"open_flags,omitempty"`
	Created       bool            `json:"created,omitempty"`
	Truncated     bool            `json:"truncated,omitempty"`
	Regular       bool            `json:"regular,omitempty"`
	IP            string          `json:"ip,omitempty"`
	Port          uint16          `json:"port,omitempty"`
	Protocol      string          `json:"protocol,omitempty"`
	ScopeID       uint32          `json:"scope_id,omitempty"`
	Protection    uint32          `json:"protection,omitempty"`
	MappingFlags  uint32          `json:"mapping_flags,omitempty"`
	CreateKind    string          `json:"create_kind,omitempty"`
	Hash          *ExecutableHash `json:"hash,omitempty"`
}

type Process struct {
	ID         string     `json:"id"`
	ParentID   string     `json:"parent_id,omitempty"`
	PID        uint32     `json:"pid"`
	TID        uint32     `json:"tid"`
	PPID       uint32     `json:"ppid"`
	UID        uint32     `json:"uid"`
	Thread     bool       `json:"thread"`
	Executable string     `json:"executable,omitempty"`
	Argv       []string   `json:"argv,omitempty"`
	Start      time.Time  `json:"start"`
	End        *time.Time `json:"end,omitempty"`
	DurationNS uint64     `json:"duration_ns"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	Signal     int        `json:"signal,omitempty"`
	StartNS    uint64     `json:"-"`
}

type Execution struct {
	ProcessID     string    `json:"process_id"`
	Path          string    `json:"path"`
	RequestedPath string    `json:"requested_path,omitempty"`
	Argv          []string  `json:"argv"`
	UID           uint32    `json:"uid"`
	Time          time.Time `json:"time"`
	SHA256        string    `json:"sha256,omitempty"`
}

type File struct {
	ProcessID string `json:"process_id"`
	Operation string `json:"operation"`
	Path      string `json:"path"`
	Target    string `json:"target,omitempty"`
	Flags     uint32 `json:"flags,omitempty"`
	Kind      string `json:"kind,omitempty"`
}

type Connection struct {
	ProcessID string    `json:"process_id"`
	IP        string    `json:"ip"`
	Port      uint16    `json:"port"`
	Protocol  string    `json:"protocol"`
	ScopeID   uint32    `json:"scope_id,omitempty"`
	Result    int64     `json:"result"`
	Status    string    `json:"status"`
	Time      time.Time `json:"time"`
}

type ExecutableHash struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Error  string `json:"error,omitempty"`
	Source string `json:"source"`
}

type Summary struct {
	Processes    int    `json:"processes"`
	Threads      int    `json:"threads"`
	Executions   int    `json:"executions"`
	FilesRead    int    `json:"files_read"`
	FilesCreated int    `json:"files_created"`
	FilesWritten int    `json:"files_written"`
	FilesDeleted int    `json:"files_deleted"`
	Connections  int    `json:"connections"`
	DurationNS   uint64 `json:"duration_ns"`
	ExitCode     int    `json:"exit_code"`
	Signal       int    `json:"signal"`
	Incomplete   bool   `json:"incomplete"`
}

type Report struct {
	SchemaVersion int              `json:"schema_version"`
	ToolVersion   string           `json:"tool_version"`
	Command       []string         `json:"command"`
	Start         time.Time        `json:"start"`
	End           time.Time        `json:"end"`
	Processes     []Process        `json:"processes"`
	Executions    []Execution      `json:"executions"`
	Files         []File           `json:"files"`
	Network       []Connection     `json:"network"`
	Hashes        []ExecutableHash `json:"hashes"`
	Diagnostics   []Diagnostic     `json:"diagnostics"`
	Summary       Summary          `json:"summary"`
}

// Builder retains bounded, deduplicated effects. Raw events can be streamed
// without keeping them in memory. It is owned by a single ingestion goroutine.
type Builder struct {
	Report    Report
	processes map[string]int
	files     map[File]bool
	hashes    map[string]bool
	limit     int
	retained  int
}

func New(command []string, version string, start time.Time, limit int) *Builder {
	return &Builder{Report: Report{SchemaVersion: SchemaVersion, ToolVersion: version,
		Command: append([]string{}, command...), Start: start, Processes: []Process{},
		Executions: []Execution{}, Files: []File{}, Network: []Connection{}, Hashes: []ExecutableHash{}, Diagnostics: []Diagnostic{}},
		processes: map[string]int{}, files: map[File]bool{}, hashes: map[string]bool{}, limit: limit}
}

func (b *Builder) Diagnostic(code string, count uint64, message string, loss bool) {
	if count == 0 {
		return
	}
	if loss {
		b.Report.Summary.Incomplete = true
	}
	for i := range b.Report.Diagnostics {
		if b.Report.Diagnostics[i].Code == code {
			b.Report.Diagnostics[i].Count += count
			return
		}
	}
	b.Report.Diagnostics = append(b.Report.Diagnostics, Diagnostic{code, count, message, loss})
}

func (b *Builder) reserve() bool {
	if b.retained >= b.limit {
		b.Diagnostic("report_limit", 1, "Report record limit reached; raw NDJSON events continue.", true)
		return false
	}
	b.retained++
	return true
}

func (b *Builder) file(e Event, op, path, target string, flags uint32) {
	if path == "" {
		return
	}
	f := File{ProcessID: e.ProcessID, Operation: op, Path: path, Target: target, Flags: flags}
	if op == "create" {
		f.Kind = e.CreateKind
		if f.Kind == "" {
			f.Kind = "regular"
		}
	}
	if !b.files[f] && b.reserve() {
		b.files[f] = true
		b.Report.Files = append(b.Report.Files, f)
	}
}

func (b *Builder) Add(e Event) {
	if (e.Kind == "open" || e.Kind == "read" || e.Kind == "write" || e.Kind == "delete" || e.Kind == "rename" || e.Kind == "create") && (e.Result == -13 || e.Result == -1) {
		b.Diagnostic("access_denied", 1, "A filesystem operation was denied; failed operations remain in NDJSON.", false)
	}
	idx, ok := b.processes[e.ProcessID]
	if !ok && e.ProcessID != "" {
		if !b.reserve() {
			return
		}
		if e.Kind != "fork" && e.Kind != "start" {
			b.Diagnostic("missing_process_start", 1, "An event has no observed process start.", true)
		}
		idx = len(b.Report.Processes)
		b.processes[e.ProcessID] = idx
		b.Report.Processes = append(b.Report.Processes, Process{ID: e.ProcessID, ParentID: e.ParentID, PID: e.PID, TID: e.TID, PPID: e.PPID, UID: e.UID, Thread: e.Thread, Start: e.Time, StartNS: e.MonotonicNS})
	}
	if e.ProcessID == "" {
		b.Diagnostic("uncorrelated_event", 1, "Event has no process identity.", true)
		return
	}
	p := &b.Report.Processes[idx]
	switch e.Kind {
	case "fork":
		if parent, ok := b.processes[e.ParentID]; ok {
			p.Executable = b.Report.Processes[parent].Executable
			p.Argv = append([]string{}, b.Report.Processes[parent].Argv...)
		}
	case "exec":
		p.Thread = e.Thread
		p.PID = e.PID
		p.TID = e.TID
		p.Executable = e.Path
		p.Argv = e.Argv
		p.UID = e.UID
		if b.reserve() {
			x := Execution{ProcessID: e.ProcessID, Path: e.Path, RequestedPath: e.Path2, Argv: append([]string{}, e.Argv...), UID: e.UID, Time: e.Time}
			if e.Hash != nil {
				x.SHA256 = e.Hash.SHA256
			}
			b.Report.Executions = append(b.Report.Executions, x)
		}
		if e.Hash != nil {
			key := e.Hash.Path + "\x00" + e.Hash.SHA256 + "\x00" + e.Hash.Error
			if !b.hashes[key] && b.reserve() {
				b.hashes[key] = true
				b.Report.Hashes = append(b.Report.Hashes, *e.Hash)
			}
			if e.Hash.Error != "" {
				b.Diagnostic("hash_failure", 1, "An executable could not be hashed; see hashes[].error.", true)
			}
		}
	case "exit":
		code, signal := DecodeExit(e.Result)
		p.ExitCode = &code
		p.Signal = signal
		p.End = &e.Time
		if e.MonotonicNS >= p.StartNS {
			p.DurationNS = e.MonotonicNS - p.StartNS
		}
	case "open":
		if e.Result < 0 || !e.Regular {
			return
		}
		if e.Created {
			b.file(e, "create", e.Path, "", 0)
		}
		if e.OpenFlags&3 != 1 && e.OpenFlags&0x200000 == 0 {
			b.file(e, "read", e.Path, "", 0)
		} // open for reading; exclude O_PATH
		if e.OpenFlags&0x200 != 0 {
			b.file(e, "write", e.Path, "", 0)
		} // successful O_TRUNC
	case "write":
		if e.Result > 0 || (e.Result == 0 && e.Truncated) {
			b.file(e, "write", e.Path, "", 0)
		}
	case "read":
		if e.Result > 0 {
			b.file(e, "read", e.Path, "", 0)
		}
	case "load":
		if e.Result >= 0 && e.Regular {
			b.file(e, "load", e.Path, "", e.Protection)
		}
	case "create":
		if e.Result == 0 {
			b.file(e, "create", e.Path, e.Path2, 0)
		}
	case "rename":
		if e.Result == 0 && e.Path2 != "" {
			b.file(e, "rename", e.Path, e.Path2, e.OpenFlags)
		}
	case "delete":
		if e.Result == 0 {
			b.file(e, "delete", e.Path, "", 0)
		}
	case "connect":
		if e.IP == "" {
			return
		}
		if b.reserve() {
			status := "failed"
			if e.Result == 0 {
				status = "connected"
			} else if e.Result == -115 {
				status = "in_progress"
			}
			b.Report.Network = append(b.Report.Network, Connection{e.ProcessID, e.IP, e.Port, e.Protocol, e.ScopeID, e.Result, status, e.Time})
		}
	}
}

func DecodeExit(status int64) (code, signal int) {
	signal = int(status & 0x7f)
	if signal != 0 {
		return 128 + signal, signal
	}
	return int((status >> 8) & 0xff), 0
}

func (b *Builder) Finish(end time.Time, code, signal int) Report {
	r := &b.Report
	r.End = end
	r.Summary.ExitCode = code
	r.Summary.Signal = signal
	if end.After(r.Start) {
		r.Summary.DurationNS = uint64(end.Sub(r.Start))
	}
	r.Summary.Processes = 0
	r.Summary.Threads = 0
	for _, p := range r.Processes {
		if p.Thread {
			r.Summary.Threads++
		} else {
			r.Summary.Processes++
		}
		if p.End == nil {
			b.Diagnostic("missing_process_exit", 1, "A tracked task has no observed exit.", true)
		}
	}
	r.Summary.Executions = len(r.Executions)
	r.Summary.Connections = len(r.Network)
	sets := map[string]map[string]bool{}
	for _, f := range r.Files {
		if sets[f.Operation] == nil {
			sets[f.Operation] = map[string]bool{}
		}
		sets[f.Operation][f.Path] = true
	}
	writes := map[string]bool{}
	for _, op := range []string{"create", "write"} {
		for p := range sets[op] {
			writes[p] = true
		}
	}
	r.Summary.FilesRead = len(sets["read"])
	r.Summary.FilesCreated = len(sets["create"])
	r.Summary.FilesWritten = len(writes)
	r.Summary.FilesDeleted = len(sets["delete"])
	sort.Slice(r.Files, func(i, j int) bool { a, c := r.Files[i], r.Files[j]; return fmt.Sprint(a) < fmt.Sprint(c) })
	return *r
}
