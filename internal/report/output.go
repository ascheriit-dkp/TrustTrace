package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

func JSON(w io.Writer, r Report) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

type NDJSON struct{ enc *json.Encoder }

func NewNDJSON(w io.Writer) *NDJSON { return &NDJSON{json.NewEncoder(w)} }
func (n *NDJSON) Event(e Event) error {
	e.SchemaVersion = SchemaVersion
	e.Type = "event"
	return n.enc.Encode(e)
}
func (n *NDJSON) Report(r Report) error {
	return n.enc.Encode(struct {
		SchemaVersion int    `json:"schema_version"`
		Type          string `json:"type"`
		Report        Report `json:"report"`
	}{SchemaVersion, "report", r})
}

// Display escapes controls, including terminal escape sequences in filenames.
func Display(s string) string {
	if strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 }) {
		return strconv.Quote(s)
	}
	return s
}

func Endpoint(ip string, port uint16, scope uint32) string {
	if scope != 0 {
		ip += "%" + strconv.FormatUint(uint64(scope), 10)
	}
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

func Table(w io.Writer, r Report) error {
	var out strings.Builder
	section := func(title string, values []string) {
		fmt.Fprintln(&out, title)
		set := map[string]bool{}
		for _, v := range values {
			if v != "" {
				set[Display(v)] = true
			}
		}
		values = values[:0]
		for v := range set {
			values = append(values, v)
		}
		sort.Strings(values)
		if len(values) == 0 {
			fmt.Fprintln(&out, "  (none observed)")
		}
		for _, v := range values {
			fmt.Fprintln(&out, "  "+v)
		}
		fmt.Fprintln(&out)
	}
	args := make([]string, len(r.Command))
	for i, v := range r.Command {
		args[i] = strconv.Quote(v)
	}
	fmt.Fprintf(&out, "COMMAND\n  %s\n\n", strings.Join(args, " "))
	execs := []string{}
	for _, e := range r.Executions {
		name := e.Path
		if name == "" {
			name = "(unresolved executable)"
		}
		execs = append(execs, name)
	}
	section("EXECUTED", execs)
	network := []string{}
	for _, c := range r.Network {
		network = append(network, fmt.Sprintf("%s %s (%s)", Endpoint(c.IP, c.Port, c.ScopeID), c.Protocol, c.Status))
	}
	section("NETWORK", network)
	writes, deletes, renames := []string{}, []string{}, []string{}
	for _, f := range r.Files {
		switch f.Operation {
		case "write", "create":
			writes = append(writes, f.Path)
		case "delete":
			deletes = append(deletes, f.Path)
		case "rename":
			renames = append(renames, f.Path+" -> "+f.Target)
		}
	}
	section("FILES WRITTEN", writes)
	section("FILES DELETED", deletes)
	if len(renames) > 0 {
		section("FILES RENAMED", renames)
	}
	s := r.Summary
	fmt.Fprintf(&out, "SUMMARY\n  processes:     %d\n  files read:    %d\n  files written: %d\n  connections:   %d\n  duration:      %.2fs\n  exit code:     %d\n", s.Processes, s.FilesRead, s.FilesWritten, s.Connections, time.Duration(s.DurationNS).Seconds(), s.ExitCode)
	if s.Signal != 0 {
		fmt.Fprintf(&out, "  signal:        %d\n", s.Signal)
	}
	if s.Incomplete {
		fmt.Fprintln(&out, "  observation:   INCOMPLETE (see diagnostics)")
	}
	_, err := io.WriteString(w, out.String())
	return err
}
