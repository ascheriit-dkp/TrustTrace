// Package diff compares sets of behavior, excluding scheduling metadata.
package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

type Options struct {
	IncludeMetadata bool
	Ignore          func(kind, value string) bool
}

func Load(r io.Reader) (report.Report, error) {
	var v report.Report
	d := json.NewDecoder(r)
	var raw json.RawMessage
	if err := d.Decode(&raw); err != nil {
		return v, fmt.Errorf("read report: %w", err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("read report: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return v, err
	}
	for _, name := range []string{"schema_version", "tool_version", "command", "start", "end", "processes", "executions", "files", "network", "hashes", "diagnostics", "summary"} {
		if len(fields[name]) == 0 || string(fields[name]) == "null" {
			return v, fmt.Errorf("invalid report: required field %s is missing", name)
		}
	}
	if v.SchemaVersion != report.SchemaVersion {
		return v, fmt.Errorf("unsupported report schema version %d", v.SchemaVersion)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return v, fmt.Errorf("expected one JSON report")
	}
	if v.Command == nil || v.Processes == nil || v.Executions == nil || v.Files == nil || v.Network == nil || v.Hashes == nil || v.Diagnostics == nil {
		return v, fmt.Errorf("invalid report: required arrays are missing")
	}
	for _, effect := range v.Files {
		switch effect.Operation {
		case "read", "write", "create", "rename", "delete", "load":
		default:
			return v, fmt.Errorf("unknown file operation %q", effect.Operation)
		}
	}
	for _, n := range v.Network {
		switch n.Status {
		case "connected", "in_progress", "failed":
		default:
			return v, fmt.Errorf("unknown connection status %q", n.Status)
		}
	}
	return v, nil
}

func behavior(r report.Report, o Options) map[string]bool {
	s := map[string]bool{}
	add := func(k, v string) {
		if o.Ignore == nil || !o.Ignore(k, v) {
			s[k+" "+report.Display(v)] = true
		}
	}
	for _, e := range r.Executions {
		add("EXEC", e.Path)
		if e.SHA256 != "" {
			add("HASH", e.Path+" sha256:"+e.SHA256)
		}
		args, _ := json.Marshal(e.Argv)
		add("ARGV", e.Path+" "+string(args))
		add("UID", fmt.Sprintf("%s %d", e.Path, e.UID))
	}
	for _, f := range r.Files {
		switch f.Operation {
		case "read":
			add("READ", f.Path)
		case "write":
			add("WRITE", f.Path)
		case "create":
			switch f.Kind {
			case "directory":
				add("MKDIR", f.Path)
			case "hardlink":
				add("LINK", f.Path+" -> "+f.Target)
			case "symlink":
				add("SYMLINK", f.Path+" -> "+f.Target)
			case "node":
				add("MKNOD", f.Path)
			default:
				add("CREATE", f.Path)
			}
		case "delete":
			add("DELETE", f.Path)
		case "rename":
			add("RENAME", fmt.Sprintf("%s -> %s flags=%d", f.Path, f.Target, f.Flags))
		case "load":
			add("LOAD", fmt.Sprintf("%s protection=%d", f.Path, f.Flags))
		}
	}
	for _, n := range r.Network {
		add("CONNECT", fmt.Sprintf("%s %s %s result=%d", report.Endpoint(n.IP, n.Port, n.ScopeID), n.Protocol, n.Status, n.Result))
	}
	add("EXIT", fmt.Sprintf("%d signal=%d", r.Summary.ExitCode, r.Summary.Signal))
	if o.IncludeMetadata {
		encoded, _ := json.Marshal(r)
		add("METADATA", string(encoded))
	}
	return s
}

func Compare(a, b report.Report, o Options) []string {
	x, y := behavior(a, o), behavior(b, o)
	out := []string{}
	for k := range y {
		if !x[k] {
			out = append(out, "+ "+k)
		}
	}
	for k := range x {
		if !y[k] {
			out = append(out, "- "+k)
		}
	}
	sort.Strings(out)
	return out
}
