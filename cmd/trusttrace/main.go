package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ascheriit-dkp/TrustTrace/internal/collector"
	"github.com/ascheriit-dkp/TrustTrace/internal/diff"
	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

var version = "dev"
var commit = "unknown"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__trusttrace_launch" {
		os.Exit(collector.LaunchHelper())
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `trusttrace - run a command and record its effects

Usage:
  trusttrace [--output table|json|ndjson|FILE.json] -- COMMAND [ARGS...]
  trusttrace diff [--include-metadata] FIRST.json SECOND.json
  trusttrace --version

Tracing requires Linux amd64/arm64, kernel BTF, and eBPF privileges.
In json/ndjson modes, the command's stdout is redirected to stderr.
Report files are created with mode 0600 and must not already exist.
`

func run(args []string, out, errout io.Writer) int {
	if len(args) > 0 && args[0] == "diff" {
		return runDiff(args[1:], out, errout)
	}
	f := flag.NewFlagSet("trusttrace", flag.ContinueOnError)
	f.SetOutput(errout)
	output := f.String("output", "table", "table, json, ndjson, or a new .json file")
	showVersion := f.Bool("version", false, "print version")
	f.Usage = func() { fmt.Fprint(errout, usage) }
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintf(out, "trusttrace %s (%s)\n", version, commit)
		return 0
	}
	command := f.Args()
	separator := false
	for _, a := range args {
		if a == "--" {
			separator = true
			break
		}
	}
	if !separator || len(command) == 0 {
		fmt.Fprint(errout, usage)
		return 2
	}
	var file *os.File
	if *output != "table" && *output != "json" && *output != "ndjson" {
		if !strings.HasSuffix(*output, ".json") {
			fmt.Fprintln(errout, "trusttrace: output must be table, json, ndjson, or a .json filename")
			return 2
		}
		var err error
		file, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintln(errout, "trusttrace: report file:", err)
			return 125
		}
		defer file.Close()
	}
	childOut := out
	var stream *report.NDJSON
	opts := collector.Options{Command: command, Version: version, Stdin: os.Stdin, Stdout: childOut, Stderr: errout}
	if *output == "json" || *output == "ndjson" {
		opts.Stdout = errout
	}
	if *output == "ndjson" {
		stream = report.NewNDJSON(out)
		opts.Events = stream.Event
	}
	r, traceErr := collector.Run(context.Background(), opts)
	if r.SchemaVersion == 0 {
		if file != nil {
			file.Close()
			os.Remove(*output)
		}
		fmt.Fprintln(errout, "trusttrace:", traceErr)
		return 125
	}
	for _, d := range r.Diagnostics {
		if d.Code != "coverage" {
			fmt.Fprintf(errout, "trusttrace: %s (%d): %s\n", d.Code, d.Count, d.Message)
		}
	}
	var err error
	switch *output {
	case "json":
		err = report.JSON(out, r)
	case "ndjson":
		err = stream.Report(r)
	default:
		if file != nil {
			err = report.JSON(file, r)
			if err == nil {
				err = file.Sync()
			}
		}
		if err == nil {
			err = report.Table(out, r)
		}
	}
	if err != nil {
		fmt.Fprintln(errout, "trusttrace: write report:", err)
		return 125
	}
	if traceErr != nil {
		fmt.Fprintln(errout, "trusttrace:", traceErr)
		return 125
	}
	return r.Summary.ExitCode
}

func runDiff(args []string, out, errout io.Writer) int {
	f := flag.NewFlagSet("trusttrace diff", flag.ContinueOnError)
	f.SetOutput(errout)
	metadata := f.Bool("include-metadata", false, "include PIDs, timestamps, durations and event ordering")
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if f.NArg() != 2 {
		fmt.Fprintln(errout, "usage: trusttrace diff [--include-metadata] FIRST.json SECOND.json")
		return 2
	}
	reports := make([]report.Report, 2)
	for i, path := range f.Args() {
		file, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(errout, "trusttrace:", err)
			return 2
		}
		reports[i], err = diff.Load(file)
		file.Close()
		if err != nil {
			fmt.Fprintf(errout, "trusttrace: %s: %v\n", path, err)
			return 2
		}
		if reports[i].Summary.Incomplete {
			fmt.Fprintf(errout, "trusttrace: %s has incomplete observation; missing behavior cannot be ruled out\n", path)
		}
	}
	changes := diff.Compare(reports[0], reports[1], diff.Options{IncludeMetadata: *metadata})
	for _, line := range changes {
		if _, err := fmt.Fprintln(out, line); err != nil {
			fmt.Fprintln(errout, "trusttrace:", err)
			return 2
		}
	}
	if len(changes) > 0 {
		return 1
	}
	return 0
}
