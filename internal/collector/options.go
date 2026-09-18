package collector

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

type Options struct {
	Command        []string
	Version        string
	Stdin          *os.File
	Stdout, Stderr io.Writer
	Events         func(report.Event) error
	RecordLimit    int
	ShutdownGrace  time.Duration
}

// Run launches exactly one command tree and returns its forensic receipt.
func Run(ctx context.Context, o Options) (report.Report, error) {
	if o.RecordLimit <= 0 {
		o.RecordLimit = 100000
	}
	if o.ShutdownGrace <= 0 {
		o.ShutdownGrace = 3 * time.Second
	}
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	return run(ctx, o)
}
