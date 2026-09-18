//go:build !linux || (!amd64 && !arm64)

package collector

import (
	"context"
	"fmt"
	"github.com/ascheriit-dkp/TrustTrace/internal/report"
)

func run(context.Context, Options) (report.Report, error) {
	return report.Report{}, fmt.Errorf("tracing requires Linux amd64 or arm64; diff is available on this platform")
}
func LaunchHelper() int { return 125 }
