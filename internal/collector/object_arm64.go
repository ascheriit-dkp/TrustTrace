//go:build linux && arm64

package collector

import _ "embed"

//go:embed trace_arm64.o
var object []byte
