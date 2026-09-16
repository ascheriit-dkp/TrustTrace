//go:build linux && amd64

package collector

import _ "embed"

//go:embed trace_amd64.o
var object []byte
