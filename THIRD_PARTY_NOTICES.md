# Third-party notices

These notices accompany the Linux amd64 and arm64 TrustTrace v0.1.0 binaries.
They reproduce upstream license/copyright notices from the pinned module
sources and the Go 1.27.1 toolchain used by the release workflow.

## Distribution inventory

`CGO_ENABLED=0 GOOS=linux GOARCH=<amd64|arm64> go list -deps -json
./cmd/trusttrace` identifies two external modules: `github.com/cilium/ebpf`
v0.19.0 and `golang.org/x/sys` v0.31.0. The static binaries also incorporate
Go runtime/standard-library code and Go's vendored
`golang.org/x/net/dns/dnsmessage` package. The latter uses the revision bundled
with Go 1.27.1, not the test-only x/net version in go.sum.

The inventory was checked for both architectures, including source-level
notices in the selected Go and assembly files. Additional notices from included
standard-library packages are retained below even where the linker may omit
individual routines. Compiler tools, test dependencies, QEMU, BusyBox, Linux
kernel images and race-test runtimes are not included in the release assets.
The project-owned embedded BPF objects are covered by the accompanying LICENSE.
Recheck this inventory when dependencies or the release Go toolchain change.

## github.com/cilium/ebpf v0.19.0 — MIT

Source: `github.com/cilium/ebpf@v0.19.0/LICENSE`.

```text
MIT License

Copyright (c) 2017 Nathan Sweet
Copyright (c) 2018, 2019 Cloudflare
Copyright (c) 2019 Authors of Cilium

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## golang.org/x/sys v0.31.0 — BSD-3-Clause

Source: `golang.org/x/sys@v0.31.0/LICENSE`.

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Go runtime and standard library — BSD-3-Clause

Source: Go 1.27.1 `LICENSE`.

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

The Go BSD license above also applies to the Go-derived code in
`github.com/cilium/ebpf@v0.19.0/internal/sysenc/layout.go`, whose source notice is:

```text
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at https://go.dev/LICENSE.
```

## Go-vendored golang.org/x/net — BSD-3-Clause

Source: Go 1.27.1 `src/vendor/golang.org/x/net/LICENSE`.

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Go, x/sys and Go-vendored x/net — additional patent grant

Source: `PATENTS` in each of the three distributions above (identical text).

```text
Additional IP Rights Grant (Patents)

"This implementation" means the copyrightable works distributed by
Google as part of the Go project.

Google hereby grants to You a perpetual, worldwide, non-exclusive,
no-charge, royalty-free, irrevocable (except as stated in this section)
patent license to make, have made, use, offer to sell, sell, import,
transfer and otherwise run, modify and propagate the contents of this
implementation of Go, where such license applies only to those patent
claims, both currently owned or controlled by Google and acquired in
the future, licensable by Google that are necessarily infringed by this
implementation of Go.  This grant does not include claims that would be
infringed only as a consequence of further modification of this
implementation.  If you or your agent or exclusive licensee institute or
order or agree to the institution of patent litigation against any
entity (including a cross-claim or counterclaim in a lawsuit) alleging
that this implementation of Go or any code incorporated within this
implementation of Go constitutes direct or contributory patent
infringement, or inducement of patent infringement, then any patent
rights granted to you under this License for this implementation of Go
shall terminate as of the date such litigation is filed.
```

## Go debug/elf — BSD-2-Clause

Source: Go 1.27.1 `src/debug/elf/elf.go`.

```text
Copyright (c) 1996-1998 John D. Polstra.  All rights reserved.
Copyright (c) 2001 David E. O'Brien
Portions Copyright 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
```

## Go amd64 runtime memmove — MIT

Source: Go 1.27.1 `src/runtime/memmove_amd64.s` (derived from Inferno).

```text
Copyright © 1994-1999 Lucent Technologies Inc. All rights reserved.
        Revisions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com).  All rights reserved.
        Portions Copyright 2009 The Go Authors. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## Go math — Sun Microsystems 1993

Source: Go 1.27.1 `src/math/log.go` (also retained in related math sources).

```text
Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.

Developed at SunPro, a Sun Microsystems, Inc. business.
Permission to use, copy, modify, and distribute this
software is freely granted, provided that this notice
is preserved.
```

## Go math — Sun Microsystems 2004

Source: Go 1.27.1 `src/math/exp.go` (also retained in related math sources).

```text
Copyright (C) 2004 by Sun Microsystems, Inc. All rights reserved.

Permission to use, copy, modify, and distribute this
software is freely granted, provided that this notice
is preserved.
```

## Go math — Cephes

Source: Go 1.27.1 `src/math/atan.go` (also retained in related math sources).

```text
Cephes Math Library Release 2.8:  June, 2000
Copyright 1984, 1987, 1989, 1992, 2000 by Stephen L. Moshier

The readme file at http://netlib.sandia.gov/cephes/ says:
   Some software in this archive may be from the book _Methods and
Programs for Mathematical Functions_ (Prentice-Hall or Simon & Schuster
International, 1989) or from the Cephes Mathematical Library, a
commercial product. In either event, it is copyrighted by the author.
What you see here may be used freely but it comes with no support or
guarantee.

  The two known misprints in the book are repaired here in the
source listings for the gamma function and the incomplete beta
integral.

  Stephen L. Moshier
  moshier@na-net.ornl.gov
```
