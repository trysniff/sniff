# Third-Party Notices

## Go

Sniff embeds an adapted form of the build-header scanner from Go's
[`go/build`](https://go.dev/src/go/build/build.go) package. The helper delegates
constraint expression parsing to the exact invoking toolchain's
`go/build/constraint` package.

Copyright belongs to The Go Authors. The adapted source is licensed under the
BSD 3-Clause License. A copy is included at
`LICENSES/Go-BSD-3-Clause.txt`.

## scip-java

Sniff embeds a modified form of
`AnalyzerFirExtensionRegistrar.kt` from
[scip-java v0.13.1](https://github.com/scip-code/scip-java/tree/v0.13.1).
The modification registers Sniff's compiler-resolved Kotlin annotation checker.

Copyright belongs to the scip-java contributors. The derived source is licensed
under the Apache License, Version 2.0. A copy is included at
`LICENSES/Apache-2.0.txt`.

## pip

Sniff distributes
[`pip` v26.2.1](https://pypi.org/project/pip/26.2.1/) as a pinned wheel so
Python build-toolchain preparation uses one verified resolver on every supported
operating system. Copyright belongs to the pip developers and contributors.
Pip is licensed under the MIT License. A copy is included at
`LICENSES/pip-26.2.1-MIT.txt`; licenses for pip's vendored dependencies remain
included inside the unmodified wheel.
