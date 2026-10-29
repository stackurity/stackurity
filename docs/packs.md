# Stack packs

A stack pack teaches Stackurity to read one technology's dependency files. Packs keep the core small (it reads Linux packages, npm, yarn, pnpm, Composer, Python, Go, Ruby, NuGet and Dart out of the box) and let support for anything else grow without a Stackurity release.

| Pack | Reads | Notes |
| --- | --- | --- |
| `java` | `.jar`, `.war`, `.ear`, `gradle.lockfile`, `pom.xml`, `build.gradle(.kts)` | Deployed archives give every bundled library from its Maven metadata (Spring Boot `BOOT-INF/lib`, `WEB-INF/lib`, EARs), skipping the application's own module. Lockfiles give exact versions, transitive included. `pom.xml` gives direct dependencies, resolving properties, `dependencyManagement` and parent poms found in the same repository, and is reported as partial coverage. |
| `cargo` | `Cargo.lock` | The Rust reader that used to be built in. |
| `swift` | `Package.resolved`, `Podfile.lock` | Swift Package Manager formats 1, 2 and 3 (Xcode projects included) as `pkg:swift/<host>/<owner>/<repo>`, the way OSV's SwiftURL ecosystem names them; registry pins by the repository they mirror when the file records it. CocoaPods pods as `pkg:cocoapods/<pod>`, subspecs counted once, development pods (`:path:`) skipped. Packages pinned to a branch or commit have no version: the file's coverage is partial and counts them. |
| `hex` | `mix.lock` | Every format since Mix 1.0, as `pkg:hex/<package>` (the Hex package, also when `mix.exs` renames it); private organisations' packages as `pkg:hex/<org>/<package>`. Git dependencies have no version: the file's coverage is partial and counts them. |
| `cpp` | `conan.lock`, `vcpkg.json`, `vcpkg.spdx.json` | Conan 1 (graph lockfiles 0.1-0.4) and Conan 2 (0.5) as `pkg:conan/<name>@<version>` with `user` and `channel`, build requirements scoped `build`. vcpkg has no lock file: `vcpkg.json` gives exact versions only for ports pinned under `overrides` (the rest are picked from `builtin-baseline` by vcpkg, which needs its registry, and are counted as partial coverage); each installed port's `share/<port>/vcpkg.spdx.json` gives its exact version. Ports are `pkg:generic/vcpkg/<port>`, as purl has no vcpkg type. |

### What each pack can check

A pack only inventories; findings come from the vulnerability sources Stackurity syncs for the package type it reports ([compatibility.md](compatibility.md#application-dependencies)).

| Pack | Inventory | Vulnerabilities | Latest releases |
| --- | --- | --- | --- |
| `java` | Yes | OSV (Maven), well covered | Maven Central |
| `cargo` | Yes | OSV (crates.io, RustSec), well covered | crates.io |
| `hex` | Yes | OSV (Hex): GitHub and the Erlang Ecosystem Foundation's CNA publish Hex advisories, several hundred, covering the common web stack (Plug, Phoenix, Cowboy, hackney, Mint, Bandit) | hex.pm |
| `swift` | Yes | Swift packages: OSV (SwiftURL), GitHub's Swift advisories only, a few dozen packages (SwiftNIO, Vapor, gRPC Swift, async-http-client, Sparkle and others); most Swift packages have none. Repository URLs are compared in any letter case. CocoaPods: none, OSV has no CocoaPods data, so pods are shown as having no vulnerability source | None (SwiftPM and CocoaPods have no registry Stackurity reads) |
| `cpp` | Yes | None: OSV lists a ConanCenter ecosystem but publishes no records for it, and no public database covers vcpkg ports. C and C++ libraries are shown as having no vulnerability source; use the inventory to find where a library is used when an advisory for it is published | None |

## For administrators

Instance administrators manage packs under **Settings → Stack packs**. The official packs ship inside the server but stay inactive until someone installs them. When a repository holds files the core cannot read, such as a `pom.xml`, a `Package.resolved` or a `mix.lock`, Home names the pack that would read them. Installing a pack:

- checks its signature (see below) and that its module compiles;
- applies to every workspace;
- queues a new scan of every repository with files the pack now reads.

The previous version is kept, so **Roll back** reinstalls it. Disabling or removing a pack makes its files show as unsupported again from the next scan.

`stackurity scan` in CI and the host agent (on `--app-dir` and discovered applications) use the server's enabled packs on their own machine, so file contents never leave it. A pack is downloaded, its signature checked against the client's own keyring and its module compiled only when a file it reads is found, and it is unloaded after the scan: hosts without such files never load one. Loading the Java pack costs about 150 MB of memory and 1.5 s; reading a 35 MB application with 120 bundled libraries adds about 50 MB and 0.3 s. Use `--no-packs` to skip packs.

| Variable | Purpose |
| --- | --- |
| `STACKURITY_PACK_TRUSTED_KEYS` | File of `publisher base64-ed25519-key` lines: publishers whose packs this server accepts, besides official ones |
| `STACKURITY_PACK_ALLOW_UNSIGNED` | `true` accepts unsigned packs. For pack development only |

## How packs are contained

A pack is a WebAssembly module run by [wazero](https://wazero.io), a runtime written in Go:

- It gets WASI preview 1 only: standard input, output and error, and exit. It gets no directories, no environment variables, no sockets and a fixed clock. A module that imports anything else is refused.
- Its memory is capped (default 128 MiB, at most 512), and each run has a time limit (default 60 s, at most 600).
- Every scan starts a fresh instance; nothing carries over between runs.
- It sees only the files its manifest names: the core reads them and mounts them read-only at `/input`, which holds those files and nothing else. Large files (a deployed JAR) are read in place rather than copied into the request.
- Its output is checked before it is used. It may report only the package types its manifest declares (`purl_types`), only with locations among the files it was given, and at most 200,000 packages. Its coverage entries are labelled `pack:<id>:` and its findings carry the pack's id and version as evidence.

## Signatures

Each pack file carries an Ed25519 signature over its id, version and the SHA-256 of its manifest and module. The server accepts a pack only if a trusted key signed it, and only if that key belongs to the publisher the manifest names, so nobody can sign a pack in someone else's name. The official key is built into Stackurity. Signatures are checked again whenever a pack is loaded, so a pack altered in the database is not run.

The official packs are built and signed by a maintainer with the official key, which never leaves their machine and is not used in CI: `stackurity pack build packs/<id> --key <official key> -o internal/packs/official/<id>.stkpack`. A test (`tools/releaselint`) checks that every archive was built from its `pack.json` and carries the official signature, and the release workflow refuses to release while a pack under `packs/` has no signed archive. Until its archive is added, a pack is not offered under **Settings → Stack packs** and Home does not name it. Pack tests build the sources unsigned, as `STACKURITY_PACK_ALLOW_UNSIGNED=true` does for development.

Ed25519 keys work offline and in air-gapped installs. Sigstore keyless signing with transparency logs is planned for packs published through a public registry.

## Writing a pack

A pack is a directory with `pack.json` and a program that targets WASI preview 1. In Go it is a `main` package using `github.com/stackurity/stackurity/pkg/pack`:

```go
package main

import "github.com/stackurity/stackurity/pkg/pack"

func main() {
	pack.Serve(func(req *pack.Request) (*pack.Response, error) {
		out := &pack.Response{}
		for _, f := range req.Files {
			// parse f.Content, append pack.Observation{Purl: "pkg:maven/g/a@1.0", Location: f.Path, ...}
			out.Checked("maven:" + f.Path)
		}
		return out, nil
	})
}
```

```json
{
  "abi": "stackurity-pack/2",
  "id": "example",
  "version": "1.0.0",
  "name": "Example",
  "publisher": "acme",
  "license": "Apache-2.0",
  "description": "What it reads and how well.",
  "files": ["example.lock"],
  "purl_types": ["generic"],
  "handles": ["example"],
  "known_limitations": ["What it cannot see"]
}
```

- `files` are base-name patterns of the files the pack reads; a bare `*` is not allowed.
- `handles` names the coverage prefixes the core reports as unsupported without the pack, which drives suggestions.
- Report every file in coverage: `Checked`, `Partial` with the reason, or `Failed`.
- Use real package URLs so vulnerability and lifecycle data apply.

```sh
stackurity pack build ./my-pack --key publisher.key   # compiles with GOOS=wasip1 GOARCH=wasm and signs
stackurity pack run my-pack-1.0.0.stkpack ./some-repo   # try it locally
stackurity pack inspect my-pack-1.0.0.stkpack           # manifest, hash and whether this build trusts it
```

Any language that compiles to WASI preview 1 works: put a ready `pack.wasm` next to `pack.json`. The protocol is one JSON request on standard input (the files' paths and sizes), the files themselves under `/input`, and one JSON response on standard output, as defined in `pkg/pack`. In Go, read a file with `f.Bytes()`, or `f.ReaderAt()` for archives.
