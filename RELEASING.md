# Releasing

How a Stackurity release is cut. The version is the newest `## X.Y.Z` heading in [CHANGELOG.md](CHANGELOG.md); a tag `vX.Y.Z` on `main` publishes it through [.github/workflows/release.yml](.github/workflows/release.yml). Maintainers of the hosted service follow the production steps in the private `stackurity-pro` repository's `RELEASING.md`, which starts from this one.

## The steps

| Step | Command | Time |
| --- | --- | --- |
| 1. Prepare | `go run ./tools/release prepare vX.Y.Z` | 1–2 min |
| 2. CI | the pull request's checks | 20–30 min |
| 3. Merge and tag | merge the pull request, then `git tag -a vX.Y.Z -m "Stackurity X.Y.Z" <merge commit> && git push origin vX.Y.Z` | 2 min |
| 4. Release workflow | runs on the tag: upgrade, restore and rollback checks, isolation suite, vulnerability gate, then binaries, images, charts, release notes | about 20 min |
| 5. Next | `go run ./tools/release next vX.Y.Z` once the release is published | 1 min |

### 1. Prepare: `tools/release prepare`

From a clean checkout of this repository:

```sh
go run ./tools/release prepare v0.15.0            # creates release-0.15.0 from origin/main and opens the pull request
go run ./tools/release prepare -dry-run v0.15.0   # only prints what it would change
go run ./tools/release prepare -no-pr v0.15.0     # commits on the branch; push and open the PR yourself
```

It does every file change a release needs, in one commit:

- **CHANGELOG.md**: the `## Unreleased` section becomes `## 0.15.0`, and a fresh, empty `## Unreleased` goes above it so the next change has its heading (parallel pull requests then don't each add one). It refuses an empty or missing Unreleased section, two of them, or a version that is not newer than the last release.
- **Charts**: `version` and `appVersion` in `deploy/helm/stackurity/Chart.yaml` and `deploy/helm/stackurity-reporter/Chart.yaml`.
- **server.json** (the MCP Registry entry): `version`.
- **Docs**: every image and chart reference that `tools/releaselint` checks in `README.md`, `docs/install.md` and `docs/kubernetes.md`.
- **Upgrade matrix**: adds the previous release to `from:` in `.github/workflows/release-checks.yml` if it is not there yet.

Then it runs what the release workflow runs before it publishes anything: `tools/changelog -check`, the release notes for the tag, and the `releaselint` and `docslint` tests with `STACKURITY_RELEASE_TAG` set (which also requires every official pack to be built and signed). Only then does it commit, push and open the pull request with `gh`. The pull request body lists the entries of the release notes, the migrations added since the previous tag and the gates below.

### 2–4. CI, tag, release workflow

Merge when CI is green. Tag the merge commit (the tag must be on `main`). The release workflow refuses to publish unless:

- `tools/changelog` finds the tag's section and `releaselint` passes with the tag,
- every earlier release in the upgrade matrix upgrades, restores from backup and rolls back cleanly to the new build (`tools/release-checks/upgrade.sh`), and the workspace isolation suite passes,
- `govulncheck`, `npm audit` and an image scan find no fixable HIGH or CRITICAL vulnerability.

Then it publishes the binaries with signed checksums, the images on GHCR and Docker Hub (signed, with SBOM and provenance), the Helm charts, and the release notes from CHANGELOG.md, and tells the Homebrew tap, the website and the licensed-edition image build.

### 5. Next: `tools/release next`

Once the release is published:

```sh
go run ./tools/release next v0.15.0
```

adds it to the upgrade matrix and opens a small pull request, so every later release is tested as an upgrade from it. `releaselint` fails the first pull request that adds something under `## Unreleased` until this is merged.

## Gates that stay

Nothing here skips a check; it only stops people from doing by hand what a command does:

- CI green on the release pull request.
- The release workflow's upgrade, restore, rollback, isolation and vulnerability gates (above), on the tag itself.
- Release notes exist for the tag and every versioned reference names it.

## A patch release

Same steps with the next patch version (`prepare v0.15.1`). The tag must be on `main`, so a patch release ships what is on `main`.
