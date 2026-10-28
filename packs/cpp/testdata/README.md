# C and C++ pack fixtures

Real files from public repositories, unchanged, downloaded on 2026-10-28 from
`raw.githubusercontent.com` at the commits below.

| Fixture | Source | What it shows |
|---|---|---|
| `user-management-conan1/conan.lock` | [prince-chrismc/user-management](https://github.com/prince-chrismc/user-management) `backend/conan.lock` at `79e7a4ffeaf75e51c7549a3f20d52d2f43485f64` | Conan 1 lockfile 0.4: a graph whose node 0 is the project's `conanfile.py`, recipe revisions, a build requirement (`catch2`), `openssl` 1.1.1n |
| `conan-docs-conan1/conan.lock` | [carbonetes/diggity](https://github.com/carbonetes/diggity) `docs/references/conan/conan.lock` at `903ee10ed2f64aeff3d13838f78ee886f32869c5` (the Conan 1 documentation's example) | References with `@user/channel`, no revisions, a consumer that is itself a package |
| `rippled-conan2/conan.lock` | [XRPLF/rippled](https://github.com/XRPLF/rippled) `conan.lock` at `05847a3c908a9b3eaf43ddbd9af3c81214e60268` | Conan 2 lockfile 0.5: revisions with timestamps, `overrides`, packages in both `requires` and `build_requires`, `cci.` versions |
| `openvino-conan2/conan.lock` | [openvinotoolkit/openvino](https://github.com/openvinotoolkit/openvino) `conan.lock` at `a3562d4a36a6f061e675e2a405b0c28019e3229a` | Conan 2 lockfile 0.5 with a long list of build tools |
| `ladybird-vcpkg/vcpkg.json` | [LadybirdBrowser/ladybird](https://github.com/LadybirdBrowser/ladybird) `vcpkg.json` at `6156613854248f4edefdba8330597ac541ac204e` | A vcpkg manifest that pins every port under `overrides`, port versions written as `version#N`, platform and feature dependencies, pins for ports it does not name |
| `multipass-vcpkg/vcpkg.json` | [canonical/multipass](https://github.com/canonical/multipass) `vcpkg.json` at `c8eb062ecf7af6cab3cecfa6126b288afcd47145` | A manifest resolved from `builtin-baseline` with one override: most versions cannot be known without the vcpkg registry |
| `joequake-vcpkg-installed/curl/share/curl/vcpkg.spdx.json` | [j0zzz/JoeQuake](https://github.com/j0zzz/JoeQuake) `Windows/curl/share/curl/vcpkg.spdx.json` at `0b9d2a3b567b488f76157bfe54cd1f4083647ef7` | The SPDX record vcpkg writes for an installed port (`curl` 8.13.0, port version 1) |
