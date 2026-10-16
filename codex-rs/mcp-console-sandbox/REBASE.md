# Reapplying the native sandbox extraction

The patch is based on `rust-v0.163.0`, commit `83086188ae0614bd882818ff1aa23f3194962012`. Only the pinned release is supported. In this checkout, `origin` is OpenAI Codex and `fork` is `t-kalinowski/cobox`.

## Procedure

1. Fetch the extraction branch and inspect its complete diff against the pinned base:

   ```sh
   git fetch fork refs/heads/mcp-console/sandbox-runner/rust-v0.163.0:refs/remotes/fork/mcp-console/sandbox-runner/rust-v0.163.0
   sandbox_tip=$(git rev-parse fork/mcp-console/sandbox-runner/rust-v0.163.0)
   git diff rust-v0.163.0 "$sandbox_tip"
   ```

2. Start a new branch at the next exact upstream release. Preserve the existing branch and reapply its current net change against the new interfaces. Keep native integration, the runner and its tests, and build registration reviewable separately.
3. Review every changed native path and its callers using [INTEGRATION.md](INTEGRATION.md). Preserve the [protocol](PROTOCOL.md), [lifetime boundaries](LIFECYCLE.md), and native enforcement. Check both ordinary native entry points and standalone hooks, including full-access optimizations and external execution without a native handshake. Keep test-host requirements separate from runtime prerequisites.
4. Update executable tests and deterministic fixtures with the implementation. Remove superseded hooks, redundant upstream regressions, and tests for deleted behavior. Check the JSON reference against production serde types, conversions, and validation; keep its executable examples passing. MCP Console pins this private, unversioned interface and must update with it.
5. Regenerate Cargo lock state against the new workspace. If Rust dependencies change, run `just bazel-lock-update` from the repository root and review both lockfiles. Inspect the complete new upstream diff for accidental enforcement, dependency, or unrelated changes. Update the pinned base, integration inventory, and tagged-release comparison link in the root [README](../../README.md). The comparison must use the new exact upstream release tag as its base and the new fork release branch as its head.
6. Follow the validation checklist below. Verify documentation links, paths, and test selectors; format changed Markdown with `yamark format --wrap paragraph` and run `git diff --check`. Keep repository documentation about current behavior and maintenance; report revision-specific results, failures, and skips in the PR or task summary.
7. Commit and push without amending or force-pushing. Report local and hosted validation separately. Downstream adoption requires selecting an exact tested revision and rebuilding its artifacts.

## Validation checklist

Use the commands in [.github/workflows/mcp-console-sandbox.yml](../../.github/workflows/mcp-console-sandbox.yml) and the [build instructions](README.md#build-and-validation). Report host capabilities and actual skips or failures; a build or unavailable runtime gate is not a passing execution test.

- On macOS and GNU Linux, run `just test --locked -p mcp-console-sandbox --retries 0` against debug and release runners. On Linux, build ordinary bubblewrap first and set `CARGO_BIN_EXE_bwrap` to the matching artifact. For release contracts also set `CARGO_BIN_EXE_mcp-console-sandbox`. Interposer tests require dynamically linked executables.
- Run `just test -p codex-sandboxing` on macOS and `just test -p codex-sandboxing -p codex-linux-sandbox -p codex-bwrap --retries 0` on Linux. Native Linux fixtures need the built debug helper on `PATH`.
- Run `bazel test //codex-rs/mcp-console-sandbox:bootstrap-contract-test` on macOS and Linux. Report host-policy or dependency-download failures separately; do not alter enforcement to obtain a pass.
- Preserve x86_64 and aarch64 musl builds, helper strip/hash order, build-scoped toolchain variables, ELF dependency checks, and static-artifact `transport::` / `lifecycle::` contracts. Static runner artifacts do not establish portability of a target's runtime or libraries.
- Exercise real fresh and inherited procfs views when reviewing Linux compatibility. Verify visibility and policy with the [procfs review matrix](LINUX_COMPATIBILITY.md#procfs-review), including the supervisor and selected filesystem/network permissions.
- On Windows, build the runner in debug and release using [WINDOWS.md](WINDOWS.md#build-and-distribute). Run executable, shared bridge, proxy-admission, and Job lifetime contracts. Before advancing the consumer pin, require debug, release, and Bazel contracts on a fresh MXC-capable host with [required native validation](WINDOWS.md#required-native-validation) enabled. Retain the successful workflow URL and verify its exact revision matches the proposed pin. Optional-host skips do not satisfy this prerequisite.
- Run scoped Clippy and `just argument-comment-lint -p mcp-console-sandbox`. After functional tests, run `just fix -p` for changed Rust packages and `just fmt` from `codex-rs`; do not rerun tests solely because fix/format ran. Follow the repository's approval rule before a full-workspace suite.
