# Windows native sandbox

The Windows executable runs commands through native MXC using Codex's shared capability, policy conversion, and launch APIs. It requires neither a running Codex application nor account provisioning.

Only fresh hosts are supported. Previously provisioned hosts require independent removal of legacy Console sandbox accounts, stored account credentials, and persistent firewall rules before use. MXC runs as the host identity, so a workload can decrypt readable DPAPI-protected legacy passwords. The runner does not detect or clean up legacy state.

The environment transport is the same as on Unix:

```powershell
$env:CONSOLE_POLICY = '{"extends":":read-only"}'
mcp-console-sandbox --config-env CONSOLE_POLICY -- cmd.exe /d /c "echo MXC ready"
```

## Build and distribute

Install Rust 1.95.0 with the `x86_64-pc-windows-msvc` toolchain, Visual Studio C++ build tools, a Windows SDK, and CMake. From `codex-rs`:

```powershell
cargo build --locked --release -p mcp-console-sandbox --bin mcp-console-sandbox
just test --locked --release -p mcp-console-sandbox --retries 0
```

Distribute `mcp-console-sandbox.exe`. For debug builds omit `--release`. The [Bazel targets](BUILD.bazel) build the executable and its public contract tests on Windows using the upstream MSVC host toolchain.

## Console transport

The complete JSON reference is [PROTOCOL.md](PROTOCOL.md). Windows accepts `--config-env NAME -- command [args...]`; the descriptor transport is Unix-only. Environment-variable matching is case-insensitive. Hidden per-drive current-directory entries such as `=C:` are omitted from inherited target variables; explicit names containing `=` are invalid. The selected configuration variable never reaches the target.

Native setup uses the trusted executor environment. The leaf crate carries the exact target environment in a bounded transport and applies it through a relay already inside MXC, after Windows has assigned its native package variables. Only the target payload and an inert native setup entry reach that relay. This preserves configured `TEMP`, `TMP`, and `LOCALAPPDATA`, including an empty target environment, without letting target overrides configure platform-directory discovery or the native loader. Symbolic `tmpdir` permissions resolve from target `TEMP` and `TMP` before wrapping the command; explicit read-only overrides and denials still apply. The relay creates no Job or storage owner; the existing native owner still confirms retirement of the complete process tree.

Every launch requires MXC support for its requested filesystem policy. Capability detection creates and closes a native process security environment; exported API names alone are insufficient. Unsupported hosts and policies fail before target execution, with no backend retry. External filesystem enforcement is unsupported on Windows.

Filesystem access uses native MXC permissions. Read-deny entries require native deny-path support. Working directories resolve through directory handles, including Windows 8.3 aliases, without requiring parent enumeration.

Managed TCP proxies require `allowLocalBinding: true`, because MXC host-loopback access is bidirectional. Explicit false, active SOCKS5 UDP, and Unix-socket grants fail preflight. The proxy validates allow/deny policy and admits clients by membership in the retained workload Job.

## Lifetime and storage

Each workload has a non-breakaway Job. The retained parent process handle and the waiting frontend define its lifetime. Successful retirement requires zero active Job members; private temporary storage is removed only after that native receipt. Every Windows exit-status bit is preserved. Binary stdin and inherited output handles do not delay retirement indefinitely.

Private storage uses `lifecycle.private_tmp` and is independent of filesystem built-in selection. Storage removal retries sharing violations for up to five seconds. Other errors and persistent sharing violations withhold success. Runner loss closes kill-on-close Jobs but does not guarantee storage deletion.

## Validation limits

Public tests cover native filesystem/network policy, managed proxy allow/deny decisions, environment transport, binary stdin, status codes, descendant retirement, owner death, and storage cleanup. By default, each runtime-dependent test probes native MXC and reports `SKIP` when it is unavailable; those hosts retain green CI checks. The workflow includes skip diagnostics for debug and release tests. Hosts that gain MXC support automatically execute the native contracts. Configuration errors, Linux-only options, Seatbelt extensions, explicit cleanup timeouts, duplicate environment names, and unsupported proxy settings remain checked without MXC. A green check with skips does not establish native enforcement coverage.

### Required native validation

Before advancing a consumer source pin, require a successful [Sandbox CI](../../.github/workflows/mcp-console-sandbox.yml) run for that exact revision on a fresh MXC-capable Windows host. Dispatch the workflow at the candidate branch or tag and set `windows_mxc_runner` to the JSON array of labels selecting that runner. For example, `["self-hosted", "Windows", "X64", "mxc"]` selects a registered runner with those labels; the workflow does not provision one. An empty input keeps the ordinary optional-host checks on `windows-2025`.

Selecting a runner enables `MCP_CONSOLE_SANDBOX_REQUIRE_MXC=1` for debug, release, and Bazel contracts. In this mode, unavailable native MXC fails the tests instead of skipping them. The workflow summary records the revision, runner, and required-mode setting. Check that the completed run's `headSha` matches the proposed consumer pin and retain its URL with the pin update. An optional-host run does not satisfy this prerequisite.

For the same required Cargo validation locally, from `codex-rs`:

```powershell
$env:MCP_CONSOLE_SANDBOX_REQUIRE_MXC = '1'
just test --locked -p mcp-console-sandbox --retries 0 --success-output final
just test --locked --release -p mcp-console-sandbox --retries 0 --success-output final
```

The Windows Bazel targets inherit this variable too. Remove it to restore optional-host development checks.

The fixture executable uses native Windows process APIs. For upstream tests invoking Python by name, put an actual interpreter on PATH rather than a Windows app execution alias.
