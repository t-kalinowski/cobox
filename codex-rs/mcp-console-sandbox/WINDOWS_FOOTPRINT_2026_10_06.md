# Windows patch reduction, 2026-10-06

Started from `mcp-console/sandbox-runner/rust-v0.160.1` at `6237b02627c57df8627b6646f8504a1513ee6b55`. The recorded upstream base is `rust-v0.160.1`, `d27764b82f7118f674371e6d6e76271d9d606edb`. The two implementation changes are separate commits: environment-only execution, then additive companion registration; a follow-up records host provisioning results. Validation ran on Windows x64 with the repository's Rust 1.95.0 MSVC toolchain.

## Changes

- Removed native `run`, its permission/environment/root/proxy/desktop parsers, and its independent session-launch path. `setup`, `status`, and protocol-v2 `--config-env NAME -- command [args...]` remain. No removed option is reinterpreted as JSON. Restricted-token (`unelevated`) support remains.
- Removed the Console `Default` desktop exception. Private-desktop creation and validation now use upstream behavior with Console-specific names. Argument forwarding, JSON/path rejection, and cross-product-state rejection moved to the retained interface; existing environment, desktop, stdio, exit, and retirement tests remain.
- Moved the two entry points to `codex-mcp-console-sandbox-windows`. Setup calls the existing library implementation. The runner compiles the original upstream module tree through a directory-scoped `#[path]`, preserving child-module resolution without source copying or generation. A separate small package keeps native `windows-sys` 0.52 distinct from the transport's 0.61.
- Preserved executable names and adjacent packaging. The additive manifest/build rules retain setup's `asInvoker` resource and explicit launcher-driven UAC, the runner's Windows subsystem, and shared linker settings. Cargo, Bazel, and the Windows CI recipe agree. The Bazel fixture now declares its existing Windows API dependency.

The existing upstream `windows-sandbox-rs/Cargo.toml`, `BUILD.bazel`, and `build.rs` are restored byte-for-byte. No new native source edit is needed to register the companions. Workspace registration and the Cargo lock entry remain necessary. `just bazel-lock-update` completed without changing `MODULE.bazel.lock`.

The remaining native edits are the existing product identity, independent accounts/credentials/helpers/synchronization/WFP/firewall/uninstall integration; loopback-enforcement correction; non-breakaway Jobs and confirmed retirement; caller cancellation and stdio fixes; product desktop names; and the retained upstream test corrections. They are inventoried in [INTEGRATION.md](INTEGRATION.md#windows-integration). Linux/macOS implementation, bootstrap-fd, Landlock, JSON protocol, permission policy, and native lifecycle corrections are unchanged by this pass.

## Footprint against the recorded upstream base

Counts use `git diff --no-renames --numstat BASE REV`. Files present in the upstream tree are counted separately from added files, including documentation and CI. Deleted additive wrappers therefore disappear from the base-to-result count; the two wrappers now live in the additive companion package.

| Scope                                   | Before: files, +lines, -lines | After: files, +lines, -lines |
| --------------------------------------- | ----------------------------- | ---------------------------- |
| Existing upstream files, whole tree     | 33, +858, -391                | 30, +828, -376               |
| Additive files, whole tree              | 64, +10955, -0                | 69, +10987, -0               |
| Existing upstream Windows backend files | 25, +434, -121                | 22, +392, -106               |
| Additive Windows backend files          | 7, +413, -0                   | 5, +388, -0                  |

The Windows backend scope is `codex-rs/windows-sandbox-rs/`; the additive companion package is included in the whole-tree totals. The three restored build files are the files that became identical to upstream. `desktop.rs` retains only product naming changes.

## Executed checks

- Cargo debug and release builds passed for the main runner, fixture, setup companion, and command-runner companion.
- `just test --locked -p codex-mcp-console-sandbox --retries 0` and its `--release` variant each passed all 15 ordinary Windows contracts. The two elevated loopback tests were skipped in these ordinary runs; a later explicit run failed both at the missing-setup check, before exercising networking. Coverage includes exact argv (empty/quoted/Unicode/trailing-backslash arguments and former option names), environment overrides/exclusion, JSON/path errors, private desktop identity, all three signed 32-bit exit cases, binary stdin/EOF, caller death, runner loss, and descendant retirement before private-storage removal. Every removed CLI option fails clearly with exit 2.
- The focused native run selected 42 bridge, WFP/product, desktop, identity, materialization, command-runner input-loop, and non-provisioning unified-exec tests. Initially 40 passed and two failed: control-pipe disconnect left a Python descendant alive; capture cancellation exceeded its ten-second assertion. With the actual Python installation directory ahead of the WindowsApps alias on PATH, an isolated TEMP/TMP directory, and serial execution, both failures passed (0.095 s and 4.788 s). No test or backend source was changed for the recheck. Native capture preservation, ConPTY preservation/termination, PowerShell I/O, and interrupt checks executed and passed; they did not silently skip for missing tools.
- Inspected both profiles' PE headers/resources: setup is a console executable with an embedded `asInvoker`, `uiAccess=false` manifest; the command runner uses the Windows GUI subsystem; all three executables retain an 8 MiB stack reserve. Staged actual binaries under their shipping names; status found adjacent helpers without creating state. Setup without companions failed before creating state.
- Scoped `just fix` passed for the runner, companion package, and native Windows backend; the CI-equivalent runner/companion Clippy check with `--all-targets -- -D warnings` also passed. Repository-wide `just fmt` reached the Windows command-length limit; scoped Cargo formatting, Bazel/Starlark formatting, and Markdown formatting completed.
- Bazel analysis passed for the runner, both companions, and all four Windows test targets. The compiled fixture and setup manifest-resource targets built successfully. The full build/test attempt failed in third-party `time` 0.3.47 with `E0463: can't find crate for time_macros`; no Bazel runtime tests executed. This is not a passing full Bazel gate.

## Provisioning and platform limits

The existing installed `mcp-console` uses version-5 state; this branch requires version 6. After the user explicitly approved provisioning, the release setup successfully created `%LOCALAPPDATA%\cobox-validation-20261006\mcp-console` through UAC. Both debug and release status reported `configured: true` and adjacent helpers available. No installed binaries were replaced and no Codex provisioning was requested.

The host cannot keep these two Console installations independently provisioned: both use the fixed `McpConsoleSandboxOff`/`McpConsoleSandboxOn` accounts, and setup resets their passwords. The new setup log records provisioning at 09:46:28 local time. The installed Console worker then detected incompatible credentials and automatically provisioned its old state at 09:46:57, explaining the user's second setup approval prompt. An explicit new-profile launch check also entered automatic setup recovery, causing another approval/reset, then failed with `CreateProcessWithLogonW failed: 2`. A matching marker and `status` do not verify password validity. Elevated attempts were stopped to avoid further repair cycles. The new directory remains, but successful elevated workload execution and loopback enforcement are not validated. They require an isolated host or a coordinated downstream migration; a different directory alone does not isolate the accounts. No credentials were printed or manually copied between profiles.

The known restricted-token deletion-boundary limitation was not changed or claimed resolved. The native deletion regression and tests requiring fresh Codex provisioning/registered package identity were excluded. Uninstall, Linux/macOS execution, other architectures, and hosted CI were not run. Administrative setup and live UAC were exercised as described above, including the conflicting old installation's automatic recovery. See [WINDOWS.md](WINDOWS.md#validation-limits) for existing limits.
