# Windows native sandbox

The Windows executable uses the existing Windows sandbox implementation without
`codex-core` or a running Codex application. It supports explicit `setup` and
`status`, native `run` options, and Console's versioned environment transport.

## Build and distribute

Install Rust 1.95.0 with the `x86_64-pc-windows-msvc` toolchain, Visual Studio C++
build tools, a Windows SDK, and CMake. From `codex-rs`:

```powershell
cargo build --locked --release -p codex-mcp-console-sandbox -p codex-windows-sandbox --bin mcp-console-sandbox --bin mcp-console-sandbox-setup --bin mcp-console-sandbox-runner
just test --release -p codex-mcp-console-sandbox --test windows_cli --test windows_console --retries 0
```

Distribute `mcp-console-sandbox.exe`, `mcp-console-sandbox-setup.exe`, and
`mcp-console-sandbox-runner.exe` together. The helpers reuse the existing setup
and command-runner implementations with Console's product identity. Only the
main executable is needed by the restricted-token backend.

## Explicit setup

Run from an ordinary interactive PowerShell session:

```powershell
.\target\release\mcp-console-sandbox.exe setup
.\target\release\mcp-console-sandbox.exe status
```

Setup requests Windows UAC approval when provisioning is needed. Repeating it
reuses current setup records and enabled accounts. Status prints JSON and exits
zero when current records, enabled accounts, and adjacent helpers are present.
It is a readiness check, not an audit of every firewall rule.

State defaults to `%LOCALAPPDATA%\mcp-console`; native commands accept an absolute
`--state-dir`. Use one stable state directory per Windows user. Accounts and
network policy are machine resources, so separate directories are not independent
installations. Existing Codex accounts, firewall rules, and WFP identifiers retain
their names. Another product's account records are rejected.

Console display names are **McpConsoleSandboxOffline** and **McpConsoleSandboxOnline**;
login names are `McpConsoleSandboxOff` and `McpConsoleSandboxOn` to fit Windows'
20-character limit. Setup also uses `ConsoleSandboxUsers`, protected credentials
in `.sandbox-secrets`, and versioned records under `.sandbox`.

## Versioned Console transport

`--config-env NAME -- COMMAND ...` consumes protocol version 2 as described in
[PROTOCOL.md](PROTOCOL.md), with these platform fields and limits:

- `windows_sandbox_level` defaults to `elevated`. `restricted-token` is explicit;
  `disabled` is rejected.
- `windows_state_dir` optionally selects an absolute persistent state directory.
- The elevated mode requires prior explicit setup. Ordinary versioned launches
  fail with setup guidance when accounts are missing.
- Restricted-token execution requires `network: enabled`, host reads, and no
  read-deny policies. Its token and ACL restrictions enforce selected writes;
  it does not provide OS-enforced network isolation or a read allowlist boundary.
- Profiles use the same native constructors and workspace metadata defaults as
  Unix. Unsupported policy fails before launching the target.
- Managed proxy configuration, custom cleanup timeouts, macOS policy extensions,
  and Linux backend selection are rejected. `--bootstrap-fd` is Unix-only.
- The selected configuration and reserved transport variable are removed from
  the target environment case insensitively. Excluded variables cannot be reused
  as private temporary environment names.

The ordinary command arguments, cwd, and stdio remain the target's inputs.
Environment inheritance and overrides retain the shared protocol rules. Private
storage grants its data directory and can export `TMPDIR`, `TEMP`, and `TMP`.

## Native CLI

Run `--help` or `run --help` for the typed native options. `run` consumes a serialized
`PermissionProfile` and explicit environment map rather than a versioned request.
The command must follow `--`; target flags pass through unchanged. Clap syntax
errors exit 2 before setup or launch. Paths and JSON are validated at that boundary.
The native CLI retains the upstream setup/repair behavior; versioned Console
launches require explicit initial provisioning.

Targets still need host read/traverse permission. In particular, Python 3.14's
private temporary directories can grant access only through owner/admin/system
ACL entries that a restricted token cannot use. Ordinary directories inheriting
the current user's access work without machine-wide ACL changes. Use native
Windows paths with backslashes for `cmd.exe`. Targets also remain subject to host
Application Control policy; error 4551 is a host policy rejection.

Restricted-token launches create capability SIDs and save mappings in `cap_sid`.
Capability ACL entries persist on filesystem objects; deleting the state directory
does not undo them. Elevated launches use provisioned accounts and refresh workspace
ACLs. Backend upgrades or network-setting changes can require administrator repair.

## Lifecycle

Console's pipe-launched workloads enter a non-breakaway Job at process creation.
After normal root exit, timeout, or cancellation, the backend terminates remaining
members and confirms zero active processes before returning an exit receipt.
A native Job completion port wakes the waiter; an accounting query confirms the
barrier, with a five-second cleanup allowance. Failure uses reserved exit code 125.
Codex's default product continues to preserve descendants after normal root exit.

The versioned transport watches its direct caller and optional
`lifecycle.parent_pid` owner through retained process handles. Owner death or Ctrl+C
requests session termination. It removes private storage only after a confirmed
receipt; startup errors and unconfirmed retirement retain storage with diagnostics.
Private storage is not deleted while target descendants are known to remain.

Restricted-token runner loss and elevated helper loss close kill-on-close Jobs.
Runner loss does not guarantee storage deletion. A forcibly killed waiting Console
frontend is not evidence of completed native retirement and cannot admit a replacement.
Windows console signals and desktop behavior are not Unix terminal semantics.

## Validation limits

The public versioned-transport regression exercises restricted-token policy,
private storage, and environment exclusion. CLI regressions cover typed validation
and target argument forwarding. Console integration acceptance covers application
execution, write denial, and descendant retirement before restart.
Elevated account provisioning and offline-network enforcement need an interactive
administrator setup and their own integration run. Linux/macOS lifecycle suites
remain separate platform coverage.
