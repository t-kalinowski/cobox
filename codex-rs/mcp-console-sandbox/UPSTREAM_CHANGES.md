# Upstream sandbox changes

This is a curated record of upstream changes inherited by the standalone sandbox runner. Add a section for each release upgrade, newest first, with the previous and new tags, source links, and effects on the runner's enforcement or compatibility. Check the production callers when selecting entries, and record adaptations to the standalone integration separately. [INTEGRATION.md](INTEGRATION.md) describes the current patch; [REBASE.md](REBASE.md) records the upgrade procedure and validation.

## 0.162.1, from 0.160.1

Integrated on 2026-10-13. The upstream range is [`rust-v0.160.1`, `d27764b82f`](https://github.com/openai/codex/commit/d27764b82f7118f674371e6d6e76271d9d606edb) to [`rust-v0.162.1`, `092d3acd6b`](https://github.com/openai/codex/commit/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d). The source patch is `mcp-console/sandbox-runner/rust-v0.160.1` at `c851aa4dd9d39f47a6a0460bf3bced7831110f1e`, including the Windows MXC integration and `windows_backend` compatibility alias.

### Linux helper selection and denied files

- Native setup rejects `bwrap` executables that the filesystem policy and host permissions allow the workload to modify or replace. Selection is initialized with the actual command policy before the synthetic procfs preflight. Standalone stdin transfer and namespace-init hooks retain that ordering. [#51211](https://github.com/openai/codex/pull/51211).
- Deny-glob expansion applies the same protected executable lookup to ripgrep and passes `--no-config`, preventing caller ripgrep configuration from weakening discovery. If no trusted ripgrep is available, the native internal walker remains available. [#51407](https://github.com/openai/codex/pull/51407), [#51527](https://github.com/openai/codex/pull/51527).
- Upstream now opens a distinct descriptor for each `--ro-bind-data` mount and tests multiple denied files. The equivalent fork hunk is dropped; ordinary and standalone paths use the release's implementation and tests. [#50059](https://github.com/openai/codex/pull/50059).
- Native executable fixtures use descriptor-safe copying/writing. Review fixture paths when exercising system and bundled helpers; test-only wrappers must remain compatible with the new helper selection rules. [#50018](https://github.com/openai/codex/pull/50018), [#49246](https://github.com/openai/codex/pull/49246).

### Windows native backend

- Windows bindings move to `windows-sys` 0.61.2, including pointer-valued handles and explicit owned/borrowed handle lifetimes. The Console companion now inherits the workspace dependency. Legacy Job retirement is composed with upstream's owned token/thread handles, and proxy-admission tests use the new handle representation. Native Windows build files remain unchanged from the release. [#50058](https://github.com/openai/codex/pull/50058).
- Writable temporary paths are resolved from the completed child environment, case insensitively, without falling back to host TEMP/TMP. Read/deny carveouts and missing-path rules remain part of the native evaluator. Console supplies its prepared target environment through the existing session path. [#51512](https://github.com/openai/codex/pull/51512).
- Elevated setup grants non-inheriting read-attributes access to the user profile when needed for PowerShell relative paths. Malformed deny-read state is recovered through the native safe path. Both changes are retained with Console's product-specific accounts and setup helper. [#49690](https://github.com/openai/codex/pull/49690), [#50940](https://github.com/openai/codex/pull/50940).
- Helper launch errors retain their cause, and account logon retries once on error 1056. The release also retains hidden-window behavior for piped legacy processes. [#49261](https://github.com/openai/codex/pull/49261), [#49325](https://github.com/openai/codex/pull/49325), [#49308](https://github.com/openai/codex/pull/49308).
- Native tests sharing Windows accounts are serialized. Registered Core service setup/stop diagnostics and the agent CLI's legacy-uninstall command are inherited source changes; they do not add Console commands or make Core service provisioning a standalone prerequisite. [#49389](https://github.com/openai/codex/pull/49389), [#51256](https://github.com/openai/codex/pull/51256), [#50507](https://github.com/openai/codex/pull/50507), [#50437](https://github.com/openai/codex/pull/50437).

### Standalone integration and validation

The net patch preserves the private JSON protocol, product identities, supervised Job receipts, proxy admission, and Unix lifetime boundaries. The old extraction branch is retained. Cargo normalizes workspace versions to `0.162.1` and registers both Console packages; all 1,312 external package entries, dependency lists, and checksums match upstream. See the [reapplication record](REBASE.md#validation-of-the-01621-reapplication) for actual local and hosted results and platform limits.

## 0.160.1, from 0.154.0

Integrated on 2026-10-06. The upstream range is [`rust-v0.154.0`, `6b9826e3`](https://github.com/openai/codex/commit/6b9826e3aa83b1a5947db50f4332cb9c65f1b340) to [`rust-v0.160.1`, `d27764b8`](https://github.com/openai/codex/commit/d27764b82f7118f674371e6d6e76271d9d606edb).

### Filesystem policy and Linux isolation

- For restricted filesystems, Linux bubblewrap masks the privileged app-server Unix socket directory and macOS Seatbelt denies access, including when network access or Unix socket grants would otherwise permit connections. Upstream consequently requires bubblewrap for restricted Linux filesystems. The standalone Landlock exception is described below. [#45984](https://github.com/openai/codex/pull/45984).
- Linux socket masking supports safe private `/tmp` layouts, unrelated namespace mounts, ancestor bind-mount aliases, and Btrfs subvolume device-number differences. These fixes avoid rejecting usable mount layouts while retaining rejection of aliases that would expose the privileged sockets. [#46125](https://github.com/openai/codex/pull/46125), [#46535](https://github.com/openai/codex/pull/46535), [#47079](https://github.com/openai/codex/pull/47079), [#47968](https://github.com/openai/codex/pull/47968).
- Restricted Linux filesystems mask WSL interop sockets and WSLg's duplicate distro root. Seccomp also denies `AF_VSOCK` and `io_uring` under restricted filesystem policies even when ordinary IP networking is enabled, closing routes to host services outside the filesystem sandbox. WSLg alias paths are rejected for explicit grants, working directories, and executables. [#44286](https://github.com/openai/codex/pull/44286), [#45837](https://github.com/openai/codex/pull/45837).
- `.aws` joins `.git`, `.agents`, and `.codex` as protected metadata under native writable-root defaults, including the runner's `:workspace` profile. Explicit policy overrides remain supported. [#48176](https://github.com/openai/codex/pull/48176).
- Git directories referenced from another writable root retain their read-only protection, including symlink aliases. Linux applies metadata mounts after the relevant nested writable bind, preserving allowed writes and metadata restrictions without preventing sandbox startup. [#47974](https://github.com/openai/codex/pull/47974), [#47623](https://github.com/openai/codex/pull/47623).

### macOS Seatbelt

- Restricted filesystem profiles deny `F_MAKECOMPRESSED` and `F_TRANSFEREXTENTS`, which can mutate files through read-only descriptors despite ordinary write restrictions. [#46500](https://github.com/openai/codex/pull/46500).
- Temporary-directory grants respect unreadable paths, read-only paths, and protected metadata. Ancestor protections cover logical symlink paths and resolved targets. Global basename denies such as `/**/.env` permit unrelated directory moves while retaining protection of matching files and directories. [#46571](https://github.com/openai/codex/pull/46571), [#47920](https://github.com/openai/codex/pull/47920).
- Profiles explicitly deny XPC service lookups and remove `com.apple.runningboard` from the platform allowlist. [#46583](https://github.com/openai/codex/pull/46583), [#46532](https://github.com/openai/codex/pull/46532).
- Network-enabled profiles permit lookup of `com.apple.TrustEvaluationAgent`, allowing system libcurl to evaluate TLS trust. This also applies to restricted profiles with permitted proxy ports or local binding; network-disabled and Unix-socket-only profiles retain the denial. [#48565](https://github.com/openai/codex/pull/48565).

### Managed network proxy

- Proxy DNS resolution on macOS uses the system resolver, including supplemental resolvers and VPN split DNS. Resolved-address policy checks remain in place. [#45982](https://github.com/openai/codex/pull/45982).
- Proxy shutdown, handle drop, and canceled waits close accepted HTTP connections and HTTP CONNECT/SOCKS5 tunnels. Explicit shutdown waits for connection cleanup; the runner uses this shutdown path during retirement. [#43884](https://github.com/openai/codex/pull/43884).
- Linux proxy-routed execution honors an explicit `dangerouslyAllowAllUnixSockets` grant. Unix sockets remain denied by default, and path-only grants do not enable standalone Unix socket creation on Linux. Seatbelt uses the prepared managed context's Unix socket permissions, preserving its path allowlist support. Privileged app-server socket protections still apply. [#45534](https://github.com/openai/codex/pull/45534), [#45548](https://github.com/openai/codex/pull/45548).

### Windows native backend

- A sandbox token's default object access-control list (DACL) grants access to its creating logon session and suppresses the shared account owner's implicit permission to rewrite the DACL. Shared filesystem capabilities no longer grant access to another logon's processes, threads, or IPC objects through these default grants. [#47361](https://github.com/openai/codex/pull/47361).
- Offline sandbox accounts receive a non-loopback inbound firewall block in addition to the existing outbound block. [#44639](https://github.com/openai/codex/pull/44639).
- Private desktops remain owned by the calling process across short-lived helper exits. Upstream now requires private desktops for elevated and unelevated launches; Console retains this behavior with product-specific names. [#44658](https://github.com/openai/codex/pull/44658), [#46554](https://github.com/openai/codex/pull/46554).
- Account setup repairs expired passwords. Runtime ACL repair handles existing children and paths beyond the legacy Windows path limit. Safe directory opens resolve ordinary Windows 10 drive-letter aliases while continuing to reject filesystem reparse points. [#46043](https://github.com/openai/codex/pull/46043), [#46241](https://github.com/openai/codex/pull/46241), [#49058](https://github.com/openai/codex/pull/49058), [#47672](https://github.com/openai/codex/pull/47672).
- Background setup helpers and unelevated commands launched with pipes suppress console-window allocation. The standalone CLI uses the updated native session backend. [#49164](https://github.com/openai/codex/pull/49164), [#49386](https://github.com/openai/codex/pull/49386).
- Native uninstall removes sandbox profiles before their accounts and preserves accounts for retry when profile deletion fails. The product-scoped cleanup integration carries this behavior forward for Console identities. [#45799](https://github.com/openai/codex/pull/45799).

### Standalone integration adaptations

- The initial reapplication preserved explicit standalone Landlock selection. That standalone capability has since been removed; the ordinary native policy/app-server-socket guard now applies without exceptions. Upstream's Landlock implementation remains intact. See the [Landlock boundary](LINUX_COMPATIBILITY.md#landlock-boundary).
- The runner passes the prepared managed-network context through Linux setup and supplies the native executor platform to proxy configuration. Its Linux hooks accommodate the new namespace flags while retaining isolated PID-namespace supervision. Sandbox selection uses the updated native API. [#45534](https://github.com/openai/codex/pull/45534), [#46334](https://github.com/openai/codex/pull/46334), [#47989](https://github.com/openai/codex/pull/47989), [#45730](https://github.com/openai/codex/pull/45730).
- Windows companion helpers call the setup implementation extracted into the native library. All Console execution uses the environment transport and upstream private-desktop behavior; the former native `run` interface and desktop opt-out have been removed. [#45169](https://github.com/openai/codex/pull/45169), [#46554](https://github.com/openai/codex/pull/46554). Current changed paths are listed in [INTEGRATION.md](INTEGRATION.md#windows-integration).

### Validation

See the [0.160.1 reapplication record](REBASE.md#validation-of-the-01601-reapplication) for local checks and untested configurations. Windows runtime and elevated provisioning were not run for this upgrade. The earlier [unelevated Windows deletion limitation](WINDOWS.md#validation-limits) has not been retested at this release and is not claimed resolved. Console's loopback filters and Job retirement were carried from the 0.154.0 patch; their scope is documented in [INTEGRATION.md](INTEGRATION.md#windows-integration).
