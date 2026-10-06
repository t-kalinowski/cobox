# Upstream sandbox changes

This is a curated record of upstream changes inherited by the standalone sandbox runner. Add a section for each release upgrade, newest first, with the previous and new tags, source links, and effects on the runner's enforcement or compatibility. Check the production callers when selecting entries, and record adaptations to the standalone integration separately. [INTEGRATION.md](INTEGRATION.md) describes the current patch; [REBASE.md](REBASE.md) records the upgrade procedure and validation.

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
- Private desktops remain owned by the calling process across short-lived helper exits. Upstream now requires private desktops for elevated and unelevated launches; the standalone CLI adaptation is described below. [#44658](https://github.com/openai/codex/pull/44658), [#46554](https://github.com/openai/codex/pull/46554).
- Account setup repairs expired passwords. Runtime ACL repair handles existing children and paths beyond the legacy Windows path limit. Safe directory opens resolve ordinary Windows 10 drive-letter aliases while continuing to reject filesystem reparse points. [#46043](https://github.com/openai/codex/pull/46043), [#46241](https://github.com/openai/codex/pull/46241), [#49058](https://github.com/openai/codex/pull/49058), [#47672](https://github.com/openai/codex/pull/47672).
- Background setup helpers and unelevated commands launched with pipes suppress console-window allocation. The standalone CLI uses the updated native session backend. [#49164](https://github.com/openai/codex/pull/49164), [#49386](https://github.com/openai/codex/pull/49386).
- Native uninstall removes sandbox profiles before their accounts and preserves accounts for retry when profile deletion fails. The product-scoped cleanup integration carries this behavior forward for Console identities. [#45799](https://github.com/openai/codex/pull/45799).

### Standalone integration adaptations

- Explicit Landlock selection remains available through trusted standalone setup, with the previous supported-policy checks. It does not mask host app-server sockets. Bubblewrap provides that isolation, and ordinary native invocations retain upstream's bubblewrap requirement for restricted filesystems. See the [Landlock boundary](LINUX_COMPATIBILITY.md#landlock-boundary).
- The runner passes the prepared managed-network context through Linux setup and supplies the native executor platform to proxy configuration. Its Linux hooks accommodate the new namespace flags while retaining isolated PID-namespace supervision. Sandbox selection uses the updated native API. [#45534](https://github.com/openai/codex/pull/45534), [#46334](https://github.com/openai/codex/pull/46334), [#47989](https://github.com/openai/codex/pull/47989), [#45730](https://github.com/openai/codex/pull/45730).
- Windows companion helpers call the setup implementation extracted into the native library. The runner keeps private desktops by default and preserves its explicit native CLI desktop opt-out through the existing named-desktop session API, scoped to Console. [#45169](https://github.com/openai/codex/pull/45169), [#46554](https://github.com/openai/codex/pull/46554). Current changed paths are listed in [INTEGRATION.md](INTEGRATION.md#windows-integration).

### Validation

See the [0.160.1 reapplication record](REBASE.md#validation-of-the-01601-reapplication) for local checks and untested configurations. Windows runtime and elevated provisioning were not run for this upgrade. The earlier [unelevated Windows deletion limitation](WINDOWS.md#validation-limits) has not been retested at this release and is not claimed resolved. Console's loopback filters and Job retirement were carried from the 0.154.0 patch; their scope is documented in [INTEGRATION.md](INTEGRATION.md#windows-integration).
