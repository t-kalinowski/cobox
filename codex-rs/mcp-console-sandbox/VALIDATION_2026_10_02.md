# Windows and WSL audit, 2026-10-02

The fork's default branch is `mcp-console/sandbox-runner/rust-v0.154.0`. This audit starts at `6a18b21c2e75a10229a842424403d71cbd1e60ef`, against upstream `rust-v0.154.0` (`6b9826e3aa83b1a5947db50f4332cb9c65f1b340`). Follow-up commits are on `codex/windows-runner-validation`. The default branch still pointed to the audited commit when checked after validation.

## Policy review

The architecture follows the fork's extraction policy: configuration and lifetime coordination live in `mcp-console-sandbox`; native hooks remain in the existing platform sandbox crates. Windows resource naming and Job retirement have separate small modules. Windows and Linux normal/build dependency trees contain no `codex-core`; the pinned-base diff contains no changes to core or protocol source. The native Linux test graph does depend on core, which is distinct from the runner's runtime graph.

The Windows review covered `a7ff9c348d`, `1da6389aef`, `6cdecd613b`, `cd4f74a156`, `3855cf3d24`, `d48940917f`, and `6a18b21c2e`. Two commits exceed AGENTS.md's 800-line change guidance: `1da6389aef` has 711 additions and 150 deletions; `6a18b21c2e` has 683 additions and 216 deletions. Their landed history is preserved. Follow-up work is split into smaller commits.

The inventory previously omitted the Windows integration surface. It now records the identity, provisioning, helper, desktop, firewall/WFP, stdio, and Job hooks. The unused public wrapper-arguments hook was removed, returning `wrapper.rs` to the pinned upstream implementation. No dependencies, policy models, native policy profiles, or application defaults were added by these fixes.

## Fixes and regressions

- Windows target exit `0xffffffff` was confused with a missing backend receipt and returned 125. The cancellation-aware bridge now represents missing receipts separately; the original Codex bridge preserves its return convention. Public contracts exercise zero, negative, and exception-style exit codes with private storage and an open caller stdin.
- Explicit Windows setup now creates the helper directory before UAC. Initial provisioning had left an administrator-owned `.sandbox-bin`, causing ordinary refresh to fail with access denied. Recreating the empty directory as the caller confirmed the diagnosis. The fixed launcher was rebuilt and idempotent setup verified; a second fresh account provisioning was not performed.
- Fedora bubblewrap consumed a reused `--ro-bind-data` descriptor, then read an unrelated reopened descriptor for a later file mask. `bwrap.rs` now retains a separate descriptor per operation. This small shared-backend correctness fix preserves the requested policy; it also applies to ordinary native callers. The regression exercises two denied files with system and bundled helpers.
- Portable Unix fixtures normalize documentation line endings, scope a glob scan to an owned directory, and accept `cat` 's executable-name prefix on both distributions. Unused leaf imports and a missing argument comment were fixed.
- Windows contracts now cover binary stdin/EOF, denied creation, root and caller death, descendant retirement, retained storage after runner loss, unsupported policy, and private cleanup. The workflow builds both companions and runs debug/release contracts. An opt-in elevated network test preserves the failing enforcement check described below.

## Executed validation

All Cargo runs used Rust 1.95.0 and Nextest 0.9.144 with retries disabled. The Windows host reports build 26200. Both WSL 2 distributions use x86_64 Linux `6.18.40.1-microsoft-standard-WSL2`; sources and Cargo outputs were on their native Linux filesystems. No namespace restrictions or sandbox enforcement were disabled.

| Host                      | Debug runner                             | Release runner | Native suites                     |
| ------------------------- | ---------------------------------------- | -------------- | --------------------------------- |
| Windows, MSVC             | 13 passed                                | 13 passed      | Failures and accommodations below |
| Ubuntu 26.04.1 LTS, WSL 2 | 97 passed                                | 97 passed      | 219 passed, 1 ignored helper test |
| Fedora 44, WSL 2          | 96 passed plus the new regression passed | 97 passed      | 219 passed, 1 ignored helper test |

Ubuntu's first release run and Fedora's first debug run encountered startup fault-injection timeouts while several builds and suites were running. Ubuntu also reported incomplete retirement in a cancellation checkpoint. Targeted serial reruns passed, and the final complete suites passed serially without changing deadlines or retry settings. The concurrent failures remain part of the record; these results do not establish reliability under equivalent load.

The core commands were:

```sh
cargo build --locked -p codex-mcp-console-sandbox -p codex-bwrap --bins
just test --locked -p codex-mcp-console-sandbox --retries 0 --test-threads 1
just test --locked -p codex-sandboxing -p codex-linux-sandbox -p codex-bwrap --retries 0
cargo build --locked --release -p codex-mcp-console-sandbox -p codex-bwrap --bins
```

Linux contract runs set `CARGO_BIN_EXE_bwrap` to the absolute helper path. Release contracts additionally set `CARGO_BIN_EXE_mcp-console-sandbox` to the release runner, while retaining the debug harness. Native suites used the built helper where needed. Windows release builds included `mcp-console-sandbox-setup` and `mcp-console-sandbox-runner`; contracts used `just test --release`.

## Windows failures and limits

**Windows enforcement is not signed off.** The restricted-token backend deleted files outside writable roots, including under `:read-only`. The native `legacy_workspace_write_delete_is_limited_to_writable_roots` failure also reproduced against the pinned upstream release. Successful creation denial does not establish deletion isolation.

Explicit UAC-approved setup provisioned separate Console accounts. Status then reported configured state and available helpers. Existing Codex account identities remained present; Console and Codex firewall rule names were separate. Elevated online/offline account launches passed 512 KiB binary stdin/EOF, denied creation, 32-bit exit codes, private cleanup, root-exit descendant retirement, and caller death. These checks used compiled fixtures and retained process handles.

However, the elevated offline account connected to a live loopback TCP listener. The online positive control also connected. This reproduced with both PowerShell and the compiled `elevated_offline_account_denies_loopback_tcp` regression, despite enabled firewall profiles and installed Console rules. The opt-in test is ignored by default because it requires explicit machine provisioning; it was explicitly executed here and failed. No broader network-isolation claim follows from setup status. See [WINDOWS.md](WINDOWS.md#validation-limits) for its command.

The initial combined Windows run reported 190 passes, two failures and one timeout across 193 tests, with three ignored tests. Some native PowerShell tests returned early because their fixed installation lookup did not find PowerShell 7. The control-pipe descendant failure also reproduced upstream, then passed when the actual Python executable directory replaced the Windows app execution alias on PATH. That focused run passed all five bridge/product/control-pipe tests. The original elevated native test uses a fresh state directory and timed out waiting for its own interactive setup; the separate Console integration run above used the explicitly provisioned stable state directory.

The five PowerShell-dependent native tests were then exercised using the bundled PowerShell 7 runtime. A temporary test-only locator selected that installation; the source change was restored afterward. Two passed and three failed. Normal-exit descendant preservation and the ConPTY descendant-start failure also reproduced on the pinned upstream implementation with the same locator. The cancellation test exceeded its ten-second assertion twice on the branch (about thirteen seconds), while its baseline run passed. That timing difference remains unresolved. These results supersede the earlier apparent passes caused by the missing-runtime early return; they are not a clean native Windows suite.

## Build and lint limits

Windows Bazel reached third-party compilation but failed in `ctor 1.0.6` with `E0463: can't find crate for linktime_proc_macro`; no Bazel runtime tests executed. This is recorded as a failed build gate. Cargo debug/release builds succeeded. Linux Bazel, macOS, ARM, musl artifacts, hosted CI, and downstream adoption were not exercised in this audit.

Scoped `just fix` passed for the runner and Windows sandbox on Windows and for the runner and Linux sandbox on Ubuntu. The argument-comment lint passed on Ubuntu after fixing the leaf comment. Its packaged driver emitted dependency warnings. The Linux copies have no VCS metadata, so Clippy fixes used `--allow-no-vcs`. Windows runner Clippy with `--all-targets -- -D warnings`, `just fmt`, Markdown formatting, Actionlint, and `git diff --check` passed.
