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
- Windows contracts now cover binary stdin/EOF, denied creation, root and caller death, descendant retirement, retained storage after runner loss, unsupported policy, and private cleanup. The workflow builds both companions and runs debug/release contracts. Opt-in elevated network tests cover the enforcement correction described below.

## Executed validation

All Cargo runs used Rust 1.95.0 and Nextest 0.9.144 with retries disabled. The Windows host reports build 26200. Both WSL 2 distributions use x86_64 Linux `6.18.40.1-microsoft-standard-WSL2`; sources and Cargo outputs were on their native Linux filesystems. No namespace restrictions or sandbox enforcement were disabled.

| Host                      | Debug runner                             | Release runner | Native suites                     |
| ------------------------- | ---------------------------------------- | -------------- | --------------------------------- |
| Windows, MSVC             | 15 passed plus 2 elevated regressions    | 17 passed      | Failures and accommodations below |
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

Initially, the elevated offline account connected to a live loopback TCP listener. The online positive control also connected. This reproduced with both PowerShell and the compiled `elevated_offline_account_denies_loopback_tcp` regression, despite enabled firewall profiles and installed Console rules. The opt-in test is ignored by default because it requires explicit machine provisioning; it was explicitly executed here and failed before the correction below. No broader network-isolation claim follows from setup status. See [WINDOWS.md](WINDOWS.md#validation-limits) for its command.

The initial combined Windows run reported 190 passes, two failures and one timeout across 193 tests, with three ignored tests. Some native PowerShell tests returned early because their fixed installation lookup did not find PowerShell 7. The control-pipe descendant failure also reproduced upstream, then passed when the actual Python executable directory replaced the Windows app execution alias on PATH. That focused run passed all five bridge/product/control-pipe tests. The original elevated native test uses a fresh state directory and timed out waiting for its own interactive setup; the separate Console integration run above used the explicitly provisioned stable state directory.

The five PowerShell-dependent native tests were then exercised using the bundled PowerShell 7 runtime. A temporary test-only locator selected that installation; the source change was restored afterward. Initially two passed and three failed. Normal-exit descendant preservation and the ConPTY descendant-start failure also reproduced on the pinned upstream implementation with the same locator. The cancellation test exceeded its ten-second assertion twice on the branch (about thirteen seconds), while its baseline run passed. The controlled-workspace rerun and fixture corrections below explain these results; the earlier missing-runtime early returns were not valid coverage.

## Build and lint limits

Windows Bazel reached third-party compilation but failed in `ctor 1.0.6` with `E0463: can't find crate for linktime_proc_macro`; no Bazel runtime tests executed. This is recorded as a failed build gate. Cargo debug/release builds succeeded. Linux Bazel, macOS, ARM, musl artifacts, hosted CI, and downstream adoption were not exercised in this audit.

Scoped `just fix` passed for the runner and Windows sandbox on Windows and for the runner and Linux sandbox on Ubuntu. The argument-comment lint passed on Ubuntu after fixing the leaf comment. Its packaged driver emitted dependency warnings. The Linux copies have no VCS metadata, so Clippy fixes used `--allow-no-vcs`. Windows runner Clippy with `--all-targets -- -D warnings`, `just fmt`, Markdown formatting, Actionlint, and `git diff --check` passed.

## Direct official-release comparison

The installed npm distribution of official `codex-cli 0.160.0` was exercised directly through `codex sandbox`. Explicit `windows.sandbox` and a command-line permissions profile selected each backend, filesystem profile, and network setting. `whoami /user` confirmed Codex's online/offline accounts and Console's separate accounts. The comparison did not build a replacement Codex CLI or change the user's configuration. The following table records the behavior before the loopback correction.

| Probe                                                             | Official 0.160.0   | Extracted runner   |
| ----------------------------------------------------------------- | ------------------ | ------------------ |
| Elevated online TCP to live IPv4 loopback listener                | Connected          | Connected          |
| Elevated offline TCP to the same listener                         | Connected, failure | Connected, failure |
| Elevated online TCP to `1.1.1.1:443`                              | Connected          | Connected          |
| Elevated offline TCP to `1.1.1.1:443`                             | Blocked            | Blocked            |
| Elevated deletion outside workspace and of `.git`, controlled ACL | Denied             | Denied             |
| Same elevated deletion under inherited Public ACLs                | Allowed            | Allowed            |
| Same deletion with restricted-token backend, controlled ACL       | Allowed, failure   | Allowed, failure   |

The controlled directory was a new test-owned directory with inherited permissions disabled, full control for its owner/SYSTEM/Administrators, and read/execute for Authenticated Users. No existing user directory ACL was changed. Public's default inherited ACL grants interactive/batch/service users broader deletion rights. Windows permits deletion using parent-directory delete-child permission. Thus the elevated filesystem result depends on host ACLs, while the legacy backend's same-user deletion failure survives the controlled comparison. The external-network positive control narrows the network failure to loopback; the offline account's external TCP block is functioning.

The versioned runner had hardcoded `use_private_desktop: false`, and native `run` defaulted its desktop flag to false. Both now default to private desktops, matching the official default; the native CLI preserves an explicit opt-out. Compiled fixture tests inspect the target's actual desktop name. All 15 ordinary Windows executable contracts passed after this correction.

Repeating the native PowerShell tests in the small controlled workspace made the cancellation test pass (9.6 seconds) without changing its ten-second assertion. The prior comparison included different workspace ACL traversal costs. Normal-exit capture preservation and the ConPTY descendant-start test still failed. An experimental backport of upstream `50d9c5deac` (piped processes without a console) did not repair capture preservation and was reverted. Temporary test locators and diagnostics were also restored.

Capture diagnostics narrowed the normal-exit failure: the root exited after 2.89 seconds, but capture joined the output readers until 32.84 seconds, after the descendant's 30-second release deadline expired. The child held inherited output handles. Official `codex sandbox` also waited through the corresponding descendant deadline, for both elevated and unelevated modes; the same fixture returned promptly outside the sandbox. This is an output-drain wait, not evidence that Console's retirement Job killed a preserved Codex descendant.

## Loopback enforcement correction

The installed firewall rules already requested offline loopback denial, but did not enforce it on this host. Existing native WFP filters covered ICMP, DNS, and SMB rather than general loopback TCP/UDP. A separate `windows-sandbox-rs/src/wfp/loopback.rs` module now installs account-scoped filters at `ALE_AUTH_CONNECT_V4` and `ALE_AUTH_CONNECT_V6`, matching the loopback flag and blocked remote-port ranges. Native proxy-port exceptions and the local-binding setting are retained. Setup version 6 requires refresh; failure to install the filters prevents successful setup. Reconfiguration and uninstall remove only the selected product's loopback filters.

The user approved the setup refresh. Executed regressions then passed TCP and UDP on both IPv4 and IPv6, with online positive controls. UDP verifies host receipt: Windows can report a successful send while dropping the packet. The direct official-release comparison repeated all four cases: official 0.160.0 still delivered offline traffic; the corrected Console runner blocked it. Both continued to block external offline TCP to `1.1.1.1:443`, and both online accounts connected. No Codex accounts or rules were changed.

The port-complement regression and four existing WFP tests passed. All 17 release runner contracts passed, including both opt-in elevated regressions; debug passed the 15 ordinary contracts and both elevated regressions. Release elevated online/offline checks also passed 512 KiB binary stdin/EOF, denied creation, all three exit codes, root-exit retirement, caller death, and private storage cleanup. Debug and release status both reported configured accounts and available helpers. Live proxy exception/reconfiguration and uninstall were not exercised; those remain validation limits. Restricted-token deletion remains separate from this network correction.

## Native PowerShell fixture corrections

The ConPTY lifecycle fixture requested closed stdin. This closed the pseudoconsole input pipe immediately; PowerShell exited with `STATUS_CONTROL_C_EXIT` (`0xC000013A`) before creating either descendant output file. Keeping terminal input open made both terminate and preserve cases pass. The correction changes the fixture's terminal lifetime, not the native backend.

The capture fixture released the descendant only after capture returned, but capture drained output handles inherited by that descendant. It now retains the root process handle before allowing root execution to continue, waits for that handle to signal exit, and only then releases the descendant. The existing output, exit, survival-marker, and descendant-exit assertions remain. This removes the circular wait while independently proving survival after root exit. Capture preservation, cancellation, ConPTY lifecycle, and interactive PowerShell input/output all passed together after these corrections. Native tests now also find PowerShell on PATH, avoiding silent early returns for a nonstandard installation.

The final native package run used the actual PowerShell and Python executable directories on PATH and the controlled workspace: **185 passed, one failed, four skipped**. All five PowerShell-dependent tests executed and passed. The remaining failure is `legacy_workspace_write_delete_is_limited_to_writable_roots`, also reproduced with official 0.160.0. Three upstream tests remained ignored; the fourth skip excluded `elevated_non_tty_cmd_forwards_env_output_and_exit` because it creates fresh Codex state and requests another interactive machine setup. The separate provisioned Console elevated checks above passed. This is not a clean native security gate.

The corrected capture fixture also passed from the normal repository workspace (13.2 seconds including ACL preparation). Its new root-start observer allows 30 seconds for setup; the existing target execution timeout remains ten seconds.

## Deletion access-check diagnosis

The remaining deletion failure is not an inability of Windows to enforce deletion permissions. A compiled `CreateFileW` probe requested individual access bits without deleting anything, against a fresh owned directory with protected ACLs. For both official 0.160.0 and Console, under both `:read-only` and `:workspace`, legacy mode denied `FILE_WRITE_DATA` but granted `DELETE` on the outside file and `FILE_DELETE_CHILD` on its parent. Combining `DELETE | FILE_WRITE_DATA` was denied. Elevated mode denied all these write/deletion requests and allowed reading the same objects.

An independent Win32 token experiment isolated `WRITE_RESTRICTED`, which the native backend passes to `CreateRestrictedToken`. Both experimental tokens used the same base token, `DISABLE_MAX_PRIVILEGE | LUA_TOKEN`, and an Authenticated Users restricting SID; the test objects granted that SID read/execute only. Adding `WRITE_RESTRICTED` allowed both deletion rights while denying data writes. Omitting only that flag denied both deletion rights and still allowed reads. Thus full restricting checks can enforce the intended deletion boundary on this host.

That experiment is not a validated one-line backend fix. For a second file readable only through the original user's permissions, the write-restricted token allowed reading but the fully restricted token denied it. Production read permissions, executable loading, IPC, and desktop access therefore need validation before changing token construction. The inherited backend's token/ACL design has an enforcement gap; reproducing it in official Codex establishes provenance, not acceptability.

Architecture references: [OpenAI's Windows sandbox design, May 13, 2026](https://openai.com/index/building-codex-windows-sandbox/), [current Windows sandbox documentation](https://learn.chatgpt.com/docs/windows/windows-sandbox), and Microsoft's [restricted-token API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken) and [file access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights). The blog does not pin its architecture to a release version; direct execution above establishes the observed release behavior on this host.

## Upstream issue and newer release check

The deletion failure that persists under the controlled ACL belongs to the unelevated fallback, then called `restricted-token` by Console and `legacy` in native test names. Console's native CLI and versioned transport both default to `elevated`; the newer-release probe explicitly selected `unelevated`. Both elevated implementations denied deletion in the controlled test. Their separate Public-directory failure depended on broad inherited host permissions and must not be conflated with the fallback's failure under restrictive ACLs. Console's public spelling is now `unelevated`.

[OpenAI Codex issue #32915](https://github.com/openai/codex/issues/32915), filed July 14, 2026, reports the same legacy deletion-boundary failure, including the native `legacy_workspace_write_delete_is_limited_to_writable_roots` regression. As checked October 2, it remains open with no comments or linked upstream fix. This establishes a public report, not a maintainer acknowledgment or remediation commitment.

The latest stable release at this check is [0.160.0](https://github.com/openai/codex/releases/tag/rust-v0.160.0), published October 1 and already exercised above. The newer official [0.162.0-alpha.7](https://github.com/openai/codex/releases/tag/rust-v0.162.0-alpha.7), published October 2, was downloaded into the ignored test directory and executed directly without replacing the installed CLI. Its reported version matched the release. Under explicit `windows.sandbox="unelevated"`, both `:read-only` and `:workspace` profiles reproduced the access-check failure against the controlled outside file and parent directory: data writes denied, `DELETE` and parent `FILE_DELETE_CHILD` granted. The probe only opened and closed handles; it did not delete files. A newer prerelease therefore does not resolve this legacy gap on the tested host.

The alpha and upstream main at `0df76892b13277eca943a6507c7964e4b0f99a5b` retain `WRITE_RESTRICTED` in token construction. The issue timeline also references [a third-party fork's PR #53](https://github.com/balajirajput96/codex/pull/53), merged in that fork on August 22. Its proposed correction removes Everyone and Logon restricting SIDs while retaining `WRITE_RESTRICTED`; it is not an upstream Codex fix, and its claimed deletion protection was not validated here. The independent token experiment above already reproduced deletion access with an Authenticated Users restricting SID and no Everyone or Logon restricting SID.
