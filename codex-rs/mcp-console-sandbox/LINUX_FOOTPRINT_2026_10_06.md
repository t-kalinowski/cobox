# Linux standalone footprint reduction

This pass started from the fetched tip of `mcp-console/sandbox-runner/rust-v0.160.1`, `5bdf256e9`, including the landed Windows consolidation. It compares the net patch with the recorded upstream base, `rust-v0.160.1` at `d27764b82f7118f674371e6d6e76271d9d606edb`. The Landlock removal and namespace hook refactor are separate commits. No Windows backend or companion source changed.

## Interface and ownership

Standalone `linux_backend: "landlock"` is removed. Both protocol-2 transports reject it before native setup, with a removal diagnostic; there is no reinterpretation or fallback. Omitted, null and explicit bubblewrap retain supervision. The shared bootstrap descriptor, fully unrestricted supervision, external-sandbox contract, and permission semantics remain unchanged. Upstream's native Landlock implementation remains intact, and its ordinary policy/app-server-socket guard is restored without a standalone exception.

The native hook is `fn(Vec<String>, OwnedFd) -> !`. Native code finishes namespace setup, mount/capability verification, proxy routing and enforcement before handing over the command and setup descriptor. The standalone package then owns setup acceptance, environment projection, spawning, signal restoration, stdin release and namespace-init control/reaping. It reuses the existing signal utilities and private descriptor I/O; no supervisor, process discovery, policy implementation or generic plugin mechanism was added.

Without a setup descriptor, the upstream fork/exec/wait block is restored byte-for-byte except for the existing stdin-reader release. The SIGPIPE regression demonstrates a behavioral restoration: the former shared `Command::spawn` path reset SIGPIPE and returned 141; ordinary upstream fork/exec preserves the ignored disposition and the fixture reaches exit 23. The standalone target still restores the caller's complete original dispositions and mask after `Command` resets, including SIGCHLD. Init handles direct forwarding signals and SIGCHLD through signalfd, alongside the unchanged control protocol.

`linux-sandbox/src/target_control.rs` is removed from the native crate and owned by the standalone package. `TargetSetupMode`, `TargetSetupHook`, the signal-mask copy derive and the exported wait-status helper are removed. No upstream file can be restored in full while retaining the requested fixes below.

## Remaining upstream hunks

| File under `linux-sandbox/src/` | Reason the standalone package cannot own the remaining change                                                                                                                                                                                                                                                                                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib.rs`                        | Exposes the single post-enforcement handoff. The standalone package cannot intercept the private native inner stage after enforcement without this entry point.                                                                                                                                                                                                                           |
| `linux_run_main.rs`             | Parses and transports the hidden setup descriptor through native re-execs, validates namespace-only setup, and calls the hook after enforcement. The full-access optimization must retain namespace init when that descriptor is present. Native helpers must restore transferred stdin and release their own readers; standalone code cannot close descriptors in those other processes. |
| `launcher.rs`                   | Moves original stdin through a preserved descriptor while bubblewrap's host monitor uses null stdin. This preserves open-file-description identity and makes target closure visible promptly. The native launcher owns bubblewrap's argv and preserved descriptors.                                                                                                                       |
| `bwrap.rs`                      | Retains `require_process_isolation` for supervised full-access launches. Each `--ro-bind-data` operation receives a fresh descriptor because bubblewrap consumes it; the native mount builder owns those descriptors. Both fixes remain shared with ordinary native callers where applicable.                                                                                             |

Landlock, proxy routing/lifecycle, vendored bubblewrap, seccomp policy, Seatbelt policy and Windows implementation sources were checked against their respective starting versions and remain unchanged. Native policy and mount setup were not copied into the standalone package.

## Net footprint against the recorded upstream base

Counts classify paths present in the upstream tree separately from additive paths; added/deleted lines are `git diff --numstat` totals, not a count of moved implementation lines. Documentation, tests and build files are included. The additive totals therefore include this report. The four native files remain necessary, while their semantic changes are smaller.

| Scope                                                                  | Before files | Before + / - | After files | After + / - |
| ---------------------------------------------------------------------- | -----------: | -----------: | ----------: | ----------: |
| Modified upstream Linux files                                          |            4 |     190 / 25 |           4 |    109 / 12 |
| Additive files inside the native Linux crate                           |            1 |       98 / 0 |           0 |       0 / 0 |
| All modified upstream files, including unchanged Windows consolidation |           31 |    843 / 372 |          31 |   762 / 359 |
| All additive files                                                     |           69 |    11006 / 0 |          71 |   11085 / 0 |

The ordinary native fork/exec/wait and Landlock guard were restored; the remaining native change is 109 additions and 12 deletions, down from 190 and 25. The 98-line Console control implementation no longer lives in the upstream crate.

## Validation

Validation used x86_64 Linux 6.8.0-146-generic, Ubuntu 24.04 userspace, Rust 1.95.0 and disabled test retries. GNU runtime checks used a disposable privileged container as UID 0 with namespace operations available; enforcement inside the runner remained enabled. This is not a non-root compatibility claim.

Before implementation, the debug build and all 97 standalone contracts passed. The initial native run passed 279 tests and failed 14 because the container UID did not own the host-mounted fixture cwd; metadata placeholder creation failed before workloads ran. With a root-owned copy of the native test crate bind-mounted only inside the container, all 293 native tests passed. No test assertions, enforcement rules or host sysctls were changed for that correction. Three ignored native tests are internal subprocess fixtures exercised by their enclosing tests.

The new backend-rejection test first failed because the target ran successfully. The ordinary-entry SIGPIPE regression first failed with 141 instead of 23. Both passed after their respective changes.

| Candidate check                                                           | Result                                                                               |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| GNU debug standalone executable suite                                     | 100 passed                                                                           |
| Native Linux, sandboxing and bubblewrap suites                            | 293 passed; 3 internal fixture tests ignored                                         |
| GNU release runner, fixture, native helper and bubblewrap builds          | Passed                                                                               |
| GNU release runner executable suite                                       | 100 passed                                                                           |
| x86_64 musl release runner and bubblewrap                                 | Built; both have no ELF interpreter, NEEDED libraries or symbol-version requirements |
| musl transport, lifecycle and native-entry runtime subset                 | 22 passed; 78 excluded by the selector                                               |
| musl system/bundled helper selection and multiple-file denials            | 4 passed; 96 excluded by the selector                                                |
| Bazel native library and standalone executable/test builds                | Passed                                                                               |
| Bazel-built standalone suite in the container, with materialized runfiles | 100 passed                                                                           |
| Downstream fresh/inherited procfs fixture                                 | 8 policy/network launches passed                                                     |

The complete GNU suites cover managed proxy routing, target loader/environment isolation, descriptor isolation, stdin identity and closure, status and signals, caller/runner death, detached children, readiness/partial/stopped-startup cancellation, private-storage cleanup, unavailable pidfds and incomplete retirement. Native-entry cases explicitly omit the standalone setup descriptor. System and bundled bubblewrap selection and the fresh-descriptor file-mask fix ran in GNU and musl checks. GNU loader interposers were not used against static musl executables.

The musl build followed the pinned release recipe with Zig 0.14.0, musl GCC, pinned libcap/OpenSSL and the stripped helper's embedded SHA-256. These were actual x86_64 runtime checks, not cross-compilation. No aarch64, macOS or Windows runtime checks were performed in this pass.

Host `bazel test` built successfully but its baseline runtime passed 88 and failed 9: AppArmor blocked bundled namespace setup, and repeated copies of read-only Bazel executables failed for the ordinary user. The candidate Bazel suite was therefore run from its real, materialized runfiles in the same namespace-capable container and passed. This does not claim the ordinary host's Bazel runtime limitations were fixed.

The scoped argument-comment lint and `just fix -p mcp-console-sandbox -p codex-linux-sandbox` passed; Clippy reported an existing unused import in the core crate. `just fmt` completed. Its unrelated justfile formatting was discarded. Tests preceded these final formatting/lint passes, following the repository workflow.

## Downstream consumers

Current MCP Console main was fetched and inspected at `ce674459`. Normal managed launches use protocol 2 and omit `linux_backend`; its shipping manifest still pins `6a18b21c2e75a10229a842424403d71cbd1e60ef` from 0.154.0. That manifest and the downstream working tree were not changed.

The current downstream `tests/fixtures/cli/sandbox/procfs.py` supports a runner interface directly. It passed against the candidate debug runner in both actual fresh and inherited procfs views, each with all/denied reads and restricted/enabled networking. It verified host and supervisor environment/memory/control isolation, namespace entry denial, policy replacement denial and unchanged synthetic host state. This exercises the supported downstream runner fixture; it is not a rebuilt, digest-bound Console frontend or shipping-pin adoption.

Before downstream adoption, update `docs/SANDBOX_CONFIGURATION.md`'s Landlock section and the Landlock-specific cases/snapshots in `tests/boundaries/cli/sandbox/test_configuration.py`: replace direct execution, lifecycle-incompatibility, unavailable-ABI and policy-representation expectations with the removal diagnostic. Remove their now-unused `LANDLOCK` capability probe and `without_landlock` fixture if no consumers remain. Retain bubblewrap policy, descriptor, signal, lifecycle, proxy and procfs tests. Non-Linux rejection of the Linux-only field remains valid.
