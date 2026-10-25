# Linux host compatibility

Managed execution uses native bubblewrap with the requested filesystem and network policy. Namespace or policy failure never selects another backend or an unrestricted target. Caller-selected external enforcement is described below; current integration points are in [INTEGRATION.md](INTEGRATION.md).

## Host requirements

Bubblewrap needs mounted procfs, permission for the selected helper's namespace operations, and the requested seccomp/network enforcement capabilities. A kernel version alone does not establish these capabilities.

| Host condition                                                      | Runner behavior                                                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Fresh namespace-local procfs                                        | Supported; host PIDs are hidden                                                                         |
| Native preflight selects inherited procfs                           | Supported with native namespace and policy enforcement; permitted host PIDs and metadata remain visible |
| `SO_PASSPIDFD` or `pidfd_send_signal` unavailable or denied         | Native control and direct-child waits provide ordinary retirement                                       |
| Host subreaper, child lists, or namespace PID discovery unavailable | Not required by the runner                                                                              |
| Missing native completion evidence or retirement deadline exceeded  | Nonzero failure and retained private storage                                                            |
| Stopped namespace init without pidfd signalling                     | Retirement can exceed its deadline                                                                      |
| Required namespace or enforcement operations unavailable            | Launch fails                                                                                            |

The executable prerequisite tests restrict actual runner/helper syscalls and inject missing wait status or a stopped namespace init. Independent observers in lifetime tests can require pidfds, child lists, and `NSpid` even though production supervision does not.

This command probes namespace permissions:

```console
unshare --user --map-root-user --mount --net --pid --fork true
```

Ubuntu AppArmor can block setup even with `kernel.unprivileged_userns_clone=1` and nonzero `user.max_user_namespaces`. Errors such as `setting up uid map: Permission denied` or `loopback: Failed RTM_NEWADDR: Operation not permitted` can reflect that restriction. Linux CI enables namespaces and removes this restriction on its runner; containers also need permission for native namespace operations.

## Older distributions

Use the static musl runner and adjacent bundled `bwrap` described in [README.md](README.md#build-and-validation). These artifacts avoid host glibc, libcap, and OpenSSL version requirements. The target command still needs libraries compatible with its distribution. Older system bubblewrap packages can lack required options; native helper selection already uses the bundle when no suitable system helper is found. On kernels without `faccessat2`, helper trust checks can also reject a system helper whose writability cannot be established.

Landlock is not required by this path. It first appeared in [Linux 5.13](https://docs.kernel.org/userspace-api/landlock.html#kernel-support), so it is not a general solution for older kernels. The retained legacy entry point rejects filesystem-restricted execution and the standalone target-setup hook. It cannot supply the runner's PID-namespace descendant retirement. Selecting it would require changes to enforcement and lifecycle behavior, rather than enabling an existing equivalent backend.

The release workflow checks the userspaces corresponding to the [Posit Connect distribution list](https://docs.posit.co/connect/admin/getting-started/requirements/#linux-support): AlmaLinux 8, 9, and 10 for the RHEL families; SLE BCI 15.6 and 15.7 for SLES 15 SP6 and SP7; openSUSE Leap 15.6; Ubuntu 22.04, 24.04, and 26.04; and Debian 13. All run on x86-64. ARM64 checks cover AlmaLinux 10 and Ubuntu 24.04 and 26.04. The checks use the bundled helper as an unprivileged user and verify filesystem permissions, blocked networking, exit status, private-storage cleanup, and detached-child retirement.

Run the same checks with already-built musl artifacts, including the fixture binary:

```console
bash .github/scripts/test-sandbox-linux-distros.sh \
  codex-rs/target/x86_64-unknown-linux-musl/release almalinux:8 ubuntu:22.04
```

These containers share the test host's kernel. AlmaLinux and SLE BCI checks do not certify native RHEL or SLES installations, kernel backports, or their security-policy defaults. The executable prerequisite suite separately exercises existing compatibility paths with newer syscalls and pidfd readiness unavailable; this also does not replace testing on the deployment's actual kernel. Hosts that deny required namespace or seccomp operations remain unsupported for managed execution.

## Procfs review

Inherited procfs retains user, mount, and PID isolation but exposes permitted host PIDs and metadata. Process tools that assume procfs PIDs match namespace PIDs may not work there. Upstream may mask inherited procfs when isolating WSL interop. Procfs remains necessary for descriptor hygiene, storage permission changes, native setup, and verified descriptor execution.

When evaluating a host, compare real fresh and inherited procfs views under the requested filesystem and network policies. Use disposable same-user fixtures with synthetic environment, memory, files, control descriptors, and loopback listeners. Check direct file/network access and access through process `environ`, `root`, `cwd`, fd links, memory, signals, ptrace, process-memory syscalls, and namespace entry. Include the actual supervisor. An injected identity mismatch or a successful launch alone does not establish these boundaries.

Unrestricted filesystem access works with restricted, enabled, or managed-proxy networking, while namespace init still owns target setup and retirement. Shared writable host files can let a workload influence helpers, the supervisor, or another unsandboxed process and thereby undermine network or other restrictions. Procfs visibility and process-control access also depend on host credentials, capabilities, and OS policy. Unrestricted files are not an adversarial isolation guarantee; restricted filesystem policies retain their stronger boundary.

## External enforcement

Without a managed proxy, `external-sandbox` selects no native sandbox. The runner supplies stdio, target environment, signals, caller-death observation, and private storage. Linux retirement signals the original process group and waits for the direct child; the outer sandbox must retire detached descendants. With a proxy, upstream native routing and namespace lifecycle apply. Declaring external restricted networking without providing an outer sandbox does not restrict host connections.

`linux_backend` may be omitted, null, or `"bubblewrap"`. Helper selection, verification, and static/GNU packaging are described in [README.md](README.md#build-and-validation).
