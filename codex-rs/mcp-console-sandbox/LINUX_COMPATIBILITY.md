# Linux host compatibility

Managed execution uses native bubblewrap with the requested filesystem and network policy. Namespace or policy failure never selects another backend or an unrestricted target. Caller-selected external enforcement is described below; current integration points are in [INTEGRATION.md](INTEGRATION.md).

## Host requirements

Bubblewrap needs mounted procfs, permission for the selected helper's namespace operations, and the requested seccomp/network enforcement capabilities. A kernel version alone does not establish these capabilities.

| Host condition                                                      | Runner behavior                                                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Fresh namespace-local procfs                                        | Supported; host PIDs are hidden                                                                         |
| Native preflight selects inherited procfs                           | Supported with native namespace and policy enforcement; permitted host PIDs and metadata remain visible |
| `pidfd_open` or `pidfd_send_signal` unavailable or denied           | Native control and direct-child waits provide ordinary retirement                                       |
| Host subreaper, child lists, or namespace PID discovery unavailable | Not required by the runner                                                                              |
| Missing native completion evidence or retirement deadline exceeded  | Nonzero failure and retained private storage                                                            |
| Stopped namespace init without pidfd signalling                     | Retirement can exceed its deadline                                                                      |
| Required namespace or enforcement operations unavailable            | Launch fails                                                                                            |

The executable prerequisite tests restrict actual runner/helper syscalls and inject missing wait status or a stopped namespace init. Independent observers in lifetime tests can require pidfds, child lists, and `NSpid` even though production supervision does not. Filesystem regressions also use nested disposable user and mount namespaces to construct bind aliases, foreign-owned fixtures, and fresh device filesystems.

This command probes namespace permissions:

```console
unshare --user --map-root-user --mount --net --pid --fork true
```

Ubuntu AppArmor can block setup even with `kernel.unprivileged_userns_clone=1` and nonzero `user.max_user_namespaces`. Errors such as `setting up uid map: Permission denied` or `loopback: Failed RTM_NEWADDR: Operation not permitted` can reflect that restriction. Linux CI enables namespaces and removes this restriction on its runner; containers also need permission for native namespace operations.

## Missing read-only paths

An absent read-only entry beneath a writable root is protected without creating a host file or directory. This includes missing workspace metadata. The first missing component stays absent inside and outside the sandbox; attempts to create or replace it fail. Existing read-only entries and deny rules retain their native mounts. Missing deny rules can still require host mount targets.

The namespace init owns a seccomp notification broker for policies containing these absent entries. It copies syscall arguments, pins filesystem references, checks the protected names, and performs permitted mutations. It does not inspect a mutable pathname and then allow the workload to execute that syscall. Normal reads, writes through authorized descriptors, file locking, and Git discovery retain native filesystem behavior. Killing the broker retires the workload, and absent read-only entries require no cleanup after termination.

This enforcement requires namespace-local procfs, `openat2`, seccomp notifications with atomic descriptor injection, and permission to inspect the target's procfs entries. Descriptor operations such as `ftruncate` also require `pidfd_getfd`. Missing-path protection is unavailable on kernel-managed devpts entries, where opening a terminal can create a node without a pathname operation. Unsupported enforcement fails without launching an unrestricted workload. Inherited host procfs remains supported only when the policy needs no missing-path broker.

The policy captures absence before target execution. If the host creates a protected entry during execution, the next brokered filesystem mutation stops the sandbox with a restart diagnostic. This prevents a newly introduced symlink from redirecting access outside the protected name. This also applies to an initially absent native cleanup registry: another sandbox that needs mount cleanup and shares the temporary directory can create that registry and require the earlier sandbox to restart. Existing registries retain native read-only masks. Moving or removing a protected entry's ancestor from inside the sandbox is denied. Host-supplied writable descriptors and host changes after an operation has acquired its references remain part of the trusted caller boundary; the broker does not revoke existing file authority.

Some operations are deliberately unsupported while this broker is active: mutations through procfs, sysfs, or magic-link paths such as `/dev/fd`; `openat2` resolve flags and read-only `openat2` access through those special paths; symlink extended attributes; and ioctls outside the supported terminal and descriptor requests. Pathname and abstract Unix sockets and ordinary IP binding retain the selected network policy. Pathname sockets keep their original address and host filesystem identity; sandbox directory-entry mutations are serialized with their binding. Namespace changes, later seccomp or Landlock installation, BPF operations, alternate syscall ABIs, and unreviewed new kernel syscall numbers are denied. The workload cannot inspect the broker memory or import its descriptors. These restrictions apply only to policies containing missing read-only entries.

## Procfs review

Inherited procfs retains user, mount, and PID isolation but exposes permitted host PIDs and metadata. Process tools that assume procfs PIDs match namespace PIDs may not work there. Upstream may mask inherited procfs when isolating WSL interop. Procfs remains necessary for descriptor hygiene, storage permission changes, native setup, and verified descriptor execution.

When evaluating a host, compare real fresh and inherited procfs views under the requested filesystem and network policies. Use disposable same-user fixtures with synthetic environment, memory, files, control descriptors, and loopback listeners. Check direct file/network access and access through process `environ`, `root`, `cwd`, fd links, memory, signals, ptrace, process-memory syscalls, and namespace entry. Include the actual supervisor. An injected identity mismatch or a successful launch alone does not establish these boundaries.

Unrestricted filesystem access works with restricted, enabled, or managed-proxy networking, while namespace init still owns target setup and retirement. Shared writable host files can let a workload influence helpers, the supervisor, or another unsandboxed process and thereby undermine network or other restrictions. Procfs visibility and process-control access also depend on host credentials, capabilities, and OS policy. Unrestricted files are not an adversarial isolation guarantee; restricted filesystem policies retain their stronger boundary.

## External enforcement

Without a managed proxy, `external-sandbox` selects no native sandbox. The runner supplies stdio, target environment, signals, caller-death observation, and private storage. Linux retirement signals the original process group and waits for the direct child; the outer sandbox must retire detached descendants. With a proxy, upstream native routing and namespace lifecycle apply. Declaring external restricted networking without providing an outer sandbox does not restrict host connections.

`linux_backend` may be omitted, null, or `"bubblewrap"`. Helper selection, verification, and static/GNU packaging are described in [README.md](README.md#build-and-validation).
