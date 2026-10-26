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

The executable prerequisite tests restrict actual runner/helper syscalls and inject missing wait status or a stopped namespace init. Independent observers in lifetime tests can require pidfds, child lists, and `NSpid` even though production supervision does not.

This command probes namespace permissions:

```console
unshare --user --map-root-user --mount --net --pid --fork true
```

Ubuntu AppArmor can block setup even with `kernel.unprivileged_userns_clone=1` and nonzero `user.max_user_namespaces`. Errors such as `setting up uid map: Permission denied` or `loopback: Failed RTM_NEWADDR: Operation not permitted` can reflect that restriction. Linux CI enables namespaces and removes this restriction on its runner; containers also need permission for native namespace operations.

## Mount target recovery

Missing read-only and denied entries beneath writable roots can require empty host files or directories as native mount targets. They remain visible while a sandbox runs. Normal completion removes the targets created for that session after their last registered owner exits.

Before planning mounts, a later bubblewrap-backed launch also recovers recorded targets left by termination of every cleanup process. This works across workspaces when the launches use the same helper temporary directory and user. The native registry records each created path and its device, inode, type, and change time. Recovery removes only a matching empty target with no live owner. Pre-existing paths, replacement files or directories, symlinks, and populated or otherwise changed targets are preserved. Cleanup never recursively removes a directory.

Ownership uses a file lock shared by the native cleanup supervisor and namespace init. The lock stays held while either owner retains its descriptor. Workload execution closes the inherited descriptor. Native registry protection remains part of the filesystem policy.

Recovery covers recorded mount targets, not private session storage or arbitrary empty metadata names. Older records without target identity cannot authorize deletion. Termination between target creation and publication of its record can still leave an unrecorded target; losing the registry also loses recovery information. Inaccessible stale paths are preserved so they do not prevent an unrelated launch.

## Procfs review

Inherited procfs retains user, mount, and PID isolation but exposes permitted host PIDs and metadata. Process tools that assume procfs PIDs match namespace PIDs may not work there. Upstream may mask inherited procfs when isolating WSL interop. Procfs remains necessary for descriptor hygiene, storage permission changes, native setup, and verified descriptor execution.

When evaluating a host, compare real fresh and inherited procfs views under the requested filesystem and network policies. Use disposable same-user fixtures with synthetic environment, memory, files, control descriptors, and loopback listeners. Check direct file/network access and access through process `environ`, `root`, `cwd`, fd links, memory, signals, ptrace, process-memory syscalls, and namespace entry. Include the actual supervisor. An injected identity mismatch or a successful launch alone does not establish these boundaries.

Unrestricted filesystem access works with restricted, enabled, or managed-proxy networking, while namespace init still owns target setup and retirement. Shared writable host files can let a workload influence helpers, the supervisor, or another unsandboxed process and thereby undermine network or other restrictions. Procfs visibility and process-control access also depend on host credentials, capabilities, and OS policy. Unrestricted files are not an adversarial isolation guarantee; restricted filesystem policies retain their stronger boundary.

## External enforcement

Without a managed proxy, `external-sandbox` selects no native sandbox. The runner supplies stdio, target environment, signals, caller-death observation, and private storage. Linux retirement signals the original process group and waits for the direct child; the outer sandbox must retire detached descendants. With a proxy, upstream native routing and namespace lifecycle apply. Declaring external restricted networking without providing an outer sandbox does not restrict host connections.

`linux_backend` may be omitted, null, or `"bubblewrap"`. Helper selection, verification, and static/GNU packaging are described in [README.md](README.md#build-and-validation).
