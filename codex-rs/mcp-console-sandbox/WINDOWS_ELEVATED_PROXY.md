# Pending Windows elevated managed-proxy proposal

MXC managed proxies already landed in PRs [#41](https://github.com/t-kalinowski/cobox/pull/41), [#42](https://github.com/t-kalinowski/cobox/pull/42), and [#43](https://github.com/t-kalinowski/cobox/pull/43). This draft retains the separate proposal to support managed proxies under the elevated account backend. It can be declined without removing the landed MXC support. It does not enable MXC alongside legacy accounts or a registered proxy pool.

## Additional machine resources

Explicit `mcp-console-sandbox setup` provisions the existing base account pair and four additional account pairs under one UAC approval. The additional login names are `McpConsoleProxyOff0`/`McpConsoleProxyOn0` through `3`: eight additional accounts, not four individual accounts. Slots 0–1 deny local access; slots 2–3 allow it. Each slot has a fixed HTTP/SOCKS TCP pair in ports 43180–43187, with capacity for two concurrent proxies per local-access setting.

Machine registration pins the pool to one Windows user and canonical state directory. The owner, accounts, helper executable names, secrets-deny group, and firewall/WFP identifiers remain distinct from Codex. Setup refreshes account passwords and policy; it does not preserve credentials as an invariant. Old base-only installations need an explicit refresh with matching companion/helper binaries before any elevated launch, including proxyless execution, because admission requires the protected registration. No launch, test selection, or status query implicitly authorizes setup or UAC.

`status` reports `managed_proxy_provisioned` independently of base `configured` status. Neither field is a complete firewall audit or free-capacity check. Missing provisioning, foreign ownership, occupied ports, and exhausted/quarantined slots reject admission with diagnostics. Ordinary launch cannot broaden account networking or fall back to an unelevated backend.

## Session policy and ownership

Each companion leases a matching slot and uses Codex's existing shared ingress inside that process. The actual listener ports must match the provisioned exceptions; allocator fallback is rejected before launch. Both TCP ports stay reserved when SOCKS service is disabled. Incoming connections must have both the account SID and the restricting SID registered for that route.

HTTP, HTTPS CONNECT, and SOCKS5 TCP reuse existing domain and full/limited-mode rules. Deny rules take precedence. Limited mode rejects POST, CONNECT, and SOCKS. Trusted host inputs select upstream HTTP/CONNECT proxies; SOCKS retains the existing direct connector. Workload overrides cannot select helpers, accounts, setup policy, proxy exceptions, or host upstream routing. Managed endpoint and bypass values replace conflicting workload variables case insensitively.

Strict local-access slots deny direct TCP/UDP, including loopback, local TCP binding/listening, and UDP receive admission. Local-enabled slots permit native loopback and local binding outside proxy domain filtering; external direct traffic remains restricted by the offline identity. Explicitly allowed local destinations remain accessible through the proxy. Active SOCKS5 UDP and Unix-socket options remain rejected; an unused UDP flag with SOCKS disabled retains the landed behavior.

Proxyless restricted execution continues to use the base offline account without proxy-port exceptions. MXC selection retains the landed incompatibility with legacy account installations; this proposal also rejects orphaned slot accounts and registered pools. It does not import the former protected-state migration or mixed-backend coexistence design.

## Retirement and recovery

The protected configuration lock serializes explicit setup and account admission. Atomic durable lease files claim slots and quarantine them after uncertain retirement. Setup refuses outstanding leases. The native Job remains responsible for workload retirement. After its receipt, the companion stops proxy resources, drops the runtime, removes private storage, verifies endpoint closure, and releases the lease. A cleanup failure withholds success and retains the lease.

There is no automatic force-reclaim path. A missing companion PID does not prove retirement. Recovery requires stopping Console, establishing that old Jobs and listeners are gone (reboot if needed), removing retained private storage identified by diagnostics, and removing only the corresponding lease files from the registered directory. Never delete account state merely to bypass quarantine.

## Validation and review status

The consolidation is based on default branch commit `c851aa4dd9` (including the `windows_backend` naming update in #45) and the pending work from old stack tip `21dc37ad19f8ab906483d62b7c9ee12ac646e615`. The old stack's [validation ledger](https://github.com/t-kalinowski/cobox/blob/21dc37ad19f8ab906483d62b7c9ee12ac646e615/codex-rs/mcp-console-sandbox/WINDOWS_PROXY_VALIDATION.md) is historical evidence, not acceptance of this new combination. The consolidated draft records current checks and links the unresolved historical review threads. Closing the superseded PRs does not resolve those findings.

The executable fixtures make real native network and process calls through the public environment transport. Restricted-token tests alone do not establish dedicated-account enforcement. Native account/pool acceptance is opt-in, requires explicitly provisioned matching state and exclusive access, and must be reported separately from ordinary package tests. Do not run the provisioning acceptance test as an ordinary regression check.

For a future adoption decision, verify dedicated-account HTTP/CONNECT/SOCKS policy, direct IPv4/IPv6 TCP/UDP with positive controls, concurrent slots and proxyless execution, account/route forgery, port conflicts, owner death, descendants, and cleanup quarantine. Retain limitations for unavailable external/inbound controls, actual Ctrl+C, different-user ownership, and fresh-slot partial provisioning. Resolver parity and MCP Console configuration admission/pinning remain separate work.
