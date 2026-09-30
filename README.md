# cobox

cobox extracts the native sandbox from [OpenAI's Codex](https://github.com/openai/codex) into a standalone executable, with more controls exposed for data science workflows in [mcp-console](https://github.com/t-kalinowski/mcp-console). The build targets the sandbox and its required platform helpers, without the coding agent.

**Use [`mcp-console sandbox`](https://github.com/t-kalinowski/mcp-console/blob/main/docs/SANDBOX_CONFIGURATION.md) for everyday use.** It provides packaging and installation workflows, application policy, and an ergonomic, stable command-line interface. MCP Console integrates the runner's process supervision and temporary-directory cleanup into its broader runtime lifecycle. The low-level interfaces in this repository have no stability guarantee.

`codex sandbox` runs commands under the agent's sandbox, but it is part of the full CLI and does not expose all the controls this integration needs. Data science runtimes need explicit control over their environment, filesystem and network access, process lifetime, and selected OS facilities. This fork adds a standalone configuration interface, lifecycle controls, and caller-supplied macOS Seatbelt rules so MCP Console can grant the permissions its runtimes need without changing the upstream profiles for everyone.

The fork reuses upstream enforcement and keeps application policy in MCP Console. We maintain a focused patch set against a pinned upstream release, reapply it to selected newer releases, and validate the executable's behavior before updating MCP Console's source pin. Keeping the upstream source tree makes those integration changes reviewable and lets us build against matching native backends and dependencies. The [integration inventory](codex-rs/mcp-console-sandbox/INTEGRATION.md) and [upgrade procedure](codex-rs/mcp-console-sandbox/REBASE.md) describe this process.

For direct integration or development, see the [runner's build instructions](codex-rs/mcp-console-sandbox/README.md), [configuration protocol](codex-rs/mcp-console-sandbox/PROTOCOL.md), and [lifecycle contract](codex-rs/mcp-console-sandbox/LIFECYCLE.md). macOS and Linux support the JSON interface; [Windows currently has a separate CLI](codex-rs/mcp-console-sandbox/WINDOWS.md).

Licensed under [Apache-2.0](LICENSE).
