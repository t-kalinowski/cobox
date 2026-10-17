"""Common runtime artifacts and environment for Windows contract tests."""

load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_test")

def windows_contract_test(name, src, extra_srcs = []):
    rust_test(
        name = name,
        srcs = [src, "tests/windows_mxc_support/mod.rs"] + extra_srcs,
        crate_root = src,
        data = [
            ":mcp-console-sandbox",
            ":mcp-console-sandbox-fixture",
        ],
        edition = "2024",
        env = {
            "CARGO_BIN_EXE_mcp-console-sandbox": "$(rlocationpath :mcp-console-sandbox)",
            "CARGO_BIN_EXE_mcp-console-sandbox-fixture": "$(rlocationpath :mcp-console-sandbox-fixture)",
        },
        env_inherit = ["MCP_CONSOLE_SANDBOX_REQUIRE_MXC"],
        tags = ["no-sandbox"],
        target_compatible_with = ["@platforms//os:windows"],
        deps = all_crate_deps(
            normal = True,
            normal_dev = True,
        ),
    )
