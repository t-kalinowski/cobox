"""Expose the active Rust toolchain's process wrapper for its CLI regression."""

def _process_wrapper_impl(ctx):
    wrapper = ctx.toolchains["@rules_rust//rust:toolchain_type"].process_wrapper
    return [DefaultInfo(files = depset([wrapper]))]

process_wrapper = rule(
    implementation = _process_wrapper_impl,
    toolchains = ["@rules_rust//rust:toolchain_type"],
)
