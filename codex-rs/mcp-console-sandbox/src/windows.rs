//! Windows environment transport and native MXC re-execution.

pub(crate) fn run() -> anyhow::Result<i32> {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == codex_sandboxing::CODEX_WINDOWS_MXC_ARG1)
    {
        codex_sandboxing::run_windows_mxc_main();
    }
    crate::windows_console::run()
}
