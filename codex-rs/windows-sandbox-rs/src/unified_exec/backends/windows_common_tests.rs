//! The result-metric hook must preserve terminal exit codes and pipe-failure behavior.

use super::*;
use crate::ipc_framed::ExitPayload;
use crate::ipc_framed::write_frame;
use pretty_assertions::assert_eq;
use std::io::Seek;

#[test]
fn runner_result_reporting_preserves_exit_and_closed_pipe_results() -> Result<()> {
    for exit_code in [Some(0), Some(23), None] {
        let mut frames = tempfile::tempfile()?;
        if let Some(exit_code) = exit_code {
            write_frame(
                &mut frames,
                &FramedMessage {
                    version: IPC_PROTOCOL_VERSION,
                    message: Message::Exit {
                        payload: ExitPayload {
                            exit_code,
                            timed_out: false,
                        },
                    },
                },
            )?;
        }
        frames.rewind()?;
        let (stdout_tx, _stdout_rx) = broadcast::channel(1);
        let (exit_tx, exit_rx) = oneshot::channel();
        start_runner_stdout_reader(frames, stdout_tx, /*stderr_tx*/ None, exit_tx);
        assert_eq!(exit_rx.blocking_recv()?, exit_code.unwrap_or(-1));
    }
    Ok(())
}

#[test]
fn console_driver_preserves_native_receipt_presence() -> Result<()> {
    const CHILD: &str = "COBOX_RECEIPT_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Product selection is immutable. Isolate it from the ordinary Codex tests.
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                concat!(
                    module_path!(),
                    "::console_driver_preserves_native_receipt_presence"
                )
                .strip_prefix("codex_windows_sandbox::")
                .expect("test module prefix"),
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()?;
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8(output.stdout)?.contains("1 passed"));
        return Ok(());
    }
    crate::WindowsSandboxProduct::Console.initialize()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for receipt in [Some(0), Some(125), Some(-1), None] {
                let mut frames = tempfile::tempfile()?;
                if let Some(exit_code) = receipt {
                    write_frame(
                        &mut frames,
                        &FramedMessage {
                            version: IPC_PROTOCOL_VERSION,
                            message: Message::Exit {
                                payload: ExitPayload {
                                    exit_code,
                                    timed_out: false,
                                },
                            },
                        },
                    )?;
                }
                frames.rewind()?;
                let (stdout_tx, stdout_rx) = broadcast::channel(/*capacity*/ 1);
                let (exit_tx, exit_rx) = oneshot::channel();
                let (writer_tx, _writer_rx) = mpsc::channel(/*buffer*/ 1);
                start_runner_stdout_reader(frames, stdout_tx, /*stderr_tx*/ None, exit_tx);
                let spawned = finish_driver_spawn(
                    ProcessDriver {
                        writer_tx,
                        stdout_rx,
                        stderr_rx: None,
                        exit_rx,
                        terminator: None,
                        writer_handle: None,
                        resizer: None,
                        tty: false,
                    },
                    /*stdin_open*/ false,
                );
                assert_eq!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(/*secs*/ 5),
                        spawned.exit_rx
                    )
                    .await?
                    .ok(),
                    receipt
                );
            }
            Ok(())
        })
}
