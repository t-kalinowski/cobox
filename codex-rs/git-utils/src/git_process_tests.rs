use super::spawn_git_command;
use super::wait_for_git_command_with_timeout_output;
use pretty_assertions::assert_eq;
#[cfg(windows)]
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

#[derive(Clone, Copy)]
enum GitWrapperLifetime {
    WaitForChild,
    ExitBeforeTimeout,
}

async fn assert_timed_out_git_wrapper_does_not_leave_child_process_running(
    wrapper_lifetime: GitWrapperLifetime,
) {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let child_pid_file = temp_dir.path().join("child.pid");
    let child_ready_file = temp_dir.path().join("child-ready");
    let release_child_file = temp_dir.path().join("release-child");
    let child_survived_file = temp_dir.path().join("child-survived");
    let release_wrapper_file = temp_dir.path().join("release-wrapper");
    // Use native fixture processes so readiness does not depend on shell startup.
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--ignored",
            "--exact",
            "git_process::tests::git_wrapper_fixture",
        ])
        .env("GIT_WRAPPER_ROLE", "wrapper")
        .env(
            "GIT_WRAPPER_LIFETIME",
            match wrapper_lifetime {
                GitWrapperLifetime::WaitForChild => "wait",
                GitWrapperLifetime::ExitBeforeTimeout => "exit",
            },
        );
    command
        .env("CHILD_PID_FILE", &child_pid_file)
        .env("CHILD_READY_FILE", &child_ready_file)
        .env("RELEASE_CHILD_FILE", &release_child_file)
        .env("CHILD_SURVIVED_FILE", &child_survived_file)
        .env("RELEASE_WRAPPER_FILE", &release_wrapper_file);

    let (mut wrapper, process_tree) = spawn_git_command(&mut command).expect("spawn Git wrapper");
    let child_pid = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(child_pid) = std::fs::read_to_string(&child_pid_file)
                && !child_pid.trim().is_empty()
                && child_ready_file.exists()
            {
                break child_pid.trim().to_string();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("wait for Git wrapper child readiness");

    if matches!(wrapper_lifetime, GitWrapperLifetime::ExitBeforeTimeout) {
        std::fs::write(&release_wrapper_file, "release").expect("release Git wrapper");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if wrapper
                    .try_wait()
                    .expect("check Git wrapper state")
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("wait for Git wrapper exit");
    }

    let output =
        wait_for_git_command_with_timeout_output(wrapper, process_tree, Duration::from_millis(100))
            .await;
    assert_eq!(output, None);

    std::fs::write(&release_child_file, "release").expect("release Git wrapper child");
    tokio::time::sleep(Duration::from_secs(3)).await;
    if !child_survived_file.exists() {
        return;
    }

    #[cfg(unix)]
    let _ = std::process::Command::new("kill")
        .args(["-KILL", &child_pid])
        .status();
    #[cfg(windows)]
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &child_pid, "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    panic!("Git wrapper child process {child_pid} survived timeout cleanup");
}

#[test]
#[ignore = "subprocess fixture for Git process-tree cleanup tests"]
fn git_wrapper_fixture() {
    let role = std::env::var("GIT_WRAPPER_ROLE").expect("fixture role");
    let release_path = match role.as_str() {
        "child" => {
            std::fs::write(
                std::env::var("CHILD_PID_FILE").expect("child PID path"),
                std::process::id().to_string(),
            )
            .expect("publish child PID");
            std::fs::write(
                std::env::var("CHILD_READY_FILE").expect("child readiness path"),
                "ready",
            )
            .expect("publish readiness after writing the PID");
            std::env::var("RELEASE_CHILD_FILE").expect("child release path")
        }
        "wrapper" => {
            let mut child =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--ignored",
                        "--exact",
                        "git_process::tests::git_wrapper_fixture",
                    ])
                    .env("GIT_WRAPPER_ROLE", "child")
                    .spawn()
                    .expect("spawn fixture child");
            match std::env::var("GIT_WRAPPER_LIFETIME")
                .expect("wrapper lifetime")
                .as_str()
            {
                "wait" => {
                    child.wait().expect("wait for child");
                    return;
                }
                "exit" => std::env::var("RELEASE_WRAPPER_FILE").expect("wrapper release path"),
                lifetime => panic!("unsupported wrapper lifetime: {lifetime}"),
            }
        }
        role => panic!("unsupported fixture role: {role}"),
    };
    while !std::path::Path::new(&release_path).exists() {
        std::thread::sleep(Duration::from_millis(/*millis*/ 10));
    }
    if role == "child" {
        std::thread::sleep(Duration::from_secs(/*secs*/ 1));
        std::fs::write(
            std::env::var("CHILD_SURVIVED_FILE").expect("child survival path"),
            "survived",
        )
        .expect("publish survival marker");
        std::thread::sleep(Duration::from_secs(/*secs*/ 60));
    }
}

#[tokio::test]
async fn timed_out_git_wrapper_does_not_leave_child_process_running() {
    assert_timed_out_git_wrapper_does_not_leave_child_process_running(
        GitWrapperLifetime::WaitForChild,
    )
    .await;
}

#[tokio::test]
async fn timed_out_exited_git_wrapper_does_not_leave_child_process_running() {
    assert_timed_out_git_wrapper_does_not_leave_child_process_running(
        GitWrapperLifetime::ExitBeforeTimeout,
    )
    .await;
}
