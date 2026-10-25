use super::*;
use pretty_assertions::assert_eq;
use std::io::BufRead;
use std::io::BufReader;
use std::process::Child;
use std::process::ChildStdout;

pub(super) fn workspace_request(workspace: &Path, script: &str) -> Value {
    let mut value = request(&["/bin/sh", "-eu", "-c", script]);
    value.as_object_mut().unwrap().remove("filesystem");
    value.as_object_mut().unwrap().remove("network");
    value["extends"] = json!(":workspace");
    value["workspace"] = json!(workspace.canonicalize().unwrap());
    value["cwd"] = value["workspace"].clone();
    value["workspace_options"] = json!({"exclude_tmpdir_env_var":true,"exclude_slash_tmp":true});
    value
}

fn entries(workspace: &Path) -> Vec<String> {
    let mut entries: Vec<_> = std::fs::read_dir(workspace)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    entries.sort();
    entries
}

struct Gated {
    child: Child,
    stdout: BufReader<ChildStdout>,
    _owner: ownership::Process,
    _staging: tempfile::TempDir,
}

impl Gated {
    fn start(workspace: &Path, script: &str) -> Self {
        Self::start_request(workspace_request(workspace, script))
    }

    fn start_request(value: Value) -> Self {
        let staging = tempfile::tempdir().unwrap();
        let mut command = runner(staging.path());
        let (mut child, mut bootstrap) = spawn(command.stdin(Stdio::piped()));
        let owner = ownership::Process::watch(child.id() as i32);
        bootstrap.write_all(&frame(&value)).unwrap();
        drop(bootstrap);
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        if line.is_empty() {
            panic!(
                "target did not become ready: {:?}",
                child.wait_with_output()
            );
        }
        assert_eq!(line, "ready\n");
        Self {
            child,
            stdout,
            _owner: owner,
            _staging: staging,
        }
    }

    fn release(mut self) -> Output {
        self.child
            .stdin
            .take()
            .unwrap()
            .write_all(b"continue\n")
            .unwrap();
        let mut stdout = Vec::new();
        self.stdout.read_to_end(&mut stdout).unwrap();
        let mut output = self.child.wait_with_output().unwrap();
        output.stdout = stdout;
        output
    }

    fn finish(self) {
        let output = self.release();
        assert_eq!(
            (output.status.code(), output.stdout, output.stderr),
            (Some(0), vec![], vec![])
        );
    }
}

#[test]
fn workspace_keeps_missing_metadata_absent_on_host_while_running() {
    let workspace = tempfile::tempdir().unwrap();
    let gate = Gated::start(
        workspace.path(),
        "mkdir ordinary; printf persistent > ordinary/source; mv ordinary/source ordinary/renamed; printf 'ready\\n'; read gate",
    );
    let while_running = entries(workspace.path());
    gate.finish();
    assert_eq!(while_running, ["ordinary"]);
    assert_eq!(entries(workspace.path()), ["ordinary"]);
    assert_eq!(
        std::fs::read(workspace.path().join("ordinary/renamed")).unwrap(),
        b"persistent"
    );
}

#[test]
fn workspace_tmpdir_does_not_create_unused_mount_registry() {
    let workspace = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let mut command = runner(staging.path());
    command.env("TMPDIR", workspace.path());
    let output = run_command(
        command,
        frame(&workspace_request(
            workspace.path(),
            "printf persistent > ordinary",
        )),
        &[],
    );
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), vec![], vec![])
    );
    assert_eq!(entries(workspace.path()), ["ordinary"]);
    assert_eq!(
        std::fs::read(workspace.path().join("ordinary")).unwrap(),
        b"persistent"
    );
}

#[test]
fn workspace_tmpdir_keeps_existing_mount_registry_read_only() {
    use std::os::unix::fs::PermissionsExt;

    let workspace = tempfile::tempdir().unwrap();
    let registry = workspace
        .path()
        .join(format!("codex-bwrap-synthetic-mount-targets-{}", unsafe {
            libc::geteuid()
        }));
    std::fs::create_dir(&registry).unwrap();
    let marker = registry.join("marker");
    std::fs::write(&marker, b"existing registry").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o640)).unwrap();
    let script = r#"
import errno
import os
from pathlib import Path
import sys

registry = Path(sys.argv[1])
for mutation in (
    lambda: os.chmod(registry / "marker", 0o600),
    lambda: (registry / "new").write_text("unexpected"),
):
    try:
        mutation()
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS), error
    else:
        raise AssertionError("registry was writable")
Path("ordinary").write_text("persistent")
"#;
    let mut value = workspace_request(workspace.path(), "");
    value["command"] = json!(["python3", "-c", script, registry]);
    let staging = tempfile::tempdir().unwrap();
    let mut command = runner(staging.path());
    command.env("TMPDIR", workspace.path());
    let output = run_command(command, frame(&value), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), vec![], vec![])
    );
    assert_eq!(std::fs::read(&marker).unwrap(), b"existing registry");
    assert_eq!(
        std::fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(entries(&registry), ["marker"]);
    assert_eq!(
        std::fs::read(workspace.path().join("ordinary")).unwrap(),
        b"persistent"
    );
}

#[test]
fn workspace_denies_creation_and_replacement_of_missing_metadata() {
    let workspace = tempfile::tempdir().unwrap();
    let script = r#"
denied() { if "$@" 2>/dev/null; then echo "unexpected success: $*"; exit 1; fi; }
mkdir ordinary
printf persistent > ordinary/source
for name in .git .agents .codex .aws .claude; do
    denied mkdir "$name"
    denied /bin/sh -c 'printf created > "$1"' sh "$name"
    denied ln -s ordinary "$name"
    denied ln -T ordinary/source "$name"
    denied mv -T ordinary/source "$name"
    mkdir replacement
    denied mv -T replacement "$name"
    rmdir replacement
done
ln -s ordinary alias
for name in .git .agents .codex .aws .claude; do
    denied /bin/sh -c 'printf created > "alias/../$1"' sh "$name"
done
rm alias
ln -s .git dangling
denied /bin/sh -c 'printf created > dangling'
rm dangling
mv ordinary/source ordinary/renamed
printf 'protected\n'
"#;
    let output = run(frame(&workspace_request(workspace.path(), script)), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"protected\n".to_vec(), vec![])
    );
    assert_eq!(entries(workspace.path()), ["ordinary"]);
    assert_eq!(
        std::fs::read(workspace.path().join("ordinary/renamed")).unwrap(),
        b"persistent"
    );
}

#[test]
fn explicit_missing_read_paths_preserve_absence_and_block_parent_creation() {
    let workspace = tempfile::tempdir().unwrap();
    let script = r#"
denied() { if "$@" 2>/dev/null; then echo "unexpected success: $*"; exit 1; fi; }
denied mkdir blocked
denied /bin/sh -c 'printf created > blocked'
denied mkdir missing-parent
printf persistent > ordinary
printf 'ready\n'
read gate
"#;
    let mut value = request(&["/bin/sh", "-eu", "-c", script]);
    value["cwd"] = json!(workspace.path());
    value["filesystem"]["entries"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"path":{"type":"path","path":workspace.path()},"access":"write"}),
            json!({"path":{"type":"path","path":workspace.path().join("blocked")},"access":"read"}),
            json!({"path":{"type":"path","path":workspace.path().join("missing-parent/child")},"access":"read"}),
        ]);
    let gate = Gated::start_request(value);
    let while_running = entries(workspace.path());
    gate.finish();
    assert_eq!(while_running, ["ordinary"]);
    assert_eq!(entries(workspace.path()), ["ordinary"]);
}

#[test]
fn concurrent_workspaces_keep_missing_metadata_absent() {
    let workspace = tempfile::tempdir().unwrap();
    let first = Gated::start(
        workspace.path(),
        "printf first > ordinary-first; printf 'ready\\n'; read gate",
    );
    let second = Gated::start(
        workspace.path(),
        "printf second > ordinary-second; printf 'ready\\n'; read gate",
    );
    let both_running = entries(workspace.path());
    first.finish();
    let second_running = entries(workspace.path());
    second.finish();
    let expected = ["ordinary-first", "ordinary-second"];
    assert_eq!(both_running, expected);
    assert_eq!(second_running, expected);
    assert_eq!(entries(workspace.path()), expected);
    assert_eq!(
        std::fs::read(workspace.path().join("ordinary-first")).unwrap(),
        b"first"
    );
    assert_eq!(
        std::fs::read(workspace.path().join("ordinary-second")).unwrap(),
        b"second"
    );
}

#[test]
fn killing_entire_sandbox_tree_leaves_no_metadata_entries() {
    let workspace = tempfile::tempdir().unwrap();
    let mut gate = Gated::start(
        workspace.path(),
        "printf persistent > ordinary; printf 'ready\\n'; read gate",
    );
    // The target is gated, so this tree is stable. Stop parents before children
    // to prevent a cleanup owner from running after another process is killed.
    let processes = ownership::watch_tree(gate.child.id() as i32);
    for process in &processes {
        process.stop();
    }
    for process in &processes {
        process.kill();
    }
    ownership::await_exit(&processes);
    assert!(!gate.child.wait().unwrap().success());
    assert_eq!(entries(workspace.path()), ["ordinary"]);
    assert_eq!(
        std::fs::read(workspace.path().join("ordinary")).unwrap(),
        b"persistent"
    );
}

#[test]
fn workspace_preserves_git_discovery_in_parent_repository() {
    let repository = tempfile::tempdir().unwrap();
    let workspace = repository.path().join("project");
    std::fs::create_dir(&workspace).unwrap();
    let output = Command::new("git")
        .args(["init", "--quiet"])
        .arg(repository.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let output = run(
        frame(&workspace_request(
            &workspace,
            "git rev-parse --show-toplevel",
        )),
        &[],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stderr, b"");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        repository.path().canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(entries(&workspace), Vec::<String>::new());
}

#[test]
fn host_created_protected_file_retires_sandbox_before_descriptor_mutation() {
    use std::os::unix::fs::PermissionsExt;

    let workspace = tempfile::tempdir().unwrap();
    let script = r#"
import os
import sys

descriptor = os.open("ordinary", os.O_CREAT | os.O_RDWR, 0o644)
os.fchmod(descriptor, 0o644)
os.write(descriptor, b"unchanged")
print("ready", flush=True)
assert sys.stdin.readline() == "continue\n"
os.fchmod(descriptor, 0o600)
raise AssertionError("sandbox survived protected-path materialization")
"#;
    let mut value = workspace_request(workspace.path(), "");
    value["command"] = json!(["python3", "-c", script]);
    let gate = Gated::start_request(value);
    // The sandbox opened this inode before the host made it protected. Policy
    // invalidation must retire it before changing this existing writable fd.
    std::fs::hard_link(
        workspace.path().join("ordinary"),
        workspace.path().join(".git"),
    )
    .unwrap();
    let output = gate.release();
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("initially missing protected path appeared"),
        "{output:?}"
    );
    assert_eq!(
        std::fs::read(workspace.path().join(".git")).unwrap(),
        b"unchanged"
    );
    assert_eq!(
        std::fs::metadata(workspace.path().join(".git"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[test]
fn workspace_preserves_native_umask_permissions_and_file_locks() {
    use std::os::unix::fs::PermissionsExt;

    let workspace = tempfile::tempdir().unwrap();
    let script = r#"
import errno
import fcntl
import os
import stat

os.umask(0o027)
descriptor = os.open("ordinary", os.O_CREAT | os.O_RDWR, 0o666)
assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o640
os.write(descriptor, b"persistent")
os.fchmod(descriptor, 0o600)
assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600
os.ftruncate(descriptor, 4)
fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
other = os.open("ordinary", os.O_RDWR)
try:
    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as error:
    assert error.errno in (errno.EAGAIN, errno.EACCES), error
else:
    raise AssertionError("independent description bypassed file lock")
fcntl.flock(descriptor, fcntl.LOCK_UN)
fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
os.close(other)
os.close(descriptor)
os.chmod("ordinary", 0o640)
temporary = os.open("temporary", os.O_CREAT | os.O_RDWR, 0o600)
os.unlink("temporary")
os.ftruncate(temporary, 3)
os.fchmod(temporary, 0o640)
assert os.fstat(temporary).st_size == 3
assert stat.S_IMODE(os.fstat(temporary).st_mode) == 0o640
os.close(temporary)
memory = os.memfd_create("ordinary-memory")
os.ftruncate(memory, 5)
os.fchmod(memory, 0o600)
assert os.fstat(memory).st_size == 5
assert stat.S_IMODE(os.fstat(memory).st_mode) == 0o600
os.close(memory)
print("native mutations preserved")
"#;
    let mut value = workspace_request(workspace.path(), "");
    value["command"] = json!(["python3", "-c", script]);
    let output = run(frame(&value), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"native mutations preserved\n".to_vec(), vec![])
    );
    assert_eq!(
        std::fs::read(workspace.path().join("ordinary")).unwrap(),
        b"pers"
    );
    assert_eq!(
        std::fs::metadata(workspace.path().join("ordinary"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
}

#[test]
fn missing_read_paths_require_namespace_local_procfs() {
    use codex_protocol::models::PermissionProfile;
    use codex_protocol::protocol::NetworkSandboxPolicy;

    let workspace = tempfile::tempdir().unwrap();
    for (profile, allow_inherited_procfs) in [
        (PermissionProfile::read_only(), true),
        (
            PermissionProfile::workspace_write_with(
                &[],
                NetworkSandboxPolicy::Restricted,
                /*exclude_tmpdir_env_var*/ true,
                /*exclude_slash_tmp*/ true,
            ),
            false,
        ),
    ] {
        for no_proc in [false, true] {
            let staging = tempfile::tempdir().unwrap();
            let mut command = runner(staging.path());
            command
                .current_dir(workspace.path())
                .arg("--sandbox-policy-cwd")
                .arg(workspace.path())
                .arg("--permission-profile")
                .arg(serde_json::to_string(&profile).unwrap());
            if no_proc {
                command.arg("--no-proc");
            }
            let output = command
                .args([
                    "--",
                    "/bin/sh",
                    "-eu",
                    "-c",
                    "if mkdir .git 2>/dev/null; then exit 1; fi; printf 'target\\n'",
                ])
                .output()
                .unwrap();
            if allow_inherited_procfs || !no_proc {
                assert_eq!(
                    (output.status.code(), output.stdout, output.stderr),
                    (Some(0), b"target\n".to_vec(), vec![])
                );
            } else {
                assert!(!output.status.success(), "{output:?}");
                assert!(output.stdout.is_empty());
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("namespace-local procfs"),
                    "{output:?}"
                );
            }
        }
    }
    assert!(entries(workspace.path()).is_empty());
}

#[test]
fn bind_alias_cannot_move_ancestor_of_missing_protected_path() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    let alias = directory.path().join("alias");
    std::fs::create_dir_all(workspace.join("parent/child")).unwrap();
    std::fs::create_dir(&alias).unwrap();
    let mut value = request(&[
        "/bin/sh",
        "-eu",
        "-c",
        "if mv \"$ALIAS/parent\" \"$ALIAS/moved\" 2>/dev/null; then echo 'protected ancestor moved'; exit 1; fi; printf 'ancestor protected\\n'",
    ]);
    value["cwd"] = json!(workspace);
    value["environment"] = json!({"ALIAS":alias,"PATH":"/usr/bin:/bin"});
    value["filesystem"]["entries"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"path":{"type":"path","path":workspace},"access":"write"}),
            json!({"path":{"type":"path","path":alias},"access":"write"}),
            json!({"path":{"type":"path","path":workspace.join("parent/child/blocked")},"access":"read"}),
        ]);
    let staging = tempfile::tempdir().unwrap();
    let staged = runner(staging.path());
    let mut command = Command::new("unshare");
    command
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--",
            "/bin/sh",
            "-eu",
            "-c",
            "mount --bind \"$1\" \"$2\"; shift 2; exec \"$@\"",
            "sh",
        ])
        .arg(&workspace)
        .arg(&alias)
        .arg(staged.get_program())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_command(command, frame(&value), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"ancestor protected\n".to_vec(), vec![])
    );
    assert!(workspace.join("parent/child").is_dir());
    assert!(!workspace.join("moved").exists());
    assert!(!workspace.join("parent/child/blocked").exists());
}
