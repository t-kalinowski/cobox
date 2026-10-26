use super::*;
use pretty_assertions::assert_eq;
use std::io::BufRead;
use std::io::BufReader;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Child;
use std::process::ChildStdout;

const METADATA: [&str; 5] = [".agents", ".aws", ".claude", ".codex", ".git"];

struct Workspace {
    root: tempfile::TempDir,
    runtime: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            runtime: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn start(&self) -> Gated {
        self.start_at(self.path())
    }

    fn start_at(&self, workspace: &Path) -> Gated {
        let mut value = request(&["/bin/sh", "-eu", "-c", "printf 'ready\\n'; read gate"]);
        value.as_object_mut().unwrap().remove("filesystem");
        value.as_object_mut().unwrap().remove("network");
        value["extends"] = json!(":workspace");
        value["workspace"] = json!(workspace.canonicalize().unwrap());
        value["cwd"] = value["workspace"].clone();
        value["workspace_options"] =
            json!({"exclude_tmpdir_env_var":true,"exclude_slash_tmp":true});
        self.start_request(value)
    }

    fn start_request(&self, value: Value) -> Gated {
        let staging = tempfile::tempdir().unwrap();
        let mut command = runner(staging.path());
        command.env("TMPDIR", self.runtime.path());
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
        Gated {
            child,
            stdout,
            _owner: owner,
            _staging: staging,
        }
    }

    fn entries(&self) -> Vec<String> {
        let mut entries: Vec<_> = std::fs::read_dir(self.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        entries.sort();
        entries
    }
}

struct Gated {
    child: Child,
    stdout: BufReader<ChildStdout>,
    _owner: ownership::Process,
    _staging: tempfile::TempDir,
}

impl Gated {
    fn output(mut self) -> Output {
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
        let output = self.output();
        assert_eq!(
            (output.status.code(), output.stdout, output.stderr),
            (Some(0), vec![], vec![])
        );
    }

    fn kill_tree(mut self) {
        // The stdin gate keeps the tree stable. Stop parents before children so
        // no cleanup owner can run after another process in the tree is killed.
        let processes = ownership::watch_tree(self.child.id() as i32);
        for process in &processes {
            process.stop();
        }
        for process in &processes {
            process.kill();
        }
        ownership::await_exit(&processes);
        assert!(!self.child.wait().unwrap().success());
    }
}

fn identity(path: &Path) -> (u64, u64) {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[test]
fn next_workspace_launch_reclaims_mount_targets_after_tree_loss() {
    let workspace = Workspace::new();
    let first = workspace.start();
    // This cleanup strategy deliberately leaves placeholders visible while the
    // sandbox runs; it recovers leftovers only when the workspace is used again.
    assert_eq!(workspace.entries(), METADATA);
    first.kill_tree();
    assert_eq!(workspace.entries(), METADATA);

    let recovery = workspace.start();
    assert_eq!(workspace.entries(), METADATA);
    recovery.finish();
    assert_eq!(workspace.entries(), Vec::<String>::new());
}

#[test]
fn later_launch_recovers_mount_targets_from_another_workspace() {
    let workspace = Workspace::new();
    workspace.start().kill_tree();
    assert_eq!(workspace.entries(), METADATA);
    let other = tempfile::tempdir().unwrap();

    workspace.start_at(other.path()).finish();

    assert_eq!(workspace.entries(), Vec::<String>::new());
}

#[test]
fn later_launch_recovers_explicit_missing_read_paths() {
    recover_explicit_missing_paths("read", &["blocked/first", "single"]);
}

#[test]
fn later_launch_recovers_explicit_missing_deny_paths() {
    recover_explicit_missing_paths("deny", &["blocked/first", "single"]);
}

#[test]
fn later_launch_recovers_read_paths_with_a_shared_missing_ancestor() {
    recover_explicit_missing_paths("read", &["blocked/first", "blocked/second", "single"]);
}

#[test]
fn later_launch_recovers_deny_paths_with_a_shared_missing_ancestor() {
    recover_explicit_missing_paths("deny", &["blocked/first", "blocked/second", "single"]);
}

fn recover_explicit_missing_paths(access: &str, paths: &[&str]) {
    let workspace = Workspace::new();
    let value = explicit_missing_request(workspace.path(), access, paths);
    workspace.start_request(value).kill_tree();
    assert_eq!(workspace.entries(), ["blocked", "single"]);
    let other = tempfile::tempdir().unwrap();

    workspace.start_at(other.path()).finish();

    assert_eq!(workspace.entries(), Vec::<String>::new());
}

fn explicit_missing_request(workspace: &Path, access: &str, paths: &[&str]) -> Value {
    let mut value = request(&["/bin/sh", "-eu", "-c", "printf 'ready\\n'; read gate"]);
    value["cwd"] = json!(workspace);
    let entries = value["filesystem"]["entries"].as_array_mut().unwrap();
    entries.push(json!({
        "path":{"type":"path","path":workspace},"access":"write"
    }));
    // Shared descendants need one host target even when multiple rules need it.
    for path in paths {
        entries.push(json!({
            "path":{"type":"path","path":workspace.join(path)},"access":access
        }));
    }
    value
}

#[test]
fn concurrent_read_paths_reuse_recorded_missing_ancestor() {
    concurrent_missing_ancestor("read");
}

#[test]
fn concurrent_deny_paths_reuse_recorded_missing_ancestor() {
    concurrent_missing_ancestor("deny");
}

fn concurrent_missing_ancestor(access: &str) {
    let workspace = Workspace::new();
    let value = explicit_missing_request(workspace.path(), access, &["blocked/child"]);
    let first = workspace.start_request(value.clone());
    assert_eq!(workspace.entries(), ["blocked"]);
    let original = identity(&workspace.path().join("blocked"));

    workspace.start_request(value).finish();

    assert_eq!(workspace.entries(), ["blocked"]);
    assert_eq!(identity(&workspace.path().join("blocked")), original);
    first.finish();
    assert_eq!(workspace.entries(), Vec::<String>::new());
}

#[test]
fn recovery_preserves_host_symlink_and_write_then_truncate() {
    let workspace = Workspace::new();
    workspace.start().kill_tree();
    let file = workspace.path().join(".claude");
    let original = std::fs::symlink_metadata(&file).unwrap();
    // The host owns this read-only file. Restore its mode after the temporary
    // write so the final empty path differs only in modification timestamps.
    std::fs::set_permissions(
        &file,
        std::fs::Permissions::from_mode(original.permissions().mode() | 0o200),
    )
    .unwrap();
    std::fs::write(&file, b"host-created contents").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_len(0)
        .unwrap();
    std::fs::set_permissions(&file, original.permissions()).unwrap();
    let edited = std::fs::symlink_metadata(&file).unwrap();
    assert_eq!(
        (edited.dev(), edited.ino()),
        (original.dev(), original.ino())
    );
    assert_ne!(
        (edited.ctime(), edited.ctime_nsec()),
        (original.ctime(), original.ctime_nsec())
    );
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("keep"), b"user directory").unwrap();
    let link = workspace.path().join(".aws");
    std::fs::remove_dir(&link).unwrap();
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    let other = tempfile::tempdir().unwrap();

    workspace.start_at(other.path()).finish();

    assert_eq!(workspace.entries(), [".aws", ".claude"]);
    assert_eq!(identity(&file), (original.dev(), original.ino()));
    assert_eq!(std::fs::read(&file).unwrap(), Vec::<u8>::new());
    assert_eq!(std::fs::read_link(link).unwrap(), outside.path());
    assert_eq!(
        std::fs::read(outside.path().join("keep")).unwrap(),
        b"user directory"
    );
}

#[test]
fn workspace_preserves_pre_existing_empty_metadata() {
    let workspace = Workspace::new();
    let directory = workspace.path().join(".git");
    let file = workspace.path().join(".claude");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, []).unwrap();
    let original = (identity(&directory), identity(&file));

    workspace.start().finish();

    assert_eq!(workspace.entries(), [".claude", ".git"]);
    assert_eq!((identity(&directory), identity(&file)), original);
}

#[test]
fn recovery_preserves_replaced_and_populated_mount_targets() {
    for contents in [b"".as_slice(), b"user contents"] {
        let workspace = Workspace::new();
        workspace.start().kill_tree();
        let directory = workspace.path().join(".git");
        let file = workspace.path().join(".claude");
        // Keep the old inodes alive to make the identity change deterministic.
        std::fs::rename(&directory, workspace.path().join("retired-git")).unwrap();
        std::fs::rename(&file, workspace.path().join("retired-claude")).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(&file, contents).unwrap();
        std::fs::write(workspace.path().join(".agents/keep"), b"user directory").unwrap();
        let replacement = (identity(&directory), identity(&file));

        workspace.start().finish();

        assert_eq!(
            workspace.entries(),
            [
                ".agents",
                ".claude",
                ".git",
                "retired-claude",
                "retired-git"
            ]
        );
        assert_eq!((identity(&directory), identity(&file)), replacement);
        assert_eq!(std::fs::read(&file).unwrap(), contents);
        assert_eq!(
            std::fs::read(workspace.path().join(".agents/keep")).unwrap(),
            b"user directory"
        );
    }
}

#[test]
fn recovery_preserves_mount_targets_owned_by_a_live_runner() {
    let workspace = Workspace::new();
    let first = workspace.start();
    let survivor = workspace.start();
    let original: Vec<_> = METADATA
        .iter()
        .map(|name| identity(&workspace.path().join(name)))
        .collect();
    first.kill_tree();

    workspace.start().finish();

    assert_eq!(workspace.entries(), METADATA);
    let active: Vec<_> = METADATA
        .iter()
        .map(|name| identity(&workspace.path().join(name)))
        .collect();
    assert_eq!(active, original);
    survivor.finish();
    assert_eq!(workspace.entries(), Vec::<String>::new());
}

#[test]
fn normal_exit_preserves_replaced_empty_mount_targets() {
    let workspace = Workspace::new();
    let running = workspace.start();
    let directory = workspace.path().join(".git");
    let file = workspace.path().join(".claude");
    std::fs::rename(&directory, workspace.path().join("retired-git")).unwrap();
    std::fs::rename(&file, workspace.path().join("retired-claude")).unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, []).unwrap();
    let replacement = (identity(&directory), identity(&file));

    running.finish();

    assert_eq!(
        workspace.entries(),
        [".claude", ".git", "retired-claude", "retired-git"]
    );
    assert_eq!((identity(&directory), identity(&file)), replacement);
}

#[test]
fn cleanup_failure_is_reported_without_blocking_later_workspaces() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("requires a non-root host to exercise directory write permissions");
        return;
    }
    let workspace = Workspace::new();
    let running = workspace.start();
    let original = std::fs::metadata(workspace.path()).unwrap().permissions();
    std::fs::set_permissions(workspace.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let failed_cleanup = running.output();
    let other = tempfile::tempdir().unwrap();

    let later = workspace.start_at(other.path()).output();

    // Restore access before assertions so the temporary workspace can retire.
    std::fs::set_permissions(workspace.path(), original).unwrap();
    assert!(!failed_cleanup.status.success(), "{failed_cleanup:?}");
    assert_eq!(failed_cleanup.stdout, b"");
    let stderr = String::from_utf8(failed_cleanup.stderr).unwrap();
    assert!(stderr.contains("failed to remove synthetic"), "{stderr}");
    assert!(
        stderr.contains(workspace.path().to_str().unwrap()),
        "{stderr}"
    );
    assert!(stderr.contains("Permission denied"), "{stderr}");
    assert_eq!(
        (later.status.code(), later.stdout, later.stderr),
        (Some(0), vec![], vec![])
    );
    assert_eq!(workspace.entries(), METADATA);
}
