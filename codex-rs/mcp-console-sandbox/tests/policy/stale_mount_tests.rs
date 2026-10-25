use super::*;
use pretty_assertions::assert_eq;
use std::io::BufRead;
use std::io::BufReader;
use std::os::unix::fs::MetadataExt;
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
    fn finish(mut self) {
        self.child
            .stdin
            .take()
            .unwrap()
            .write_all(b"continue\n")
            .unwrap();
        let mut stdout = Vec::new();
        self.stdout.read_to_end(&mut stdout).unwrap();
        let output = self.child.wait_with_output().unwrap();
        assert_eq!(
            (output.status.code(), stdout, output.stderr),
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
