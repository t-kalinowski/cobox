use super::*;
use pretty_assertions::assert_eq;
use std::io::BufRead;
use std::io::BufReader;
use std::process::Child;
use std::process::ChildStdout;

fn workspace_request(workspace: &Path, script: &str) -> Value {
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
        let staging = tempfile::tempdir().unwrap();
        let mut command = runner(staging.path());
        let (mut child, mut bootstrap) = spawn(command.stdin(Stdio::piped()));
        let owner = ownership::Process::watch(child.id() as i32);
        bootstrap
            .write_all(&frame(&workspace_request(workspace, script)))
            .unwrap();
        drop(bootstrap);
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        Self {
            child,
            stdout,
            _owner: owner,
            _staging: staging,
        }
    }

    fn finish(mut self) {
        self.child
            .stdin
            .take()
            .unwrap()
            .write_all(b"continue\n")
            .unwrap();
        let mut stdout = String::new();
        self.stdout.read_to_string(&mut stdout).unwrap();
        let output = self.child.wait_with_output().unwrap();
        assert_eq!(
            (output.status.code(), stdout, output.stderr),
            (Some(0), String::new(), vec![])
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
