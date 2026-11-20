use super::*;
use pretty_assertions::assert_eq;
use std::io::BufRead;
use std::io::BufReader;

#[test]
fn writable_roots_cover_subtrees_without_implicit_metadata_exclusions() {
    for descriptor in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let writable = root.join("writable");
        std::fs::create_dir(&writable).unwrap();
        std::fs::write(writable.join("read-only"), "unchanged").unwrap();
        std::fs::write(writable.join("secret"), "private").unwrap();
        let script = r#"
set -eu
denied() { if "$@" 2>/dev/null; then echo "unexpected success: $*"; exit 1; fi; }
for name in .git .agents .codex .aws .claude; do
    if test "$LAUNCH" = 1; then test ! -e "writable/$name"; fi
    mkdir -p "writable/$name"
    for nested in ordinary .git .agents .codex .aws .claude; do
        mkdir -p "writable/$name/$nested"
        printf '%s' "$LAUNCH" > "writable/$name/$nested/value"
        test "$(cat "writable/$name/$nested/value")" = "$LAUNCH"
        printf disposable > "writable/$name/$nested/remove"
        rm "writable/$name/$nested/remove"
    done
done
test "$(cat writable/read-only)" = unchanged
denied /bin/sh -c 'echo changed > writable/read-only'
denied cat writable/secret
denied /bin/sh -c 'echo escaped > outside'
printf 'complete subtree writable; explicit exclusions retained\n'
"#;
        for launch in [1, 2] {
            let mut value = request(&["/bin/sh", "-c", script]);
            value["cwd"] = json!(root);
            value["environment"] = json!({"PATH":"/usr/bin:/bin", "LAUNCH":launch.to_string()});
            value["filesystem"] = json!({"kind":"restricted","entries":[
                {"path":{"type":"special","value":{"kind":"root"}},"access":"read"},
                {"path":{"type":"path","path":writable},"access":"write"},
                {"path":{"type":"path","path":writable.join("read-only")},"access":"read"},
                {"path":{"type":"path","path":writable.join("secret")},"access":"deny"}
            ]});
            let output = if descriptor {
                run(frame(&value), &[])
            } else {
                for field in ["command", "cwd"] {
                    value.as_object_mut().unwrap().remove(field);
                }
                let staging = tempfile::tempdir().unwrap();
                runner(staging.path())
                    .current_dir(&root)
                    .args(["--config-env", "POLICY", "--", "/bin/sh", "-c", script])
                    .env("POLICY", value.to_string())
                    .output()
                    .unwrap()
            };
            assert_eq!(
                (output.status.code(), output.stdout, output.stderr),
                (
                    Some(0),
                    b"complete subtree writable; explicit exclusions retained\n".to_vec(),
                    vec![]
                ),
                "descriptor={descriptor}, launch={launch}"
            );
            assert_eq!(
                std::fs::read(writable.join("read-only")).unwrap(),
                b"unchanged"
            );
            assert_eq!(std::fs::read(writable.join("secret")).unwrap(), b"private");
            assert!(!root.join("outside").exists());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn replaceable_foreign_parent_cannot_remove_metadata_protection() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("requires a disposable root fixture for a foreign-owned directory");
        return;
    }
    let workspace = tempfile::tempdir().unwrap();
    let foreign = workspace.path().join("foreign");
    let protected = foreign.join(".git");
    std::fs::create_dir(&foreign).unwrap();
    let foreign_uid = 65534;
    std::os::unix::fs::chown(&foreign, Some(foreign_uid), Some(foreign_uid)).unwrap();
    std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(/*mode*/ 0o555)).unwrap();
    let mut request = request(&[
        "/bin/sh",
        "-c",
        r#"
set -eu
mv foreign previous
mkdir -p foreign/.git
printf compromised > foreign/.git/config
printf 'metadata write escaped\n'
"#,
    ]);
    request["cwd"] = json!(workspace.path());
    request["environment"] = json!({"PATH": "/usr/bin:/bin"});
    request["filesystem"] = json!({"kind": "restricted", "entries": [
        {"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"},
        {"path": {"type": "path", "path": workspace.path()}, "access": "write"},
        {"path": {"type": "path", "path": protected}, "access": "read"}
    ]});
    request["network"] = json!("enabled");
    let staging = tempfile::tempdir().unwrap();
    let staged_runner = runner(staging.path());
    let mut command = Command::new("/usr/bin/setpriv");
    command
        .arg("--bounding-set=-dac_override,-dac_read_search,-chown,-fowner")
        .arg(staged_runner.get_program())
        // Use the staged bubblewrap and exercise native setup before release.
        .env("PATH", staging.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_command(command, frame(&request), &[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(output.stdout, b"");
    assert_eq!(
        output.stderr,
        format!(
            "error building bubblewrap command: failed to prepare synthetic bubblewrap mount target {}: Permission denied (os error 13)\n",
            protected.display()
        )
        .as_bytes()
    );
    assert!(!workspace.path().join("previous").exists());
    assert!(!protected.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn root_write_with_local_denial_respects_foreign_host_ownership() {
    use std::os::unix::fs::MetadataExt;

    let root = std::fs::metadata("/").unwrap();
    if root.uid() == unsafe { libc::geteuid() } || root.mode() & 0o022 != 0 {
        eprintln!("requires a foreign filesystem root without group or other writes");
        return;
    }
    let workspace = tempfile::tempdir().unwrap();
    let created = workspace.path().join("created");
    let secret = workspace.path().join("secret");
    std::fs::write(&secret, "private").unwrap();
    let mut request = fixture("write", &[created.to_str().unwrap()]);
    request["cwd"] = json!("/");
    request["filesystem"] = json!({"kind": "restricted", "entries": [
        {"path": {"type": "special", "value": {"kind": "root"}}, "access": "write"},
        {"path": {"type": "path", "path": secret}, "access": "deny"}
    ]});
    request["network"] = json!("enabled");
    let output = run(frame(&request), &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&created).unwrap(), b"created");
    assert_eq!(std::fs::read(&secret).unwrap(), b"private");
    request["command"] = json!([
        "/bin/sh",
        "-c",
        "if cat \"$1\" >/dev/null 2>&1; then exit 13; fi",
        "sh",
        secret
    ]);
    let output = run(frame(&request), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), vec![], vec![])
    );
}

#[test]
fn unrestricted_filesystem_preserves_independent_network_policy() {
    let outside = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for kind in ["unrestricted", "external-sandbox"] {
        for network in ["restricted", "enabled"] {
            let file = outside.path().join(format!("{kind}-{network}"));
            let mut request = fixture("write", &[file.to_str().unwrap()]);
            request["cwd"] = json!(workspace.path());
            request["filesystem"] = json!({"kind": kind});
            request["network"] = json!(network);
            let output = run(frame(&request), &[]);
            assert!(output.status.success(), "{kind}/{network}: {output:?}");
            assert_eq!(std::fs::read(file).unwrap(), b"created");

            request["command"] = fixture("connect", &[&address])["command"].clone();
            let output = run(frame(&request), &[]);
            assert_eq!(
                output.status.success(),
                network == "enabled" || kind == "external-sandbox",
                "{kind}/{network}: {output:?}"
            );
            request["command"] = fixture("stdout", &[])["command"].clone();
            let output = run(frame(&request), b"target input\0\xff");
            assert_eq!(
                (output.status.code(), output.stdout, output.stderr),
                (Some(0), b"target input\0\xff".to_vec(), vec![])
            );
        }
    }
}

#[test]
fn unrestricted_and_external_managed_proxy_preserve_routing_and_allowlist() {
    // Linux's bridge binds 127.0.0.1 in its own network namespace. A distinct
    // host loopback address identifies the origin even when their ports match.
    #[cfg(target_os = "linux")]
    let direct_origin = "127.0.0.2";
    #[cfg(not(target_os = "linux"))]
    let direct_origin = "127.0.0.1";
    for kind in ["unrestricted", "external-sandbox"] {
        for network in ["restricted", "enabled"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nallowed",
                    )
                    .unwrap();
            });
            let mut request = fixture("proxy-get", &[&format!("http://{address}/")]);
            request["filesystem"] = json!({"kind": kind});
            request["network"] = json!(network);
            request["proxy"] = proxy_config();
            request["proxy"]["allowLocalBinding"] = json!(false);
            let output = run(frame(&request), &[]);
            assert!(output.status.success(), "{kind}/{network}: {output:?}");
            assert!(output.stdout.ends_with(b"allowed"), "{output:?}");
            server.join().unwrap();
            request["proxy"]["domains"] = json!({"127.0.0.1": "deny"});
            let output = run(frame(&request), &[]);
            assert!(output.status.success(), "{output:?}");
            assert!(output.stdout.starts_with(b"HTTP/1.1 403"), "{output:?}");
            let listener = TcpListener::bind((direct_origin, 0)).unwrap();
            request["command"] = fixture("connect", &[&listener.local_addr().unwrap().to_string()])
                ["command"]
                .clone();
            let directory = tempfile::tempdir().unwrap();
            let command = runner(directory.path());
            #[cfg(target_os = "linux")]
            let command = {
                // Exercise a bridge and host origin with the same port number
                // in their independent network namespaces.
                let library = startup::interposer(directory.path());
                let mut command = command;
                startup::preload(&mut command, &library);
                command.env("SANDBOX_TEST_NATIVE_PRELOAD", &library).env(
                    "SANDBOX_TEST_BRIDGE_PORT",
                    listener.local_addr().unwrap().port().to_string(),
                );
                command
            };
            let output = run_command(command, frame(&request), &[]);
            #[cfg(target_os = "linux")]
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("forced bridge port\n"),
                "bridge port was not forced: {output:?}"
            );
            assert!(
                !output.status.success(),
                "direct connection bypassed proxy: {output:?}"
            );
        }
    }
}

#[test]
fn unrestricted_signal_forwarding_retires_descendants_and_private_storage() {
    for network in ["restricted", "enabled"] {
        let directory = tempfile::tempdir().unwrap();
        let (mut child, mut bootstrap) = spawn(runner(directory.path()).stdin(Stdio::piped()));
        let mut request = fixture("lifecycle", &["interrupted"]);
        request["filesystem"] = json!({"kind": "unrestricted"});
        request["network"] = json!(network);
        request["lifecycle"] =
            json!({"parent_pid": std::process::id(), "private_tmp": {"environment": ["TMPDIR"]}});
        bootstrap.write_all(&frame(&request)).unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "target failed before readiness");
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(42), "{output:?}");
        assert_eq!(output.stderr, b"");
        assert!(!Path::new(value["temporary"].as_str().unwrap()).exists());
    }
}

#[test]
fn external_sandbox_supervises_the_process_group_without_native_enforcement() {
    let directory = tempfile::tempdir().unwrap();
    let (mut child, mut bootstrap) = spawn(runner(directory.path()).stdin(Stdio::piped()));
    let mut request = fixture("lifecycle", &["group-tree"]);
    request["filesystem"] = json!({"kind": "external-sandbox"});
    request["lifecycle"] = json!({"sigterm": "retire", "private_tmp": {"environment": ["TMPDIR"]}});
    bootstrap.write_all(&frame(&request)).unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(!line.is_empty(), "target failed before readiness");
    let value: Value = serde_json::from_str(&line).unwrap();
    child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert!(line.trim().parse::<u32>().unwrap() > 1);
    let mut partial = [0; b"{\"partial\":".len()];
    stdout.read_exact(&mut partial).unwrap();
    assert_eq!(&partial, b"{\"partial\":");
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let stdin = child.stdin.take();
    let output = child.wait_with_output().unwrap();
    drop(stdin);
    assert_eq!((output.status.code(), output.stderr), (Some(0), vec![]));
    assert!(!Path::new(value["temporary"].as_str().unwrap()).exists());
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "");
}

#[test]
fn unrestricted_caller_death_retires_the_lifetime() {
    for network in ["restricted", "enabled"] {
        let directory = tempfile::tempdir().unwrap();
        let runner = runner(directory.path());
        let mut request = fixture("lifecycle", &["detached"]);
        request["filesystem"] = json!({"kind": "unrestricted"});
        request["network"] = json!(network);
        request["lifecycle"] = json!({"private_tmp": {"environment": ["TMPDIR"]}});
        let mut owner = Command::new(cargo_bin("mcp-console-sandbox-fixture").unwrap())
            .arg("owner")
            .arg(runner.get_program())
            .env("SANDBOX_TEST_REQUEST", request.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(owner.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert!(line.trim().parse::<u32>().unwrap() > 1);
        line.clear();
        stdout.read_line(&mut line).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        let stdin = owner.stdin.take();
        owner.kill().unwrap();
        let output = owner.wait_with_output().unwrap();
        let mut rest = String::new();
        stdout.read_to_string(&mut rest).unwrap();
        drop(stdin);
        assert_eq!((rest, output.stderr), (String::new(), vec![]));
        assert!(!Path::new(value["temporary"].as_str().unwrap()).exists());
    }
}

#[test]
fn external_sandbox_runs_inside_existing_native_network_restrictions() {
    let directory = tempfile::tempdir().unwrap();
    let runner = runner(directory.path());
    let mut request = request(&[
        runner.get_program().to_str().unwrap(),
        "--config-env",
        "OUTER_POLICY",
        "--",
        "/bin/echo",
        "externally enforced",
    ]);
    request["environment"]["OUTER_POLICY"] = json!(
        json!({
            "filesystem":{"kind":"external-sandbox"},"network":"restricted"
        })
        .to_string()
    );
    let output = run(frame(&request), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"externally enforced\n".to_vec(), vec![])
    );
}
