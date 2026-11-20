use super::*;
use pretty_assertions::assert_eq;
use std::io::BufRead;
use std::io::BufReader;
use std::os::unix::net::UnixStream;

#[test]
fn pathname_socket_preserves_address_and_host_inode() {
    let script = r#"
import errno
import os
import socket
import sys

os.mkdir("ordinary")
address = sys.argv[1]
server = socket.socket(socket.AF_UNIX)
server.bind(address)
assert server.getsockname() == address, (server.getsockname(), address)
server.listen(1)
for name in (".git", ".agents", ".codex", ".aws", ".claude"):
    with socket.socket(socket.AF_UNIX) as protected:
        try:
            protected.bind(name)
        except OSError as error:
            assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS), error
        else:
            raise AssertionError("bound protected socket: " + name)
print("ready", flush=True)
connection, _ = server.accept()
with connection:
    assert connection.recv(4) == b"ping"
    connection.sendall(b"pong")
server.close()
"#;
    for absolute in [false, true] {
        let workspace = tempfile::tempdir().unwrap();
        let socket = workspace.path().join("ordinary/socket");
        let address = if absolute {
            socket.to_str().unwrap()
        } else {
            "./ordinary/socket"
        };
        let mut value = missing_paths::workspace_request(workspace.path(), "");
        value["command"] = json!(["python3", "-c", script, address]);
        value["network"] = json!("enabled");
        let staging = tempfile::tempdir().unwrap();
        let mut command = runner(staging.path());
        let (mut child, mut bootstrap) = spawn(command.stdin(Stdio::null()));
        let _owner = ownership::Process::watch(child.id() as i32);
        bootstrap.write_all(&frame(&value)).unwrap();
        drop(bootstrap);
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        if line.is_empty() {
            panic!(
                "socket did not become ready: {:?}",
                child.wait_with_output()
            );
        }
        assert_eq!(line, "ready\n");
        for name in [".git", ".agents", ".codex", ".aws", ".claude"] {
            assert!(!workspace.path().join(name).exists());
        }
        let mut connection = UnixStream::connect(&socket).unwrap();
        connection.write_all(b"ping").unwrap();
        let mut reply = [0; 4];
        connection.read_exact(&mut reply).unwrap();
        assert_eq!(reply, *b"pong");
        let mut rest = Vec::new();
        stdout.read_to_end(&mut rest).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            (output.status.code(), rest, output.stderr),
            (Some(0), vec![], vec![])
        );
    }
}

#[test]
fn missing_path_enforcement_preserves_restricted_network_bind_denial() {
    let workspace = tempfile::tempdir().unwrap();
    let script = r#"
import errno
import socket

with socket.socket(socket.AF_UNIX) as server:
    try:
        server.bind("ordinary.sock")
    except OSError as error:
        assert error.errno == errno.EPERM, error
    else:
        raise AssertionError("restricted network permitted bind")
print("bind denied")
"#;
    let mut value = missing_paths::workspace_request(workspace.path(), "");
    value["command"] = json!(["python3", "-c", script]);
    let output = run(frame(&value), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"bind denied\n".to_vec(), vec![])
    );
    assert!(!workspace.path().join("ordinary.sock").exists());
}

#[test]
fn pathname_socket_racing_directory_replacement_cannot_create_protected_entry() {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::create_dir(workspace.path().join("protected")).unwrap();
    let script = r#"
import errno
import os
import socket
import threading

os.mkdir("ordinary")
start = threading.Barrier(2)
def replace_directory():
    start.wait()
    for _ in range(100):
        os.rename("ordinary", "parked")
        os.symlink("protected", "ordinary")
        os.unlink("ordinary")
        os.rename("parked", "ordinary")

thread = threading.Thread(target=replace_directory)
thread.start()
start.wait()
for _ in range(400):
    with socket.socket(socket.AF_UNIX) as server:
        try:
            server.bind("ordinary/blocked.sock")
        except OSError as error:
            assert error.errno in (
                errno.EACCES, errno.EPERM, errno.EROFS,
                errno.ENOENT, errno.EADDRINUSE,
            ), error
thread.join()
assert not os.path.lexists("protected/blocked.sock")
with socket.socket(socket.AF_UNIX) as server:
    server.bind("ordinary/final.sock")
print("socket race contained")
"#;
    let mut value = missing_paths::workspace_request(workspace.path(), "");
    value["command"] = json!(["python3", "-c", script]);
    value["network"] = json!("enabled");
    value["filesystem"] = json!({"kind":"restricted","entries":[
        {"path":{"type":"path","path":workspace.path().join("protected/blocked.sock")},"access":"read"}
    ]});
    let output = run(frame(&value), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"socket race contained\n".to_vec(), vec![])
    );
    assert!(!workspace.path().join("protected/blocked.sock").exists());
    assert!(workspace.path().join("ordinary/final.sock").exists());
}
