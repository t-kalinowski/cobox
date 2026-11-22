use super::*;
use pretty_assertions::assert_eq;

#[test]
fn missing_path_broker_authority_is_inaccessible_with_network_enabled() {
    let workspace = tempfile::tempdir().unwrap();
    let script = r#"
import ctypes
import errno
import os

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]

libc.process_vm_readv.argtypes = [
    ctypes.c_int, ctypes.POINTER(IOVec), ctypes.c_ulong,
    ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.c_ulong,
]
libc.process_vm_readv.restype = ctypes.c_ssize_t

# Invalid descriptors distinguish filter rejection from ordinary descriptor
# validation, without depending on the host's ptrace_scope configuration.
ctypes.set_errno(0)
descriptor_result = libc.syscall(438, -1, 0, 0)
descriptor_errno = ctypes.get_errno()
ctypes.set_errno(0)
landlock_result = libc.syscall(446, -1, 0)
landlock_errno = ctypes.get_errno()
source = ctypes.create_string_buffer(b"x")
destination = ctypes.create_string_buffer(1)
local = IOVec(ctypes.addressof(destination), 1)
remote = IOVec(ctypes.addressof(source), 1)
ctypes.set_errno(0)
memory_result = libc.process_vm_readv(os.getpid(), ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
memory_errno = ctypes.get_errno()

try:
    os.readlink(f"/proc/{os.getppid()}/fd/0")
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EPERM), error
else:
    raise AssertionError("broker descriptors were visible")

try:
    descriptor = os.open(f"/proc/{os.getppid()}/mem", os.O_RDWR)
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EPERM, errno.EOPNOTSUPP), error
else:
    os.close(descriptor)
    raise AssertionError("broker memory was writable")

actual = (descriptor_result, descriptor_errno, memory_result, memory_errno, landlock_result, landlock_errno)
assert actual == (-1, errno.EPERM, -1, errno.EPERM, -1, errno.EPERM), actual
print("broker authority isolated")
"#;
    let mut value = request(&["python3", "-c", script]);
    value.as_object_mut().unwrap().remove("filesystem");
    value["extends"] = json!(":workspace");
    value["workspace"] = json!(workspace.path());
    value["cwd"] = json!(workspace.path());
    value["workspace_options"] = json!({"exclude_tmpdir_env_var":true,"exclude_slash_tmp":true});
    // Full networking selects the mode that formerly omitted ptrace-family
    // restrictions; filesystem mediation must protect its own authority too.
    value["network"] = json!("enabled");
    let output = run(frame(&value), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"broker authority isolated\n".to_vec(), vec![])
    );
}

#[test]
fn missing_path_broker_preserves_sticky_directory_create_restrictions() {
    use codex_protocol::models::PermissionProfile;
    use codex_protocol::protocol::NetworkSandboxPolicy;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let source = Path::new("/etc/passwd");
    if std::fs::metadata(source).unwrap().uid() == unsafe { libc::geteuid() }
        || std::fs::read_to_string("/proc/sys/fs/protected_regular")
            .unwrap()
            .trim()
            == "0"
    {
        eprintln!("requires protected_regular and a foreign-owned readable fixture");
        return;
    }
    let workspace = tempfile::tempdir().unwrap();
    let sticky = workspace.path().join("sticky");
    let foreign = sticky.join("foreign");
    std::fs::create_dir(&sticky).unwrap();
    std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
    std::fs::write(&foreign, b"").unwrap();
    let script = r#"
import errno
import os

try:
    descriptor = os.open("sticky/foreign", os.O_RDONLY | os.O_CREAT, 0o600)
except OSError as error:
    assert error.errno == errno.EACCES, error
else:
    os.close(descriptor)
    raise AssertionError("O_CREAT bypassed protected_regular")
print("sticky create restriction preserved")
"#;
    let profile = PermissionProfile::workspace_write_with(
        &[],
        NetworkSandboxPolicy::Restricted,
        /*exclude_tmpdir_env_var*/ true,
        /*exclude_slash_tmp*/ true,
    );
    let staging = tempfile::tempdir().unwrap();
    let staged_runner = runner(staging.path());
    // An outer disposable namespace supplies the foreign-owned inode without
    // chown privileges or changes to the host source. The inner public runner
    // must retain the kernel's sticky-parent check for O_RDONLY | O_CREAT.
    let output = Command::new("unshare")
        .current_dir(workspace.path())
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
        .arg(source)
        .arg(&foreign)
        .arg(staged_runner.get_program())
        .arg("--sandbox-policy-cwd")
        .arg(workspace.path())
        .arg("--permission-profile")
        .arg(serde_json::to_string(&profile).unwrap())
        .args(["--", "python3", "-c", script])
        .output()
        .unwrap();
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (
            Some(0),
            b"sticky create restriction preserved\n".to_vec(),
            vec![]
        )
    );
    assert_eq!(std::fs::read(&foreign).unwrap(), b"");
}

#[test]
fn missing_path_broker_preserves_descriptor_metadata_semantics() {
    let workspace = tempfile::tempdir().unwrap();
    let script = r#"
import ctypes
import errno
import os

libc = ctypes.CDLL(None, use_errno=True)
libc.futimens.argtypes = [ctypes.c_int, ctypes.c_void_p]
libc.futimens.restype = ctypes.c_int
libc.syscall.restype = ctypes.c_long
with open("fd-metadata", "w") as stream:
    stream.write("contents")
os.setxattr("fd-metadata", "user.keep", b"existing")
descriptor = os.open("fd-metadata", os.O_PATH)
outcomes = []
for name, operation in [
    ("fchmod", lambda: os.fchmod(descriptor, 0o600)),
    ("fchown", lambda: os.fchown(descriptor, os.getuid(), os.getgid())),
    ("fsetxattr", lambda: os.setxattr(descriptor, "user.new", b"value")),
    ("fremovexattr", lambda: os.removexattr(descriptor, "user.keep")),
]:
    try:
        operation()
    except OSError as error:
        outcomes.append((name, error.errno))
    else:
        outcomes.append((name, "succeeded"))
ctypes.set_errno(0)
result = libc.futimens(descriptor, None)
outcomes.append(("futimens", ctypes.get_errno() if result == -1 else "succeeded"))
if os.uname().machine == "x86_64":
    ctypes.set_errno(0)
    result = libc.syscall(261, descriptor, 0, 0)
    outcomes.append(("futimesat", ctypes.get_errno() if result == -1 else "succeeded"))
os.close(descriptor)

# Owner-authorized metadata writes also work on ordinary read-only fds.
descriptor = os.open("fd-metadata", os.O_RDONLY)
os.fchmod(descriptor, 0o640)
os.fchown(descriptor, os.getuid(), os.getgid())
os.setxattr(descriptor, "user.new", b"value")
os.removexattr(descriptor, "user.new")
assert libc.futimens(descriptor, None) == 0, ctypes.get_errno()
os.close(descriptor)
assert all(error == errno.EBADF for name, error in outcomes), outcomes
print("descriptor metadata semantics preserved")
"#;
    let mut value = request(&["python3", "-c", script]);
    value.as_object_mut().unwrap().remove("filesystem");
    value["extends"] = json!(":workspace");
    value["workspace"] = json!(workspace.path());
    value["cwd"] = json!(workspace.path());
    value["workspace_options"] = json!({"exclude_tmpdir_env_var":true,"exclude_slash_tmp":true});
    let output = run(frame(&value), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (
            Some(0),
            b"descriptor metadata semantics preserved\n".to_vec(),
            vec![]
        )
    );
}

#[test]
fn missing_read_only_devpts_paths_fail_before_target_start() {
    use codex_protocol::models::PermissionProfile;
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::permissions::FileSystemSandboxPolicy;
    use codex_protocol::permissions::FileSystemSpecialPath;
    use codex_protocol::protocol::NetworkSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;

    let filesystem = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            FileSystemAccessMode::Write,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path("/dev/pts/0")
                .unwrap()
                .into(),
            FileSystemAccessMode::Read,
        ),
    ]);
    let profile =
        PermissionProfile::from_runtime_permissions(&filesystem, NetworkSandboxPolicy::Enabled);
    let staging = tempfile::tempdir().unwrap();
    let staged_runner = runner(staging.path());
    let script = r#"
import os
from pathlib import Path

assert not Path("/dev/pts/0").exists()
master = os.open("/dev/ptmx", os.O_RDWR | os.O_NOCTTY)
assert Path("/dev/pts/0").exists()
print("protected device node created", flush=True)
os._exit(0)
"#;
    // A fresh outer devpts makes slot zero deterministically absent during
    // policy planning. All device nodes and temporary files are namespace-local.
    let output = Command::new(cargo_bin("bwrap").unwrap())
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--bind",
        ])
        .arg(staging.path())
        .arg(staging.path())
        .args(["--chdir", "/", "--"])
        .arg(staged_runner.get_program())
        .args(["--sandbox-policy-cwd", "/", "--permission-profile"])
        .arg(serde_json::to_string(&profile).unwrap())
        .args(["--", "python3", "-c", script])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("missing read-only paths on devpts are unsupported"),
        "{output:?}"
    );
}
