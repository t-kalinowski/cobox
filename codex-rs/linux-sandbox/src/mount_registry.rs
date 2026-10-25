//! Ownership of host paths created only to serve as bubblewrap mount targets.
//!
//! Records authorize removal of one unchanged, empty inode. They are published
//! before the command starts, and survive a killed runner for recovery on a
//! later native launch. They do not promise recovery across disk failure or a
//! kill between creating a target and publishing its record. Legacy markers
//! coordinate live users but never authorize deletion of an unrecorded path.
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::fs::Metadata;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::bwrap::SyntheticMountTarget;
use crate::bwrap::SyntheticMountTargetKind;

const LEASED_MARKER: &[u8] = b"leased\n";
const RECORD_FILE: &str = "target.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct MountTargetRecord {
    path: Vec<u8>,
    kind: SyntheticMountTargetKind,
    dev: u64,
    ino: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl MountTargetRecord {
    fn new(target: &SyntheticMountTarget, metadata: &Metadata) -> Self {
        Self {
            path: target.path().as_os_str().as_bytes().to_vec(),
            kind: target.kind(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(OsString::from_vec(self.path.clone()))
    }

    fn matches(&self, path: &Path, metadata: &Metadata) -> bool {
        self.path == path.as_os_str().as_bytes()
            && self.dev == metadata.dev()
            && self.ino == metadata.ino()
            && self.ctime == metadata.ctime()
            && self.ctime_nsec == metadata.ctime_nsec()
            && match self.kind {
                SyntheticMountTargetKind::EmptyFile => {
                    metadata.file_type().is_file() && metadata.len() == 0
                }
                SyntheticMountTargetKind::EmptyDirectory => metadata.file_type().is_dir(),
            }
    }
}

struct TargetRegistration {
    marker_dir: PathBuf,
    marker_file: PathBuf,
}

#[derive(Default)]
pub(crate) struct SyntheticMountRegistrations {
    targets: Vec<TargetRegistration>,
    owner_path: Option<PathBuf>,
    lease: Option<File>,
}

impl SyntheticMountRegistrations {
    pub(crate) fn preserve_lease(
        &self,
        args: &mut Vec<String>,
        preserved_files: &mut Vec<File>,
    ) -> io::Result<()> {
        let Some(lease) = &self.lease else {
            return Ok(());
        };
        let lease = lease.try_clone()?;
        let fd = lease.as_raw_fd().to_string();
        let separator = args
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or_else(|| panic!("missing bubblewrap command"));
        if args[..separator].iter().any(|arg| arg == "--unshare-pid") {
            // The launcher uses --as-pid-1 here. Its trusted native inner stage
            // owns the lease until init exits, with CLOEXEC for workload forks.
            let inner_separator = args
                .iter()
                .enumerate()
                .skip(separator + 1)
                .find_map(|(index, arg)| (arg == "--").then_some(index))
                .unwrap_or_else(|| panic!("missing native inner command"));
            args.splice(
                inner_separator..inner_separator,
                ["--mount-cleanup-lease-fd".to_string(), fd.clone()],
            );
        }
        // Without --as-pid-1, bubblewrap retains this descriptor in its init
        // process and closes it before executing the native inner stage.
        args.splice(separator..separator, ["--sync-fd".to_string(), fd]);
        preserved_files.push(lease);
        Ok(())
    }
}

pub(crate) fn register_synthetic_mount_targets(
    targets: &[SyntheticMountTarget],
) -> io::Result<SyntheticMountRegistrations> {
    if targets.is_empty() {
        return Ok(SyntheticMountRegistrations::default());
    }
    with_synthetic_mount_registry_lock(|| {
        let owner_path = owner_lease_path(std::process::id() as libc::pid_t);
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&owner_path)?;
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut registrations = SyntheticMountRegistrations {
            targets: Vec::new(),
            owner_path: Some(owner_path),
            lease: Some(lease),
        };
        let result = (|| {
            let mut seen = HashSet::new();
            for target in targets {
                if !seen.insert(target.path()) {
                    continue;
                }
                let marker_dir = synthetic_mount_marker_dir(target.path());
                fs::create_dir_all(&marker_dir)?;
                let marker_file = marker_dir.join(std::process::id().to_string());
                fs::write(&marker_file, LEASED_MARKER)?;
                registrations.targets.push(TargetRegistration {
                    marker_dir: marker_dir.clone(),
                    marker_file,
                });
                prepare_target(target, &marker_dir).map_err(|err| {
                    io::Error::new(
                        err.kind(),
                        format!(
                            "failed to prepare synthetic bubblewrap mount target {}: {err}",
                            target.path().display()
                        ),
                    )
                })?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            cleanup_registrations(&mut registrations)?;
            return Err(error);
        }
        Ok(registrations)
    })
}

fn prepare_target(target: &SyntheticMountTarget, marker_dir: &Path) -> io::Result<()> {
    // Exclusive creation distinguishes our own placeholders from paths added
    // after mount planning. Existing paths, including legacy leftovers, do not
    // gain deletion authority merely because they are empty.
    let created = match target.kind() {
        SyntheticMountTargetKind::EmptyFile => OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(target.path())
            .and_then(|file| file.metadata()),
        SyntheticMountTargetKind::EmptyDirectory => fs::DirBuilder::new()
            .mode(0o755)
            .create(target.path())
            .and_then(|()| fs::symlink_metadata(target.path())),
    };
    let metadata = match created {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(error),
    };
    let record = MountTargetRecord::new(target, &metadata);
    let pending = marker_dir.join("target.tmp");
    fs::write(&pending, serde_json::to_vec(&record)?)?;
    fs::rename(pending, marker_dir.join(RECORD_FILE))
}

pub(crate) fn is_registered_target(path: &Path) -> bool {
    with_synthetic_mount_registry_lock(|| {
        let marker_dir = synthetic_mount_marker_dir(path);
        let Ok(Some(record)) = read_record(&marker_dir) else {
            return false;
        };
        fs::symlink_metadata(path).is_ok_and(|metadata| record.matches(path, &metadata))
    })
}

fn read_record(marker_dir: &Path) -> io::Result<Option<MountTargetRecord>> {
    match fs::read(marker_dir.join(RECORD_FILE)) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn recover_stale_mount_targets() {
    with_synthetic_mount_registry_lock(|| {
        let root = synthetic_mount_registry_root();
        let entries = fs::read_dir(&root).unwrap_or_else(|err| {
            panic!(
                "failed to read synthetic mount registry {}: {err}",
                root.display()
            )
        });
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|err| panic!("failed to read mount registry entry: {err}"));
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                let _ = cleanup_recorded_target(&path);
            } else if entry.file_name().as_bytes().starts_with(b"owner-") && !lease_is_active(&path)
            {
                let _ = fs::remove_file(path);
            }
        }
    });
}

pub(crate) fn cleanup_synthetic_mount_targets(mut registrations: SyntheticMountRegistrations) {
    if registrations.targets.is_empty() {
        return;
    }
    with_synthetic_mount_registry_lock(|| cleanup_registrations(&mut registrations))
        .unwrap_or_else(|err| {
            panic!("failed to clean up synthetic bubblewrap mount targets: {err}")
        });
}

fn cleanup_registrations(registrations: &mut SyntheticMountRegistrations) -> io::Result<()> {
    drop(registrations.lease.take());
    if registrations
        .owner_path
        .as_deref()
        .is_some_and(lease_is_active)
    {
        // A surviving native init still holds the inherited description.
        // Leave its markers reachable for a later recovery pass.
        return Ok(());
    }
    for target in registrations.targets.iter().rev() {
        remove_file_if_present(&target.marker_file)?;
    }
    for target in registrations.targets.iter().rev() {
        cleanup_recorded_target(&target.marker_dir)?;
    }
    if let Some(path) = &registrations.owner_path {
        remove_file_if_present(path)?;
    }
    Ok(())
}

fn cleanup_recorded_target(marker_dir: &Path) -> io::Result<()> {
    if marker_dir_has_active_process(marker_dir) {
        return Ok(());
    }
    if let Some(record) = read_record(marker_dir)? {
        let path = record.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "failed to inspect synthetic bubblewrap mount target {}: {error}",
                        path.display()
                    ),
                ));
            }
        };
        if path.is_absolute()
            && synthetic_mount_marker_dir(&path) == marker_dir
            && metadata.is_some_and(|metadata| record.matches(&path, &metadata))
        {
            // Never recurse. Host writes or replacements revoke deletion
            // authority. A failed removal retains the record for later recovery.
            let removed = match record.kind {
                SyntheticMountTargetKind::EmptyFile => fs::remove_file(&path),
                SyntheticMountTargetKind::EmptyDirectory => fs::remove_dir(&path),
            };
            match removed {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "failed to remove synthetic bubblewrap mount target {}: {error}",
                            path.display()
                        ),
                    ));
                }
            }
        }
    }
    remove_file_if_present(&marker_dir.join(RECORD_FILE))?;
    remove_file_if_present(&marker_dir.join("target.tmp"))?;
    match fs::remove_dir(marker_dir) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn marker_dir_has_active_process(marker_dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(marker_dir) else {
        return true;
    };
    let mut active = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return true;
        };
        let path = entry.path();
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        let Ok(contents) = fs::read(&path) else {
            return true;
        };
        let owner_active = if contents == LEASED_MARKER {
            lease_is_active(&owner_lease_path(pid))
        } else {
            // Interoperate conservatively with older runners whose PID marker
            // has no lease. These markers never confer deletion authority.
            process_is_active(pid)
        };
        if owner_active {
            active = true;
        } else {
            let _ = fs::remove_file(path);
        }
    }
    active
}

fn owner_lease_path(pid: libc::pid_t) -> PathBuf {
    synthetic_mount_registry_root().join(format!("owner-{pid}"))
}

fn lease_is_active(path: &Path) -> bool {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    // A successful lock proves no live holder retains this open description.
    // Unlike kill(pid, 0), this also handles zombies and reused process IDs.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    result < 0
}

fn process_is_active(pid: libc::pid_t) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return true;
    }
    !matches!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH))
}

pub(crate) fn with_synthetic_mount_registry_lock<T>(f: impl FnOnce() -> T) -> T {
    let registry_root = synthetic_mount_registry_root();
    fs::create_dir_all(&registry_root).unwrap_or_else(|err| {
        panic!(
            "failed to create synthetic bubblewrap mount registry {}: {err}",
            registry_root.display()
        )
    });
    let lock_path = registry_root.join("lock");
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap_or_else(|err| {
            panic!(
                "failed to open synthetic bubblewrap mount registry lock {}: {err}",
                lock_path.display()
            )
        });
    if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } < 0 {
        let err = std::io::Error::last_os_error();
        panic!(
            "failed to lock synthetic bubblewrap mount registry {}: {err}",
            lock_path.display()
        );
    }
    let result = f();
    if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) } < 0 {
        let err = std::io::Error::last_os_error();
        panic!(
            "failed to unlock synthetic bubblewrap mount registry {}: {err}",
            lock_path.display()
        );
    }
    result
}

pub(crate) fn synthetic_mount_marker_dir(path: &Path) -> PathBuf {
    synthetic_mount_registry_root().join(format!("{:016x}", hash_path(path)))
}

pub(crate) fn synthetic_mount_registry_root() -> PathBuf {
    static REGISTRY_ROOT: OnceLock<PathBuf> = OnceLock::new();

    REGISTRY_ROOT
        .get_or_init(|| {
            let effective_uid = unsafe { libc::geteuid() };
            let temp_dir = std::env::temp_dir();
            let temp_dir = temp_dir.canonicalize().unwrap_or_else(|err| {
                panic!(
                    "failed to resolve synthetic mount registry temp directory {}: {err}",
                    temp_dir.display()
                )
            });
            let registry_root = temp_dir.join(format!(
                "codex-bwrap-synthetic-mount-targets-{effective_uid}"
            ));
            // A registry symlink can redirect bookkeeping into a writable root
            // that does not overlap TMPDIR, bypassing its read-only mount.
            assert!(
                !registry_root.is_symlink(),
                "synthetic mount registry must not be a symlink: {}",
                registry_root.display()
            );
            registry_root
        })
        .clone()
}

fn hash_path(path: &Path) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in path.as_os_str().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
