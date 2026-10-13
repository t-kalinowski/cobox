use super::LegacyLease;
use super::begin_setup;
use super::configuration_guard;
use super::pool_marker;
use anyhow::Result;
use pretty_assertions::assert_eq;
use std::os::windows::fs::OpenOptionsExt;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;

#[test]
fn admission_lock_is_exclusive_and_released_with_its_owner() -> Result<()> {
    let state = tempfile::tempdir()?;
    std::fs::create_dir(state.path().join(".sandbox-secrets"))?;
    let guard = configuration_guard(state.path())?;
    assert!(configuration_guard(state.path()).is_err());
    // Deleting/replacing the pathname cannot split the barrier while it is held.
    assert!(
        std::fs::remove_file(
            state
                .path()
                .join(".sandbox-secrets/console-proxy-configuration.lock")
        )
        .is_err()
    );
    drop(guard);
    let _next_owner = configuration_guard(state.path())?;
    Ok(())
}

#[test]
fn setup_invalidates_the_marker_without_delete_access() -> Result<()> {
    let state = tempfile::tempdir()?;
    std::fs::create_dir(state.path().join(".sandbox-secrets"))?;
    let marker = pool_marker(state.path());
    std::fs::write(&marker, b"1\n")?;
    // Deny pathname deletion without changing this machine's ACLs or accounts.
    let _reader = std::fs::File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&marker)?;
    let _setup = begin_setup(state.path())?;
    assert_eq!(std::fs::read(&marker)?, b"");
    Ok(())
}

#[test]
fn legacy_admission_is_concurrent_but_setup_requires_confirmed_retirement() -> Result<()> {
    let state = tempfile::tempdir()?;
    std::fs::create_dir(state.path().join(".sandbox-secrets"))?;
    std::fs::write(pool_marker(state.path()), b"1\n")?;
    let first = configuration_guard(state.path())?;
    assert!(begin_setup(state.path()).is_err());
    let first = LegacyLease::acquire(state.path(), first)?;
    let second = LegacyLease::acquire(state.path(), configuration_guard(state.path())?)?;
    assert!(begin_setup(state.path()).is_err());
    first.release()?;
    assert!(begin_setup(state.path()).is_err());
    second.release()?;
    // Abandoning preflight has no workload to quarantine.
    drop(LegacyLease::acquire(
        state.path(),
        configuration_guard(state.path())?,
    )?);
    let guard = begin_setup(state.path())?;
    assert_eq!(std::fs::read(pool_marker(state.path()))?, b"");
    drop(guard);
    assert!(LegacyLease::acquire(state.path(), configuration_guard(state.path())?).is_err());
    std::fs::write(pool_marker(state.path()), b"1\n")?;
    let mut unretired = LegacyLease::acquire(state.path(), configuration_guard(state.path())?)?;
    unretired.mark_spawn_attempted();
    drop(unretired);
    assert!(begin_setup(state.path()).is_err());
    // Reuse prevents per-launch growth, including where DELETE is unavailable.
    assert_eq!(
        std::fs::read_dir(state.path().join(".sandbox-secrets"))?.count(),
        4
    );
    Ok(())
}
