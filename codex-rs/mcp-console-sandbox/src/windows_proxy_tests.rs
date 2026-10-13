use super::configuration_guard;
use anyhow::Result;

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
