use super::filter_sensitive_write_roots;
use pretty_assertions::assert_eq;
use std::path::Path;
use std::path::PathBuf;

#[test]
fn effective_write_roots_protect_base_and_slot_pool_state() -> anyhow::Result<()> {
    const CHILD: &str = "COBOX_POOL_WRITE_TEST_CHILD";
    let Ok(identity) = std::env::var(CHILD) else {
        for identity in ["base", "slot"] {
            let output = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    concat!(
                        module_path!(),
                        "::effective_write_roots_protect_base_and_slot_pool_state"
                    )
                    .strip_prefix("codex_windows_sandbox::")
                    .unwrap(),
                    "--nocapture",
                ])
                .env(CHILD, identity)
                .output()?;
            assert!(output.status.success(), "{identity}: {output:?}");
            assert!(String::from_utf8(output.stdout)?.contains("1 passed"));
        }
        return Ok(());
    };
    crate::WindowsSandboxProduct::Console.initialize()?;
    let root = tempfile::tempdir()?;
    let pool = root.path().join("state");
    let slot = pool.join("proxy-slots/0");
    let sibling = root.path().join("state-other");
    let unrelated = root.path().join("workspace");
    for path in [&slot, &sibling, &unrelated] {
        std::fs::create_dir_all(path)?;
    }
    let home = if identity == "slot" {
        crate::ConsoleProxySlot::new(/*index*/ 0)?.initialize()?;
        &slot
    } else {
        &pool
    };
    let roots = [
        root.path().to_path_buf(),
        pool.clone(),
        slot.clone(),
        sibling.clone(),
        unrelated.clone(),
    ];
    let permissions = crate::ResolvedWindowsSandboxPermissions::try_from_permission_profile(
        &codex_protocol::models::PermissionProfile::read_only(),
    )?;
    assert_eq!(
        super::effective_write_roots_for_permissions(
            &permissions,
            root.path(),
            &Default::default(),
            home,
            Some(&roots)
        ),
        vec![
            dunce::canonicalize(sibling)?,
            dunce::canonicalize(unrelated)?
        ]
    );
    Ok(())
}

#[test]
fn console_proxy_pool_rejects_write_roots_overlapping_in_either_direction() {
    let pool = Path::new(r"C:\Console\State");
    let slot = pool.join("proxy-slots").join("0");
    let sibling = PathBuf::from(r"C:\Console\State-other");
    let unrelated = PathBuf::from(r"C:\workspace");
    let roots = vec![
        PathBuf::from(r"C:\"),
        PathBuf::from(r"C:\Console"),
        PathBuf::from("c:/console/STATE"),
        pool.join("proxy-slots").join("1"),
        pool.join(".sandbox-secrets"),
        sibling.clone(),
        unrelated.clone(),
    ];
    assert_eq!(
        filter_sensitive_write_roots(roots, &slot, Some(pool)),
        vec![sibling, unrelated]
    );
}
