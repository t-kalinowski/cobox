//! Public Windows filesystem policy materialization without native child launches.
use super::*;
use codex_protocol::permissions::NetworkSandboxPolicy;
use pretty_assertions::assert_eq;

#[test]
fn workspace_metadata_is_protected_by_windows_compatibility_policies() {
    for existing in [false, true] {
        let directory = tempfile::TempDir::new().unwrap();
        let cwd =
            AbsolutePathBuf::from_absolute_path(dunce::canonicalize(directory.path()).unwrap())
                .unwrap();
        let metadata = cwd.join(".claude");
        if existing {
            std::fs::create_dir(metadata.as_path()).unwrap();
        }
        let profile = PermissionProfile::workspace_write_with(
            std::slice::from_ref(&cwd),
            NetworkSandboxPolicy::Restricted,
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );
        for profile in [
            profile.clone(),
            profile.materialize_project_roots_with_workspace_roots(std::slice::from_ref(&cwd)),
        ] {
            let legacy =
                compatibility_sandbox_policy_for_permission_profile(&profile, cwd.as_path());
            let roots = legacy.get_writable_roots_with_cwd(cwd.as_path());
            for overrides in [
                resolve_windows_restricted_token_filesystem_overrides(
                    SandboxType::WindowsRestrictedToken,
                    &profile,
                    &cwd,
                    WindowsSandboxLevel::RestrictedToken,
                )
                .unwrap(),
                resolve_windows_elevated_filesystem_overrides(
                    SandboxType::WindowsRestrictedToken,
                    &profile,
                    &cwd,
                    /*use_windows_elevated_backend*/ true,
                    &HashMap::new(),
                )
                .unwrap(),
            ] {
                assert_eq!(
                    overrides,
                    Some(WindowsSandboxFilesystemOverrides {
                        read_roots_override: None,
                        read_roots_include_platform_defaults: false,
                        write_roots_override: None,
                        additional_deny_read_paths: vec![],
                        additional_deny_write_paths: vec![metadata.clone()],
                    })
                );
                assert!(
                    roots
                        .iter()
                        .any(|root| { root.is_path_writable(cwd.join("ordinary").as_path()) })
                );
                assert_eq!(metadata.as_path().exists(), existing);
            }
        }
    }
}

#[cfg(target_os = "windows")]
#[test]
fn elevated_non_write_temp_never_grants_write_access() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::permissions::FileSystemSpecialPath;

    let dir = tempfile::TempDir::new().unwrap();
    let cwd = AbsolutePathBuf::from_absolute_path(dir.path().join("work")).unwrap();
    let temp = dir.path().join("temp");
    std::fs::create_dir_all(cwd.as_path()).unwrap();
    std::fs::create_dir_all(&temp).unwrap();
    let env = HashMap::from([("Temp".into(), temp.to_string_lossy().into_owned())]);
    for access in [FileSystemAccessMode::Read, FileSystemAccessMode::Deny] {
        let profile = PermissionProfile::from_runtime_permissions(
            &FileSystemSandboxPolicy::restricted(vec![
                FileSystemSandboxEntry::new(
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Root,
                    },
                    FileSystemAccessMode::Read,
                ),
                FileSystemSandboxEntry::new(
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Tmpdir,
                    },
                    access,
                ),
            ]),
            NetworkSandboxPolicy::Restricted,
        );
        let overrides = resolve_windows_elevated_filesystem_overrides(
            SandboxType::WindowsRestrictedToken,
            &profile,
            &cwd,
            true,
            &env,
        )
        .unwrap();
        let write_roots = overrides
            .as_ref()
            .and_then(|o| o.write_roots_override.as_ref());
        assert!(write_roots.is_none_or(Vec::is_empty));
        if access == FileSystemAccessMode::Deny {
            assert_eq!(
                overrides.unwrap().additional_deny_read_paths,
                vec![
                    AbsolutePathBuf::from_absolute_path(dunce::canonicalize(&temp).unwrap())
                        .unwrap(),
                ]
            );
        }
    }
}
