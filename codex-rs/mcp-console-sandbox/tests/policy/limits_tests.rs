use super::*;
use pretty_assertions::assert_eq;

#[test]
fn mandatory_denies_clamp_descendant_grants_and_unrestricted_profiles() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let denied = root.join("private");
    std::fs::create_dir_all(denied.join("nested")).unwrap();
    std::fs::write(denied.join("nested/secret"), "secret").unwrap();
    for unrestricted in [false, true] {
        let mut value = request(&[
            "/bin/sh",
            "-c",
            "echo started; if cat private/nested/secret 2>/dev/null; then exit 31; fi; if echo bad > private/nested/new 2>/dev/null; then exit 32; fi; echo allowed > public; echo clamped",
        ]);
        // Filesystem enforcement is independent of networking. Avoid requiring
        // a host capable of creating a network namespace for this contract.
        value["network"] = json!("enabled");
        value["cwd"] = json!(root);
        value["filesystem"] = if unrestricted {
            json!({"kind":"unrestricted"})
        } else {
            json!({"kind":"restricted", "entries":[
                {"path":{"type":"special","value":{"kind":"root"}},"access":"read"},
                {"path":{"type":"path","path":root},"access":"write"},
                {"path":{"type":"special","value":{"kind":"project_roots","subpath":"private/nested"}},"access":"write"},
                {"path":{"type":"path","path":denied.join("nested")},"access":"read"}
            ]})
        };
        value["limits"] = json!({"filesystem":{"deny":[denied, denied.join("nested")]}});
        let output = run(frame(&value), &[]);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"started\nclamped\n");
        assert_eq!(
            std::fs::read_to_string(root.join("public")).unwrap(),
            "allowed\n"
        );
        assert!(!denied.join("nested/new").exists());
    }
}

#[test]
fn mandatory_denies_cover_symlink_grants_and_missing_descendants() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let denied = root.join("private");
    std::fs::create_dir(&denied).unwrap();
    std::fs::write(denied.join("secret"), "secret").unwrap();
    std::os::unix::fs::symlink(&denied, root.join("alias")).unwrap();
    let mut value = request(&[
        "/bin/sh",
        "-c",
        "echo started; if cat alias/secret 2>/dev/null; then exit 31; fi; if mkdir -p alias/missing 2>/dev/null; then exit 32; fi; echo clamped",
    ]);
    value["network"] = json!("enabled");
    value["cwd"] = json!(root);
    value["filesystem"]["entries"].as_array_mut().unwrap().extend([
        json!({"path":{"type":"path","path":root},"access":"write"}),
        json!({"path":{"type":"path","path":root.join("alias")},"access":"write"}),
        json!({"path":{"type":"path","path":root.join("alias/missing/child")},"access":"write"}),
    ]);
    value["limits"] = json!({"filesystem":{"deny":[denied]}});
    let output = run(frame(&value), &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"started\nclamped\n");
    assert!(!denied.join("missing").exists());
}

#[test]
fn mandatory_denies_cover_a_subtree_of_a_writable_alias() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let real = root.join("real");
    let alias = root.join("alias");
    std::fs::create_dir_all(real.join("private")).unwrap();
    std::fs::write(real.join("private/secret"), "secret").unwrap();
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let mut value = fixture(
        "probe-limits",
        &[
            alias.join("private/secret").to_str().unwrap(),
            alias.join("private/new").to_str().unwrap(),
            alias.join("public").to_str().unwrap(),
        ],
    );
    value["network"] = json!("enabled");
    value["limits"] = json!({"filesystem":{"deny":[real.join("private")]}});
    for grant in [&real, &alias] {
        let mut value = value.clone();
        value["filesystem"]["entries"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":{"type":"path","path":grant},"access":"write"}));
        let output = run(frame(&value), &[]);
        // Seatbelt rejects a writable root that contains a user-controlled
        // symlink. Access through the alias under a physical grant is supported.
        if cfg!(target_os = "macos") && grant == &alias {
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("symlinked writable roots are not supported"),
                "{output:?}"
            );
        } else {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(output.stdout, b"started\nclamped\n");
            assert_eq!(
                std::fs::read_to_string(real.join("public")).unwrap(),
                "allowed"
            );
        }
    }
}

#[test]
fn invalid_limits_and_external_enforcement_fail_before_target_start() {
    for limits in [
        json!({"filesystem":{"deny":["relative/path"]}}),
        json!({"filesystem":{"deny":["/tmp/*.secret"]}}),
        json!({"filesystem":{"deny":["/tmp/secret"]},"unknown":true}),
    ] {
        let mut value = request(&["/bin/echo", "launched"]);
        value["limits"] = limits;
        let output = run(frame(&value), &[]);
        assert!(!output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
    }
    let mut value = request(&["/bin/echo", "launched"]);
    value["filesystem"] = json!({"kind":"external-sandbox"});
    value["limits"] = json!({"filesystem":{"deny":["/tmp/secret"]}});
    let output = run(frame(&value), &[]);
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("limits"),
        "{output:?}"
    );
}

#[test]
fn private_storage_cannot_reopen_a_mandatory_deny() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut value = request(&["/bin/echo", "launched"]);
    value["lifecycle"] = json!({"private_tmp":{"parent":root,"environment":["TMPDIR"]}});
    value["limits"] = json!({"filesystem":{"deny":[root]}});
    let output = run(frame(&value), &[]);
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("private storage"),
        "{output:?}"
    );
}

#[test]
fn domain_limits_keep_enabled_network_behind_the_proxy() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    for domains in [json!({"deny":["127.0.0.1"]}), json!({"allow":[]})] {
        let mut value = fixture("proxy-get", &[&url]);
        value["network"] = json!("enabled");
        value["limits"] = json!({"network":{"domains":domains,"allow_local_binding":false}});
        #[cfg(target_os = "macos")]
        {
            value["macos_seatbelt_profile_extension"] = json!("(allow network*)");
        }
        let output = run(frame(&value), &[]);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stdout.starts_with(b"HTTP/1.1 403"), "{output:?}");
    }
}

#[test]
fn domain_limits_do_not_enable_a_restricted_network() {
    let mut value = fixture("context", &[]);
    value["limits"] = json!({"network":{"domains":{"allow":["*.example.com"]}}});
    #[cfg(target_os = "macos")]
    {
        value["macos_seatbelt_profile_extension"] = json!("(allow network*)");
    }
    let output = run(frame(&value), &[]);
    assert!(output.status.success(), "{output:?}");
    let context: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        context["environment"].get("HTTP_PROXY").is_none(),
        "{context}"
    );
    #[cfg(target_os = "macos")]
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        value["command"] = fixture(
            "probe-denied-connect",
            &[&listener.local_addr().unwrap().to_string()],
        )["command"]
            .clone();
        let output = run(frame(&value), &[]);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"started\ndenied\n");
    }
}

#[test]
fn mandatory_local_binding_denial_preserves_outbound_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for limit in [None, Some(true), Some(false)] {
        let denied = limit == Some(false);
        let mut value = fixture(
            "probe-local-binding-limit",
            &[if denied { "denied" } else { "allowed" }, &address],
        );
        value["network"] = json!("enabled");
        #[cfg(target_os = "macos")]
        {
            value["macos_seatbelt_profile_extension"] = json!("(allow network*)");
        }
        if let Some(limit) = limit {
            value["limits"] = json!({"network":{"allow_local_binding":limit}});
        }
        let output = run(frame(&value), &[]);
        assert!(output.status.success(), "{limit:?}: {output:?}");
        assert_eq!(
            output.stdout,
            if denied {
                b"started\nbinding-denied\nconnected\n".as_slice()
            } else {
                b"started\nbound\nconnected\n".as_slice()
            }
        );
    }
}

#[test]
fn domain_limits_block_direct_host_loopback_with_local_binding_allowed() {
    // On Linux a separate host address distinguishes the destination from
    // listeners in the target's network namespace.
    let host = if cfg!(target_os = "linux") {
        "127.0.0.2"
    } else {
        "127.0.0.1"
    };
    let listener = TcpListener::bind((host, 0)).unwrap();
    let mut value = fixture(
        "probe-denied-connect",
        &[&listener.local_addr().unwrap().to_string()],
    );
    value["network"] = json!("enabled");
    value["limits"] = json!({"network":{"domains":{"deny":[host]}}});
    #[cfg(target_os = "macos")]
    {
        value["macos_seatbelt_profile_extension"] = json!("(allow network*)");
    }
    let output = run(frame(&value), &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"started\ndenied\n");
}

#[cfg(target_os = "macos")]
#[test]
fn domain_limits_allow_matching_proxy_requests_and_local_binding() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let response = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0; 2048];
        assert!(stream.read(&mut buf).unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nallowed")
            .unwrap();
    });
    let mut value = fixture("proxy-get", &[&format!("http://{address}/")]);
    value["network"] = json!("enabled");
    value["limits"] = json!({"network":{"domains":{"allow":["127.0.0.1"]}}});
    value["macos_seatbelt_profile_extension"] = json!("(allow network*)");
    let output = run(frame(&value), &[]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.ends_with(b"allowed"), "{output:?}");
    response.join().unwrap();
    value["command"] = fixture("bind-loopback", &[])["command"].clone();
    let output = run(frame(&value), &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"bound\n");
}

#[cfg(target_os = "macos")]
#[test]
fn mandatory_denies_survive_macos_extension_grants() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let denied = root.join("private");
    std::fs::create_dir_all(denied.join("nested")).unwrap();
    let secret = denied.join("nested/secret");
    std::fs::write(&secret, "secret").unwrap();
    let mut value = fixture(
        "probe-limits",
        &[
            secret.to_str().unwrap(),
            denied.join("nested/new").to_str().unwrap(),
            root.join("public").to_str().unwrap(),
        ],
    );
    value["filesystem"]["entries"]
        .as_array_mut()
        .unwrap()
        .push(json!({"path":{"type":"path","path":root},"access":"write"}));
    value["limits"] = json!({"filesystem":{"deny":[denied]}});
    value["macos_seatbelt_profile_extension"] = json!(format!(
        "(allow file-read* file-write* (subpath {}))",
        serde_json::to_string(&denied.join("nested")).unwrap()
    ));
    let output = run(frame(&value), &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"started\nclamped\n");
}
