use super::console_host_environment;
use pretty_assertions::assert_eq;
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

#[test]
fn console_host_environment_rejects_unrepresentable_names_and_values() {
    let invalid = OsString::from_wide(&[0xd800]);
    for entries in [
        vec![(invalid.clone(), OsString::from("value"))],
        vec![(OsString::from("HOST_OVERRIDE"), invalid.clone())],
    ] {
        let error = console_host_environment(entries).unwrap_err();
        assert!(error.to_string().contains("not valid Unicode"));
    }
    assert_eq!(
        console_host_environment([
            (OsString::from("=C:"), invalid),
            (OsString::from("HOST_OVERRIDE"), OsString::from("trusted")),
        ])
        .unwrap(),
        HashMap::from([("HOST_OVERRIDE".to_owned(), "trusted".to_owned())]),
    );
}
