use std::env;
use std::path::PathBuf;

const SETUP_BIN: &str = "mcp-console-sandbox-setup";
const SETUP_MANIFEST: &str = "mcp-console-sandbox-setup.manifest";

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed={SETUP_MANIFEST}");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return Ok(());
    }

    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .ok_or_else(|| "CARGO_MANIFEST_DIR should be set for build scripts".to_string())?;
    let manifest_path = PathBuf::from(manifest_dir).join(SETUP_MANIFEST);
    let manifest_path = manifest_path.display();

    // Keep the manifest scoped to setup; the command runner has its own
    // windows_subsystem attribute and must not inherit this resource.
    match (
        env::var("CARGO_CFG_TARGET_ENV").as_deref(),
        env::var("CARGO_CFG_TARGET_ABI").as_deref(),
    ) {
        (Ok("msvc"), _) => {
            println!("cargo:rustc-link-arg-bin={SETUP_BIN}=/MANIFEST:EMBED");
            println!("cargo:rustc-link-arg-bin={SETUP_BIN}=/MANIFESTINPUT:{manifest_path}");
        }
        (Ok("gnu"), Ok("llvm")) => {
            println!("cargo:rustc-link-arg-bin={SETUP_BIN}=-Wl,-Xlink=/manifest:embed");
            println!(
                "cargo:rustc-link-arg-bin={SETUP_BIN}=-Wl,-Xlink=/manifestinput:{manifest_path}"
            );
        }
        _ => {}
    }

    Ok(())
}
