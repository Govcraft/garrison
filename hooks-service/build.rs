use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("hooks_descriptor.bin");

    let proto_files: Vec<PathBuf> = std::fs::read_dir("proto")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("proto"))
        .collect();

    tonic_prost_build::configure()
        .file_descriptor_set_path(&descriptor_path)
        .build_server(true)
        .build_client(false)
        .out_dir(&out_dir)
        .compile_protos(&proto_files, &[PathBuf::from("proto")])?;

    // Copy the freshly-built descriptor to a stable path at the project root
    // so the schemaforge runtime's `[[schema_forge.hooks.bindings]]` entry can
    // reference `hooks-service/hooks_descriptor.bin` without picking up a stale
    // copy. See schemaforge issue #15.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let stable_path = manifest_dir.join("hooks_descriptor.bin");
    std::fs::copy(&descriptor_path, &stable_path)?;

    for f in &proto_files {
        println!("cargo:rerun-if-changed={}", f.display());
    }
    println!(
        "cargo:rustc-env=HOOKS_DESCRIPTOR_PATH={}",
        descriptor_path.display()
    );
    Ok(())
}
