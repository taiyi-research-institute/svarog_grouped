use std::fs;

use clap::{arg, Command};
use glob::glob;
use tonic_build;
use xuanmi_base_support::*;

fn main() -> Outcome<()> {
    // parse arguments
    let matches = Command::new("protoc-rust")
        .arg(
            arg!(-p --proto <PROTO_DIR>)
                .required(false)
                .default_value("proto"),
        )
        .arg(arg!(-r --rust <RUST_MODULE_DIR>).required(true))
        .get_matches();
    let proto_dir = matches.get_one::<String>("proto").unwrap().to_owned();
    let rust_dir = matches.get_one::<String>("rust").unwrap().to_owned();

    let mut mod_rs: Vec<String> = Vec::new();
    '_proto_to_rs: {
        let mut protos: Vec<String> = Vec::new();
        for entry in glob(&format!("{}/*.proto", proto_dir)).catch_()? {
            if let Ok(path) = entry {
                protos.push(path.to_str().unwrap().to_string());
                let filename = path.file_stem().unwrap().to_str().unwrap();
                mod_rs.push(format!("pub mod {};", filename));
            }
        }
        fs::create_dir_all(&rust_dir).catch_()?;
        tonic_build::configure()
            .out_dir(&rust_dir)
            .compile(&protos, &[&proto_dir])
            .catch_()?;
    }

    '_protogen_mod_rs: {
        // Concat mod_rs into a single string.
        let mod_rs = mod_rs.join("\n");
        // Write mod_rs to src/protogen/mod.rs.
        fs::write(&format!("{}/mod.rs", rust_dir), mod_rs).catch_()?;
    }

    Ok(())
}
