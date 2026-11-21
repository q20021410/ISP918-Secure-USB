use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=../secure_shield.ico");

    let out_dir = env::var("OUT_DIR").unwrap();
    let res_path = Path::new(&out_dir).join("app.res");

    let rc_candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\rc.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\rc.exe",
        "rc.exe",
    ];

    for rc in &rc_candidates {
        if Path::new(rc).exists() || *rc == "rc.exe" {
            let status = Command::new(rc)
                .args(&["/nologo", "/fo", res_path.to_str().unwrap(), "app.rc"])
                .status();
            if let Ok(s) = status {
                if s.success() && res_path.exists() {
                    println!("cargo:rustc-link-arg-bins={}", res_path.display());
                    break;
                }
            }
        }
    }
}
