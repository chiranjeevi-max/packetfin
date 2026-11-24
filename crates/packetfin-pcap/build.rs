//! Link search path for libpcap or Npcap's `wpcap`.
//!
//! `src/ffi.rs` names the library. When it is not on the linker's default
//! search path, set `LIBPCAP_LIBDIR` to the directory that holds it: the
//! Npcap SDK's `Lib/x64` (or `Lib/ARM64`) on Windows, or a libpcap install
//! prefix's `lib` elsewhere.

fn main() {
    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    if let Some(directory) = std::env::var_os("LIBPCAP_LIBDIR") {
        // Cargo reads build-script output as UTF-8, so a path that is not
        // UTF-8 cannot be passed on unchanged.
        match directory.to_str() {
            Some(directory) => println!("cargo::rustc-link-search=native={directory}"),
            None => println!("cargo::error=LIBPCAP_LIBDIR is not valid UTF-8"),
        }
    }
}
