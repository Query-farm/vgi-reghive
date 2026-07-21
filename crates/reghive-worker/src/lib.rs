//! Library surface of the `reghive` VGI worker.
//!
//! The binary (`main.rs`) is the actual worker; this `lib` target exposes the
//! parsing modules so integration tests under `tests/` can exercise them
//! directly, without the Arrow IPC / RPC plumbing.

pub mod arrow_map;
pub mod hive;
pub mod meta;
pub mod sample;
pub mod scalar;
pub mod table;

/// Worker version string, published as the catalog `implementation_version`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
