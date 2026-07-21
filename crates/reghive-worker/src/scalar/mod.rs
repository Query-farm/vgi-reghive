//! Scalar functions exposed by the reghive worker, registered under
//! `reghive.main`.

pub mod hive_info;
pub mod hive_key;
pub mod hive_value;
pub mod io;
pub mod key_info;
pub mod logs_applied;
pub mod well_formed;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(hive_info::HiveInfo);
    worker.register_scalar(well_formed::WellFormed);
    worker.register_scalar(logs_applied::LogsApplied);
    worker.register_scalar(key_info::KeyInfo);
    worker.register_scalar(hive_key::HiveKey);
    worker.register_scalar(hive_value::HiveValue);
}
