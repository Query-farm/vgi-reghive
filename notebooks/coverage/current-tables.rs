//! Table functions exposed by the reghive worker, registered under
//! `reghive.main`.

pub mod common;
pub mod hive_subtree;
pub mod read_hive;

use vgi::Worker;

/// Register every table function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table(read_hive::ReadHive);
    worker.register_table(hive_subtree::HiveSubtree);
}
