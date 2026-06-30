//! Small Arrow input helpers shared by the scalar probes: reading a BLOB cell
//! (the hive bytes) and a VARCHAR cell (a key path / value name), tolerant of the
//! several Arrow widths DuckDB may hand a worker.

use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef};
use arrow_schema::DataType;
use vgi_rpc::{Result, RpcError};

/// Borrow the bytes of a BLOB cell at `row`, or `None` if null. Errors if the
/// column is not a binary type.
pub fn blob_val(col: &ArrayRef, row: usize) -> Result<Option<Vec<u8>>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Binary => col.as_binary::<i32>().value(row).to_vec(),
        DataType::LargeBinary => col.as_binary::<i64>().value(row).to_vec(),
        DataType::BinaryView => col.as_binary_view().value(row).to_vec(),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a BLOB (binary) argument, got {other:?}"
            )))
        }
    }))
}

/// Borrow the UTF-8 text of a VARCHAR cell at `row`, or `None` if null.
pub fn text_val(col: &ArrayRef, row: usize) -> Result<Option<String>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Utf8 => col.as_string::<i32>().value(row).to_string(),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row).to_string(),
        DataType::Utf8View => col.as_string_view().value(row).to_string(),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a VARCHAR (string) argument, got {other:?}"
            )))
        }
    }))
}
