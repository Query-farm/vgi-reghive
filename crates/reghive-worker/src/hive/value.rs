//! Decode a `notatin` `CellKeyValue` into the §5 value columns: the REG_* type
//! name, the lossless `value_raw` bytes, the coerced `value_data` rendering, and
//! the `value_dword` integer — all via the pure `reghive_core::valuetype` engine
//! (the worker keeps the raw bytes and lets core do the coercion).

use notatin::cell_key_value::CellKeyValue;
use reghive_core::valuetype;

/// The decoded view of one registry value.
#[derive(Clone, Debug, Default)]
pub struct DecodedValue {
    /// Value name; `None` for the (Default) value.
    pub name: Option<String>,
    pub value_type: String,
    pub value_data: String,
    pub value_raw: Vec<u8>,
    pub value_dword: Option<i64>,
    pub diagnostics: Option<String>,
}

/// Decode a value cell. `value_raw` is the exact on-disk bytes; `value_data` is
/// the convenience coercion. Never panics — every field is read defensively.
pub fn decode(val: &CellKeyValue) -> DecodedValue {
    let raw = val.detail.value_bytes().unwrap_or_default();
    let type_raw = val.detail.data_type_raw();
    let coerced = valuetype::coerce(type_raw, &raw);

    let name = {
        let n = val.detail.value_name();
        if n.is_empty() {
            None
        } else {
            Some(n)
        }
    };

    DecodedValue {
        name,
        value_type: valuetype::type_name(type_raw),
        value_data: coerced.value_data,
        value_raw: raw,
        value_dword: coerced.value_dword,
        diagnostics: coerced.diagnostics.map(|s| s.to_string()),
    }
}
