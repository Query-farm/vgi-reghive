//! Open a hive blob into a `notatin` `Parser` (with optional sibling
//! transaction-log replay and deleted-cell recovery), plus the base-block
//! summary the worker surfaces directly.
//!
//! Robustness: a hostile / truncated / non-hive blob yields an [`OpenError`]
//! (never a panic). The base block is parsed by the pure `reghive_core` reader
//! first, so `hive_info` / `well_formed` work even when `notatin` declines to
//! build a walkable parser.

use std::io::Cursor;

use notatin::parser::Parser;
use notatin::parser_builder::ParserBuilder;
use reghive_core::baseblock::{self, BaseBlock, WellFormedKind};

/// Why opening a hive failed (maps onto `well_formed.kind`).
#[derive(Clone, Debug)]
pub struct OpenError {
    pub kind: WellFormedKind,
    pub message: String,
}

impl OpenError {
    fn new(kind: WellFormedKind, message: impl Into<String>) -> Self {
        OpenError {
            kind,
            message: message.into(),
        }
    }
}

/// A successfully opened hive: the walkable parser plus its surfaced header.
pub struct Opened {
    pub parser: Parser,
    /// The base block, if it parsed (best-effort; may be `None` for odd headers).
    pub base: Option<BaseBlock>,
    /// The hive's `well_formed` classification at open time.
    pub kind: WellFormedKind,
    /// The synthetic root key name (e.g. `CMI-CreateHive{…}`) used to normalize
    /// paths, or empty if unavailable.
    pub root_name: String,
    /// The logical hive type label (SYSTEM / SOFTWARE / …).
    pub hive_type: String,
    /// True when the primary base block alone is dirty (pre-recovery).
    pub was_dirty: bool,
}

/// Open an in-memory hive blob. `logs` are optional `.LOG1`/`.LOG2` blobs to
/// replay when `apply_logs` is set; `recover_deleted` enables unallocated-cell
/// recovery.
pub fn open_blob(
    bytes: &[u8],
    apply_logs: bool,
    recover_deleted: bool,
    logs: &[Vec<u8>],
) -> std::result::Result<Opened, OpenError> {
    // Parse the base block ourselves first — this also rejects obvious garbage
    // before handing bytes to notatin, and feeds hive_info / well_formed.
    let (base, kind) = baseblock::parse(bytes);
    match kind {
        WellFormedKind::Ok | WellFormedKind::BadChecksum => {}
        WellFormedKind::Truncated => {
            return Err(OpenError::new(kind, "blob too short to be a hive"))
        }
        WellFormedKind::BadSignature => {
            return Err(OpenError::new(kind, "not a regf hive (bad signature)"))
        }
        WellFormedKind::NotAHive => {
            return Err(OpenError::new(kind, "regf file is not a primary hive"))
        }
        WellFormedKind::ShortBaseBlock => {
            return Err(OpenError::new(kind, "incomplete base block"))
        }
        WellFormedKind::BinSizeOverrun => {
            return Err(OpenError::new(kind, "hive-bins size overruns the blob"))
        }
    }

    let was_dirty = base.as_ref().map(|b| b.is_dirty()).unwrap_or(false);

    let mut builder = ParserBuilder::from_file(Cursor::new(bytes.to_vec()));
    builder.recover_deleted(recover_deleted);
    if apply_logs {
        for log in logs {
            builder.with_transaction_log(Cursor::new(log.clone()));
        }
    }
    let mut parser = builder
        .build()
        .map_err(|e| OpenError::new(WellFormedKind::Truncated, format!("notatin: {e}")))?;

    // The root key name anchors path normalization (and the hive-type sniff).
    let root_name = match parser.get_root_key() {
        Ok(Some(root)) => root.key_name.clone(),
        _ => String::new(),
    };

    let hive_type = base
        .as_ref()
        .map(|b| b.hive_type(Some(&root_name)).label().to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string());

    Ok(Opened {
        parser,
        base,
        kind,
        root_name,
        hive_type,
        was_dirty,
    })
}
