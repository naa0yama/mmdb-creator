//! Excel (.xlsx) import library for mmdb-creator.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub(crate) mod address;
pub mod filter;
pub mod import;
pub mod reader;
pub mod writer;

pub use reader::{CellValue, SheetInfo, SheetResult, XlsxRow, inspect_sheets, read_xlsx};
