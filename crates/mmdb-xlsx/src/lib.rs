//! Excel (.xlsx) import library for mmdb-creator.

pub(crate) mod address;
pub mod reader;

pub use reader::{CellValue, SheetInfo, SheetResult, XlsxRow, inspect_sheets, read_xlsx};
