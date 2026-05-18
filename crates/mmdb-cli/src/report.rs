//! Report subcommand: generate an HTML Sankey topology report from scanned.jsonl.

use std::io::BufRead as _;
use std::path::Path;

use anyhow::Context as _;
use mmdb_core::types::ScanGwRecord;

/// Run the report subcommand.
// NOTEST(io): reads jsonl, writes HTML — file I/O not tested at unit level
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn run(input: &Path, output: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(input)
        .with_context(|| format!("failed to open input: {}", input.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut records: Vec<ScanGwRecord> = Vec::new();
    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: ScanGwRecord =
            serde_json::from_str(line).context("failed to parse ScanGwRecord")?;
        records.push(record);
    }
    let html = mmdb_web::report::generate(&records)?;
    std::fs::write(output, html)
        .with_context(|| format!("failed to write output: {}", output.display()))?;
    tracing::info!(
        output = %output.display(),
        records = records.len(),
        "report generated"
    );
    Ok(())
}
