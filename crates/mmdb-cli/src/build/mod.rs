//! Build subcommand: convert `scanned.jsonl` to mmdbctl NDJSON and invoke mmdbctl.

use std::io::{BufRead as _, Write as _};
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result};

use mmdb_core::{build::to_mmdb_record, config::Config, external, types::ScanGwRecord};

/// Run the build subcommand.
// NOTEST(io): reads JSONL from disk, writes output.jsonl, invokes mmdbctl binary
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run(_config: &Config, input: &Path, output: &Path) -> Result<()> {
    external::require_commands(&["mmdbctl"])?;

    let out_jsonl = Path::new("data/output.jsonl");

    tokio::try_join!(
        async {
            crate::backup::rotate_backup(out_jsonl, 5)
                .await
                .with_context(|| format!("failed to rotate backup for {}", out_jsonl.display()))
        },
        async {
            crate::backup::rotate_backup(output, 5)
                .await
                .with_context(|| format!("failed to rotate backup for {}", output.display()))
        },
    )?;

    // Read input JSONL and convert each record.
    let file = std::fs::File::open(input)
        .with_context(|| format!("failed to open input: {}", input.display()))?;
    let reader = std::io::BufReader::new(file);

    let out_file = std::fs::File::create(out_jsonl)
        .with_context(|| format!("failed to create {}", out_jsonl.display()))?;
    let mut writer = std::io::BufWriter::new(out_file);

    let mut total = 0usize;
    let mut inservice = 0usize;
    let mut xlsx_matched = 0usize;

    for line in reader.lines() {
        let line = line.context("failed to read line from input")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: ScanGwRecord =
            serde_json::from_str(line).context("failed to parse ScanGwRecord")?;

        if record.gateway_found {
            inservice = inservice.saturating_add(1);
        }
        if record.xlsx_matched {
            xlsx_matched = xlsx_matched.saturating_add(1);
        }
        total = total.saturating_add(1);

        let mmdb = to_mmdb_record(&record);
        let json = serde_json::to_string(&mmdb).context("failed to serialize MmdbRecord")?;
        writeln!(writer, "{json}").context("failed to write output line")?;
    }

    writer.flush().context("failed to flush output.jsonl")?;

    tracing::info!(
        total,
        inservice,
        xlsx_matched,
        no_xlsx = total.saturating_sub(xlsx_matched),
        "build: wrote {}",
        out_jsonl.display()
    );

    // Without --fields, mmdbctl infers the field list from the first JSON object
    // only, silently dropping any field absent from that first record.
    let status = Command::new("mmdbctl")
        .args([
            "import",
            "--json",
            "--ip",
            "4",
            "--size",
            "32",
            "--fields",
            "continent,country,autonomous_system_number,autonomous_system_organization,whois,gateway,operational,xlsx_matched,gateway_found",
            "-i",
            out_jsonl
                .to_str()
                .context("output.jsonl path is not valid UTF-8")?,
            "-o",
            output.to_str().context("output path is not valid UTF-8")?,
        ])
        .status()
        .context("failed to run mmdbctl")?;

    if !status.success() {
        anyhow::bail!("mmdbctl exited with status {status}; see output above for details");
    }

    tracing::info!(output = %output.display(), "build: MMDB written");
    Ok(())
}
