//! Export subcommand: merge collected data and generate `MMDB` via mmdbctl.

use std::path::Path;

use anyhow::Result;

use mmdb_core::{config::Config, external};

/// Run the export subcommand.
// NOTEST(io): invokes external mmdbctl binary — depends on external process
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unused_async)]
pub async fn run(_config: &Config, output: &Path) -> Result<()> {
    external::require_commands(&["mmdbctl"])?;

    tracing::info!(?output, "export: not yet implemented");
    Ok(())
}
