//! Rotating backup utility for JSONL output files.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use chrono::Local;

/// Copy `path` to a timestamped sibling, then delete the oldest siblings
/// beyond `keep`.  No-ops when `path` does not exist.
///
/// Backup name format: `{stem}.{YYYYMMDD-HHMMSS}.{ext}` (local time).
///
/// # Errors
///
/// Returns an error if copying or deleting files fails.
pub async fn rotate_backup(path: &Path, keep: usize) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .with_context(|| format!("invalid file stem for {}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .with_context(|| format!("invalid extension for {}", path.display()))?;
    let parent = path.parent().map_or_else(
        || Path::new("."),
        |p| {
            if p.as_os_str().is_empty() {
                Path::new(".")
            } else {
                p
            }
        },
    );

    let ts = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let backup_path = parent.join(format!("{stem}.{ts}.{ext}"));

    tokio::fs::copy(path, &backup_path).await.with_context(|| {
        format!(
            "failed to copy {} to {}",
            path.display(),
            backup_path.display()
        )
    })?;

    tracing::debug!(
        src = %path.display(),
        dst = %backup_path.display(),
        "backup: created"
    );

    // Collect sibling backup files matching {stem}.*.{ext}
    let prefix = format!("{stem}.");
    let suffix = format!(".{ext}");
    let original_name = format!("{stem}.{ext}");

    let mut read_dir = tokio::fs::read_dir(parent)
        .await
        .with_context(|| format!("failed to read directory {}", parent.display()))?;

    let mut backups: Vec<PathBuf> = Vec::new();
    while let Some(entry) = read_dir
        .next_entry()
        .await
        .context("failed to read directory entry")?
    {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(&prefix)
            && name_str.ends_with(&suffix)
            && name_str != original_name.as_str()
        {
            backups.push(entry.path());
        }
    }

    // Sort descending (newest first; YYYYMMDD-HHMMSS is lexicographically monotone)
    backups.sort_unstable_by(|a, b| b.cmp(a));

    for old in backups.into_iter().skip(keep) {
        tokio::fs::remove_file(&old)
            .await
            .with_context(|| format!("failed to remove old backup {}", old.display()))?;
        tracing::debug!(path = %old.display(), "backup: removed old");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore)] // tokio::fs uses fchmod which Miri does not support
    #[tokio::test]
    async fn noop_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scanned.jsonl");

        rotate_backup(&path, 5).await.unwrap();

        let mut rd = tokio::fs::read_dir(dir.path()).await.unwrap();
        assert!(rd.next_entry().await.unwrap().is_none());
    }

    #[cfg_attr(miri, ignore)] // tokio::fs uses fchmod which Miri does not support
    #[tokio::test]
    async fn creates_single_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scanned.jsonl");
        tokio::fs::write(&path, b"data").await.unwrap();

        rotate_backup(&path, 5).await.unwrap();

        assert!(path.exists(), "original must still exist");

        let mut rd = tokio::fs::read_dir(dir.path()).await.unwrap();
        let mut backup_names = Vec::new();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "scanned.jsonl" {
                backup_names.push(name);
            }
        }
        assert_eq!(backup_names.len(), 1);
        let name = backup_names.first().unwrap();
        assert!(name.starts_with("scanned."));
        assert!(
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
        );
    }

    #[cfg_attr(miri, ignore)] // tokio::fs uses fchmod which Miri does not support
    #[tokio::test]
    async fn backup_preserves_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scanned.jsonl");
        tokio::fs::write(&path, b"hello world").await.unwrap();

        rotate_backup(&path, 5).await.unwrap();

        let mut rd = tokio::fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "scanned.jsonl" {
                let content = tokio::fs::read(entry.path()).await.unwrap();
                assert_eq!(content, b"hello world");
            }
        }
    }

    #[cfg_attr(miri, ignore)] // tokio::fs uses fchmod which Miri does not support
    #[tokio::test]
    async fn retains_at_most_keep_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scanned.jsonl");

        // Pre-create 5 older backups
        for i in 1..=5u32 {
            let name = format!("scanned.2026050{i}-000000.jsonl");
            tokio::fs::write(dir.path().join(&name), b"old")
                .await
                .unwrap();
        }
        tokio::fs::write(&path, b"new").await.unwrap();

        // This call creates one more backup (total 6), oldest should be pruned
        rotate_backup(&path, 5).await.unwrap();

        let mut rd = tokio::fs::read_dir(dir.path()).await.unwrap();
        let mut backups = Vec::new();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "scanned.jsonl" {
                backups.push(name);
            }
        }
        assert_eq!(
            backups.len(),
            5,
            "should retain exactly 5 backups, got: {backups:?}"
        );
        // The oldest (20260501-000000) must have been removed
        assert!(
            !backups.iter().any(|n| n.contains("20260501-000000")),
            "oldest backup should be pruned"
        );
    }
}
