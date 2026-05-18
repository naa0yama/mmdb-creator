//! Rotating backup utility — writes timestamped copies to a `backup/` subdirectory.

use std::path::Path;

use anyhow::{Context as _, Result};
use chrono::Local;

/// Copy `path` to `{parent}/backup/{stem}.{YYYYMMDD-HHMMSS}.{ext}`, then
/// delete the oldest entries beyond `keep`.  No-ops when `path` does not exist.
///
/// # Errors
///
/// Returns an error if copying, creating the backup directory, or deleting
/// files fails.
#[allow(clippy::module_name_repetitions)]
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

    let backup_dir = parent.join("backup");
    tokio::fs::create_dir_all(&backup_dir)
        .await
        .with_context(|| format!("failed to create backup directory {}", backup_dir.display()))?;

    let backup_path = backup_dir.join(format!(
        "{stem}.{}.{ext}",
        Local::now().format("%Y%m%d-%H%M%S")
    ));

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

    let prefix = format!("{stem}.");
    let suffix = format!(".{ext}");

    let mut read_dir = tokio::fs::read_dir(&backup_dir)
        .await
        .with_context(|| format!("failed to read directory {}", backup_dir.display()))?;

    let mut backups = Vec::new();
    while let Some(entry) = read_dir
        .next_entry()
        .await
        .context("failed to read directory entry")?
    {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(&prefix) && name_str.ends_with(&suffix) {
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
    async fn creates_single_backup_in_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scanned.jsonl");
        tokio::fs::write(&path, b"data").await.unwrap();

        rotate_backup(&path, 5).await.unwrap();

        assert!(path.exists(), "original must still exist");

        let backup_dir = dir.path().join("backup");
        assert!(backup_dir.is_dir(), "backup/ subdir must be created");

        let mut rd = tokio::fs::read_dir(&backup_dir).await.unwrap();
        let mut backup_names = Vec::new();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            backup_names.push(entry.file_name().to_string_lossy().to_string());
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

        let backup_dir = dir.path().join("backup");
        let mut rd = tokio::fs::read_dir(&backup_dir).await.unwrap();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            let content = tokio::fs::read(entry.path()).await.unwrap();
            assert_eq!(content, b"hello world");
        }
    }

    #[cfg_attr(miri, ignore)] // tokio::fs uses fchmod which Miri does not support
    #[tokio::test]
    async fn retains_at_most_keep_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scanned.jsonl");

        let backup_dir = dir.path().join("backup");
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();

        // Pre-create 5 older backups
        for i in 1..=5u32 {
            let name = format!("scanned.2026050{i}-000000.jsonl");
            tokio::fs::write(backup_dir.join(&name), b"old")
                .await
                .unwrap();
        }
        tokio::fs::write(&path, b"new").await.unwrap();

        // This call creates one more backup (total 6), oldest should be pruned
        rotate_backup(&path, 5).await.unwrap();

        let mut rd = tokio::fs::read_dir(&backup_dir).await.unwrap();
        let mut backups = Vec::new();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            backups.push(entry.file_name().to_string_lossy().to_string());
        }
        assert_eq!(
            backups.len(),
            5,
            "should retain exactly 5 backups, got: {backups:?}"
        );
        assert!(
            !backups.iter().any(|n| n.contains("20260501-000000")),
            "oldest backup should be pruned"
        );
    }
}
