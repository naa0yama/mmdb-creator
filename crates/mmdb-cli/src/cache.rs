//! Cache management utilities: clear cache directories and files before a forced re-run.

use std::path::Path;

use anyhow::{Context as _, Result};

/// Remove all contents of a directory, then recreate it as an empty directory.
///
/// Does nothing if the directory does not exist.
///
/// # Errors
///
/// Returns an error if removing or recreating the directory fails.
pub async fn clear_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    tokio::fs::remove_dir_all(path)
        .await
        .with_context(|| format!("failed to remove cache directory {}", path.display()))?;
    tokio::fs::create_dir_all(path)
        .await
        .with_context(|| format!("failed to recreate cache directory {}", path.display()))?;
    tracing::info!(path = %path.display(), "cache: cleared directory");
    Ok(())
}

/// Remove a single file if it exists.
///
/// Does nothing if the file does not exist.
///
/// # Errors
///
/// Returns an error if removing the file fails.
pub async fn clear_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    tokio::fs::remove_file(path)
        .await
        .with_context(|| format!("failed to remove cache file {}", path.display()))?;
    tracing::info!(path = %path.display(), "cache: cleared file");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn clear_dir_removes_contents_and_recreates() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        tokio::fs::create_dir_all(&cache_dir).await.unwrap();
        tokio::fs::write(cache_dir.join("foo.jsonl"), b"data")
            .await
            .unwrap();

        clear_dir(&cache_dir).await.unwrap();

        assert!(cache_dir.exists(), "directory should be recreated");
        let mut entries = tokio::fs::read_dir(&cache_dir).await.unwrap();
        assert!(
            entries.next_entry().await.unwrap().is_none(),
            "directory should be empty"
        );
    }

    #[tokio::test]
    async fn clear_dir_noop_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent");

        clear_dir(&missing).await.unwrap();
    }

    #[tokio::test]
    async fn clear_file_removes_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("scan.jsonl");
        tokio::fs::write(&file, b"data").await.unwrap();

        clear_file(&file).await.unwrap();

        assert!(!file.exists());
    }

    #[tokio::test]
    async fn clear_file_noop_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent.jsonl");

        clear_file(&missing).await.unwrap();
    }
}
