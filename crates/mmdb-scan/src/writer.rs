//! Buffered JSONL writer task for scan results.
//!
//! Decouples the scan loop from file I/O via an mpsc channel.
//! Flushes to disk when the buffer reaches `flush_count` records,
//! when `flush_interval` elapses, or when a `Shutdown` message is received.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use mmdb_core::types::ScanRecord;
use tokio::{io::AsyncWriteExt as _, sync::mpsc, task::JoinHandle, time};

/// Messages sent to the writer task.
#[allow(clippy::module_name_repetitions)]
pub enum WriterMsg {
    Record(Box<ScanRecord>),
    Shutdown,
}

/// Handle to the background writer task.
#[allow(clippy::module_name_repetitions)]
pub struct WriterHandle {
    sender: mpsc::Sender<WriterMsg>,
    join: JoinHandle<Result<()>>,
}

impl WriterHandle {
    /// Send a single scan record to the writer buffer (non-blocking).
    ///
    /// # Errors
    ///
    /// Returns an error if the writer task has already shut down.
    pub async fn send(&self, record: ScanRecord) -> Result<()> {
        self.sender
            .send(WriterMsg::Record(Box::new(record)))
            .await
            .context("writer task has shut down unexpectedly")
    }

    /// Flush the remaining buffer and wait for the writer task to exit.
    ///
    /// # Errors
    ///
    /// Returns any I/O error encountered by the writer task.
    pub async fn shutdown(self) -> Result<()> {
        // Dropping sender also closes the channel, but sending Shutdown is explicit.
        let _ = self.sender.send(WriterMsg::Shutdown).await;
        self.join.await.context("writer task panicked")??;
        Ok(())
    }
}

/// Spawn a background writer task that appends [`ScanRecord`]s to `path` as JSONL.
///
/// # Errors
///
/// Returns an error if the output file cannot be created or opened.
#[allow(clippy::module_name_repetitions)]
pub async fn spawn_writer(
    path: PathBuf,
    flush_count: usize,
    flush_interval: Duration,
) -> Result<WriterHandle> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .with_context(|| format!("failed to open scan output file {}", path.display()))?;

    let (sender, receiver) = mpsc::channel::<WriterMsg>(1024);

    let join = tokio::spawn(writer_task(file, receiver, flush_count, flush_interval));

    Ok(WriterHandle { sender, join })
}

async fn writer_task(
    mut file: tokio::fs::File,
    mut receiver: mpsc::Receiver<WriterMsg>,
    flush_count: usize,
    flush_interval: Duration,
) -> Result<()> {
    let mut buffer: Vec<ScanRecord> = Vec::with_capacity(flush_count);
    let mut interval = time::interval(flush_interval);
    interval.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            msg = receiver.recv() => {
                match msg {
                    Some(WriterMsg::Record(record)) => {
                        buffer.push(*record);
                        if buffer.len() >= flush_count {
                            flush_buffer(&mut file, &mut buffer).await?;
                        }
                    }
                    Some(WriterMsg::Shutdown) | None => {
                        flush_buffer(&mut file, &mut buffer).await?;
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush_buffer(&mut file, &mut buffer).await?;
                }
            }
        }
    }

    file.flush()
        .await
        .context("failed to flush scan output file")?;
    Ok(())
}

async fn flush_buffer(file: &mut tokio::fs::File, buffer: &mut Vec<ScanRecord>) -> Result<()> {
    for record in buffer.drain(..) {
        let line =
            serde_json::to_string(&record).context("failed to serialize ScanRecord to JSON")?;
        file.write_all(line.as_bytes())
            .await
            .context("failed to write scan JSONL line")?;
        file.write_all(b"\n")
            .await
            .context("failed to write newline")?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use mmdb_core::types::{Hop, RouteData};
    use tempfile::NamedTempFile;

    fn sample_record(dst: &str) -> ScanRecord {
        ScanRecord {
            range: String::from("192.0.2.0/29"),
            routes: RouteData {
                version: String::from("0.1"),
                measured_at: String::from("2026-05-07T00:00:00Z"),
                source: String::from("10.0.0.1"),
                destination: dst.to_owned(),
                stop_reason: String::from("COMPLETED"),
                hops: vec![Hop {
                    hop: 1,
                    ip: Some(dst.to_owned()),
                    rtt_avg: Some(1.0),
                    rtt_best: Some(0.9),
                    rtt_worst: Some(1.1),
                    icmp_type: Some(0),
                    asn: None,
                    ptr: None,
                }],
            },
        }
    }

    // NOTEST(io): file I/O — skipped in Miri
    #[tokio::test]
    async fn writer_flushes_on_shutdown() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let handle = spawn_writer(path.clone(), 100, Duration::from_secs(60))
            .await
            .unwrap();

        handle.send(sample_record("192.0.2.1")).await.unwrap();
        handle.send(sample_record("192.0.2.2")).await.unwrap();
        handle.shutdown().await.unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("192.0.2.1"));
        assert!(lines[1].contains("192.0.2.2"));
    }

    // NOTEST(io): file I/O — skipped in Miri
    #[tokio::test]
    async fn writer_flushes_on_count_threshold() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        // flush_count = 2 so the second record triggers a flush.
        let handle = spawn_writer(path.clone(), 2, Duration::from_secs(60))
            .await
            .unwrap();

        handle.send(sample_record("192.0.2.1")).await.unwrap();
        handle.send(sample_record("192.0.2.2")).await.unwrap();
        // Give the writer task a moment to flush before checking.
        tokio::time::sleep(Duration::from_millis(50)).await;

        handle.shutdown().await.unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
    }
}
