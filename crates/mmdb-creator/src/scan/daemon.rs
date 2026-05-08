//! scamper daemon lifecycle management.
//!
//! Spawns `scamper` in daemon mode (`-D`) connected via a Unix socket,
//! waits for the socket to become ready, attaches the session, and
//! provides the connected stream for sending trace commands.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use tokio::{
    io::AsyncWriteExt as _,
    net::UnixStream,
    process::{Child, Command},
    time,
};

/// A running scamper daemon and its connected Unix socket stream.
#[allow(clippy::module_name_repetitions)]
pub struct ScamperDaemon {
    child: Child,
    socket_path: PathBuf,
    stream: UnixStream,
}

impl ScamperDaemon {
    /// Spawn a scamper daemon at `pps` packets-per-second and attach to it.
    ///
    /// Polls for the socket to appear for up to 3 seconds (30 × 100 ms intervals).
    ///
    /// # Errors
    ///
    /// Returns an error if scamper cannot be spawned, the socket does not appear
    /// within the timeout, or the initial `attach` handshake fails.
    pub async fn spawn(pps: u32) -> Result<Self> {
        let socket_path = socket_path();

        // Remove stale socket from a previous run if present.
        if socket_path.exists() {
            tokio::fs::remove_file(&socket_path)
                .await
                .with_context(|| {
                    format!("failed to remove stale socket {}", socket_path.display())
                })?;
        }

        let child = Command::new("scamper")
            .args([
                "-D",
                "-U",
                socket_path
                    .to_str()
                    .context("socket path is not valid UTF-8")?,
                "-p",
                &pps.to_string(),
            ])
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn scamper daemon")?;

        // Wait for the socket to appear (max 3 seconds).
        let mut ready = false;
        for _ in 0..30u32 {
            time::sleep(std::time::Duration::from_millis(100)).await;
            if tokio::fs::metadata(&socket_path).await.is_ok() {
                ready = true;
                break;
            }
        }
        if !ready {
            anyhow::bail!(
                "scamper daemon socket {} did not appear within 3 seconds",
                socket_path.display()
            );
        }

        let mut stream = UnixStream::connect(&socket_path).await.with_context(|| {
            format!(
                "failed to connect to scamper socket {}",
                socket_path.display()
            )
        })?;

        // Attach with JSON output — avoids the sc_warts2json binary dependency and the
        // file-header requirement of the warts binary format.
        // Request JSON output so DATA blocks contain plain JSON text instead of
        // UUencoded warts binary, avoiding the need for sc_warts2json.
        stream
            .write_all(b"attach format json\n")
            .await
            .context("failed to send attach command to scamper")?;

        // Drain the initial handshake: scamper sends "OK\n" then "MORE\n".
        // We must consume these before handing the stream to scan_loop, otherwise
        // scan_loop's pre-fill writes commands before scamper has signalled readiness.
        {
            use tokio::io::{AsyncBufReadExt as _, BufReader};
            let mut reader = BufReader::new(&mut stream);
            let mut got_more = false;
            for _ in 0..10u8 {
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .await
                    .context("failed to read attach handshake from scamper")?;
                let trimmed = line.trim();
                tracing::debug!(msg = trimmed, "scamper: attach handshake");
                if trimmed == "MORE" {
                    got_more = true;
                    break;
                }
            }
            if !got_more {
                anyhow::bail!("scamper attach handshake did not receive MORE within 10 lines");
            }
        }

        tracing::info!(
            pps,
            socket = %socket_path.display(),
            "scamper: daemon ready"
        );

        Ok(Self {
            child,
            socket_path,
            stream,
        })
    }

    /// Borrow the connected Unix socket stream for sending trace commands.
    #[allow(clippy::missing_const_for_fn)]
    pub fn stream(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    /// Kill the scamper daemon and remove the socket file.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be killed or the socket cannot be removed.
    pub async fn shutdown(mut self) -> Result<()> {
        self.child
            .kill()
            .await
            .context("failed to kill scamper daemon")?;

        if self.socket_path.exists() {
            tokio::fs::remove_file(&self.socket_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove scamper socket {}",
                        self.socket_path.display()
                    )
                })?;
        }

        tracing::info!(socket = %self.socket_path.display(), "scamper: daemon stopped");
        Ok(())
    }
}

/// Generate a per-process Unix socket path under `/tmp`.
fn socket_path() -> PathBuf {
    PathBuf::from(format!("/tmp/mmdb-creator-{}.sock", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_contains_pid() {
        let path = socket_path();
        let pid = std::process::id().to_string();
        assert!(path.to_string_lossy().contains(&pid));
        assert!(path.to_string_lossy().starts_with("/tmp/mmdb-creator-"));
        assert!(path.to_string_lossy().ends_with(".sock"));
    }

    // Integration test — requires `scamper` installed.
    #[tokio::test]
    #[ignore = "requires scamper binary installed on PATH"]
    async fn spawn_and_shutdown_daemon() {
        let daemon = ScamperDaemon::spawn(10).await.unwrap();
        daemon.shutdown().await.unwrap();
    }
}
