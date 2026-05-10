//! External command availability checks.

use std::path::PathBuf;

use anyhow::Result;

/// Verify that a single external command is available in `PATH`.
///
/// Returns the resolved path on success, or an error with an install hint.
///
/// # Errors
///
/// Returns an error if `name` is not found in any directory on `PATH`.
pub fn require_command(name: &str) -> Result<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();

    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "required external command `{name}` not found in PATH\n\
                 hint: install it and ensure it is on your PATH"
            )
        })
}

/// Verify that all listed external commands are available in `PATH`.
///
/// Fails on the first missing command.
///
/// # Errors
///
/// Returns an error for the first command in `names` not found in `PATH`.
pub fn require_commands(names: &[&str]) -> Result<()> {
    for &name in names {
        require_command(name)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_common_command() {
        // `ls` is present on every Unix system
        let path = require_command("ls");
        assert!(path.is_ok(), "expected `ls` to be found in PATH");
    }

    #[test]
    fn errors_on_missing_command() {
        let result = require_command("__no_such_command_mmdb_cli__");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("__no_such_command_mmdb_cli__"));
        assert!(msg.contains("PATH"));
    }

    #[test]
    fn require_commands_fails_on_first_missing() {
        let result = require_commands(&["ls", "__no_such_command_mmdb_cli__"]);
        assert!(result.is_err());
    }

    #[test]
    fn require_commands_passes_when_all_present() {
        let result = require_commands(&["ls"]);
        assert!(result.is_ok());
    }
}
