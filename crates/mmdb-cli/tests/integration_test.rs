//! Integration tests for the mmdb-cli binary.

use assert_cmd::cargo::CargoError;
use assert_cmd::prelude::*;
use predicates::prelude::predicate;
use std::process::Command;

fn cmd() -> Result<Command, CargoError> {
    Command::cargo_bin("mmdb-cli")
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_version_flag() {
    cmd()
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("mmdb-cli"))
        .stdout(predicate::str::contains("(rev:"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_help_shows_subcommands() {
    cmd()
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("import"))
        .stdout(predicate::str::contains("build"))
        .stdout(predicate::str::contains("scan"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_import_help() {
    cmd()
        .unwrap()
        .args(["import", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("whois"))
        .stdout(predicate::str::contains("xlsx"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_build_help() {
    cmd()
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--out"))
        .stdout(predicate::str::contains("--input"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_scan_help() {
    cmd()
        .unwrap()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--full"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_scan_enrich_only_is_unknown_flag() {
    cmd()
        .unwrap()
        .args(["scan", "--enrich-only"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("enrich"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_missing_config_fails() {
    // Non-interactive stdin ("no" to the create prompt) causes a non-zero exit.
    cmd()
        .unwrap()
        .args(["--config", "nonexistent.toml", "import"])
        .assert()
        .failure();
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_invalid_config_toml_fails() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("bad.toml");
    std::fs::write(&config_path, b"this is not valid toml = [[[").unwrap();

    cmd()
        .unwrap()
        .args(["--config", config_path.to_str().unwrap(), "scan"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to parse config"));
}
