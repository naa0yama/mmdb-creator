# Testing Patterns — Project-Specific

> **Shared templates**: See `~/.claude/skills/rust-coding/references/testing-templates.md`
> for unit test, async test, integration test templates, fixtures, coverage rules,
> and ETXTBSY workaround.

## Miri Compatibility

For universal Miri rules and decision flowchart, see
`~/.claude/skills/rust-implementation/references/testing.md` → "Miri" section.

### Crate-Level Exclusions

| Crate  | Reason                         | Tests |
| ------ | ------------------------------ | ----- |
| (none) | No crates excluded at CI level | —     |

### Per-Test Skip Categories

1. **Process spawning (assert_cmd / Command)** — 7 tests. Integration tests in `crates/mmdb-creator/tests/integration_test.rs` execute the binary via `std::process::Command`. Miri does not support subprocess spawning.
2. **sysinfo / sysconf (process metrics)** — 4 tests. Tests calling sysinfo methods trigger `sysconf(_SC_CLK_TCK)` internally. Miri does not stub this syscall. Files: `crates/mmdb-creator/src/telemetry/metrics/process.rs`. Use `#[cfg_attr(miri, ignore)]` on individual tests.
3. **File system (tempfile)** — Tests using `tempfile::tempdir()` or real file I/O. Miri has limited file system support.
4. **TLS / Crypto (reqwest + rustls)** — TLS initialization is extremely slow under Miri (~10 min/call). Any test exercising the HTTP client must be ignored.
5. **Regex compilation (mmdb-xlsx)** — DFA construction under interpretation is extremely slow (~2-6 min/test). Tests in `crates/mmdb-xlsx/src/address.rs` call `parse_addresses` which initialises a `OnceLock<Regex>` on first call. All 15 unit tests in `address.rs` and 11 integration tests in `crates/mmdb-xlsx/tests/integration_test.rs` (which call `read_xlsx` → `parse_addresses`) need `#[cfg_attr(miri, ignore)]`.
6. **Network I/O (reqwest, tokio net)** — HTTP client and async socket operations use unsupported syscalls under Miri.

### Statistics

| Metric                                     | Count |
| ------------------------------------------ | ----- |
| Total tests                                | 103   |
| Per-crate breakdown: mmdb-core             | 4     |
| Per-crate breakdown: mmdb-creator          | 44    |
| Per-crate breakdown: mmdb-whois            | 17    |
| Per-crate breakdown: mmdb-xlsx             | 38    |
| Miri-annotated (cfg_attr)                  | 11    |
| Miri-missing annotations (mmdb-xlsx regex) | ~26   |
| Miri-compatible (estimated)                | 66    |
| Miri-excluded (crate-level)                | 0     |
