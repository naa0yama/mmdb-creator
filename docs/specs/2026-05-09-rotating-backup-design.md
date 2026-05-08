# Design: Rotating Backup for Output JSONL Files

## Problem

`data/scanned.jsonl` and `data/whois-cidr.jsonl` are overwritten each time
the corresponding commands run. An accidental or incorrect run destroys the
previous output with no way to recover it. A simple timestamped-copy rotation
scheme allows the user to `cp` back to any of the last five states.

## Goals

- Before each write to a target file, preserve the current on-disk content as
  a timestamped sibling (e.g. `scanned.20260509-001712.jsonl`).
- Retain at most 5 backup copies per file; delete the oldest when the limit is
  exceeded.
- Zero change to the normal write path: existing atomic-rename and direct
  `File::create` flows are unmodified.
- Timestamp format: `%Y%m%d-%H%M%S` (local time).

## Non-Goals

- Cache files (`data/cache/whois-cidr-*.jsonl`, `data/cache/ripestat-*.jsonl`)
  are excluded — too numerous for per-file rotation to be useful.
- No compression or checksum of backup files.
- No configurable retention count (hard-coded to 5).

## Approach

Add a single async utility function `rotate_backup` in a new module
`crates/mmdb-creator/src/backup.rs`.

Call it at two sites, always immediately before the destructive write:

| Call site                              | File                    | Position                         |
| -------------------------------------- | ----------------------- | -------------------------------- |
| `write_jsonl` in `enrich.rs`           | `data/scanned.jsonl`    | before `tokio::fs::rename`       |
| `write_whois_jsonl` in `import/mod.rs` | `data/whois-cidr.jsonl` | before `tokio::fs::File::create` |

## Implementation Notes

### `rotate_backup` signature

```rust
/// Copy `path` to a timestamped sibling, then delete the oldest siblings
/// beyond `keep`.  No-ops when `path` does not exist.
pub async fn rotate_backup(path: &Path, keep: usize) -> Result<()>
```

### Backup file naming

Given `path = data/scanned.jsonl`:

- stem: `scanned`
- ext: `jsonl`
- backup name: `scanned.20260509-001712.jsonl`

Pattern used to identify siblings: `{stem}.YYYYMMDD-HHMMSS.{ext}` — matched
by checking that the file name starts with `{stem}.`, ends with `.{ext}`, and
is not equal to the original file name (`{stem}.{ext}`).

### Rotation algorithm

1. If `path` does not exist → return `Ok(())`.
2. Build `backup_path = parent / format!("{stem}.{ts}.{ext}")` where `ts` is
   `chrono::Local::now().format("%Y%m%d-%H%M%S")`.
3. `tokio::fs::copy(path, backup_path)`.
4. Read `parent` directory; collect all paths whose name matches the sibling
   pattern; sort lexicographically descending (newest first).
5. Delete all entries beyond index `keep - 1`.

### Crate dependencies

`chrono` is already in the workspace. No new dependencies required.

## Testing Strategy

Unit tests in `backup.rs` using `tempfile::TempDir`:

- No-op when file does not exist.
- Creates exactly one backup on first call.
- Accumulates up to `keep` backups, then removes oldest on the `keep+1`-th call.
- Backup name format is correct (matches expected timestamp pattern).
- Original file is preserved after `rotate_backup` (copy, not move).

## Open Questions

None.
