# Design: --force flag for cache-clearing subcommands

## Problem

`import --whois` and `scan` cache intermediate results to avoid redundant
network calls. When data becomes stale or corrupted, users have no way to
force a clean re-run without manually deleting cache directories. A `--force`
flag would let users trigger a cache wipe atomically before execution.

## Goals

- Add `--force` to `import` subcommand: wipe `data/cache/import/` before running.
- Add `--force` to `scan` subcommand: wipe `data/cache/scan/scanning.jsonl` before running.
- Subcommands without caches (`export`, `validate`) do NOT get `--force`.
- Shared cache-clear logic is implemented in one place to avoid duplication.

## Non-Goals

- A global `--force` flag at the top-level `Args` level.
- Clearing `data/whois-cidr.jsonl` or `data/scanned.jsonl` (those are final outputs, not caches).
- Interactive confirmation prompt before deletion.

## Approach

Add `force: bool` field to the `Import` and `Scan` variants in `cli.rs`.
Implement a `clear_dir(path)` helper and a `clear_file(path)` helper in
`crates/mmdb-creator/src/` (e.g., `src/cache.rs`) called at the top of each
subcommand's `run()` function when `force` is true.

## Implementation Notes

### CLI (`crates/mmdb-creator/src/cli.rs`)

```rust
Import {
    #[arg(long)]
    force: bool,
    // ... existing fields
}

Scan {
    #[arg(long)]
    force: bool,
    // ... existing fields
}
```

### Cache helper (`crates/mmdb-creator/src/cache.rs`)

```rust
/// Remove all contents of a directory, then recreate it.
pub async fn clear_dir(path: &Path) -> Result<()>

/// Remove a single file if it exists.
pub async fn clear_file(path: &Path) -> Result<()>
```

### import subcommand (`crates/mmdb-creator/src/import/mod.rs`)

```rust
if force {
    cache::clear_dir(Path::new("data/cache/import")).await?;
}
```

### scan subcommand (`crates/mmdb-creator/src/scan/mod.rs`)

```rust
if force {
    cache::clear_file(Path::new("data/cache/scan/scanning.jsonl")).await?;
}
```

### Propagation

`main.rs` passes `force` from the matched `Command` variant down to the
respective `run()` function.

## Testing Strategy

- Unit test `clear_dir`: create temp dir with files, call, assert dir exists and is empty.
- Unit test `clear_file`: create temp file, call, assert file is gone; call on non-existent path, assert no error.
- Integration test or manual: run `import --force`, verify cache dir recreated empty.

## Open Questions

None.
