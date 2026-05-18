# Backup Component

## Location

`mmdb-core::backup` — single canonical implementation shared across all crates.

## Behavior

`rotate_backup(path, keep)`:

- No-op when `path` does not exist.
- Copies `path` to `{parent}/backup/{stem}.{YYYYMMDD-HHMMSS}.{ext}` (local time).
- Creates `backup/` directory if absent.
- Prunes oldest entries beyond `keep` (default: 5).

## Directory Layout

```
data/
  scanned.jsonl          # current file
  backup/
    scanned.20260101-120000.jsonl
    scanned.20260102-120000.jsonl
    ...
```

`data/backup/` is listed in `.gitignore` and not tracked.
