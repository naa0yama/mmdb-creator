# Component: Scan Resume

## Overview

`mmdb-scan::resume` tracks which scan targets have already been processed
so that an interrupted scan can continue without re-scanning completed IPs.

## Done-set key: `(IpNet, IpAddr)`

The resume done-set is keyed by `(parent_cidr, destination_ip)` pairs, not
by `IpAddr` alone.

**Motivation**: when a hosting xlsx row adds a `/32` for an IP that was
previously scanned under a broader whois CIDR (e.g., `/23`), the IP must be
re-scanned under the new, more-specific CIDR so that a `ScanRecord` with
`range = /32` is written to `scanning.jsonl`. Keying by IP alone would
incorrectly treat the `/32` as already done.

**Invariant**: a target `(cidr, ip)` is considered done only when the
identical `(cidr, ip)` pair appears in `scanning.jsonl`. Changing the CIDR
for an already-scanned IP always triggers a re-scan on the next run.

## API

```rust
// Load completed (CIDR, IP) pairs from an existing scanning.jsonl.
pub async fn load_completed(path: &Path) -> Result<HashSet<(IpNet, IpAddr)>>;

// Return targets not present in done.
pub fn compute_remaining<'a, S: BuildHasher>(
    targets: &'a [(IpNet, IpAddr)],
    done: &HashSet<(IpNet, IpAddr), S>,
) -> Vec<&'a (IpNet, IpAddr)>;
```

Records whose `range` field does not parse as a valid `IpNet` are silently
skipped — the IP is re-scanned on the next run (safe fallback).
