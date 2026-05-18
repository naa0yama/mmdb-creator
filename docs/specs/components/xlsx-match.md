# xlsx-match Component

## Overview

The xlsx-match component attaches per-sheettype operational data from Excel
files (`.xlsx`) to scanned gateway records (`ScanGwRecord`).

## Match Strategies

1. **backbone (PTR match)** — all `ptr_field` columns must match the
   corresponding PTR capture group after normalisation (AND). First match wins.
2. **backbone (CIDR fallback)** — bidirectional containment:
   `xlsx_net ⊇ scan_range` OR `scan_range ⊇ xlsx_net`. First match wins.
3. **hosting (CIDR exact)** — `xlsx_net == scan_range`. First match wins.

The two sheettypes are kept in separate indices. `attach()` builds a
`HashMap<sheettype, matched_row>` stored as `ScanGwRecord.xlsx`.

## XlsxMatchStatus

`xlsx_matched` is a structured type that tracks which sheettypes produced a
match, rather than a single boolean.

```rust
pub struct XlsxMatchStatus {
    pub backbone: bool,
    pub hosting: bool,
}
```

- `XlsxMatchStatus::any()` — returns `true` if either field is true.
- `XlsxMatchStatus::default()` — both fields false.
- JSON output: `{"backbone": true, "hosting": false}`

Callers that previously tested `xlsx_matched` as a bool now call
`xlsx_matched.any()` for the same any-match semantics.
