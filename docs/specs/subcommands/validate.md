# Design: `validate` Subcommand

## Overview

config.toml の構文・意味論的チェックと、xlsx ファイルからの `[[sheets]]` TOML スキャフォールド生成を提供する。
`validate --ptr` は scan 後に PTR パターンのカバレッジを診断する。

```bash
mmdb-cli validate                # config.toml の検証
mmdb-cli validate --init-sheets  # xlsx から [[sheets]] TOML を生成して stdout に出力
mmdb-cli validate --ptr          # data/scanned.jsonl の PTR パターンカバレッジを診断
```

---

## validate (no flags)

Startup validation は全サブコマンド実行前に自動で行われる。

Checks performed in order:

1. Config file exists and parses as valid TOML
2. Required fields are present (`[whois].server`)
3. `[[sheets]]` entries (if present):
   - `filename` exists on disk
   - `header_row` >= 1
   - `columns` have unique `name` values
   - `columns` have valid `col_type` values (enforced by serde)
4. `[[sheets.columns]]` `ptr_field` values exist in `Config.normalize`
5. `{name}` placeholders in `[[scan.ptr_patterns]]` exist in `Config.normalize`

Exit 0 on success, 1 on failure.

---

## validate --init-sheets

For each `[[sheets]]` entry in config.toml:

1. Open the xlsx file with calamine (via `mmdb_xlsx::inspect_sheets`)
2. Get all sheet names; filter out `excludes_sheets`
3. For each remaining sheet: read the header row, collect all non-empty column headers
4. Deduplicate column headers across all sheets in the same file
5. Print to stdout as TOML:

```toml
[[sheets]]
filename = "data/exsample/IPAM_20260401r2.xlsx"
header_row = 3
excludes_sheets = []
# Available sheets: ["border1.ty1"]

[[sheets.columns]]
name = "site"
sheet_name = "site"
type = "string"

[[sheets.columns]]
name = "floor"
sheet_name = "floor"
type = "string"

# ... all columns from header row
```

Column output rules:

- `name` = snake_case version of `sheet_name` (lowercase, spaces→underscores, hyphens→underscores)
- `sheet_name` = original header text from xlsx
- `type` = always `"string"` (user edits manually to integer/addresses/bool)

---

## validate --ptr

### Purpose

`scan.ptr_patterns` や `normalize` ルールが不完全な場合、多数の domain-matching PTR が
regex マッチに失敗する。手動で `jq` パイプラインを書かずにカバレッジを診断するコマンド。

### Iterative Workflow

```
scan                          ← first run; PTR DNS cached;
                                ptr_patterns absent → matching no-op;
                                data/scanned.jsonl has ptr=populated, device=null

Add [[scan.ptr_patterns]] + [normalize.*] to config.toml

validate --ptr                ← re-applies current config to existing scanned.jsonl;
                                shows unique domain-matching but unmatched PTRs

edit config.toml              ← add/refine rules; add excludes for known PTRs

validate --ptr                ← immediately reflects new rules; no rescan needed

repeat until output is empty or acceptable

scan                          ← re-run scan to regenerate data/scanned.jsonl with final rules
                                (resume logic skips already-scanned CIDRs; only enrich re-runs)
```

> **Note:** `--enrich-only` フラグは削除された。enrich のみ再実行したい場合は
> 通常の `scan` を実行すること (resume ロジックにより既スキャン済み CIDR はスキップされる)。

### Filtering Logic

For each unique PTR string collected from `gateway.ptr` and `routes[].ptr`:

```
1. domain filter      — PTR ends with any [[scan.ptr_patterns]].domain?
                         No  → skip silently (out-of-scope domain)
                         Yes → continue

2. pattern.excludes   — PTR matches any excludes entry of the matched pattern?
                         Yes → skip silently (consciously excluded)
                         No  → continue

3. regex match        — ptr_parse::parse succeeds?
                         No  → REPORT (domain-matching but unmatched)
                         Yes → continue to step 4

4. normalize.excludes — for each captured field, does the normalized value
                         match that field's excludes?
                         Any match → skip silently (consciously excluded)
                         None      → skip silently (matched successfully)
```

Step 3 "no match" is the only path that produces output.

### excludes Fields

`[[scan.ptr_patterns]].excludes` — applied **before** regex matching (entire PTR suppression):

```toml
[[scan.ptr_patterns]]
domain = "example.com"
regex = "{interface}.{device}.{facility}"
excludes = [
	"\\.ad\\.example\\.com$", # Active Directory hosts
	"\\.transit\\.example\\.com$", # upstream transit hops
]
```

`[normalize.<name>].excludes` — applied **after** regex matched and capture extracted (field value suppression):

```toml
[normalize.interface]
rules    = [ ... ]
excludes = [
    "^lo\\d*$",    # loopback interfaces
    "^mgmt\\d*$",  # management interfaces
]
```

### Output Format

Sorted alphabetically, stdout:

```
ge-0-0-0.rtr02.dc2.example.com
xe-0-0-1.rtr01.dc1.example.com

ptr_unmatched: 2
```

No range or IP — just PTR strings the user can copy into config as patterns.

Exit code 0 always (diagnostic).

Error + exit 1 when `data/scanned.jsonl` is missing:

```
error: data/scanned.jsonl not found — run 'scan' first
```

---

## Implementation

### Module

```
crates/mmdb-cli/src/validate.rs
```

### mmdb-xlsx addition

```rust
pub struct SheetInfo {
    pub name: String,
    pub headers: Vec<String>,
}

pub fn inspect_sheets(config: &SheetConfig) -> Result<Vec<SheetInfo>>;
```

### snake_case conversion

```rust
fn to_snake_case(s: &str) -> String {
    s.trim().to_lowercase().replace(' ', "_").replace('-', "_")
}
```

### validate::run_ptr

```rust
pub fn run_ptr(config: &Config, scanned_path: &Path) -> Result<()>
```

1. Open `scanned_path`; return actionable `Err` if missing.
2. Deserialize each line as `ScanGwRecord`; skip malformed with `warn!`.
3. Collect all unique non-null PTR strings (`gateway.ptr` + `routes[].ptr`).
4. Compile `scan.ptr_patterns` (including `excludes`) and `normalize` map.
5. For each unique PTR (sorted), apply the four-step filter above.
6. Print unmatched PTRs then `ptr_unmatched: N` summary.

### Config Changes

```rust
pub struct PtrPattern {
    pub domain: Option<String>,
    pub regex: String,
    #[serde(default)]
    pub excludes: Vec<String>,
}

pub struct NormalizeConfig {
    #[serde(default)] pub rules: Vec<NormalizeRule>,
    #[serde(default)] pub case: NormalizeCase,
    #[serde(default)] pub excludes: Vec<String>,
}
```

### CLI

```rust
Validate {
    /// Read xlsx files from config and generate [[sheets]] TOML to stdout
    #[arg(long)]
    init_sheets: bool,
    /// Re-apply current ptr_patterns/normalize config to data/scanned.jsonl
    /// and report unique domain-matching but unmatched PTR hostnames
    #[arg(long, conflicts_with = "init_sheets")]
    ptr: bool,
},
```

`--ptr` と `--init-sheets` は相互排他。Clap がパース時点でエラーとして拒否する。
