# Design: `validate` Subcommand

## Overview

config.toml の構文・意味論的チェックと、xlsx ファイルからの `[[sheets]]` TOML スキャフォールド生成を提供する。
`validate --ptr` は scan 後に PTR パターンのカバレッジを診断する。

```bash
mmdb-cli validate                # config.toml の検証
mmdb-cli validate --init-sheets  # xlsx から [[sheets]] TOML を生成して stdout に出力
mmdb-cli validate --ptr          # data/scanned.jsonl の PTR パターンカバレッジを診断
mmdb-cli validate --xlsx-rows    # data/xlsx-rows.jsonl の sheettype 内重複 CIDR チェック
```

---

## validate (no flags)

Startup validation は全サブコマンド実行前に自動で行われる。

Checks performed in order:

1. Config file exists and parses as valid TOML
2. `[whois].server` is not empty (has a serde default of `"whois.iana.org"`; fails only if explicitly set to blank)
3. `[[sheets]]` entries (if present):
   - `filename` exists on disk
   - `header_row` >= 1
   - `columns` have unique `name` values
   - `columns[m].name` contains only `[a-z0-9_]` (ASCII lowercase, digits, underscore)
   - `columns` have valid `col_type` values (enforced by serde)
   - exactly one of `sheet_name` / `sheet_names` is set per column (mutually exclusive)
   - `sheet_names` is only used with `type = "addresses"`
   - `sheet_names` and `ptr_field` are not combined
   - `groups` entries each have at least 2 sheet names
   - no sheet name appears in more than one group
   - no group sheet name is also in `excludes_sheets`
   - every sheet name in `groups` exists as a tab in the xlsx file
4. `[[sheets.columns]]` `ptr_field` values exist in `Config.normalize`
5. `{name}` placeholders in `[[scan.ptr_patterns]]` exist in `Config.normalize`

Exit 0 on success, 1 on failure.

---

## validate --init-sheets

For each `[[sheets]]` entry in config.toml:

1. Open the xlsx file with calamine (via `mmdb_xlsx::inspect_sheets`)
2. Get all sheet names; filter out `excludes_sheets`
3. For each remaining sheet: read the header row, collect all non-empty column headers;
   also collect up to 3 rows of raw cell text (header row + 2 data rows) for preview
4. Deduplicate column headers across all sheets in the same file
5. Print to stdout as TOML, with a per-sheet preview block before the column scaffold:

```toml
[[sheets]]
filename = "data/exsample/IPAM_20260401r2.xlsx"
header_row = 3
excludes_sheets = []

# --- Sheet: border1.ty1 ---
# Rows 3–5 (header_row = 3):
#   row 3 | Site     | Floor | IP Address    |
#   row 4 | EXAMPLE  | 1F    | 198.51.100.0  |
#   row 5 | EXAMPLE  | 2F    | 198.51.100.10 |

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
- If any generated `name` contains characters outside `[a-z0-9_]` (e.g. Japanese headers),
  all such names are reported and the command exits non-zero. The user must rename the xlsx
  column headers to ASCII before re-running.

Preview block rules:

- Printed as comment lines immediately after `# --- Sheet: <name> ---`.
- Shows `header_row` through `header_row + 2` (up to 3 rows; capped if the sheet is shorter).
- Row numbers are 1-indexed and match the `header_row` setting so users can verify alignment.
- All columns (including empty cells) are included so column positions are visible.
- Missing rows (sheet has fewer rows than expected) are omitted without error.

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

## validate --xlsx-rows

### Purpose

`import --xlsx` 完了直後に重複チェックが自動実行されるが、設定変更後や手動確認時に
`data/xlsx-rows.jsonl` を再チェックするためのコマンド。

```bash
mmdb-cli validate --xlsx-rows
# → xlsx-rows.jsonl: no duplicate CIDRs detected (5 sheets)
# → または Err: 重複 CIDR と出所ファイルを列挙して exit 1
```

### Check Logic

| sheettype  | 重複条件                              | 結果                           |
| ---------- | ------------------------------------- | ------------------------------ |
| `hosting`  | 同一 CIDR を持つ行が 2 件以上         | `Err` + 重複 CIDR と出所を列挙 |
| `backbone` | **完全一致** CIDR を持つ行が 2 件以上 | `Err` + 重複 CIDR と出所を列挙 |

backbone の包含関係 (例: /19 と /20) は階層構造として正常であり重複エラーとしない。

**冗長グループの免除:** `[[sheets]].groups` でグループ ID セットが交差するシート間の重複 CIDR は
エラーとしない。シートは複数グループに同時所属可能 (overlapping groups)。グループは `config.toml`
から読み込む (xlsx-rows.jsonl には埋め込まれない) ため、このサブコマンドは config.toml と
xlsx-rows.jsonl の両方を参照する。

### Input

`data/xlsx-rows.jsonl` — `import --xlsx` が生成するファイル。存在しない場合は exit 1:

```
error: data/xlsx-rows.jsonl not found — run 'import --xlsx' first
```

### Output (success)

```
xlsx-rows.jsonl: no duplicate CIDRs detected (5 sheets)
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
    /// Raw cell text for up to 3 rows starting at `header_row` (header + 2 data rows).
    /// All columns including empty cells are included so column positions are visible.
    /// Empty when `inspect_sheets` was called with `preview = false`.
    pub preview_rows: Vec<Vec<String>>,
}

pub fn inspect_sheets(config: &SheetConfig, preview: bool) -> Result<Vec<SheetInfo>>;
```

### snake_case conversion

```rust
fn to_snake_case(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .split('_')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("_")
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
    /// Check xlsx-rows.jsonl for duplicate CIDRs within the same sheettype
    #[arg(long, conflicts_with = "init_sheets", conflicts_with = "ptr")]
    xlsx_rows: bool,
},
```

`--ptr`, `--init-sheets`, `--xlsx-rows` は互いに排他。Clap がパース時点でエラーとして拒否する。
