# Design: `mmdb` Subcommand Group

## Overview

`mmdb` はトップレベルサブコマンドグループであり、MMDB ファイルの生成とクエリを一括して提供する。

```bash
mmdb-cli mmdb build                        # scanned.jsonl から MMDB を生成
mmdb-cli mmdb build --out custom.mmdb      # 出力先を指定
mmdb-cli mmdb query 198.51.100.1           # IP アドレスを MMDB で検索
mmdb-cli mmdb q 198.51.100.1 203.0.113.5  # エイリアス q / 複数 IP
```

---

## Background

旧来の `build` トップレベルサブコマンドは MMDB を生成するだけで、
その内容をコマンドラインから確認する手段がなかった。
`mmdb build` と `mmdb query` をグループ化することで、
MMDB 関連のワークフローを一か所に集約し、発見性を高める。

---

## Goals

- `build`: `scanned.jsonl` を NDJSON に変換し `mmdbctl` を呼び出して MMDB を生成する
  (旧 `build` トップレベルサブコマンドと同一の動作)。
- `query` (エイリアス `q`): MMDB ファイル内の IP アドレスを検索し、
  縦型キー/値テーブルとして表示する。
- 他のサブコマンド (`import`, `scan`, `validate`, `enrich`) の動作は変更しない。

## Non-Goals

- `query` の JSON/機械可読出力モード (本変更のスコープ外)。
- IPv6 アドレスのクエリ (現行 MMDB は IPv4 専用)。
- MMDB レコードスキーマの変更。

---

## Subcommands

| Subcommand   | Alias | Purpose                                           |
| ------------ | ----- | ------------------------------------------------- |
| `mmdb build` | —     | `scanned.jsonl` から MMDB を生成 (`mmdbctl` 経由) |
| `mmdb query` | `q`   | MMDB ファイルで IP アドレスを検索し縦型表で表示   |

---

## CLI Definition

```rust
pub enum Command {
    Import { ... },
    /// Build and query MMDB files
    Mmdb {
        #[command(subcommand)]
        command: MmdbCommand,
    },
    Scan { ... },
    Validate { ... },
    Enrich { ... },
}

pub enum MmdbCommand {
    /// Build MMDB from scanned.jsonl via mmdbctl
    Build {
        /// Output MMDB file path
        #[arg(short, long, default_value = "data/output.mmdb")]
        out: PathBuf,
        /// Source JSONL file (scanned.jsonl)
        #[arg(short, long, default_value = "data/scanned.jsonl")]
        input: PathBuf,
    },
    /// Look up one or more IP addresses in an MMDB file
    #[command(alias = "q")]
    Query {
        /// MMDB file to query
        #[arg(short = 'm', long, default_value = "data/output.mmdb")]
        mmdb: PathBuf,
        /// IP addresses to look up
        ips: Vec<String>,
    },
}
```

---

## `mmdb build` Behavior

`scanned.jsonl` を mmdbctl-compatible NDJSON に変換してから `mmdbctl` を呼び出す。
詳細な仕様は `docs/specs/subcommands/build.md` を参照。

### Execution Flow

```
1. require_command("mmdbctl")
2. read data/scanned.jsonl line-by-line → ScanGwRecord
3. for each record:
     a. convert to MmdbRecord (GeoLite2 compatible field names)
     b. write JSON line to data/output.jsonl
4. log summary: total, gateway=inservice, xlsx-matched, skipped
5. mmdbctl import --json --ip 4 --size 32 -i data/output.jsonl -o <out>
```

`--json` フラグは `.jsonl` 拡張子のファイルを NDJSON として扱うために必要。

### Default Paths

| Argument  | Default              |
| --------- | -------------------- |
| `--input` | `data/scanned.jsonl` |
| `--out`   | `data/output.mmdb`   |

### Output Files

| File                | Purpose                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `data/output.jsonl` | マージ済みデータの NDJSON。diff で変更点を追跡可能。git 管理向き |
| `data/output.mmdb`  | mmdbctl で生成した MMDB バイナリ                                 |

---

## `mmdb query` Behavior

`maxminddb` クレートを用いて MMDB を直接読み取る (サブプロセスなし)。
各 IP のレコードを `serde_json::Value` としてデシリアライズし、
ネストされたオブジェクトをドット記法に展開して縦型テーブルで表示する。

### Output Format

```
===[ 198.51.100.1 ]=====================================================
range                          198.51.100.0/30
autonomous_system_number       64496
autonomous_system_organization Example Corp
country.iso_code               JP
gateway.ip                     198.51.100.1
gateway.ptr                    xe-0-0-1.rtr0101.dc01.example.net
gateway.device                 rtr0101
gateway.device_role            rtr
gateway.facility               dc01
gateway.interface              xe-0-0-1
gateway.facing                 user
operational.serviceid          SVC-001
=======================================================================
```

IP が MMDB に存在しない場合は `(not found)` をルール行の間に表示する。
IP 文字列が無効な場合はエラーとして非ゼロ終了する。

### Flatten Algorithm

`serde_json::Value::Object` を再帰的に走査し、各リーフ (非 Object) に対して
`"parent.child" => value.to_string()` を出力する。配列はカンマ区切りでインライン表示。
キー列幅は各 IP の全行にわたる `max_key_len` で統一する。

### Default Paths

| Argument | Default            |
| -------- | ------------------ |
| `--mmdb` | `data/output.mmdb` |

---

## Error Handling

| Condition               | Behavior                                 |
| ----------------------- | ---------------------------------------- |
| `ips` が空              | エラー終了 (`no IP addresses specified`) |
| 無効な IP 文字列        | エラー終了 (`invalid IP address: …`)     |
| MMDB ファイルが開けない | エラー終了 (`failed to open MMDB …`)     |
| IP が MMDB に存在しない | `(not found)` を表示して続行             |

---

## Testing Strategy

- `flatten_value` ヘルパー関数のユニットテスト (ネストオブジェクト、配列、空オブジェクト)。
- `value_to_display_string` ユニットテスト (文字列、数値、bool、null)。
- 無効な IP 文字列がエラーを返すユニットテスト。
- 統合テスト: 実 MMDB ファイルが必要なため `NOTEST` でスキップ。

---

## File Layout

```
crates/mmdb-cli/src/
  cli.rs          # Command::Mmdb + MmdbCommand enum 定義
  build/
    mod.rs        # mmdb build: run() — mmdb-core + mmdbctl 呼び出し
  mmdb_query/
    mod.rs        # mmdb query: run() — maxminddb 直接読み取り + 縦型出力
  main.rs         # Command::Mmdb { command } → MmdbCommand ディスパッチ
```
