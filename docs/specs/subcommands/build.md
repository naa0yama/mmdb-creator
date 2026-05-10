# Design: `mmdb build` Subcommand

## Overview

`scanned.jsonl` を mmdbctl-compatible NDJSON に変換し、`mmdbctl` を呼び出して MMDB を生成する。
`build` は `mmdb` サブコマンドグループの一部として提供される。

```bash
mmdb-cli mmdb build
mmdb-cli mmdb build --input data/scanned.jsonl --out data/output.mmdb
```

---

## Why mmdbctl?

IPinfo の `mmdbctl` CLI を使用して MMDB ファイルを生成する:

- 内部で MaxMind 公式 `mmdbwriter` (Go) を使用しており信頼性が高い
- NDJSON 入力で型情報 (int, float, bool, nested object) を保持できる
- CSV 入力は全て string 型になるため NDJSON 一択

---

## Output Files

| File                | Purpose                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `data/output.jsonl` | マージ済みデータの NDJSON。diff で変更点を追跡可能。git 管理向き |
| `data/output.mmdb`  | mmdbctl で生成した MMDB バイナリ                                 |

JSONL を常に出力しておくことで:

- 前回との diff が取れる (何が変わったか一目瞭然)
- mmdb 生成に失敗しても中間データが残る
- デバッグ・目視確認が容易

---

## Execution Flow

```
1. require_command("mmdbctl")
2. rotate_backup("data/output.jsonl", keep=5)   ← before overwrite
3. rotate_backup("data/output.mmdb", keep=5)    ← before overwrite
4. read data/scanned.jsonl line-by-line → ScanGwRecord
5. for each record:
     a. convert to MmdbRecord (field mapping table below)
     b. write JSON line to data/output.jsonl
6. log summary: total, gateway=inservice, xlsx-matched, skipped
7. mmdbctl import --json --ip 4 --size 32
       --fields continent,country,autonomous_system_number,
                autonomous_system_organization,whois,gateway,
                xlsx,xlsx_matched,gateway_found
       -i data/output.jsonl -o <out>
```

`--json` フラグは `.jsonl` 拡張子のファイルを NDJSON として扱うために必要。

`--fields` を明示することで、先頭 JSON レコードにフィールドが欠けていても
全フィールドが MMDB に記録される (mmdbctl のデフォルト挙動を抑止)。

Steps 2-3 warnings (non-fatal):

- `gateway.status != "inservice"` → warn count at end
- `xlsx` map absent or empty → warn count at end (expected for whois-only ranges)

---

## MMDB Record Schema

GeoLite2-ASN + GeoLite2-City 互換フィールド + カスタムフィールド:

```json
{
	"range": "198.51.100.0/30",

	"autonomous_system_number": 64496,
	"autonomous_system_organization": "Example Corp",

	"continent": { "code": "AS" },
	"country": { "iso_code": "JP" },

	"whois": {
		"inetnum": "198.51.100.0 - 198.51.100.255",
		"netname": "EXAMPLE-NET",
		"descr": "Example Network",
		"source": "APNIC",
		"last_modified": "2025-01-15T00:00:00Z"
	},

	"gateway": {
		"ip": "198.51.100.1",
		"ptr": "xe-0-0-1.rtr0101.dc01.example.net",
		"device": "rtr0101",
		"device_role": "rtr",
		"facility": "dc01",
		"interface": "xe-0-0-1",
		"facing": "user"
	},

	"xlsx": {
		"backbone": {
			"filename": "IPAM.xlsx",
			"sheetname": "border1.ty1",
			"serviceid": "SVC-001",
			"cableid": "C10001"
		}
	},

	"xlsx_matched": true,
	"gateway_found": true
}
```

`routes` (traceroute hop list) は MMDB には含めない。

### GeoLite2 Compatible Fields

- `continent.code` — ISO 国コード → 大陸コードの静的マッピング
- `country.iso_code` — whois `country` から
- `autonomous_system_number` — whois ASN を u32 に変換 (`"AS64496"` / `"64496"` 両対応)
- `autonomous_system_organization` — whois `as-name`

### Custom Fields

- `whois` — whois 由来データ (inetnum, netname, descr, source, last_modified)
- `gateway` — scan PTR 解析で特定したゲートウェイデバイス情報
- `xlsx` — xlsx 由来の運用データ。sheettype ("backbone"/"hosting") をキーとする map; 各値は _source 由来の filename/sheetname と全カラムを含む

---

## ScanGwRecord → MmdbRecord Field Mapping

| `MmdbRecord` field               | Source in `ScanGwRecord`       | Transform                                            |
| -------------------------------- | ------------------------------ | ---------------------------------------------------- |
| `range`                          | `range`                        | —                                                    |
| `autonomous_system_number`       | `as_num`                       | parse `"AS64496"` / `"64496"` → `u32`                |
| `autonomous_system_organization` | `as_name`                      | —                                                    |
| `country.iso_code`               | `country`                      | —                                                    |
| `continent.code`                 | derived from `country`         | static ISO-3166 → continent map                      |
| `whois.inetnum`                  | `inetnum`                      | —                                                    |
| `whois.netname`                  | `netname`                      | —                                                    |
| `whois.descr`                    | `descr`                        | —                                                    |
| `whois.source`                   | `whois_source`                 | —                                                    |
| `whois.last_modified`            | `whois_last_modified`          | —                                                    |
| `gateway.ip`                     | `gateway.ip`                   | —                                                    |
| `gateway.ptr`                    | `gateway.ptr`                  | —                                                    |
| `gateway.device`                 | `gateway.device.device`        | —                                                    |
| `gateway.device_role`            | `gateway.device.device_role`   | —                                                    |
| `gateway.facility`               | `gateway.device.facility`      | —                                                    |
| `gateway.interface`              | `gateway.device.interface`     | —                                                    |
| `gateway.facing`                 | `gateway.device.facing`        | —                                                    |
| `xlsx.<type>.filename`           | `xlsx[type]._source.file`      | `type` = "backbone" or "hosting"                     |
| `xlsx.<type>.sheetname`          | `xlsx[type]._source.sheet`     | —                                                    |
| `xlsx.<type>.*` (flatten)        | `xlsx[type].*` excl. `_source` | strip `_source`, flatten remainder                   |
| `xlsx_matched`                   | derived                        | `rec.xlsx.as_ref().is_some_and(\|m\| !m.is_empty())` |
| `gateway_found`                  | derived                        | `rec.gateway.status == "inservice"`                  |

---

## Continent Code Mapping

Static table covering ISO 3166-1 alpha-2 codes present in APNIC / JPNIC / RIPE data:

| Countries                     | Continent |
| ----------------------------- | --------- |
| JP, CN, KR, SG, HK, TW, IN, … | AS        |
| AU, NZ, …                     | OC        |
| US, CA, MX, …                 | NA        |
| GB, DE, FR, NL, …             | EU        |
| BR, AR, …                     | SA        |
| ZA, NG, …                     | AF        |

Unknown country code → `continent` field omitted (not an error).

---

## mmdbctl Key Options

| Flag      | Default | Note                                                   |
| --------- | ------- | ------------------------------------------------------ |
| `--json`  | —       | `.jsonl` 拡張子ファイルを NDJSON として処理 (常に付与) |
| `--ip`    | `6`     | IPv4 データなら `--ip 4` を明示                        |
| `--size`  | `32`    | Record size: 24, 28, 32                                |
| `--merge` | `none`  | 重複時: `none` (上書き), `toplevel`, `recurse`         |

---

## CLI Definition

`mmdb build` は `MmdbCommand` enum の `Build` バリアントとして定義される
(`mmdb` サブコマンドグループの詳細は `docs/specs/subcommands/mmdb.md` を参照)。

```rust
MmdbCommand::Build {
    /// Output MMDB file path
    #[arg(short, long, default_value = "data/output.mmdb")]
    out: PathBuf,

    /// Source JSONL file (scanned.jsonl)
    #[arg(short, long, default_value = "data/scanned.jsonl")]
    input: PathBuf,
}
```

---

## File Layout

```
crates/mmdb-cli/src/
  build/
    mod.rs      # public run() entry point
```
