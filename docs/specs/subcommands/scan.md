# Design: `scan` Subcommand

## Overview

import で収集した CIDR データを元に demarc 探索を行う。
scamper ICMP-Paris traceroute でゲートウェイを特定し、PTR パターンマッチでデバイス情報を抽出する。

```bash
mmdb-cli scan                    # フルスキャン + enrich
mmdb-cli scan --force            # キャッシュ削除 + フルスキャン
mmdb-cli scan --full             # 全ホスト IP をスキャン (デフォルト: 先後3アドレスずつ)
mmdb-cli scan --force --full     # キャッシュ削除 + 全ホストスキャン (y/N 確認あり)
mmdb-cli scan --ip 198.51.100.0/24  # 単一 CIDR のみスキャン
```

> **Note:** `--enrich-only` は削除された。enrich のみ再実行する場合は通常の `scan` を使用する
> (resume ロジックにより既スキャン済み CIDR はスキップされる)。

> **Note:** `--force --full` の組み合わせはスキャンキャッシュを削除しすべての IP を再プローブするため、
> 実行前に `(y/N)` 確認プロンプトが表示される。

---

## Probe Tool: scamper

`mtr` の代わりに `scamper` デーモンを使用する:

| 比較項目   | mtr (旧)             | scamper (現行)                |
| ---------- | -------------------- | ----------------------------- |
| ECMP 対応  | なし (単一パスのみ)  | ICMP-Paris (フローID固定)     |
| 並列制御   | 1プロセス/ターゲット | 1デーモンで全ターゲットを管理 |
| pps 制御   | 困難                 | `pps` パラメーターで一元管理  |
| プロトコル | ICMP/UDP/TCP         | ICMP-Paris traceroute         |

---

## Target Address Selection

| CIDR                 | 有効アドレス数 | Default (--full なし) | --full                   |
| -------------------- | -------------- | --------------------- | ------------------------ |
| `/32` (単一アドレス) | 1              | そのアドレス1つ       | 同上 (1アドレスのみ)     |
| `/31`                | 2              | 2アドレス全て         | 同上                     |
| `/30`                | 2              | 有効アドレス2つ全て   | 同上                     |
| `/29` 以上           | 6+             | 先頭3つ + 末尾3つ     | `net.hosts()` 全アドレス |

- ネットワークアドレスとブロードキャストアドレスは常に除外
- `expand_cidrs(cidrs, full: bool)` が選択ロジックを実装

---

## scamper Daemon Lifecycle

```
scan 開始
  ├─ scamper -D -U /tmp/mmdb-cli-<pid>.sock -p <pps> を spawn
  ├─ ソケットが ready になるまでポーリング (最大 3 秒, 100ms 間隔)
  └─ UnixStream::connect で接続

scan 終了 / Ctrl+C / panic
  ├─ writer タスクに shutdown シグナル送信 → バッファを flush
  ├─ child.kill().await でデーモンを終了
  └─ ソケットファイルを削除
```

### Socket Protocol

```
Rust → デーモン:
  "attach\n"
  "trace -P icmp-paris -q 3 198.51.100.1\n"
  ...

デーモン → Rust (完了した順に JSON で返る):
  {
    "type": "trace", "method": "icmp-echo-paris",
    "src": "192.0.2.100", "dst": "198.51.100.1",
    "stop_reason": "GAPLIMIT",
    "hops": [
      { "addr": "198.51.100.1", "probe_ttl": 1, "probe_id": 1, "rtt": 0.232 },
      ...
    ]
  }
```

---

## Buffering and Flush Strategy

mpsc チャネルで scan ループと writer タスクを分離する。

**Flush triggers (OR condition):**

- バッファ件数 >= 100 件
- 前回 flush から 5 秒経過

**Forced flush:**

- shutdown シグナル受信時 (Ctrl+C / 正常終了)
- panic hook 経由の同期 flush

```
scan ループ ──result──► mpsc channel ──► writer タスク
                                              │
                                    ┌─ 100件 OR 5秒 ─► append to scanning.jsonl
                                    └─ shutdown      ─► flush all + exit
```

---

## scamper JSON → RouteData Mapping

### RouteData Fields

| Output field  | scamper source             | Type       | Notes                                |
| ------------- | -------------------------- | ---------- | ------------------------------------ |
| `version`     | `version`                  | `String`   | scamper version string               |
| `measured_at` | `start.sec` + `start.usec` | `String`   | ISO 8601 UTC                         |
| `source`      | `src`                      | `String`   | probe source IP                      |
| `destination` | `dst`                      | `String`   | target IP                            |
| `stop_reason` | `stop_reason`              | `String`   | `COMPLETED` / `GAPLIMIT` / `UNREACH` |
| `hops`        | `hops` (grouped)           | `Vec<Hop>` |                                      |

### Hop Fields (grouped by probe_ttl)

| Output field | scamper source       | Type             | Notes                        |
| ------------ | -------------------- | ---------------- | ---------------------------- |
| `hop`        | `probe_ttl`          | `u32`            | 1-indexed                    |
| `ip`         | `addr`               | `Option<String>` | null for non-responding hops |
| `rtt_avg`    | avg of `rtt`         | `Option<f64>`    |                              |
| `rtt_best`   | min of `rtt`         | `Option<f64>`    |                              |
| `rtt_worst`  | max of `rtt`         | `Option<f64>`    |                              |
| `icmp_type`  | `icmp_type`          | `Option<u8>`     | 11=TTL exceeded / 0=reached  |
| `asn`        | post-scan enrich     | `Option<u32>`    |                              |
| `ptr`        | post-scan PTR lookup | `Option<String>` |                              |

**Parsing rules:**

1. `hops` を `probe_ttl` でグルーピング
2. 同一 `probe_ttl` グループの `rtt` から avg / best / worst を算出
3. 同一 `probe_ttl` に複数の `addr` が出た場合 → `tracing::warn!` + 多数決
4. `probe_ttl` の歯抜け箇所 (応答なし) を `ip: null` ホップとして補完
5. `stop_reason` を記録

---

## Resume (Skip Logic)

scan 開始時に `data/scanned.jsonl` を読み込み、完了済みの CIDR を抽出してスキップ。

```
total     = CIDRs generated from whois-cidr.jsonl + xlsx-rows.jsonl
done      = IPs already in scanned.jsonl
remaining = total - done
```

TUI 上で "Skipped (cached): N" として表示する。

---

## Post-scan Enrich (2-Phase)

**Phase 1 (scan):** ホップ IP・RTT・icmp_type を収集、ASN・PTR は `null` で scanning.jsonl に書き込む

**Phase 2 (enrich):** scan 完了後に実行

1. 全ホップ IP を重複排除
2. Team Cymru WHOIS bulk (`whois.cymru.com:43`) で ASN を一括取得
3. DNS reverse lookup で PTR を一括解決
4. xlsx 行を各 `ScanGwRecord` に付加 (PTR マッチまたは CIDR 包含で選択)
5. 派生フラグを全レコードに設定してから `data/scanned.jsonl` に書き込む:
   - `xlsx_matched = xlsx.as_ref().is_some_and(|m| !m.is_empty())`
   - `gateway_found = gateway.status == "inservice"`

### PTR Progress Logging

`mmdb-dns/src/ptr.rs` の `join_next` ループにてプログレス出力:

- 1% 刻みで `tracing::info!` を出力
- `completed == total` 時に最終ログを出力
- `total == 0` の場合はスキップ

---

## Gateway Resolution

### Per-trace Classification

Walk hops from last to first. For each hop:

1. If `ptr` is null → skip.
2. Check whether the PTR matches any `[[scan.ptr_patterns]]` entry:
   a. If `domain` field set: PTR must end with that suffix.
   b. Apply `regex` to the full PTR string.
   c. First matching entry wins.
3. Pattern matches → this hop is the gateway candidate.
4. No match → move to the next hop upward.
5. All hops exhausted without match → no gateway candidate for this trace.

### Per-range Consensus (Majority Vote)

- Collect gateway candidates from all traces in the range.
- IP with the most votes wins; ties broken by vote count.
- `gateway.votes` = winner vote count; `gateway.total` = total trace count.

### gateway.status Values

| Value            | Condition                                                           |
| ---------------- | ------------------------------------------------------------------- |
| `"inservice"`    | At least one trace yielded a PTR match → backbone device identified |
| `"no_hops"`      | Every trace for this range has an empty hops list                   |
| `"no_ptr_match"` | Hops are present but no hop PTR matched any configured pattern      |

### Output Record

`ScanGwRecord` is the per-range output written to `data/scanned.jsonl`:

```json
{
	"range": "198.51.100.0/25",
	"gateway": {
		"ip": "198.51.100.1",
		"ptr": "user.virtual.xe-0-0-1.rtr0101.dc01.example.net",
		"votes": 5,
		"total": 6,
		"status": "inservice",
		"device": {
			"interface": "xe-0-0-1",
			"if_speed": "10g",
			"device": "rtr0101",
			"device_role": "rtr",
			"facility": "dc01",
			"facing": "user_virtual",
			"customer_asn": null
		}
	},
	"inetnum": "198.51.100.0 - 198.51.100.255",
	"country": "JP",
	"whois_source": "APNIC",
	"whois_last_modified": "2025-01-15T00:00:00Z",
	"xlsx": {
		"backbone": {
			"_source": {
				"file": "IPAM.xlsx",
				"sheet": "border1.ty1",
				"row_index": 3,
				"sheettype": "backbone"
			},
			"host": "border1",
			"port": "xe-0/0/1",
			"serviceid": "SVC-001"
		}
	},
	"xlsx_matched": true,
	"gateway_found": true,
	"measured_at": "2026-05-09T14:08:43Z"
}
```

- `gateway` object: always present (never null); all fields serialised unconditionally.
- `host_ip`, `host_ptr`: `#[serde(skip)]` — reserved for future host-analysis phase.
- `inetnum`, `country`, `whois_source`, `whois_last_modified`: joined from whois-cidr.jsonl via LPM at GW-resolution time.
- `xlsx`: sheettype-keyed map (`"backbone"` / `"hosting"`) of matched xlsx rows; each entry contains `_source` metadata and column values. Absent when no match for any sheettype.
- `xlsx_matched`: `true` when at least one sheettype matched (`xlsx` map is non-empty); `false` otherwise.
- `gateway_found`: `true` when gateway resolution fully succeeded (`gateway.status == "inservice"`); `false` otherwise.

---

## PTR Pattern Configuration

```toml
[[scan.ptr_patterns]]
domain = "example.net"
regex = '''(?x)
  ^(?:(?P<facing>user(?:\.virtual)?|virtual)\.)?
  (?:as(?P<customer_asn>\d+)\.)?
  (?P<interface>(?:ge|xe|et)-[\d-]+)
  (?:\.[a-z]+\d+)?\.
  (?P<device>(?P<device_role>[a-z]+)\d+)\.
  (?P<facility>[a-z0-9]+)\.
  example\.ad\.jp$
'''
excludes = [
	"\\.ad\\.example\\.com$", # Active Directory hosts
	"\\.transit\\.example\\.com$", # upstream transit hops
]
```

### {placeholder} Syntax

When `regex` contains `{name}` placeholders, expansion is applied:

```toml
[[scan.ptr_patterns]]
domain = "example.net"
regex = "{interface}.{device}.{facility}"
# Expands to:
# ^(?P<interface>[^.]+)\.(?P<device>[^.]+)\.(?P<facility>[^.]+)\.example\.net$
```

- Non-placeholder segments are escaped with `regex::escape()`.
- Placeholder names must match keys in `Config.normalize`.
- Raw regex strings (no `{`) are passed to `Regex::new()` unchanged (backward compat).

### Named Capture Groups

| Group          | Example value  | Notes                                           |
| -------------- | -------------- | ----------------------------------------------- |
| `interface`    | `xe-0-0-1`     | interface name                                  |
| `device`       | `rtr0101`      | full device identifier                          |
| `device_role`  | `rtr`          | role portion of device name                     |
| `facility`     | `dc01`         | site/facility name                              |
| `facing`       | `user.virtual` | raw prefix label; normalised to canonical value |
| `customer_asn` | `64496`        | BGP ASN as decimal string; parsed to u32        |

`if_speed` is derived from the `interface` prefix: `ge-` → `"1g"`, `xe-` → `"10g"`, `et-` → `"100g"`.

### facing Normalisation

| Raw `facing` group | `customer_asn` present | Output           |
| ------------------ | ---------------------- | ---------------- |
| `"user.virtual"`   | —                      | `"user_virtual"` |
| `"user"`           | —                      | `"user"`         |
| `"virtual"`        | —                      | `"virtual"`      |
| absent             | yes                    | `"bgp_peer"`     |
| absent             | no                     | `"network"`      |

---

## xlsx Integration in Scan

### Unified Scan Targets

`scan/mod.rs` の `load_cidrs` は `whois-cidr.jsonl` と `xlsx-rows.jsonl` の両方から CIDR を収集する:

- `xlsx-rows.jsonl` が存在しない場合はサイレントにスキップ (xlsx import はオプション)
- 重複 CIDR は expand 前に重複排除

### PTR xlsx Match in Enrich Phase

enrich フェーズで `xlsx-rows.jsonl` を読み込み、各 `ScanGwRecord` に xlsx 行を付加する。

**Index structures** (built once at enrich startup, separated by sheettype):

```
backbone_ptr_candidates:  Vec<PtrCandidate>   // backbone rows with ≥1 ptr_field column
backbone_cidr_candidates: Vec<CidrCandidate>  // backbone rows, one entry per IpNet
hosting_cidr_candidates:  Vec<CidrCandidate>  // hosting rows, one entry per IpNet (exact-only)
```

**Match algorithm per ScanGwRecord:**

Backbone and hosting matches are independent; both run for every record.

_Backbone match:_

1. If gateway PTR was parsed by `ptr_patterns`:
   - For each `backbone_ptr_candidate`, normalize each `ptr_field` column value
     (warn if no normalize rule), normalize the corresponding PTR capture group value, compare.
   - All `ptr_field` columns must match (AND condition).
   - First matching row used; multiple matches → warn + use first.
2. If no PTR match:
   - For each `backbone_cidr_candidate`, check bidirectional containment:
     `xlsx_net.contains(&range_net)` OR `range_net.contains(&xlsx_net)`.
   - First matching entry used; multiple matches → warn + use first.

_Hosting match (exact CIDR only; no PTR matching):_

3. For each `hosting_cidr_candidate`, check `xlsx_net == range_net` (exact equality).
   - First matching entry used; multiple matches → warn + use first.

_Attach:_

4. Each match is stored under its sheettype key: `ScanGwRecord.xlsx["backbone"]` /
   `ScanGwRecord.xlsx["hosting"]`. Unmatched sheettypes are omitted.
5. If neither backbone nor hosting matched → `xlsx` field absent.

**Normalization semantics:**

```
PTR capture  : interface = "xe-0-0-1" → normalize.interface → "xe-0-0-1"
xlsx port    : "xe-0/0/1"             → normalize.interface → "xe-0-0-1"  ✓

PTR capture  : interface = "gi-0-0-1" → normalize.interface → "gi-0-0-1"
xlsx port    : "GigabitEthernet0/0/1" → normalize.interface → "gi-0-0-1"  ✓
```

---

## whois LPM Join in GW Resolution

At the GW-resolution stage, load `whois-cidr.jsonl` and build a longest-prefix-match index.
For each `ScanGwRecord`, find the most-specific covering whois entry and attach:

- `inetnum` — IP range string from whois inetnum
- `country` — ISO 3166-1 alpha-2 country code
- `whois_source` — RIR name (e.g. `"APNIC"`)
- `whois_last_modified` — last-modified timestamp

If `whois-cidr.jsonl` does not exist (xlsx-only run), skip silently.

---

## Rotating Backup

Before writing `data/scanned.jsonl`, `rotate_backup(path, keep=5)` is called:

1. If `path` does not exist → no-op.
2. Copy to `scanned.YYYYMMDD-HHMMSS.jsonl` (local time).
3. Read parent dir; collect sibling files matching `{stem}.YYYYMMDD-HHMMSS.{ext}`.
4. Sort descending (newest first); delete all entries beyond index 4 (keep 5).

Same mechanism applies to `data/cache/scan/scanning.jsonl` (rotated at scan start),
`whois-cidr.jsonl`, and `xlsx-rows.jsonl`.

`mmdb build` applies the same rotation to `data/output.jsonl` and `data/output.mmdb`
before overwriting them (file-extension-aware: `output.YYYYMMDD-HHMMSS.jsonl`,
`output.YYYYMMDD-HHMMSS.mmdb`).

---

## Configuration

```toml
[scan]
pps = 50
probes = 3
window = 100
flush_count = 100
flush_interval_sec = 5
```

| Field                | Default | Description                   |
| -------------------- | ------- | ----------------------------- |
| `pps`                | 50      | scamper グローバル pps 上限   |
| `probes`             | 3       | ホップあたりプローブ数 (`-q`) |
| `window`             | 100     | 同時投入ターゲット数          |
| `flush_count`        | 100     | バッファ flush 件数閾値       |
| `flush_interval_sec` | 5       | バッファ flush 時間閾値 (秒)  |

---

## TUI Display

`indicatif` + `tracing-indicatif`:

```
Scanning  [=========>-----------]  2134/5000  42%
  Rate: 18.3 IP/s   ETA: 3m 09s
  Done: 2134   Skipped: 823   Failed: 6
```

---

## Hop Filtering & Renumbering

scamper の全ホップから対象 ASN のホップのみを抽出し、hop 番号を振り直す:

```
scamper raw output (all hops):
  ttl=1: 192.0.2.1      AS???    ← own network (excluded)
  ttl=2: 203.0.113.1    AS64497  ← transit (excluded)
  ttl=3: 198.51.100.1   AS64496  ← target ASN (kept, hop=1)
  ttl=4: 198.51.100.5   AS64496  ← target ASN (kept, hop=2)
  ttl=5: 192.0.2.1      AS64496  ← destination (kept, hop=3)

After filter (target ASN only, renumbered):
  hop=1: 198.51.100.1  AS64496
  hop=2: 198.51.100.5  AS64496
  hop=3: 192.0.2.1     AS64496
```

---

## File Layout

```
crates/mmdb-scan/src/
├── lib.rs         # crate root; pub mod re-exports
├── daemon.rs      # scamper daemon spawn / lifecycle management
├── socket.rs      # Unix socket attach / command send
├── enrich.rs      # post-scan ASN + PTR enrich + xlsx PTR match
├── gw.rs          # gateway resolution, majority vote, whois LPM join
├── writer.rs      # buffered JSONL writer task
├── resume.rs      # expand_cidrs, select_targets, skip logic
├── ptr_parse.rs   # PTR pattern parsing (pure, no I/O)
├── normalize.rs   # normalize rule application
└── xlsx_match.rs  # xlsx row indexing and match logic

crates/mmdb-cli/src/scan/
└── mod.rs         # thin wrapper: calls mmdb_scan::run()
```

## External Tool Requirement

| Tool      | Purpose               | Install               |
| --------- | --------------------- | --------------------- |
| `scamper` | ICMP-Paris traceroute | `apt install scamper` |
