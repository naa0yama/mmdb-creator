# Component: WhoisClient

`mmdb-whois` クレートが提供する WHOIS クエリエンジン。TCP 43 接続、RPSL 解析、
RIR 自動判定 (IANA)、レートリミット、リトライ、ディスクキャッシュを一体管理する。

## Configuration

`[whois]` セクション (`config.toml`):

```toml
[whois]
# auto_rir = true   # RIR を whois.iana.org で自動判定 (デフォルト: true)
# server = "whois.iana.org"  # フォールバックサーバー

timeout_sec = 10
rate_limit_ms = 2000
max_retries = 3
initial_backoff_ms = 1000
cache_dir = "data/cache/import"
cache_ttl_secs = 604800
```

| Field                | Default               | Description                                             |
| -------------------- | --------------------- | ------------------------------------------------------- |
| `auto_rir`           | `true`                | IANA 経由で RIR WHOIS サーバーを自動判定                |
| `server`             | `"whois.iana.org"`    | `auto_rir = false` 時または IANA 失敗時のフォールバック |
| `timeout_sec`        | 10                    | TCP 接続タイムアウト                                    |
| `rate_limit_ms`      | 2000                  | CIDR 間のレート制限間隔                                 |
| `max_retries`        | 3                     | 一時エラー時の最大リトライ回数                          |
| `initial_backoff_ms` | 1000                  | リトライ初回待機時間 (指数バックオフ)                   |
| `cache_dir`          | `"data/cache/import"` | キャッシュファイルの格納ディレクトリ                    |
| `cache_ttl_secs`     | 604800 (7日)          | キャッシュ有効期間                                      |

## RIR 自動判定 (`auto_rir`)

`auto_rir = true` (デフォルト) の場合、各 CIDR の先頭 IP アドレスを
`whois.iana.org` に問い合わせて正しい RIR WHOIS サーバーを取得する。

### 解決フロー

```
resolve_server(ip)
  1. メモリキャッシュ (Option<HashMap<IpNet, String>>) を確認
     ├─ 未ロード → ディスクキャッシュから全 whois-iana-*.json を読み込む
     └─ ヒット → そのサーバーを返す
  2. キャッシュミス → whois.iana.org に TCP 43 で問い合わせ
     ├─ 成功 → inetnum ブロック + refer フィールドを解析
     │          → メモリキャッシュ + ディスクキャッシュに保存
     └─ 失敗 → fallback server を使用 (ログ警告)
```

### IANA レスポンス例

```
inetnum:      193.0.0.0 - 193.255.255.255
organisation: RIPE NCC
refer:        whois.ripe.net
```

`inetnum` を `IpNet` に変換してキャッシュキー、`refer:` の値を RIR サーバーとして保存する。

### ディスクキャッシュ

パス: `{cache_dir}/whois-iana-{family}-{sanitized_block}.json`

例:

- `data/cache/import/whois-iana-ipv4-193.0.0.0_8.json`
- `data/cache/import/whois-iana-ipv6-2001-db8--_32.json`

内容:

```json
{ "block": "193.0.0.0/8", "server": "whois.ripe.net" }
```

TTL は `cache_ttl_secs` を使用。IANA のブロック割り当ては変化が極めて少ないため
長めの TTL でも問題ない。プロセス起動後の初回クエリ時にディスクキャッシュを一括ロード
し、以降はメモリキャッシュのみ参照する。

## クエリフロー

```
query_cidr(cidr)
  → resolve_server(cidr.network())   # RIR サーバー特定 (auto_rir 時)
  → query_server(cidr, server, depth=0)
      → tcp43_raw(cidr, server, -M flag)  # Step 1: 包含する inetnum を一括取得
          → parse_rpsl_all()              # ヒット → 結果を返す
      → tcp43_raw(cidr, server, bare)     # Step 2: ベアクエリ
          → parse_rpsl_all()
      → parse_referral()                  # Step 3: refer: あれば追跡 (最大 depth 3)
          → query_server(cidr, refer_server, depth+1)
```

Step 1 (`-M` クエリ) は初回呼び出し (`depth == 0`) のみ実行する。referral 追跡先の
RIR サーバーでは実行しない。

## キャッシュ (CIDR 単位)

パス: `{cache_dir}/whois-cidr-{family}-{sanitized_cidr}.jsonl`

`cache_ttl_secs` 以内のキャッシュが存在する場合はネットワークアクセスをスキップする。
キャッシュ書き込みは `query_cidr` の成功後に行われる。

## レートリミットとリトライ

- 各 CIDR クエリの前に `rate_limit_ms` 待機する。
- レートリミット応答 (`ERROR:201`, `rate limit exceeded` 等) はリトライ対象。
- タイムアウト・接続拒否・接続リセットも一時エラーとして `max_retries` 回まで再試行。
- リトライ間隔は指数バックオフ (`initial_backoff_ms` × 2^n)。
