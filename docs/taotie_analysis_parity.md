# taotie 分析基盤の taotie 移植チェックリスト

作成日: 2026-06-24

## 方針

taotie の分析・相関・調査機能を taotie に移植する。ただし taotie の API/画面をそのまま移すのではなく、taotie の制約を守る。

- UI は全件データを保持しない
- raw record は詳細表示時だけ読む
- findings/entities/edges/graph は background job と read model を経由する
- graph は selected entity/event centered で小さく返す
- parser/外部ツールは UI hot path に入れない

## 移植対象

| 分類 | taotie 機能 | taotie 方針 | 状態 |
| --- | --- | --- | --- |
| L4 findings | heuristic detections | `lake/findings` + `get_finding_summary` | 着手済み |
| L4 findings | taotie-core 52 detectors | sidecar/import adapter または native analyzer | 未着手 |
| Sigma | Sigma matching | background analyzer + findings read model | 未着手 |
| IOC | IOC照合 | `get_ioc_matches` + `get_ioc_event_page`。次に IOC analyzer + `lake/findings` engine=`ioc` | 一部実装済み |
| Rules | suppress/override | `meta/finding_overrides.json` + findings/event_rows rebuild | 一部実装済み |
| Risk | ATT&CK technique 集約 | `get_risk_summary` | 着手済み |
| Correlation | process/file/ip/user pivot | read model 化した `correlation_summary` | 一部実装済み |
| Correlation chains | suspicious multi-artifact chains | `read_models/correlation_chains` + bounded summary/detail UI | 一部実装済み |
| L3 graph | entities | `lake/entities` + bounded entity summary | 一部実装済み |
| L3 graph | edges | `lake/edges` + centered subgraph query | 一部実装済み |
| Users | user activity | `get_user_activity_summary` + user filtered events | 一部実装済み |
| Defender | Defender Operational/MpLog 集約 | `artifact_type=defender` + `get_defender_summary` + Defender tab | 一部実装済み |
| Coverage | parse coverage | `coverage_summary` / `failed_parser_summary` | 一部実装済み |
| Coverage matrix | host x artifact matrix | `read_models/coverage_matrix` | 未着手 |
| Analyzer provenance | analyzer_runs | `lake/analyzer_runs` + `get_analyzer_runs` | 着手済み |
| Bookmarks | event bookmarks | `meta/bookmarks.json` + paged bookmark event view | 一部実装済み |
| Hex/raw | evidence byte viewer | raw object ranged reader | 未着手 |
| Search | full-text/search_events | `EventPageQuery.search` + 将来 Tantivy | 初期実装済み |

## 2026-06-24 の初期移植

| 項目 | 内容 |
| --- | --- |
| 追加 schema | `FindingRecord`, `FindingSummary`, `FindingEventPageQuery`, `RiskSummary`, `AnalyzerRunSummary`, `EntityRecord`, `EdgeRecord`, `Subgraph`, `CorrelationChainSummary`, `CorrelationChainEventPageQuery` |
| 追加 storage | `lake/findings`, `lake/analyzer_runs`, `lake/entities`, `lake/edges`, `read_models/correlation_chains` |
| 追加 API | `get_finding_summary`, `get_finding_event_page`, `get_risk_summary`, `get_analyzer_runs`, `get_entity_summary`, `get_subgraph`, `get_correlation_chains`, `get_correlation_chain_event_page` |
| 追加 UI | `不審イベント`, `リスク`, `アナライザ履歴`, `相関図`, `相関チェーン` タブ |
| 追加 analyzer | taotie `t3-detect` 由来の初期ヒューリスティック |
| 追加 graph | taotie `t3-normalize` 由来の host/user/process/file/ip/url/hash entity と edge 派生 |
| 追加 event query | `EventPageQuery.sort_by/sort_dir` による read model 全体の server-side sort |
| 追加 event search | `EventPageQuery.search` による EventID/user/process/file/ip/url/hash/message 横断の paged search |
| 追加 event row | EventID/process/file/ip/url/hash/channel/level を一覧用 read model に materialize |
| 追加 drill-down | findings から該当イベントを paged query で表示 |
| 追加 chain | file/ip/hash/url/user を起点にした bounded chain summary、semantic title/severity/score、根拠イベントを表示 |
| 追加 chain read model | 取り込み後に `read_models/correlation_chains` を再構築し、タブ表示は read model を優先 |
| 追加 import adapter | Prefetch / Amcache / USN / browser の CSV/JSON export を構造化イベント化し、相関チェーンに投入 |
| 追加 chain findings | medium 以上の semantic chain を `engine=correlation` の finding として再構築し、risk summary と finding drill-down に連携 |
| 追加 event row rebuild | findings を lake 全体から置換再構築した後、`read_models/event_rows.has_finding` も再構築して chain finding の根拠イベントに反映 |
| 追加 suppress/override | finding の `engine/rule_id/title` に対する抑制と severity 上書きを `meta/finding_overrides.json` に保存し、再構築時に適用 |
| 追加 bookmarks | event bookmark を `meta/bookmarks.json` に保存し、`get_bookmark_event_page` で bounded/paged 表示 |
| 追加 IOC | `IocHit`, `IocEventPageQuery`, `get_ioc_matches`, `get_ioc_event_page`, 左ペイン `IOC照合` タブを追加。hash/ip/process 完全一致と調査用 text match を read model 全体に適用 |
| 追加 Defender | `DefenderSummary`, `DefenderEventPageQuery`, `get_defender_summary`, `get_defender_event_page`, 左ペイン `Defender` タブを追加。MPOperationalEvents/Defender Operational export と MPLog を `artifact_type=defender` に正規化 |

## 残作業

1. Prefetch / Amcache / USN / browser の raw/native parser または外部ツール sidecar adapter を追加する
2. entity/edge の重複 evidence を Parquet append 間で union する compaction job を追加する
3. noisy chain 調整と override 条件の詳細化を追加する
4. IOC analyzer と IOC/rule suppress/override を追加する。照合 API/UI と drill-down は実装済み
5. taotie-core 由来 detector/Sigma を native analyzer または sidecar で移植する
6. coverage matrix / raw ranged hex viewer を追加する
7. `EventPageQuery.search` を Tantivy-backed search に置き換える、または大規模ケース用に併用する
8. taotie との比較表を更新する
