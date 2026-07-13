use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use chrono::Duration;
use duckdb::{Connection, Row};
use serde::Serialize;
use taotie_schema::{
    bounded_limit, derive_artifact_objects_from_detail, derive_evidence_offsets_from_detail,
    parse_utc, AnalyzerRunSummary, AnswerCandidate, ArtifactObject, BeaconIntervalBin, CaseManifest,
    CaseSummary,
    CorrelationChainEventPageQuery, CorrelationChainSummary, CorrelationSummary, CoverageSummary,
    DefenderEventPageQuery, DefenderSummary, EdgeRecord, EntityRecord, EventContext,
    EventContextGroup, EventContextQuery, EventDetailLight, EventExportResult, EventFacetValue,
    EventFull, EventPageQuery, EventRow, EventTimelineBin, EvidenceOffset, FailedParserSummary,
    FileOpBin, FilePageQuery,
    FileRecord, FindingEventPageQuery, FindingSummary, IocEventPageQuery, IocHit, Page,
    ParserStatus, PrefetchSummary, ProcessTreeEdge, RawRecord, RiskSummary, Subgraph, TimelineBin,
    TimestompPoint, UserActivitySummary,
};
use tracing::debug;

use crate::{Result, StorageError};

const EVENT_ROW_FALLBACK_FINDING_ENGINE: &str = "event_rows";
/// Bump this whenever the event_rows SQL projection (columns/extraction) changes,
/// so existing read models built by an older projection auto-rebuild on next open
/// instead of being silently reused (which would keep stale/missing columns).
const EVENT_ROWS_PROJECTION_VERSION: u32 = 5;
const EVENT_ROW_FALLBACK_FINDING_RULE_PREFIX: &str = "event_row:";

#[derive(Debug, Clone)]
pub struct DuckDbQueryLayer {
    root: PathBuf,
    manifest: CaseManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortDir {
    Asc,
    Desc,
}

impl SortDir {
    fn from_query(value: Option<&str>) -> Self {
        match value {
            Some("desc") => Self::Desc,
            _ => Self::Asc,
        }
    }

    fn as_sql(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventSortField {
    EventTimeUtc,
    Severity,
    ArtifactType,
    Host,
    UserName,
    ProcessName,
    FilePath,
    Ip,
    Url,
    Hash,
    EventCode,
    Channel,
    Level,
    EventAction,
    MessageShort,
    CommandLine,
    ParserName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventSort {
    field: EventSortField,
    dir: SortDir,
}

impl EventSort {
    fn from_query(query: &EventPageQuery) -> Self {
        let field = match query.sort_by.as_deref() {
            Some("severity") => EventSortField::Severity,
            Some("artifact_type") => EventSortField::ArtifactType,
            Some("host") => EventSortField::Host,
            Some("user_name") => EventSortField::UserName,
            Some("process_name") => EventSortField::ProcessName,
            Some("file_path") => EventSortField::FilePath,
            Some("ip") => EventSortField::Ip,
            Some("url") => EventSortField::Url,
            Some("hash") => EventSortField::Hash,
            Some("event_code") => EventSortField::EventCode,
            Some("channel") => EventSortField::Channel,
            Some("level") => EventSortField::Level,
            Some("event_action") => EventSortField::EventAction,
            Some("message_short") => EventSortField::MessageShort,
            Some("command_line") => EventSortField::CommandLine,
            Some("parser_name") => EventSortField::ParserName,
            _ => EventSortField::EventTimeUtc,
        };
        Self {
            field,
            dir: SortDir::from_query(query.sort_dir.as_deref()),
        }
    }

    fn expr(self) -> &'static str {
        match self.field {
            EventSortField::EventTimeUtc => "event_time_utc",
            EventSortField::Severity => {
                "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"
            }
            EventSortField::ArtifactType => "artifact_type",
            EventSortField::Host => "COALESCE(host, '')",
            EventSortField::UserName => "COALESCE(user_name, '')",
            EventSortField::ProcessName => "COALESCE(process_name, '')",
            EventSortField::FilePath => "COALESCE(file_path, '')",
            EventSortField::Ip => "COALESCE(ip, '')",
            EventSortField::Url => "COALESCE(url, '')",
            EventSortField::Hash => "COALESCE(hash, '')",
            EventSortField::EventCode => "COALESCE(event_code, '')",
            EventSortField::Channel => "COALESCE(channel, '')",
            EventSortField::Level => "COALESCE(level, '')",
            EventSortField::EventAction => "event_action",
            EventSortField::MessageShort => "message_short",
            EventSortField::CommandLine => "COALESCE(command_line, '')",
            EventSortField::ParserName => "parser_name",
        }
    }

    fn value(self, row: &EventRow) -> String {
        match self.field {
            EventSortField::EventTimeUtc => row.event_time_utc.clone(),
            EventSortField::Severity => severity_rank(&row.severity).to_string(),
            EventSortField::ArtifactType => row.artifact_type.clone(),
            EventSortField::Host => row.host.clone().unwrap_or_default(),
            EventSortField::UserName => row.user_name.clone().unwrap_or_default(),
            EventSortField::ProcessName => row.process_name.clone().unwrap_or_default(),
            EventSortField::FilePath => row.file_path.clone().unwrap_or_default(),
            EventSortField::Ip => row.ip.clone().unwrap_or_default(),
            EventSortField::Url => row.url.clone().unwrap_or_default(),
            EventSortField::Hash => row.hash.clone().unwrap_or_default(),
            EventSortField::EventCode => row.event_code.clone().unwrap_or_default(),
            EventSortField::Channel => row.channel.clone().unwrap_or_default(),
            EventSortField::Level => row.level.clone().unwrap_or_default(),
            EventSortField::EventAction => row.event_action.clone(),
            EventSortField::MessageShort => row.message_short.clone(),
            EventSortField::CommandLine => row.command_line.clone().unwrap_or_default(),
            EventSortField::ParserName => row.parser_name.clone(),
        }
    }

    fn sql_literal(self, value: &str) -> String {
        match self.field {
            EventSortField::Severity => value.parse::<i64>().unwrap_or(0).to_string(),
            _ => sql_literal(value),
        }
    }
}

impl DuckDbQueryLayer {
    pub fn new(root: PathBuf, manifest: CaseManifest) -> Self {
        Self { root, manifest }
    }

    pub fn case_summary(&self) -> Result<CaseSummary> {
        let started = Instant::now();
        let file_count = self.count_table("inventory/files", "1=1")?;
        let event_count = self.count_table("read_models/event_rows", "1=1")?;
        let failed_parse_count = self.count_table("inventory/parse_runs", "status = 'failed'")?;
        let unsupported_file_count =
            self.count_table("inventory/files", "parser_status = 'unsupported'")?;
        let summary = CaseSummary {
            case_id: self.manifest.case_id.clone(),
            name: self.manifest.name.clone(),
            root_path: self.root.display().to_string(),
            created_at: self.manifest.created_at.clone(),
            schema_version: self.manifest.schema_version.clone(),
            file_count,
            event_count,
            failed_parse_count,
            unsupported_file_count,
        };
        log_payload("case_summary", &summary, started);
        Ok(summary)
    }

    pub fn coverage_summary(&self) -> Result<Vec<CoverageSummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/coverage_summary")? else {
            return Ok(Vec::new());
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT case_id, artifact_type, SUM(total_files), SUM(parsed_files), \
             SUM(failed_files), SUM(unsupported_files), SUM(event_count) \
             FROM {expr} GROUP BY case_id, artifact_type ORDER BY artifact_type"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(CoverageSummary {
                case_id: row.get(0)?,
                artifact_type: row.get(1)?,
                total_files: row.get(2)?,
                parsed_files: row.get(3)?,
                failed_files: row.get(4)?,
                unsupported_files: row.get(5)?,
                event_count: row.get(6)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("coverage_summary", &out, started);
        Ok(out)
    }

    pub fn failed_parser_summary(&self) -> Result<Vec<FailedParserSummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/failed_parser_summary")? else {
            return Ok(Vec::new());
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT case_id, parser_name, artifact_type, SUM(failure_count), \
             MAX(last_error), MAX(last_seen_at) FROM {expr} \
             GROUP BY case_id, parser_name, artifact_type \
             ORDER BY SUM(failure_count) DESC, parser_name"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(FailedParserSummary {
                case_id: row.get(0)?,
                parser_name: row.get(1)?,
                artifact_type: row.get(2)?,
                failure_count: row.get(3)?,
                last_error: row.get(4)?,
                last_seen_at: row.get(5)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("failed_parser_summary", &out, started);
        Ok(out)
    }

    pub fn timeline_bins(
        &self,
        granularity: &str,
        limit: Option<usize>,
    ) -> Result<Vec<TimelineBin>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/timeline_bins")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 500, 10_000);
        let granularity = sql_literal(granularity);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT case_id, granularity, bin_start_utc, artifact_type, SUM(event_count), \
             MAX(severity_max) FROM {expr} WHERE granularity = {granularity} \
             GROUP BY case_id, granularity, bin_start_utc, artifact_type \
             ORDER BY bin_start_utc ASC, artifact_type ASC LIMIT {limit}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(TimelineBin {
                case_id: row.get(0)?,
                granularity: row.get(1)?,
                bin_start_utc: row.get(2)?,
                artifact_type: row.get(3)?,
                event_count: row.get(4)?,
                severity_max: row.get(5)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("timeline_bins", &out, started);
        Ok(out)
    }

    pub fn event_page(&self, query: EventPageQuery) -> Result<Page<EventRow>> {
        self.event_page_with_clauses(query, Vec::new(), "event_page")
    }

    pub fn event_facets(
        &self,
        query: EventPageQuery,
        per_field_limit: Option<usize>,
    ) -> Result<Vec<EventFacetValue>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let has_search_text = self.table_has_column("read_models/event_rows", "search_text")?;
        let clauses = event_filter_clauses(&query, has_search_text);
        let where_sql = if clauses.is_empty() {
            "1=1".to_string()
        } else {
            clauses.join(" AND ")
        };
        let limit = bounded_limit(per_field_limit, 8, 30);
        let conn = Connection::open_in_memory()?;
        let mut out = Vec::new();
        for (field, sql_expr) in [
            ("artifact_type", "artifact_type"),
            ("severity", "severity"),
            ("channel", "COALESCE(channel, '-')"),
            ("level", "COALESCE(level, '-')"),
            ("event_code", "COALESCE(event_code, '-')"),
            ("host", "COALESCE(host, '-')"),
            ("user_name", "COALESCE(user_name, '-')"),
            ("event_action", "event_action"),
            ("parser_name", "parser_name"),
        ] {
            let sql = format!(
                "SELECT {value_expr} AS value, COUNT(*) AS count FROM {expr} \
                 WHERE {where_sql} GROUP BY value ORDER BY count DESC, value ASC LIMIT {limit}",
                value_expr = sql_expr
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |row| {
                Ok(EventFacetValue {
                    field: field.to_string(),
                    value: row.get::<_, String>(0)?,
                    count: row.get(1)?,
                })
            })?;
            out.extend(collect_rows(rows)?);
        }
        log_payload("event_facets", &out, started);
        Ok(out)
    }

    /// Aggregate event_rows into time bins with per-severity counts, honoring the
    /// same filter DSL as the event page. event_time_utc is an RFC3339 string
    /// (fixed-width prefix), so we bucket by string-prefix truncation — no date
    /// CAST, robust to the exact suffix. granularity: minute | hour(default) | day.
    pub fn event_timeline(
        &self,
        query: EventPageQuery,
        granularity: &str,
    ) -> Result<Vec<EventTimelineBin>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let has_search_text = self.table_has_column("read_models/event_rows", "search_text")?;
        let clauses = event_filter_clauses(&query, has_search_text);
        let where_sql = if clauses.is_empty() {
            "1=1".to_string()
        } else {
            clauses.join(" AND ")
        };
        let (prefix_len, suffix): (usize, &str) = match granularity {
            "minute" => (16, ":00Z"),
            "day" => (10, "T00:00:00Z"),
            _ => (13, ":00:00Z"),
        };
        let bin_expr = format!("substr(event_time_utc, 1, {prefix_len}) || {}", sql_literal(suffix));
        let limit = bounded_limit(Some(20_000), 500, 100_000);
        let conn = Connection::open_in_memory()?;
        // If the number of bins exceeds the cap (only realistic at minute
        // granularity over a very wide time span), keep the MOST RECENT bins
        // (inner ORDER BY DESC LIMIT) and re-sort ascending for the chart, so
        // the investigation-relevant recent window is never silently dropped.
        let sql = format!(
            "SELECT * FROM ( \
               SELECT {bin_expr} AS bin_start_utc, \
               COUNT(*) AS total, \
               CAST(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS BIGINT) AS critical, \
               CAST(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS BIGINT) AS high, \
               CAST(SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS BIGINT) AS medium, \
               CAST(SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS BIGINT) AS low, \
               CAST(SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) AS BIGINT) AS info \
               FROM {expr} WHERE {where_sql} \
               GROUP BY bin_start_utc ORDER BY bin_start_utc DESC LIMIT {limit} \
             ) ORDER BY bin_start_utc ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(EventTimelineBin {
                bin_start_utc: row.get(0)?,
                total: row.get(1)?,
                critical: row.get(2)?,
                high: row.get(3)?,
                medium: row.get(4)?,
                low: row.get(5)?,
                info: row.get(6)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("event_timeline", &out, started);
        Ok(out)
    }

    /// NTFS timestomping scatter: pair each MFT record's $SI-created (x) with its
    /// $FN-created (y) by file path. event_rows stores the two timestamps as
    /// separate rows (distinct event_action), so pivot on file_path. Every
    /// off-diagonal point (si != fn) is a timestomp suspect. Keeps all suspects
    /// plus a stride-sampled set of consistent points so the diagonal is visible.
    pub fn timestomp_scatter(&self, limit: Option<usize>) -> Result<Vec<TimestompPoint>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let cap = bounded_limit(limit, 1_500, 6_000);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT file_path, \
               MAX(CASE WHEN event_action = 'mft_created' THEN event_time_utc END) AS si_created, \
               MAX(CASE WHEN event_action = 'mft_filename_created' THEN event_time_utc END) AS fn_created \
             FROM {expr} \
             WHERE artifact_type = 'mft' \
               AND event_action IN ('mft_created', 'mft_filename_created') \
               AND file_path IS NOT NULL \
             GROUP BY file_path \
             HAVING si_created IS NOT NULL AND fn_created IS NOT NULL"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            let file_path: String = row.get(0)?;
            let si_created: String = row.get(1)?;
            let fn_created: String = row.get(2)?;
            Ok((file_path, si_created, fn_created))
        })?;
        let mut mismatches = Vec::new();
        let mut consistent = Vec::new();
        for row in rows {
            let (file_path, si_created_utc, fn_created_utc) = row?;
            let delta_seconds = match (parse_utc(&si_created_utc), parse_utc(&fn_created_utc)) {
                (Ok(si), Ok(fnt)) => (fnt - si).num_seconds(),
                _ => 0,
            };
            // A sub-hour skew is normal (copy semantics set $SI from the source);
            // treat only a >1h divergence as a timestomp suspect.
            let mismatch = delta_seconds.abs() > 3_600;
            let point = TimestompPoint {
                file_path,
                si_created_utc,
                fn_created_utc,
                delta_seconds,
                mismatch,
            };
            if mismatch {
                mismatches.push(point);
            } else {
                consistent.push(point);
            }
        }
        // Balanced sample: cap suspects at 2/3 of the budget so the diagonal
        // (consistent points) stays visible even when suspects dominate.
        fn stride_sample(src: Vec<TimestompPoint>, budget: usize, out: &mut Vec<TimestompPoint>) {
            if budget == 0 || src.is_empty() {
                return;
            }
            if src.len() <= budget {
                out.extend(src);
                return;
            }
            let stride = src.len() / budget;
            for (idx, point) in src.into_iter().enumerate() {
                if idx % stride == 0 && out.len() < out.capacity() {
                    out.push(point);
                }
            }
        }
        let mut out = Vec::with_capacity(cap);
        let suspect_budget = (cap * 2 / 3).min(mismatches.len());
        stride_sample(mismatches, suspect_budget, &mut out);
        let remaining = cap.saturating_sub(out.len());
        stride_sample(consistent, remaining, &mut out);
        out.truncate(cap);
        log_payload("timestomp_scatter", &out, started);
        Ok(out)
    }

    /// Process spawn tree edges. Reads process_created events from the lake (the
    /// parent image lives in attributes_json, not a column), normalizes both
    /// sides to a lowercase basename, and aggregates parent -> child counts.
    pub fn process_tree(&self, limit: Option<usize>) -> Result<Vec<ProcessTreeEdge>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(Vec::new());
        };
        let edge_cap = bounded_limit(limit, 80, 400);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT process_name, attributes_json FROM {expr} \
             WHERE event_action = 'process_created' AND process_name IS NOT NULL LIMIT 200000"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            let child: String = row.get(0)?;
            let attrs: Option<String> = row.get(1)?;
            Ok((child, attrs))
        })?;
        let mut counts: HashMap<(String, String), i64> = HashMap::new();
        for row in rows {
            let (child_raw, attrs) = row?;
            let child = process_basename(&child_raw);
            if child.is_empty() {
                continue;
            }
            let parent = attrs
                .as_deref()
                .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
                .and_then(|v| {
                    v.get("parent_process")
                        .and_then(|p| p.as_str())
                        .map(str::to_string)
                })
                .map(|p| process_basename(&p))
                .filter(|p| !p.is_empty());
            // Only chart real spawn relationships; skip events with no parent so a
            // synthetic "(unknown)" root doesn't dominate the tree.
            let Some(parent) = parent else {
                continue;
            };
            *counts.entry((parent, child)).or_insert(0) += 1;
        }
        let mut edges: Vec<ProcessTreeEdge> = counts
            .into_iter()
            .map(|((parent, child), count)| ProcessTreeEdge {
                parent,
                child,
                count,
            })
            .collect();
        edges.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.parent.cmp(&b.parent)));
        edges.truncate(edge_cap);
        log_payload("process_tree", &edges, started);
        Ok(edges)
    }

    /// USN journal file-operation timeline, bucketed by hour and split by reason,
    /// so the UI can diverge creates upward and deletes downward.
    pub fn file_op_timeline(&self, limit: Option<usize>) -> Result<Vec<FileOpBin>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let cap = bounded_limit(limit, 180, 800);
        let conn = Connection::open_in_memory()?;
        // Hour-granularity buckets (YYYY-MM-DDTHH) so a case that spans a single
        // day still spreads across the axis instead of collapsing to one bar.
        let sql = format!(
            "SELECT substr(event_time_utc, 1, 13) AS bin, event_action, COUNT(*) AS n \
             FROM {expr} \
             WHERE artifact_type = 'usn_jrnl' \
               AND event_action IN ('usn_created', 'usn_deleted', 'usn_renamed', 'usn_modified') \
             GROUP BY bin, event_action ORDER BY bin ASC LIMIT {rows_cap}",
            rows_cap = cap * 4
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            let bin: String = row.get(0)?;
            let action: String = row.get(1)?;
            let n: i64 = row.get(2)?;
            Ok((bin, action, n))
        })?;
        let mut order: Vec<String> = Vec::new();
        let mut acc: HashMap<String, FileOpBin> = HashMap::new();
        for row in rows {
            let (bin, action, n) = row?;
            let entry = acc.entry(bin.clone()).or_insert_with(|| {
                order.push(bin.clone());
                FileOpBin {
                    bin_start_utc: bin.clone(),
                    created: 0,
                    deleted: 0,
                    renamed: 0,
                    modified: 0,
                }
            });
            match action.as_str() {
                "usn_created" => entry.created += n,
                "usn_deleted" => entry.deleted += n,
                "usn_renamed" => entry.renamed += n,
                "usn_modified" => entry.modified += n,
                _ => {}
            }
        }
        let mut out: Vec<FileOpBin> = order.into_iter().filter_map(|b| acc.remove(&b)).collect();
        out.truncate(cap);
        log_payload("file_op_timeline", &out, started);
        Ok(out)
    }

    /// Beaconing interval histogram. Orders connections by destination IP then
    /// time, computes the gap between consecutive connections to the same
    /// destination, and buckets those gaps — a dominant bucket is a fixed-interval
    /// C2 beacon signature.
    pub fn beacon_intervals(&self, limit: Option<usize>) -> Result<Vec<BeaconIntervalBin>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let scan_cap = bounded_limit(limit, 200_000, 500_000);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT ip, event_time_utc FROM {expr} \
             WHERE event_action IN ('network_connection', 'firewall_connection_allowed') \
               AND ip IS NOT NULL \
             ORDER BY ip ASC, event_time_utc ASC LIMIT {scan_cap}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            let ip: String = row.get(0)?;
            let time: String = row.get(1)?;
            Ok((ip, time))
        })?;
        let buckets: [(&str, i64, i64); 8] = [
            ("<10s", 0, 10),
            ("10-30s", 10, 30),
            ("30-60s", 30, 60),
            ("1-5m", 60, 300),
            ("5-15m", 300, 900),
            ("15-60m", 900, 3600),
            ("1-6h", 3600, 21_600),
            (">6h", 21_600, i64::MAX),
        ];
        let mut hist = [0i64; 8];
        let mut bucket_ips: Vec<HashMap<String, i64>> = vec![HashMap::new(); 8];
        let mut prev_ip: Option<String> = None;
        let mut prev_time: Option<chrono::DateTime<chrono::Utc>> = None;
        for row in rows {
            let (ip, time) = row?;
            let parsed = parse_utc(&time).ok();
            if prev_ip.as_deref() == Some(ip.as_str()) {
                if let (Some(prev), Some(curr)) = (prev_time, parsed) {
                    let delta = (curr - prev).num_seconds();
                    if delta >= 0 {
                        for (idx, (_, lo, hi)) in buckets.iter().enumerate() {
                            if delta >= *lo && delta < *hi {
                                hist[idx] += 1;
                                *bucket_ips[idx].entry(ip.clone()).or_insert(0) += 1;
                                break;
                            }
                        }
                    }
                }
            }
            prev_ip = Some(ip);
            prev_time = parsed;
        }
        let out: Vec<BeaconIntervalBin> = buckets
            .iter()
            .enumerate()
            .map(|(idx, (label, lo, hi))| BeaconIntervalBin {
                label: label.to_string(),
                lower_seconds: *lo,
                upper_seconds: if *hi == i64::MAX { -1 } else { *hi },
                count: hist[idx],
                top_ip: bucket_ips[idx]
                    .iter()
                    .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
                    .map(|(ip, _)| ip.clone()),
            })
            .collect();
        log_payload("beacon_intervals", &out, started);
        Ok(out)
    }

    pub fn event_context(&self, query: EventContextQuery) -> Result<Option<EventContext>> {
        let started = Instant::now();
        let Some(anchor) = self.event_detail_light(&query.event_id)? else {
            return Ok(None);
        };
        let per_group_limit = bounded_limit(query.per_group_limit, 50, 200);
        let window_minutes = query.window_minutes.unwrap_or(15).clamp(1, 24 * 60);
        let mut groups = Vec::new();

        if let Ok(anchor_time) = parse_utc(&anchor.event_time_utc) {
            let start = (anchor_time - Duration::minutes(window_minutes)).to_rfc3339();
            let end = (anchor_time + Duration::minutes(window_minutes)).to_rfc3339();
            let mut time_window_clauses = vec![format!(
                "event_time_utc >= {} AND event_time_utc <= {}",
                sql_literal(&start),
                sql_literal(&end)
            )];
            if query.same_host_only.unwrap_or(false) {
                if let Some(host) = anchor
                    .host
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    time_window_clauses.push(format!("host = {}", sql_literal(host)));
                }
            }
            if let Some(group) = self.context_group(
                "前後時間".to_string(),
                "time_window".to_string(),
                format!("±{window_minutes}m"),
                time_window_clauses,
                per_group_limit,
            )? {
                groups.push(group);
            }
        }

        for (label, relation, value, column) in [
            (
                "同一ユーザー",
                "same_user",
                anchor.user_name.as_deref(),
                "user_name",
            ),
            ("同一ホスト", "same_host", anchor.host.as_deref(), "host"),
            (
                "同一プロセス",
                "same_process",
                anchor.process_name.as_deref(),
                "process_name",
            ),
            (
                "同一ファイル",
                "same_file",
                anchor.file_path.as_deref(),
                "file_path",
            ),
            ("同一IP", "same_ip", anchor.ip.as_deref(), "ip"),
            ("同一URL", "same_url", anchor.url.as_deref(), "url"),
            ("同一ハッシュ", "same_hash", anchor.hash.as_deref(), "hash"),
        ] {
            let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
                continue;
            };
            if let Some(group) = self.context_group(
                label.to_string(),
                relation.to_string(),
                value.to_string(),
                vec![format!("{column} = {}", sql_literal(value))],
                per_group_limit,
            )? {
                groups.push(group);
            }
        }

        if let Some(value) = anchor
            .file_path
            .as_deref()
            .or(anchor.process_name.as_deref())
            .and_then(basename)
        {
            if let Some(group) = self.context_group(
                "同一ファイル名".to_string(),
                "same_file_basename".to_string(),
                value.clone(),
                vec![format!(
                    "lower(regexp_replace(COALESCE(file_path, process_name, ''), '^.*[\\\\/]', '')) = {}",
                    sql_literal(&value.to_ascii_lowercase())
                )],
                per_group_limit,
            )? {
                groups.push(group);
            }
        }

        let out = EventContext { anchor, groups };
        log_payload("event_context", &out, started);
        Ok(Some(out))
    }

    pub fn export_event_rows(
        &self,
        query: EventPageQuery,
        output_path: &Path,
        format: &str,
        max_rows: Option<usize>,
    ) -> Result<EventExportResult> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(EventExportResult {
                output_path: output_path.display().to_string(),
                format: format.to_string(),
                row_count: 0,
                truncated: false,
            });
        };
        let format = match format {
            "jsonl" => "jsonl",
            _ => "csv",
        };
        let limit = bounded_limit(max_rows, 100_000, 1_000_000);
        let sort = EventSort::from_query(&query);
        let has_search_text = self.table_has_column("read_models/event_rows", "search_text")?;
        let mut clauses = Vec::new();
        if let Some(artifact_type) = query.artifact_type.as_deref().filter(|s| !s.is_empty()) {
            clauses.push(format!("artifact_type = {}", sql_literal(artifact_type)));
        }
        if let Some(user_name) = query.user_name.as_deref().filter(|s| !s.is_empty()) {
            clauses.push(format!("user_name = {}", sql_literal(user_name)));
        }
        if let Some(search) = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            clauses.push(event_search_clause(search, has_search_text));
        }
        let where_sql = if clauses.is_empty() {
            "1=1".to_string()
        } else {
            clauses.join(" AND ")
        };
        let cmd_col = self.event_rows_command_col()?;
        let sql = format!(
            "SELECT event_id, case_id, event_time_utc, artifact_type, host, user_name, \
             process_name, file_path, ip, url, hash, event_code, channel, level, \
             event_action, severity, message_short, source_file_id, parser_name, has_finding, {cmd_col} \
             FROM {expr} WHERE {where_sql} ORDER BY {sort_expr} {sort_direction}, event_id ASC LIMIT {}",
            limit + 1,
            sort_expr = sort.expr(),
            sort_direction = sort.dir.as_sql()
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event_row)?;
        let mut rows = collect_rows(rows)?;
        let truncated = rows.len() > limit;
        if truncated {
            rows.truncate(limit);
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_event_export(output_path, format, &rows)?;
        let out = EventExportResult {
            output_path: output_path.display().to_string(),
            format: format.to_string(),
            row_count: rows.len() as i64,
            truncated,
        };
        log_payload("export_event_rows", &out, started);
        Ok(out)
    }

    pub fn finding_event_page(&self, query: FindingEventPageQuery) -> Result<Page<EventRow>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/findings")? else {
            return self.event_row_finding_event_page(query);
        };
        let mut clauses = vec![format!("title = {}", sql_literal(&query.title))];
        if let Some(engine) = query.engine.as_deref().filter(|s| !s.is_empty()) {
            clauses.push(format!("engine = {}", sql_literal(engine)));
        }
        if let Some(rule_id) = query.rule_id.as_deref().filter(|s| !s.is_empty()) {
            clauses.push(format!("rule_id = {}", sql_literal(rule_id)));
        }
        let where_sql = clauses.join(" AND ");
        let sql = format!(
            "SELECT event_ids_json FROM {expr} WHERE {where_sql} \
             ORDER BY first_seen_utc ASC, detection_id ASC LIMIT 5000"
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut seen = HashSet::new();
        let mut event_ids = Vec::new();
        for row in rows {
            for event_id in parse_json_strings(&row?) {
                if seen.insert(event_id.clone()) {
                    event_ids.push(event_id);
                }
                if event_ids.len() >= 5000 {
                    break;
                }
            }
            if event_ids.len() >= 5000 {
                break;
            }
        }
        if event_ids.is_empty() {
            return self.event_row_finding_event_page(query);
        }
        let extra = vec![format!("event_id IN ({})", sql_list(event_ids.iter()))];
        let page = self.event_page_with_clauses(query.page, extra, "finding_event_page")?;
        log_payload("finding_event_ids", &event_ids.len(), started);
        Ok(page)
    }

    fn event_row_finding_event_page(&self, query: FindingEventPageQuery) -> Result<Page<EventRow>> {
        if query.engine.as_deref() != Some(EVENT_ROW_FALLBACK_FINDING_ENGINE) {
            return Ok(Page::empty());
        }
        let Some((severity, artifact_type, event_action)) =
            decode_event_row_finding_rule_id(query.rule_id.as_deref())
        else {
            return Ok(Page::empty());
        };
        self.event_page_with_clauses(
            query.page,
            vec![
                format!("severity = {}", sql_literal(&severity)),
                format!("artifact_type = {}", sql_literal(&artifact_type)),
                format!("event_action = {}", sql_literal(&event_action)),
                event_row_finding_candidate_clause(),
            ],
            "event_row_finding_event_page",
        )
    }

    pub fn ioc_match(&self, indicators: &[String], limit: Option<usize>) -> Result<Vec<IocHit>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let mut seen = HashSet::new();
        let mut normalized = Vec::new();
        for indicator in indicators
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            let key = indicator.to_ascii_lowercase();
            if seen.insert(key) {
                normalized.push(indicator.to_string());
            }
            if normalized.len() >= 500 {
                break;
            }
        }
        if normalized.is_empty() {
            return Ok(Vec::new());
        }
        let limit = bounded_limit(limit, 100, 500);
        let values_sql = normalized
            .iter()
            .map(|indicator| format!("({})", sql_literal(indicator)))
            .collect::<Vec<_>>()
            .join(", ");
        let has_search_text = self.table_has_column("read_models/event_rows", "search_text")?;
        let haystack_sql = event_ioc_haystack_sql(has_search_text);
        let sql = format!(
            "WITH ind(ioc) AS (VALUES {values_sql}), \
             ev AS ( \
               SELECT case_id, event_id, artifact_type, event_time_utc, \
                 COALESCE(hash, '') AS hash_v, \
                 COALESCE(ip, '') AS ip_v, \
                 COALESCE(process_name, '') AS process_v, \
                 {haystack_sql} AS hay \
               FROM {expr} \
             ), \
             hits AS ( \
               SELECT i.ioc, e.case_id, e.event_id, e.artifact_type, e.event_time_utc, \
                 lower(e.hash_v) = lower(i.ioc) AS is_hash, \
                 lower(e.ip_v) = lower(i.ioc) AS is_ip, \
                 lower(e.process_v) = lower(i.ioc) AS is_process \
               FROM ind i \
               JOIN ev e ON lower(e.hash_v) = lower(i.ioc) \
                 OR lower(e.ip_v) = lower(i.ioc) \
                 OR lower(e.process_v) = lower(i.ioc) \
                 OR instr(e.hay, lower(i.ioc)) > 0 \
             ) \
             SELECT MAX(case_id), ioc, \
               CASE \
                 WHEN SUM(CASE WHEN is_hash THEN 1 ELSE 0 END) > 0 THEN 'hash' \
                 WHEN SUM(CASE WHEN is_ip THEN 1 ELSE 0 END) > 0 THEN 'ip' \
                 WHEN SUM(CASE WHEN is_process THEN 1 ELSE 0 END) > 0 THEN 'process' \
                 ELSE 'text' \
               END, \
               COUNT(*), STRING_AGG(DISTINCT artifact_type, ', '), \
               to_json(list(event_id ORDER BY event_time_utc ASC, event_id ASC)[1:500]), \
               MIN(event_time_utc), MAX(event_time_utc) \
             FROM hits \
             GROUP BY ioc \
             ORDER BY COUNT(*) DESC, MAX(event_time_utc) DESC, ioc ASC LIMIT {limit}"
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(IocHit {
                case_id: row.get(0)?,
                ioc: row.get(1)?,
                match_kind: row.get(2)?,
                hit_count: row.get(3)?,
                artifact_types: row.get(4)?,
                event_ids_json: row.get(5)?,
                first_seen_utc: row.get(6)?,
                last_seen_utc: row.get(7)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("ioc_match", &out, started);
        Ok(out)
    }

    pub fn ioc_event_page(&self, query: IocEventPageQuery) -> Result<Page<EventRow>> {
        let ioc = query.ioc.trim();
        if ioc.is_empty() {
            return Ok(Page::empty());
        }
        let has_search_text = self.table_has_column("read_models/event_rows", "search_text")?;
        self.event_page_with_clauses(
            query.page,
            vec![ioc_event_clause(ioc, has_search_text)],
            "ioc_event_page",
        )
    }

    pub fn defender_summary(&self, limit: Option<usize>) -> Result<Vec<DefenderSummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 100, 1_000);
        let rank_sql = "MAX(CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END)";
        let sql = format!(
            "SELECT MAX(case_id), event_action, {severity}, COUNT(*), \
             STRING_AGG(DISTINCT artifact_type, ', '), MIN(event_time_utc), MAX(event_time_utc), \
             any_value(message_short) \
             FROM {expr} WHERE {where_sql} \
             GROUP BY event_action \
             ORDER BY {rank_sql} DESC, COUNT(*) DESC, MAX(event_time_utc) DESC LIMIT {limit}",
            severity = severity_max_sql("severity"),
            where_sql = defender_event_clause(),
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(DefenderSummary {
                case_id: row.get(0)?,
                category: row.get(1)?,
                severity_max: row.get(2)?,
                event_count: row.get(3)?,
                artifact_types: row.get(4)?,
                first_seen_utc: row.get(5)?,
                last_seen_utc: row.get(6)?,
                sample_message: row.get(7)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("defender_summary", &out, started);
        Ok(out)
    }

    pub fn defender_event_page(&self, query: DefenderEventPageQuery) -> Result<Page<EventRow>> {
        let mut clauses = vec![defender_event_clause()];
        if let Some(category) = query
            .category
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            clauses.push(format!("event_action = {}", sql_literal(category)));
        }
        self.event_page_with_clauses(query.page, clauses, "defender_event_page")
    }

    pub fn prefetch_summary(&self, limit: Option<usize>) -> Result<Vec<PrefetchSummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 100, 1_000);
        let rank_sql = "MAX(CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END)";
        let sql = format!(
            r#"WITH pref AS (
                 SELECT case_id,
                   COALESCE(
                     NULLIF(process_name, ''),
                     NULLIF(regexp_replace(COALESCE(file_path, ''), '^.*[\\/]', ''), ''),
                     'unknown'
                   ) AS process_name,
                   file_path,
                   event_time_utc,
                   severity,
                   event_action,
                   source_file_id,
                   message_short,
                   NULLIF(regexp_extract(attributes_json, '"run_count":"?([0-9]+)"?', 1), '') AS run_count_text,
                   NULLIF(regexp_extract(attributes_json, '"referenced_file_count":([0-9]+)', 1), '') AS ref_count_text,
                   NULLIF(regexp_extract(attributes_json, '"prefetch_hash":"([^"]+)"', 1), '') AS prefetch_hash,
                   NULLIF(regexp_extract(attributes_json, '"prefetch_file_name":"([^"]+)"', 1), '') AS prefetch_file_name,
                   NULLIF(regexp_extract(attributes_json, '"suspicion":"([^"]+)"', 1), '') AS suspicion
                 FROM {expr}
                 WHERE artifact_type = 'prefetch'
               )
               SELECT MAX(case_id), process_name, any_value(file_path), any_value(prefetch_file_name),
                 any_value(prefetch_hash), MAX(try_cast(run_count_text AS BIGINT)),
                 MAX(try_cast(ref_count_text AS BIGINT)), COUNT(DISTINCT source_file_id),
                 COUNT(*), MIN(event_time_utc), MAX(event_time_utc), {severity},
                 STRING_AGG(DISTINCT event_action, ', '), any_value(suspicion), any_value(message_short)
               FROM pref
               GROUP BY process_name
               ORDER BY {rank_sql} DESC, MAX(try_cast(run_count_text AS BIGINT)) DESC NULLS LAST,
                 MAX(event_time_utc) DESC, COUNT(*) DESC
               LIMIT {limit}"#,
            severity = severity_max_sql("severity"),
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(PrefetchSummary {
                case_id: row.get(0)?,
                process_name: row.get(1)?,
                file_path: row.get(2)?,
                prefetch_file_name: row.get(3)?,
                prefetch_hash: row.get(4)?,
                run_count_max: row.get(5)?,
                referenced_file_count_max: row.get(6)?,
                source_file_count: row.get(7)?,
                event_count: row.get(8)?,
                first_seen_utc: row.get(9)?,
                last_seen_utc: row.get(10)?,
                severity_max: row.get(11)?,
                actions: row.get(12)?,
                suspicion: row.get(13)?,
                sample_message: row.get(14)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("prefetch_summary", &out, started);
        Ok(out)
    }

    pub fn event_page_by_event_ids(
        &self,
        event_ids: &[String],
        query: EventPageQuery,
        log_name: &str,
    ) -> Result<Page<EventRow>> {
        let mut seen = HashSet::new();
        let mut bounded = Vec::new();
        for event_id in event_ids.iter().filter(|value| !value.trim().is_empty()) {
            if seen.insert(event_id.clone()) {
                bounded.push(event_id.clone());
            }
            if bounded.len() >= 5000 {
                break;
            }
        }
        if bounded.is_empty() {
            return Ok(Page::empty());
        }
        let extra = vec![format!("event_id IN ({})", sql_list(bounded.iter()))];
        self.event_page_with_clauses(query, extra, log_name)
    }

    fn event_page_with_clauses(
        &self,
        query: EventPageQuery,
        mut clauses: Vec<String>,
        log_name: &str,
    ) -> Result<Page<EventRow>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Page::empty());
        };
        let limit = bounded_limit(query.limit, 100, 500);
        let sort = EventSort::from_query(&query);
        let has_search_text = self.table_has_column("read_models/event_rows", "search_text")?;
        clauses.extend(event_filter_clauses(&query, has_search_text));
        if let Some(cursor) = query.cursor.as_deref().filter(|s| !s.is_empty()) {
            let (sort_value, id) = decode_cursor(cursor)?;
            let sort_literal = sort.sql_literal(&sort_value);
            let op = if sort.dir == SortDir::Asc { ">" } else { "<" };
            clauses.push(format!(
                "(({expr}) {op} {value} OR (({expr}) = {value} AND event_id > {id}))",
                expr = sort.expr(),
                value = sort_literal,
                id = sql_literal(&id)
            ));
        }
        let sort_direction = sort.dir.as_sql();
        let sort_expr = sort.expr();
        let where_sql = if clauses.is_empty() {
            "1=1".to_string()
        } else {
            clauses.join(" AND ")
        };
        let cmd_col = self.event_rows_command_col()?;
        let sql = format!(
            "SELECT event_id, case_id, event_time_utc, artifact_type, host, user_name, \
             process_name, file_path, ip, url, hash, event_code, channel, level, \
             event_action, severity, message_short, source_file_id, parser_name, has_finding, {cmd_col} \
             FROM {expr} WHERE {where_sql} ORDER BY {sort_expr} {sort_direction}, event_id ASC LIMIT {}",
            limit + 1
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event_row)?;
        let mut rows = collect_rows(rows)?;
        let next_cursor = if rows.len() > limit {
            rows.truncate(limit);
            rows.last()
                .map(|row| encode_cursor(&sort.value(row), &row.event_id))
        } else {
            None
        };
        let page = Page { rows, next_cursor };
        log_payload(log_name, &page, started);
        Ok(page)
    }

    fn context_group(
        &self,
        label: String,
        relation: String,
        value: String,
        clauses: Vec<String>,
        limit: usize,
    ) -> Result<Option<EventContextGroup>> {
        let rows = self.event_rows_for_context(clauses, limit)?;
        if rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(EventContextGroup {
            label,
            relation,
            value,
            rows,
        }))
    }

    fn event_rows_for_context(&self, clauses: Vec<String>, limit: usize) -> Result<Vec<EventRow>> {
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let where_sql = if clauses.is_empty() {
            "1=1".to_string()
        } else {
            clauses.join(" AND ")
        };
        let cmd_col = self.event_rows_command_col()?;
        let sql = format!(
            "SELECT event_id, case_id, event_time_utc, artifact_type, host, user_name, \
             process_name, file_path, ip, url, hash, event_code, channel, level, \
             event_action, severity, message_short, source_file_id, parser_name, has_finding, {cmd_col} \
             FROM {expr} WHERE {where_sql} ORDER BY event_time_utc ASC, event_id ASC LIMIT {limit}"
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event_row)?;
        collect_rows(rows)
    }

    pub fn correlation_summary(&self, limit: Option<usize>) -> Result<Vec<CorrelationSummary>> {
        let started = Instant::now();
        let limit = bounded_limit(limit, 100, 1_000);
        if let Some(expr) = self.table_expr("read_models/correlation_chains")? {
            let conn = Connection::open_in_memory()?;
            let noise_clause = correlation_file_key_noise_clause();
            let sql = format!(
                "SELECT case_id, key_kind, key_value, \
                 NULL AS user_name, NULL AS host, \
                 CASE WHEN key_kind = 'ip' THEN key_value ELSE NULL END AS ip, \
                 CASE WHEN key_kind = 'file_basename' THEN key_value ELSE NULL END AS file_path, \
                 artifact_types, event_count, first_seen_utc, last_seen_utc, severity_max, \
                 explanation FROM {expr} \
                 WHERE {noise_clause} \
                 ORDER BY score DESC, event_count DESC, last_seen_utc DESC LIMIT {limit}"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |row| {
                Ok(CorrelationSummary {
                    case_id: row.get(0)?,
                    key_kind: row.get(1)?,
                    key_value: row.get(2)?,
                    user_name: row.get(3)?,
                    host: row.get(4)?,
                    ip: row.get(5)?,
                    file_path: row.get(6)?,
                    artifact_types: row.get(7)?,
                    event_count: row.get(8)?,
                    first_seen_utc: row.get(9)?,
                    last_seen_utc: row.get(10)?,
                    severity_max: row.get(11)?,
                    explanation: row.get(12)?,
                })
            })?;
            let out = collect_rows(rows)?;
            log_payload("correlation_summary", &out, started);
            return Ok(out);
        }
        if !hot_correlation_lake_fallback_allowed() {
            log_payload(
                "correlation_summary_skipped_missing_read_model",
                &0,
                started,
            );
            return Ok(Vec::new());
        }
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(Vec::new());
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "WITH normal_source AS ( \
               SELECT case_id, artifact_type, event_time_utc, severity, user_name, host, ip, \
                 file_path, process_name, hash, event_action \
               FROM {expr} \
               WHERE artifact_type NOT IN ('mft', 'usn_jrnl') \
                 OR ({high_cardinality_clause}) \
             ), base AS ( \
               SELECT case_id, artifact_type, event_time_utc, severity, user_name, host, ip, \
                 file_path, process_name, hash, event_action, \
                 CASE \
                   WHEN COALESCE(file_path, process_name) IS NOT NULL \
                     AND COALESCE(file_path, process_name) <> '' THEN 'file_basename' \
                   WHEN hash IS NOT NULL AND hash <> '' THEN 'hash' \
                   WHEN ip IS NOT NULL AND ip <> '' AND ip <> '-' THEN 'ip' \
                   WHEN user_name IS NOT NULL AND user_name <> '' AND user_name <> '-' THEN 'user_name' \
                   WHEN host IS NOT NULL AND host <> '' AND host <> '-' THEN 'host' \
                   ELSE NULL \
                 END AS key_kind, \
                 CASE \
                   WHEN COALESCE(file_path, process_name) IS NOT NULL \
                     AND COALESCE(file_path, process_name) <> '' \
                     THEN lower(regexp_replace(COALESCE(file_path, process_name), '^.*[\\\\/]', '')) \
                   WHEN hash IS NOT NULL AND hash <> '' THEN lower(hash) \
                   WHEN ip IS NOT NULL AND ip <> '' AND ip <> '-' THEN ip \
                   WHEN user_name IS NOT NULL AND user_name <> '' AND user_name <> '-' THEN lower(user_name) \
                   WHEN host IS NOT NULL AND host <> '' AND host <> '-' THEN lower(host) \
                   ELSE NULL \
                 END AS key_value \
               FROM normal_source \
             ) \
             SELECT case_id, key_kind, key_value, MAX(user_name), MAX(host), MAX(ip), \
               MAX(COALESCE(file_path, process_name)), STRING_AGG(DISTINCT artifact_type, ', '), \
               COUNT(*), MIN(event_time_utc), MAX(event_time_utc), {severity}, \
               CASE WHEN key_kind = 'file_basename' AND COUNT(DISTINCT artifact_type) > 1 \
                 THEN '複数アーティファクトで同一ファイル名/実行名を確認' \
                 WHEN COUNT(DISTINCT artifact_type) > 1 \
                 THEN '複数アーティファクトで同一キーを確認' \
                 ELSE '同一キーで複数イベントを確認' \
               END \
             FROM base \
             WHERE key_kind IS NOT NULL AND key_value IS NOT NULL \
               AND {noise_clause} \
             GROUP BY case_id, key_kind, key_value \
             HAVING COUNT(*) > 1 OR COUNT(DISTINCT artifact_type) > 1 \
             ORDER BY COUNT(DISTINCT artifact_type) DESC, COUNT(*) DESC, MAX(event_time_utc) DESC \
            LIMIT {limit}",
            severity = severity_max_sql("severity"),
            noise_clause = correlation_file_key_noise_clause(),
            high_cardinality_clause = high_cardinality_correlation_file_clause()
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(CorrelationSummary {
                case_id: row.get(0)?,
                key_kind: row.get(1)?,
                key_value: row.get(2)?,
                user_name: row.get(3)?,
                host: row.get(4)?,
                ip: row.get(5)?,
                file_path: row.get(6)?,
                artifact_types: row.get(7)?,
                event_count: row.get(8)?,
                first_seen_utc: row.get(9)?,
                last_seen_utc: row.get(10)?,
                severity_max: row.get(11)?,
                explanation: row.get(12)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("correlation_summary", &out, started);
        Ok(out)
    }

    pub fn correlation_chains(&self, limit: Option<usize>) -> Result<Vec<CorrelationChainSummary>> {
        let started = Instant::now();
        if let Some(expr) = self.table_expr("read_models/correlation_chains")? {
            let limit = bounded_limit(limit, 100, 500);
            let conn = Connection::open_in_memory()?;
            let noise_clause = correlation_file_key_noise_clause();
            let sql = format!(
                "SELECT case_id, key_kind, key_value, title, severity, artifact_types, \
                 event_count, step_count, first_seen_utc, last_seen_utc, severity_max, \
                 score, explanation, steps_json FROM {expr} \
                 WHERE {noise_clause} \
                 ORDER BY score DESC, event_count DESC, last_seen_utc DESC LIMIT {limit}"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], row_to_correlation_chain)?;
            let out = collect_rows(rows)?;
            log_payload("correlation_chains", &out, started);
            return Ok(out);
        }
        if !hot_correlation_lake_fallback_allowed() {
            log_payload("correlation_chains_skipped_missing_read_model", &0, started);
            return Ok(Vec::new());
        }
        self.correlation_chains_from_lake(limit, "correlation_chains")
    }

    pub fn answer_candidates(
        &self,
        question_key: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<AnswerCandidate>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/answer_candidates")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 100, 1_000);
        let where_clause = question_key
            .filter(|value| !value.trim().is_empty())
            .map(|value| format!("WHERE question_key = {}", sql_literal(value.trim())))
            .unwrap_or_default();
        let sql = format!(
            "SELECT candidate_id, case_id, question_key, question_label, candidate_value, \
             confidence, status, severity, category, reason, evidence_event_ids_json, \
             evidence_refs_json, missing_steps_json, next_action, first_seen_utc, \
             last_seen_utc, attributes_json FROM {expr} {where_clause} \
             ORDER BY confidence DESC, \
               CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 \
                 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC, \
               question_key ASC, candidate_value ASC LIMIT {limit}"
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_answer_candidate)?;
        let out = collect_rows(rows)?;
        log_payload("answer_candidates", &out, started);
        Ok(out)
    }

    pub fn answer_candidate_count(&self) -> Result<usize> {
        Ok(self.count_table("read_models/answer_candidates", "1=1")? as usize)
    }

    pub fn rebuild_correlation_chains(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<CorrelationChainSummary>> {
        self.correlation_chains_from_lake(limit, "rebuild_correlation_chains")
    }

    pub fn analyzer_events_full(&self) -> Result<Vec<EventFull>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(Vec::new());
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT event_id, case_id, event_time_utc, event_time_original, time_kind, \
             time_confidence, source_confidence, artifact_type, source_file_id, parse_run_id, \
             parser_name, parser_version, schema_version, evidence_ref, host, user_name, \
             process_name, file_path, ip, url, hash, event_action, severity, message_short, \
             message_full, raw_record_ref, attributes_json \
             FROM {expr} ORDER BY event_time_utc ASC, event_id ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event_full)?;
        let out = collect_rows(rows)?;
        log_payload("analyzer_events_full", &out.len(), started);
        Ok(out)
    }

    pub fn analyzer_events_full_batch(
        &self,
        after: Option<(&str, &str)>,
        limit: usize,
    ) -> Result<Vec<EventFull>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(Vec::new());
        };
        let limit = limit.clamp(1, 100_000);
        let where_clause = after
            .map(|(event_time_utc, event_id)| {
                format!(
                    "WHERE (event_time_utc > {} OR (event_time_utc = {} AND event_id > {}))",
                    sql_literal(event_time_utc),
                    sql_literal(event_time_utc),
                    sql_literal(event_id)
                )
            })
            .unwrap_or_default();
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT event_id, case_id, event_time_utc, event_time_original, time_kind, \
             time_confidence, source_confidence, artifact_type, source_file_id, parse_run_id, \
             parser_name, parser_version, schema_version, evidence_ref, host, user_name, \
             process_name, file_path, ip, url, hash, event_action, severity, message_short, \
             message_full, raw_record_ref, attributes_json \
             FROM {expr} {where_clause} \
             ORDER BY event_time_utc ASC, event_id ASC LIMIT {limit}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event_full)?;
        let out = collect_rows(rows)?;
        log_payload("analyzer_events_full_batch", &out.len(), started);
        Ok(out)
    }

    pub fn lake_event_count(&self) -> Result<usize> {
        Ok(self.count_table("lake/events_full", "1=1")? as usize)
    }

    pub fn rebuild_event_rows_from_lake(&self) -> Result<usize> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            let dir = self.root.join("read_models").join("event_rows");
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
            }
            fs::create_dir_all(&dir)?;
            return Ok(0);
        };
        let source_count = self.count_table("lake/events_full", "1=1")? as usize;
        let existing_count = self.count_table("read_models/event_rows", "1=1")? as usize;
        let finding_event_ids = self.finding_event_id_set()?;
        let has_search_text = self.table_has_column("read_models/event_rows", "search_text")?;
        let missing_search_text_count = if has_search_text {
            self.count_table(
                "read_models/event_rows",
                "search_text IS NULL OR search_text = ''",
            )? as usize
        } else {
            0
        };
        let version_path = self
            .root
            .join("read_models")
            .join("event_rows")
            .join("_projection_version");
        let version_ok = fs::read_to_string(&version_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|v| v == EVENT_ROWS_PROJECTION_VERSION)
            .unwrap_or(false);
        if source_count > 0
            && existing_count == source_count
            && finding_event_ids.is_empty()
            && has_search_text
            && missing_search_text_count == 0
            && version_ok
            && std::env::var("TAOTIE4_FORCE_EVENT_ROWS_REBUILD").as_deref() != Ok("1")
        {
            log_payload(
                "rebuild_event_rows_from_lake_reused",
                &existing_count,
                started,
            );
            return Ok(existing_count);
        }
        let dir = self.root.join("read_models").join("event_rows");
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        let out_path = dir.join("part-duckdb.parquet");
        let conn = Connection::open_in_memory()?;
        let has_finding_expr = if finding_event_ids.is_empty() {
            "false".to_string()
        } else {
            format!(
                "CASE WHEN event_id IN ({}) THEN true ELSE false END",
                sql_list(finding_event_ids.iter())
            )
        };
        let sql = format!(
            "COPY ( \
               SELECT \
                 event_id, case_id, event_time_utc, artifact_type, host, \
                 {user_name_expr} AS user_name, \
                 process_name, file_path, ip, url, hash, \
                 COALESCE( \
                   NULLIF(regexp_extract(attributes_json, '\"event_id\":\"([^\"]*)\"', 1), ''), \
                   NULLIF(regexp_extract(attributes_json, '\"EventID\":\"([^\"]*)\"', 1), ''), \
                   NULLIF(regexp_extract(attributes_json, '\"event_code\":\"([^\"]*)\"', 1), '') \
                 ) AS event_code, \
                 COALESCE( \
                   NULLIF(regexp_extract(attributes_json, '\"channel\":\"([^\"]*)\"', 1), ''), \
                   NULLIF(regexp_extract(attributes_json, '\"Channel\":\"([^\"]*)\"', 1), '') \
                 ) AS channel, \
                 COALESCE( \
                   NULLIF(regexp_extract(attributes_json, '\"level\":\"([^\"]*)\"', 1), ''), \
                   NULLIF(regexp_extract(attributes_json, '\"Level\":\"([^\"]*)\"', 1), ''), \
                   NULLIF(regexp_extract(attributes_json, '\"level_display_name\":\"([^\"]*)\"', 1), '') \
                 ) AS level, \
                 event_action, severity, {message_short_expr} AS message_short, \
                 source_file_id, parser_name, \
                 {has_finding_expr} AS has_finding, \
                 NULLIF(regexp_extract(attributes_json, '\"command_line\":\"([^\"]*)\"', 1), '') AS command_line, \
                 {search_text_expr} AS search_text \
               FROM {expr} \
               ORDER BY event_time_utc ASC, event_id ASC \
             ) TO {out_path} (FORMAT PARQUET, COMPRESSION ZSTD)",
            user_name_expr = sql_sanitize_account("user_name"),
            message_short_expr = sql_sanitize_account_in_message("message_short"),
            search_text_expr = event_row_search_text_sql(),
            out_path = sql_literal(&out_path.display().to_string())
        );
        conn.execute_batch(&sql)?;
        let _ = fs::write(&version_path, EVENT_ROWS_PROJECTION_VERSION.to_string());
        let count = self.count_table("read_models/event_rows", "1=1")? as usize;
        log_payload("rebuild_event_rows_from_lake", &count, started);
        Ok(count)
    }

    pub fn analyzer_events_for_answer_candidates(&self) -> Result<Vec<EventFull>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(Vec::new());
        };
        let event_row_expr = self.table_expr("read_models/event_rows")?;
        let using_event_rows = event_row_expr.is_some();
        let event_rows_have_search_text =
            self.table_has_column("read_models/event_rows", "search_text")?;
        let haystack = if event_row_expr.is_some() {
            event_row_haystack_sql(event_rows_have_search_text)
        } else {
            "lower(concat_ws(' ', artifact_type, event_action, severity, \
             message_short, message_full, COALESCE(host, ''), COALESCE(user_name, ''), \
             COALESCE(process_name, ''), COALESCE(file_path, ''), COALESCE(ip, ''), \
             COALESCE(url, ''), COALESCE(hash, ''), source_file_id, parser_name, attributes_json))"
                .to_string()
        };
        let terms: Vec<&str> = if event_row_expr.is_some() && !event_rows_have_search_text {
            vec![
                "systemhealthcheck",
                "whoami",
                "powerview.ps1",
                "keepass",
                "filezilla",
                ".bat",
                "batch",
                "move.aspx",
                "moveit.asp",
                "moveitsvc",
                "guestaccess.aspx",
                "api/v1/token",
                "nmap",
                "ruby",
                "0x17",
                "mssqlservice",
                "kerberoast",
                "asrep",
                "psexec",
                "psexesvc",
                "firewall",
                "audit_policy",
                "terminalservices",
                "remoteconnectionmanager",
                "1149",
                "logontype",
                "4724",
                "defender",
                "webshell",
                "instlogos",
                "wget ",
            ]
        } else {
            vec![
                "systemhealthcheck",
                ".hta",
                "mshta",
                "whoami",
                "remoteconnectionmanager",
                "logontype",
                "1149",
                "powerview.ps1",
                "keepass",
                ".kdbx",
                ".dmp",
                "minidump",
                "lsass",
                "filezilla",
                "zeek_",
                "network_http_request",
                "network_ftp_command",
                "network_file_transfer",
                "network_url_observed",
                "pcap_conversation_reconstructed",
                "archive_recovery_candidate",
                "archive_suspicious_member",
                "archive_member_observed",
                "deleted_file_recovered",
                "carved_file_recovered",
                "mft_ads_resident_content_observed",
                "mft_resident_data_observed",
                "cve-2023-38831",
                "document_sensitive_text_observed",
                "document text extracted",
                "document_recovery_candidate",
                "browser_encrypted_secret_candidate",
                "browser_secret_decrypted",
                "keepass_database_observed",
                "keepass_entry_decrypted",
                "dpapi_masterkey",
                ".bat",
                "batch",
                "move.aspx",
                "moveit.asp",
                "moveitsvc",
                "guestaccess.aspx",
                "api/v1/token",
                "nmap",
                "ruby",
                "0x17",
                "mssqlservice",
                "kerberoast",
                "kerberoast_candidate",
                "asrep_roast_candidate",
                "ticket_encryption",
                "psexec",
                "psexesvc",
                "psexec_named_pipe",
                "firewall_outbound",
                "firewall_block",
                "metasploit",
                "rulename",
                "rule added",
                "audit_policy",
                "audit policy",
                "other object access",
                "scheduled_task",
                "scheduled task",
                "task created",
                "eventid 4698",
                "\"event_id\":\"4698\"",
                "defender_threat_detected",
                "sharphound",
                "get-filehash",
                "hash=",
                "algorithm=md5",
                "getstreamhash",
                "terminalservices",
                "4724",
                "defender",
                "webshell",
                "instlogos",
                "consolehost_history",
                "psreadline",
                "wget ",
            ]
        };
        let pattern = terms
            .iter()
            .map(|term| escape_regex_literal(&term.to_ascii_lowercase()))
            .collect::<Vec<_>>()
            .join("|");
        let where_sql = format!("regexp_matches({haystack}, {})", sql_literal(&pattern));
        let priority_sql = answer_candidate_priority_sql(&haystack);
        let conn = Connection::open_in_memory()?;
        let sql = if let Some(event_row_expr) = event_row_expr {
            format!(
                "SELECT event_id, case_id, event_time_utc, event_time_utc AS event_time_original, \
                  'event_created' AS time_kind, 0.7::DOUBLE AS time_confidence, \
                  0.7::DOUBLE AS source_confidence, artifact_type, source_file_id, \
                  '' AS parse_run_id, parser_name, '' AS parser_version, '' AS schema_version, \
                  source_file_id AS evidence_ref, host, user_name, process_name, file_path, ip, url, hash, \
                  event_action, severity, message_short, message_short AS message_full, \
                  '' AS raw_record_ref, '{{}}' AS attributes_json \
                 FROM {event_row_expr} \
                 WHERE {where_sql} \
                 ORDER BY {priority_sql}, event_time_utc ASC, event_id ASC LIMIT 50000"
            )
        } else {
            format!(
                "SELECT event_id, case_id, event_time_utc, event_time_original, time_kind, \
                 time_confidence, source_confidence, artifact_type, source_file_id, parse_run_id, \
                 parser_name, parser_version, schema_version, evidence_ref, host, user_name, \
                 process_name, file_path, ip, url, hash, event_action, severity, message_short, \
                 message_full, raw_record_ref, attributes_json \
                 FROM {expr} WHERE {where_sql} \
                 ORDER BY {priority_sql}, event_time_utc ASC, event_id ASC LIMIT 100000"
            )
        };
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event_full)?;
        let mut out = collect_rows(rows)?;
        if using_event_rows {
            let extra = self.answer_candidate_extra_events_from_lake(&expr)?;
            let mut extra_by_id = extra
                .into_iter()
                .map(|event| (event.event_id.clone(), event))
                .collect::<HashMap<_, _>>();
            for event in &mut out {
                if let Some(full) = extra_by_id.remove(&event.event_id) {
                    *event = full;
                }
            }
            let mut seen = out
                .iter()
                .map(|event| event.event_id.clone())
                .collect::<HashSet<_>>();
            for event in extra_by_id.into_values() {
                if seen.insert(event.event_id.clone()) {
                    out.push(event);
                }
            }
        }
        log_payload("analyzer_events_for_answer_candidates", &out.len(), started);
        Ok(out)
    }

    fn answer_candidate_extra_events_from_lake(&self, expr: &str) -> Result<Vec<EventFull>> {
        let haystack = "lower(concat_ws(' ', artifact_type, event_action, severity, \
             message_short, message_full, COALESCE(host, ''), COALESCE(user_name, ''), \
             COALESCE(process_name, ''), COALESCE(file_path, ''), COALESCE(ip, ''), \
             COALESCE(url, ''), COALESCE(hash, ''), source_file_id, parser_name, attributes_json))";
        let priority_sql = answer_candidate_priority_sql(haystack);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT event_id, case_id, event_time_utc, event_time_original, time_kind, \
             time_confidence, source_confidence, artifact_type, source_file_id, parse_run_id, \
             parser_name, parser_version, schema_version, evidence_ref, host, user_name, \
             process_name, file_path, ip, url, hash, event_action, severity, message_short, \
             message_full, raw_record_ref, attributes_json \
             FROM {expr} \
             WHERE ({haystack} LIKE '%terminalservices%' \
                    OR {haystack} LIKE '%remoteconnectionmanager%' \
                    OR {haystack} LIKE '%logontype%' \
                    OR {haystack} LIKE '%1149%' \
                    OR {haystack} LIKE '%kerberoast_candidate%' \
                    OR {haystack} LIKE '%asrep_roast_candidate%' \
                    OR {haystack} LIKE '%ticket_encryption%' \
                    OR {haystack} LIKE '%0x17%' \
                    OR {haystack} LIKE '%mssqlservice%' \
                    OR {haystack} LIKE '%psexesvc%' \
                    OR {haystack} LIKE '%psexec_named_pipe%' \
                    OR {haystack} LIKE '%firewall_outbound%' \
                    OR {haystack} LIKE '%firewall_block%' \
                    OR {haystack} LIKE '%metasploit%' \
                    OR {haystack} LIKE '%rulename%' \
                    OR {haystack} LIKE '%rule added%' \
                    OR {haystack} LIKE '%audit_policy%' \
                    OR {haystack} LIKE '%audit policy%' \
                    OR {haystack} LIKE '%other object access%' \
                    OR {haystack} LIKE '%scheduled_task%' \
                    OR {haystack} LIKE '%scheduled task%' \
                    OR {haystack} LIKE '%task created%' \
                    OR {haystack} LIKE '%eventid 4698%' \
                    OR {haystack} LIKE '%\"event_id\":\"4698\"%' \
                    OR {haystack} LIKE '%defender_threat_detected%' \
                    OR {haystack} LIKE '%sharphound%' \
                    OR {haystack} LIKE '%get-filehash%' \
                    OR {haystack} LIKE '%hash=%' \
                    OR {haystack} LIKE '%algorithm=md5%' \
                    OR {haystack} LIKE '%getstreamhash%' \
                    OR {haystack} LIKE '%browser_secret_decrypted%' \
                    OR {haystack} LIKE '%keepass_entry_decrypted%' \
                    OR {haystack} LIKE '%deleted_file_recovered%' \
                    OR {haystack} LIKE '%carved_file_recovered%' \
                    OR {haystack} LIKE '%mft_ads_resident_content_observed%' \
                    OR {haystack} LIKE '%mft_resident_data_observed%' \
                    OR {haystack} LIKE '%pcap_conversation_reconstructed%') \
             ORDER BY {priority_sql}, event_time_utc ASC, event_id ASC LIMIT 50000"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event_full)?;
        collect_rows(rows)
    }

    pub fn analyzer_events_for_detection_candidates(&self) -> Result<Vec<EventFull>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(Vec::new());
        };
        let haystack = "lower(concat_ws(' ', artifact_type, event_action, severity, \
            message_short, message_full, COALESCE(host, ''), COALESCE(user_name, ''), \
            COALESCE(process_name, ''), COALESCE(file_path, ''), COALESCE(ip, ''), \
            COALESCE(url, ''), COALESCE(hash, ''), source_file_id, parser_name, attributes_json))";
        let terms = [
            "powershell",
            "pwsh",
            "cmd.exe",
            "wscript",
            "cscript",
            "rundll32",
            "regsvr32",
            "mshta",
            "certutil",
            "bitsadmin",
            "wevtutil",
            "schtasks",
            "sc.exe",
            " net ",
            "mimikatz",
            "procdump",
            "lsass",
            "comsvcs",
            "minidump",
            "ntds.dit",
            "ntdsutil",
            "secretsdump",
            "psexec",
            "psexesvc",
            "paexec",
            "remcom",
            "wmic",
            "wmiprvse",
            "vssadmin",
            "shadowcopy",
            "wbadmin",
            "bcdedit",
            "eventid 7045",
            "\"event_id\":\"7045\"",
            "eventid 4697",
            "\"event_id\":\"4697\"",
            "eventid 4624",
            "\"event_id\":\"4624\"",
            "logontype",
            "eventid 4724",
            "\"event_id\":\"4724\"",
            "eventid 4738",
            "\"event_id\":\"4738\"",
            "eventid 4768",
            "\"event_id\":\"4768\"",
            "eventid 4769",
            "\"event_id\":\"4769\"",
            "eventid 5136",
            "\"event_id\":\"5136\"",
            "eventid 1102",
            "\"event_id\":\"1102\"",
            "eventid 4720",
            "\"event_id\":\"4720\"",
            "eventid 4728",
            "\"event_id\":\"4728\"",
            "eventid 4732",
            "\"event_id\":\"4732\"",
            "eventid 4756",
            "\"event_id\":\"4756\"",
            "terminalservices",
            "remoteconnectionmanager",
            "defender",
            "quarantine",
            "webshell",
            "backdoor",
            "moveit",
            "move.aspx",
            "moveit.asp",
            "nmap",
            "ruby",
            "credential",
            "password",
            "dpapi",
            "keepass",
            "filezilla",
            "http://",
            "https://",
            "ftp://",
            ".ps1",
            ".bat",
            ".cmd",
            ".hta",
            ".vbs",
            ".js",
            ".jse",
            ".wsf",
            ".scr",
            "run key",
            "currentversion\\\\run",
            "amsi",
            "etw",
            "firewall",
            "bloodhound",
            "sharphound",
        ];
        let where_sql = terms
            .iter()
            .map(|term| {
                format!(
                    "{haystack} LIKE {} ESCAPE '\\'",
                    sql_literal(&format!("%{}%", escape_like(term)))
                )
            })
            .collect::<Vec<_>>()
            .join(" OR ");
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT event_id, case_id, event_time_utc, event_time_original, time_kind, \
             time_confidence, source_confidence, artifact_type, source_file_id, parse_run_id, \
             parser_name, parser_version, schema_version, evidence_ref, host, user_name, \
             process_name, file_path, ip, url, hash, event_action, severity, message_short, \
             message_full, raw_record_ref, attributes_json \
             FROM {expr} WHERE {where_sql} \
             ORDER BY event_time_utc ASC, event_id ASC LIMIT 300000"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event_full)?;
        let out = collect_rows(rows)?;
        log_payload(
            "analyzer_events_for_detection_candidates",
            &out.len(),
            started,
        );
        Ok(out)
    }

    pub fn rebuild_event_rows_with_findings(&self) -> Result<Vec<EventRow>> {
        let started = Instant::now();
        let finding_event_ids = self.finding_event_id_set()?;
        let mut rows = self
            .analyzer_events_full()?
            .into_iter()
            .map(|event| {
                let mut row = event.to_event_row();
                row.has_finding = finding_event_ids.contains(&row.event_id);
                row
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.event_time_utc
                .cmp(&right.event_time_utc)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        log_payload("rebuild_event_rows_with_findings", &rows.len(), started);
        Ok(rows)
    }

    fn finding_event_id_set(&self) -> Result<HashSet<String>> {
        let Some(expr) = self.table_expr("lake/findings")? else {
            return Ok(HashSet::new());
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!("SELECT event_ids_json FROM {expr}");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = HashSet::new();
        for row in rows {
            for event_id in parse_json_strings(&row?) {
                out.insert(event_id);
            }
        }
        Ok(out)
    }

    fn correlation_chains_from_lake(
        &self,
        limit: Option<usize>,
        log_name: &str,
    ) -> Result<Vec<CorrelationChainSummary>> {
        let started = Instant::now();
        let event_expr = self.table_expr("lake/events_full")?;
        let limit = bounded_limit(limit, 100, 500);
        let mut out = Vec::new();
        if let Some(expr) = event_expr {
            let conn = Connection::open_in_memory()?;
            let noise_clause = correlation_file_key_noise_clause();
            let sql = format!(
            "WITH normal_source AS ( \
               SELECT case_id, event_id, artifact_type, event_time_utc, event_action, severity, \
                 file_path, process_name, ip, url, hash, user_name \
               FROM {expr} \
               WHERE artifact_type NOT IN ('mft', 'usn_jrnl') \
                 OR ({high_cardinality_clause}) \
             ), keyed AS ( \
               SELECT case_id, event_id, artifact_type, event_time_utc, event_action, severity, \
                 CASE \
                   WHEN COALESCE(file_path, process_name) IS NOT NULL AND COALESCE(file_path, process_name) <> '' \
                     THEN 'file_basename' \
                   WHEN ip IS NOT NULL AND ip <> '' AND ip <> '-' THEN 'ip' \
                   WHEN hash IS NOT NULL AND hash <> '' THEN 'hash' \
                   WHEN url IS NOT NULL AND url <> '' THEN 'url' \
                   WHEN user_name IS NOT NULL AND user_name <> '' AND user_name <> '-' THEN 'user_name' \
                   ELSE NULL \
                 END AS key_kind, \
                 CASE \
                   WHEN COALESCE(file_path, process_name) IS NOT NULL AND COALESCE(file_path, process_name) <> '' \
                     THEN lower(regexp_replace(COALESCE(file_path, process_name), '^.*[\\\\/]', '')) \
                   WHEN ip IS NOT NULL AND ip <> '' AND ip <> '-' THEN ip \
                   WHEN hash IS NOT NULL AND hash <> '' THEN lower(hash) \
                   WHEN url IS NOT NULL AND url <> '' THEN lower(url) \
                   WHEN user_name IS NOT NULL AND user_name <> '' AND user_name <> '-' THEN lower(user_name) \
                   ELSE NULL \
                 END AS key_value \
               FROM normal_source \
             ), grouped AS ( \
               SELECT case_id, key_kind, key_value, STRING_AGG(DISTINCT artifact_type, ', ') AS artifact_types, \
                 COUNT(*) AS event_count, COUNT(DISTINCT event_id) AS step_count, \
                 MIN(event_time_utc) AS first_seen_utc, MAX(event_time_utc) AS last_seen_utc, \
                 {severity} AS severity_max, COUNT(DISTINCT artifact_type) AS artifact_count, \
                 MAX(CASE WHEN artifact_type IN ('prefetch', 'amcache', 'lnk', 'jump_list') \
                   OR lower(event_action) IN ('process_created', 'process_exited', 'prefetch_execution', \
                     'prefetch_last_run', 'prefetch_previous_run', 'amcache_program_seen', \
                     'scheduled_task_suspicious_exec', 'scheduled_task_action_started', \
                     'service_installed', 'registry_userassist_execution', 'registry_shimcache_execution') \
                   THEN 1 ELSE 0 END) AS has_execution, \
                 MAX(CASE WHEN artifact_type IN ('browser', 'web_cache', 'onedrive_log') \
                   OR lower(event_action) LIKE '%download%' THEN 1 ELSE 0 END) AS has_browser, \
                 MAX(CASE WHEN artifact_type = 'defender' OR lower(event_action) LIKE 'defender%' THEN 1 ELSE 0 END) AS has_defender, \
                 MAX(CASE WHEN artifact_type = 'scheduled_task' OR lower(event_action) LIKE 'scheduled_task%' THEN 1 ELSE 0 END) AS has_task, \
                 MAX(CASE WHEN artifact_type = 'registry_hive' OR lower(event_action) LIKE 'registry%' THEN 1 ELSE 0 END) AS has_registry, \
                 MAX(CASE WHEN lower(event_action) = 'service_installed' OR lower(event_action) = 'registry_service_image' THEN 1 ELSE 0 END) AS has_service, \
                 MAX(CASE WHEN artifact_type = 'mft' OR lower(event_action) LIKE 'mft_%' THEN 1 ELSE 0 END) AS has_mft, \
                 MAX(CASE WHEN artifact_type = 'usn_jrnl' OR lower(event_action) LIKE 'usn_%' THEN 1 ELSE 0 END) AS has_usn, \
                 MAX(CASE WHEN lower(event_action) LIKE '%delete%' OR lower(event_action) LIKE '%removed%' THEN 1 ELSE 0 END) AS has_deleted, \
                 to_json(list(struct_pack(ts := event_time_utc, artifact := artifact_type, \
                   action := event_action, event_id := event_id) ORDER BY event_time_utc, event_id)[1:50]) AS steps_json \
               FROM keyed \
               WHERE key_kind IS NOT NULL AND key_value IS NOT NULL AND key_value <> '' \
                 AND length(key_value) >= 3 \
                 AND {noise_clause} \
               GROUP BY case_id, key_kind, key_value \
               HAVING COUNT(*) >= 2 OR COUNT(DISTINCT artifact_type) >= 2 \
             ) \
             SELECT case_id, key_kind, key_value, \
               CASE \
                 WHEN key_kind = 'file_basename' AND has_defender = 1 AND has_execution = 1 \
                   THEN 'Defender 検知対象の実行痕跡' \
                 WHEN key_kind = 'file_basename' AND has_browser = 1 AND has_execution = 1 \
                   THEN 'ダウンロードされたファイルが実行された' \
                 WHEN key_kind = 'file_basename' AND has_registry = 1 AND has_execution = 1 \
                   THEN 'Registry 永続化対象の実行痕跡' \
                 WHEN key_kind = 'file_basename' AND has_task = 1 AND has_execution = 1 \
                   THEN 'Scheduled Task と実行痕跡の連結' \
                 WHEN key_kind = 'file_basename' AND has_execution = 1 AND (has_usn = 1 OR has_deleted = 1) \
                   THEN '実行後に削除/変更された痕跡' \
                 WHEN key_kind = 'file_basename' AND has_service = 1 AND has_execution = 1 \
                   THEN 'サービス登録と実行痕跡の連結' \
                 WHEN key_kind = 'file_basename' AND has_execution = 1 AND has_mft = 1 \
                   THEN '作成され実行されたファイル' \
                 WHEN key_kind = 'file_basename' AND artifact_count >= 2 \
                   THEN '複数アーティファクトに跨るファイル活動' \
                 WHEN key_kind = 'hash' THEN '同一ハッシュの横断出現' \
                 WHEN key_kind = 'url' THEN '同一URLの横断出現' \
                 WHEN key_kind = 'ip' THEN '同一IPの横断出現' \
                 WHEN key_kind = 'user_name' THEN '同一ユーザーの反復活動' \
                 ELSE '同一キーの反復活動チェーン' \
               END AS title, \
               CASE \
                 WHEN key_kind = 'file_basename' AND has_defender = 1 AND has_execution = 1 THEN 'critical' \
                 WHEN key_kind = 'file_basename' AND has_browser = 1 AND has_execution = 1 THEN 'critical' \
                 WHEN key_kind = 'file_basename' AND has_execution = 1 AND (has_usn = 1 OR has_deleted = 1) THEN 'critical' \
                 WHEN key_kind = 'file_basename' AND has_registry = 1 AND has_execution = 1 THEN 'high' \
                 WHEN key_kind = 'file_basename' AND has_task = 1 AND has_execution = 1 THEN 'high' \
                 WHEN key_kind = 'file_basename' AND has_service = 1 AND has_execution = 1 THEN 'high' \
                 WHEN artifact_count >= 3 THEN 'high' \
                 WHEN key_kind = 'file_basename' AND has_execution = 1 AND has_mft = 1 THEN 'medium' \
                 WHEN key_kind IN ('hash', 'url') AND artifact_count >= 2 THEN 'medium' \
                 ELSE 'low' \
               END AS severity, \
               artifact_types, event_count, step_count, \
               first_seen_utc, last_seen_utc, severity_max, \
               CAST((artifact_count * 30 + LEAST(event_count, 20) + has_execution * 10 \
                 + has_browser * 15 + has_defender * 35 + has_registry * 25 + has_task * 20 \
                 + has_service * 15 + has_usn * 20 + has_deleted * 20 + {severity_score}) AS BIGINT) AS score, \
               CASE \
                 WHEN key_kind = 'file_basename' AND has_defender = 1 AND has_execution = 1 \
                   THEN 'Defender 検知/隔離ログと実行痕跡が同一ファイル名で連結' \
                 WHEN key_kind = 'file_basename' AND has_browser = 1 AND has_execution = 1 \
                   THEN 'ダウンロード痕跡と実行痕跡が同一ファイル名で連結' \
                 WHEN key_kind = 'file_basename' AND has_registry = 1 AND has_execution = 1 \
                   THEN 'Registry 永続化/実行痕跡が同一ファイル名で連結' \
                 WHEN key_kind = 'file_basename' AND has_task = 1 AND has_execution = 1 \
                   THEN 'Scheduled Task と実行痕跡が同一ファイル名で連結' \
                 WHEN key_kind = 'file_basename' AND has_execution = 1 AND (has_usn = 1 OR has_deleted = 1) \
                   THEN '実行痕跡と削除/変更痕跡が同一ファイル名で連結' \
                 WHEN key_kind = 'file_basename' AND has_service = 1 AND has_execution = 1 \
                   THEN 'サービス登録/実行痕跡が同一ファイル名で連結' \
                 WHEN key_kind = 'file_basename' AND has_execution = 1 AND has_mft = 1 \
                   THEN 'ファイルシステム痕跡と実行痕跡が同一ファイル名で連結' \
                 WHEN artifact_count >= 2 THEN '複数アーティファクトにまたがる活動チェーン' \
                 ELSE '同一キーの反復活動チェーン' \
               END AS explanation, steps_json \
             FROM grouped \
             WHERE NOT (key_kind = 'file_basename' \
               AND has_defender = 0 AND has_execution = 0 \
               AND (key_value LIKE '%.dll' OR key_value LIKE '%.sys' \
                 OR key_value LIKE '%.dat' OR key_value LIKE '%.xml' \
                 OR key_value LIKE '%.log1' OR key_value LIKE '%.log2')) \
             ORDER BY score DESC, event_count DESC, last_seen_utc DESC LIMIT {limit}",
            severity = severity_max_sql("severity"),
            severity_score = severity_rank_sql("severity_max"),
            noise_clause = noise_clause,
            high_cardinality_clause = high_cardinality_correlation_file_clause()
        );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], row_to_correlation_chain)?;
            out.extend(collect_rows(rows)?);
        }
        out.extend(self.structure_object_correlation_chains(limit)?);
        normalize_correlation_chain_severity(&mut out);
        out.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.event_count.cmp(&left.event_count))
                .then_with(|| right.last_seen_utc.cmp(&left.last_seen_utc))
        });
        out.truncate(limit);
        log_payload(log_name, &out, started);
        Ok(out)
    }

    fn structure_object_correlation_chains(
        &self,
        limit: usize,
    ) -> Result<Vec<CorrelationChainSummary>> {
        let Some(expr) = self.table_expr("lake/artifact_objects")? else {
            return Ok(Vec::new());
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "WITH normalized AS ( \
               SELECT case_id, event_id, artifact_type, object_kind, lower(object_key) AS object_key, \
                 display_name, event_time_utc, confidence \
               FROM {expr} \
               WHERE object_key IS NOT NULL AND object_key <> '' AND length(object_key) >= 3 \
                 AND object_kind IN ( \
                   'ntfs_file_record', 'ntfs_attribute', 'ntfs_data_run', \
                   'prefetch_section', 'prefetch_run_count', 'prefetch_run_time', \
                   'prefetch_file_metric', 'prefetch_trace_chain', \
                   'lnk_property_value', 'ese_page_tag', 'ese_table_hint', \
                   'file_reference', 'process_reference', 'hash_reference', 'url_reference' \
                 ) \
                 AND NOT (object_kind = 'file_reference' AND lower(object_key) IN ( \
                   'file_reference:/', 'file_reference:c:\\program', \
                   'file_reference:c:\\programdata\\microsoft\\windows', \
                   'file_reference:c:\\windows\\explorer.exe', \
                   'file_reference:\\device\\harddiskvolume3\\program' \
                 )) \
                 AND NOT (object_kind = 'process_reference' AND lower(object_key) IN ( \
                   'process_reference:winlogon.exe', 'process_reference:explorer.exe', \
                   'process_reference:onedrive.exe', 'process_reference:onedrivesetup.exe', \
                   'process_reference:onedrivestandaloneupdater.exe', \
                   'process_reference:microsoft.sharepoint.exe', 'process_reference:filecoauth.exe', \
                   'process_reference:filecoauthlib64.dll', 'process_reference:explorerframe.dll', \
                   'process_reference:tiworker.exe', 'process_reference:mmres.dll', \
                   'process_reference:svchost.exe' \
                 )) \
             ), grouped AS ( \
               SELECT case_id, object_kind, object_key, STRING_AGG(DISTINCT artifact_type, ', ') AS artifact_types, \
                 COUNT(*) AS event_count, COUNT(DISTINCT event_id) AS step_count, \
                 COALESCE(MIN(event_time_utc), '') AS first_seen_utc, \
                 COALESCE(MAX(event_time_utc), '') AS last_seen_utc, \
                 COUNT(DISTINCT artifact_type) AS artifact_count, MAX(confidence) AS confidence_max, \
                 to_json(list(struct_pack(ts := event_time_utc, artifact := artifact_type, \
                   action := object_kind, event_id := event_id) ORDER BY event_time_utc, event_id)[1:50]) AS steps_json \
               FROM normalized \
               GROUP BY case_id, object_kind, object_key \
               HAVING COUNT(DISTINCT event_id) >= 2 OR COUNT(DISTINCT artifact_type) >= 2 \
             ) \
             SELECT case_id, 'artifact_object:' || object_kind AS key_kind, object_key AS key_value, \
               CASE \
                 WHEN object_kind = 'ntfs_data_run' THEN 'NTFS DATA runlist の横断一致' \
                 WHEN object_kind = 'ntfs_attribute' THEN 'NTFS 属性構造の横断一致' \
                 WHEN object_kind LIKE 'prefetch_%' THEN 'Prefetch 構造の横断一致' \
                 WHEN object_kind = 'lnk_property_value' THEN 'LNK PropertyStore の横断一致' \
                 WHEN object_kind IN ('ese_page_tag', 'ese_table_hint') THEN 'ESE 内部構造の横断一致' \
                 WHEN object_kind IN ('process_reference', 'file_reference') THEN '構造抽出された実体の横断一致' \
                 ELSE '構造オブジェクトの横断一致' \
               END AS title, \
               CASE \
                 WHEN object_kind IN ('ntfs_data_run', 'lnk_property_value') AND artifact_count >= 2 THEN 'high' \
                 WHEN object_kind IN ('ese_page_tag', 'ese_table_hint') AND artifact_count >= 2 THEN 'medium' \
                 WHEN confidence_max >= 0.85 THEN 'medium' \
                 ELSE 'low' \
               END AS severity, \
               artifact_types, event_count, step_count, first_seen_utc, last_seen_utc, \
               CASE \
                 WHEN confidence_max >= 0.85 THEN 'medium' \
                 WHEN confidence_max >= 0.65 THEN 'low' \
                 ELSE 'info' \
               END AS severity_max, \
               CAST((artifact_count * 35 + LEAST(event_count, 25) + LEAST(step_count, 25) * 5 \
                 + CASE WHEN object_kind IN ('ntfs_data_run', 'lnk_property_value') THEN 25 ELSE 0 END \
                 + CASE WHEN object_kind IN ('ese_page_tag', 'ese_table_hint') THEN 15 ELSE 0 END) AS BIGINT) AS score, \
               CASE \
                 WHEN object_kind = 'lnk_property_value' \
                   THEN 'LNK PropertyStore の同一キー/値候補が複数イベントまたは複数アーティファクトで一致' \
                 WHEN object_kind IN ('ese_page_tag', 'ese_table_hint') \
                   THEN 'ESE ページタグまたはテーブル名候補が複数イベントまたは複数アーティファクトで一致' \
                 WHEN object_kind LIKE 'prefetch_%' \
                   THEN 'Prefetch の版別構造/実行時刻/セクションが複数イベントで一致' \
                 ELSE 'artifact_objects の構造キーが複数イベントまたは複数アーティファクトで一致' \
               END AS explanation, steps_json \
             FROM grouped \
             ORDER BY score DESC, event_count DESC, last_seen_utc DESC LIMIT {limit}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_correlation_chain)?;
        collect_rows(rows)
    }

    pub fn correlation_chain_event_page(
        &self,
        query: CorrelationChainEventPageQuery,
    ) -> Result<Page<EventRow>> {
        let key_value = query.key_value.trim();
        if key_value.is_empty() {
            return Ok(Page::empty());
        }
        if let Some(object_kind) = query.key_kind.strip_prefix("artifact_object:") {
            let event_ids = self.artifact_object_chain_event_ids(object_kind, key_value, 1_000)?;
            if event_ids.is_empty() {
                return Ok(Page::empty());
            }
            let event_ids = event_ids.into_iter().collect::<HashSet<_>>();
            let clause = format!("event_id IN ({})", sql_in_list(&event_ids));
            return self.event_page_with_clauses(
                query.page,
                vec![clause],
                "correlation_chain_event_page",
            );
        }
        let Some(clause) = correlation_chain_key_clause(&query.key_kind, key_value) else {
            return Ok(Page::empty());
        };
        self.event_page_with_clauses(query.page, vec![clause], "correlation_chain_event_page")
    }

    fn artifact_object_chain_event_ids(
        &self,
        object_kind: &str,
        key_value: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        let Some(expr) = self.table_expr("lake/artifact_objects")? else {
            return Ok(Vec::new());
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT DISTINCT event_id FROM {expr} \
             WHERE object_kind = {} AND lower(object_key) = {} \
             ORDER BY event_id LIMIT {limit}",
            sql_literal(object_kind),
            sql_literal(&key_value.to_ascii_lowercase())
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        collect_rows(rows)
    }

    pub fn finding_summary(&self, limit: Option<usize>) -> Result<Vec<FindingSummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/findings")? else {
            return self.event_row_finding_summary(limit);
        };
        let limit = bounded_limit(limit, 100, 1_000);
        let has_enrich = self.table_has_column("lake/findings", "enrichment_json")?;
        let enrich_col = if has_enrich {
            "enrichment_json"
        } else {
            "'{}'"
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT case_id, title, severity, engine, rule_id, attack_json, event_ids_json, \
             first_seen_utc, message, {enrich_col}, entity_ids_json FROM {expr}"
        );
        let mut stmt = conn.prepare(&sql)?;
        #[derive(Default)]
        struct FindingSummaryBuild {
            attack_json: String,
            finding_count: i64,
            event_ids: HashSet<String>,
            entities: HashSet<String>,
            first_seen_utc: Option<String>,
            last_seen_utc: Option<String>,
            sample_message: Option<String>,
            enrichment_json: Option<String>,
        }

        type FindingSummaryKey = (String, String, String, String, Option<String>);
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })?;
        let mut groups: HashMap<FindingSummaryKey, FindingSummaryBuild> = HashMap::new();
        for row in rows {
            let (
                case_id,
                title,
                severity,
                engine,
                rule_id,
                attack_json,
                event_ids_json,
                first_seen_utc,
                message,
                enrichment_json,
                entity_ids_json,
            ) = row?;
            let entry = groups
                .entry((case_id, title, severity, engine, rule_id))
                .or_default();
            if entry.attack_json.is_empty() {
                entry.attack_json = attack_json;
            }
            if entry
                .enrichment_json
                .as_deref()
                .map_or(true, |current| current == "{}" || current.is_empty())
            {
                if let Some(enr) = enrichment_json.filter(|e| !e.is_empty() && e != "{}") {
                    entry.enrichment_json = Some(enr);
                }
            }
            entry.finding_count += 1;
            for event_id in parse_json_strings(&event_ids_json) {
                entry.event_ids.insert(event_id);
            }
            if let Some(entity_ids_json) = entity_ids_json {
                for entity in parse_json_strings(&entity_ids_json) {
                    if !entity.is_empty() {
                        entry.entities.insert(entity);
                    }
                }
            }
            if let Some(first_seen_utc) = first_seen_utc {
                if entry
                    .first_seen_utc
                    .as_deref()
                    .map_or(true, |current| first_seen_utc.as_str() < current)
                {
                    entry.first_seen_utc = Some(first_seen_utc.clone());
                }
                if entry
                    .last_seen_utc
                    .as_deref()
                    .map_or(true, |current| first_seen_utc.as_str() > current)
                {
                    entry.last_seen_utc = Some(first_seen_utc);
                }
            }
            if entry.sample_message.is_none() {
                entry.sample_message = message;
            }
        }

        let mut out = groups
            .into_iter()
            .map(
                |((case_id, title, severity, engine, rule_id), build)| FindingSummary {
                    case_id,
                    title,
                    severity,
                    engine,
                    rule_id,
                    attack_json: build.attack_json,
                    finding_count: build.finding_count,
                    event_count: build.event_ids.len() as i64,
                    first_seen_utc: build.first_seen_utc,
                    last_seen_utc: build.last_seen_utc,
                    sample_message: build.sample_message,
                    enrichment_json: build.enrichment_json,
                    affected_entities: {
                        let mut v: Vec<String> = build.entities.into_iter().collect();
                        v.sort();
                        v.truncate(24);
                        v
                    },
                },
            )
            .collect::<Vec<_>>();
        out.sort_by(|left, right| {
            severity_rank(&right.severity)
                .cmp(&severity_rank(&left.severity))
                .then_with(|| right.finding_count.cmp(&left.finding_count))
                .then_with(|| right.last_seen_utc.cmp(&left.last_seen_utc))
        });
        out.truncate(limit);
        log_payload("finding_summary", &out, started);
        if out.is_empty() {
            self.event_row_finding_summary(Some(limit))
        } else {
            Ok(out)
        }
    }

    fn event_row_finding_summary(&self, limit: Option<usize>) -> Result<Vec<FindingSummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("read_models/event_rows")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 100, 1_000);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT case_id, severity, artifact_type, event_action, COUNT(*) AS event_count, \
              MIN(event_time_utc) AS first_seen_utc, MAX(event_time_utc) AS last_seen_utc, \
              MIN(message_short) AS sample_message \
             FROM {expr} \
             WHERE {candidate_clause} \
             GROUP BY case_id, severity, artifact_type, event_action \
             ORDER BY {severity_rank} DESC, event_count DESC, last_seen_utc DESC, \
               artifact_type ASC, event_action ASC LIMIT {limit}",
            candidate_clause = event_row_finding_candidate_clause(),
            severity_rank = severity_rank_sql("severity"),
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            let case_id = row.get::<_, String>(0)?;
            let severity = row.get::<_, String>(1)?;
            let artifact_type = row.get::<_, String>(2)?;
            let event_action = row.get::<_, String>(3)?;
            let event_count = row.get::<_, i64>(4)?;
            let first_seen_utc = row.get::<_, Option<String>>(5)?;
            let last_seen_utc = row.get::<_, Option<String>>(6)?;
            let sample_message = row.get::<_, Option<String>>(7)?;
            Ok(FindingSummary {
                case_id,
                title: event_row_finding_title(&artifact_type, &event_action),
                severity: severity.clone(),
                engine: EVENT_ROW_FALLBACK_FINDING_ENGINE.to_string(),
                rule_id: Some(event_row_finding_rule_id(
                    &severity,
                    &artifact_type,
                    &event_action,
                )),
                attack_json: event_row_finding_attack_json(&artifact_type, &event_action),
                finding_count: 1,
                event_count,
                first_seen_utc,
                last_seen_utc,
                sample_message,
                enrichment_json: None,
                affected_entities: Vec::new(),
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("event_row_finding_summary", &out, started);
        Ok(out)
    }

    pub fn risk_summary(&self, limit: Option<usize>) -> Result<Vec<RiskSummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/findings")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 100, 1_000);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT case_id, severity, attack_json, event_ids_json, first_seen_utc FROM {expr}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;

        let mut by_technique: HashMap<String, RiskSummary> = HashMap::new();
        for row in rows {
            let (case_id, severity, attack_json, event_ids_json, first_seen_utc) = row?;
            let mut techniques = parse_json_strings(&attack_json);
            if techniques.is_empty() {
                techniques.push("未分類".to_string());
            }
            let event_count = parse_json_strings(&event_ids_json).len().max(1) as i64;
            for technique in techniques {
                let entry = by_technique
                    .entry(technique.clone())
                    .or_insert_with(|| RiskSummary {
                        case_id: case_id.clone(),
                        technique,
                        severity_max: None,
                        finding_count: 0,
                        event_count: 0,
                        first_seen_utc: None,
                        last_seen_utc: None,
                    });
                entry.finding_count += 1;
                entry.event_count += event_count;
                if severity_rank(&severity) > entry.severity_max.as_deref().map_or(0, severity_rank)
                {
                    entry.severity_max = Some(severity.clone());
                }
                if let Some(ts) = first_seen_utc.as_deref().filter(|s| !s.is_empty()) {
                    if entry.first_seen_utc.as_deref().map_or(true, |old| ts < old) {
                        entry.first_seen_utc = Some(ts.to_string());
                    }
                    if entry.last_seen_utc.as_deref().map_or(true, |old| ts > old) {
                        entry.last_seen_utc = Some(ts.to_string());
                    }
                }
            }
        }

        let mut out = by_technique.into_values().collect::<Vec<_>>();
        out.sort_by(|left, right| {
            right
                .severity_max
                .as_deref()
                .map_or(0, severity_rank)
                .cmp(&left.severity_max.as_deref().map_or(0, severity_rank))
                .then_with(|| right.finding_count.cmp(&left.finding_count))
                .then_with(|| left.technique.cmp(&right.technique))
        });
        out.truncate(limit);
        log_payload("risk_summary", &out, started);
        Ok(out)
    }

    pub fn analyzer_runs(&self, limit: Option<usize>) -> Result<Vec<AnalyzerRunSummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/analyzer_runs")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 100, 1_000);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT run_id, case_id, analyzer_id, name, version, status, started_at, \
             finished_at, input_count, output_count, error_message, metadata_json \
             FROM {expr} ORDER BY started_at DESC, run_id DESC LIMIT {limit}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(AnalyzerRunSummary {
                run_id: row.get(0)?,
                case_id: row.get(1)?,
                analyzer_id: row.get(2)?,
                name: row.get(3)?,
                version: row.get(4)?,
                status: row.get(5)?,
                started_at: row.get(6)?,
                finished_at: row.get(7)?,
                input_count: row.get(8)?,
                output_count: row.get(9)?,
                error_message: row.get(10)?,
                metadata_json: row.get(11)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("analyzer_runs", &out, started);
        Ok(out)
    }

    pub fn entity_summary(&self, limit: Option<usize>) -> Result<Vec<EntityRecord>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/entities")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 100, 500);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT entity_id, MAX(case_id), MAX(entity_type), MAX(canonical_value), \
             MAX(display_name), MAX(host), MIN(first_seen_utc), MAX(last_seen_utc), \
             SUM(event_count), MAX(attributes_json) \
             FROM {expr} GROUP BY entity_id \
             ORDER BY SUM(event_count) DESC, MAX(last_seen_utc) DESC, \
             MAX(entity_type) ASC, MAX(canonical_value) ASC LIMIT {limit}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_entity_record)?;
        let out = collect_rows(rows)?;
        log_payload("entity_summary", &out, started);
        Ok(out)
    }

    pub fn subgraph(
        &self,
        entity_id: &str,
        hops: Option<usize>,
        edge_limit: Option<usize>,
    ) -> Result<Subgraph> {
        let started = Instant::now();
        let Some(entity_expr) = self.table_expr("lake/entities")? else {
            return Ok(Subgraph {
                nodes: Vec::new(),
                edges: Vec::new(),
            });
        };
        let Some(edge_expr) = self.table_expr("lake/edges")? else {
            return Ok(Subgraph {
                nodes: self
                    .entities_by_id(&entity_expr, [entity_id.to_string()].into_iter().collect())?,
                edges: Vec::new(),
            });
        };
        let hops = hops.unwrap_or(1).clamp(1, 2);
        let edge_limit = bounded_limit(edge_limit, 200, 500);
        let conn = Connection::open_in_memory()?;
        let mut node_ids = HashSet::from([entity_id.to_string()]);
        let mut frontier = HashSet::from([entity_id.to_string()]);
        let mut edge_ids = HashSet::new();
        let mut edges = Vec::new();

        for _ in 0..hops {
            if frontier.is_empty() || edges.len() >= edge_limit {
                break;
            }
            let remaining = edge_limit - edges.len();
            let in_list = sql_in_list(&frontier);
            let sql = format!(
                "SELECT edge_id, MAX(case_id), MAX(src_entity_id), MAX(dst_entity_id), \
                 MAX(edge_type), MIN(first_seen_utc), MAX(last_seen_utc), MAX(confidence), \
                 MAX(evidence_event_ids_json), MAX(attributes_json) \
                 FROM {edge_expr} \
                 WHERE src_entity_id IN ({in_list}) OR dst_entity_id IN ({in_list}) \
                 GROUP BY edge_id ORDER BY MAX(last_seen_utc) DESC, edge_id ASC LIMIT {remaining}"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], row_to_edge_record)?;
            let mut next_frontier = HashSet::new();
            for row in rows {
                let edge = row?;
                if !edge_ids.insert(edge.edge_id.clone()) {
                    continue;
                }
                for candidate in [&edge.src_entity_id, &edge.dst_entity_id] {
                    if node_ids.insert(candidate.clone()) {
                        next_frontier.insert(candidate.clone());
                    }
                }
                edges.push(edge);
            }
            frontier = next_frontier;
        }

        let nodes = self.entities_by_id(&entity_expr, node_ids)?;
        let out = Subgraph { nodes, edges };
        log_payload("subgraph", &out, started);
        Ok(out)
    }

    fn entities_by_id(&self, entity_expr: &str, ids: HashSet<String>) -> Result<Vec<EntityRecord>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = Connection::open_in_memory()?;
        let in_list = sql_in_list(&ids);
        let sql = format!(
            "SELECT entity_id, MAX(case_id), MAX(entity_type), MAX(canonical_value), \
             MAX(display_name), MAX(host), MIN(first_seen_utc), MAX(last_seen_utc), \
             SUM(event_count), MAX(attributes_json) \
             FROM {entity_expr} WHERE entity_id IN ({in_list}) GROUP BY entity_id \
             ORDER BY MAX(entity_type) ASC, MAX(canonical_value) ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_entity_record)?;
        collect_rows(rows)
    }

    pub fn user_activity_summary(&self, limit: Option<usize>) -> Result<Vec<UserActivitySummary>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(Vec::new());
        };
        let limit = bounded_limit(limit, 100, 1_000);
        let conn = Connection::open_in_memory()?;
        let sql = format!(
            "SELECT case_id, user_name, COUNT(*), COUNT(DISTINCT host), \
             STRING_AGG(DISTINCT artifact_type, ', '), MIN(event_time_utc), MAX(event_time_utc), \
             {severity} \
             FROM {expr} \
             WHERE user_name IS NOT NULL AND user_name <> '' AND user_name <> '-' \
             GROUP BY case_id, user_name \
             ORDER BY COUNT(*) DESC, user_name ASC LIMIT {limit}",
            severity = severity_max_sql("severity")
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(UserActivitySummary {
                case_id: row.get(0)?,
                user_name: row.get(1)?,
                event_count: row.get(2)?,
                host_count: row.get(3)?,
                artifact_types: row.get(4)?,
                first_seen_utc: row.get(5)?,
                last_seen_utc: row.get(6)?,
                severity_max: row.get(7)?,
            })
        })?;
        let out = collect_rows(rows)?;
        log_payload("user_activity_summary", &out, started);
        Ok(out)
    }

    pub fn file_page(&self, query: FilePageQuery) -> Result<Page<FileRecord>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("inventory/files")? else {
            return Ok(Page::empty());
        };
        let limit = bounded_limit(query.limit, 100, 500);
        let mut clauses = Vec::new();
        if let Some(cursor) = query.cursor.as_deref().filter(|s| !s.is_empty()) {
            let (path, id) = decode_cursor(cursor)?;
            clauses.push(format!(
                "(normalized_path > {} OR (normalized_path = {} AND file_id > {}))",
                sql_literal(&path),
                sql_literal(&path),
                sql_literal(&id)
            ));
        }
        let where_sql = if clauses.is_empty() {
            "1=1".to_string()
        } else {
            clauses.join(" AND ")
        };
        let sql = format!(
            "SELECT file_id, case_id, parent_file_id, original_path, normalized_path, filename, \
             extension, size, sha256, artifact_type, parser_status, event_count, object_ref \
             FROM {expr} WHERE {where_sql} ORDER BY normalized_path ASC, file_id ASC LIMIT {}",
            limit + 1
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_file_record)?;
        let mut rows = collect_rows(rows)?;
        let next_cursor = if rows.len() > limit {
            rows.truncate(limit);
            rows.last()
                .map(|row| encode_cursor(&row.normalized_path, &row.file_id))
        } else {
            None
        };
        let page = Page { rows, next_cursor };
        log_payload("file_page", &page, started);
        Ok(page)
    }

    pub fn event_detail_light(&self, event_id: &str) -> Result<Option<EventDetailLight>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/events_full")? else {
            return Ok(None);
        };
        // Sanitize principal/message fields at read time so the lake-backed detail pane
        // shows clean values on EXISTING cases without re-ingest (the raw attributes_json
        // column is intentionally left untouched so the raw record stays faithful).
        let user_name_expr = sql_sanitize_account("user_name");
        let message_short_expr = sql_sanitize_account_in_message("message_short");
        let message_full_expr = sql_sanitize_account_in_message("message_full");
        let sql = format!(
            "SELECT event_id, case_id, event_time_utc, event_time_original, time_kind, \
             time_confidence, source_confidence, artifact_type, source_file_id, parse_run_id, \
             parser_name, parser_version, schema_version, evidence_ref, host, \
             {user_name_expr} AS user_name, \
             process_name, file_path, ip, url, hash, event_action, severity, \
             {message_short_expr} AS message_short, \
             {message_full_expr} AS message_full, raw_record_ref, attributes_json FROM {expr} \
             WHERE event_id = {} LIMIT 1",
            sql_literal(event_id)
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        let out = if let Some(row) = rows.next()? {
            Some(row_to_event_full(row)?.to_detail_light())
        } else {
            None
        };
        log_payload("event_detail_light", &out, started);
        Ok(out)
    }

    pub fn event_raw_record(&self, event_id: &str) -> Result<Option<RawRecord>> {
        let started = Instant::now();
        let Some(expr) = self.table_expr("lake/raw_records")? else {
            return Ok(None);
        };
        let sql = format!(
            "SELECT raw_record_ref, case_id, event_id, parse_run_id, source_file_id, \
             evidence_ref, raw_record_json FROM {expr} WHERE event_id = {} LIMIT 1",
            sql_literal(event_id)
        );
        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        let out = if let Some(row) = rows.next()? {
            Some(RawRecord {
                raw_record_ref: row.get(0)?,
                case_id: row.get(1)?,
                event_id: row.get(2)?,
                parse_run_id: row.get(3)?,
                source_file_id: row.get(4)?,
                evidence_ref: row.get(5)?,
                raw_record_json: row.get(6)?,
            })
        } else {
            None
        };
        log_payload("event_raw_record", &out, started);
        Ok(out)
    }

    pub fn event_artifact_objects(&self, event_id: &str) -> Result<Vec<ArtifactObject>> {
        let started = Instant::now();
        if let Some(expr) = self.table_expr("lake/artifact_objects")? {
            let sql = format!(
                "SELECT object_id, case_id, event_id, source_file_id, parse_run_id, artifact_type, \
                 object_kind, object_key, display_name, event_time_utc, evidence_ref, \
                 evidence_offset, evidence_length, confidence, attributes_json FROM {expr} \
                 WHERE event_id = {} ORDER BY confidence DESC, object_kind ASC LIMIT 100",
                sql_literal(event_id)
            );
            let conn = Connection::open_in_memory()?;
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], row_to_artifact_object)?;
            let out = collect_rows(rows)?;
            if !out.is_empty() {
                log_payload("event_artifact_objects", &out, started);
                return Ok(out);
            }
        }
        let out = self
            .event_detail_light(event_id)?
            .map(|detail| derive_artifact_objects_from_detail(&detail))
            .unwrap_or_default();
        log_payload("event_artifact_objects_fallback", &out, started);
        Ok(out)
    }

    pub fn event_evidence_offsets(&self, event_id: &str) -> Result<Vec<EvidenceOffset>> {
        let started = Instant::now();
        if let Some(expr) = self.table_expr("lake/evidence_offsets")? {
            let sql = format!(
                "SELECT offset_id, case_id, event_id, source_file_id, parse_run_id, object_ref, \
                 label, structure_kind, \"offset\", length, parser_name, confidence, attributes_json \
                 FROM {expr} WHERE event_id = {} ORDER BY \"offset\" ASC, structure_kind ASC LIMIT 50",
                sql_literal(event_id)
            );
            let conn = Connection::open_in_memory()?;
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], row_to_evidence_offset)?;
            let out = collect_rows(rows)?;
            if !out.is_empty() {
                log_payload("event_evidence_offsets", &out, started);
                return Ok(out);
            }
        }
        let out = self
            .event_detail_light(event_id)?
            .map(|detail| derive_evidence_offsets_from_detail(&detail))
            .unwrap_or_default();
        log_payload("event_evidence_offsets_fallback", &out, started);
        Ok(out)
    }

    fn count_table(&self, relative_dir: &str, where_sql: &str) -> Result<i64> {
        let Some(expr) = self.table_expr(relative_dir)? else {
            return Ok(0);
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!("SELECT COUNT(*) FROM {expr} WHERE {where_sql}");
        Ok(conn.query_row(&sql, [], |row| row.get(0))?)
    }

    fn table_has_column(&self, relative_dir: &str, column: &str) -> Result<bool> {
        let Some(expr) = self.table_expr(relative_dir)? else {
            return Ok(false);
        };
        let conn = Connection::open_in_memory()?;
        let sql = format!("DESCRIBE SELECT * FROM {expr}");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            if row?.eq_ignore_ascii_case(column) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// event_rows に command_line 列があればそのまま、無ければ `NULL AS command_line` を返す。
    /// 旧 projection(version<5)で作られた read model を壊さずに末尾列を足すためのガード。
    fn event_rows_command_col(&self) -> Result<&'static str> {
        Ok(
            if self.table_has_column("read_models/event_rows", "command_line")? {
                "command_line"
            } else {
                "NULL AS command_line"
            },
        )
    }

    fn table_expr(&self, relative_dir: &str) -> Result<Option<String>> {
        let dir = self.root.join(relative_dir);
        if !has_parquet_parts(&dir)? {
            return Ok(None);
        }
        let glob = dir.join("*.parquet");
        Ok(Some(format!(
            "read_parquet({}, union_by_name = true)",
            sql_literal(&glob.display().to_string())
        )))
    }
}

fn row_to_event_row(row: &Row<'_>) -> duckdb::Result<EventRow> {
    Ok(EventRow {
        event_id: row.get(0)?,
        case_id: row.get(1)?,
        event_time_utc: row.get(2)?,
        artifact_type: row.get(3)?,
        host: row.get(4)?,
        user_name: row.get(5)?,
        process_name: row.get(6)?,
        file_path: row.get(7)?,
        ip: row.get(8)?,
        url: row.get(9)?,
        hash: row.get(10)?,
        event_code: row.get(11)?,
        channel: row.get(12)?,
        level: row.get(13)?,
        event_action: row.get(14)?,
        severity: row.get(15)?,
        message_short: row.get(16)?,
        source_file_id: row.get(17)?,
        parser_name: row.get(18)?,
        has_finding: row.get(19)?,
        command_line: row.get(20)?,
    })
}

fn row_to_answer_candidate(row: &Row<'_>) -> duckdb::Result<AnswerCandidate> {
    Ok(AnswerCandidate {
        candidate_id: row.get(0)?,
        case_id: row.get(1)?,
        question_key: row.get(2)?,
        question_label: row.get(3)?,
        candidate_value: row.get(4)?,
        confidence: row.get(5)?,
        status: row.get(6)?,
        severity: row.get(7)?,
        category: row.get(8)?,
        reason: row.get(9)?,
        evidence_event_ids_json: row.get(10)?,
        evidence_refs_json: row.get(11)?,
        missing_steps_json: row.get(12)?,
        next_action: row.get(13)?,
        first_seen_utc: row.get(14)?,
        last_seen_utc: row.get(15)?,
        attributes_json: row.get(16)?,
    })
}

fn write_event_export(path: &Path, format: &str, rows: &[EventRow]) -> Result<()> {
    let file = fs::File::create(path)?;
    let mut writer = BufWriter::new(file);
    if format == "jsonl" {
        for row in rows {
            serde_json::to_writer(&mut writer, row)?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        return Ok(());
    }

    writeln!(
        writer,
        "event_time_utc,event_id,artifact_type,severity,event_action,host,user_name,process_name,file_path,ip,url,hash,event_code,channel,level,source_file_id,parser_name,has_finding,message_short"
    )?;
    for row in rows {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_cell(&row.event_time_utc),
            csv_cell(&row.event_id),
            csv_cell(&row.artifact_type),
            csv_cell(&row.severity),
            csv_cell(&row.event_action),
            csv_cell(row.host.as_deref().unwrap_or("")),
            csv_cell(row.user_name.as_deref().unwrap_or("")),
            csv_cell(row.process_name.as_deref().unwrap_or("")),
            csv_cell(row.file_path.as_deref().unwrap_or("")),
            csv_cell(row.ip.as_deref().unwrap_or("")),
            csv_cell(row.url.as_deref().unwrap_or("")),
            csv_cell(row.hash.as_deref().unwrap_or("")),
            csv_cell(row.event_code.as_deref().unwrap_or("")),
            csv_cell(row.channel.as_deref().unwrap_or("")),
            csv_cell(row.level.as_deref().unwrap_or("")),
            csv_cell(&row.source_file_id),
            csv_cell(&row.parser_name),
            csv_cell(if row.has_finding { "true" } else { "false" }),
            csv_cell(&row.message_short)
        )?;
    }
    writer.flush()?;
    Ok(())
}

fn csv_cell(value: &str) -> String {
    if value
        .chars()
        .any(|ch| matches!(ch, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn basename(value: &str) -> Option<String> {
    value
        .rsplit(|ch| ch == '\\' || ch == '/')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn row_to_event_full(row: &Row<'_>) -> duckdb::Result<EventFull> {
    Ok(EventFull {
        event_id: row.get(0)?,
        case_id: row.get(1)?,
        event_time_utc: row.get(2)?,
        event_time_original: row.get(3)?,
        time_kind: row.get(4)?,
        time_confidence: row.get(5)?,
        source_confidence: row.get(6)?,
        artifact_type: row.get(7)?,
        source_file_id: row.get(8)?,
        parse_run_id: row.get(9)?,
        parser_name: row.get(10)?,
        parser_version: row.get(11)?,
        schema_version: row.get(12)?,
        evidence_ref: row.get(13)?,
        host: row.get(14)?,
        user_name: row.get(15)?,
        process_name: row.get(16)?,
        file_path: row.get(17)?,
        ip: row.get(18)?,
        url: row.get(19)?,
        hash: row.get(20)?,
        event_action: row.get(21)?,
        severity: row.get(22)?,
        message_short: row.get(23)?,
        message_full: row.get(24)?,
        raw_record_ref: row.get(25)?,
        attributes_json: row.get(26)?,
    })
}

fn row_to_artifact_object(row: &Row<'_>) -> duckdb::Result<ArtifactObject> {
    Ok(ArtifactObject {
        object_id: row.get(0)?,
        case_id: row.get(1)?,
        event_id: row.get(2)?,
        source_file_id: row.get(3)?,
        parse_run_id: row.get(4)?,
        artifact_type: row.get(5)?,
        object_kind: row.get(6)?,
        object_key: row.get(7)?,
        display_name: row.get(8)?,
        event_time_utc: row.get(9)?,
        evidence_ref: row.get(10)?,
        evidence_offset: row.get(11)?,
        evidence_length: row.get(12)?,
        confidence: row.get(13)?,
        attributes_json: row.get(14)?,
    })
}

fn row_to_evidence_offset(row: &Row<'_>) -> duckdb::Result<EvidenceOffset> {
    Ok(EvidenceOffset {
        offset_id: row.get(0)?,
        case_id: row.get(1)?,
        event_id: row.get(2)?,
        source_file_id: row.get(3)?,
        parse_run_id: row.get(4)?,
        object_ref: row.get(5)?,
        label: row.get(6)?,
        structure_kind: row.get(7)?,
        offset: row.get(8)?,
        length: row.get(9)?,
        parser_name: row.get(10)?,
        confidence: row.get(11)?,
        attributes_json: row.get(12)?,
    })
}

fn row_to_entity_record(row: &Row<'_>) -> duckdb::Result<EntityRecord> {
    Ok(EntityRecord {
        entity_id: row.get(0)?,
        case_id: row.get(1)?,
        entity_type: row.get(2)?,
        canonical_value: row.get(3)?,
        display_name: row.get(4)?,
        host: row.get(5)?,
        first_seen_utc: row.get(6)?,
        last_seen_utc: row.get(7)?,
        event_count: row.get(8)?,
        attributes_json: row.get(9)?,
    })
}

fn row_to_edge_record(row: &Row<'_>) -> duckdb::Result<EdgeRecord> {
    Ok(EdgeRecord {
        edge_id: row.get(0)?,
        case_id: row.get(1)?,
        src_entity_id: row.get(2)?,
        dst_entity_id: row.get(3)?,
        edge_type: row.get(4)?,
        first_seen_utc: row.get(5)?,
        last_seen_utc: row.get(6)?,
        confidence: row.get(7)?,
        evidence_event_ids_json: row.get(8)?,
        attributes_json: row.get(9)?,
    })
}

fn row_to_file_record(row: &Row<'_>) -> duckdb::Result<FileRecord> {
    let status: String = row.get(10)?;
    Ok(FileRecord {
        file_id: row.get(0)?,
        case_id: row.get(1)?,
        parent_file_id: row.get(2)?,
        original_path: row.get(3)?,
        normalized_path: row.get(4)?,
        filename: row.get(5)?,
        extension: row.get(6)?,
        size: row.get(7)?,
        sha256: row.get(8)?,
        artifact_type: row.get(9)?,
        parser_status: match status.as_str() {
            "pending" => ParserStatus::Pending,
            "parsed" => ParserStatus::Parsed,
            "failed" => ParserStatus::Failed,
            "unsupported" => ParserStatus::Unsupported,
            _ => ParserStatus::Failed,
        },
        event_count: row.get(11)?,
        object_ref: row.get(12)?,
    })
}

fn row_to_correlation_chain(row: &Row<'_>) -> duckdb::Result<CorrelationChainSummary> {
    Ok(CorrelationChainSummary {
        case_id: row.get(0)?,
        key_kind: row.get(1)?,
        key_value: row.get(2)?,
        title: row.get(3)?,
        severity: row.get(4)?,
        artifact_types: row.get(5)?,
        event_count: row.get(6)?,
        step_count: row.get(7)?,
        first_seen_utc: row.get(8)?,
        last_seen_utc: row.get(9)?,
        severity_max: row.get(10)?,
        score: row.get(11)?,
        explanation: row.get(12)?,
        steps_json: row.get(13)?,
    })
}

fn collect_rows<T>(
    rows: duckdb::MappedRows<'_, impl FnMut(&Row<'_>) -> duckdb::Result<T>>,
) -> Result<Vec<T>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn has_parquet_parts(dir: &Path) -> Result<bool> {
    if !dir.exists() {
        return Ok(false);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry
            .path()
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == "parquet")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Reduce a process image path/command to a lowercase basename for tree grouping,
/// e.g. `C:\\Windows\\System32\\cmd.exe` -> `cmd.exe`. When the value is a command
/// line (parent falls back to ParentCommandLine), cut at the executable extension
/// so trailing arguments are dropped without breaking exe names that contain spaces.
fn process_basename(value: &str) -> String {
    let trimmed = value.trim().trim_matches('"').trim();
    let last = trimmed
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_ascii_lowercase();
    for ext in [".exe", ".com", ".bat", ".cmd", ".scr", ".dll", ".ps1"] {
        if let Some(pos) = last.find(ext) {
            return last[..pos + ext.len()].to_string();
        }
    }
    last
}

fn severity_max_sql(column: &str) -> String {
    format!(
        "CASE MAX(CASE {column} \
           WHEN 'critical' THEN 5 \
           WHEN 'high' THEN 4 \
           WHEN 'medium' THEN 3 \
           WHEN 'low' THEN 2 \
           WHEN 'info' THEN 1 \
           ELSE 0 END) \
         WHEN 5 THEN 'critical' \
         WHEN 4 THEN 'high' \
         WHEN 3 THEN 'medium' \
         WHEN 2 THEN 'low' \
         WHEN 1 THEN 'info' \
         ELSE NULL END"
    )
}

fn severity_rank_sql(column: &str) -> String {
    format!(
        "CASE {column} \
           WHEN 'critical' THEN 5 \
           WHEN 'high' THEN 4 \
           WHEN 'medium' THEN 3 \
           WHEN 'low' THEN 2 \
           WHEN 'info' THEN 1 \
           ELSE 0 END"
    )
}

fn correlation_file_key_noise_clause() -> String {
    format!(
        "NOT (key_kind = 'file_basename' AND ( \
           lower(COALESCE(key_value, '')) IN ({noise}) \
           OR (instr(lower(COALESCE(key_value, '')), '.') = 0 \
             AND lower(COALESCE(key_value, '')) NOT IN ({allowed_extensionless})) \
        ))",
        noise = noisy_file_basename_sql_list(),
        allowed_extensionless = allowed_extensionless_file_key_sql_list()
    )
}

fn high_cardinality_correlation_file_clause() -> &'static str {
    "lower(COALESCE(file_path, process_name, '')) LIKE '%.exe' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.dll' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.ps1' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.bat' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.cmd' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.scr' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.hta' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.js' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.jse' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.vbs' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.vbe' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.wsf' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.lnk' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.msi' \
     OR lower(COALESCE(file_path, process_name, '')) LIKE '%.jar'"
}

fn noisy_file_basename_sql_list() -> &'static str {
    "'desktop.ini', 'thumbs.db', 'iconcache.db', 'ntuser.dat', 'usrclass.dat', \
     'edb.log', 'edb.chk', 'setupapi.dev.log', 'security.evtx', 'system.evtx', \
     'application.evtx', 'windows', 'desktop', 'inetcache', 'downloads', 'favorites', \
     'documents', 'pictures', 'videos', 'music', 'recent', 'history', 'cookies', \
     'cache', 'temp', 'tmp', 'logs', 'program files', 'program files (x86)', \
     'programdata', 'users', 'public', 'appdata', 'local', 'locallow', 'roaming', \
     'microsoft', 'google', 'chrome', 'edge', 'mozilla', 'firefox', 'default', \
     'profile', 'profiles', 'system32', 'syswow64', 'winsxs', 'software', 'system', \
     'dismhost.exe', 'mighost.exe', 'setuphost.exe', 'setupdiag.exe', 'tiworker.exe', \
     'trustedinstaller.exe', 'wimserv.exe', 'wermgr.exe', 'werfault.exe', 'mrt.exe', \
     'gatherosstate.exe', 'onedrivesetup.exe', 'onedrivestandaloneupdater.exe', \
     'microsoftedgeupdate.exe', 'wmiadap.exe', 'conhost.exe', 'services.exe', \
     'explorer.exe', 'winlogon.exe', 'vds.exe', 'smss.exe', 'wininit.exe', \
     'taskmgr.exe', 'userinit.exe', 'csrss.exe', 'compattelrunner.exe', 'svchost.exe', \
     'wmiprvse.exe', 'am_engine.exe', 'microsoft.sharepoint.exe', 'onedrive.exe', \
     'diagerr.xml', 'opcservices.dll', 'clusapi.dll', 'storagewmi.dll', \
     'software.log1', 'software.log2', 'system.log1', 'system.log2', \
     'security.log1', 'security.log2', 'sam.log1', 'sam.log2', \
     'default.log1', 'default.log2', 'ntuser.dat.log1', 'ntuser.dat.log2', \
     'usrclass.dat.log1', 'usrclass.dat.log2', 'amcache.hve.log1', 'amcache.hve.log2'"
}

fn allowed_extensionless_file_key_sql_list() -> &'static str {
    "'powershell', 'pwsh', 'cmd', 'rundll32', 'regsvr32', 'mshta', 'wscript', \
     'cscript', 'wmic', 'certutil', 'bitsadmin', 'wevtutil', 'schtasks', 'sc', \
     'net', 'net1', 'curl', 'wget', 'python', 'perl', 'ruby', 'java', 'teamviewer', \
     'anydesk', 'screenconnect', 'merlin', 'sliver', 'beacon'"
}

fn normalize_correlation_chain_severity(chains: &mut [CorrelationChainSummary]) {
    for chain in chains {
        let artifacts = chain
            .artifact_types
            .split(',')
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<HashSet<_>>();
        let key_kind = chain.key_kind.to_ascii_lowercase();
        let key_value = chain.key_value.to_ascii_lowercase();
        let title = chain.title.to_ascii_lowercase();
        let steps = chain.steps_json.to_ascii_lowercase();
        if structure_chain_noise_key(&key_kind, &key_value) {
            continue;
        }

        let has_execution = has_any_artifact(
            &artifacts,
            &[
                "prefetch",
                "amcache",
                "lnk",
                "jump_list",
                "scheduled_task",
                "registry_hive",
            ],
        ) || contains_any_query(
            &steps,
            &[
                "process_created",
                "prefetch_",
                "amcache_program_seen",
                "scheduled_task_exec_action",
                "lnk_target_reference",
                "registry_userassist",
            ],
        );
        let has_filesystem = has_any_artifact(
            &artifacts,
            &["mft", "usn_jrnl", "windows_search_log", "jump_list", "lnk"],
        );
        let has_network = has_any_artifact(
            &artifacts,
            &[
                "browser",
                "web_cache",
                "network_capture",
                "onedrive_log",
                "filezilla",
            ],
        ) || key_kind == "ip"
            || key_kind == "url";
        let has_defender = has_any_artifact(&artifacts, &["defender"])
            || contains_any_query(&steps, &["defender_"]);
        let has_persistence = has_any_artifact(&artifacts, &["scheduled_task", "registry_hive"])
            || contains_any_query(
                &steps,
                &["scheduled_task", "run_key", "service_image", "persistence"],
            );
        let suspicious_key = contains_any_query(
            &key_value,
            &[
                ".exe",
                ".dll",
                ".ps1",
                ".bat",
                ".cmd",
                ".scr",
                ".hta",
                ".js",
                ".jse",
                ".vbs",
                ".wsf",
                "powershell",
                "rundll32",
                "regsvr32",
                "mshta",
                "mimikatz",
                "lsass",
            ],
        );
        let user_writable_key = contains_any_query(
            &key_value,
            &[
                "\\appdata\\",
                "/appdata/",
                "\\temp\\",
                "/temp/",
                "\\downloads\\",
                "/downloads/",
                "\\startup\\",
                "/startup/",
                "\\public\\",
                "/public/",
            ],
        );

        let mut desired = chain.severity.clone();
        let mut reason = None;
        if has_defender && has_execution {
            desired = "critical".to_string();
            reason = Some("Defender 検知と実行痕跡が同一キーで連結");
        } else if has_network && has_execution && suspicious_key {
            desired = "critical".to_string();
            reason = Some("通信/取得痕跡と実行痕跡が同一キーで連結");
        } else if has_execution && has_filesystem && (suspicious_key || user_writable_key) {
            desired = "high".to_string();
            reason = Some("実行痕跡とファイルシステム痕跡が高リスクキーで連結");
        } else if has_persistence && (has_execution || suspicious_key) {
            desired = "high".to_string();
            reason = Some("永続化候補と実行候補が連結");
        } else if key_kind.starts_with("artifact_object:")
            && contains_any_query(
                &key_kind,
                &[
                    "ntfs_data_run",
                    "lnk_property_value",
                    "prefetch_trace_chain",
                    "prefetch_run_time",
                ],
            )
            && chain.step_count >= 2
        {
            desired = "high".to_string();
            reason = Some("深い構造オブジェクトが複数イベントで一致");
        } else if title.contains("構造") && chain.step_count >= 3 {
            desired = "medium".to_string();
            reason = Some("構造抽出キーが複数イベントで一致");
        }

        if severity_rank(&desired) > severity_rank(&chain.severity) {
            chain.severity = desired.clone();
            chain.score += match desired.as_str() {
                "critical" => 80,
                "high" => 45,
                "medium" => 20,
                _ => 0,
            };
            if let Some(reason) = reason {
                if !chain.explanation.contains(reason) {
                    chain.explanation = format!("{}。4構造化補正: {reason}", chain.explanation);
                }
                if chain.title == "同一キーの反復活動チェーン"
                    || chain.title == "構造オブジェクトの横断一致"
                {
                    chain.title = reason.to_string();
                }
            }
        }
    }
}

fn has_any_artifact(artifacts: &HashSet<String>, needles: &[&str]) -> bool {
    needles.iter().any(|needle| artifacts.contains(*needle))
}

fn contains_any_query(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn structure_chain_noise_key(key_kind: &str, key_value: &str) -> bool {
    if !key_kind.starts_with("artifact_object:") {
        return false;
    }
    matches!(
        key_value,
        "file_reference:/"
            | "file_reference:c:\\program"
            | "file_reference:c:\\programdata\\microsoft\\windows"
            | "file_reference:c:\\windows\\explorer.exe"
            | "file_reference:\\device\\harddiskvolume3\\program"
            | "process_reference:winlogon.exe"
            | "process_reference:explorer.exe"
            | "process_reference:onedrive.exe"
            | "process_reference:onedrivesetup.exe"
            | "process_reference:onedrivestandaloneupdater.exe"
            | "process_reference:microsoft.sharepoint.exe"
            | "process_reference:filecoauth.exe"
            | "process_reference:filecoauthlib64.dll"
            | "process_reference:explorerframe.dll"
            | "process_reference:tiworker.exe"
            | "process_reference:mmres.dll"
            | "process_reference:svchost.exe"
    )
}

fn severity_rank(value: &str) -> i64 {
    match value {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn event_row_finding_candidate_clause() -> String {
    let haystack = "lower(concat_ws(' ', artifact_type, event_action, severity, message_short, \
      COALESCE(host, ''), COALESCE(user_name, ''), COALESCE(process_name, ''), \
      COALESCE(file_path, ''), COALESCE(ip, ''), COALESCE(url, ''), COALESCE(hash, ''), \
      COALESCE(event_code, ''), COALESCE(channel, ''), COALESCE(parser_name, '')))";
    let pattern = [
        "defender",
        "threat",
        "malware",
        "c2",
        "rat",
        "merlin",
        "psexec",
        "psexesvc",
        "powershell",
        "encoded",
        "base64",
        "mshta",
        "rundll32",
        "regsvr32",
        "wevtutil",
        "log_tamper",
        "timestomp",
        "si_fn",
        "credential",
        "lsass",
        "mimikatz",
        "dump",
        "keepass",
        "filezilla",
        "scheduled_task",
        "remote_access",
        "rdp",
        "webshell",
        "archive_suspicious",
        "recovered",
        "deleted_file",
        "carved_file",
        "network_http_request",
        "network_file_transfer",
    ]
    .iter()
    .map(|term| escape_regex_literal(term))
    .collect::<Vec<_>>()
    .join("|");
    format!(
        "(has_finding OR severity IN ('critical', 'high') \
          OR (severity = 'medium' AND regexp_matches({haystack}, {})))",
        sql_literal(&pattern)
    )
}

fn event_row_finding_rule_id(severity: &str, artifact_type: &str, event_action: &str) -> String {
    let payload = serde_json::to_string(&[severity, artifact_type, event_action])
        .unwrap_or_else(|_| "[]".to_string());
    format!("{EVENT_ROW_FALLBACK_FINDING_RULE_PREFIX}{payload}")
}

fn decode_event_row_finding_rule_id(rule_id: Option<&str>) -> Option<(String, String, String)> {
    let payload = rule_id?.strip_prefix(EVENT_ROW_FALLBACK_FINDING_RULE_PREFIX)?;
    let values = serde_json::from_str::<Vec<String>>(payload).ok()?;
    if values.len() != 3 {
        return None;
    }
    Some((values[0].clone(), values[1].clone(), values[2].clone()))
}

fn event_row_finding_title(artifact_type: &str, event_action: &str) -> String {
    let action = if event_action.trim().is_empty() {
        "suspicious_event"
    } else {
        event_action
    };
    format!("{action} ({artifact_type})")
}

fn event_row_finding_attack_json(artifact_type: &str, event_action: &str) -> String {
    let haystack = format!("{artifact_type} {event_action}").to_ascii_lowercase();
    let mut tags = Vec::new();
    if haystack.contains("powershell") || haystack.contains("cmd") || haystack.contains("mshta") {
        tags.push("T1059 Command and Scripting Interpreter");
    }
    if haystack.contains("scheduled_task") || haystack.contains("task") {
        tags.push("T1053 Scheduled Task/Job");
    }
    if haystack.contains("psexec") || haystack.contains("service") {
        tags.push("T1569 System Services");
    }
    if haystack.contains("defender") || haystack.contains("tamper") || haystack.contains("wevtutil")
    {
        tags.push("T1562 Impair Defenses");
    }
    if haystack.contains("credential")
        || haystack.contains("lsass")
        || haystack.contains("keepass")
        || haystack.contains("filezilla")
    {
        tags.push("T1003 Credential Access");
    }
    if haystack.contains("network") || haystack.contains("c2") || haystack.contains("rat") {
        tags.push("T1105 Ingress Tool Transfer");
    }
    if haystack.contains("mft") || haystack.contains("timestomp") || haystack.contains("deleted") {
        tags.push("T1070 Indicator Removal");
    }
    if tags.is_empty() {
        tags.push("event_rows:fallback");
    }
    serde_json::to_string(&tags).unwrap_or_else(|_| "[]".to_string())
}

fn parse_json_strings(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value).unwrap_or_default()
}

fn encode_cursor(first: &str, second: &str) -> String {
    serde_json::to_string(&[first, second]).unwrap_or_else(|_| format!("{first}|{second}"))
}

fn decode_cursor(cursor: &str) -> Result<(String, String)> {
    if let Ok(values) = serde_json::from_str::<Vec<String>>(cursor) {
        if values.len() == 2 {
            return Ok((values[0].clone(), values[1].clone()));
        }
    }
    let (first, second) = cursor
        .split_once('|')
        .ok_or_else(|| StorageError::InvalidCursor(cursor.to_string()))?;
    Ok((first.to_string(), second.to_string()))
}

fn sql_in_list(values: &HashSet<String>) -> String {
    sql_list(values.iter())
}

fn sql_list<'a>(values: impl Iterator<Item = &'a String>) -> String {
    values
        .map(|value| sql_literal(value))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Reserved Windows account markers (regex alternation). Mirrors
/// `WELL_KNOWN_ACCOUNT_MARKERS` in taotie-parsers. On an already-parsed (existing)
/// case, anything before such a marker is upstream evtx-crate binary-misdecode
/// garbage; we drop it at read/projection time so no re-ingest is required. The
/// expressions are a no-op on clean and on legitimate (incl. non-ASCII) values.
const SQL_ACCOUNT_MARKERS: &str =
    "NT AUTHORITY|NT SERVICE|BUILTIN|NT VIRTUAL MACHINE|FONT DRIVER HOST|WINDOW MANAGER";

/// SQL expr: for a whole account value, keep from the earliest reserved marker to the
/// end and drop any garbage prefix. No-op when no marker is present.
fn sql_sanitize_account(expr: &str) -> String {
    format!(
        "regexp_replace({expr}, '^.*?(({markers})\\\\.*)$', '\\1', 'i')",
        markers = SQL_ACCOUNT_MARKERS
    )
}

/// SQL expr: for a rendered message, drop a garbage run sitting between `user=` and a
/// reserved marker while preserving the `user=` label and the marker tail.
fn sql_sanitize_account_in_message(expr: &str) -> String {
    format!(
        "regexp_replace({expr}, '(user=).*?(({markers})\\\\)', '\\1\\2', 'i')",
        markers = SQL_ACCOUNT_MARKERS
    )
}

fn event_row_search_text_sql() -> String {
    // Placeholder substitution (NOT format!) so the embedded regex quantifiers
    // (e.g. {1,3}, {32,64}) keep their literal braces. user_name/message_short/
    // message_full are sanitized inline so the search index never matches the
    // upstream evtx garbage even though the lake columns still hold it.
    r#"lower(concat_ws(' ',
        event_id,
        artifact_type,
        COALESCE(host, ''),
        COALESCE(__USER_NAME__, ''),
        COALESCE(process_name, ''),
        COALESCE(file_path, ''),
        COALESCE(ip, ''),
        COALESCE(url, ''),
        COALESCE(hash, ''),
        event_action,
        severity,
        __MESSAGE_SHORT__,
        source_file_id,
        parser_name,
        left(COALESCE(__MESSAGE_FULL__, ''), 2048),
        left(COALESCE(attributes_json, ''), 4096),
        regexp_extract(lower(concat_ws(' ', COALESCE(message_full, ''), COALESCE(attributes_json, ''))), 'cve-[0-9]{4}-[0-9]{4,7}', 0),
        regexp_extract(lower(concat_ws(' ', COALESCE(message_full, ''), COALESCE(attributes_json, ''))), 'https?://[^[:space:]"<>]+', 0),
        regexp_extract(lower(concat_ws(' ', COALESCE(message_full, ''), COALESCE(attributes_json, ''))), '(?:[0-9]{1,3}\.){3}[0-9]{1,3}', 0),
        regexp_extract(lower(concat_ws(' ', COALESCE(message_full, ''), COALESCE(attributes_json, ''))), '[a-f0-9]{32,64}', 0),
        regexp_extract(lower(concat_ws(' ', COALESCE(message_full, ''), COALESCE(attributes_json, ''))), '(hosturl|zone.identifier|password|secret|token|dpapi|keepass|filezilla|merlin\.exe)', 0)
    ))"#
    .replace("__USER_NAME__", &sql_sanitize_account("user_name"))
    .replace(
        "__MESSAGE_SHORT__",
        &sql_sanitize_account_in_message("message_short"),
    )
    .replace(
        "__MESSAGE_FULL__",
        &sql_sanitize_account_in_message("message_full"),
    )
}

fn legacy_event_ioc_haystack_sql() -> &'static str {
    "lower(concat_ws(' ', event_id, artifact_type, COALESCE(host, ''), \
     COALESCE(user_name, ''), COALESCE(process_name, ''), COALESCE(file_path, ''), \
     COALESCE(ip, ''), COALESCE(url, ''), COALESCE(hash, ''), COALESCE(event_code, ''), \
     COALESCE(channel, ''), COALESCE(level, ''), event_action, severity, message_short, \
     source_file_id, parser_name))"
}

fn event_ioc_haystack_sql(has_search_text: bool) -> String {
    if has_search_text {
        format!("COALESCE(search_text, {})", legacy_event_ioc_haystack_sql())
    } else {
        legacy_event_ioc_haystack_sql().to_string()
    }
}

fn event_row_haystack_sql(has_search_text: bool) -> String {
    if has_search_text {
        event_ioc_haystack_sql(true)
    } else {
        "lower(concat_ws(' ', message_short, COALESCE(file_path, ''), \
         COALESCE(process_name, ''), COALESCE(ip, ''), COALESCE(user_name, ''), \
         COALESCE(url, ''), artifact_type, event_action, severity))"
            .to_string()
    }
}

fn ioc_event_clause(ioc: &str, has_search_text: bool) -> String {
    let literal = sql_literal(ioc);
    let lower_literal = sql_literal(&ioc.to_ascii_lowercase());
    format!(
        "(lower(COALESCE(hash, '')) = {lower_literal} \
         OR lower(COALESCE(ip, '')) = {lower_literal} \
         OR lower(COALESCE(process_name, '')) = {lower_literal} \
         OR instr({haystack}, lower({literal})) > 0)",
        haystack = event_ioc_haystack_sql(has_search_text)
    )
}

fn defender_event_clause() -> String {
    "(artifact_type = 'defender' \
      OR lower(COALESCE(channel, '')) LIKE '%defender%' \
      OR lower(COALESCE(event_action, '')) LIKE 'defender_%' \
      OR lower(COALESCE(parser_name, '')) LIKE '%defender%' \
      OR lower(COALESCE(message_short, '')) LIKE '%microsoft defender%' \
      OR lower(COALESCE(message_short, '')) LIKE '%windows defender%')"
        .to_string()
}

const MAX_EVENT_SEARCH_TERMS: usize = 16;
const MAX_EVENT_SEARCH_VALUE_CHARS: usize = 256;
const MAX_EVENT_SEARCH_TOKENS: usize = 96;
const MAX_EVENT_SEARCH_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventSearchMatchKind {
    Exact,
    Contains,
    /// Anchored wildcard match: `*`/`?` act as glob, everything else literal.
    /// Lets Event ID filters like `472*` match 4720..4729 while plain `4724` stays exact.
    Glob,
    GreaterOrEqual,
    LessOrEqual,
    /// Strict `<` — used for exclusive time upper bounds (bin windows) so an
    /// event exactly on the next bin's start is not double-counted.
    Less,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventSearchField {
    expr: &'static str,
    kind: EventSearchMatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventSearchTermMode {
    Contains,
    Regex,
    Word,
    Extension,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventSearchTerm {
    field: Option<EventSearchField>,
    value: String,
    mode: EventSearchTermMode,
    negated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EventSearchExprToken {
    Term(String),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EventSearchExpr {
    Term(EventSearchTerm),
    And(Vec<EventSearchExpr>),
    Or(Vec<EventSearchExpr>),
    Not(Box<EventSearchExpr>),
}

struct EventSearchExprParser {
    tokens: Vec<EventSearchExprToken>,
    pos: usize,
    term_count: usize,
    depth: usize,
}

fn event_filter_clauses(query: &EventPageQuery, has_search_text: bool) -> Vec<String> {
    let mut clauses = Vec::new();
    if let Some(artifact_type) = query.artifact_type.as_deref().filter(|s| !s.is_empty()) {
        clauses.push(format!("artifact_type = {}", sql_literal(artifact_type)));
    }
    if let Some(user_name) = query.user_name.as_deref().filter(|s| !s.is_empty()) {
        clauses.push(format!("user_name = {}", sql_literal(user_name)));
    }
    if let Some(search) = query
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        clauses.push(event_search_clause(search, has_search_text));
    }
    clauses
}

fn event_search_clause(search: &str, has_search_text: bool) -> String {
    if let Some(expr) = event_search_expression_clause(search, has_search_text) {
        return format!("({expr})");
    }
    let term_clauses = event_search_terms(search)
        .into_iter()
        .filter_map(|term| event_search_term_clause(term, has_search_text))
        .collect::<Vec<_>>();
    if !term_clauses.is_empty() {
        return format!("({})", term_clauses.join(" AND "));
    }
    event_search_like_clause(search, has_search_text)
}

fn event_search_expression_clause(search: &str, has_search_text: bool) -> Option<String> {
    let tokens = tokenize_event_search_expression(search);
    if tokens.is_empty() {
        return None;
    }
    let ast = EventSearchExprParser::new(tokens).parse()?;
    let clause = event_search_expr_clause(&ast, has_search_text)?;
    (!clause.trim().is_empty()).then_some(clause)
}

fn event_search_like_clause(search: &str, has_search_text: bool) -> String {
    let needle = sql_literal(&format!(
        "%{}%",
        escape_like(search.to_ascii_lowercase().trim())
    ));
    format!(
        "{} LIKE {needle} ESCAPE '\\'",
        event_ioc_haystack_sql(has_search_text)
    )
}

fn event_search_terms(search: &str) -> Vec<EventSearchTerm> {
    tokenize_event_search(search)
        .into_iter()
        .take(MAX_EVENT_SEARCH_TERMS)
        .filter_map(|token| parse_event_search_token(&token))
        .collect()
}

fn parse_event_search_token(token: &str) -> Option<EventSearchTerm> {
    let mut token = token.trim();
    let mut negated = false;
    if let Some(stripped) = token.strip_prefix('-').or_else(|| token.strip_prefix('!')) {
        negated = true;
        token = stripped.trim();
    }
    if token.is_empty() {
        return None;
    }
    if let Some((field_name, raw_value)) = token.split_once(':') {
        let field_name = field_name.trim().to_ascii_lowercase();
        if matches!(field_name.as_str(), "re" | "regex") {
            let (value, _) = normalize_event_search_value(raw_value);
            return (!value.is_empty()).then_some(EventSearchTerm {
                field: None,
                value,
                mode: EventSearchTermMode::Regex,
                negated,
            });
        }
        if matches!(field_name.as_str(), "word" | "exact" | "token") {
            let (value, regex) = normalize_event_search_value(raw_value);
            return (!value.is_empty()).then_some(EventSearchTerm {
                field: None,
                value,
                mode: if regex {
                    EventSearchTermMode::Regex
                } else {
                    EventSearchTermMode::Word
                },
                negated,
            });
        }
        if matches!(field_name.as_str(), "ext" | "extension" | "suffix") {
            let (value, regex) = normalize_event_search_value(raw_value);
            return (!value.is_empty()).then_some(EventSearchTerm {
                field: None,
                value,
                mode: if regex {
                    EventSearchTermMode::Regex
                } else {
                    EventSearchTermMode::Extension
                },
                negated,
            });
        }
        if let Some(field) = event_search_field(&field_name) {
            let (value, regex) = normalize_event_search_value(raw_value);
            return (!value.is_empty()).then_some(EventSearchTerm {
                field: Some(field),
                value,
                mode: if regex {
                    EventSearchTermMode::Regex
                } else {
                    EventSearchTermMode::Contains
                },
                negated,
            });
        }
    }
    let quoted = is_quoted_event_search_value(token);
    let value = truncate_chars(
        &unquote_event_search_value(token),
        MAX_EVENT_SEARCH_VALUE_CHARS,
    );
    (!value.is_empty()).then_some(EventSearchTerm {
        field: None,
        value,
        mode: if quoted {
            EventSearchTermMode::Word
        } else {
            EventSearchTermMode::Contains
        },
        negated,
    })
}

fn normalize_event_search_value(raw_value: &str) -> (String, bool) {
    let raw_value = raw_value.trim();
    if let Some(value) = regex_delimited_value(raw_value) {
        return (truncate_chars(&value, MAX_EVENT_SEARCH_VALUE_CHARS), true);
    }
    (
        truncate_chars(
            &unquote_event_search_value(raw_value),
            MAX_EVENT_SEARCH_VALUE_CHARS,
        ),
        false,
    )
}

fn event_search_term_clause(term: EventSearchTerm, has_search_text: bool) -> Option<String> {
    let value = term.value.trim();
    if value.is_empty() {
        return None;
    }
    let expr = term
        .field
        .map(|field| field.expr.to_string())
        .unwrap_or_else(|| event_ioc_haystack_sql(has_search_text));
    let body = if term
        .field
        .is_some_and(|field| field.kind == EventSearchMatchKind::GreaterOrEqual)
    {
        format!(
            "try_cast({expr} AS TIMESTAMPTZ) >= try_cast({} AS TIMESTAMPTZ)",
            sql_literal(value)
        )
    } else if term
        .field
        .is_some_and(|field| field.kind == EventSearchMatchKind::LessOrEqual)
    {
        format!(
            "try_cast({expr} AS TIMESTAMPTZ) <= try_cast({} AS TIMESTAMPTZ)",
            sql_literal(value)
        )
    } else if term
        .field
        .is_some_and(|field| field.kind == EventSearchMatchKind::Less)
    {
        format!(
            "try_cast({expr} AS TIMESTAMPTZ) < try_cast({} AS TIMESTAMPTZ)",
            sql_literal(value)
        )
    } else if term.mode == EventSearchTermMode::Regex {
        let pattern = sql_literal(&value.to_ascii_lowercase());
        if term.field.is_none() && has_search_text {
            format!("regexp_matches({expr}, {pattern})")
        } else {
            format!("regexp_matches(lower({expr}), {pattern})")
        }
    } else if term.mode == EventSearchTermMode::Extension {
        event_search_extension_clause(value)?
    } else if term
        .field
        .is_some_and(|field| field.kind == EventSearchMatchKind::Glob)
    {
        format!(
            "regexp_matches(lower({expr}), {})",
            sql_literal(&event_glob_to_regex(value))
        )
    } else if term
        .field
        .is_some_and(|field| field.kind == EventSearchMatchKind::Exact)
    {
        if term.field.is_none() && has_search_text {
            format!("{expr} = {}", sql_literal(&value.to_ascii_lowercase()))
        } else {
            format!(
                "lower({expr}) = {}",
                sql_literal(&value.to_ascii_lowercase())
            )
        }
    } else if term.mode == EventSearchTermMode::Word {
        event_search_word_clause(&expr, value)
    } else {
        let needle = sql_literal(&format!(
            "%{}%",
            escape_like(value.to_ascii_lowercase().trim())
        ));
        if term.field.is_none() && has_search_text {
            format!("{expr} LIKE {needle} ESCAPE '\\'")
        } else {
            format!("lower({expr}) LIKE {needle} ESCAPE '\\'")
        }
    };
    if term.negated {
        Some(format!("NOT ({body})"))
    } else {
        Some(body)
    }
}

fn event_search_word_clause(expr: &str, value: &str) -> String {
    let pattern = format!(
        "(^|[^[:alnum:]_]){}($|[^[:alnum:]_])",
        escape_regex_literal(&value.to_ascii_lowercase())
    );
    format!("regexp_matches(lower({expr}), {})", sql_literal(&pattern))
}

fn event_search_extension_clause(value: &str) -> Option<String> {
    let extension = value.trim().trim_start_matches('.').to_ascii_lowercase();
    if extension.is_empty() {
        return None;
    }
    let pattern = format!(r"\.{}($|[^[:alnum:]_])", escape_regex_literal(&extension));
    Some(format!(
        "regexp_matches(lower(concat_ws(' ', COALESCE(file_path, ''), COALESCE(process_name, ''), message_short)), {})",
        sql_literal(&pattern)
    ))
}

fn event_search_expr_clause(expr: &EventSearchExpr, has_search_text: bool) -> Option<String> {
    match expr {
        EventSearchExpr::Term(term) => event_search_term_clause(term.clone(), has_search_text),
        EventSearchExpr::And(nodes) => {
            let clauses = nodes
                .iter()
                .filter_map(|node| event_search_expr_clause(node, has_search_text))
                .collect::<Vec<_>>();
            if clauses.is_empty() {
                None
            } else {
                Some(format!("({})", clauses.join(" AND ")))
            }
        }
        EventSearchExpr::Or(nodes) => {
            let clauses = nodes
                .iter()
                .filter_map(|node| event_search_expr_clause(node, has_search_text))
                .collect::<Vec<_>>();
            if clauses.is_empty() {
                None
            } else {
                Some(format!("({})", clauses.join(" OR ")))
            }
        }
        EventSearchExpr::Not(node) => {
            event_search_expr_clause(node, has_search_text).map(|clause| format!("NOT ({clause})"))
        }
    }
}

fn event_search_field(field: &str) -> Option<EventSearchField> {
    let exact = EventSearchMatchKind::Exact;
    let contains = EventSearchMatchKind::Contains;
    let glob = EventSearchMatchKind::Glob;
    let field = match field {
        "after" | "since" | "from" | "start" | "start_utc" | "time_after" => EventSearchField {
            expr: "event_time_utc",
            kind: EventSearchMatchKind::GreaterOrEqual,
        },
        "before" | "until" | "to" | "end" | "end_utc" | "time_before" => EventSearchField {
            expr: "event_time_utc",
            kind: EventSearchMatchKind::LessOrEqual,
        },
        "before_exclusive" | "time_before_exclusive" => EventSearchField {
            expr: "event_time_utc",
            kind: EventSearchMatchKind::Less,
        },
        "id" | "event" | "event_id" => EventSearchField {
            expr: "event_id",
            kind: contains,
        },
        "time" | "ts" | "event_time" | "event_time_utc" => EventSearchField {
            expr: "event_time_utc",
            kind: contains,
        },
        "type" | "artifact" | "artifact_type" => EventSearchField {
            expr: "artifact_type",
            kind: exact,
        },
        "host" | "hostname" => EventSearchField {
            expr: "COALESCE(host, '')",
            kind: contains,
        },
        "user" | "username" | "user_name" => EventSearchField {
            expr: "COALESCE(user_name, '')",
            kind: contains,
        },
        "process" | "proc" | "process_name" | "exe" => EventSearchField {
            expr: "COALESCE(process_name, '')",
            kind: contains,
        },
        "file" | "path" | "file_path" => EventSearchField {
            expr: "COALESCE(file_path, '')",
            kind: contains,
        },
        "ip" => EventSearchField {
            expr: "COALESCE(ip, '')",
            kind: contains,
        },
        "url" => EventSearchField {
            expr: "COALESCE(url, '')",
            kind: contains,
        },
        "hash" => EventSearchField {
            expr: "COALESCE(hash, '')",
            kind: exact,
        },
        "eid" | "eventid" | "event_id_code" | "event_code" => EventSearchField {
            expr: "COALESCE(event_code, '')",
            kind: glob,
        },
        "channel" => EventSearchField {
            expr: "COALESCE(channel, '')",
            kind: contains,
        },
        "level" => EventSearchField {
            expr: "COALESCE(level, '')",
            kind: contains,
        },
        "action" | "event_action" => EventSearchField {
            expr: "event_action",
            kind: exact,
        },
        "severity" | "sev" => EventSearchField {
            expr: "severity",
            kind: exact,
        },
        "message" | "msg" | "message_short" => EventSearchField {
            expr: "message_short",
            kind: contains,
        },
        "parser" | "parser_name" => EventSearchField {
            expr: "parser_name",
            kind: exact,
        },
        "source" | "source_file" | "source_file_id" => EventSearchField {
            expr: "source_file_id",
            kind: contains,
        },
        "finding" | "has_finding" => EventSearchField {
            expr: "CASE WHEN has_finding THEN 'true' ELSE 'false' END",
            kind: exact,
        },
        _ => return None,
    };
    Some(field)
}

fn tokenize_event_search(search: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut in_regex = false;
    let mut escaped = false;
    for ch in search.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if (quote.is_some() || in_regex) && ch == '\\' {
            current.push(ch);
            escaped = true;
            continue;
        }
        if let Some(quote_ch) = quote {
            current.push(ch);
            if ch == quote_ch {
                quote = None;
            }
            continue;
        }
        if in_regex {
            current.push(ch);
            if ch == '/' {
                in_regex = false;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            current.push(ch);
            quote = Some(ch);
            continue;
        }
        if ch == '/' && current_is_field_prefix(&current) {
            current.push(ch);
            in_regex = true;
            continue;
        }
        if ch.is_whitespace() {
            if !current.trim().is_empty() {
                out.push(current.trim().to_string());
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

fn tokenize_event_search_expression(search: &str) -> Vec<EventSearchExprToken> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut in_regex = false;
    let mut escaped = false;
    for ch in search.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if (quote.is_some() || in_regex) && ch == '\\' {
            current.push(ch);
            escaped = true;
            continue;
        }
        if let Some(quote_ch) = quote {
            current.push(ch);
            if ch == quote_ch {
                quote = None;
            }
            continue;
        }
        if in_regex {
            current.push(ch);
            if ch == '/' {
                in_regex = false;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            current.push(ch);
            quote = Some(ch);
            continue;
        }
        if ch == '/' && current_is_field_prefix(&current) {
            current.push(ch);
            in_regex = true;
            continue;
        }
        if ch == '(' || ch == ')' {
            push_event_search_expr_token(&mut out, &mut current);
            if ch == '(' {
                out.push(EventSearchExprToken::LParen);
            } else {
                out.push(EventSearchExprToken::RParen);
            }
            if out.len() >= MAX_EVENT_SEARCH_TOKENS {
                break;
            }
            continue;
        }
        if ch.is_whitespace() {
            push_event_search_expr_token(&mut out, &mut current);
            if out.len() >= MAX_EVENT_SEARCH_TOKENS {
                break;
            }
        } else {
            current.push(ch);
        }
    }
    push_event_search_expr_token(&mut out, &mut current);
    out.truncate(MAX_EVENT_SEARCH_TOKENS);
    out
}

fn push_event_search_expr_token(out: &mut Vec<EventSearchExprToken>, current: &mut String) {
    let token = current.trim();
    if token.is_empty() {
        current.clear();
        return;
    }
    let normalized = match token.to_ascii_uppercase().as_str() {
        "AND" => EventSearchExprToken::And,
        "OR" => EventSearchExprToken::Or,
        "NOT" => EventSearchExprToken::Not,
        _ => EventSearchExprToken::Term(token.to_string()),
    };
    out.push(normalized);
    current.clear();
}

impl EventSearchExprParser {
    fn new(tokens: Vec<EventSearchExprToken>) -> Self {
        Self {
            tokens,
            pos: 0,
            term_count: 0,
            depth: 0,
        }
    }

    fn parse(mut self) -> Option<EventSearchExpr> {
        let expr = self.parse_or()?;
        (self.pos == self.tokens.len() && self.term_count > 0).then_some(expr)
    }

    fn parse_or(&mut self) -> Option<EventSearchExpr> {
        let mut nodes = vec![self.parse_and()?];
        while self.consume_operator(EventSearchExprToken::Or) {
            nodes.push(self.parse_and()?);
        }
        Some(flatten_event_search_expr_or(nodes))
    }

    fn parse_and(&mut self) -> Option<EventSearchExpr> {
        let mut nodes = vec![self.parse_unary()?];
        loop {
            if self.consume_operator(EventSearchExprToken::And) {
                nodes.push(self.parse_unary()?);
                continue;
            }
            if self.next_starts_unary() {
                nodes.push(self.parse_unary()?);
                continue;
            }
            break;
        }
        Some(flatten_event_search_expr_and(nodes))
    }

    fn parse_unary(&mut self) -> Option<EventSearchExpr> {
        if self.consume_operator(EventSearchExprToken::Not) {
            return self
                .parse_unary()
                .map(|expr| EventSearchExpr::Not(Box::new(expr)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Option<EventSearchExpr> {
        let token = self.tokens.get(self.pos)?.clone();
        match token {
            EventSearchExprToken::Term(value) => {
                self.pos += 1;
                self.term_count += 1;
                if self.term_count > MAX_EVENT_SEARCH_TERMS {
                    return None;
                }
                parse_event_search_token(&value).map(EventSearchExpr::Term)
            }
            EventSearchExprToken::LParen => {
                if self.depth >= MAX_EVENT_SEARCH_DEPTH {
                    return None;
                }
                self.pos += 1;
                self.depth += 1;
                let expr = self.parse_or()?;
                self.depth -= 1;
                if !matches!(
                    self.tokens.get(self.pos),
                    Some(EventSearchExprToken::RParen)
                ) {
                    return None;
                }
                self.pos += 1;
                Some(expr)
            }
            _ => None,
        }
    }

    fn consume_operator(&mut self, expected: EventSearchExprToken) -> bool {
        if self.tokens.get(self.pos) == Some(&expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn next_starts_unary(&self) -> bool {
        matches!(
            self.tokens.get(self.pos),
            Some(EventSearchExprToken::Term(_))
                | Some(EventSearchExprToken::Not)
                | Some(EventSearchExprToken::LParen)
        )
    }
}

fn flatten_event_search_expr_and(nodes: Vec<EventSearchExpr>) -> EventSearchExpr {
    let mut out = Vec::new();
    for node in nodes {
        match node {
            EventSearchExpr::And(children) => out.extend(children),
            node => out.push(node),
        }
    }
    if out.len() == 1 {
        out.pop().expect("single node exists")
    } else {
        EventSearchExpr::And(out)
    }
}

fn flatten_event_search_expr_or(nodes: Vec<EventSearchExpr>) -> EventSearchExpr {
    let mut out = Vec::new();
    for node in nodes {
        match node {
            EventSearchExpr::Or(children) => out.extend(children),
            node => out.push(node),
        }
    }
    if out.len() == 1 {
        out.pop().expect("single node exists")
    } else {
        EventSearchExpr::Or(out)
    }
}

fn current_is_field_prefix(value: &str) -> bool {
    value
        .find(':')
        .is_some_and(|idx| idx + 1 == value.len() && idx > 0)
}

fn regex_delimited_value(value: &str) -> Option<String> {
    let mut chars = value.char_indices();
    if chars.next().map(|(_, ch)| ch) != Some('/') {
        return None;
    }
    let mut escaped = false;
    for (idx, ch) in chars {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '/' {
            let trailing = value[idx + ch.len_utf8()..].trim();
            if trailing.is_empty() || trailing == "i" {
                return Some(value[1..idx].replace("\\/", "/"));
            }
            return None;
        }
    }
    None
}

fn unquote_event_search_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let mut chars = value.chars();
        let first = chars.next();
        let last = value.chars().next_back();
        if matches!(
            (first, last),
            (Some('"'), Some('"')) | (Some('\''), Some('\''))
        ) {
            return value[1..value.len() - 1]
                .replace("\\\"", "\"")
                .replace("\\'", "'");
        }
    }
    value.to_string()
}

fn is_quoted_event_search_value(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 2 {
        return false;
    }
    matches!(
        (value.chars().next(), value.chars().next_back()),
        (Some('"'), Some('"')) | (Some('\''), Some('\''))
    )
}

fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn correlation_chain_key_clause(key_kind: &str, key_value: &str) -> Option<String> {
    let literal = sql_literal(&key_value.to_ascii_lowercase());
    match key_kind {
        "file_basename" => Some(format!(
            "lower(regexp_replace(COALESCE(file_path, process_name, ''), '^.*[\\\\/]', '')) = {literal}"
        )),
        "ip" => Some(format!("ip = {}", sql_literal(key_value))),
        "hash" => Some(format!("lower(COALESCE(hash, '')) = {literal}")),
        "url" => Some(format!("lower(COALESCE(url, '')) = {literal}")),
        "user_name" => Some(format!("lower(COALESCE(user_name, '')) = {literal}")),
        _ => None,
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Convert a user-entered glob (`*` = any chars, `?` = one char) into an ANCHORED
/// regex. All other regex metacharacters are escaped, so plain `4724` stays exact
/// (`^4724$`) while `472*` becomes `^472.*$` (matches 4720..4729 etc.).
fn event_glob_to_regex(value: &str) -> String {
    let trimmed = value.trim().to_ascii_lowercase();
    let mut out = String::with_capacity(trimmed.len() + 2);
    out.push('^');
    for ch in trimmed.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '\\' | '.' | '+' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out.push('$');
    out
}

fn escape_regex_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn answer_candidate_priority_sql(haystack: &str) -> String {
    let terms = [
        ("move.aspx", 0),
        ("ruby", 2),
        ("nmap", 3),
        ("moveit.asp", 4),
        ("api/v1/token", 5),
        ("guestaccess.aspx", 6),
        ("kerberoast_candidate", 7),
        ("asrep_roast_candidate", 7),
        ("ticket_encryption", 7),
        ("0x17", 7),
        ("psexesvc", 8),
        ("psexec_named_pipe", 8),
        ("browser_secret_decrypted", 9),
        ("keepass_entry_decrypted", 9),
        ("defender_threat_detected", 10),
        ("sharphound", 10),
        ("terminalservices", 11),
        ("remoteconnectionmanager", 11),
        ("1149", 11),
        ("logontype", 11),
        ("4724", 12),
        ("metasploit", 13),
        ("firewall_outbound", 13),
        ("firewall_block", 13),
        ("audit_policy", 14),
        ("audit policy", 14),
        ("other object access", 14),
        ("scheduled_task", 15),
        ("scheduled task", 15),
        ("task created", 15),
        ("get-filehash", 16),
        ("hash=", 16),
        ("algorithm=md5", 16),
        ("getstreamhash", 16),
        ("instlogos", 17),
        ("wget ", 18),
        ("systemhealthcheck", 20),
        ("powerview.ps1", 21),
        ("filezilla", 22),
        ("zeek_", 23),
        ("network_ftp_command", 24),
        ("archive_recovery_candidate", 25),
        ("document_sensitive_text_observed", 26),
        ("browser_encrypted_secret_candidate", 27),
    ];
    let mut sql = "CASE".to_string();
    for (term, priority) in terms {
        sql.push_str(&format!(
            " WHEN {haystack} LIKE {} ESCAPE '\\' THEN {priority}",
            sql_literal(&format!("%{}%", escape_like(term)))
        ));
    }
    sql.push_str(" ELSE 100 END");
    sql
}

fn hot_correlation_lake_fallback_allowed() -> bool {
    std::env::var("TAOTIE4_ALLOW_HOT_CORRELATION_LAKE_FALLBACK").as_deref() == Ok("1")
}

fn log_payload<T: Serialize>(name: &str, payload: &T, started: Instant) {
    let payload_bytes = serde_json::to_vec(payload).map_or(0, |bytes| bytes.len());
    debug!(
        target: "taotie.storage.query",
        name,
        elapsed_ms = started.elapsed().as_millis(),
        payload_bytes,
        "ui query completed"
    );
}
