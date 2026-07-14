use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CURRENT_SCHEMA_VERSION: &str = "taotie-lite-v1";

pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

pub fn now_utc() -> String {
    Utc::now().to_rfc3339()
}

pub fn parse_utc(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(value).map(|dt| dt.with_timezone(&Utc))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseManifest {
    pub case_id: String,
    pub name: String,
    pub created_at: String,
    pub schema_version: String,
}

impl CaseManifest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            case_id: new_id("case"),
            name: name.into(),
            created_at: now_utc(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseSummary {
    pub case_id: String,
    pub name: String,
    pub root_path: String,
    pub created_at: String,
    pub schema_version: String,
    pub file_count: i64,
    pub event_count: i64,
    pub failed_parse_count: i64,
    pub unsupported_file_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseCustodyProfile {
    pub case_id: String,
    pub investigator: Option<String>,
    pub custodian: Option<String>,
    pub organization: Option<String>,
    pub evidence_source: Option<String>,
    pub acquisition_method: Option<String>,
    pub acquired_at: Option<String>,
    pub legal_authority: Option<String>,
    pub chain_of_custody_note: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParserStatus {
    Pending,
    Parsed,
    Failed,
    Unsupported,
}

impl ParserStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Parsed => "parsed",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileRecord {
    pub file_id: String,
    pub case_id: String,
    pub parent_file_id: Option<String>,
    pub original_path: String,
    pub normalized_path: String,
    pub filename: String,
    pub extension: String,
    pub size: i64,
    pub sha256: String,
    pub artifact_type: String,
    pub parser_status: ParserStatus,
    pub event_count: i64,
    pub object_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRange {
    pub object_ref: String,
    pub sha256: String,
    pub offset: i64,
    pub length: i64,
    pub total_size: i64,
    pub hex_dump: String,
    pub ascii_preview: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceVerification {
    pub file_id: String,
    pub original_path: String,
    pub object_ref: String,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub size: i64,
    pub verified: bool,
    pub error_message: Option<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodyManifestVerification {
    pub manifest_path: String,
    pub manifest_sha256: Option<String>,
    pub computed_manifest_sha256: Option<String>,
    pub manifest_hash_ok: bool,
    pub manifest_type_ok: bool,
    pub case_id_matches: bool,
    pub evidence_file_count: i64,
    pub evidence_hash_checked_count: i64,
    pub evidence_hash_mismatch_count: i64,
    pub audit_log_sha256_at_generation: Option<String>,
    pub current_audit_log_sha256: Option<String>,
    pub audit_log_unchanged: bool,
    pub checked_at: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportBundleVerification {
    pub bundle_path: String,
    pub bundle_sha256: Option<String>,
    pub computed_bundle_sha256: Option<String>,
    pub bundle_hash_ok: bool,
    pub bundle_type_ok: bool,
    pub case_id_matches: bool,
    pub report_path: Option<String>,
    pub report_sha256_at_generation: Option<String>,
    pub current_report_sha256: Option<String>,
    pub report_hash_ok: bool,
    pub custody_manifest_path: Option<String>,
    pub custody_manifest_sha256_at_generation: Option<String>,
    pub current_custody_manifest_sha256: Option<String>,
    pub custody_manifest_hash_ok: bool,
    pub custody_manifest_internal_hash_ok: bool,
    pub custody_manifest_type_ok: bool,
    pub case_custody_profile_sha256_at_generation: Option<String>,
    pub current_case_custody_profile_sha256: Option<String>,
    pub case_custody_profile_hash_ok: bool,
    pub signature_algorithm: Option<String>,
    pub signature_key_id: Option<String>,
    pub signature_present: bool,
    pub signature_payload_hash_ok: bool,
    pub signature_valid: bool,
    pub signature_key_matches_case_key: bool,
    pub audit_log_sha256_at_generation: Option<String>,
    pub current_audit_log_sha256: Option<String>,
    pub audit_log_unchanged: bool,
    pub checked_at: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParseRunStatus {
    Running,
    Succeeded,
    Failed,
    Unsupported,
    Cancelled,
}

impl ParseRunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParseRun {
    pub parse_run_id: String,
    pub case_id: String,
    pub file_id: String,
    pub parser_name: String,
    pub parser_version: String,
    pub parser_config_hash: String,
    pub schema_version: String,
    pub status: ParseRunStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: i64,
    pub event_count: i64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParserVersionRecord {
    pub case_id: String,
    pub parser_name: String,
    pub parser_version: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaVersionRecord {
    pub case_id: String,
    pub schema_name: String,
    pub schema_version: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventFull {
    pub event_id: String,
    pub case_id: String,
    pub event_time_utc: String,
    pub event_time_original: String,
    pub time_kind: String,
    pub time_confidence: f64,
    pub source_confidence: f64,
    pub artifact_type: String,
    pub source_file_id: String,
    pub parse_run_id: String,
    pub parser_name: String,
    pub parser_version: String,
    pub schema_version: String,
    pub evidence_ref: String,
    pub host: Option<String>,
    pub user_name: Option<String>,
    pub process_name: Option<String>,
    pub file_path: Option<String>,
    pub ip: Option<String>,
    pub url: Option<String>,
    pub hash: Option<String>,
    pub event_action: String,
    pub severity: String,
    pub message_short: String,
    pub message_full: String,
    pub raw_record_ref: String,
    pub attributes_json: String,
}

impl EventFull {
    pub fn to_event_row(&self) -> EventRow {
        EventRow {
            event_id: self.event_id.clone(),
            case_id: self.case_id.clone(),
            event_time_utc: self.event_time_utc.clone(),
            artifact_type: self.artifact_type.clone(),
            host: self.host.clone(),
            user_name: self.user_name.clone(),
            process_name: self.process_name.clone(),
            file_path: self.file_path.clone(),
            ip: self.ip.clone(),
            url: self.url.clone(),
            hash: self.hash.clone(),
            event_code: attr_string(
                &self.attributes_json,
                &["event_id", "EventID", "event_code"],
            ),
            channel: attr_string(&self.attributes_json, &["channel", "Channel"]),
            level: attr_string(
                &self.attributes_json,
                &["level", "Level", "level_display_name"],
            ),
            event_action: self.event_action.clone(),
            severity: self.severity.clone(),
            message_short: self.message_short.clone(),
            source_file_id: self.source_file_id.clone(),
            parser_name: self.parser_name.clone(),
            has_finding: false,
            command_line: attr_string(&self.attributes_json, &["command_line", "CommandLine"]),
        }
    }

    pub fn to_detail_light(&self) -> EventDetailLight {
        EventDetailLight {
            event_id: self.event_id.clone(),
            case_id: self.case_id.clone(),
            event_time_utc: self.event_time_utc.clone(),
            event_time_original: self.event_time_original.clone(),
            time_kind: self.time_kind.clone(),
            time_confidence: self.time_confidence,
            source_confidence: self.source_confidence,
            artifact_type: self.artifact_type.clone(),
            source_file_id: self.source_file_id.clone(),
            parse_run_id: self.parse_run_id.clone(),
            parser_name: self.parser_name.clone(),
            parser_version: self.parser_version.clone(),
            schema_version: self.schema_version.clone(),
            evidence_ref: self.evidence_ref.clone(),
            host: self.host.clone(),
            user_name: self.user_name.clone(),
            process_name: self.process_name.clone(),
            file_path: self.file_path.clone(),
            ip: self.ip.clone(),
            url: self.url.clone(),
            hash: self.hash.clone(),
            event_action: self.event_action.clone(),
            severity: self.severity.clone(),
            message_short: self.message_short.clone(),
            message_full: self.message_full.clone(),
            raw_record_ref: self.raw_record_ref.clone(),
            attributes_json: self.attributes_json.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RawRecord {
    pub raw_record_ref: String,
    pub case_id: String,
    pub event_id: String,
    pub parse_run_id: String,
    pub source_file_id: String,
    pub evidence_ref: String,
    pub raw_record_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactObject {
    pub object_id: String,
    pub case_id: String,
    pub event_id: String,
    pub source_file_id: String,
    pub parse_run_id: String,
    pub artifact_type: String,
    pub object_kind: String,
    pub object_key: String,
    pub display_name: String,
    pub event_time_utc: Option<String>,
    pub evidence_ref: String,
    pub evidence_offset: Option<i64>,
    pub evidence_length: Option<i64>,
    pub confidence: f64,
    pub attributes_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceOffset {
    pub offset_id: String,
    pub case_id: String,
    pub event_id: String,
    pub source_file_id: String,
    pub parse_run_id: String,
    pub object_ref: String,
    pub label: String,
    pub structure_kind: String,
    pub offset: i64,
    pub length: i64,
    pub parser_name: String,
    pub confidence: f64,
    pub attributes_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventRow {
    pub event_id: String,
    pub case_id: String,
    pub event_time_utc: String,
    pub artifact_type: String,
    pub host: Option<String>,
    pub user_name: Option<String>,
    pub process_name: Option<String>,
    pub file_path: Option<String>,
    pub ip: Option<String>,
    pub url: Option<String>,
    pub hash: Option<String>,
    pub event_code: Option<String>,
    pub channel: Option<String>,
    pub level: Option<String>,
    pub event_action: String,
    pub severity: String,
    pub message_short: String,
    pub source_file_id: String,
    pub parser_name: String,
    pub has_finding: bool,
    /// プロセス作成系イベントのコマンドライン(attributes_json 由来)。多くのイベントでは空。
    #[serde(default)]
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventDetailLight {
    pub event_id: String,
    pub case_id: String,
    pub event_time_utc: String,
    pub event_time_original: String,
    pub time_kind: String,
    pub time_confidence: f64,
    pub source_confidence: f64,
    pub artifact_type: String,
    pub source_file_id: String,
    pub parse_run_id: String,
    pub parser_name: String,
    pub parser_version: String,
    pub schema_version: String,
    pub evidence_ref: String,
    pub host: Option<String>,
    pub user_name: Option<String>,
    pub process_name: Option<String>,
    pub file_path: Option<String>,
    pub ip: Option<String>,
    pub url: Option<String>,
    pub hash: Option<String>,
    pub event_action: String,
    pub severity: String,
    pub message_short: String,
    pub message_full: String,
    pub raw_record_ref: String,
    pub attributes_json: String,
}

pub fn derive_artifact_objects_from_event(event: &EventFull) -> Vec<ArtifactObject> {
    derive_artifact_objects_from_parts(
        &event.case_id,
        &event.event_id,
        &event.source_file_id,
        &event.parse_run_id,
        &event.artifact_type,
        &event.event_time_utc,
        &event.evidence_ref,
        event.file_path.as_deref(),
        event.process_name.as_deref(),
        event.hash.as_deref(),
        event.ip.as_deref(),
        event.url.as_deref(),
        event.user_name.as_deref(),
        &event.attributes_json,
    )
}

pub fn derive_artifact_objects_from_detail(detail: &EventDetailLight) -> Vec<ArtifactObject> {
    derive_artifact_objects_from_parts(
        &detail.case_id,
        &detail.event_id,
        &detail.source_file_id,
        &detail.parse_run_id,
        &detail.artifact_type,
        &detail.event_time_utc,
        &detail.evidence_ref,
        detail.file_path.as_deref(),
        detail.process_name.as_deref(),
        detail.hash.as_deref(),
        detail.ip.as_deref(),
        detail.url.as_deref(),
        detail.user_name.as_deref(),
        &detail.attributes_json,
    )
}

pub fn derive_evidence_offsets_from_event(event: &EventFull) -> Vec<EvidenceOffset> {
    derive_evidence_offsets_from_parts(
        &event.case_id,
        &event.event_id,
        &event.source_file_id,
        &event.parse_run_id,
        &event.artifact_type,
        &event.evidence_ref,
        &event.parser_name,
        &event.attributes_json,
    )
}

pub fn derive_evidence_offsets_from_detail(detail: &EventDetailLight) -> Vec<EvidenceOffset> {
    derive_evidence_offsets_from_parts(
        &detail.case_id,
        &detail.event_id,
        &detail.source_file_id,
        &detail.parse_run_id,
        &detail.artifact_type,
        &detail.evidence_ref,
        &detail.parser_name,
        &detail.attributes_json,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventContextGroup {
    pub label: String,
    pub relation: String,
    pub value: String,
    pub rows: Vec<EventRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventContext {
    pub anchor: EventDetailLight,
    pub groups: Vec<EventContextGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimelineBin {
    pub case_id: String,
    pub granularity: String,
    pub bin_start_utc: String,
    pub artifact_type: String,
    pub event_count: i64,
    pub severity_max: Option<String>,
}

/// Read-time timeline bin computed directly from event_rows, with per-severity
/// counts. Powers the enriched timeline chart (severity-stacked bars, arbitrary
/// granularity, filterable) without a precomputed read model — so it is not
/// truncated by the timeline_bins 1000-row cap and severity is exact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventTimelineBin {
    pub bin_start_utc: String,
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
}

/// One file's NTFS $STANDARD_INFORMATION vs $FILE_NAME creation time pair.
/// Timestomping backdates $SI (easily writable) while $FN (kernel-only) keeps
/// the true value, so points off the diagonal (mismatch) are timestomp suspects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimestompPoint {
    pub file_path: String,
    pub si_created_utc: String,
    pub fn_created_utc: String,
    pub delta_seconds: i64,
    pub mismatch: bool,
}

/// A parent -> child process spawn edge with its observed count. Built from
/// process_created events (4688 / Sysmon 1); the parent image is read from the
/// event's attributes_json and normalized to a basename.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessTreeEdge {
    pub parent: String,
    pub child: String,
    pub count: i64,
}

/// One process instance in the instance-level process tree, derived from a
/// `process_created` event. The tree is returned as a flat node list; the UI
/// assembles the hierarchy from `key` / `parent_key`. `key` prefers the Sysmon
/// ProcessGuid (exact per-instance identity), falling back to a PID-derived key.
/// A node whose `parent_key` matches no other node's `key` is a root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessNode {
    pub key: String,
    pub parent_key: Option<String>,
    pub name: String,
    /// Full image path (process_name before basename), for the detail card.
    pub image: Option<String>,
    pub pid: Option<String>,
    pub guid: Option<String>,
    pub command_line: Option<String>,
    /// Image hash (SHA256/SHA1) when the source provides one (e.g. Sysmon).
    pub hash: Option<String>,
    pub user_name: Option<String>,
    pub first_seen_utc: Option<String>,
    pub event_id: String,
    pub severity: Option<String>,
    pub has_finding: bool,
    /// Titles of detections covering this process (why it's flagged).
    #[serde(default)]
    pub finding_titles: Vec<String>,
    /// Distinct ATT&CK tactics/techniques from those detections.
    #[serde(default)]
    pub attack: Vec<String>,
}

/// One non-process-creation event attributed to a process instance (same Sysmon
/// ProcessGuid): network connections, file/registry operations, etc. Powers the
/// "related activity" section of the process-tree detail drawer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessRelatedEvent {
    pub event_id: String,
    pub event_time_utc: Option<String>,
    pub artifact_type: String,
    pub event_action: String,
    pub message: Option<String>,
}

/// One time bucket of USN journal file operations, split by reason so the UI can
/// draw creates upward and deletes downward (diverging bars).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOpBin {
    pub bin_start_utc: String,
    pub created: i64,
    pub deleted: i64,
    pub renamed: i64,
    pub modified: i64,
}

/// One bucket of a beaconing-interval histogram: how many consecutive
/// connection-to-same-destination gaps fell within [lower, upper) seconds.
/// A dominant single bucket is the classic C2 fixed-interval beacon signature.
/// `top_ip` is the destination contributing the most gaps in this bucket, so the
/// UI can drill straight into that destination's events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeaconIntervalBin {
    pub label: String,
    pub lower_seconds: i64,
    pub upper_seconds: i64,
    pub count: i64,
    pub top_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntityRecord {
    pub entity_id: String,
    pub case_id: String,
    pub entity_type: String,
    pub canonical_value: String,
    pub display_name: String,
    pub host: Option<String>,
    pub first_seen_utc: Option<String>,
    pub last_seen_utc: Option<String>,
    pub event_count: i64,
    pub attributes_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EdgeRecord {
    pub edge_id: String,
    pub case_id: String,
    pub src_entity_id: String,
    pub dst_entity_id: String,
    pub edge_type: String,
    pub first_seen_utc: Option<String>,
    pub last_seen_utc: Option<String>,
    pub confidence: f64,
    pub evidence_event_ids_json: String,
    pub attributes_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subgraph {
    pub nodes: Vec<EntityRecord>,
    pub edges: Vec<EdgeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageSummary {
    pub case_id: String,
    pub artifact_type: String,
    pub total_files: i64,
    pub parsed_files: i64,
    pub failed_files: i64,
    pub unsupported_files: i64,
    pub event_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailedParserSummary {
    pub case_id: String,
    pub parser_name: String,
    pub artifact_type: String,
    pub failure_count: i64,
    pub last_error: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingRecord {
    pub detection_id: String,
    pub case_id: String,
    pub engine: String,
    pub rule_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub attack_json: String,
    pub event_ids_json: String,
    pub entity_ids_json: String,
    pub first_seen_utc: Option<String>,
    pub message: Option<String>,
    /// Rule-level enrichment as JSON: {description, references[], falsepositives[],
    /// matched[], rule_level, tactics[]}. Empty "{}" when unavailable.
    #[serde(default)]
    pub enrichment_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingSummary {
    pub case_id: String,
    pub title: String,
    pub severity: String,
    pub engine: String,
    pub rule_id: Option<String>,
    pub attack_json: String,
    pub finding_count: i64,
    pub event_count: i64,
    pub first_seen_utc: Option<String>,
    pub last_seen_utc: Option<String>,
    pub sample_message: Option<String>,
    /// Carried from the first finding in the group (rule-level enrichment JSON).
    #[serde(default)]
    pub enrichment_json: Option<String>,
    /// Distinct affected entities across the group: "host:X" / "user:Y" / "process:Z".
    #[serde(default)]
    pub affected_entities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnswerCandidate {
    pub candidate_id: String,
    pub case_id: String,
    pub question_key: String,
    pub question_label: String,
    pub candidate_value: String,
    pub confidence: f64,
    pub status: String,
    pub severity: String,
    pub category: String,
    pub reason: String,
    pub evidence_event_ids_json: String,
    pub evidence_refs_json: String,
    pub missing_steps_json: String,
    pub next_action: Option<String>,
    pub first_seen_utc: Option<String>,
    pub last_seen_utc: Option<String>,
    pub attributes_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionObjectiveEvaluation {
    pub objective_id: String,
    pub objective_name: String,
    pub status: String,
    pub severity_max: Option<String>,
    pub finding_count: i64,
    pub event_count: i64,
    pub artifact_types: String,
    pub attack_techniques: String,
    pub evidence_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaseQualityGate {
    pub gate_id: String,
    pub category: String,
    pub status: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub metric: String,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaseDetectionEvaluation {
    pub case_id: String,
    pub evaluated_at: String,
    pub overall_score: f64,
    pub detection_coverage_rate: f64,
    pub investigation_readiness_score: f64,
    pub report_quality_score: f64,
    pub applicable_objective_count: i64,
    pub covered_objective_count: i64,
    pub partial_objective_count: i64,
    pub missing_objective_count: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub confirmed_findings: i64,
    pub open_findings: i64,
    pub unreviewed_high_findings: i64,
    pub correlation_chain_count: i64,
    pub high_correlation_chain_count: i64,
    pub risk_technique_count: i64,
    pub parsed_file_rate: f64,
    pub evidence_verification_rate: f64,
    pub parser_gap_count: i64,
    pub unsupported_file_count: i64,
    pub report_gap_count: i64,
    pub objectives: Vec<DetectionObjectiveEvaluation>,
    pub quality_gates: Vec<CaseQualityGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IocHit {
    pub case_id: String,
    pub ioc: String,
    pub match_kind: String,
    pub hit_count: i64,
    pub artifact_types: String,
    pub event_ids_json: String,
    pub first_seen_utc: Option<String>,
    pub last_seen_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingOverride {
    pub override_id: String,
    pub case_id: String,
    pub enabled: bool,
    pub action: String,
    pub engine: Option<String>,
    pub rule_id: Option<String>,
    pub title: Option<String>,
    pub severity: Option<String>,
    pub reason: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingReview {
    pub review_id: String,
    pub case_id: String,
    pub engine: String,
    pub rule_id: Option<String>,
    pub title: String,
    pub status: String,
    pub reviewer: Option<String>,
    pub assignee: Option<String>,
    pub tags_json: Option<String>,
    pub due_at: Option<String>,
    pub comment: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseApprovalRecord {
    pub approval_id: String,
    pub case_id: String,
    pub target_kind: String,
    pub target_id: Option<String>,
    pub target_path: Option<String>,
    pub target_sha256: Option<String>,
    pub status: String,
    pub approver: Option<String>,
    pub role: Option<String>,
    pub comment: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingReviewSummary {
    pub case_id: String,
    pub total_reviews: i64,
    pub new_count: i64,
    pub in_review_count: i64,
    pub confirmed_count: i64,
    pub false_positive_count: i64,
    pub benign_count: i64,
    pub needs_context_count: i64,
    pub open_count: i64,
    pub overdue_count: i64,
    pub unassigned_count: i64,
    pub tagged_count: i64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriageAction {
    pub action_id: String,
    pub case_id: String,
    pub priority: i64,
    pub category: String,
    pub title: String,
    pub reason: String,
    pub severity: String,
    pub status: String,
    pub source_kind: String,
    pub source_key: String,
    pub event_count: i64,
    pub first_seen_utc: Option<String>,
    pub last_seen_utc: Option<String>,
    pub evidence_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub audit_id: String,
    pub case_id: String,
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub target_kind: String,
    pub target_id: Option<String>,
    pub summary: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventBookmark {
    pub bookmark_id: String,
    pub case_id: String,
    pub event_id: String,
    pub label: Option<String>,
    pub note: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskSummary {
    pub case_id: String,
    pub technique: String,
    pub severity_max: Option<String>,
    pub finding_count: i64,
    pub event_count: i64,
    pub first_seen_utc: Option<String>,
    pub last_seen_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalyzerRunSummary {
    pub run_id: String,
    pub case_id: String,
    pub analyzer_id: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub input_count: i64,
    pub output_count: i64,
    pub error_message: Option<String>,
    pub metadata_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationSummary {
    pub case_id: String,
    pub key_kind: String,
    pub key_value: String,
    pub user_name: Option<String>,
    pub host: Option<String>,
    pub ip: Option<String>,
    pub file_path: Option<String>,
    pub artifact_types: String,
    pub event_count: i64,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    pub severity_max: Option<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationChainSummary {
    pub case_id: String,
    pub key_kind: String,
    pub key_value: String,
    pub title: String,
    pub severity: String,
    pub artifact_types: String,
    pub event_count: i64,
    pub step_count: i64,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    pub severity_max: Option<String>,
    pub score: i64,
    pub explanation: String,
    pub steps_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationChainEventPageQuery {
    pub key_kind: String,
    pub key_value: String,
    pub page: EventPageQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IocEventPageQuery {
    pub ioc: String,
    pub page: EventPageQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefenderSummary {
    pub case_id: String,
    pub category: String,
    pub severity_max: Option<String>,
    pub event_count: i64,
    pub artifact_types: String,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    pub sample_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefenderEventPageQuery {
    pub category: Option<String>,
    pub page: EventPageQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefetchSummary {
    pub case_id: String,
    pub process_name: String,
    pub file_path: Option<String>,
    pub prefetch_file_name: Option<String>,
    pub prefetch_hash: Option<String>,
    pub run_count_max: Option<i64>,
    pub referenced_file_count_max: Option<i64>,
    pub source_file_count: i64,
    pub event_count: i64,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    pub severity_max: Option<String>,
    pub actions: String,
    pub suspicion: Option<String>,
    pub sample_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserActivitySummary {
    pub case_id: String,
    pub user_name: String,
    pub event_count: i64,
    pub host_count: i64,
    pub artifact_types: String,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    pub severity_max: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParserErrorRecord {
    pub case_id: String,
    pub parse_run_id: String,
    pub file_id: String,
    pub parser_name: String,
    pub error_message: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsupportedFileRecord {
    pub case_id: String,
    pub file_id: String,
    pub artifact_type: String,
    pub reason: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Page<T> {
    pub rows: Vec<T>,
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    pub fn empty() -> Self {
        Self {
            rows: Vec::new(),
            next_cursor: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventPageQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
    pub artifact_type: Option<String>,
    pub user_name: Option<String>,
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub sort_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventFacetValue {
    pub field: String,
    pub value: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedSearch {
    pub search_id: String,
    pub case_id: String,
    pub name: String,
    pub query: EventPageQuery,
    pub description: Option<String>,
    pub created_by: Option<String>,
    #[serde(default = "default_saved_search_visibility")]
    pub visibility: String,
    #[serde(default)]
    pub shared_with: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn default_saved_search_visibility() -> String {
    "case".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventContextQuery {
    pub event_id: String,
    pub window_minutes: Option<i64>,
    pub per_group_limit: Option<usize>,
    pub same_host_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventExportResult {
    pub output_path: String,
    pub format: String,
    pub row_count: i64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEventPageQuery {
    pub title: String,
    pub engine: Option<String>,
    pub rule_id: Option<String>,
    pub page: EventPageQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilePageQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

pub fn bounded_limit(value: Option<usize>, default: usize, max: usize) -> usize {
    value.unwrap_or(default).clamp(1, max)
}

fn attr_string(attributes_json: &str, keys: &[&str]) -> Option<String> {
    let parsed = serde_json::from_str::<serde_json::Value>(attributes_json).ok()?;
    for key in keys {
        let Some(value) = parsed.get(*key) else {
            continue;
        };
        let out = match value {
            serde_json::Value::String(value) => value.trim().to_string(),
            serde_json::Value::Number(value) => value.to_string(),
            serde_json::Value::Bool(value) => value.to_string(),
            _ => continue,
        };
        if !out.is_empty() && out != "-" {
            return Some(out);
        }
    }
    None
}

fn attr_i64(attributes_json: &str, keys: &[&str]) -> Option<i64> {
    let parsed = serde_json::from_str::<serde_json::Value>(attributes_json).ok()?;
    for key in keys {
        let Some(value) = parsed.get(*key) else {
            continue;
        };
        let out = match value {
            serde_json::Value::Number(value) => {
                value.as_i64().or_else(|| value.as_u64().map(|v| v as i64))
            }
            serde_json::Value::String(value) => value.trim().parse::<i64>().ok(),
            _ => None,
        };
        if out.is_some() {
            return out;
        }
    }
    None
}

fn value_i64(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(value) => {
            value.as_i64().or_else(|| value.as_u64().map(|v| v as i64))
        }
        serde_json::Value::String(value) => value.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn derive_artifact_objects_from_parts(
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    file_path: Option<&str>,
    process_name: Option<&str>,
    hash: Option<&str>,
    ip: Option<&str>,
    url: Option<&str>,
    user_name: Option<&str>,
    attributes_json: &str,
) -> Vec<ArtifactObject> {
    let mut rows = Vec::new();
    let record_offset = attr_i64(attributes_json, &["record_offset", "offset"]);
    let record_length = attr_i64(
        attributes_json,
        &["record_size", "record_length", "structure_length", "length"],
    );

    match artifact_type {
        "mft" => {
            if let Some(record_number) =
                attr_i64(attributes_json, &["record_number", "entry_number"])
            {
                let sequence = attr_i64(attributes_json, &["sequence_number"])
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string());
                push_artifact_object(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    record_offset,
                    record_length,
                    attributes_json,
                    "ntfs_file_record",
                    format!("mft:{record_number}:{sequence}"),
                    file_path
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("MFT record {record_number}")),
                    0.95,
                );
                push_mft_structure_objects(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    attributes_json,
                    record_number,
                    &sequence,
                    record_offset,
                    record_length,
                );
                push_mft_resident_content_object(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    attributes_json,
                    file_path,
                    record_number,
                    &sequence,
                    record_offset,
                );
            }
        }
        "usn_jrnl" => {
            if let Some(usn) = attr_i64(attributes_json, &["usn", "USN"]) {
                push_artifact_object(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    record_offset,
                    record_length,
                    attributes_json,
                    "usn_record",
                    format!("usn:{usn}"),
                    file_path
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("USN {usn}")),
                    0.95,
                );
            } else if let Some(offset) = record_offset {
                push_artifact_object(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    record_offset,
                    record_length,
                    attributes_json,
                    "usn_record",
                    format!("usn_offset:{offset}"),
                    file_path
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("USN record offset {offset}")),
                    0.9,
                );
            }
        }
        "prefetch" => {
            if let Some(process) = process_name
                .map(str::to_string)
                .or_else(|| attr_string(attributes_json, &["process_name", "executable_name"]))
            {
                let pf_hash =
                    attr_string(attributes_json, &["prefetch_hash"]).unwrap_or_else(|| "-".into());
                push_artifact_object(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    record_offset,
                    record_length,
                    attributes_json,
                    "prefetch_execution",
                    format!("prefetch:{}:{pf_hash}", process.to_ascii_lowercase()),
                    process,
                    0.9,
                );
            }
            push_prefetch_section_objects(
                &mut rows,
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                artifact_type,
                event_time_utc,
                evidence_ref,
                attributes_json,
            );
        }
        "lnk" | "jumplist" => {
            let target = file_path
                .map(str::to_string)
                .or_else(|| attr_string(attributes_json, &["target_path", "local_base_path"]));
            if let Some(target) = target {
                push_artifact_object(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    record_offset,
                    record_length,
                    attributes_json,
                    if artifact_type == "lnk" {
                        "shell_link_target"
                    } else {
                        "jumplist_target"
                    },
                    format!("{}:{}", artifact_type, target.to_ascii_lowercase()),
                    target,
                    0.85,
                );
            }
            if artifact_type == "lnk" {
                push_lnk_extra_block_objects(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    attributes_json,
                );
            }
        }
        "registry" | "amcache" => {
            let registry_key = attr_string(
                attributes_json,
                &["registry_key", "key_path", "key_hint", "source_path"],
            )
            .or_else(|| file_path.map(str::to_string));
            if let Some(registry_key) = registry_key {
                push_artifact_object(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    record_offset,
                    record_length,
                    attributes_json,
                    if artifact_type == "amcache" {
                        "amcache_entry"
                    } else {
                        "registry_value"
                    },
                    format!("{}:{}", artifact_type, registry_key.to_ascii_lowercase()),
                    registry_key,
                    0.8,
                );
            }
        }
        "srum" | "web_cache" | "ese" => {
            let resource = url
                .map(str::to_string)
                .or_else(|| ip.map(str::to_string))
                .or_else(|| file_path.map(str::to_string))
                .or_else(|| attr_string(attributes_json, &["resource", "string", "source_path"]));
            if let Some(resource) = resource {
                push_artifact_object(
                    &mut rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    record_offset,
                    record_length,
                    attributes_json,
                    "ese_row_signal",
                    format!("{}:{}", artifact_type, resource.to_ascii_lowercase()),
                    resource,
                    0.65,
                );
            }
            push_ese_structure_objects(
                &mut rows,
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                artifact_type,
                event_time_utc,
                evidence_ref,
                attributes_json,
            );
        }
        _ => {}
    }

    push_evtx_semantic_objects(
        &mut rows,
        case_id,
        event_id,
        source_file_id,
        parse_run_id,
        artifact_type,
        event_time_utc,
        evidence_ref,
        attributes_json,
    );
    push_sidecar_output_objects(
        &mut rows,
        case_id,
        event_id,
        source_file_id,
        parse_run_id,
        artifact_type,
        event_time_utc,
        evidence_ref,
        file_path,
        hash,
        url,
        user_name,
        attributes_json,
    );

    for (kind, value) in [
        ("file_reference", file_path),
        ("process_reference", process_name),
        ("hash_reference", hash),
        ("ip_reference", ip),
        ("url_reference", url),
        ("user_reference", user_name),
    ] {
        let Some(value) = value
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != "-")
        else {
            continue;
        };
        if rows
            .iter()
            .any(|row| row.object_kind == kind || row.display_name.eq_ignore_ascii_case(value))
        {
            continue;
        }
        push_artifact_object(
            &mut rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            record_offset,
            record_length,
            attributes_json,
            kind,
            format!("{kind}:{}", value.to_ascii_lowercase()),
            value.to_string(),
            0.6,
        );
    }

    rows
}

#[allow(clippy::too_many_arguments)]
fn push_evtx_semantic_objects(
    rows: &mut Vec<ArtifactObject>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    attributes_json: &str,
) {
    if artifact_type != "evtx" && artifact_type != "hayabusa" {
        return;
    }
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return;
    };
    let Some(semantics) = parsed.get("semantics").filter(|value| value.is_object()) else {
        return;
    };
    let event_kind = semantics
        .get("event_kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("windows_event");
    let event_id_value = parsed
        .get("event_id")
        .and_then(json_value_string_ref)
        .unwrap_or("-");
    if matches!(
        event_kind,
        "kerberos_as_request" | "kerberos_tgs_request" | "kerberos_preauth_failed"
    ) {
        let target = json_nested_string(&parsed, &["data", "TargetUserName"])
            .or_else(|| json_nested_string(&parsed, &["data", "AccountName"]))
            .unwrap_or_else(|| "-".to_string());
        let service = semantics
            .get("service_name")
            .and_then(json_value_string_ref)
            .unwrap_or("-");
        let enc = semantics
            .get("ticket_encryption_name")
            .and_then(json_value_string_ref)
            .unwrap_or("-");
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            None,
            None,
            attributes_json,
            "kerberos_ticket_request",
            format!("kerberos:{event_id_value}:{target}:{service}:{enc}").to_ascii_lowercase(),
            format!("Kerberos {event_kind} user={target} service={service} enc={enc}"),
            if semantic_labels_contain(semantics, "kerberoast_candidate")
                || semantic_labels_contain(semantics, "asrep_roast_candidate")
            {
                0.9
            } else {
                0.75
            },
        );
    }
    if event_kind.starts_with("firewall_") {
        let rule = semantics
            .get("rule_name")
            .and_then(json_value_string_ref)
            .map(str::to_string)
            .or_else(|| json_nested_string(&parsed, &["data", "RuleName"]))
            .unwrap_or_else(|| "-".to_string());
        let direction = semantics
            .get("firewall_direction")
            .and_then(json_value_string_ref)
            .unwrap_or("-");
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            None,
            None,
            attributes_json,
            "firewall_rule_or_flow",
            format!("firewall:{event_kind}:{rule}:{direction}").to_ascii_lowercase(),
            format!("Firewall {event_kind} rule={rule} direction={direction}"),
            0.74,
        );
    }
    if event_kind.contains("audit_policy") || event_kind == "privilege_rights_changed" {
        let subcategory = semantics
            .get("audit_subcategory")
            .and_then(json_value_string_ref)
            .unwrap_or("-");
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            None,
            None,
            attributes_json,
            "audit_policy_change",
            format!("audit_policy:{event_kind}:{subcategory}").to_ascii_lowercase(),
            format!("Audit policy {event_kind} {subcategory}"),
            0.76,
        );
    }
    if event_kind.starts_with("rdp_") {
        let user = json_nested_string(&parsed, &["data", "TargetUserName"])
            .or_else(|| json_nested_string(&parsed, &["data", "User"]))
            .unwrap_or_else(|| "-".to_string());
        let ip = json_nested_string(&parsed, &["data", "IpAddress"])
            .or_else(|| json_nested_string(&parsed, &["data", "ClientAddress"]))
            .unwrap_or_else(|| "-".to_string());
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            None,
            None,
            attributes_json,
            "rdp_logon_observation",
            format!("rdp:{user}:{ip}:{event_time_utc}").to_ascii_lowercase(),
            format!("RDP {event_kind} user={user} ip={ip}"),
            0.82,
        );
    }
    if let Some(pipe) = semantics.get("pipe_name").and_then(json_value_string_ref) {
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            None,
            None,
            attributes_json,
            "named_pipe_observation",
            format!("named_pipe:{pipe}").to_ascii_lowercase(),
            format!("Named pipe {pipe}"),
            if pipe.to_ascii_lowercase().contains("psexesvc") {
                0.88
            } else {
                0.68
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_sidecar_output_objects(
    rows: &mut Vec<ArtifactObject>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    file_path: Option<&str>,
    hash: Option<&str>,
    url: Option<&str>,
    user_name: Option<&str>,
    attributes_json: &str,
) {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return;
    };
    let Some(record_kind) = parsed
        .get("sidecar_record_kind")
        .and_then(json_value_string_ref)
    else {
        return;
    };
    let object_attrs = attributes_json;
    match record_kind {
        "deleted_file_recovered"
        | "carved_file_recovered"
        | "carved_file_hash"
        | "archive_member_extracted" => {
            let recovered = parsed
                .get("recovered_path")
                .and_then(json_value_string_ref)
                .or_else(|| parsed.get("member_path").and_then(json_value_string_ref))
                .or(file_path)
                .unwrap_or("recovered-file");
            push_artifact_object(
                rows,
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                artifact_type,
                event_time_utc,
                evidence_ref,
                None,
                parsed.get("size").and_then(value_i64),
                object_attrs,
                "recovered_file",
                format!(
                    "recovered_file:{}:{}",
                    hash.unwrap_or("-"),
                    recovered.to_ascii_lowercase()
                ),
                recovered.to_string(),
                0.82,
            );
        }
        "keepass_entry_decrypted"
        | "keepass_entry_candidate"
        | "browser_secret_decrypted"
        | "browser_login_candidate"
        | "browser_encrypted_secret_candidate"
        | "dpapi_masterkey_candidate" => {
            let origin = parsed
                .get("origin_url")
                .and_then(json_value_string_ref)
                .or(url)
                .unwrap_or("-");
            let username = parsed
                .get("username")
                .and_then(json_value_string_ref)
                .or(user_name)
                .unwrap_or("-");
            let title = parsed
                .get("title")
                .and_then(json_value_string_ref)
                .or_else(|| parsed.get("Title").and_then(json_value_string_ref))
                .unwrap_or(record_kind);
            push_artifact_object(
                rows,
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                artifact_type,
                event_time_utc,
                evidence_ref,
                None,
                None,
                object_attrs,
                "credential_store_entry",
                format!("credential:{record_kind}:{origin}:{username}:{title}")
                    .to_ascii_lowercase(),
                format!("Credential entry {title} origin={origin} user={username}"),
                if record_kind.ends_with("_decrypted") {
                    0.88
                } else {
                    0.62
                },
            );
        }
        "pcap_conversation_reconstructed" | "network_conversation_reconstructed" => {
            let flow_path = parsed
                .get("flow_path")
                .and_then(json_value_string_ref)
                .or_else(|| parsed.get("output_path").and_then(json_value_string_ref))
                .unwrap_or("pcap-conversation");
            push_artifact_object(
                rows,
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                artifact_type,
                event_time_utc,
                evidence_ref,
                None,
                None,
                object_attrs,
                "reconstructed_network_conversation",
                format!("conversation:{flow_path}").to_ascii_lowercase(),
                flow_path.to_string(),
                0.84,
            );
        }
        _ => {
            if let Some(output_dir) = parsed
                .get("sidecar_output_dir")
                .and_then(json_value_string_ref)
            {
                push_artifact_object(
                    rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    None,
                    None,
                    object_attrs,
                    "sidecar_output",
                    format!("sidecar:{record_kind}:{output_dir}").to_ascii_lowercase(),
                    format!("{record_kind} output"),
                    0.5,
                );
            }
        }
    }
}

fn json_nested_string(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    json_value_string_ref(current).map(str::to_string)
}

fn json_value_string_ref(value: &serde_json::Value) -> Option<&str> {
    value
        .as_str()
        .filter(|value| !value.trim().is_empty() && *value != "-")
}

fn semantic_labels_contain(semantics: &serde_json::Value, label: &str) -> bool {
    semantics
        .get("labels")
        .and_then(serde_json::Value::as_array)
        .map(|labels| labels.iter().any(|value| value.as_str() == Some(label)))
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn push_mft_structure_objects(
    rows: &mut Vec<ArtifactObject>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    attributes_json: &str,
    record_number: i64,
    sequence: &str,
    record_offset: Option<i64>,
    record_length: Option<i64>,
) {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return;
    };
    let Some(attributes) = parsed
        .get("attributes")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    for attribute in attributes.iter().take(24) {
        let attr_type_name = attribute
            .get("type_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("UNKNOWN");
        let attr_id = attribute
            .get("id")
            .and_then(value_i64)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let attr_offset = attribute.get("offset").and_then(value_i64);
        let attr_length = attribute.get("length").and_then(value_i64);
        let evidence_offset = match (record_offset, attr_offset) {
            (Some(base), Some(offset)) => Some(base.saturating_add(offset)),
            _ => record_offset,
        };
        let object_attrs = serde_json::json!({
            "record_number": record_number,
            "sequence_number": sequence,
            "attribute": attribute,
        })
        .to_string();
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            evidence_offset,
            attr_length.or(record_length),
            &object_attrs,
            "ntfs_attribute",
            format!("mft_attr:{record_number}:{sequence}:{attr_id}:{attr_type_name}"),
            format!("MFT {record_number} {attr_type_name} attr#{attr_id}"),
            0.88,
        );
    }

    let Some(data_runs) = parsed
        .get("data_runs")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    for data_run in data_runs.iter().take(16) {
        let run_index = data_run
            .get("run_index")
            .and_then(value_i64)
            .unwrap_or_default();
        let attr_id = data_run
            .get("attribute_id")
            .and_then(value_i64)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let runlist_offset = data_run.get("runlist_record_offset").and_then(value_i64);
        let evidence_offset = match (record_offset, runlist_offset) {
            (Some(base), Some(offset)) => Some(base.saturating_add(offset)),
            _ => record_offset,
        };
        let clusters = data_run
            .get("cluster_count")
            .and_then(value_i64)
            .unwrap_or_default();
        let lcn = data_run
            .get("lcn")
            .and_then(value_i64)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "sparse".to_string());
        let object_attrs = serde_json::json!({
            "record_number": record_number,
            "sequence_number": sequence,
            "data_run": data_run,
        })
        .to_string();
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            evidence_offset,
            Some(16),
            &object_attrs,
            "ntfs_data_run",
            format!("mft_run:{record_number}:{sequence}:{attr_id}:{run_index}"),
            format!("MFT {record_number} DATA run#{run_index} LCN {lcn} clusters {clusters}"),
            0.8,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_mft_resident_content_object(
    rows: &mut Vec<ArtifactObject>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    attributes_json: &str,
    file_path: Option<&str>,
    record_number: i64,
    sequence: &str,
    record_offset: Option<i64>,
) {
    let Some(value_offset) = attr_i64(attributes_json, &["resident_value_offset"]) else {
        return;
    };
    let Some(value_length) = attr_i64(attributes_json, &["resident_value_length"]) else {
        return;
    };
    let stream_kind =
        attr_string(attributes_json, &["stream_kind"]).unwrap_or_else(|| "resident_data".into());
    let stream_name = attr_string(attributes_json, &["stream_name"]);
    let sha256 = attr_string(attributes_json, &["resident_sha256", "sha256"])
        .unwrap_or_else(|| "-".to_string());
    let evidence_offset = record_offset.map(|base| base.saturating_add(value_offset));
    let object_kind = if stream_kind.eq_ignore_ascii_case("ads") {
        "ntfs_ads_resident_content"
    } else {
        "ntfs_resident_content"
    };
    let stream_label = stream_name
        .as_deref()
        .map(|name| format!(":{name}"))
        .unwrap_or_default();
    let display_name = file_path
        .map(str::to_string)
        .unwrap_or_else(|| format!("MFT record {record_number}{stream_label}"));
    let host_url = attr_string(attributes_json, &["HostUrl", "host_url"]);
    let display_name = if let Some(host_url) = host_url {
        format!("{display_name} HostUrl={host_url}")
    } else {
        display_name
    };
    push_artifact_object(
        rows,
        case_id,
        event_id,
        source_file_id,
        parse_run_id,
        artifact_type,
        event_time_utc,
        evidence_ref,
        evidence_offset,
        Some(value_length.clamp(1, 64 * 1024)),
        attributes_json,
        object_kind,
        format!(
            "mft_resident:{record_number}:{sequence}:{}:{sha256}",
            stream_name.as_deref().unwrap_or("$DATA")
        )
        .to_ascii_lowercase(),
        display_name,
        if object_kind == "ntfs_ads_resident_content" {
            0.9
        } else {
            0.78
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn push_prefetch_section_objects(
    rows: &mut Vec<ArtifactObject>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    attributes_json: &str,
) {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return;
    };
    let process = parsed
        .get("executable_name_header")
        .or_else(|| parsed.get("prefetch_file_name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("prefetch");
    let hash = parsed
        .get("prefetch_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let Some(sections) = parsed.get("sections").and_then(serde_json::Value::as_array) else {
        return;
    };
    for section in sections.iter().take(16) {
        let name = section
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("section");
        let offset = section.get("offset").and_then(value_i64);
        let length = section.get("length").and_then(value_i64);
        let confidence = section
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.7);
        let object_attrs = serde_json::json!({
            "process": process,
            "prefetch_hash": hash,
            "section": section,
        })
        .to_string();
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            offset,
            length,
            &object_attrs,
            "prefetch_section",
            format!(
                "prefetch_section:{}:{hash}:{name}",
                process.to_ascii_lowercase()
            ),
            format!("Prefetch {process} {name}"),
            confidence,
        );
    }
    if let Some(offset) = parsed.get("run_count_offset").and_then(value_i64) {
        let run_count = parsed.get("run_count").and_then(value_i64);
        let object_attrs = serde_json::json!({
            "process": process,
            "prefetch_hash": hash,
            "run_count": run_count,
            "run_count_offset": offset,
        })
        .to_string();
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            Some(offset),
            Some(4),
            &object_attrs,
            "prefetch_run_count",
            format!("prefetch_run_count:{}:{hash}", process.to_ascii_lowercase()),
            format!("Prefetch {process} run count"),
            0.8,
        );
    }
    if let Some(entries) = parsed
        .get("run_time_entries")
        .and_then(serde_json::Value::as_array)
    {
        for entry in entries.iter().take(16) {
            let Some(offset) = entry.get("offset").and_then(value_i64) else {
                continue;
            };
            let timestamp = entry
                .get("timestamp")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");
            let confidence = entry
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.8);
            let object_attrs = serde_json::json!({
                "process": process,
                "prefetch_hash": hash,
                "run_time_entry": entry,
            })
            .to_string();
            push_artifact_object(
                rows,
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                artifact_type,
                event_time_utc,
                evidence_ref,
                Some(offset),
                Some(8),
                &object_attrs,
                "prefetch_run_time",
                format!(
                    "prefetch_run_time:{}:{hash}:{timestamp}",
                    process.to_ascii_lowercase()
                ),
                format!("Prefetch {process} run time {timestamp}"),
                confidence,
            );
        }
    }
    if let Some(metrics) = parsed
        .get("file_metrics")
        .and_then(serde_json::Value::as_array)
    {
        for metric in metrics.iter().take(32) {
            let Some(offset) = metric.get("offset").and_then(value_i64) else {
                continue;
            };
            let index = metric.get("index").and_then(value_i64).unwrap_or_default();
            let length = metric.get("length").and_then(value_i64).unwrap_or(32);
            let filename = metric
                .get("filename")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");
            let object_attrs = serde_json::json!({
                "process": process,
                "prefetch_hash": hash,
                "offset_basis": parsed.get("offset_basis"),
                "file_metric": metric,
            })
            .to_string();
            push_artifact_object(
                rows,
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                artifact_type,
                event_time_utc,
                evidence_ref,
                Some(offset),
                Some(length),
                &object_attrs,
                "prefetch_file_metric",
                format!(
                    "prefetch_file_metric:{}:{hash}:{index}:{filename}",
                    process.to_ascii_lowercase()
                ),
                format!("Prefetch {process} file metric #{index} {filename}"),
                metric
                    .get("confidence")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.78),
            );
        }
    }
    if let Some(chains) = parsed
        .get("trace_chains")
        .and_then(serde_json::Value::as_array)
    {
        for chain in chains.iter().take(32) {
            let Some(offset) = chain.get("offset").and_then(value_i64) else {
                continue;
            };
            let index = chain.get("index").and_then(value_i64).unwrap_or_default();
            let length = chain.get("length").and_then(value_i64).unwrap_or(8);
            let block_count = chain
                .get("block_load_count")
                .and_then(value_i64)
                .unwrap_or_default();
            let object_attrs = serde_json::json!({
                "process": process,
                "prefetch_hash": hash,
                "offset_basis": parsed.get("offset_basis"),
                "trace_chain": chain,
            })
            .to_string();
            push_artifact_object(
                rows,
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                artifact_type,
                event_time_utc,
                evidence_ref,
                Some(offset),
                Some(length),
                &object_attrs,
                "prefetch_trace_chain",
                format!(
                    "prefetch_trace_chain:{}:{hash}:{index}",
                    process.to_ascii_lowercase()
                ),
                format!("Prefetch {process} trace chain #{index} blocks {block_count}"),
                chain
                    .get("confidence")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.74),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_lnk_extra_block_objects(
    rows: &mut Vec<ArtifactObject>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    attributes_json: &str,
) {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return;
    };
    let Some(blocks) = parsed
        .get("extra_data_blocks")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    for block in blocks.iter().take(16) {
        let signature_name = block
            .get("signature_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("UnknownExtraDataBlock");
        let signature = block
            .get("signature")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let offset = block.get("offset").and_then(value_i64);
        let length = block.get("length").and_then(value_i64);
        let confidence = block
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.75);
        let object_attrs = serde_json::json!({ "extra_data_block": block }).to_string();
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            offset,
            length,
            &object_attrs,
            "lnk_extra_block",
            format!("lnk_extra:{event_id}:{signature}:{offset:?}"),
            format!("LNK {signature_name}"),
            confidence,
        );
        if let Some(properties) = block
            .get("property_entries")
            .and_then(serde_json::Value::as_array)
        {
            for property in properties.iter().take(32) {
                let Some(key) = property
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                else {
                    continue;
                };
                let value_hint = property
                    .get("value_hint")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("-");
                let value_offset = property.get("value_offset").and_then(value_i64).or(offset);
                let value_length = property
                    .get("value_length")
                    .and_then(value_i64)
                    .or(Some(32));
                let confidence = property
                    .get("confidence")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.6);
                let object_attrs = serde_json::json!({
                    "property_entry": property,
                    "extra_data_signature": signature,
                    "extra_data_signature_name": signature_name,
                })
                .to_string();
                push_artifact_object(
                    rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    value_offset,
                    value_length,
                    &object_attrs,
                    "lnk_property_value",
                    format!(
                        "lnk_property:{}:{}",
                        key.to_ascii_lowercase(),
                        value_hint.to_ascii_lowercase()
                    ),
                    if value_hint == "-" {
                        format!("LNK property {key}")
                    } else {
                        format!("LNK property {key}={value_hint}")
                    },
                    confidence,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_ese_structure_objects(
    rows: &mut Vec<ArtifactObject>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    attributes_json: &str,
) {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return;
    };
    if let Some(header) = parsed.get("ese_header").filter(|value| value.is_object()) {
        let offset = header.get("offset").and_then(value_i64).unwrap_or(0);
        let length = header.get("length").and_then(value_i64).unwrap_or(4096);
        let object_attrs = serde_json::json!({ "ese_header": header }).to_string();
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            Some(offset),
            Some(length),
            &object_attrs,
            "ese_database_header",
            format!("ese_header:{source_file_id}"),
            "ESE database header".to_string(),
            0.75,
        );
    }
    let Some(pages) = parsed
        .get("ese_pages")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    for page in pages.iter().take(8) {
        let page_number = page
            .get("page_number")
            .and_then(value_i64)
            .unwrap_or_default();
        let offset = page.get("offset").and_then(value_i64);
        let length = page.get("length").and_then(value_i64);
        let confidence = page
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.55);
        let object_attrs = serde_json::json!({ "ese_page": page }).to_string();
        push_artifact_object(
            rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            artifact_type,
            event_time_utc,
            evidence_ref,
            offset,
            length,
            &object_attrs,
            "ese_database_page",
            format!("ese_page:{source_file_id}:{page_number}"),
            format!("ESE page {page_number}"),
            confidence,
        );
        if let Some(tags) = page.get("tags").and_then(serde_json::Value::as_array) {
            for tag in tags.iter().take(64) {
                let tag_index = tag.get("tag_index").and_then(value_i64).unwrap_or_default();
                let absolute_offset =
                    tag.get("absolute_offset").and_then(value_i64).or_else(|| {
                        tag.get("offset")
                            .and_then(value_i64)
                            .and_then(|tag_offset| {
                                offset.map(|page_offset| page_offset + tag_offset)
                            })
                    });
                let length = tag.get("length").and_then(value_i64).or(Some(16));
                let confidence = tag
                    .get("confidence")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.6);
                let object_attrs = serde_json::json!({
                    "ese_page_number": page_number,
                    "ese_page_tag": tag,
                })
                .to_string();
                push_artifact_object(
                    rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    absolute_offset,
                    length,
                    &object_attrs,
                    "ese_page_tag",
                    format!("ese_tag:{source_file_id}:{page_number}:{tag_index}"),
                    format!("ESE page {page_number} tag {tag_index}"),
                    confidence,
                );
            }
        }
        if let Some(hints) = page
            .get("table_name_hints")
            .and_then(serde_json::Value::as_array)
        {
            for hint in hints.iter().filter_map(serde_json::Value::as_str).take(12) {
                let object_attrs = serde_json::json!({
                    "ese_page_number": page_number,
                    "table_name_hint": hint,
                })
                .to_string();
                push_artifact_object(
                    rows,
                    case_id,
                    event_id,
                    source_file_id,
                    parse_run_id,
                    artifact_type,
                    event_time_utc,
                    evidence_ref,
                    offset,
                    length,
                    &object_attrs,
                    "ese_table_hint",
                    format!("ese_table:{}:{}", artifact_type, hint.to_ascii_lowercase()),
                    format!("ESE table hint {hint}"),
                    0.5,
                );
            }
        }
    }
}

fn push_artifact_object(
    rows: &mut Vec<ArtifactObject>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    event_time_utc: &str,
    evidence_ref: &str,
    evidence_offset: Option<i64>,
    evidence_length: Option<i64>,
    attributes_json: &str,
    object_kind: &str,
    object_key: String,
    display_name: String,
    confidence: f64,
) {
    if object_key.trim().is_empty() || display_name.trim().is_empty() {
        return;
    }
    rows.push(ArtifactObject {
        object_id: new_id("aobj"),
        case_id: case_id.to_string(),
        event_id: event_id.to_string(),
        source_file_id: source_file_id.to_string(),
        parse_run_id: parse_run_id.to_string(),
        artifact_type: artifact_type.to_string(),
        object_kind: object_kind.to_string(),
        object_key,
        display_name,
        event_time_utc: Some(event_time_utc.to_string()),
        evidence_ref: evidence_ref.to_string(),
        evidence_offset,
        evidence_length,
        confidence,
        attributes_json: attributes_json.to_string(),
    });
}

fn derive_evidence_offsets_from_parts(
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    artifact_type: &str,
    evidence_ref: &str,
    parser_name: &str,
    attributes_json: &str,
) -> Vec<EvidenceOffset> {
    let Some(offset) = attr_i64(attributes_json, &["record_offset", "offset"]) else {
        if artifact_type == "prefetch" {
            return prefetch_section_evidence_offsets(
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                evidence_ref,
                parser_name,
                attributes_json,
            );
        }
        if artifact_type == "lnk" {
            return lnk_extra_block_evidence_offsets(
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                evidence_ref,
                parser_name,
                attributes_json,
            );
        }
        if matches!(artifact_type, "srum" | "web_cache" | "ese") {
            return ese_structure_evidence_offsets(
                case_id,
                event_id,
                source_file_id,
                parse_run_id,
                evidence_ref,
                parser_name,
                attributes_json,
            );
        }
        return Vec::new();
    };
    let length = attr_i64(
        attributes_json,
        &["record_size", "record_length", "structure_length", "length"],
    )
    .unwrap_or(4096)
    .clamp(1, 64 * 1024);
    let structure_kind = match artifact_type {
        "mft" => "mft_record",
        "usn_jrnl" => "usn_record",
        "lnk" => "lnk_structure",
        "prefetch" => "prefetch_structure",
        "registry" => "registry_cell",
        "amcache" => "registry_cell",
        "srum" | "web_cache" | "ese" => "ese_record",
        _ => "artifact_structure",
    };
    let label = match artifact_type {
        "mft" => attr_i64(attributes_json, &["record_number"])
            .map(|record| format!("MFT record {record}"))
            .unwrap_or_else(|| format!("MFT record offset {offset}")),
        "usn_jrnl" => attr_i64(attributes_json, &["usn"])
            .map(|usn| format!("USN {usn}"))
            .unwrap_or_else(|| format!("USN record offset {offset}")),
        _ => format!("{structure_kind} offset {offset}"),
    };
    let mut rows = vec![EvidenceOffset {
        offset_id: new_id("evoff"),
        case_id: case_id.to_string(),
        event_id: event_id.to_string(),
        source_file_id: source_file_id.to_string(),
        parse_run_id: parse_run_id.to_string(),
        object_ref: evidence_ref.to_string(),
        label,
        structure_kind: structure_kind.to_string(),
        offset,
        length,
        parser_name: parser_name.to_string(),
        confidence: 0.9,
        attributes_json: attributes_json.to_string(),
    }];

    if artifact_type == "mft" {
        push_mft_evidence_offsets(
            &mut rows,
            case_id,
            event_id,
            source_file_id,
            parse_run_id,
            evidence_ref,
            parser_name,
            attributes_json,
            offset,
        );
    }

    rows
}

#[allow(clippy::too_many_arguments)]
fn push_mft_evidence_offsets(
    rows: &mut Vec<EvidenceOffset>,
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    evidence_ref: &str,
    parser_name: &str,
    attributes_json: &str,
    record_offset: i64,
) {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return;
    };
    if let Some(attributes) = parsed
        .get("attributes")
        .and_then(serde_json::Value::as_array)
    {
        for attribute in attributes.iter().take(24) {
            let Some(attr_offset) = attribute.get("offset").and_then(value_i64) else {
                continue;
            };
            let length = attribute
                .get("length")
                .and_then(value_i64)
                .unwrap_or(64)
                .clamp(1, 64 * 1024);
            let type_name = attribute
                .get("type_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("UNKNOWN");
            let attr_id = attribute
                .get("id")
                .and_then(value_i64)
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string());
            rows.push(EvidenceOffset {
                offset_id: new_id("evoff"),
                case_id: case_id.to_string(),
                event_id: event_id.to_string(),
                source_file_id: source_file_id.to_string(),
                parse_run_id: parse_run_id.to_string(),
                object_ref: evidence_ref.to_string(),
                label: format!("MFT {type_name} attr#{attr_id}"),
                structure_kind: "mft_attribute".to_string(),
                offset: record_offset.saturating_add(attr_offset),
                length,
                parser_name: parser_name.to_string(),
                confidence: 0.85,
                attributes_json: serde_json::json!({ "attribute": attribute }).to_string(),
            });
        }
    }

    if let Some(data_runs) = parsed
        .get("data_runs")
        .and_then(serde_json::Value::as_array)
    {
        for data_run in data_runs.iter().take(16) {
            let Some(runlist_offset) = data_run.get("runlist_record_offset").and_then(value_i64)
            else {
                continue;
            };
            let run_index = data_run
                .get("run_index")
                .and_then(value_i64)
                .unwrap_or_default();
            rows.push(EvidenceOffset {
                offset_id: new_id("evoff"),
                case_id: case_id.to_string(),
                event_id: event_id.to_string(),
                source_file_id: source_file_id.to_string(),
                parse_run_id: parse_run_id.to_string(),
                object_ref: evidence_ref.to_string(),
                label: format!("MFT DATA runlist #{run_index}"),
                structure_kind: "mft_data_runlist".to_string(),
                offset: record_offset.saturating_add(runlist_offset),
                length: 16,
                parser_name: parser_name.to_string(),
                confidence: 0.8,
                attributes_json: serde_json::json!({ "data_run": data_run }).to_string(),
            });
        }
    }

    let Some(value_offset) = attr_i64(attributes_json, &["resident_value_offset"]) else {
        return;
    };
    let Some(value_length) = attr_i64(attributes_json, &["resident_value_length"]) else {
        return;
    };
    let stream_kind =
        attr_string(attributes_json, &["stream_kind"]).unwrap_or_else(|| "resident_data".into());
    let stream_name =
        attr_string(attributes_json, &["stream_name"]).unwrap_or_else(|| "$DATA".to_string());
    let record_number = attr_i64(attributes_json, &["record_number"])
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    rows.push(EvidenceOffset {
        offset_id: new_id("evoff"),
        case_id: case_id.to_string(),
        event_id: event_id.to_string(),
        source_file_id: source_file_id.to_string(),
        parse_run_id: parse_run_id.to_string(),
        object_ref: evidence_ref.to_string(),
        label: format!("MFT resident {stream_kind} {stream_name} record {record_number}"),
        structure_kind: if stream_kind.eq_ignore_ascii_case("ads") {
            "mft_ads_resident_content"
        } else {
            "mft_resident_content"
        }
        .to_string(),
        offset: record_offset.saturating_add(value_offset),
        length: value_length.clamp(1, 64 * 1024),
        parser_name: parser_name.to_string(),
        confidence: if stream_kind.eq_ignore_ascii_case("ads") {
            0.9
        } else {
            0.82
        },
        attributes_json: serde_json::json!({
            "record_number": record_number,
            "stream_kind": stream_kind,
            "stream_name": stream_name,
            "resident_value_offset": value_offset,
            "resident_value_length": value_length,
            "resident_sha256": attr_string(attributes_json, &["resident_sha256", "sha256"]),
            "HostUrl": attr_string(attributes_json, &["HostUrl", "host_url"]),
            "ReferrerUrl": attr_string(attributes_json, &["ReferrerUrl", "referrer_url"]),
            "ZoneId": attr_string(attributes_json, &["ZoneId", "zone_id"]),
        })
        .to_string(),
    });
}

fn prefetch_section_evidence_offsets(
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    evidence_ref: &str,
    parser_name: &str,
    attributes_json: &str,
) -> Vec<EvidenceOffset> {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    if let Some(sections) = parsed.get("sections").and_then(serde_json::Value::as_array) {
        for section in sections.iter().take(16) {
            let Some(offset) = section.get("offset").and_then(value_i64) else {
                continue;
            };
            let length = section
                .get("length")
                .and_then(value_i64)
                .unwrap_or(256)
                .clamp(1, 64 * 1024);
            let name = section
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("section");
            let confidence = section
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.7);
            rows.push(EvidenceOffset {
                offset_id: new_id("evoff"),
                case_id: case_id.to_string(),
                event_id: event_id.to_string(),
                source_file_id: source_file_id.to_string(),
                parse_run_id: parse_run_id.to_string(),
                object_ref: evidence_ref.to_string(),
                label: format!("Prefetch {name} section"),
                structure_kind: "prefetch_section".to_string(),
                offset,
                length,
                parser_name: parser_name.to_string(),
                confidence,
                attributes_json: serde_json::json!({ "section": section }).to_string(),
            });
        }
    }
    if let Some(offset) = parsed.get("run_count_offset").and_then(value_i64) {
        rows.push(EvidenceOffset {
            offset_id: new_id("evoff"),
            case_id: case_id.to_string(),
            event_id: event_id.to_string(),
            source_file_id: source_file_id.to_string(),
            parse_run_id: parse_run_id.to_string(),
            object_ref: evidence_ref.to_string(),
            label: "Prefetch run count".to_string(),
            structure_kind: "prefetch_run_count".to_string(),
            offset,
            length: 4,
            parser_name: parser_name.to_string(),
            confidence: 0.8,
            attributes_json: serde_json::json!({
                "run_count": parsed.get("run_count"),
                "run_count_offset": offset,
            })
            .to_string(),
        });
    }
    if let Some(entries) = parsed
        .get("run_time_entries")
        .and_then(serde_json::Value::as_array)
    {
        for entry in entries.iter().take(16) {
            let Some(offset) = entry.get("offset").and_then(value_i64) else {
                continue;
            };
            let label = entry
                .get("timestamp")
                .and_then(serde_json::Value::as_str)
                .map(|value| format!("Prefetch run time {value}"))
                .unwrap_or_else(|| "Prefetch run time".to_string());
            let confidence = entry
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.8);
            rows.push(EvidenceOffset {
                offset_id: new_id("evoff"),
                case_id: case_id.to_string(),
                event_id: event_id.to_string(),
                source_file_id: source_file_id.to_string(),
                parse_run_id: parse_run_id.to_string(),
                object_ref: evidence_ref.to_string(),
                label,
                structure_kind: "prefetch_run_time".to_string(),
                offset,
                length: 8,
                parser_name: parser_name.to_string(),
                confidence,
                attributes_json: serde_json::json!({ "run_time_entry": entry }).to_string(),
            });
        }
    }
    if let Some(metrics) = parsed
        .get("file_metrics")
        .and_then(serde_json::Value::as_array)
    {
        for metric in metrics.iter().take(32) {
            let Some(offset) = metric.get("offset").and_then(value_i64) else {
                continue;
            };
            let length = metric
                .get("length")
                .and_then(value_i64)
                .unwrap_or(32)
                .clamp(1, 256);
            let index = metric.get("index").and_then(value_i64).unwrap_or_default();
            rows.push(EvidenceOffset {
                offset_id: new_id("evoff"),
                case_id: case_id.to_string(),
                event_id: event_id.to_string(),
                source_file_id: source_file_id.to_string(),
                parse_run_id: parse_run_id.to_string(),
                object_ref: evidence_ref.to_string(),
                label: format!("Prefetch file metric #{index}"),
                structure_kind: "prefetch_file_metric".to_string(),
                offset,
                length,
                parser_name: parser_name.to_string(),
                confidence: metric
                    .get("confidence")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.78),
                attributes_json: serde_json::json!({
                    "offset_basis": parsed.get("offset_basis"),
                    "file_metric": metric,
                })
                .to_string(),
            });
        }
    }
    if let Some(chains) = parsed
        .get("trace_chains")
        .and_then(serde_json::Value::as_array)
    {
        for chain in chains.iter().take(32) {
            let Some(offset) = chain.get("offset").and_then(value_i64) else {
                continue;
            };
            let length = chain
                .get("length")
                .and_then(value_i64)
                .unwrap_or(8)
                .clamp(1, 256);
            let index = chain.get("index").and_then(value_i64).unwrap_or_default();
            rows.push(EvidenceOffset {
                offset_id: new_id("evoff"),
                case_id: case_id.to_string(),
                event_id: event_id.to_string(),
                source_file_id: source_file_id.to_string(),
                parse_run_id: parse_run_id.to_string(),
                object_ref: evidence_ref.to_string(),
                label: format!("Prefetch trace chain #{index}"),
                structure_kind: "prefetch_trace_chain".to_string(),
                offset,
                length,
                parser_name: parser_name.to_string(),
                confidence: chain
                    .get("confidence")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.74),
                attributes_json: serde_json::json!({
                    "offset_basis": parsed.get("offset_basis"),
                    "trace_chain": chain,
                })
                .to_string(),
            });
        }
    }
    rows
}

fn lnk_extra_block_evidence_offsets(
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    evidence_ref: &str,
    parser_name: &str,
    attributes_json: &str,
) -> Vec<EvidenceOffset> {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return Vec::new();
    };
    let Some(blocks) = parsed
        .get("extra_data_blocks")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for block in blocks.iter().take(16) {
        let Some(offset) = block.get("offset").and_then(value_i64) else {
            continue;
        };
        let length = block
            .get("length")
            .and_then(value_i64)
            .unwrap_or(64)
            .clamp(1, 64 * 1024);
        let signature_name = block
            .get("signature_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("UnknownExtraDataBlock");
        let confidence = block
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.75);
        rows.push(EvidenceOffset {
            offset_id: new_id("evoff"),
            case_id: case_id.to_string(),
            event_id: event_id.to_string(),
            source_file_id: source_file_id.to_string(),
            parse_run_id: parse_run_id.to_string(),
            object_ref: evidence_ref.to_string(),
            label: format!("LNK {signature_name}"),
            structure_kind: "lnk_extra_block".to_string(),
            offset,
            length,
            parser_name: parser_name.to_string(),
            confidence,
            attributes_json: serde_json::json!({ "extra_data_block": block }).to_string(),
        });
        if let Some(properties) = block
            .get("property_entries")
            .and_then(serde_json::Value::as_array)
        {
            for property in properties.iter().take(32) {
                let Some(property_offset) = property.get("value_offset").and_then(value_i64) else {
                    continue;
                };
                let length = property
                    .get("value_length")
                    .and_then(value_i64)
                    .unwrap_or(32)
                    .clamp(1, 4096);
                let key = property
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("property");
                let confidence = property
                    .get("confidence")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.6);
                rows.push(EvidenceOffset {
                    offset_id: new_id("evoff"),
                    case_id: case_id.to_string(),
                    event_id: event_id.to_string(),
                    source_file_id: source_file_id.to_string(),
                    parse_run_id: parse_run_id.to_string(),
                    object_ref: evidence_ref.to_string(),
                    label: format!("LNK property {key}"),
                    structure_kind: "lnk_property_value".to_string(),
                    offset: property_offset,
                    length,
                    parser_name: parser_name.to_string(),
                    confidence,
                    attributes_json: serde_json::json!({ "property_entry": property }).to_string(),
                });
            }
        }
    }
    rows
}

fn ese_structure_evidence_offsets(
    case_id: &str,
    event_id: &str,
    source_file_id: &str,
    parse_run_id: &str,
    evidence_ref: &str,
    parser_name: &str,
    attributes_json: &str,
) -> Vec<EvidenceOffset> {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    if let Some(header) = parsed.get("ese_header").filter(|value| value.is_object()) {
        let offset = header.get("offset").and_then(value_i64).unwrap_or(0);
        let length = header
            .get("length")
            .and_then(value_i64)
            .unwrap_or(4096)
            .clamp(1, 64 * 1024);
        rows.push(EvidenceOffset {
            offset_id: new_id("evoff"),
            case_id: case_id.to_string(),
            event_id: event_id.to_string(),
            source_file_id: source_file_id.to_string(),
            parse_run_id: parse_run_id.to_string(),
            object_ref: evidence_ref.to_string(),
            label: "ESE database header".to_string(),
            structure_kind: "ese_database_header".to_string(),
            offset,
            length,
            parser_name: parser_name.to_string(),
            confidence: 0.75,
            attributes_json: serde_json::json!({ "ese_header": header }).to_string(),
        });
    }
    if let Some(pages) = parsed
        .get("ese_pages")
        .and_then(serde_json::Value::as_array)
    {
        for page in pages.iter().take(8) {
            let Some(offset) = page.get("offset").and_then(value_i64) else {
                continue;
            };
            let length = page
                .get("length")
                .and_then(value_i64)
                .unwrap_or(4096)
                .clamp(1, 64 * 1024);
            let page_number = page
                .get("page_number")
                .and_then(value_i64)
                .unwrap_or_default();
            let confidence = page
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.55);
            rows.push(EvidenceOffset {
                offset_id: new_id("evoff"),
                case_id: case_id.to_string(),
                event_id: event_id.to_string(),
                source_file_id: source_file_id.to_string(),
                parse_run_id: parse_run_id.to_string(),
                object_ref: evidence_ref.to_string(),
                label: format!("ESE page {page_number}"),
                structure_kind: "ese_database_page".to_string(),
                offset,
                length,
                parser_name: parser_name.to_string(),
                confidence,
                attributes_json: serde_json::json!({ "ese_page": page }).to_string(),
            });
            if let Some(tags) = page.get("tags").and_then(serde_json::Value::as_array) {
                for tag in tags.iter().take(64) {
                    let tag_offset = tag.get("absolute_offset").and_then(value_i64).or_else(|| {
                        tag.get("offset")
                            .and_then(value_i64)
                            .map(|tag_offset| offset + tag_offset)
                    });
                    let Some(tag_offset) = tag_offset else {
                        continue;
                    };
                    let length = tag
                        .get("length")
                        .and_then(value_i64)
                        .unwrap_or(16)
                        .clamp(1, 64 * 1024);
                    let tag_index = tag.get("tag_index").and_then(value_i64).unwrap_or_default();
                    let confidence = tag
                        .get("confidence")
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or(0.6);
                    rows.push(EvidenceOffset {
                        offset_id: new_id("evoff"),
                        case_id: case_id.to_string(),
                        event_id: event_id.to_string(),
                        source_file_id: source_file_id.to_string(),
                        parse_run_id: parse_run_id.to_string(),
                        object_ref: evidence_ref.to_string(),
                        label: format!("ESE page {page_number} tag {tag_index}"),
                        structure_kind: "ese_page_tag".to_string(),
                        offset: tag_offset,
                        length,
                        parser_name: parser_name.to_string(),
                        confidence,
                        attributes_json: serde_json::json!({ "ese_page_tag": tag }).to_string(),
                    });
                }
            }
        }
    }
    rows
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    IntakeFile,
    DetectArtifactType,
    ParseArtifact,
    BuildEventRows,
    BuildTimelineBins,
    BuildTantivyIndex,
    BuildAnswerCandidates,
    ExtractEntities,
    BuildEdges,
    BuildCorrelationChains,
    RunFindings,
    ImportPlaso,
    ImportKape,
    RunTika,
    RunYara,
    RunSidecar,
    RunNetworkSidecar,
    RunCredentialSidecar,
    RunDocumentSidecar,
    RunArchiveSidecar,
}

impl JobKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntakeFile => "intake_file",
            Self::DetectArtifactType => "detect_artifact_type",
            Self::ParseArtifact => "parse_artifact",
            Self::BuildEventRows => "build_event_rows",
            Self::BuildTimelineBins => "build_timeline_bins",
            Self::BuildTantivyIndex => "build_tantivy_index",
            Self::BuildAnswerCandidates => "build_answer_candidates",
            Self::ExtractEntities => "extract_entities",
            Self::BuildEdges => "build_edges",
            Self::BuildCorrelationChains => "build_correlation_chains",
            Self::RunFindings => "run_findings",
            Self::ImportPlaso => "import_plaso",
            Self::ImportKape => "import_kape",
            Self::RunTika => "run_tika",
            Self::RunYara => "run_yara",
            Self::RunSidecar => "run_sidecar",
            Self::RunNetworkSidecar => "run_network_sidecar",
            Self::RunCredentialSidecar => "run_credential_sidecar",
            Self::RunDocumentSidecar => "run_document_sidecar",
            Self::RunArchiveSidecar => "run_archive_sidecar",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobRecord {
    pub job_id: String,
    pub case_id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub priority: i64,
    pub progress: f64,
    pub attempts: i64,
    pub max_attempts: i64,
    pub created_at: String,
    pub updated_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub worker_id: Option<String>,
    pub heartbeat_at: Option<String>,
    pub cancel_requested: bool,
    pub resource_limits_json: String,
    pub payload_json: String,
    pub error_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_row_projection_excludes_raw_record() {
        let event = EventFull {
            event_id: "event_1".into(),
            case_id: "case_1".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "2026-01-01 00:00:00".into(),
            time_kind: "textlog_line_timestamp".into(),
            time_confidence: 0.8,
            source_confidence: 0.9,
            artifact_type: "text_log".into(),
            source_file_id: "file_1".into(),
            parse_run_id: "parse_1".into(),
            parser_name: "fake".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/demo".into(),
            host: Some("host1".into()),
            user_name: None,
            process_name: None,
            file_path: None,
            ip: None,
            url: None,
            hash: None,
            event_action: "observed".into(),
            severity: "info".into(),
            message_short: "short".into(),
            message_full: "full".into(),
            raw_record_ref: "raw_record_1".into(),
            attributes_json: "{}".into(),
        };

        let row = event.to_event_row();
        let json = serde_json::to_value(row).unwrap();
        assert!(json.get("raw_record_ref").is_none());
        assert!(json.get("message_full").is_none());
        assert!(json.get("attributes_json").is_none());
    }

    #[test]
    fn derives_artifact_objects_and_evidence_offsets_from_mft_attributes() {
        let event = EventFull {
            event_id: "event_mft".into(),
            case_id: "case_1".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "2026-01-01 00:00:00".into(),
            time_kind: "mft_created".into(),
            time_confidence: 0.9,
            source_confidence: 0.9,
            artifact_type: "mft".into(),
            source_file_id: "file_1".into(),
            parse_run_id: "parse_1".into(),
            parser_name: "taotie_core_mft".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/mft".into(),
            host: Some("host1".into()),
            user_name: None,
            process_name: None,
            file_path: Some("C:\\Temp\\evil.exe".into()),
            ip: None,
            url: None,
            hash: None,
            event_action: "mft_created".into(),
            severity: "info".into(),
            message_short: "MFT created".into(),
            message_full: "MFT created".into(),
            raw_record_ref: "raw_record_1".into(),
            attributes_json: serde_json::json!({
                "record_number": 42,
                "sequence_number": 7,
                "record_offset": 43008,
                "record_size": 1024,
                "attributes": [
                    {
                        "type": 16,
                        "type_name": "STANDARD_INFORMATION",
                        "offset": 56,
                        "length": 72,
                        "id": 1,
                        "non_resident": false
                    },
                    {
                        "type": 128,
                        "type_name": "DATA",
                        "offset": 240,
                        "length": 80,
                        "id": 3,
                        "non_resident": true,
                        "data_run_offset": 64
                    }
                ],
                "data_runs": [
                    {
                        "attribute_id": 3,
                        "run_index": 0,
                        "runlist_record_offset": 304,
                        "vcn_start": 0,
                        "cluster_count": 4,
                        "lcn": 32,
                        "sparse": false
                    }
                ]
            })
            .to_string(),
        };

        let objects = derive_artifact_objects_from_event(&event);
        assert!(objects.iter().any(|row| {
            row.object_kind == "ntfs_file_record"
                && row.object_key == "mft:42:7"
                && row.evidence_offset == Some(43008)
                && row.evidence_length == Some(1024)
        }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "ntfs_attribute"
                && row.object_key == "mft_attr:42:7:3:DATA"
                && row.evidence_offset == Some(43248)
                && row.evidence_length == Some(80)
        }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "ntfs_data_run"
                && row.object_key == "mft_run:42:7:3:0"
                && row.evidence_offset == Some(43312)
        }));

        let offsets = derive_evidence_offsets_from_event(&event);
        assert_eq!(offsets.len(), 4);
        assert_eq!(offsets[0].structure_kind, "mft_record");
        assert_eq!(offsets[0].offset, 43008);
        assert_eq!(offsets[0].length, 1024);
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "mft_attribute" && row.offset == 43248));
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "mft_data_runlist" && row.offset == 43312));
    }

    #[test]
    fn derives_prefetch_section_objects_and_offsets() {
        let event = EventFull {
            event_id: "event_pf".into(),
            case_id: "case_1".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "2026-01-01 00:00:00".into(),
            time_kind: "prefetch_last_run".into(),
            time_confidence: 0.8,
            source_confidence: 0.8,
            artifact_type: "prefetch".into(),
            source_file_id: "file_pf".into(),
            parse_run_id: "parse_1".into(),
            parser_name: "taotie_core_prefetch".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/pf".into(),
            host: Some("host1".into()),
            user_name: None,
            process_name: Some("powershell.exe".into()),
            file_path: Some("powershell.exe".into()),
            ip: None,
            url: None,
            hash: None,
            event_action: "process_executed".into(),
            severity: "medium".into(),
            message_short: "Prefetch execution".into(),
            message_full: "Prefetch execution".into(),
            raw_record_ref: "raw_record_1".into(),
            attributes_json: serde_json::json!({
                "prefetch_hash": "022a1004",
                "executable_name_header": "POWERSHELL.EXE",
                "run_count": 3,
                "run_count_offset": 208,
                "run_time_entries": [
                    {
                        "execution_index": 0,
                        "offset": 120,
                        "timestamp": "2026-01-01T00:00:00Z",
                        "confidence": 0.8
                    }
                ],
                "file_metrics": [
                    {
                        "index": 0,
                        "offset": 304,
                        "length": 32,
                        "filename": "\\DEVICE\\HARDDISKVOLUME4\\WINDOWS\\SYSTEM32\\POWERSHELL.EXE",
                        "prefetch_duration_ms": 25,
                        "confidence": 0.82
                    }
                ],
                "trace_chains": [
                    {
                        "index": 0,
                        "offset": 368,
                        "length": 8,
                        "block_load_count": 4,
                        "confidence": 0.78
                    }
                ],
                "sections": [
                    {
                        "name": "filename_strings",
                        "offset": 288,
                        "length": 112,
                        "count": 112,
                        "length_source": "explicit_size",
                        "confidence": 0.9
                    }
                ]
            })
            .to_string(),
        };

        let objects = derive_artifact_objects_from_event(&event);
        assert!(objects.iter().any(|row| {
            row.object_kind == "prefetch_section"
                && row.object_key == "prefetch_section:powershell.exe:022a1004:filename_strings"
                && row.evidence_offset == Some(288)
                && row.evidence_length == Some(112)
        }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "prefetch_run_count" && row.evidence_offset == Some(208)
        }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "prefetch_run_time" && row.evidence_offset == Some(120)
        }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "prefetch_file_metric" && row.evidence_offset == Some(304)
        }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "prefetch_trace_chain" && row.evidence_offset == Some(368)
        }));

        let offsets = derive_evidence_offsets_from_event(&event);
        assert_eq!(offsets.len(), 5);
        assert_eq!(offsets[0].structure_kind, "prefetch_section");
        assert_eq!(offsets[0].offset, 288);
        assert_eq!(offsets[0].length, 112);
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "prefetch_run_count" && row.offset == 208));
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "prefetch_run_time" && row.offset == 120));
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "prefetch_file_metric" && row.offset == 304));
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "prefetch_trace_chain" && row.offset == 368));
    }

    #[test]
    fn derives_mft_resident_ads_content_objects_and_offsets() {
        let event = EventFull {
            event_id: "event_ads".into(),
            case_id: "case_1".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "2026-01-01 00:00:00".into(),
            time_kind: "mft_modified".into(),
            time_confidence: 0.75,
            source_confidence: 0.9,
            artifact_type: "mft".into(),
            source_file_id: "file_mft".into(),
            parse_run_id: "parse_1".into(),
            parser_name: "taotie_core_mft".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/mft".into(),
            host: None,
            user_name: None,
            process_name: None,
            file_path: Some("C:\\Users\\alice\\Downloads\\invoice.zip:Zone.Identifier".into()),
            ip: None,
            url: Some("http://example.test/invoice.zip".into()),
            hash: Some("4d967db0f0f6c9f2d9e56a9445aa9f2a".into()),
            event_action: "mft_ads_resident_content_observed".into(),
            severity: "medium".into(),
            message_short: "MFT ADS resident content observed".into(),
            message_full: "MFT ADS resident content observed".into(),
            raw_record_ref: "raw_ads".into(),
            attributes_json: serde_json::json!({
                "record_number": 42,
                "sequence_number": 7,
                "record_offset": 43008,
                "record_size": 1024,
                "stream_name": "Zone.Identifier",
                "stream_kind": "ads",
                "resident_value_offset": 376,
                "resident_value_length": 98,
                "resident_sha256": "4d967db0f0f6c9f2d9e56a9445aa9f2a",
                "HostUrl": "http://example.test/invoice.zip",
                "ZoneId": "3"
            })
            .to_string(),
        };

        let objects = derive_artifact_objects_from_event(&event);
        assert!(objects.iter().any(|row| {
            row.object_kind == "ntfs_ads_resident_content"
                && row
                    .display_name
                    .contains("HostUrl=http://example.test/invoice.zip")
                && row.evidence_offset == Some(43384)
                && row.evidence_length == Some(98)
        }));

        let offsets = derive_evidence_offsets_from_event(&event);
        assert!(offsets.iter().any(|row| {
            row.structure_kind == "mft_ads_resident_content"
                && row.label.contains("Zone.Identifier")
                && row.offset == 43384
                && row.length == 98
        }));
    }

    #[test]
    fn derives_sidecar_recovery_and_credential_objects() {
        let recovered = EventFull {
            event_id: "event_recovered".into(),
            case_id: "case_1".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "sidecar_generated".into(),
            time_kind: "sidecar_generated".into(),
            time_confidence: 0.2,
            source_confidence: 0.8,
            artifact_type: "disk_image".into(),
            source_file_id: "file_img".into(),
            parse_run_id: "parse_1".into(),
            parser_name: "taotie-sidecar-worker".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/image".into(),
            host: None,
            user_name: None,
            process_name: None,
            file_path: Some("Users/alice/Desktop/deleted.txt".into()),
            ip: None,
            url: None,
            hash: Some("abc123".into()),
            event_action: "deleted_file_recovered".into(),
            severity: "high".into(),
            message_short: "deleted file recovered".into(),
            message_full: "deleted file recovered".into(),
            raw_record_ref: "raw_1".into(),
            attributes_json: serde_json::json!({
                "sidecar_record_kind": "deleted_file_recovered",
                "recovered_path": "/case/sidecar/deleted.txt",
                "sha256": "abc123",
                "size": 42,
            })
            .to_string(),
        };
        let objects = derive_artifact_objects_from_event(&recovered);
        assert!(objects.iter().any(|row| {
            row.object_kind == "recovered_file"
                && row.display_name == "/case/sidecar/deleted.txt"
                && row.evidence_length == Some(42)
        }));

        let credential = EventFull {
            event_id: "event_cred".into(),
            case_id: "case_1".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "sidecar_generated".into(),
            time_kind: "sidecar_generated".into(),
            time_confidence: 0.2,
            source_confidence: 0.8,
            artifact_type: "credential_store".into(),
            source_file_id: "file_kdbx".into(),
            parse_run_id: "parse_1".into(),
            parser_name: "taotie-sidecar-worker".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/kdbx".into(),
            host: None,
            user_name: Some("alice".into()),
            process_name: None,
            file_path: None,
            ip: None,
            url: Some("https://vpn.example.test".into()),
            hash: None,
            event_action: "keepass_entry_decrypted".into(),
            severity: "high".into(),
            message_short: "KeePass entry decrypted".into(),
            message_full: "KeePass entry decrypted".into(),
            raw_record_ref: "raw_2".into(),
            attributes_json: serde_json::json!({
                "sidecar_record_kind": "keepass_entry_decrypted",
                "title": "VPN Portal",
                "username": "alice",
                "url": "https://vpn.example.test",
                "password_present": true,
            })
            .to_string(),
        };
        let objects = derive_artifact_objects_from_event(&credential);
        assert!(objects.iter().any(|row| {
            row.object_kind == "credential_store_entry"
                && row.display_name.contains("VPN Portal")
                && row.confidence >= 0.88
        }));
    }

    #[test]
    fn derives_lnk_extra_block_objects_and_offsets() {
        let event = EventFull {
            event_id: "event_lnk".into(),
            case_id: "case_1".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "2026-01-01 00:00:00".into(),
            time_kind: "lnk_file_import_observed".into(),
            time_confidence: 0.7,
            source_confidence: 0.7,
            artifact_type: "lnk".into(),
            source_file_id: "file_lnk".into(),
            parse_run_id: "parse_1".into(),
            parser_name: "taotie_core_lnk".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/lnk".into(),
            host: None,
            user_name: Some("jdoe".into()),
            process_name: Some("evil.exe".into()),
            file_path: Some("C:\\Temp\\evil.exe".into()),
            ip: None,
            url: None,
            hash: None,
            event_action: "lnk_target_executable_observed".into(),
            severity: "medium".into(),
            message_short: "LNK observed".into(),
            message_full: "LNK observed".into(),
            raw_record_ref: "raw_record_1".into(),
            attributes_json: serde_json::json!({
                "extra_data_blocks": [
                    {
                        "signature": "a0000009",
                        "signature_raw": 2684354569u64,
                        "signature_name": "PropertyStoreDataBlock",
                        "offset": 256,
                        "length": 112,
                        "guid_candidates": ["9f284c9f-3989-8e4c-bc0c-155fa9f494e4"],
                        "property_entries": [
                            {
                                "key": "System.AppUserModel.ID",
                                "value_hint": "Taotie.Test.App",
                                "format_id": "9f284c9f-3989-8e4c-bc0c-155fa9f494e4",
                                "property_id": 5,
                                "value_offset": 320,
                                "value_length": 30,
                                "confidence": 0.78
                            }
                        ],
                        "confidence": 0.85
                    }
                ]
            })
            .to_string(),
        };

        let objects = derive_artifact_objects_from_event(&event);
        assert!(objects.iter().any(|row| {
            row.object_kind == "lnk_extra_block"
                && row.display_name == "LNK PropertyStoreDataBlock"
                && row.evidence_offset == Some(256)
                && row.evidence_length == Some(112)
        }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "lnk_property_value"
                && row.object_key == "lnk_property:system.appusermodel.id:taotie.test.app"
                && row.evidence_offset == Some(320)
        }));

        let offsets = derive_evidence_offsets_from_event(&event);
        assert_eq!(offsets.len(), 2);
        assert_eq!(offsets[0].structure_kind, "lnk_extra_block");
        assert_eq!(offsets[0].offset, 256);
        assert_eq!(offsets[0].length, 112);
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "lnk_property_value" && row.offset == 320));
    }

    #[test]
    fn derives_ese_structure_objects_and_offsets() {
        let event = EventFull {
            event_id: "event_ese".into(),
            case_id: "case_1".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "2026-01-01 00:00:00".into(),
            time_kind: "artifact_import_time".into(),
            time_confidence: 0.25,
            source_confidence: 0.25,
            artifact_type: "web_cache".into(),
            source_file_id: "file_webcache".into(),
            parse_run_id: "parse_1".into(),
            parser_name: "taotie_core_ese".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/webcache".into(),
            host: None,
            user_name: Some("alice".into()),
            process_name: None,
            file_path: Some("WebCacheV01.dat".into()),
            ip: None,
            url: Some("https://example.test/download/evil.exe".into()),
            hash: None,
            event_action: "webcache_download_observed".into(),
            severity: "medium".into(),
            message_short: "web cache signal".into(),
            message_full: "web cache signal".into(),
            raw_record_ref: "raw_record_1".into(),
            attributes_json: serde_json::json!({
                "ese_header": {
                    "signature_offset": 0,
                    "page_size": 4096,
                    "page_count": 2,
                    "offset": 0,
                    "length": 4096,
                    "confidence": 0.8
                },
                "ese_pages": [
                    {
                        "page_number": 0,
                        "offset": 0,
                        "length": 4096,
                        "confidence": 0.55
                    },
                    {
                        "page_number": 1,
                        "offset": 4096,
                        "length": 4096,
                        "checksum_hint": 287454020u64,
                        "tags": [
                            {
                                "tag_index": 0,
                                "offset": 204,
                                "absolute_offset": 4300,
                                "length": 128,
                                "flags_hint": 0,
                                "value_preview": "Visited https://example.test/download/evil.exe",
                                "confidence": 0.65
                            }
                        ],
                        "table_name_hints": ["Container_1 UrlHistoryTable"],
                        "confidence": 0.55
                    }
                ]
            })
            .to_string(),
        };

        let objects = derive_artifact_objects_from_event(&event);
        assert!(objects.iter().any(|row| {
            row.object_kind == "ese_database_header" && row.evidence_offset == Some(0)
        }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "ese_database_page"
                && row.object_key == "ese_page:file_webcache:1"
                && row.evidence_offset == Some(4096)
        }));
        assert!(objects
            .iter()
            .any(|row| { row.object_kind == "ese_page_tag" && row.evidence_offset == Some(4300) }));
        assert!(objects.iter().any(|row| {
            row.object_kind == "ese_table_hint"
                && row.object_key == "ese_table:web_cache:container_1 urlhistorytable"
        }));

        let offsets = derive_evidence_offsets_from_event(&event);
        assert_eq!(offsets.len(), 4);
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "ese_database_page" && row.offset == 4096));
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "ese_page_tag" && row.offset == 4300));
    }

    #[test]
    fn bounded_limit_clamps() {
        assert_eq!(bounded_limit(None, 50, 100), 50);
        assert_eq!(bounded_limit(Some(0), 50, 100), 1);
        assert_eq!(bounded_limit(Some(500), 50, 100), 100);
    }
}
