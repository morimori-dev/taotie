use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use chrono::{Timelike, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use taotie_jobs::JobQueue;
use taotie_parsers::{
    parse_evtx_path, parse_mft_path, parse_usn_jrnl_path, FakeParser, ParserAdapter, ParserInput,
    ParserOutcome, StructuredArtifactParser,
};
mod sigma;

use taotie_schema::{
    derive_artifact_objects_from_event, derive_evidence_offsets_from_event, new_id, now_utc,
    parse_utc, AnalyzerRunSummary, AnswerCandidate, ArtifactObject, AuditLogEntry,
    BeaconIntervalBin, CaseApprovalRecord, CaseCustodyProfile, CaseDetectionEvaluation,
    CaseQualityGate, CaseSummary, FileOpBin, ProcessNode, ProcessRelatedEvent, ProcessTreeEdge,
    TimestompPoint,
    CorrelationChainEventPageQuery, CorrelationChainSummary, CorrelationSummary, CoverageSummary,
    CustodyManifestVerification, DefenderEventPageQuery, DefenderSummary,
    DetectionObjectiveEvaluation, EdgeRecord, EntityRecord, EventBookmark, EventContext,
    EventContextQuery, EventDetailLight, EventExportResult, EventFacetValue, EventFull,
    EventPageQuery, EventRow, EventTimelineBin, EvidenceOffset, EvidenceRange, EvidenceVerification,
    FailedParserSummary, FilePageQuery, FileRecord, FindingEventPageQuery, FindingOverride,
    FindingRecord, FindingReview, FindingReviewSummary, FindingSummary, IocEventPageQuery, IocHit,
    JobKind, JobRecord, JobStatus, Page, ParseRun, ParseRunStatus, ParserErrorRecord, ParserStatus,
    ParserVersionRecord, PrefetchSummary, RawRecord, ReportBundleVerification, RiskSummary,
    SavedSearch, SchemaVersionRecord, Subgraph, TimelineBin, TriageAction, UnsupportedFileRecord,
    UserActivitySummary, CURRENT_SCHEMA_VERSION,
};
use taotie_search::{EventSearchIndex, IndexEvent, TantivyEventIndex};
pub use taotie_search::{
    IndexMetadata as SearchIndexMetadata, SearchHit as EventSearchHit,
    SearchQuery as EventSearchQuery,
};
use taotie_storage::{CaseWorkspace, DuckDbQueryLayer, StoredObject, TableKind};

const ANSWER_CANDIDATE_READ_MODEL_VERSION: &str = "taotie-answer-candidates-v3";
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("storage error: {0}")]
    Storage(#[from] taotie_storage::StorageError),
    #[error("job error: {0}")]
    Jobs(#[from] taotie_jobs::JobError),
    #[error("parser error: {0}")]
    Parser(#[from] taotie_parsers::ParserError),
    #[error("search error: {0}")]
    Search(#[from] taotie_search::SearchError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

pub type Result<T> = std::result::Result<T, ApiError>;

const LOCAL_DETECT_PREVIEW_BYTES: usize = 256 * 1024;
const LOCAL_TEXT_PARSE_PREVIEW_BYTES: usize = 8 * 1024 * 1024;
const LOCAL_STRUCTURED_PARSE_PREVIEW_BYTES: usize = 2 * 1024 * 1024;
const LOCAL_BINARY_PARSE_PREVIEW_BYTES: usize = 512 * 1024;
const SYNC_ANALYSIS_EVENT_LIMIT: usize = 25_000;
const MAX_EVIDENCE_RANGE_BYTES: usize = 64 * 1024;
const MAX_ANSWER_CANDIDATE_EVIDENCE_VALUES: usize = 32;
const BACKGROUND_JOB_STALE_AFTER_MINUTES: i64 = 15;
const DEFAULT_MAX_LOCAL_INGEST_WORKERS: usize = 16;

static STORAGE_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FakeArtifactRequest {
    pub case_root: String,
    pub original_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadedArtifactRequest {
    pub case_root: String,
    pub original_path: String,
    pub content_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnswerCandidateQuery {
    pub case_root: String,
    pub question_key: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalPathIngestRequest {
    pub case_root: String,
    pub input_path: String,
    pub recursive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalPathScanRequest {
    pub input_path: String,
    pub recursive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalPathScanResult {
    pub file_count: usize,
    pub total_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalPathIngestResult {
    pub summary: CaseSummary,
    pub file_count: usize,
    pub skipped_count: usize,
    pub failed_count: usize,
    pub worker_count: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct LocalIngestTask {
    source_path: PathBuf,
    original_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRangeRequest {
    pub case_root: String,
    pub object_ref: String,
    pub offset: Option<i64>,
    pub length: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceFindRequest {
    pub case_root: String,
    pub object_ref: String,
    pub pattern: String,
    pub is_hex: bool,
    pub from_offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceFindResult {
    pub offset: Option<i64>,
    pub total_size: i64,
    pub pattern_len: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceVerificationRequest {
    pub case_root: String,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodyManifestVerificationRequest {
    pub case_root: String,
    pub manifest_path: String,
    pub evidence_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportBundleVerificationRequest {
    pub case_root: String,
    pub bundle_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseRequest {
    pub case_root: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenCaseRequest {
    pub case_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClearCaseRequest {
    pub case_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClearCaseResult {
    pub case_root: String,
    pub removed_paths: Vec<String>,
    pub root_removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseCustodyProfileRequest {
    pub case_root: String,
    pub investigator: Option<String>,
    pub custodian: Option<String>,
    pub organization: Option<String>,
    pub evidence_source: Option<String>,
    pub acquisition_method: Option<String>,
    pub acquired_at: Option<String>,
    pub legal_authority: Option<String>,
    pub chain_of_custody_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReportSigningKeyRecord {
    pub key_id: String,
    pub algorithm: String,
    pub created_at: String,
    pub public_key_base64: String,
    pub secret_key_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReportBundleSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_base64: String,
    pub signed_sha256: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportSignatureVerification {
    pub algorithm: Option<String>,
    pub key_id: Option<String>,
    pub present: bool,
    pub payload_hash_ok: bool,
    pub valid: bool,
    pub key_matches_case_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingOverrideRequest {
    pub case_root: String,
    pub engine: Option<String>,
    pub rule_id: Option<String>,
    pub title: Option<String>,
    pub action: String,
    pub severity: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingReviewRequest {
    pub case_root: String,
    pub engine: String,
    pub rule_id: Option<String>,
    pub title: String,
    pub status: String,
    pub reviewer: Option<String>,
    pub assignee: Option<String>,
    pub tags: Option<Vec<String>>,
    pub due_at: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseApprovalRequest {
    pub case_root: String,
    pub target_kind: String,
    pub target_id: Option<String>,
    pub target_path: Option<String>,
    pub target_sha256: Option<String>,
    pub status: String,
    pub approver: Option<String>,
    pub role: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventFacetRequest {
    pub case_root: String,
    pub page: EventPageQuery,
    pub per_field_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedSearchRequest {
    pub case_root: String,
    pub name: String,
    pub query: EventPageQuery,
    pub description: Option<String>,
    pub created_by: Option<String>,
    pub visibility: Option<String>,
    pub shared_with: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteSavedSearchRequest {
    pub case_root: String,
    pub search_id: String,
    pub requested_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildSearchIndexRequest {
    pub case_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartSearchIndexBuildRequest {
    pub case_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartAnswerCandidateBuildRequest {
    pub case_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SidecarPlanRequest {
    pub case_root: String,
    pub event_id: String,
    pub sidecar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SidecarBatchRequest {
    pub case_root: String,
    pub limit: Option<usize>,
    pub execute: Option<bool>,
    pub rebuild_after_execute: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SidecarBatchResult {
    pub queued_count: usize,
    pub executed_count: usize,
    pub succeeded_count: usize,
    pub failed_count: usize,
    pub skipped_count: usize,
    pub jobs: Vec<JobRecord>,
    pub tool_status_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSearchIndexRequest {
    pub case_root: String,
    pub text: String,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchIndexStatus {
    pub metadata: Option<SearchIndexMetadata>,
    pub current_event_count: i64,
    pub is_stale: bool,
    pub active_job: Option<JobRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventBookmarkRequest {
    pub case_root: String,
    pub event_id: String,
    pub label: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IocMatchRequest {
    pub case_root: String,
    pub indicators: Vec<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IocFindingRequest {
    pub case_root: String,
    pub indicators: Vec<String>,
    pub limit: Option<usize>,
}

pub fn create_case(request: CaseRequest) -> Result<CaseSummary> {
    let workspace = CaseWorkspace::create(request.case_root, request.name)?;
    append_audit_log(
        &workspace,
        "case_created",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        "case workspace created",
        serde_json::json!({
            "name": workspace.manifest().name.clone(),
            "schema_version": workspace.manifest().schema_version.clone(),
        }),
    )?;
    workspace
        .query_layer()
        .case_summary()
        .map_err(ApiError::from)
}

pub fn open_case(request: OpenCaseRequest) -> Result<CaseSummary> {
    let workspace = CaseWorkspace::open(request.case_root)?;
    workspace
        .query_layer()
        .case_summary()
        .map_err(ApiError::from)
}

pub fn clear_case_workspace(request: ClearCaseRequest) -> Result<ClearCaseResult> {
    let case_root = PathBuf::from(request.case_root);
    let manifest_path = case_root.join("meta").join("case.json");
    if !manifest_path.exists() {
        return Err(ApiError::InvalidRequest(format!(
            "case manifest not found at {}",
            manifest_path.display()
        )));
    }

    let managed_names = ["raw", "inventory", "lake", "read_models", "indexes", "meta"];
    let mut removed_paths = Vec::new();
    for name in managed_names {
        let path = case_root.join(name);
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
        removed_paths.push(path.display().to_string());
    }

    let root_removed = if case_root.exists() && fs::read_dir(&case_root)?.next().is_none() {
        fs::remove_dir(&case_root)?;
        true
    } else {
        false
    };

    Ok(ClearCaseResult {
        case_root: case_root.display().to_string(),
        removed_paths,
        root_removed,
    })
}

pub fn get_case_custody_profile(case_root: &str) -> Result<CaseCustodyProfile> {
    let workspace = CaseWorkspace::open(case_root)?;
    load_case_custody_profile(&workspace)
}

pub fn set_case_custody_profile(request: CaseCustodyProfileRequest) -> Result<CaseCustodyProfile> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let profile = case_custody_profile_from_request(&workspace, request)?;
    save_case_custody_profile(&workspace, &profile)?;
    append_audit_log(
        &workspace,
        "case_custody_profile_updated",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        "case custody profile updated",
        serde_json::json!({
            "investigator": profile.investigator.as_deref(),
            "custodian": profile.custodian.as_deref(),
            "organization": profile.organization.as_deref(),
            "evidence_source": profile.evidence_source.as_deref(),
            "acquisition_method": profile.acquisition_method.as_deref(),
            "acquired_at": profile.acquired_at.as_deref(),
        }),
    )?;
    Ok(profile)
}

pub fn rebuild_analysis_read_models(case_root: &str) -> Result<CaseSummary> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    rebuild_case_analysis(&workspace, &queue, "manual_rebuild")?;
    maybe_start_auto_analysis_read_model_refresh(&workspace, &queue, "manual_rebuild")?;
    append_audit_log(
        &workspace,
        "analysis_read_models_rebuilt",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        "analysis read models rebuilt",
        serde_json::json!({ "mode": "manual_rebuild" }),
    )?;
    workspace
        .query_layer()
        .case_summary()
        .map_err(ApiError::from)
}

pub fn start_analysis_read_model_jobs(
    case_root: &str,
    trigger: Option<String>,
) -> Result<Vec<JobRecord>> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let trigger = trigger
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("manual_refresh");
    let jobs = maybe_start_auto_analysis_read_model_refresh(&workspace, &queue, trigger)?;
    append_audit_log(
        &workspace,
        "analysis_read_model_jobs_requested",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        &format!(
            "analysis read model background jobs requested: {}",
            jobs.len()
        ),
        serde_json::json!({
            "trigger": trigger,
            "job_ids": jobs.iter().map(|job| job.job_id.as_str()).collect::<Vec<_>>(),
            "job_kinds": jobs.iter().map(|job| job.kind.as_str()).collect::<Vec<_>>(),
        }),
    )?;
    Ok(jobs)
}

pub fn ingest_fake_artifact(request: FakeArtifactRequest) -> Result<CaseSummary> {
    let parser = FakeParser;
    ingest_bytes(
        &request.case_root,
        &request.original_path,
        request.content.into_bytes(),
        &parser,
    )
}

pub fn ingest_uploaded_artifact(request: UploadedArtifactRequest) -> Result<CaseSummary> {
    let parser = StructuredArtifactParser;
    let bytes = BASE64_STANDARD.decode(request.content_base64)?;
    ingest_bytes(&request.case_root, &request.original_path, bytes, &parser)
}

pub fn scan_local_path(request: LocalPathScanRequest) -> Result<LocalPathScanResult> {
    let input_path = PathBuf::from(&request.input_path);
    let recursive = request.recursive.unwrap_or(true);
    let source_files = collect_local_source_files(&input_path, recursive)?;
    let mut total_bytes = 0i64;
    for source_path in &source_files {
        if let Ok(metadata) = fs::metadata(source_path) {
            total_bytes = total_bytes.saturating_add(metadata.len() as i64);
        }
    }
    Ok(LocalPathScanResult {
        file_count: source_files.len(),
        total_bytes,
    })
}

pub fn ingest_local_path(request: LocalPathIngestRequest) -> Result<LocalPathIngestResult> {
    let input_path = PathBuf::from(&request.input_path);
    if !input_path.exists() {
        return Err(ApiError::InvalidRequest(format!(
            "input path not found: {}",
            input_path.display()
        )));
    }

    let recursive = request.recursive.unwrap_or(true);
    let mut source_files = collect_local_source_files(&input_path, recursive)?;
    let base_dir = if input_path.is_dir() {
        input_path.clone()
    } else {
        input_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    sort_local_source_files(&mut source_files, &base_dir);
    let defer_analysis_rebuild = input_path.is_dir() && source_files.len() > 1;
    let skip_existing_files = input_path.is_dir();
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let existing_inventory = if skip_existing_files {
        existing_local_file_inventory(&workspace)?
    } else {
        HashMap::new()
    };
    let mut skipped_count = 0usize;
    let mut errors = Vec::new();
    let mut tasks = Vec::new();
    for source_path in source_files {
        let original_path = local_original_path(&source_path, &base_dir);
        if skip_existing_files {
            match should_skip_existing_local_file(&existing_inventory, &source_path, &original_path)
            {
                Ok(true) => {
                    skipped_count += 1;
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    errors.push(format!("{}: {error}", source_path.display()));
                    continue;
                }
            }
        }
        tasks.push(LocalIngestTask {
            source_path,
            original_path,
        });
    }
    let (file_count, mut ingest_errors, worker_count) = ingest_local_tasks(
        &request.case_root,
        tasks,
        !defer_analysis_rebuild,
        input_path.is_dir(),
    )?;
    errors.append(&mut ingest_errors);
    if defer_analysis_rebuild && file_count > 0 {
        let queue = JobQueue::open(workspace.jobs_db_path())?;
        maybe_start_auto_analysis_read_model_refresh(&workspace, &queue, "local_path_batch")?;
    }
    let summary = get_case_summary(&request.case_root)?;
    append_audit_log(
        &workspace,
        "local_path_ingested",
        if input_path.is_dir() {
            "directory"
        } else {
            "file"
        },
        None,
        &format!(
            "local path ingest completed: {} files, {} skipped, {} failed",
            file_count,
            skipped_count,
            errors.len()
        ),
        serde_json::json!({
            "input_path": request.input_path,
            "recursive": recursive,
            "file_count": file_count,
            "skipped_count": skipped_count,
            "failed_count": errors.len(),
            "worker_count": worker_count,
            "errors_sample": errors.iter().take(10).collect::<Vec<_>>(),
        }),
    )?;
    Ok(LocalPathIngestResult {
        summary,
        file_count,
        skipped_count,
        failed_count: errors.len(),
        worker_count,
        errors,
    })
}

fn ingest_local_tasks(
    case_root: &str,
    tasks: Vec<LocalIngestTask>,
    rebuild_analysis: bool,
    allow_parallel: bool,
) -> Result<(usize, Vec<String>, usize)> {
    if tasks.is_empty() {
        return Ok((0, Vec::new(), 0));
    }
    let worker_count = if allow_parallel {
        local_ingest_worker_count(tasks.len())
    } else {
        1
    };
    if worker_count <= 1 || tasks.len() <= 1 {
        let mut file_count = 0usize;
        let mut errors = Vec::new();
        for task in tasks {
            match ingest_local_file_no_summary(
                case_root,
                &task.source_path,
                &task.original_path,
                rebuild_analysis,
            ) {
                Ok(_) => file_count += 1,
                Err(error) => errors.push(format!("{}: {error}", task.source_path.display())),
            }
        }
        return Ok((file_count, errors, worker_count));
    }

    let queue = Arc::new(Mutex::new(VecDeque::from(tasks)));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let case_root = Arc::new(case_root.to_string());
    let mut handles = Vec::new();

    for worker_index in 0..worker_count {
        let queue = Arc::clone(&queue);
        let errors = Arc::clone(&errors);
        let completed = Arc::clone(&completed);
        let case_root = Arc::clone(&case_root);
        let thread_name = format!("taotie-ingest-worker-{worker_index}");
        let handle = std::thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || loop {
                let task = {
                    let mut queue = match queue.lock() {
                        Ok(queue) => queue,
                        Err(_) => return,
                    };
                    queue.pop_front()
                };
                let Some(task) = task else {
                    return;
                };
                match ingest_local_file_no_summary(
                    &case_root,
                    &task.source_path,
                    &task.original_path,
                    rebuild_analysis,
                ) {
                    Ok(_) => {
                        completed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        if let Ok(mut errors) = errors.lock() {
                            errors.push(format!("{}: {error}", task.source_path.display()));
                        }
                    }
                }
            })
            .map_err(ApiError::Io)?;
        handles.push((thread_name, handle));
    }

    for (thread_name, handle) in handles {
        if handle.join().is_err() {
            if let Ok(mut errors) = errors.lock() {
                errors.push(format!("{thread_name}: worker panicked"));
            }
        }
    }

    let errors = Arc::try_unwrap(errors)
        .ok()
        .and_then(|errors| errors.into_inner().ok())
        .unwrap_or_else(|| vec!["ingest worker error collection failed".to_string()]);
    Ok((completed.load(Ordering::Relaxed), errors, worker_count))
}

fn local_ingest_worker_count(task_count: usize) -> usize {
    if task_count <= 1 {
        return task_count.max(1);
    }
    let configured = env::var("TAOTIE4_INGEST_WORKERS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0);
    let available = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);
    let default_workers = available
        .saturating_sub(1)
        .max(2)
        .min(DEFAULT_MAX_LOCAL_INGEST_WORKERS);
    configured.unwrap_or(default_workers).max(1).min(task_count)
}

fn storage_write_lock() -> Result<std::sync::MutexGuard<'static, ()>> {
    STORAGE_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| ApiError::InvalidRequest("storage write lock poisoned".to_string()))
}

fn existing_local_file_inventory(
    workspace: &CaseWorkspace,
) -> Result<HashMap<String, Vec<(i64, String)>>> {
    let mut out: HashMap<String, Vec<(i64, String)>> = HashMap::new();
    let query = workspace.query_layer();
    let mut cursor = None;
    loop {
        let page = query.file_page(FilePageQuery {
            limit: Some(500),
            cursor,
        })?;
        let Page { rows, next_cursor } = page;
        for file in rows {
            if file.parser_status == ParserStatus::Parsed {
                out.entry(file.normalized_path)
                    .or_default()
                    .push((file.size, file.sha256));
            }
        }
        cursor = next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(out)
}

fn should_skip_existing_local_file(
    existing: &HashMap<String, Vec<(i64, String)>>,
    source_path: &Path,
    original_path: &str,
) -> Result<bool> {
    let normalized_path = original_path.replace('\\', "/");
    let Some(candidates) = existing.get(&normalized_path) else {
        return Ok(false);
    };
    let size = fs::metadata(source_path)?.len() as i64;
    Ok(candidates
        .iter()
        .any(|(candidate_size, _)| *candidate_size == size))
}

fn sort_local_source_files(source_files: &mut [PathBuf], base_dir: &Path) {
    source_files.sort_by(|left, right| {
        let left_original = local_original_path(left, base_dir);
        let right_original = local_original_path(right, base_dir);
        local_ingest_priority(&left_original)
            .cmp(&local_ingest_priority(&right_original))
            .then_with(|| left_original.cmp(&right_original))
    });
}

fn local_original_path(source_path: &Path, base_dir: &Path) -> String {
    let relative = source_path
        .strip_prefix(base_dir)
        .unwrap_or(source_path)
        .to_string_lossy()
        .replace('\\', "/");
    normalize_local_original_path(&relative)
}

fn normalize_local_original_path(relative_path: &str) -> String {
    for wrapper in ["Triage/", "Collection/"] {
        if let Some(stripped) = relative_path.strip_prefix(wrapper) {
            return stripped.to_string();
        }
    }
    relative_path.to_string()
}

fn local_ingest_priority(original_path: &str) -> u8 {
    let artifact_type = detect_artifact_type(original_path);
    match artifact_type.as_str() {
        "mft" => 0,
        "usn_jrnl" | "ntfs_logfile" => 1,
        "evtx" | "hayabusa" => 2,
        "prefetch" | "amcache" => 3,
        "registry_hive" | "registry_log" | "scheduled_task" => 4,
        "lnk" | "jump_list" | "windows_search_log" => 5,
        "defender" | "defender_mplog" | "defender_operational" => 6,
        "srum" | "web_cache" | "browser" | "onedrive_log" | "filezilla" => 7,
        "text_log" | "json" | "jsonl" | "csv" | "xml" => 20,
        "archive" | "document" | "network_capture" | "credential_store" => 40,
        "vmem" => 90,
        _ => 60,
    }
}

fn should_defer_synchronous_analysis_rebuild(artifact_type: &str, event_count: usize) -> bool {
    event_count > SYNC_ANALYSIS_EVENT_LIMIT
        || matches!(artifact_type, "mft" | "usn_jrnl" | "ntfs_logfile" | "vmem")
            && event_count > 1_000
}

fn collect_local_source_files(input_path: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    if !input_path.exists() {
        return Err(ApiError::InvalidRequest(format!(
            "input path not found: {}",
            input_path.display()
        )));
    }
    let mut source_files = Vec::new();
    if input_path.is_file() {
        source_files.push(input_path.to_path_buf());
    } else if input_path.is_dir() {
        if recursive {
            collect_files_recursive(input_path, &mut source_files)?;
        } else {
            for entry in fs::read_dir(input_path)? {
                let path = entry?.path();
                if path.is_file() {
                    source_files.push(path);
                }
            }
        }
    }
    Ok(source_files)
}

fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files_recursive(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn ingest_local_file_no_summary(
    case_root: &str,
    source_path: &Path,
    original_path: &str,
    rebuild_analysis: bool,
) -> Result<()> {
    ingest_local_file_inner(case_root, source_path, original_path, rebuild_analysis)
}

fn ingest_local_file_inner(
    case_root: &str,
    source_path: &Path,
    original_path: &str,
    rebuild_analysis: bool,
) -> Result<()> {
    let parser = StructuredArtifactParser;
    let detect_preview = read_parse_preview(source_path, LOCAL_DETECT_PREVIEW_BYTES)?;
    let artifact_type = detect_artifact_type_from_bytes(original_path, &detect_preview);
    let source_size = fs::metadata(source_path)?.len() as i64;
    let parse_preview_limit = local_parse_preview_limit(&artifact_type, source_size);
    let preview = if parse_preview_limit <= detect_preview.len() {
        detect_preview
    } else {
        read_parse_preview(source_path, parse_preview_limit)?
    };
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let intake_job = queue.enqueue(
        workspace.manifest().case_id.as_str(),
        JobKind::IntakeFile,
        100,
        serde_json::json!({
            "original_path": original_path,
            "source_path": source_path.display().to_string(),
            "artifact_type": artifact_type,
            "mode": "local_path",
        })
        .to_string(),
        default_resource_limits(),
    )?;
    let object = workspace.raw_object_store().store_file(source_path)?;
    queue.complete(&intake_job.job_id)?;
    let parse_path = if should_parse_from_stored_path(&artifact_type, original_path, &preview) {
        Some(object.path.clone())
    } else {
        None
    };
    if should_defer_local_path_parse(&artifact_type, object.size, parse_path.as_deref()) {
        spawn_deferred_local_path_parse(
            case_root.to_string(),
            original_path.to_string(),
            artifact_type,
            preview,
            object,
            parse_path,
            rebuild_analysis,
        )?;
        return Ok(());
    }
    ingest_stored_object_no_summary(
        &workspace,
        &queue,
        original_path,
        artifact_type,
        preview,
        object,
        &parser,
        parse_path.as_deref(),
        rebuild_analysis,
    )
}

fn local_parse_preview_limit(artifact_type: &str, source_size: i64) -> usize {
    let limit = match artifact_type {
        "evtx" | "mft" | "usn_jrnl" | "ntfs_logfile" => LOCAL_DETECT_PREVIEW_BYTES,
        "text_log"
        | "json"
        | "jsonl"
        | "csv"
        | "xml"
        | "html"
        | "defender_mplog"
        | "defender_operational"
        | "onedrive_log"
        | "filezilla" => LOCAL_TEXT_PARSE_PREVIEW_BYTES,
        "prefetch" | "amcache" | "registry_hive" | "scheduled_task" | "lnk" | "jump_list"
        | "browser" | "web_cache" | "srum" | "sqlite" | "windows_search_log" => {
            LOCAL_STRUCTURED_PARSE_PREVIEW_BYTES
        }
        _ => LOCAL_BINARY_PARSE_PREVIEW_BYTES,
    };
    limit.min(source_size.max(0) as usize)
}

fn should_defer_local_path_parse(
    artifact_type: &str,
    object_size: i64,
    parse_path: Option<&Path>,
) -> bool {
    let _ = (artifact_type, object_size, parse_path);
    false
}

fn spawn_deferred_local_path_parse(
    case_root: String,
    original_path: String,
    artifact_type: String,
    preview: Vec<u8>,
    object: StoredObject,
    parse_path: Option<PathBuf>,
    rebuild_analysis: bool,
) -> Result<()> {
    let thread_name = format!("taotie-deferred-parse-{}", short_id(&object.sha256));
    std::thread::Builder::new()
        .name(thread_name.clone())
        .spawn(move || {
            if let Err(error) = run_deferred_local_path_parse(
                &case_root,
                &original_path,
                artifact_type,
                preview,
                object,
                parse_path,
                rebuild_analysis,
            ) {
                eprintln!("{thread_name}: deferred parse failed: {error}");
            }
        })
        .map(|_| ())
        .map_err(ApiError::Io)
}

fn run_deferred_local_path_parse(
    case_root: &str,
    original_path: &str,
    artifact_type: String,
    preview: Vec<u8>,
    object: StoredObject,
    parse_path: Option<PathBuf>,
    rebuild_analysis: bool,
) -> Result<CaseSummary> {
    let parser = StructuredArtifactParser;
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    ingest_stored_object(
        &workspace,
        &queue,
        original_path,
        artifact_type,
        preview,
        object,
        &parser,
        parse_path.as_deref(),
        rebuild_analysis,
    )
}

fn read_parse_preview(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max_bytes as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn should_parse_from_stored_path(artifact_type: &str, original_path: &str, preview: &[u8]) -> bool {
    match artifact_type {
        "evtx" => preview.starts_with(b"ElfFile"),
        "mft" => preview.starts_with(b"FILE"),
        "usn_jrnl" => {
            let lower = original_path.to_ascii_lowercase();
            (lower.ends_with("$j") || lower.contains("/$j") || lower.contains("\\$j"))
                && !matches!(
                    Path::new(original_path)
                        .extension()
                        .and_then(|value| value.to_str())
                        .map(|value| value.to_ascii_lowercase())
                        .as_deref(),
                    Some("csv" | "json" | "jsonl" | "txt" | "log" | "xml")
                )
        }
        _ => false,
    }
}

fn ingest_bytes(
    case_root: &str,
    original_path: &str,
    bytes: Vec<u8>,
    parser: &dyn ParserAdapter,
) -> Result<CaseSummary> {
    let artifact_type = detect_artifact_type_from_bytes(original_path, &bytes);
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let intake_job = queue.enqueue(
        workspace.manifest().case_id.as_str(),
        JobKind::IntakeFile,
        100,
        serde_json::json!({
            "original_path": original_path,
            "artifact_type": artifact_type,
        })
        .to_string(),
        default_resource_limits(),
    )?;

    let object = workspace.raw_object_store().store_bytes(&bytes)?;
    queue.complete(&intake_job.job_id)?;

    ingest_stored_object(
        &workspace,
        &queue,
        original_path,
        artifact_type,
        bytes,
        object,
        parser,
        None,
        true,
    )
}

fn ingest_stored_object(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    original_path: &str,
    artifact_type: String,
    bytes: Vec<u8>,
    object: StoredObject,
    parser: &dyn ParserAdapter,
    parse_path: Option<&Path>,
    rebuild_analysis: bool,
) -> Result<CaseSummary> {
    ingest_stored_object_inner(
        workspace,
        queue,
        original_path,
        artifact_type,
        bytes,
        object,
        parser,
        parse_path,
        rebuild_analysis,
    )?;
    workspace
        .query_layer()
        .case_summary()
        .map_err(ApiError::from)
}

fn ingest_stored_object_no_summary(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    original_path: &str,
    artifact_type: String,
    bytes: Vec<u8>,
    object: StoredObject,
    parser: &dyn ParserAdapter,
    parse_path: Option<&Path>,
    rebuild_analysis: bool,
) -> Result<()> {
    ingest_stored_object_inner(
        workspace,
        queue,
        original_path,
        artifact_type,
        bytes,
        object,
        parser,
        parse_path,
        rebuild_analysis,
    )
}

fn ingest_stored_object_inner(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    original_path: &str,
    artifact_type: String,
    bytes: Vec<u8>,
    object: StoredObject,
    parser: &dyn ParserAdapter,
    parse_path: Option<&Path>,
    rebuild_analysis: bool,
) -> Result<()> {
    let metadata = parser.metadata();
    let file_id = new_id("file");
    let parse_run_id = new_id("parse");
    let started_at = now_utc();
    let parser_job = queue.enqueue(
        workspace.manifest().case_id.as_str(),
        JobKind::ParseArtifact,
        90,
        serde_json::json!({
            "file_id": file_id,
            "object_ref": object.object_ref,
            "parser": metadata.parser_name,
        })
        .to_string(),
        default_resource_limits(),
    )?;
    let parser_worker_id = format!("taotie-parser-{}", short_id(&parser_job.job_id));
    let _ = queue.start(&parser_job.job_id, &parser_worker_id)?;
    queue.update_progress(&parser_job.job_id, 0.05)?;

    let parse_input = ParserInput {
        case_id: workspace.manifest().case_id.clone(),
        source_file_id: file_id.clone(),
        object_ref: object.object_ref.clone(),
        original_path: original_path.to_string(),
        artifact_type: artifact_type.clone(),
        parse_run_id: parse_run_id.clone(),
        bytes,
    };

    workspace.append_parser_versions(&[ParserVersionRecord {
        case_id: workspace.manifest().case_id.clone(),
        parser_name: metadata.parser_name.clone(),
        parser_version: metadata.parser_version.clone(),
        recorded_at: now_utc(),
    }])?;
    workspace.append_schema_versions(&[SchemaVersionRecord {
        case_id: workspace.manifest().case_id.clone(),
        schema_name: "canonical_events".to_string(),
        schema_version: CURRENT_SCHEMA_VERSION.to_string(),
        recorded_at: now_utc(),
    }])?;

    let parse_result = match (artifact_type.as_str(), parse_path) {
        ("evtx", Some(path)) => {
            parse_evtx_path(&parse_input, &metadata, path).map(ParserOutcome::Parsed)
        }
        ("mft", Some(path)) => {
            parse_mft_path(&parse_input, &metadata, path).map(ParserOutcome::Parsed)
        }
        ("usn_jrnl", Some(path)) => {
            parse_usn_jrnl_path(&parse_input, &metadata, path).map(ParserOutcome::Parsed)
        }
        _ => parser.parse(parse_input),
    };

    match parse_result {
        Ok(ParserOutcome::Parsed(parsed)) => {
            let finished_at = now_utc();
            let entity_started_at = now_utc();
            let extract_entities_job = queue.enqueue(
                workspace.manifest().case_id.as_str(),
                JobKind::ExtractEntities,
                55,
                serde_json::json!({
                    "file_id": file_id,
                    "analyzer": "entity_edge_extraction",
                })
                .to_string(),
                default_resource_limits(),
            )?;
            let build_edges_job = queue.enqueue(
                workspace.manifest().case_id.as_str(),
                JobKind::BuildEdges,
                50,
                serde_json::json!({
                    "file_id": file_id,
                    "analyzer": "entity_edge_extraction",
                })
                .to_string(),
                default_resource_limits(),
            )?;
            let (entities, edges) =
                derive_entities_edges(&workspace.manifest().case_id, &parsed.events)?;
            let entity_run = AnalyzerRunSummary {
                run_id: new_id("analyzer"),
                case_id: workspace.manifest().case_id.clone(),
                analyzer_id: "entity_edge_extraction".to_string(),
                name: "Entity / Edge 抽出".to_string(),
                version: "taotie-port-of-taotie-v1".to_string(),
                status: "succeeded".to_string(),
                started_at: entity_started_at,
                finished_at: Some(now_utc()),
                input_count: parsed.events.len() as i64,
                output_count: (entities.len() + edges.len()) as i64,
                error_message: None,
                metadata_json: serde_json::json!({
                    "source": "taotie.t3-normalize",
                    "entities": entities.len(),
                    "edges": edges.len(),
                })
                .to_string(),
            };
            let file = file_record(
                &workspace,
                &file_id,
                original_path,
                &artifact_type,
                ParserStatus::Parsed,
                parsed.events.len() as i64,
                &object,
            );
            let parse_run = ParseRun {
                parse_run_id,
                case_id: workspace.manifest().case_id.clone(),
                file_id: file_id.clone(),
                parser_name: metadata.parser_name.clone(),
                parser_version: metadata.parser_version.clone(),
                parser_config_hash: metadata.parser_config_hash.clone(),
                schema_version: metadata.schema_version.clone(),
                status: ParseRunStatus::Succeeded,
                started_at,
                finished_at: Some(finished_at),
                duration_ms: 0,
                event_count: parsed.events.len() as i64,
                error_message: None,
            };
            let timeline_bins = build_timeline_bins(&parsed.events);
            let artifact_objects = derive_artifact_objects(&parsed.events);
            let evidence_offsets = derive_evidence_offsets(&parsed.events);
            let coverage = coverage_for_file(&file);
            let build_bins_job = queue.enqueue(
                workspace.manifest().case_id.as_str(),
                JobKind::BuildTimelineBins,
                70,
                serde_json::json!({ "file_id": file_id }).to_string(),
                default_resource_limits(),
            )?;
            let defer_sync_analysis_rebuild = rebuild_analysis
                && should_defer_synchronous_analysis_rebuild(&artifact_type, parsed.events.len());
            let append_incremental_event_rows = !rebuild_analysis || defer_sync_analysis_rebuild;
            let incremental_event_rows = if append_incremental_event_rows {
                let rows = parsed
                    .events
                    .iter()
                    .map(EventFull::to_event_row)
                    .collect::<Vec<_>>();
                Some(rows)
            } else {
                None
            };
            let incremental_event_row_count = incremental_event_rows
                .as_ref()
                .map(|rows| rows.len())
                .unwrap_or(0);
            {
                let _write_guard = storage_write_lock()?;
                workspace.append_files(&[file])?;
                workspace.append_parse_runs(&[parse_run])?;
                workspace.append_events_full(&parsed.events)?;
                workspace.append_raw_records(&parsed.raw_records)?;
                workspace.append_artifact_objects(&artifact_objects)?;
                workspace.append_evidence_offsets(&evidence_offsets)?;
                workspace.append_entities(&entities)?;
                workspace.append_edges(&edges)?;
                workspace.append_timeline_bins(&timeline_bins)?;
                workspace.append_coverage_summary(&[coverage])?;
                workspace.append_analyzer_runs(&[entity_run])?;
                if let Some(rows) = &incremental_event_rows {
                    workspace.append_event_rows(rows)?;
                }
                queue.complete(&parser_job.job_id)?;
                queue.complete(&extract_entities_job.job_id)?;
                queue.complete(&build_edges_job.job_id)?;
                queue.complete(&build_bins_job.job_id)?;
                append_audit_log(
                    workspace,
                    "artifact_ingested",
                    "file",
                    Some(file_id.as_str()),
                    &format!(
                        "parsed {} as {} with {} events",
                        original_path,
                        artifact_type,
                        parsed.events.len()
                    ),
                    serde_json::json!({
                        "original_path": original_path,
                        "artifact_type": artifact_type,
                        "parser_status": "parsed",
                        "event_count": parsed.events.len(),
                        "artifact_object_count": artifact_objects.len(),
                        "evidence_offset_count": evidence_offsets.len(),
                        "incremental_event_row_count": incremental_event_row_count,
                        "sync_analysis_rebuild_deferred": defer_sync_analysis_rebuild,
                        "sha256": object.sha256,
                        "object_ref": object.object_ref,
                    }),
                )?;
            }
            if rebuild_analysis && !defer_sync_analysis_rebuild {
                rebuild_case_analysis(workspace, queue, "single_file")?;
            }
            if rebuild_analysis {
                let trigger = if defer_sync_analysis_rebuild {
                    "high_volume_single_file_ingest"
                } else {
                    "single_file_ingest"
                };
                maybe_start_auto_analysis_read_model_refresh(workspace, queue, trigger)?;
            }
        }
        Ok(ParserOutcome::Unsupported { reason }) => {
            let file = file_record(
                &workspace,
                &file_id,
                original_path,
                &artifact_type,
                ParserStatus::Unsupported,
                0,
                &object,
            );
            let parse_run = ParseRun {
                parse_run_id: parse_run_id.clone(),
                case_id: workspace.manifest().case_id.clone(),
                file_id: file_id.clone(),
                parser_name: metadata.parser_name.clone(),
                parser_version: metadata.parser_version.clone(),
                parser_config_hash: metadata.parser_config_hash.clone(),
                schema_version: metadata.schema_version.clone(),
                status: ParseRunStatus::Unsupported,
                started_at,
                finished_at: Some(now_utc()),
                duration_ms: 0,
                event_count: 0,
                error_message: Some(reason.clone()),
            };
            {
                let _write_guard = storage_write_lock()?;
                workspace.append_files(&[file.clone()])?;
                workspace.append_parse_runs(&[parse_run])?;
                workspace.append_unsupported_files(&[UnsupportedFileRecord {
                    case_id: workspace.manifest().case_id.clone(),
                    file_id: file_id.clone(),
                    artifact_type: artifact_type.clone(),
                    reason: reason.clone(),
                    recorded_at: now_utc(),
                }])?;
                workspace.append_coverage_summary(&[coverage_for_file(&file)])?;
                queue.complete(&parser_job.job_id)?;
                append_audit_log(
                    workspace,
                    "artifact_unsupported",
                    "file",
                    Some(file_id.as_str()),
                    &format!("unsupported {} as {}", original_path, artifact_type),
                    serde_json::json!({
                        "original_path": original_path,
                        "artifact_type": artifact_type,
                        "parser_status": "unsupported",
                        "reason": reason,
                        "sha256": object.sha256,
                        "object_ref": object.object_ref,
                    }),
                )?;
            }
        }
        Err(error) => {
            let error_message = error.to_string();
            let file = file_record(
                &workspace,
                &file_id,
                original_path,
                &artifact_type,
                ParserStatus::Failed,
                0,
                &object,
            );
            let parse_run = ParseRun {
                parse_run_id: parse_run_id.clone(),
                case_id: workspace.manifest().case_id.clone(),
                file_id: file_id.clone(),
                parser_name: metadata.parser_name.clone(),
                parser_version: metadata.parser_version.clone(),
                parser_config_hash: metadata.parser_config_hash.clone(),
                schema_version: metadata.schema_version.clone(),
                status: ParseRunStatus::Failed,
                started_at,
                finished_at: Some(now_utc()),
                duration_ms: 0,
                event_count: 0,
                error_message: Some(error_message.clone()),
            };
            {
                let _write_guard = storage_write_lock()?;
                workspace.append_files(&[file.clone()])?;
                workspace.append_parse_runs(&[parse_run])?;
                workspace.append_parser_errors(&[ParserErrorRecord {
                    case_id: workspace.manifest().case_id.clone(),
                    parse_run_id,
                    file_id: file_id.clone(),
                    parser_name: metadata.parser_name.clone(),
                    error_message: error_message.clone(),
                    recorded_at: now_utc(),
                }])?;
                workspace.append_failed_parser_summary(&[FailedParserSummary {
                    case_id: workspace.manifest().case_id.clone(),
                    parser_name: metadata.parser_name.clone(),
                    artifact_type: artifact_type.clone(),
                    failure_count: 1,
                    last_error: error_message.clone(),
                    last_seen_at: now_utc(),
                }])?;
                workspace.append_coverage_summary(&[coverage_for_file(&file)])?;
                queue.fail(&parser_job.job_id, &error_message)?;
                append_audit_log(
                    workspace,
                    "artifact_parse_failed",
                    "file",
                    Some(file_id.as_str()),
                    &format!("failed to parse {} as {}", original_path, artifact_type),
                    serde_json::json!({
                        "original_path": original_path,
                        "artifact_type": artifact_type,
                        "parser_status": "failed",
                        "error": error_message,
                        "sha256": object.sha256,
                        "object_ref": object.object_ref,
                    }),
                )?;
            }
        }
    }

    Ok(())
}

fn rebuild_case_analysis(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    mode: &str,
) -> Result<FindingRebuildResult> {
    let findings_started_at = now_utc();
    let findings_job = queue.enqueue(
        workspace.manifest().case_id.as_str(),
        JobKind::RunFindings,
        60,
        serde_json::json!({
            "analyzer": "finding_rebuild",
            "mode": mode,
        })
        .to_string(),
        default_resource_limits(),
    )?;
    let chain_started_at = now_utc();
    let build_chains_job = queue.enqueue(
        workspace.manifest().case_id.as_str(),
        JobKind::BuildCorrelationChains,
        45,
        serde_json::json!({
            "analyzer": "correlation_chains",
            "mode": mode,
        })
        .to_string(),
        default_resource_limits(),
    )?;
    let build_rows_job = queue.enqueue(
        workspace.manifest().case_id.as_str(),
        JobKind::BuildEventRows,
        80,
        serde_json::json!({ "mode": mode }).to_string(),
        default_resource_limits(),
    )?;

    let lake_event_count = workspace.query_layer().lake_event_count()?;
    let structure_rebuild = rebuild_derived_evidence_models(workspace, lake_event_count)?;
    let large_case_fast_path = lake_event_count > 500_000
        && std::env::var("TAOTIE4_FORCE_FULL_ANALYSIS").as_deref() != Ok("1");
    if large_case_fast_path {
        let event_row_count = workspace.query_layer().rebuild_event_rows_from_lake()?;
        let build_fast_answers =
            std::env::var("TAOTIE4_BUILD_FAST_ANSWER_CANDIDATES").as_deref() == Ok("1");
        let answer_candidate_events = if build_fast_answers {
            workspace
                .query_layer()
                .analyzer_events_for_answer_candidates()?
        } else {
            Vec::new()
        };
        let answer_candidates =
            build_answer_candidates(&workspace.manifest().case_id, &answer_candidate_events)?;
        workspace.replace_answer_candidates(&answer_candidates)?;
        let existing_findings = workspace
            .query_layer()
            .finding_summary(Some(1_000))?
            .into_iter()
            .map(|row| row.finding_count.max(0) as usize)
            .sum::<usize>();
        let result = FindingRebuildResult {
            input_event_count: lake_event_count,
            heuristic_count: 0,
            chain_count: 0,
            hayabusa_count: 0,
            ioc_count: 0,
            final_count: existing_findings,
            override_count: load_finding_overrides(workspace)?
                .iter()
                .filter(|row| row.enabled)
                .count(),
            event_row_count,
        };
        workspace.append_analyzer_runs(&[AnalyzerRunSummary {
            run_id: new_id("analyzer"),
            case_id: workspace.manifest().case_id.clone(),
            analyzer_id: "large_case_fast_read_models".to_string(),
            name: "巨大ケース read model 高速復旧".to_string(),
            version: "taotie-large-case-fast-path-v1".to_string(),
            status: "succeeded".to_string(),
            started_at: findings_started_at,
            finished_at: Some(now_utc()),
            input_count: lake_event_count as i64,
            output_count: event_row_count as i64,
            error_message: None,
            metadata_json: serde_json::json!({
                "mode": mode,
                "read_model": "read_models/event_rows",
                "answer_candidate_count": answer_candidates.len(),
                "answer_source_event_count": answer_candidate_events.len(),
                "existing_finding_count": existing_findings,
                "skipped_full_analysis": true,
                "skipped_answer_candidate_scan": !build_fast_answers,
                "answer_candidate_scan_env": "TAOTIE4_BUILD_FAST_ANSWER_CANDIDATES=1",
                "force_full_analysis_env": "TAOTIE4_FORCE_FULL_ANALYSIS=1",
                "artifact_object_count": structure_rebuild.0,
                "evidence_offset_count": structure_rebuild.1,
            })
            .to_string(),
        }])?;
        queue.complete(&findings_job.job_id)?;
        queue.complete(&build_chains_job.job_id)?;
        queue.complete(&build_rows_job.job_id)?;
        return Ok(result);
    }

    let correlation_chains = if large_case_fast_path {
        workspace.query_layer().correlation_chains(Some(500))?
    } else {
        let chains = workspace
            .query_layer()
            .rebuild_correlation_chains(Some(500))?;
        workspace.replace_correlation_chains(&chains)?;
        chains
    };
    let finding_rebuild = rebuild_findings_and_event_rows(workspace, &correlation_chains)?;
    let answer_candidate_events = workspace
        .query_layer()
        .analyzer_events_for_answer_candidates()?;
    let answer_candidates =
        build_answer_candidates(&workspace.manifest().case_id, &answer_candidate_events)?;
    workspace.replace_answer_candidates(&answer_candidates)?;
    let analyzer_run = AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "heuristic_findings".to_string(),
        name: "ヒューリスティック検知".to_string(),
        version: "taotie-port-of-taotie-v1".to_string(),
        status: "succeeded".to_string(),
        started_at: findings_started_at.clone(),
        finished_at: Some(now_utc()),
        input_count: finding_rebuild.input_event_count as i64,
        output_count: finding_rebuild.heuristic_count as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "source": "taotie.t3-detect",
            "rule_count": heuristic_rules().len(),
            "mode": mode,
            "hayabusa_count": finding_rebuild.hayabusa_count,
            "ioc_count": finding_rebuild.ioc_count,
            "override_count": finding_rebuild.override_count,
            "large_case_fast_path": large_case_fast_path,
        })
        .to_string(),
    };
    let chain_finding_run = AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "correlation_findings".to_string(),
        name: "相関 Finding 化".to_string(),
        version: "taotie-port-of-taotie-v1".to_string(),
        status: "succeeded".to_string(),
        started_at: findings_started_at,
        finished_at: Some(now_utc()),
        input_count: correlation_chains.len() as i64,
        output_count: finding_rebuild.chain_count as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "source": "read_models/correlation_chains",
            "minimum_severity": "medium",
            "mode": mode,
            "output_after_overrides": finding_rebuild.final_count,
            "large_case_fast_path": large_case_fast_path,
        })
        .to_string(),
    };
    let chain_run = AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "correlation_chains".to_string(),
        name: "相関チェーン".to_string(),
        version: "taotie-port-of-taotie-v1".to_string(),
        status: "succeeded".to_string(),
        started_at: chain_started_at,
        finished_at: Some(now_utc()),
        input_count: finding_rebuild.input_event_count as i64,
        output_count: correlation_chains.len() as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "source": "taotie.q_correlation_chains",
            "read_model": "read_models/correlation_chains",
            "mode": mode,
            "large_case_fast_path": large_case_fast_path,
            "reused_existing_read_model": large_case_fast_path,
            "artifact_object_count": structure_rebuild.0,
            "evidence_offset_count": structure_rebuild.1,
        })
        .to_string(),
    };
    let answer_run = AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "answer_candidates".to_string(),
        name: "調査候補カード".to_string(),
        version: "taotie-answer-candidates-v1".to_string(),
        status: "succeeded".to_string(),
        started_at: now_utc(),
        finished_at: Some(now_utc()),
        input_count: finding_rebuild.input_event_count as i64,
        output_count: answer_candidates.len() as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "read_model": "read_models/answer_candidates",
            "mode": mode,
            "source_event_count": answer_candidate_events.len(),
        })
        .to_string(),
    };
    workspace.append_analyzer_runs(&[analyzer_run, chain_finding_run, chain_run, answer_run])?;
    queue.complete(&findings_job.job_id)?;
    queue.complete(&build_chains_job.job_id)?;
    queue.complete(&build_rows_job.job_id)?;
    Ok(finding_rebuild)
}

pub fn get_case_summary(case_root: &str) -> Result<CaseSummary> {
    query(case_root)?.case_summary().map_err(ApiError::from)
}

pub fn get_coverage_summary(case_root: &str) -> Result<Vec<CoverageSummary>> {
    query(case_root)?.coverage_summary().map_err(ApiError::from)
}

pub fn get_failed_parser_summary(case_root: &str) -> Result<Vec<FailedParserSummary>> {
    query(case_root)?
        .failed_parser_summary()
        .map_err(ApiError::from)
}

pub fn get_finding_summary(case_root: &str, limit: Option<usize>) -> Result<Vec<FindingSummary>> {
    query(case_root)?
        .finding_summary(limit)
        .map_err(ApiError::from)
}

pub fn get_answer_candidates(request: AnswerCandidateQuery) -> Result<Vec<AnswerCandidate>> {
    query(&request.case_root)?
        .answer_candidates(request.question_key.as_deref(), request.limit)
        .map_err(ApiError::from)
}

pub fn start_answer_candidate_build(
    request: StartAnswerCandidateBuildRequest,
) -> Result<JobRecord> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    if let Some(active) = active_answer_candidate_job(&queue)? {
        return Ok(active);
    }
    let job = enqueue_answer_candidate_job(&workspace, &queue, "background", 42)?;
    spawn_answer_candidate_job(&request.case_root, &queue, &job)?;
    Ok(job)
}

pub fn get_triage_actions(case_root: &str, limit: Option<usize>) -> Result<Vec<TriageAction>> {
    let workspace = CaseWorkspace::open(case_root)?;
    build_triage_actions(&workspace, limit)
}

pub fn get_case_detection_evaluation(case_root: &str) -> Result<CaseDetectionEvaluation> {
    let workspace = CaseWorkspace::open(case_root)?;
    build_case_detection_evaluation(&workspace)
}

pub fn get_finding_event_page(
    case_root: &str,
    query_page: FindingEventPageQuery,
) -> Result<Page<EventRow>> {
    query(case_root)?
        .finding_event_page(query_page)
        .map_err(ApiError::from)
}

pub fn get_ioc_matches(request: IocMatchRequest) -> Result<Vec<IocHit>> {
    query(&request.case_root)?
        .ioc_match(&request.indicators, request.limit)
        .map_err(ApiError::from)
}

pub fn run_ioc_findings(request: IocFindingRequest) -> Result<Vec<FindingSummary>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let indicators = normalize_ioc_indicators(&request.indicators, request.limit.unwrap_or(500));
    save_ioc_indicators(&workspace, &indicators)?;
    let started_at = now_utc();
    let chains = workspace.query_layer().correlation_chains(Some(500))?;
    let result = rebuild_findings_and_event_rows(&workspace, &chains)?;
    workspace.append_analyzer_runs(&[AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "ioc_findings".to_string(),
        name: "IOC Finding 化".to_string(),
        version: "taotie-ioc-v1".to_string(),
        status: "succeeded".to_string(),
        started_at,
        finished_at: Some(now_utc()),
        input_count: indicators.len() as i64,
        output_count: result.ioc_count as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "indicator_count": indicators.len(),
            "event_row_count": result.event_row_count,
        })
        .to_string(),
    }])?;
    append_audit_log(
        &workspace,
        "ioc_findings_generated",
        "ioc",
        None,
        &format!("IOC findings generated for {} indicators", indicators.len()),
        serde_json::json!({
            "indicator_count": indicators.len(),
            "ioc_finding_count": result.ioc_count,
            "event_row_count": result.event_row_count,
        }),
    )?;
    workspace
        .query_layer()
        .finding_summary(Some(100))
        .map_err(ApiError::from)
}

pub fn get_ioc_event_page(
    case_root: &str,
    query_page: IocEventPageQuery,
) -> Result<Page<EventRow>> {
    query(case_root)?
        .ioc_event_page(query_page)
        .map_err(ApiError::from)
}

pub fn get_defender_summary(case_root: &str, limit: Option<usize>) -> Result<Vec<DefenderSummary>> {
    query(case_root)?
        .defender_summary(limit)
        .map_err(ApiError::from)
}

pub fn get_defender_event_page(
    case_root: &str,
    query_page: DefenderEventPageQuery,
) -> Result<Page<EventRow>> {
    query(case_root)?
        .defender_event_page(query_page)
        .map_err(ApiError::from)
}

pub fn get_prefetch_summary(case_root: &str, limit: Option<usize>) -> Result<Vec<PrefetchSummary>> {
    query(case_root)?
        .prefetch_summary(limit)
        .map_err(ApiError::from)
}

pub fn get_finding_overrides(case_root: &str) -> Result<Vec<FindingOverride>> {
    let workspace = CaseWorkspace::open(case_root)?;
    load_finding_overrides(&workspace)
}

pub fn get_finding_reviews(case_root: &str) -> Result<Vec<FindingReview>> {
    let workspace = CaseWorkspace::open(case_root)?;
    load_finding_reviews(&workspace)
}

pub fn get_finding_review_summary(case_root: &str) -> Result<FindingReviewSummary> {
    let workspace = CaseWorkspace::open(case_root)?;
    let reviews = load_finding_reviews(&workspace)?;
    Ok(build_finding_review_summary(&workspace, &reviews))
}

pub fn set_finding_review(request: FindingReviewRequest) -> Result<Vec<FindingReview>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let mut reviews = load_finding_reviews(&workspace)?;
    let review = finding_review_from_request(&workspace, request)?;
    let target_engine = review.engine.clone();
    let target_rule_id = review.rule_id.clone();
    let target_title = review.title.clone();
    if let Some(existing) = reviews
        .iter_mut()
        .find(|existing| same_finding_review_target(existing, &review))
    {
        existing.status = review.status;
        existing.reviewer = review.reviewer;
        existing.assignee = review.assignee;
        existing.tags_json = review.tags_json;
        existing.due_at = review.due_at;
        existing.comment = review.comment;
        existing.updated_at = now_utc();
    } else {
        reviews.push(review);
    }
    save_finding_reviews(&workspace, &reviews)?;
    let saved = load_finding_reviews(&workspace)?;
    if let Some(row) = saved.iter().find(|row| {
        row.engine == target_engine && row.rule_id == target_rule_id && row.title == target_title
    }) {
        append_audit_log(
            &workspace,
            "finding_review_updated",
            "finding",
            Some(row.review_id.as_str()),
            &format!("review {}: {}", row.status, row.title),
            serde_json::json!({
                "engine": row.engine.as_str(),
                "rule_id": row.rule_id.as_deref(),
                "title": row.title.as_str(),
                "status": row.status.as_str(),
                "reviewer": row.reviewer.as_deref(),
                "assignee": row.assignee.as_deref(),
                "tags_json": row.tags_json.as_deref(),
                "due_at": row.due_at.as_deref(),
            }),
        )?;
    }
    Ok(saved)
}

pub fn get_case_approvals(
    case_root: &str,
    limit: Option<usize>,
) -> Result<Vec<CaseApprovalRecord>> {
    let workspace = CaseWorkspace::open(case_root)?;
    let mut approvals = load_case_approvals(&workspace)?;
    approvals.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    approvals.truncate(limit.unwrap_or(100).clamp(1, 500));
    Ok(approvals)
}

pub fn set_case_approval(request: CaseApprovalRequest) -> Result<Vec<CaseApprovalRecord>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let mut approvals = load_case_approvals(&workspace)?;
    let approval = case_approval_from_request(&workspace, request)?;
    let target_key = case_approval_target_key(&approval);
    if let Some(existing) = approvals
        .iter_mut()
        .find(|existing| case_approval_target_key(existing) == target_key)
    {
        existing.status = approval.status;
        existing.approver = approval.approver;
        existing.role = approval.role;
        existing.comment = approval.comment;
        existing.target_sha256 = approval.target_sha256;
        existing.updated_at = approval.updated_at;
    } else {
        approvals.push(approval);
    }
    save_case_approvals(&workspace, &approvals)?;
    let saved = get_case_approvals(workspace.root().to_string_lossy().as_ref(), Some(500))?;
    if let Some(row) = saved
        .iter()
        .find(|row| case_approval_target_key(row) == target_key)
    {
        append_audit_log(
            &workspace,
            "case_approval_updated",
            row.target_kind.as_str(),
            row.target_id
                .as_deref()
                .or(row.target_path.as_deref())
                .or(Some(row.approval_id.as_str())),
            &format!("approval {}: {}", row.status, approval_target_label(row)),
            serde_json::json!({
                "approval_id": row.approval_id.as_str(),
                "target_kind": row.target_kind.as_str(),
                "target_id": row.target_id.as_deref(),
                "target_path": row.target_path.as_deref(),
                "target_sha256": row.target_sha256.as_deref(),
                "status": row.status.as_str(),
                "approver": row.approver.as_deref(),
                "role": row.role.as_deref(),
            }),
        )?;
    }
    Ok(saved)
}

pub fn get_saved_searches(case_root: &str, limit: Option<usize>) -> Result<Vec<SavedSearch>> {
    get_saved_searches_for(case_root, limit, None)
}

pub fn get_saved_searches_for(
    case_root: &str,
    limit: Option<usize>,
    viewer: Option<&str>,
) -> Result<Vec<SavedSearch>> {
    let workspace = CaseWorkspace::open(case_root)?;
    let viewer = clean_saved_search_principal(viewer.map(str::to_string));
    let mut rows = load_saved_searches(&workspace)?;
    rows.retain(|row| saved_search_visible_to(row, viewer.as_deref()));
    rows.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| left.name.cmp(&right.name))
    });
    rows.truncate(limit.unwrap_or(100).clamp(1, 500));
    Ok(rows)
}

pub fn save_saved_search(request: SavedSearchRequest) -> Result<Vec<SavedSearch>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let mut rows = load_saved_searches(&workspace)?;
    let actor = clean_saved_search_principal(request.created_by.clone());
    let search = saved_search_from_request(&workspace, request)?;
    let name_key = search.name.to_ascii_lowercase();
    let owner_key = saved_search_owner(&search).map(str::to_ascii_lowercase);
    let mut audit_search_id = search.search_id.clone();
    if let Some(existing) = rows.iter_mut().find(|existing| {
        existing.name.to_ascii_lowercase() == name_key
            && saved_search_owner(existing).map(str::to_ascii_lowercase) == owner_key
    }) {
        existing.name = search.name;
        existing.query = search.query;
        existing.description = search.description;
        existing.created_by = search.created_by;
        existing.visibility = search.visibility;
        existing.shared_with = search.shared_with;
        existing.updated_at = search.updated_at;
        audit_search_id = existing.search_id.clone();
    } else {
        rows.push(search);
    }
    rows.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    rows.truncate(200);
    save_saved_searches(&workspace, &rows)?;
    let saved = get_saved_searches_for(
        workspace.root().to_string_lossy().as_ref(),
        Some(200),
        actor.as_deref(),
    )?;
    if let Some(row) = saved.iter().find(|row| row.search_id == audit_search_id) {
        append_audit_log(
            &workspace,
            "saved_search_saved",
            "saved_search",
            Some(row.search_id.as_str()),
            &format!("saved search: {}", row.name),
            serde_json::json!({
                "search_id": row.search_id.as_str(),
                "name": row.name.as_str(),
                "description": row.description.as_deref(),
                "created_by": row.created_by.as_deref(),
                "visibility": row.visibility.as_str(),
                "shared_with": &row.shared_with,
                "query": &row.query,
            }),
        )?;
    }
    Ok(saved)
}

pub fn delete_saved_search(request: DeleteSavedSearchRequest) -> Result<Vec<SavedSearch>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let mut rows = load_saved_searches(&workspace)?;
    let search_id = request.search_id.trim().to_string();
    let actor = clean_saved_search_principal(request.requested_by);
    if search_id.is_empty() {
        return Err(ApiError::InvalidRequest(
            "delete saved search requires search_id".to_string(),
        ));
    }
    let removed = rows.iter().find(|row| row.search_id == search_id).cloned();
    if let Some(row) = removed.as_ref() {
        if !saved_search_manageable_by(row, actor.as_deref()) {
            return Err(ApiError::InvalidRequest(
                "saved search can only be deleted by its owner".to_string(),
            ));
        }
    }
    rows.retain(|row| row.search_id != search_id);
    save_saved_searches(&workspace, &rows)?;
    if let Some(row) = removed {
        append_audit_log(
            &workspace,
            "saved_search_deleted",
            "saved_search",
            Some(row.search_id.as_str()),
            &format!("deleted saved search: {}", row.name),
            serde_json::json!({
                "search_id": row.search_id.as_str(),
                "name": row.name.as_str(),
                "requested_by": actor.as_deref(),
                "visibility": row.visibility.as_str(),
                "shared_with": &row.shared_with,
            }),
        )?;
    }
    get_saved_searches_for(
        workspace.root().to_string_lossy().as_ref(),
        Some(200),
        actor.as_deref(),
    )
}

pub fn get_audit_log(case_root: &str, limit: Option<usize>) -> Result<Vec<AuditLogEntry>> {
    let workspace = CaseWorkspace::open(case_root)?;
    load_audit_log(&workspace, limit)
}

pub fn add_finding_override(request: FindingOverrideRequest) -> Result<Vec<FindingOverride>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let mut overrides = load_finding_overrides(&workspace)?;
    let override_row = finding_override_from_request(&workspace, request)?;
    let audit_target_id = override_row.override_id.clone();
    let audit_action = override_row.action.clone();
    let audit_engine = override_row.engine.clone();
    let audit_rule_id = override_row.rule_id.clone();
    let audit_title = override_row.title.clone();
    let audit_severity = override_row.severity.clone();
    let inserted = if !overrides
        .iter()
        .any(|existing| same_override(existing, &override_row))
    {
        overrides.push(override_row);
        save_finding_overrides(&workspace, &overrides)?;
        true
    } else {
        false
    };
    rebuild_findings_after_override_change(&workspace, "add")?;
    if inserted {
        append_audit_log(
            &workspace,
            "finding_override_added",
            "finding_override",
            Some(audit_target_id.as_str()),
            "finding override added",
            serde_json::json!({
                "action": audit_action,
                "engine": audit_engine,
                "rule_id": audit_rule_id,
                "title": audit_title,
                "severity": audit_severity,
            }),
        )?;
    }
    Ok(load_finding_overrides(&workspace)?)
}

pub fn remove_finding_override(case_root: &str, override_id: &str) -> Result<Vec<FindingOverride>> {
    let workspace = CaseWorkspace::open(case_root)?;
    let mut overrides = load_finding_overrides(&workspace)?;
    let original_len = overrides.len();
    overrides.retain(|row| row.override_id != override_id);
    if overrides.len() != original_len {
        save_finding_overrides(&workspace, &overrides)?;
        rebuild_findings_after_override_change(&workspace, "remove")?;
        append_audit_log(
            &workspace,
            "finding_override_removed",
            "finding_override",
            Some(override_id),
            "finding override removed",
            serde_json::json!({ "override_id": override_id }),
        )?;
    }
    Ok(load_finding_overrides(&workspace)?)
}

pub fn get_event_bookmarks(case_root: &str) -> Result<Vec<EventBookmark>> {
    let workspace = CaseWorkspace::open(case_root)?;
    load_event_bookmarks(&workspace)
}

pub fn add_event_bookmark(request: EventBookmarkRequest) -> Result<Vec<EventBookmark>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    if workspace
        .query_layer()
        .event_detail_light(&request.event_id)?
        .is_none()
    {
        return Err(ApiError::InvalidRequest(format!(
            "event not found: {}",
            request.event_id
        )));
    }
    let mut bookmarks = load_event_bookmarks(&workspace)?;
    if !bookmarks.iter().any(|row| row.event_id == request.event_id) {
        bookmarks.push(EventBookmark {
            bookmark_id: new_id("bookmark"),
            case_id: workspace.manifest().case_id.clone(),
            event_id: request.event_id,
            label: clean_request_string(request.label),
            note: clean_request_string(request.note),
            created_at: now_utc(),
        });
        save_event_bookmarks(&workspace, &bookmarks)?;
        append_audit_log(
            &workspace,
            "event_bookmark_added",
            "event",
            Some(
                bookmarks
                    .last()
                    .map(|row| row.event_id.as_str())
                    .unwrap_or(""),
            ),
            "event bookmarked",
            serde_json::json!({
                "event_id": bookmarks.last().map(|row| row.event_id.as_str()),
                "label": bookmarks.last().and_then(|row| row.label.as_deref()),
            }),
        )?;
    }
    Ok(load_event_bookmarks(&workspace)?)
}

pub fn remove_event_bookmark(case_root: &str, bookmark_id: &str) -> Result<Vec<EventBookmark>> {
    let workspace = CaseWorkspace::open(case_root)?;
    let mut bookmarks = load_event_bookmarks(&workspace)?;
    let original_len = bookmarks.len();
    bookmarks.retain(|row| row.bookmark_id != bookmark_id);
    if bookmarks.len() != original_len {
        save_event_bookmarks(&workspace, &bookmarks)?;
        append_audit_log(
            &workspace,
            "event_bookmark_removed",
            "bookmark",
            Some(bookmark_id),
            "event bookmark removed",
            serde_json::json!({ "bookmark_id": bookmark_id }),
        )?;
    }
    Ok(load_event_bookmarks(&workspace)?)
}

pub fn get_bookmark_event_page(case_root: &str, page: EventPageQuery) -> Result<Page<EventRow>> {
    let workspace = CaseWorkspace::open(case_root)?;
    let event_ids = load_event_bookmarks(&workspace)?
        .into_iter()
        .map(|row| row.event_id)
        .collect::<Vec<_>>();
    workspace
        .query_layer()
        .event_page_by_event_ids(&event_ids, page, "bookmark_event_page")
        .map_err(ApiError::from)
}

pub fn get_risk_summary(case_root: &str, limit: Option<usize>) -> Result<Vec<RiskSummary>> {
    query(case_root)?
        .risk_summary(limit)
        .map_err(ApiError::from)
}

pub fn get_analyzer_runs(case_root: &str, limit: Option<usize>) -> Result<Vec<AnalyzerRunSummary>> {
    query(case_root)?
        .analyzer_runs(limit)
        .map_err(ApiError::from)
}

pub fn get_entity_summary(case_root: &str, limit: Option<usize>) -> Result<Vec<EntityRecord>> {
    query(case_root)?
        .entity_summary(limit)
        .map_err(ApiError::from)
}

pub fn get_subgraph(
    case_root: &str,
    entity_id: &str,
    hops: Option<usize>,
    edge_limit: Option<usize>,
) -> Result<Subgraph> {
    query(case_root)?
        .subgraph(entity_id, hops, edge_limit)
        .map_err(ApiError::from)
}

pub fn get_correlation_summary(
    case_root: &str,
    limit: Option<usize>,
) -> Result<Vec<CorrelationSummary>> {
    query(case_root)?
        .correlation_summary(limit)
        .map_err(ApiError::from)
}

pub fn get_correlation_chains(
    case_root: &str,
    limit: Option<usize>,
) -> Result<Vec<CorrelationChainSummary>> {
    query(case_root)?
        .correlation_chains(limit)
        .map_err(ApiError::from)
}

pub fn rebuild_correlation_read_model(
    case_root: &str,
    limit: Option<usize>,
) -> Result<Vec<CorrelationChainSummary>> {
    let workspace = CaseWorkspace::open(case_root)?;
    let started_at = now_utc();
    let chains = workspace.query_layer().rebuild_correlation_chains(limit)?;
    workspace.replace_correlation_chains(&chains)?;
    workspace.append_analyzer_runs(&[AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "correlation_chains".to_string(),
        name: "横断相関 read model 生成".to_string(),
        version: "taotie-explicit-correlation-read-model-v1".to_string(),
        status: "succeeded".to_string(),
        started_at,
        finished_at: Some(now_utc()),
        input_count: workspace.query_layer().lake_event_count()? as i64,
        output_count: chains.len() as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "mode": "explicit_rebuild",
            "read_model": "read_models/correlation_chains",
            "limit": limit.unwrap_or(500),
        })
        .to_string(),
    }])?;
    append_audit_log(
        &workspace,
        "correlation_read_model_rebuilt",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        "correlation read model rebuilt",
        serde_json::json!({
            "chain_count": chains.len(),
            "limit": limit.unwrap_or(500),
        }),
    )?;
    Ok(chains)
}

pub fn get_correlation_chain_event_page(
    case_root: &str,
    query_page: CorrelationChainEventPageQuery,
) -> Result<Page<EventRow>> {
    query(case_root)?
        .correlation_chain_event_page(query_page)
        .map_err(ApiError::from)
}

pub fn get_user_activity_summary(
    case_root: &str,
    limit: Option<usize>,
) -> Result<Vec<UserActivitySummary>> {
    query(case_root)?
        .user_activity_summary(limit)
        .map_err(ApiError::from)
}

pub fn generate_case_report(case_root: &str, output_path: Option<String>) -> Result<String> {
    let workspace = CaseWorkspace::open(case_root)?;
    let query = workspace.query_layer();
    let summary = query.case_summary()?;
    let custody_profile = load_case_custody_profile(&workspace)?;
    let coverage = query.coverage_summary()?;
    let failed = query.failed_parser_summary()?;
    let findings = query.finding_summary(Some(30))?;
    let chains = query.correlation_chains(Some(30))?;
    let risks = query.risk_summary(Some(20))?;
    let users = query.user_activity_summary(Some(20))?;
    let defenders = query.defender_summary(Some(20))?;
    let prefetch = query.prefetch_summary(Some(20))?;
    let analyzers = query.analyzer_runs(Some(20))?;
    let triage_actions = build_triage_actions(&workspace, Some(30))?;
    let evidence_files = query.file_page(FilePageQuery {
        limit: Some(50),
        cursor: None,
    })?;
    let finding_reviews = load_finding_reviews(&workspace)?;
    let case_approvals = load_case_approvals(&workspace)?;
    let saved_searches = load_saved_searches(&workspace)?;
    let finding_review_summary = build_finding_review_summary(&workspace, &finding_reviews);
    let audit_log = load_audit_log(&workspace, Some(20))?;
    let evidence_verification = load_latest_evidence_verification(&workspace)?;
    let detection_evaluation = build_case_detection_evaluation(&workspace)?;
    let generated_at = now_utc();

    let mut report = String::new();
    report.push_str("# taotie ケース調査レポート\n\n");
    report.push_str(&format!("生成日時: `{}`\n\n", md_inline(&generated_at)));
    report.push_str("## ケース概要\n\n");
    report.push_str("| 項目 | 値 |\n|---|---:|\n");
    report.push_str(&format!(
        "| Case ID | `{}` |\n",
        md_inline(&summary.case_id)
    ));
    report.push_str(&format!("| Name | {} |\n", md_cell(&summary.name)));
    report.push_str(&format!("| Root | `{}` |\n", md_inline(&summary.root_path)));
    report.push_str(&format!("| Files | {} |\n", summary.file_count));
    report.push_str(&format!("| Events | {} |\n", summary.event_count));
    report.push_str(&format!(
        "| Failed parses | {} |\n",
        summary.failed_parse_count
    ));
    report.push_str(&format!(
        "| Unsupported files | {} |\n\n",
        summary.unsupported_file_count
    ));

    report.push_str("## Case Custody\n\n");
    report.push_str("| Field | Value |\n|---|---|\n");
    report.push_str(&format!(
        "| Investigator | {} |\n",
        md_cell(custody_profile.investigator.as_deref().unwrap_or("-"))
    ));
    report.push_str(&format!(
        "| Custodian | {} |\n",
        md_cell(custody_profile.custodian.as_deref().unwrap_or("-"))
    ));
    report.push_str(&format!(
        "| Organization | {} |\n",
        md_cell(custody_profile.organization.as_deref().unwrap_or("-"))
    ));
    report.push_str(&format!(
        "| Evidence Source | {} |\n",
        md_cell(custody_profile.evidence_source.as_deref().unwrap_or("-"))
    ));
    report.push_str(&format!(
        "| Acquisition Method | {} |\n",
        md_cell(custody_profile.acquisition_method.as_deref().unwrap_or("-"))
    ));
    report.push_str(&format!(
        "| Acquired At | {} |\n",
        md_cell(custody_profile.acquired_at.as_deref().unwrap_or("-"))
    ));
    report.push_str(&format!(
        "| Legal Authority | {} |\n",
        md_cell(custody_profile.legal_authority.as_deref().unwrap_or("-"))
    ));
    report.push_str(&format!(
        "| Chain Note | {} |\n",
        md_cell(
            custody_profile
                .chain_of_custody_note
                .as_deref()
                .unwrap_or("-")
        )
    ));
    report.push_str(&format!(
        "| Updated | {} |\n\n",
        md_cell(&custody_profile.updated_at)
    ));

    report.push_str("## 実ケース検知評価\n\n");
    report.push_str("| 指標 | 値 |\n|---|---:|\n");
    report.push_str(&format!(
        "| Overall score | {:.1} |\n",
        detection_evaluation.overall_score
    ));
    report.push_str(&format!(
        "| Detection coverage | {:.1}% |\n",
        detection_evaluation.detection_coverage_rate
    ));
    report.push_str(&format!(
        "| Investigation readiness | {:.1} |\n",
        detection_evaluation.investigation_readiness_score
    ));
    report.push_str(&format!(
        "| Report quality | {:.1} |\n",
        detection_evaluation.report_quality_score
    ));
    report.push_str(&format!(
        "| Objectives covered / partial / missing | {} / {} / {} |\n",
        detection_evaluation.covered_objective_count,
        detection_evaluation.partial_objective_count,
        detection_evaluation.missing_objective_count
    ));
    report.push_str(&format!(
        "| Critical/High findings | {} / {} |\n",
        detection_evaluation.critical_findings, detection_evaluation.high_findings
    ));
    report.push_str(&format!(
        "| Unreviewed high findings | {} |\n",
        detection_evaluation.unreviewed_high_findings
    ));
    report.push_str(&format!(
        "| Evidence verification | {:.1}% |\n\n",
        detection_evaluation.evidence_verification_rate
    ));

    report.push_str("### 検知目的別カバレッジ\n\n");
    report.push_str(
        "| Objective | Status | Severity | Findings | Events | Artifacts | ATT&CK | Note |\n|---|---|---|---:|---:|---|---|---|\n",
    );
    for row in &detection_evaluation.objectives {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.objective_name),
            md_cell(&row.status),
            md_cell(row.severity_max.as_deref().unwrap_or("-")),
            row.finding_count,
            row.event_count,
            md_cell(&row.artifact_types),
            md_cell(&row.attack_techniques),
            md_cell(&row.evidence_note)
        ));
    }
    report.push('\n');

    report.push_str("### 調査/報告品質ゲート\n\n");
    report.push_str(
        "| Gate | Category | Status | Severity | Metric | Detail | Next Action |\n|---|---|---|---|---|---|---|\n",
    );
    for row in &detection_evaluation.quality_gates {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.title),
            md_cell(&row.category),
            md_cell(&row.status),
            md_cell(&row.severity),
            md_cell(&row.metric),
            md_cell(&row.detail),
            md_cell(&row.recommended_action)
        ));
    }
    report.push('\n');

    report.push_str("## Parser Coverage\n\n");
    report.push_str(
        "| Artifact | Parsed | Failed | Unsupported | Events |\n|---|---:|---:|---:|---:|\n",
    );
    for row in coverage.iter().take(25) {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md_cell(&row.artifact_type),
            row.parsed_files,
            row.failed_files,
            row.unsupported_files,
            row.event_count
        ));
    }
    report.push('\n');

    report.push_str("## Evidence Ledger\n\n");
    report.push_str("| Path | Artifact | Status | Size | SHA256 | Object Ref | Events |\n|---|---|---|---:|---|---|---:|\n");
    for row in &evidence_files.rows {
        report.push_str(&format!(
            "| {} | {} | {} | {} | `{}` | `{}` | {} |\n",
            md_cell(&row.original_path),
            md_cell(&row.artifact_type),
            md_cell(match &row.parser_status {
                ParserStatus::Pending => "pending",
                ParserStatus::Parsed => "parsed",
                ParserStatus::Failed => "failed",
                ParserStatus::Unsupported => "unsupported",
            }),
            row.size,
            md_inline(&row.sha256),
            md_inline(&row.object_ref),
            row.event_count
        ));
    }
    if evidence_files.next_cursor.is_some() {
        report.push_str("| ... | ... | ... | ... | ... | ... | ... |\n");
    }
    report.push('\n');

    report.push_str("## Evidence Verification\n\n");
    report.push_str("| Verified | Path | Size | Expected SHA256 | Actual SHA256 | Checked | Error |\n|---|---|---:|---|---|---|---|\n");
    for row in evidence_verification.iter().take(50) {
        report.push_str(&format!(
            "| {} | {} | {} | `{}` | `{}` | {} | {} |\n",
            if row.verified { "ok" } else { "failed" },
            md_cell(&row.original_path),
            row.size,
            md_inline(&row.expected_sha256),
            md_inline(row.actual_sha256.as_deref().unwrap_or("-")),
            md_cell(&row.checked_at),
            md_cell(row.error_message.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Triage Queue\n\n");
    report.push_str("| Priority | Category | Severity | Status | Title | Events | Last | Reason |\n|---:|---|---|---|---|---:|---|---|\n");
    for row in triage_actions.iter().take(30) {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            row.priority,
            md_cell(&row.category),
            md_cell(&row.severity),
            md_cell(&row.status),
            md_cell(&row.title),
            row.event_count,
            md_cell(row.last_seen_utc.as_deref().unwrap_or("-")),
            md_cell(&row.reason)
        ));
    }
    report.push('\n');

    report.push_str("## Top Findings\n\n");
    report.push_str("| Severity | Engine | Rule | Title | Events | First | Last |\n|---|---|---|---|---:|---|---|\n");
    for row in &findings {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.severity),
            md_cell(&row.engine),
            md_cell(row.rule_id.as_deref().unwrap_or("-")),
            md_cell(&row.title),
            row.event_count,
            md_cell(row.first_seen_utc.as_deref().unwrap_or("-")),
            md_cell(row.last_seen_utc.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Review Summary\n\n");
    report.push_str("| Total | Open | New | In Review | Needs Context | Confirmed | False Positive | Benign | Overdue | Unassigned | Tagged |\n");
    report.push_str("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    report.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n\n",
        finding_review_summary.total_reviews,
        finding_review_summary.open_count,
        finding_review_summary.new_count,
        finding_review_summary.in_review_count,
        finding_review_summary.needs_context_count,
        finding_review_summary.confirmed_count,
        finding_review_summary.false_positive_count,
        finding_review_summary.benign_count,
        finding_review_summary.overdue_count,
        finding_review_summary.unassigned_count,
        finding_review_summary.tagged_count
    ));

    report.push_str("## Review Status\n\n");
    report.push_str("| Status | Engine | Rule | Title | Reviewer | Assignee | Due | Tags | Updated | Comment |\n|---|---|---|---|---|---|---|---|---|---|\n");
    for row in finding_reviews.iter().take(30) {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.status),
            md_cell(&row.engine),
            md_cell(row.rule_id.as_deref().unwrap_or("-")),
            md_cell(&row.title),
            md_cell(row.reviewer.as_deref().unwrap_or("-")),
            md_cell(row.assignee.as_deref().unwrap_or("-")),
            md_cell(row.due_at.as_deref().unwrap_or("-")),
            md_cell(&finding_review_tags(row).join(", ")),
            md_cell(&row.updated_at),
            md_cell(row.comment.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Case Approvals\n\n");
    report.push_str("| Status | Target | Path/ID | SHA256 | Approver | Role | Updated | Comment |\n|---|---|---|---|---|---|---|---|\n");
    for row in case_approvals.iter().take(30) {
        report.push_str(&format!(
            "| {} | {} | {} | `{}` | {} | {} | {} | {} |\n",
            md_cell(&row.status),
            md_cell(&row.target_kind),
            md_cell(
                row.target_path
                    .as_deref()
                    .or(row.target_id.as_deref())
                    .unwrap_or("-")
            ),
            md_inline(row.target_sha256.as_deref().unwrap_or("-")),
            md_cell(row.approver.as_deref().unwrap_or("-")),
            md_cell(row.role.as_deref().unwrap_or("-")),
            md_cell(&row.updated_at),
            md_cell(row.comment.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Saved Searches\n\n");
    report.push_str(
        "| Name | Filters | Sort | Owner | Visibility | Shared With | Updated | Description |\n|---|---|---|---|---|---|---|---|\n",
    );
    for row in saved_searches.iter().take(30) {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.name),
            md_cell(&saved_search_filter_label(&row.query)),
            md_cell(&saved_search_sort_label(&row.query)),
            md_cell(row.created_by.as_deref().unwrap_or("-")),
            md_cell(&row.visibility),
            md_cell(&saved_search_shared_with_label(row)),
            md_cell(&row.updated_at),
            md_cell(row.description.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Correlation Chains\n\n");
    report.push_str("| Severity | Score | Key | Title | Artifacts | Events | Explanation |\n|---|---:|---|---|---|---:|---|\n");
    for row in &chains {
        report.push_str(&format!(
            "| {} | {} | `{}` | {} | {} | {} | {} |\n",
            md_cell(&row.severity),
            row.score,
            md_inline(&format!("{}={}", row.key_kind, row.key_value)),
            md_cell(&row.title),
            md_cell(&row.artifact_types),
            row.event_count,
            md_cell(&row.explanation)
        ));
    }
    report.push('\n');

    report.push_str("## MITRE Risk Summary\n\n");
    report.push_str("| Technique | Severity | Findings | Events | First | Last |\n|---|---|---:|---:|---|---|\n");
    for row in &risks {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.technique),
            md_cell(row.severity_max.as_deref().unwrap_or("-")),
            row.finding_count,
            row.event_count,
            md_cell(row.first_seen_utc.as_deref().unwrap_or("-")),
            md_cell(row.last_seen_utc.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Users\n\n");
    report.push_str("| User | Events | Hosts | Artifacts | Severity | First | Last |\n|---|---:|---:|---|---|---|---|\n");
    for row in &users {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.user_name),
            row.event_count,
            row.host_count,
            md_cell(&row.artifact_types),
            md_cell(row.severity_max.as_deref().unwrap_or("-")),
            md_cell(&row.first_seen_utc),
            md_cell(&row.last_seen_utc)
        ));
    }
    report.push('\n');

    report.push_str("## Defender\n\n");
    report.push_str("| Category | Severity | Events | Artifacts | First | Last | Sample |\n|---|---|---:|---|---|---|---|\n");
    for row in &defenders {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.category),
            md_cell(row.severity_max.as_deref().unwrap_or("-")),
            row.event_count,
            md_cell(&row.artifact_types),
            md_cell(&row.first_seen_utc),
            md_cell(&row.last_seen_utc),
            md_cell(row.sample_message.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Prefetch Analysis\n\n");
    report.push_str("| Process | Severity | Run Count | Referenced Files | PF Hash | Events | Last | Suspicion |\n|---|---|---:|---:|---|---:|---|---|\n");
    for row in &prefetch {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.process_name),
            md_cell(row.severity_max.as_deref().unwrap_or("-")),
            row.run_count_max
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            row.referenced_file_count_max
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            md_cell(row.prefetch_hash.as_deref().unwrap_or("-")),
            row.event_count,
            md_cell(&row.last_seen_utc),
            md_cell(row.suspicion.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Failed Parsers\n\n");
    report.push_str("| Artifact | Parser | Failed | Sample |\n|---|---|---:|---|\n");
    for row in failed.iter().take(20) {
        report.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            md_cell(&row.artifact_type),
            md_cell(&row.parser_name),
            row.failure_count,
            md_cell(&row.last_error)
        ));
    }
    report.push('\n');

    report.push_str("## Analyzer Runs\n\n");
    report.push_str("| Analyzer | Status | Input | Output | Started | Finished |\n|---|---|---:|---:|---|---|\n");
    for row in &analyzers {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            md_cell(&row.analyzer_id),
            md_cell(&row.status),
            row.input_count,
            row.output_count,
            md_cell(&row.started_at),
            md_cell(row.finished_at.as_deref().unwrap_or("-"))
        ));
    }
    report.push('\n');

    report.push_str("## Audit Trail\n\n");
    report.push_str("| Time | Actor | Action | Target | Summary |\n|---|---|---|---|---|\n");
    for row in &audit_log {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md_cell(&row.occurred_at),
            md_cell(&row.actor),
            md_cell(&row.action),
            md_cell(row.target_id.as_deref().unwrap_or(row.target_kind.as_str())),
            md_cell(&row.summary)
        ));
    }

    let path = output_path.map(PathBuf::from).unwrap_or_else(|| {
        workspace.root().join("reports").join(format!(
            "taotie_case_report_{}.md",
            filename_time(&generated_at)
        ))
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, report)?;
    append_audit_log(
        &workspace,
        "case_report_generated",
        "report",
        Some(path.to_string_lossy().as_ref()),
        "case report generated",
        serde_json::json!({ "output_path": path.display().to_string() }),
    )?;
    Ok(path.display().to_string())
}

pub fn generate_custody_manifest(case_root: &str, output_path: Option<String>) -> Result<String> {
    let workspace = CaseWorkspace::open(case_root)?;
    let query = workspace.query_layer();
    let summary = query.case_summary()?;
    let custody_profile = load_case_custody_profile(&workspace)?;
    let files = collect_file_inventory_for_manifest(&workspace)?;
    let evidence_file_count = files.len();
    let generated_at = now_utc();
    let audit_log_sha256 = match hash_file(&audit_log_path(&workspace)) {
        Ok(value) => Some(value),
        Err(_) => None,
    };
    let payload = serde_json::json!({
        "manifest_type": "taotie_custody_manifest_v1",
        "generated_at": generated_at.clone(),
        "case": summary,
        "custody_profile": custody_profile,
        "evidence_file_count": evidence_file_count,
        "audit_log_sha256": audit_log_sha256,
        "evidence_files": files,
    });
    let payload_bytes = serde_json::to_vec_pretty(&payload)?;
    let manifest_sha256 = sha256_bytes(&payload_bytes);
    let document = serde_json::json!({
        "manifest_sha256": manifest_sha256.clone(),
        "payload": payload,
    });
    let path = output_path.map(PathBuf::from).unwrap_or_else(|| {
        workspace.root().join("reports").join(format!(
            "taotie_custody_manifest_{}.json",
            filename_time(&generated_at)
        ))
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(&document)?)?;
    append_audit_log(
        &workspace,
        "custody_manifest_generated",
        "report",
        Some(path.to_string_lossy().as_ref()),
        "custody manifest generated",
        serde_json::json!({
            "output_path": path.display().to_string(),
            "manifest_sha256": manifest_sha256,
            "evidence_file_count": evidence_file_count,
        }),
    )?;
    Ok(path.display().to_string())
}

pub fn generate_report_bundle(case_root: &str, output_path: Option<String>) -> Result<String> {
    let workspace = CaseWorkspace::open(case_root)?;
    let generated_at = now_utc();
    let report_path = generate_case_report(case_root, None)?;
    let custody_manifest_path = generate_custody_manifest(case_root, None)?;
    let report_sha256 = hash_file(Path::new(&report_path))?;
    let custody_manifest_sha256 = hash_file(Path::new(&custody_manifest_path))?;
    let (custody_manifest_internal_hash_ok, custody_manifest_type_ok) =
        custody_manifest_document_status(Some(custody_manifest_path.as_str()));
    let summary = workspace.query_layer().case_summary()?;
    let custody_profile = load_case_custody_profile(&workspace)?;
    let detection_evaluation = build_case_detection_evaluation(&workspace)?;
    let case_custody_profile_sha256 = hash_file(&case_custody_profile_path(&workspace)).ok();
    let (signing_key, signing_key_created) = load_or_create_report_signing_key(&workspace)?;
    let public_key_bytes =
        decode_base64_array::<32>("report signing public key", &signing_key.public_key_base64)?;
    let public_key_sha256 = sha256_bytes(&public_key_bytes);
    let path = output_path.map(PathBuf::from).unwrap_or_else(|| {
        workspace.root().join("reports").join(format!(
            "taotie_report_bundle_{}.json",
            filename_time(&generated_at)
        ))
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if signing_key_created {
        append_audit_log(
            &workspace,
            "report_signing_key_created",
            "case",
            Some(workspace.manifest().case_id.as_str()),
            "report signing key created",
            serde_json::json!({
                "algorithm": signing_key.algorithm.as_str(),
                "key_id": signing_key.key_id.as_str(),
                "public_key_sha256": public_key_sha256.as_str(),
            }),
        )?;
    }
    append_audit_log(
        &workspace,
        "report_bundle_generated",
        "report",
        Some(path.to_string_lossy().as_ref()),
        "report bundle generated",
        serde_json::json!({
            "output_path": path.display().to_string(),
            "report_path": report_path,
            "custody_manifest_path": custody_manifest_path,
            "signature_algorithm": signing_key.algorithm.as_str(),
            "signature_key_id": signing_key.key_id.as_str(),
        }),
    )?;
    let audit_log_sha256 = hash_file(&audit_log_path(&workspace)).ok();
    let payload = serde_json::json!({
        "bundle_type": "taotie_report_bundle_v1",
        "generated_at": generated_at,
        "case": summary,
        "custody_profile": custody_profile,
        "case_custody_profile_sha256": case_custody_profile_sha256,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "case_detection_evaluation": detection_evaluation,
        "report": {
            "path": report_path,
            "sha256": report_sha256,
        },
        "custody_manifest": {
            "path": custody_manifest_path,
            "sha256": custody_manifest_sha256,
            "internal_hash_ok": custody_manifest_internal_hash_ok,
            "manifest_type_ok": custody_manifest_type_ok,
        },
        "signature": {
            "algorithm": signing_key.algorithm.as_str(),
            "key_id": signing_key.key_id.as_str(),
            "public_key_sha256": public_key_sha256,
        },
        "audit_log_sha256": audit_log_sha256,
    });
    let payload_bytes = serde_json::to_vec_pretty(&payload)?;
    let bundle_sha256 = sha256_bytes(&payload_bytes);
    let signature = sign_report_payload(&signing_key, &payload_bytes, &bundle_sha256)?;
    let document = serde_json::json!({
        "bundle_sha256": bundle_sha256,
        "signature": signature,
        "payload": payload,
    });
    fs::write(path.as_path(), serde_json::to_vec_pretty(&document)?)?;
    Ok(path.display().to_string())
}

pub fn verify_report_bundle(
    request: ReportBundleVerificationRequest,
) -> Result<ReportBundleVerification> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let checked_at = now_utc();
    let bundle_path = PathBuf::from(&request.bundle_path);
    let document = match fs::read(&bundle_path)
        .map_err(ApiError::from)
        .and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(ApiError::from)
        }) {
        Ok(document) => document,
        Err(error) => {
            return Ok(report_bundle_verification_error(
                &workspace,
                request.bundle_path,
                checked_at,
                error.to_string(),
            ));
        }
    };

    let bundle_sha256 = document
        .get("bundle_sha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let payload = document
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let computed_bundle_sha256 = serde_json::to_vec_pretty(&payload)
        .ok()
        .map(|bytes| sha256_bytes(&bytes));
    let bundle_hash_ok =
        bundle_sha256.is_some() && bundle_sha256.as_deref() == computed_bundle_sha256.as_deref();
    let signature_verification = verify_report_payload_signature(
        &workspace,
        &payload,
        computed_bundle_sha256.as_deref(),
        document.get("signature"),
    );
    let bundle_type_ok = payload
        .get("bundle_type")
        .and_then(serde_json::Value::as_str)
        == Some("taotie_report_bundle_v1");
    let case_id_matches = payload
        .get("case")
        .and_then(|case| case.get("case_id"))
        .and_then(serde_json::Value::as_str)
        == Some(workspace.manifest().case_id.as_str());
    let report_path = json_string_at(&payload, &["report", "path"]);
    let report_sha256_at_generation = json_string_at(&payload, &["report", "sha256"]);
    let current_report_sha256 = hash_path_string(report_path.as_deref());
    let report_hash_ok = report_sha256_at_generation.is_some()
        && report_sha256_at_generation == current_report_sha256;
    let custody_manifest_path = json_string_at(&payload, &["custody_manifest", "path"]);
    let custody_manifest_sha256_at_generation =
        json_string_at(&payload, &["custody_manifest", "sha256"]);
    let current_custody_manifest_sha256 = hash_path_string(custody_manifest_path.as_deref());
    let custody_manifest_hash_ok = custody_manifest_sha256_at_generation.is_some()
        && custody_manifest_sha256_at_generation == current_custody_manifest_sha256;
    let (custody_manifest_internal_hash_ok, custody_manifest_type_ok) =
        custody_manifest_document_status(custody_manifest_path.as_deref());
    let case_custody_profile_sha256_at_generation = payload
        .get("case_custody_profile_sha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let current_case_custody_profile_sha256 =
        hash_file(&case_custody_profile_path(&workspace)).ok();
    let case_custody_profile_hash_ok = match case_custody_profile_sha256_at_generation.as_deref() {
        Some(expected) => current_case_custody_profile_sha256.as_deref() == Some(expected),
        None => !case_custody_profile_path(&workspace).exists(),
    };
    let audit_log_sha256_at_generation = payload
        .get("audit_log_sha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let current_audit_log_sha256 = hash_file(&audit_log_path(&workspace)).ok();
    let audit_log_unchanged = audit_log_sha256_at_generation.is_some()
        && audit_log_sha256_at_generation == current_audit_log_sha256;
    let verification = ReportBundleVerification {
        bundle_path: request.bundle_path,
        bundle_sha256,
        computed_bundle_sha256,
        bundle_hash_ok,
        bundle_type_ok,
        case_id_matches,
        report_path,
        report_sha256_at_generation,
        current_report_sha256,
        report_hash_ok,
        custody_manifest_path,
        custody_manifest_sha256_at_generation,
        current_custody_manifest_sha256,
        custody_manifest_hash_ok,
        custody_manifest_internal_hash_ok,
        custody_manifest_type_ok,
        case_custody_profile_sha256_at_generation,
        current_case_custody_profile_sha256,
        case_custody_profile_hash_ok,
        signature_algorithm: signature_verification.algorithm,
        signature_key_id: signature_verification.key_id,
        signature_present: signature_verification.present,
        signature_payload_hash_ok: signature_verification.payload_hash_ok,
        signature_valid: signature_verification.valid,
        signature_key_matches_case_key: signature_verification.key_matches_case_key,
        audit_log_sha256_at_generation,
        current_audit_log_sha256,
        audit_log_unchanged,
        checked_at,
        error_message: None,
    };
    append_audit_log(
        &workspace,
        "report_bundle_verified",
        "report",
        Some(verification.bundle_path.as_str()),
        &format!(
            "report bundle verified: bundle_hash_ok={}, report_hash_ok={}, custody_hash_ok={}",
            verification.bundle_hash_ok,
            verification.report_hash_ok,
            verification.custody_manifest_hash_ok
        ),
        serde_json::json!({
            "bundle_path": verification.bundle_path.as_str(),
            "bundle_hash_ok": verification.bundle_hash_ok,
            "bundle_type_ok": verification.bundle_type_ok,
            "case_id_matches": verification.case_id_matches,
            "report_hash_ok": verification.report_hash_ok,
            "custody_manifest_hash_ok": verification.custody_manifest_hash_ok,
            "custody_manifest_internal_hash_ok": verification.custody_manifest_internal_hash_ok,
            "case_custody_profile_hash_ok": verification.case_custody_profile_hash_ok,
            "signature_algorithm": verification.signature_algorithm.as_deref(),
            "signature_key_id": verification.signature_key_id.as_deref(),
            "signature_valid": verification.signature_valid,
            "signature_key_matches_case_key": verification.signature_key_matches_case_key,
            "audit_log_unchanged": verification.audit_log_unchanged,
        }),
    )?;
    Ok(verification)
}

pub fn verify_custody_manifest(
    request: CustodyManifestVerificationRequest,
) -> Result<CustodyManifestVerification> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let checked_at = now_utc();
    let manifest_path = PathBuf::from(&request.manifest_path);
    let document = match fs::read(&manifest_path)
        .map_err(ApiError::from)
        .and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(ApiError::from)
        }) {
        Ok(document) => document,
        Err(error) => {
            return Ok(CustodyManifestVerification {
                manifest_path: request.manifest_path,
                manifest_sha256: None,
                computed_manifest_sha256: None,
                manifest_hash_ok: false,
                manifest_type_ok: false,
                case_id_matches: false,
                evidence_file_count: 0,
                evidence_hash_checked_count: 0,
                evidence_hash_mismatch_count: 0,
                audit_log_sha256_at_generation: None,
                current_audit_log_sha256: hash_file(&audit_log_path(&workspace)).ok(),
                audit_log_unchanged: false,
                checked_at,
                error_message: Some(error.to_string()),
            });
        }
    };
    let manifest_sha256 = document
        .get("manifest_sha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let payload = document
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let computed_manifest_sha256 = serde_json::to_vec_pretty(&payload)
        .ok()
        .map(|bytes| sha256_bytes(&bytes));
    let manifest_hash_ok = manifest_sha256.is_some()
        && manifest_sha256.as_deref() == computed_manifest_sha256.as_deref();
    let manifest_type_ok = payload
        .get("manifest_type")
        .and_then(serde_json::Value::as_str)
        == Some("taotie_custody_manifest_v1");
    let case_id_matches = payload
        .get("case")
        .and_then(|case| case.get("case_id"))
        .and_then(serde_json::Value::as_str)
        == Some(workspace.manifest().case_id.as_str());
    let evidence_file_count = payload
        .get("evidence_file_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_default();
    let (checked_count, mismatch_count) =
        verify_manifest_evidence_hashes(&workspace, &payload, request.evidence_limit)?;
    let audit_log_sha256_at_generation = payload
        .get("audit_log_sha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let current_audit_log_sha256 = hash_file(&audit_log_path(&workspace)).ok();
    let audit_log_unchanged = audit_log_sha256_at_generation.is_some()
        && audit_log_sha256_at_generation == current_audit_log_sha256;
    let verification = CustodyManifestVerification {
        manifest_path: request.manifest_path,
        manifest_sha256,
        computed_manifest_sha256,
        manifest_hash_ok,
        manifest_type_ok,
        case_id_matches,
        evidence_file_count,
        evidence_hash_checked_count: checked_count,
        evidence_hash_mismatch_count: mismatch_count,
        audit_log_sha256_at_generation,
        current_audit_log_sha256,
        audit_log_unchanged,
        checked_at,
        error_message: None,
    };
    append_audit_log(
        &workspace,
        "custody_manifest_verified",
        "report",
        Some(verification.manifest_path.as_str()),
        &format!(
            "custody manifest verified: manifest_hash_ok={}, evidence_mismatch={}",
            verification.manifest_hash_ok, verification.evidence_hash_mismatch_count
        ),
        serde_json::json!({
            "manifest_path": verification.manifest_path.as_str(),
            "manifest_hash_ok": verification.manifest_hash_ok,
            "manifest_type_ok": verification.manifest_type_ok,
            "case_id_matches": verification.case_id_matches,
            "evidence_hash_checked_count": verification.evidence_hash_checked_count,
            "evidence_hash_mismatch_count": verification.evidence_hash_mismatch_count,
            "audit_log_unchanged": verification.audit_log_unchanged,
        }),
    )?;
    Ok(verification)
}

fn build_case_detection_evaluation(workspace: &CaseWorkspace) -> Result<CaseDetectionEvaluation> {
    let query = workspace.query_layer();
    let summary = query.case_summary()?;
    let coverage = query.coverage_summary()?;
    let findings = query.finding_summary(Some(500))?;
    let chains = query.correlation_chains(Some(500))?;
    let risks = query.risk_summary(Some(500))?;
    let reviews = load_finding_reviews(workspace)?;
    let approvals = load_case_approvals(workspace)?;
    let evidence_verification = load_latest_evidence_verification(workspace)?;

    let parsed_files: i64 = coverage.iter().map(|row| row.parsed_files).sum();
    let total_files: i64 = coverage.iter().map(|row| row.total_files).sum();
    let parsed_file_rate = percent_ratio(parsed_files, total_files);
    let evidence_verified = evidence_verification
        .iter()
        .filter(|row| row.verified)
        .count() as i64;
    let evidence_verification_rate = if summary.file_count > 0 {
        percent_ratio(evidence_verified, summary.file_count)
    } else {
        100.0
    };

    let total_findings: i64 = findings.iter().map(|row| row.finding_count).sum();
    let critical_findings = findings
        .iter()
        .filter(|row| row.severity == "critical")
        .count() as i64;
    let high_findings = findings
        .iter()
        .filter(|row| severity_rank(&row.severity) >= severity_rank("high"))
        .count() as i64;
    let confirmed_findings = findings
        .iter()
        .filter(|finding| {
            review_for_finding(&reviews, finding).is_some_and(|review| review.status == "confirmed")
        })
        .count() as i64;
    let open_findings = findings
        .iter()
        .filter(|finding| {
            review_for_finding(&reviews, finding)
                .map_or(true, |review| is_open_review_status(&review.status))
        })
        .count() as i64;
    let unreviewed_high_findings = findings
        .iter()
        .filter(|finding| severity_rank(&finding.severity) >= severity_rank("high"))
        .filter(|finding| {
            review_for_finding(&reviews, finding)
                .map_or(true, |review| is_open_review_status(&review.status))
        })
        .count() as i64;
    let high_correlation_chain_count = chains
        .iter()
        .filter(|row| severity_rank(&row.severity) >= severity_rank("high"))
        .count() as i64;

    let mut objectives = detection_objective_specs()
        .into_iter()
        .map(|spec| build_detection_objective(&summary, &coverage, &findings, spec))
        .collect::<Vec<_>>();
    objectives.push(build_correlation_objective(&summary, &coverage, &chains));

    let applicable_objective_count = objectives
        .iter()
        .filter(|row| row.status != "not_observed")
        .count() as i64;
    let covered_objective_count = objectives
        .iter()
        .filter(|row| row.status == "covered")
        .count() as i64;
    let partial_objective_count = objectives
        .iter()
        .filter(|row| row.status == "partial")
        .count() as i64;
    let missing_objective_count = objectives
        .iter()
        .filter(|row| row.status == "missing")
        .count() as i64;
    let detection_coverage_rate = if applicable_objective_count > 0 {
        round1(
            ((covered_objective_count as f64) + (partial_objective_count as f64 * 0.5)) * 100.0
                / applicable_objective_count as f64,
        )
    } else {
        0.0
    };

    let parser_gap_count = summary.failed_parse_count + summary.unsupported_file_count;
    let report_bundle_approved = approvals
        .iter()
        .any(|row| row.status == "approved" && row.target_kind.contains("report"));
    let quality_gates = build_case_quality_gates(
        &summary,
        parsed_file_rate,
        evidence_verification_rate,
        parser_gap_count,
        unreviewed_high_findings,
        open_findings,
        chains.len() as i64,
        high_correlation_chain_count,
        risks.len() as i64,
        report_bundle_approved,
    );
    let report_gap_count = quality_gates
        .iter()
        .filter(|row| row.category == "report" && row.status != "pass")
        .count() as i64;

    let gate_penalty: f64 = quality_gates
        .iter()
        .map(|row| match row.status.as_str() {
            "fail" => 12.0,
            "warn" => 5.0,
            _ => 0.0,
        })
        .sum();
    let investigation_readiness_score = clamp_score(
        100.0
            - (unreviewed_high_findings as f64 * 7.0)
            - (parser_gap_count as f64 * 4.0)
            - (missing_objective_count as f64 * 8.0)
            - gate_penalty,
    );
    let report_quality_score = clamp_score(
        evidence_verification_rate * 0.45
            + if report_bundle_approved { 25.0 } else { 0.0 }
            + if open_findings == 0 || total_findings == 0 {
                20.0
            } else {
                10.0
            }
            + if !risks.is_empty() { 10.0 } else { 0.0 },
    );
    let overall_score = clamp_score(
        detection_coverage_rate * 0.45
            + investigation_readiness_score * 0.35
            + report_quality_score * 0.20,
    );

    Ok(CaseDetectionEvaluation {
        case_id: workspace.manifest().case_id.clone(),
        evaluated_at: now_utc(),
        overall_score,
        detection_coverage_rate,
        investigation_readiness_score,
        report_quality_score,
        applicable_objective_count,
        covered_objective_count,
        partial_objective_count,
        missing_objective_count,
        total_findings,
        critical_findings,
        high_findings,
        confirmed_findings,
        open_findings,
        unreviewed_high_findings,
        correlation_chain_count: chains.len() as i64,
        high_correlation_chain_count,
        risk_technique_count: risks.len() as i64,
        parsed_file_rate,
        evidence_verification_rate,
        parser_gap_count,
        unsupported_file_count: summary.unsupported_file_count,
        report_gap_count,
        objectives,
        quality_gates,
    })
}

#[derive(Clone, Copy)]
struct DetectionObjectiveSpec {
    id: &'static str,
    name: &'static str,
    artifact_hints: &'static [&'static str],
    rule_hints: &'static [&'static str],
    attack_hints: &'static [&'static str],
}

fn detection_objective_specs() -> Vec<DetectionObjectiveSpec> {
    vec![
        DetectionObjectiveSpec {
            id: "execution",
            name: "実行痕跡",
            artifact_hints: &[
                "evtx",
                "prefetch",
                "amcache",
                "scheduled_task",
                "mft",
                "usn_jrnl",
                "lnk",
                "jump_list",
                "recentdocs",
            ],
            rule_hints: &[
                "execution",
                "lolbin",
                "powershell",
                "scheduled",
                "service",
                "psexec",
                "process",
            ],
            attack_hints: &["T1059", "T1204", "T1218", "T1036", "T1053"],
        },
        DetectionObjectiveSpec {
            id: "credential_access",
            name: "資格情報アクセス",
            artifact_hints: &["evtx", "defender", "text_log", "credential_store"],
            rule_hints: &[
                "credential",
                "lsass",
                "kerberoast",
                "dcsync",
                "ntds",
                "password",
                "ticket",
                "mimikatz",
            ],
            attack_hints: &["T1003", "T1110", "T1558", "T1552"],
        },
        DetectionObjectiveSpec {
            id: "credential_recovery",
            name: "資格情報復元導線",
            artifact_hints: &["credential_store", "filezilla", "browser"],
            rule_hints: &[
                "credential-store",
                "filezilla-saved",
                "saved-credential",
                "dpapi",
                "keepass",
                "login-data",
            ],
            attack_hints: &["T1555", "T1552"],
        },
        DetectionObjectiveSpec {
            id: "persistence",
            name: "永続化",
            artifact_hints: &["evtx", "registry", "scheduled_task", "amcache", "prefetch"],
            rule_hints: &[
                "persistence",
                "service",
                "scheduled",
                "run-key",
                "wmi-event",
                "ifeo",
                "winlogon",
                "bits",
            ],
            attack_hints: &["T1547", "T1543", "T1053", "T1219"],
        },
        DetectionObjectiveSpec {
            id: "defense_evasion",
            name: "防御回避/痕跡消去",
            artifact_hints: &["evtx", "defender", "mft", "usn_jrnl", "registry"],
            rule_hints: &[
                "tamper",
                "clear",
                "defender",
                "shadowcopy",
                "firewall",
                "safeboot",
                "timestomp",
                "delete",
            ],
            attack_hints: &["T1070", "T1562"],
        },
        DetectionObjectiveSpec {
            id: "lateral_movement",
            name: "横展開/リモート実行",
            artifact_hints: &["evtx", "prefetch", "amcache", "usn_jrnl", "mft"],
            rule_hints: &[
                "psexec",
                "rdp",
                "wmi",
                "remote",
                "dcom",
                "network-logon",
                "intrusion-chain",
            ],
            attack_hints: &["T1021", "T1569", "T1570"],
        },
        DetectionObjectiveSpec {
            id: "filesystem_timeline",
            name: "ファイルシステム時系列",
            artifact_hints: &[
                "mft",
                "usn_jrnl",
                "lnk",
                "jump_list",
                "recentdocs",
                "prefetch",
                "amcache",
            ],
            rule_hints: &[
                "mft",
                "download",
                "execute",
                "delete",
                "lnk",
                "recentdocs",
                "jumplist",
            ],
            attack_hints: &["T1070.004", "T1070.006", "T1105", "T1204"],
        },
        DetectionObjectiveSpec {
            id: "network_ioc",
            name: "通信/IOC",
            artifact_hints: &[
                "browser",
                "srum",
                "evtx",
                "defender",
                "text_log",
                "network_capture",
                "filezilla",
            ],
            rule_hints: &[
                "download",
                "c2",
                "rat",
                "remote-access",
                "domain",
                "ioc",
                "network-capture",
                "filezilla",
            ],
            attack_hints: &["T1105", "T1219", "T1071", "T1041", "T1048"],
        },
        DetectionObjectiveSpec {
            id: "content_recovery",
            name: "文書/アーカイブ復元導線",
            artifact_hints: &["document", "archive"],
            rule_hints: &[
                "document-recovery",
                "archive-exploit",
                "recovery-candidate",
                "cve",
            ],
            attack_hints: &["T1203", "T1204", "T1027"],
        },
        DetectionObjectiveSpec {
            id: "exfil_reconstruction",
            name: "流出経路/期間復元",
            artifact_hints: &[
                "network_capture",
                "filezilla",
                "browser",
                "srum",
                "web_cache",
            ],
            rule_hints: &[
                "exfil",
                "network-capture",
                "filezilla",
                "download",
                "transfer",
            ],
            attack_hints: &["T1041", "T1048", "T1105"],
        },
    ]
}

fn build_detection_objective(
    summary: &CaseSummary,
    coverage: &[CoverageSummary],
    findings: &[FindingSummary],
    spec: DetectionObjectiveSpec,
) -> DetectionObjectiveEvaluation {
    let mut artifact_types = HashSet::new();
    let mut attack_techniques = HashSet::new();
    for row in coverage.iter().filter(|row| {
        spec.artifact_hints
            .iter()
            .any(|hint| row.artifact_type.contains(hint))
    }) {
        artifact_types.insert(row.artifact_type.clone());
    }

    let mut finding_count = 0i64;
    let mut event_count = 0i64;
    let mut severity_max: Option<String> = None;
    for finding in findings
        .iter()
        .filter(|finding| finding_matches_detection_objective(finding, spec))
    {
        finding_count += finding.finding_count.max(1);
        event_count += finding.event_count.max(0);
        severity_max = max_severity(severity_max.as_deref(), &finding.severity).map(str::to_string);
        for technique in json_string_values(&finding.attack_json) {
            attack_techniques.insert(technique);
        }
    }

    let status = if summary.file_count == 0 && summary.event_count == 0 {
        "not_observed"
    } else if finding_count > 0 {
        "covered"
    } else if !artifact_types.is_empty() {
        "partial"
    } else {
        "missing"
    }
    .to_string();

    let evidence_note = match status.as_str() {
        "covered" => format!("{finding_count} 件の検知グループで確認"),
        "partial" => "関連アーティファクトはあるが検知グループが未生成".to_string(),
        "missing" => "ケース内でこの調査目的を満たす検知/アーティファクトが不足".to_string(),
        _ => "評価対象データなし".to_string(),
    };

    DetectionObjectiveEvaluation {
        objective_id: spec.id.to_string(),
        objective_name: spec.name.to_string(),
        status,
        severity_max,
        finding_count,
        event_count,
        artifact_types: sorted_join(&artifact_types),
        attack_techniques: sorted_join(&attack_techniques),
        evidence_note,
    }
}

fn build_correlation_objective(
    summary: &CaseSummary,
    coverage: &[CoverageSummary],
    chains: &[CorrelationChainSummary],
) -> DetectionObjectiveEvaluation {
    let mut artifact_types = HashSet::new();
    for row in coverage {
        if row.total_files > 0 {
            artifact_types.insert(row.artifact_type.clone());
        }
    }
    let event_count: i64 = chains.iter().map(|row| row.event_count).sum();
    let severity_max = chains
        .iter()
        .fold(None, |acc, row| max_severity(acc, &row.severity))
        .map(str::to_string);
    let status = if summary.file_count == 0 && summary.event_count == 0 {
        "not_observed"
    } else if !chains.is_empty() {
        "covered"
    } else if artifact_types.len() >= 2 {
        "partial"
    } else {
        "missing"
    }
    .to_string();
    DetectionObjectiveEvaluation {
        objective_id: "cross_artifact_correlation".to_string(),
        objective_name: "アーティファクト横断相関".to_string(),
        status: status.clone(),
        severity_max,
        finding_count: chains.len() as i64,
        event_count,
        artifact_types: sorted_join(&artifact_types),
        attack_techniques: String::new(),
        evidence_note: match status.as_str() {
            "covered" => format!("{} 件の相関チェーンを生成", chains.len()),
            "partial" => "複数アーティファクトはあるが相関チェーンが未生成".to_string(),
            "missing" => "横断相関に必要なデータが不足".to_string(),
            _ => "評価対象データなし".to_string(),
        },
    }
}

fn finding_matches_detection_objective(
    finding: &FindingSummary,
    spec: DetectionObjectiveSpec,
) -> bool {
    let mut hay = format!(
        "{} {} {}",
        finding.engine,
        finding.rule_id.as_deref().unwrap_or_default(),
        finding.title
    )
    .to_ascii_lowercase();
    if let Some(message) = finding.sample_message.as_deref() {
        hay.push(' ');
        hay.push_str(&message.to_ascii_lowercase());
    }
    let rule_hit = spec
        .rule_hints
        .iter()
        .any(|hint| hay.contains(&hint.to_ascii_lowercase()));
    let attack_hit = json_string_values(&finding.attack_json)
        .iter()
        .any(|value| {
            spec.attack_hints
                .iter()
                .any(|hint| value.eq_ignore_ascii_case(hint) || value.starts_with(hint))
        });
    rule_hit || attack_hit
}

fn build_case_quality_gates(
    summary: &CaseSummary,
    parsed_file_rate: f64,
    evidence_verification_rate: f64,
    parser_gap_count: i64,
    unreviewed_high_findings: i64,
    open_findings: i64,
    correlation_chain_count: i64,
    high_correlation_chain_count: i64,
    risk_technique_count: i64,
    report_bundle_approved: bool,
) -> Vec<CaseQualityGate> {
    let mut gates = Vec::new();
    gates.push(CaseQualityGate {
        gate_id: "parser_coverage".to_string(),
        category: "detection".to_string(),
        status: if parser_gap_count == 0 && parsed_file_rate >= 95.0 {
            "pass"
        } else if parsed_file_rate >= 80.0 {
            "warn"
        } else {
            "fail"
        }
        .to_string(),
        severity: if parser_gap_count == 0 {
            "info"
        } else if parsed_file_rate >= 80.0 {
            "medium"
        } else {
            "high"
        }
        .to_string(),
        title: "パーサカバレッジ".to_string(),
        detail: format!("parsed_rate={parsed_file_rate:.1}% parser_gap_count={parser_gap_count}"),
        metric: format!("{parsed_file_rate:.1}%"),
        recommended_action: "failed/unsupported を優先して解消し、再取り込み後に分析を再構築する"
            .to_string(),
    });
    gates.push(CaseQualityGate {
        gate_id: "high_finding_review".to_string(),
        category: "investigation".to_string(),
        status: if unreviewed_high_findings == 0 {
            "pass"
        } else if unreviewed_high_findings <= 3 {
            "warn"
        } else {
            "fail"
        }
        .to_string(),
        severity: if unreviewed_high_findings == 0 {
            "info"
        } else if unreviewed_high_findings <= 3 {
            "high"
        } else {
            "critical"
        }
        .to_string(),
        title: "高優先度検知レビュー".to_string(),
        detail: format!(
            "unreviewed_high_findings={unreviewed_high_findings} open_findings={open_findings}"
        ),
        metric: unreviewed_high_findings.to_string(),
        recommended_action:
            "critical/high の検知を確認し confirmed/false_positive/benign に分類する".to_string(),
    });
    gates.push(CaseQualityGate {
        gate_id: "correlation_drilldown".to_string(),
        category: "investigation".to_string(),
        status: if high_correlation_chain_count > 0 || summary.event_count < 5 {
            "pass"
        } else if correlation_chain_count > 0 {
            "warn"
        } else {
            "fail"
        }
        .to_string(),
        severity: if high_correlation_chain_count > 0 || summary.event_count < 5 {
            "info"
        } else if correlation_chain_count > 0 {
            "medium"
        } else {
            "high"
        }
        .to_string(),
        title: "横断相関ドリルダウン".to_string(),
        detail: format!(
            "chains={correlation_chain_count} high_or_above={high_correlation_chain_count}"
        ),
        metric: correlation_chain_count.to_string(),
        recommended_action:
            "相関チェーンからイベントへ入り、同一ファイル/ユーザー/ホストで前後関係を確認する"
                .to_string(),
    });
    gates.push(CaseQualityGate {
        gate_id: "evidence_verification".to_string(),
        category: "report".to_string(),
        status: if evidence_verification_rate >= 95.0 {
            "pass"
        } else if evidence_verification_rate > 0.0 {
            "warn"
        } else if summary.file_count == 0 {
            "pass"
        } else {
            "fail"
        }
        .to_string(),
        severity: if evidence_verification_rate >= 95.0 || summary.file_count == 0 {
            "info"
        } else if evidence_verification_rate > 0.0 {
            "medium"
        } else {
            "high"
        }
        .to_string(),
        title: "証拠ハッシュ検証".to_string(),
        detail: format!("evidence_verification_rate={evidence_verification_rate:.1}%"),
        metric: format!("{evidence_verification_rate:.1}%"),
        recommended_action: "証拠台帳タブでハッシュ検証を完了し、レポートバンドルに含める"
            .to_string(),
    });
    gates.push(CaseQualityGate {
        gate_id: "mitre_mapping".to_string(),
        category: "report".to_string(),
        status: if risk_technique_count >= 3 || summary.event_count == 0 {
            "pass"
        } else if risk_technique_count > 0 {
            "warn"
        } else {
            "fail"
        }
        .to_string(),
        severity: if risk_technique_count >= 3 || summary.event_count == 0 {
            "info"
        } else {
            "medium"
        }
        .to_string(),
        title: "MITRE 整理".to_string(),
        detail: format!("risk_technique_count={risk_technique_count}"),
        metric: risk_technique_count.to_string(),
        recommended_action: "主要検知を ATT&CK 技術にひも付け、調査報告の戦術/技術欄を補強する"
            .to_string(),
    });
    gates.push(CaseQualityGate {
        gate_id: "report_bundle_approval".to_string(),
        category: "report".to_string(),
        status: if report_bundle_approved {
            "pass"
        } else {
            "warn"
        }
        .to_string(),
        severity: if report_bundle_approved {
            "info"
        } else {
            "medium"
        }
        .to_string(),
        title: "成果物承認".to_string(),
        detail: if report_bundle_approved {
            "approved report bundle exists".to_string()
        } else {
            "approved report bundle not found".to_string()
        },
        metric: if report_bundle_approved {
            "approved"
        } else {
            "pending"
        }
        .to_string(),
        recommended_action: "レポートバンドル生成後、検証結果とあわせて承認レコードを残す"
            .to_string(),
    });
    gates
}

fn review_for_finding<'a>(
    reviews: &'a [FindingReview],
    finding: &FindingSummary,
) -> Option<&'a FindingReview> {
    reviews.iter().find(|row| {
        row.engine == finding.engine && row.rule_id == finding.rule_id && row.title == finding.title
    })
}

fn json_string_values(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value).unwrap_or_default()
}

fn percent_ratio(part: i64, total: i64) -> f64 {
    if total <= 0 {
        return 0.0;
    }
    round1(part.max(0) as f64 * 100.0 / total as f64)
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn clamp_score(value: f64) -> f64 {
    round1(value.clamp(0.0, 100.0))
}

fn md_cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace('\n', "<br>")
        .replace('\r', "")
}

fn md_inline(value: &str) -> String {
    value.replace('`', "'").replace('\n', " ").replace('\r', "")
}

fn filename_time(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn search_index_for_workspace(workspace: &CaseWorkspace) -> TantivyEventIndex {
    TantivyEventIndex::new(workspace.root().join("indexes").join("tantivy"))
}

fn index_event_from_full(event: EventFull) -> IndexEvent {
    let event_code = event_attr_string(&event, &["event_id", "EventID", "event_code", "Id"]);
    let channel = event_attr_string(&event, &["channel", "Channel"]);
    let level = event_attr_string(&event, &["level", "Level", "LevelDisplayName"]);
    IndexEvent {
        event_id: event.event_id,
        event_time_utc: event.event_time_utc,
        artifact_type: event.artifact_type,
        severity: event.severity,
        event_action: event.event_action,
        host: event.host,
        user_name: event.user_name,
        process_name: event.process_name,
        file_path: event.file_path,
        ip: event.ip,
        url: event.url,
        hash: event.hash,
        event_code,
        channel,
        level,
        parser_name: event.parser_name,
        source_file_id: event.source_file_id,
        message_short: event.message_short,
        message_full: event.message_full,
    }
}

pub fn get_timeline_bins(case_root: &str, granularity: &str) -> Result<Vec<TimelineBin>> {
    query(case_root)?
        .timeline_bins(granularity, Some(1_000))
        .map_err(ApiError::from)
}

pub fn get_event_timeline(
    case_root: &str,
    page: EventPageQuery,
    granularity: &str,
) -> Result<Vec<EventTimelineBin>> {
    query(case_root)?
        .event_timeline(page, granularity)
        .map_err(ApiError::from)
}

pub fn get_timestomp_scatter(case_root: &str) -> Result<Vec<TimestompPoint>> {
    query(case_root)?
        .timestomp_scatter(Some(1_500))
        .map_err(ApiError::from)
}

pub fn get_process_tree(case_root: &str) -> Result<Vec<ProcessTreeEdge>> {
    query(case_root)?
        .process_tree(Some(80))
        .map_err(ApiError::from)
}

pub fn get_process_tree_instances(case_root: &str) -> Result<Vec<ProcessNode>> {
    query(case_root)?
        .process_tree_instances(Some(2000))
        .map_err(ApiError::from)
}

pub fn get_process_related_events(
    case_root: &str,
    guid: &str,
) -> Result<Vec<ProcessRelatedEvent>> {
    query(case_root)?
        .process_related_events(guid, Some(300))
        .map_err(ApiError::from)
}

pub fn get_file_op_timeline(case_root: &str) -> Result<Vec<FileOpBin>> {
    query(case_root)?
        .file_op_timeline(Some(180))
        .map_err(ApiError::from)
}

pub fn get_beacon_intervals(case_root: &str) -> Result<Vec<BeaconIntervalBin>> {
    query(case_root)?
        .beacon_intervals(Some(200_000))
        .map_err(ApiError::from)
}

pub fn get_event_page(case_root: &str, page: EventPageQuery) -> Result<Page<EventRow>> {
    query(case_root)?.event_page(page).map_err(ApiError::from)
}

pub fn get_event_facets(
    case_root: &str,
    page: EventPageQuery,
    per_field_limit: Option<usize>,
) -> Result<Vec<EventFacetValue>> {
    query(case_root)?
        .event_facets(page, per_field_limit)
        .map_err(ApiError::from)
}

pub fn build_search_index(request: BuildSearchIndexRequest) -> Result<SearchIndexMetadata> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let job = enqueue_search_index_job(&workspace, &queue, "manual_sync", 35)?;
    execute_search_index_job(&request.case_root, &job.job_id, "taotie-sync-search-index")
}

pub fn start_search_index_build(request: StartSearchIndexBuildRequest) -> Result<JobRecord> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    if let Some(active) = active_search_index_job(&queue)? {
        return Ok(active);
    }
    let job = enqueue_search_index_job(&workspace, &queue, "background", 35)?;
    spawn_search_index_job(&request.case_root, &queue, &job)?;
    Ok(job)
}

pub fn enqueue_sidecar_analysis(request: SidecarPlanRequest) -> Result<JobRecord> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let detail = workspace
        .query_layer()
        .event_detail_light(&request.event_id)?
        .ok_or_else(|| ApiError::InvalidRequest(format!("unknown event: {}", request.event_id)))?;
    let attrs = serde_json::from_str::<serde_json::Value>(&detail.attributes_json)
        .unwrap_or_else(|_| serde_json::json!({}));
    let sidecar = request
        .sidecar
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            attrs
                .get("sidecar_recommended")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| sidecar_for_event(&detail.artifact_type, &detail.event_action))
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "event has no sidecar recommendation: {}",
                detail.event_id
            ))
        })?;
    let job_kind = sidecar_job_kind(&sidecar);
    let expected_outputs = attrs
        .get("sidecar_expected_outputs")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| sidecar_expected_outputs(&sidecar));
    let target = detail
        .file_path
        .as_deref()
        .or(detail.url.as_deref())
        .or(detail.process_name.as_deref())
        .or(detail.hash.as_deref())
        .unwrap_or(detail.evidence_ref.as_str())
        .to_string();
    let job = queue.enqueue(
        workspace.manifest().case_id.as_str(),
        job_kind,
        25,
        serde_json::json!({
            "executor": "sidecar",
            "mode": "planned_background_job",
            "event_id": detail.event_id.clone(),
            "source_file_id": detail.source_file_id.clone(),
            "parse_run_id": detail.parse_run_id.clone(),
            "artifact_type": detail.artifact_type.clone(),
            "event_action": detail.event_action.clone(),
            "sidecar": sidecar.clone(),
            "target": target.clone(),
            "evidence_ref": detail.evidence_ref.clone(),
            "raw_record_ref": detail.raw_record_ref.clone(),
            "expected_outputs": expected_outputs.clone(),
            "output_scope": "case_sidecars",
            "execution_policy": "background_worker_only",
        })
        .to_string(),
        sidecar_resource_limits(&sidecar),
    )?;
    append_audit_log(
        &workspace,
        "sidecar_analysis_enqueued",
        "event",
        Some(detail.event_id.as_str()),
        &format!("sidecar analysis queued: {sidecar} for {target}"),
        serde_json::json!({
            "job_id": job.job_id.clone(),
            "event_id": detail.event_id.clone(),
            "sidecar": sidecar.clone(),
            "artifact_type": detail.artifact_type.clone(),
            "target": target.clone(),
        }),
    )?;
    Ok(job)
}

pub fn run_sidecar_batch(request: SidecarBatchRequest) -> Result<SidecarBatchResult> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let limit = request.limit.unwrap_or(25).clamp(1, 200);
    let execute = request.execute.unwrap_or(true);
    let rebuild_after_execute = request.rebuild_after_execute.unwrap_or(true);
    let existing_jobs = queue.recent(500)?;
    let mut already_targeted = HashSet::new();
    let mut runnable_jobs = existing_jobs
        .iter()
        .filter(|job| is_sidecar_job_kind(&job.kind) && matches!(job.status, JobStatus::Queued))
        .cloned()
        .collect::<Vec<_>>();
    for job in existing_jobs
        .iter()
        .filter(|job| is_sidecar_job_kind(&job.kind))
    {
        if let Some(event_id) = sidecar_job_event_id(job) {
            already_targeted.insert(event_id);
        }
    }

    let mut queued_jobs = Vec::new();
    if runnable_jobs.len() < limit {
        let events = workspace.query_layer().analyzer_events_full()?;
        for event in events {
            if runnable_jobs.len() + queued_jobs.len() >= limit {
                break;
            }
            if already_targeted.contains(&event.event_id) {
                continue;
            }
            let attrs = serde_json::from_str::<serde_json::Value>(&event.attributes_json)
                .unwrap_or_else(|_| serde_json::json!({}));
            let sidecar = attrs
                .get("sidecar_recommended")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .or_else(|| sidecar_for_event(&event.artifact_type, &event.event_action));
            let Some(sidecar) = sidecar else {
                continue;
            };
            let job = enqueue_sidecar_analysis(SidecarPlanRequest {
                case_root: request.case_root.clone(),
                event_id: event.event_id.clone(),
                sidecar: Some(sidecar),
            })?;
            already_targeted.insert(event.event_id);
            queued_jobs.push(job);
        }
    }
    runnable_jobs.extend(queued_jobs.clone());
    runnable_jobs.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(a.created_at.cmp(&b.created_at))
    });
    runnable_jobs.truncate(limit);

    let mut executed = Vec::new();
    if execute {
        for job in &runnable_jobs {
            executed.push(execute_sidecar_job_inner(
                &request.case_root,
                &job.job_id,
                &format!("taotie-sidecar-{}", short_id(&job.job_id)),
                false,
            )?);
        }
        if rebuild_after_execute
            && executed
                .iter()
                .any(|job| job.status == JobStatus::Succeeded)
        {
            rebuild_case_analysis(&workspace, &queue, "sidecar_batch")?;
            maybe_start_auto_analysis_read_model_refresh(&workspace, &queue, "sidecar_batch")?;
        }
    }

    let jobs = if execute { executed } else { runnable_jobs };
    let succeeded_count = jobs
        .iter()
        .filter(|job| job.status == JobStatus::Succeeded)
        .count();
    let failed_count = jobs
        .iter()
        .filter(|job| job.status == JobStatus::Failed)
        .count();
    let executed_count = jobs
        .iter()
        .filter(|job| matches!(job.status, JobStatus::Succeeded | JobStatus::Failed))
        .count();
    Ok(SidecarBatchResult {
        queued_count: queued_jobs.len(),
        executed_count,
        succeeded_count,
        failed_count,
        skipped_count: limit.saturating_sub(jobs.len()),
        jobs,
        tool_status_json: serde_json::to_string(&sidecar_tool_status())?,
    })
}

pub fn execute_sidecar_job(case_root: &str, job_id: &str, worker_id: &str) -> Result<JobRecord> {
    execute_sidecar_job_inner(case_root, job_id, worker_id, true)
}

fn execute_sidecar_job_inner(
    case_root: &str,
    job_id: &str,
    worker_id: &str,
    rebuild_analysis_after_job: bool,
) -> Result<JobRecord> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let Some(started) = queue.start(job_id, worker_id)? else {
        return Err(ApiError::InvalidRequest(format!("unknown job: {job_id}")));
    };
    if started.status != JobStatus::Running {
        return queue
            .get(job_id)?
            .ok_or_else(|| ApiError::InvalidRequest(format!("unknown job: {job_id}")));
    }
    let execution = execute_sidecar_job_record(
        &workspace,
        &queue,
        &started,
        worker_id,
        rebuild_analysis_after_job,
    );
    if let Err(error) = &execution {
        let _ = queue.fail(job_id, &error.to_string());
        append_sidecar_analyzer_run(
            &workspace,
            &started,
            "failed",
            0,
            Some(error.to_string()),
            serde_json::json!({ "job_id": job_id }),
        )?;
    }
    execution?;
    queue.complete(job_id)?;
    queue
        .get(job_id)?
        .ok_or_else(|| ApiError::InvalidRequest(format!("unknown job: {job_id}")))
}

fn execute_sidecar_job_record(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    job: &JobRecord,
    worker_id: &str,
    rebuild_analysis_after_job: bool,
) -> Result<()> {
    let payload = serde_json::from_str::<serde_json::Value>(&job.payload_json)?;
    let event_id = payload
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::InvalidRequest("sidecar job payload has no event_id".into()))?;
    let sidecar = payload
        .get("sidecar")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("generic_sidecar")
        .to_string();
    let detail = workspace
        .query_layer()
        .event_detail_light(event_id)?
        .ok_or_else(|| ApiError::InvalidRequest(format!("unknown event: {event_id}")))?;
    let (object, _) = workspace
        .raw_object_store()
        .read_range(&detail.evidence_ref, 0, 1)?;
    let output_dir = workspace.root().join("sidecars").join(&job.job_id);
    fs::create_dir_all(&output_dir)?;
    fs::write(
        output_dir.join("plan.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "job": job,
            "source_event": detail,
            "source_object": {
                "object_ref": object.object_ref,
                "sha256": object.sha256,
                "size": object.size,
            },
            "started_at": now_utc(),
        }))?,
    )?;

    queue.update_progress(&job.job_id, 0.10)?;
    let input_bytes = read_file_limited(&object.path, 16 * 1024 * 1024)?;
    let mut execution = SidecarExecution::new(sidecar.clone(), output_dir.clone());
    match job.kind {
        JobKind::RunNetworkSidecar => {
            run_network_sidecar(&object.path, &input_bytes, &detail, &mut execution)?;
        }
        JobKind::RunCredentialSidecar => {
            run_credential_sidecar(&object.path, &input_bytes, &detail, &mut execution)?;
        }
        JobKind::RunDocumentSidecar | JobKind::RunTika => {
            run_document_sidecar(&object.path, &input_bytes, &detail, &mut execution)?;
        }
        JobKind::RunArchiveSidecar => {
            run_archive_sidecar(&object.path, &input_bytes, &detail, &mut execution)?;
        }
        JobKind::RunYara | JobKind::RunSidecar => {
            run_generic_sidecar(&object.path, &input_bytes, &detail, &mut execution)?;
        }
        _ => {
            return Err(ApiError::InvalidRequest(format!(
                "job is not a sidecar job: {}",
                job.kind.as_str()
            )));
        }
    }
    queue.heartbeat(&job.job_id, worker_id)?;
    queue.update_progress(&job.job_id, 0.55)?;
    execution.write_outputs()?;
    let output_manifest = hash_sidecar_outputs(&output_dir)?;
    fs::write(
        output_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&output_manifest)?,
    )?;
    let parse_run_id = new_id("sidecar_parse");
    let events = sidecar_events_from_execution(
        workspace,
        &detail,
        &parse_run_id,
        &job.job_id,
        &execution,
        &output_manifest,
    )?;
    let raw_records = sidecar_raw_records(&events, &execution.records)?;
    let artifact_objects = derive_artifact_objects(&events);
    let evidence_offsets = derive_evidence_offsets(&events);
    let (entities, edges) = derive_entities_edges(&workspace.manifest().case_id, &events)?;
    let timeline_bins = build_timeline_bins(&events);
    workspace.append_parser_versions(&[ParserVersionRecord {
        case_id: workspace.manifest().case_id.clone(),
        parser_name: "taotie-sidecar-worker".to_string(),
        parser_version: env!("CARGO_PKG_VERSION").to_string(),
        recorded_at: now_utc(),
    }])?;
    workspace.append_schema_versions(&[SchemaVersionRecord {
        case_id: workspace.manifest().case_id.clone(),
        schema_name: "canonical_events".to_string(),
        schema_version: CURRENT_SCHEMA_VERSION.to_string(),
        recorded_at: now_utc(),
    }])?;
    workspace.append_parse_runs(&[ParseRun {
        parse_run_id: parse_run_id.clone(),
        case_id: workspace.manifest().case_id.clone(),
        file_id: detail.source_file_id.clone(),
        parser_name: "taotie-sidecar-worker".to_string(),
        parser_version: env!("CARGO_PKG_VERSION").to_string(),
        parser_config_hash: "sidecar-worker-v1".to_string(),
        schema_version: CURRENT_SCHEMA_VERSION.to_string(),
        status: ParseRunStatus::Succeeded,
        started_at: job.started_at.clone().unwrap_or_else(now_utc),
        finished_at: Some(now_utc()),
        duration_ms: 0,
        event_count: events.len() as i64,
        error_message: None,
    }])?;
    workspace.append_events_full(&events)?;
    workspace.append_raw_records(&raw_records)?;
    workspace.append_artifact_objects(&artifact_objects)?;
    workspace.append_evidence_offsets(&evidence_offsets)?;
    workspace.append_entities(&entities)?;
    workspace.append_edges(&edges)?;
    workspace.append_timeline_bins(&timeline_bins)?;
    append_sidecar_analyzer_run(
        workspace,
        job,
        "succeeded",
        events.len() as i64,
        None,
        serde_json::json!({
            "sidecar": sidecar,
            "output_dir": output_dir.display().to_string(),
            "tool_runs": execution.tools,
            "output_manifest": output_manifest,
            "source_event_id": event_id,
        }),
    )?;
    queue.update_progress(&job.job_id, 0.75)?;
    if rebuild_analysis_after_job {
        rebuild_case_analysis(workspace, queue, "sidecar_worker")?;
        maybe_start_auto_analysis_read_model_refresh(workspace, queue, "sidecar_worker")?;
    }
    queue.update_progress(&job.job_id, 0.95)?;
    append_audit_log(
        workspace,
        "sidecar_analysis_completed",
        "event",
        Some(event_id),
        &format!(
            "sidecar analysis completed: {} produced {} events",
            execution.sidecar,
            events.len()
        ),
        serde_json::json!({
            "job_id": job.job_id,
            "sidecar": execution.sidecar,
            "event_count": events.len(),
            "output_dir": output_dir.display().to_string(),
        }),
    )?;
    Ok(())
}

pub fn get_search_index_metadata(case_root: &str) -> Result<Option<SearchIndexMetadata>> {
    let workspace = CaseWorkspace::open(case_root)?;
    search_index_for_workspace(&workspace)
        .metadata()
        .map_err(ApiError::from)
}

pub fn get_search_index_status(case_root: &str) -> Result<SearchIndexStatus> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let metadata = search_index_for_workspace(&workspace).metadata()?;
    let current_event_count = workspace.query_layer().case_summary()?.event_count;
    let is_stale = match &metadata {
        Some(metadata) => metadata.indexed_event_count != current_event_count,
        None => current_event_count > 0,
    };
    Ok(SearchIndexStatus {
        metadata,
        current_event_count,
        is_stale,
        active_job: active_search_index_job(&queue)?,
    })
}

pub fn search_indexed_events(request: EventSearchIndexRequest) -> Result<Page<EventSearchHit>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    search_index_for_workspace(&workspace)
        .search_first_page(EventSearchQuery {
            text: request.text,
            limit: request.limit,
            cursor: request.cursor,
        })
        .map_err(ApiError::from)
}

fn active_search_index_job(queue: &JobQueue) -> Result<Option<JobRecord>> {
    Ok(queue.recent(500)?.into_iter().find(|job| {
        job.kind == JobKind::BuildTantivyIndex
            && matches!(job.status, JobStatus::Queued | JobStatus::Running)
            && background_job_is_fresh(job)
            && is_real_search_index_job(job)
    }))
}

fn is_real_search_index_job(job: &JobRecord) -> bool {
    serde_json::from_str::<serde_json::Value>(&job.payload_json)
        .ok()
        .and_then(|value| {
            value
                .get("index")
                .and_then(|index| index.as_str())
                .map(str::to_string)
        })
        .as_deref()
        == Some("tantivy_events")
}

fn enqueue_search_index_job(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    mode: &str,
    priority: i64,
) -> Result<JobRecord> {
    queue
        .enqueue(
            workspace.manifest().case_id.as_str(),
            JobKind::BuildTantivyIndex,
            priority,
            serde_json::json!({
                "index": "tantivy_events",
                "mode": mode,
            })
            .to_string(),
            default_resource_limits(),
        )
        .map_err(ApiError::from)
}

fn active_answer_candidate_job(queue: &JobQueue) -> Result<Option<JobRecord>> {
    Ok(queue.recent(500)?.into_iter().find(|job| {
        job.kind == JobKind::BuildAnswerCandidates
            && matches!(job.status, JobStatus::Queued | JobStatus::Running)
            && background_job_is_fresh(job)
            && is_answer_candidate_job(job)
    }))
}

fn active_correlation_read_model_job(queue: &JobQueue) -> Result<Option<JobRecord>> {
    Ok(queue.recent(500)?.into_iter().find(|job| {
        job.kind == JobKind::BuildCorrelationChains
            && matches!(job.status, JobStatus::Queued | JobStatus::Running)
            && background_job_is_fresh(job)
            && is_correlation_read_model_job(job)
    }))
}

fn active_detection_read_model_job(queue: &JobQueue) -> Result<Option<JobRecord>> {
    Ok(queue.recent(500)?.into_iter().find(|job| {
        job.kind == JobKind::RunFindings
            && matches!(job.status, JobStatus::Queued | JobStatus::Running)
            && background_job_is_fresh(job)
            && is_detection_read_model_job(job)
    }))
}

fn background_job_is_fresh(job: &JobRecord) -> bool {
    let last_seen = job
        .heartbeat_at
        .as_deref()
        .unwrap_or(job.updated_at.as_str());
    parse_utc(last_seen)
        .map(|last_seen| {
            Utc::now() - last_seen < chrono::Duration::minutes(BACKGROUND_JOB_STALE_AFTER_MINUTES)
        })
        .unwrap_or(true)
}

fn is_answer_candidate_job(job: &JobRecord) -> bool {
    serde_json::from_str::<serde_json::Value>(&job.payload_json)
        .ok()
        .and_then(|value| {
            value
                .get("read_model")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .as_deref()
        == Some("answer_candidates")
}

fn is_correlation_read_model_job(job: &JobRecord) -> bool {
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(&job.payload_json) else {
        return false;
    };
    let read_model = payload
        .get("read_model")
        .and_then(serde_json::Value::as_str);
    let analyzer = payload.get("analyzer").and_then(serde_json::Value::as_str);
    matches!(
        read_model,
        Some("correlation_chains") | Some("read_models/correlation_chains")
    ) || analyzer == Some("correlation_chains")
}

fn is_detection_read_model_job(job: &JobRecord) -> bool {
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(&job.payload_json) else {
        return false;
    };
    let read_model = payload
        .get("read_model")
        .and_then(serde_json::Value::as_str);
    let analyzer = payload.get("analyzer").and_then(serde_json::Value::as_str);
    matches!(read_model, Some("lake/findings") | Some("findings"))
        || analyzer == Some("detection_findings")
}

fn enqueue_answer_candidate_job(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    mode: &str,
    priority: i64,
) -> Result<JobRecord> {
    queue
        .enqueue(
            workspace.manifest().case_id.as_str(),
            JobKind::BuildAnswerCandidates,
            priority,
            serde_json::json!({
                "read_model": "answer_candidates",
                "mode": mode,
                "execution_policy": "background_worker_only",
            })
            .to_string(),
            default_resource_limits(),
        )
        .map_err(ApiError::from)
}

fn enqueue_correlation_read_model_job(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    trigger: &str,
    limit: usize,
    priority: i64,
) -> Result<JobRecord> {
    queue
        .enqueue(
            workspace.manifest().case_id.as_str(),
            JobKind::BuildCorrelationChains,
            priority,
            serde_json::json!({
                "analyzer": "correlation_chains",
                "read_model": "correlation_chains",
                "mode": format!("auto_{trigger}"),
                "trigger": trigger,
                "limit": limit,
                "execution_policy": "background_worker_only",
            })
            .to_string(),
            default_resource_limits(),
        )
        .map_err(ApiError::from)
}

fn enqueue_detection_read_model_job(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    trigger: &str,
    priority: i64,
) -> Result<JobRecord> {
    queue
        .enqueue(
            workspace.manifest().case_id.as_str(),
            JobKind::RunFindings,
            priority,
            serde_json::json!({
                "analyzer": "detection_findings",
                "read_model": "lake/findings",
                "mode": format!("auto_{trigger}"),
                "trigger": trigger,
                "execution_policy": "background_worker_only",
            })
            .to_string(),
            default_resource_limits(),
        )
        .map_err(ApiError::from)
}

fn spawn_answer_candidate_job(case_root: &str, queue: &JobQueue, job: &JobRecord) -> Result<()> {
    let case_root = case_root.to_string();
    let job_id = job.job_id.clone();
    let worker_id = format!("taotie-answer-candidates-{}", short_id(&job_id));
    let spawn_result = std::thread::Builder::new()
        .name(worker_id.clone())
        .spawn(move || {
            let _ = execute_answer_candidate_job(&case_root, &job_id, &worker_id);
        });
    if let Err(error) = spawn_result {
        let _ = queue.fail(&job.job_id, &error.to_string());
        return Err(ApiError::Io(error));
    }
    Ok(())
}

pub fn execute_answer_candidate_job(
    case_root: &str,
    job_id: &str,
    worker_id: &str,
) -> Result<JobRecord> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let started = queue.start(job_id, worker_id)?;
    let Some(started) = started else {
        return Err(ApiError::InvalidRequest(format!("unknown job: {job_id}")));
    };
    if started.status != JobStatus::Running {
        return Err(ApiError::InvalidRequest(format!(
            "answer candidate job is not runnable: {job_id} status={}",
            started.status.as_str()
        )));
    }
    let started_at = started.started_at.clone().unwrap_or_else(now_utc);
    let build_result = build_answer_candidate_read_model(&workspace, &queue, job_id, started_at);
    if let Err(error) = &build_result {
        let _ = queue.fail(job_id, &error.to_string());
    }
    build_result?;
    queue.complete(job_id)?;
    Ok(queue.get(job_id)?.ok_or_else(|| {
        ApiError::InvalidRequest(format!("answer candidate job disappeared: {job_id}"))
    })?)
}

fn build_answer_candidate_read_model(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    job_id: &str,
    started_at: String,
) -> Result<()> {
    queue.update_progress(job_id, 0.05)?;
    let input_fingerprint = answer_candidate_input_fingerprint(workspace)?;
    if let Some(existing_count) =
        reusable_answer_candidate_count(workspace, input_fingerprint.as_str())?
    {
        queue.update_progress(job_id, 0.85)?;
        workspace.append_analyzer_runs(&[AnalyzerRunSummary {
            run_id: new_id("analyzer"),
            case_id: workspace.manifest().case_id.clone(),
            analyzer_id: "answer_candidates".to_string(),
            name: "調査候補カード".to_string(),
            version: ANSWER_CANDIDATE_READ_MODEL_VERSION.to_string(),
            status: "succeeded".to_string(),
            started_at,
            finished_at: Some(now_utc()),
            input_count: 0,
            output_count: existing_count as i64,
            error_message: None,
            metadata_json: serde_json::json!({
                "read_model": "read_models/answer_candidates",
                "source": "background_job",
                "job_id": job_id,
                "input_fingerprint": input_fingerprint,
                "candidate_version": ANSWER_CANDIDATE_READ_MODEL_VERSION,
                "reused_existing_read_model": true,
            })
            .to_string(),
        }])?;
        append_audit_log(
            workspace,
            "answer_candidates_reused",
            "case",
            Some(workspace.manifest().case_id.as_str()),
            &format!("investigation leads reused: {existing_count}"),
            serde_json::json!({
                "job_id": job_id,
                "answer_candidate_count": existing_count,
                "input_fingerprint": input_fingerprint,
            }),
        )?;
        queue.update_progress(job_id, 0.95)?;
        return Ok(());
    }
    let source_events = workspace
        .query_layer()
        .analyzer_events_for_answer_candidates()?;
    queue.update_progress(job_id, 0.55)?;
    let candidates = build_answer_candidates(&workspace.manifest().case_id, &source_events)?;
    workspace.replace_answer_candidates(&candidates)?;
    queue.update_progress(job_id, 0.85)?;
    workspace.append_analyzer_runs(&[AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "answer_candidates".to_string(),
        name: "調査候補カード".to_string(),
        version: ANSWER_CANDIDATE_READ_MODEL_VERSION.to_string(),
        status: "succeeded".to_string(),
        started_at,
        finished_at: Some(now_utc()),
        input_count: source_events.len() as i64,
        output_count: candidates.len() as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "read_model": "read_models/answer_candidates",
            "source": "background_job",
            "job_id": job_id,
            "input_fingerprint": input_fingerprint,
            "candidate_version": ANSWER_CANDIDATE_READ_MODEL_VERSION,
            "reused_existing_read_model": false,
            "source_event_count": source_events.len(),
        })
        .to_string(),
    }])?;
    append_audit_log(
        workspace,
        "answer_candidates_built",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        &format!("investigation leads built: {}", candidates.len()),
        serde_json::json!({
            "job_id": job_id,
            "source_event_count": source_events.len(),
            "answer_candidate_count": candidates.len(),
        }),
    )?;
    queue.update_progress(job_id, 0.95)?;
    Ok(())
}

fn answer_candidate_input_fingerprint(workspace: &CaseWorkspace) -> Result<String> {
    if let Some(fingerprint) = workspace.table_fingerprint(TableKind::EventRows)? {
        return Ok(format!(
            "{ANSWER_CANDIDATE_READ_MODEL_VERSION}|event_rows|{fingerprint}"
        ));
    }
    if let Some(fingerprint) = workspace.table_fingerprint(TableKind::EventsFull)? {
        return Ok(format!(
            "{ANSWER_CANDIDATE_READ_MODEL_VERSION}|events_full|{fingerprint}"
        ));
    }
    Ok(format!("{ANSWER_CANDIDATE_READ_MODEL_VERSION}|empty|none"))
}

fn reusable_answer_candidate_count(
    workspace: &CaseWorkspace,
    input_fingerprint: &str,
) -> Result<Option<usize>> {
    let current_count = workspace.query_layer().answer_candidate_count()?;
    let legacy_read_model_is_fresh = answer_candidate_read_model_is_fresh(workspace)?;
    let mut reusable_legacy_run = false;
    for run in workspace.query_layer().analyzer_runs(Some(200))? {
        if run.analyzer_id != "answer_candidates" || run.status != "succeeded" {
            continue;
        }
        let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&run.metadata_json) else {
            if current_count > 0 && legacy_read_model_is_fresh && run.output_count > 0 {
                reusable_legacy_run = true;
            }
            continue;
        };
        if current_count > 0
            && legacy_read_model_is_fresh
            && run.output_count > 0
            && metadata
                .get("read_model")
                .and_then(serde_json::Value::as_str)
                == Some("read_models/answer_candidates")
            && metadata.get("input_fingerprint").is_none()
        {
            reusable_legacy_run = true;
        }
        let Some(previous_fingerprint) = metadata
            .get("input_fingerprint")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let previous_version = metadata
            .get("candidate_version")
            .and_then(serde_json::Value::as_str);
        if previous_fingerprint != input_fingerprint
            || previous_version != Some(ANSWER_CANDIDATE_READ_MODEL_VERSION)
        {
            continue;
        }
        let previous_output = run.output_count.max(0) as usize;
        if previous_output == 0 || current_count > 0 {
            return Ok(Some(current_count));
        }
    }
    if reusable_legacy_run {
        return Ok(Some(current_count));
    }
    Ok(None)
}

fn answer_candidate_read_model_is_fresh(workspace: &CaseWorkspace) -> Result<bool> {
    let Some(answer_modified) =
        workspace.table_latest_modified_nanos(TableKind::AnswerCandidates)?
    else {
        return Ok(false);
    };
    let input_modified = workspace
        .table_latest_modified_nanos(TableKind::EventRows)?
        .or(workspace.table_latest_modified_nanos(TableKind::EventsFull)?);
    Ok(input_modified
        .map(|modified| answer_modified >= modified)
        .unwrap_or(true))
}

fn maybe_start_auto_analysis_read_model_refresh(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    trigger: &str,
) -> Result<Vec<JobRecord>> {
    let mut jobs = Vec::new();
    if let Some(job) = maybe_start_auto_correlation_read_model_refresh(workspace, queue, trigger)? {
        jobs.push(job);
    }
    if let Some(job) = maybe_start_auto_detection_read_model_refresh(workspace, queue, trigger)? {
        if !jobs.iter().any(|existing| existing.job_id == job.job_id) {
            jobs.push(job);
        }
    }
    if let Some(job) = maybe_start_auto_search_index_refresh(workspace, queue, trigger)? {
        if !jobs.iter().any(|existing| existing.job_id == job.job_id) {
            jobs.push(job);
        }
    }
    Ok(jobs)
}

fn maybe_start_auto_correlation_read_model_refresh(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    trigger: &str,
) -> Result<Option<JobRecord>> {
    let current_event_count = workspace.query_layer().lake_event_count()?;
    if current_event_count == 0 || correlation_read_model_is_fresh(workspace, current_event_count)?
    {
        return Ok(None);
    }
    if let Some(active) = active_correlation_read_model_job(queue)? {
        return Ok(Some(active));
    }
    let job = enqueue_correlation_read_model_job(workspace, queue, trigger, 500, 44)?;
    spawn_correlation_read_model_job(&workspace.root().display().to_string(), queue, &job)?;
    Ok(Some(job))
}

fn correlation_read_model_is_fresh(
    workspace: &CaseWorkspace,
    current_event_count: usize,
) -> Result<bool> {
    let input_modified = [
        workspace.table_latest_modified_nanos(TableKind::EventsFull)?,
        workspace.table_latest_modified_nanos(TableKind::ArtifactObjects)?,
        workspace.table_latest_modified_nanos(TableKind::EvidenceOffsets)?,
    ]
    .into_iter()
    .flatten()
    .max();
    let Some(correlation_modified) =
        workspace.table_latest_modified_nanos(TableKind::CorrelationChains)?
    else {
        return correlation_empty_result_run_is_fresh(workspace, current_event_count);
    };
    Ok(input_modified
        .map(|modified| correlation_modified >= modified)
        .unwrap_or(true))
}

fn correlation_empty_result_run_is_fresh(
    workspace: &CaseWorkspace,
    current_event_count: usize,
) -> Result<bool> {
    for run in workspace.query_layer().analyzer_runs(Some(200))? {
        if run.analyzer_id != "correlation_chains"
            || run.status != "succeeded"
            || run.output_count != 0
            || run.input_count != current_event_count as i64
        {
            continue;
        }
        let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&run.metadata_json) else {
            continue;
        };
        let read_model = metadata
            .get("read_model")
            .and_then(serde_json::Value::as_str);
        if read_model == Some("read_models/correlation_chains")
            || read_model == Some("correlation_chains")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn maybe_start_auto_detection_read_model_refresh(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    trigger: &str,
) -> Result<Option<JobRecord>> {
    let current_event_count = workspace.query_layer().lake_event_count()?;
    if current_event_count == 0 || detection_read_model_is_fresh(workspace, current_event_count)? {
        return Ok(None);
    }
    if !correlation_read_model_is_fresh(workspace, current_event_count)? {
        if let Some(active) = active_correlation_read_model_job(queue)? {
            return Ok(Some(active));
        }
        return Ok(None);
    }
    if let Some(active) = active_detection_read_model_job(queue)? {
        return Ok(Some(active));
    }
    let job = enqueue_detection_read_model_job(workspace, queue, trigger, 43)?;
    spawn_detection_read_model_job(&workspace.root().display().to_string(), queue, &job)?;
    Ok(Some(job))
}

fn detection_read_model_is_fresh(
    workspace: &CaseWorkspace,
    current_event_count: usize,
) -> Result<bool> {
    let input_modified = [
        workspace.table_latest_modified_nanos(TableKind::EventsFull)?,
        workspace.table_latest_modified_nanos(TableKind::CorrelationChains)?,
    ]
    .into_iter()
    .flatten()
    .max();
    let Some(findings_modified) = workspace.table_latest_modified_nanos(TableKind::Findings)?
    else {
        return detection_empty_result_run_is_fresh(workspace, current_event_count);
    };
    Ok(input_modified
        .map(|modified| findings_modified >= modified)
        .unwrap_or(true))
}

fn detection_empty_result_run_is_fresh(
    workspace: &CaseWorkspace,
    current_event_count: usize,
) -> Result<bool> {
    for run in workspace.query_layer().analyzer_runs(Some(200))? {
        if run.analyzer_id != "detection_findings"
            || run.status != "succeeded"
            || run.output_count != 0
            || run.input_count != current_event_count as i64
        {
            continue;
        }
        let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&run.metadata_json) else {
            continue;
        };
        let read_model = metadata
            .get("read_model")
            .and_then(serde_json::Value::as_str);
        if read_model == Some("lake/findings") || read_model == Some("findings") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn spawn_detection_read_model_job(
    case_root: &str,
    queue: &JobQueue,
    job: &JobRecord,
) -> Result<()> {
    let case_root = case_root.to_string();
    let job_id = job.job_id.clone();
    let worker_id = format!("taotie-detection-{}", short_id(&job_id));
    let spawn_result = std::thread::Builder::new()
        .name(worker_id.clone())
        .spawn(move || {
            let _ = execute_detection_read_model_job(&case_root, &job_id, &worker_id);
        });
    if let Err(error) = spawn_result {
        let _ = queue.fail(&job.job_id, &error.to_string());
        return Err(ApiError::Io(error));
    }
    Ok(())
}

pub fn execute_detection_read_model_job(
    case_root: &str,
    job_id: &str,
    worker_id: &str,
) -> Result<JobRecord> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let started = queue.start(job_id, worker_id)?;
    let Some(started) = started else {
        return Err(ApiError::InvalidRequest(format!("unknown job: {job_id}")));
    };
    if started.status != JobStatus::Running {
        return Err(ApiError::InvalidRequest(format!(
            "detection read model job is not runnable: {job_id} status={}",
            started.status.as_str()
        )));
    }
    let payload = serde_json::from_str::<serde_json::Value>(&started.payload_json)
        .unwrap_or_else(|_| serde_json::json!({}));
    let trigger = payload
        .get("trigger")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let started_at = started.started_at.clone().unwrap_or_else(now_utc);
    let build_result =
        build_detection_read_model_for_workspace(&workspace, &queue, job_id, started_at, &trigger);
    if let Err(error) = &build_result {
        let _ = queue.fail(job_id, &error.to_string());
    }
    build_result?;
    queue.complete(job_id)?;
    Ok(queue
        .get(job_id)?
        .ok_or_else(|| ApiError::InvalidRequest(format!("detection job disappeared: {job_id}")))?)
}

fn build_detection_read_model_for_workspace(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    job_id: &str,
    started_at: String,
    trigger: &str,
) -> Result<()> {
    queue.update_progress(job_id, 0.05)?;
    let chains = workspace.query_layer().correlation_chains(Some(500))?;
    queue.update_progress(job_id, 0.20)?;
    let result = rebuild_findings_and_event_rows(workspace, &chains)?;
    queue.update_progress(job_id, 0.85)?;
    workspace.append_analyzer_runs(&[AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "detection_findings".to_string(),
        name: "検知/リスク read model 自動生成".to_string(),
        version: "taotie-auto-detection-risk-read-model-v1".to_string(),
        status: "succeeded".to_string(),
        started_at,
        finished_at: Some(now_utc()),
        input_count: result.input_event_count as i64,
        output_count: result.final_count as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "read_model": "lake/findings",
            "derived_read_models": ["read_models/event_rows", "risk_summary"],
            "source": "background_job",
            "job_id": job_id,
            "trigger": trigger,
            "background_job": true,
            "heuristic_count": result.heuristic_count,
            "chain_count": result.chain_count,
            "hayabusa_count": result.hayabusa_count,
            "ioc_count": result.ioc_count,
            "override_count": result.override_count,
            "event_row_count": result.event_row_count,
            "correlation_chain_count": chains.len(),
        })
        .to_string(),
    }])?;
    append_audit_log(
        workspace,
        "detection_read_model_auto_rebuilt",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        &format!(
            "detection/risk read model auto rebuilt: {} findings",
            result.final_count
        ),
        serde_json::json!({
            "job_id": job_id,
            "trigger": trigger,
            "finding_count": result.final_count,
            "heuristic_count": result.heuristic_count,
            "chain_count": result.chain_count,
            "hayabusa_count": result.hayabusa_count,
            "ioc_count": result.ioc_count,
            "event_row_count": result.event_row_count,
            "correlation_chain_count": chains.len(),
        }),
    )?;
    queue.update_progress(job_id, 0.95)?;
    Ok(())
}

fn spawn_correlation_read_model_job(
    case_root: &str,
    queue: &JobQueue,
    job: &JobRecord,
) -> Result<()> {
    let case_root = case_root.to_string();
    let job_id = job.job_id.clone();
    let worker_id = format!("taotie-correlation-{}", short_id(&job_id));
    let spawn_result = std::thread::Builder::new()
        .name(worker_id.clone())
        .spawn(move || {
            let _ = execute_correlation_read_model_job(&case_root, &job_id, &worker_id);
        });
    if let Err(error) = spawn_result {
        let _ = queue.fail(&job.job_id, &error.to_string());
        return Err(ApiError::Io(error));
    }
    Ok(())
}

pub fn execute_correlation_read_model_job(
    case_root: &str,
    job_id: &str,
    worker_id: &str,
) -> Result<JobRecord> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let started = queue.start(job_id, worker_id)?;
    let Some(started) = started else {
        return Err(ApiError::InvalidRequest(format!("unknown job: {job_id}")));
    };
    if started.status != JobStatus::Running {
        return Err(ApiError::InvalidRequest(format!(
            "correlation read model job is not runnable: {job_id} status={}",
            started.status.as_str()
        )));
    }
    let payload = serde_json::from_str::<serde_json::Value>(&started.payload_json)
        .unwrap_or_else(|_| serde_json::json!({}));
    let limit = payload
        .get("limit")
        .and_then(serde_json::Value::as_u64)
        .map(|value| value.clamp(1, 5_000) as usize)
        .unwrap_or(500);
    let trigger = payload
        .get("trigger")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let started_at = started.started_at.clone().unwrap_or_else(now_utc);
    let build_result = build_correlation_read_model_for_workspace(
        &workspace, &queue, job_id, started_at, limit, &trigger,
    );
    if let Err(error) = &build_result {
        let _ = queue.fail(job_id, &error.to_string());
    }
    build_result?;
    queue.complete(job_id)?;
    let _ =
        maybe_start_auto_detection_read_model_refresh(&workspace, &queue, "correlation_read_model");
    Ok(queue.get(job_id)?.ok_or_else(|| {
        ApiError::InvalidRequest(format!("correlation job disappeared: {job_id}"))
    })?)
}

fn build_correlation_read_model_for_workspace(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    job_id: &str,
    started_at: String,
    limit: usize,
    trigger: &str,
) -> Result<()> {
    queue.update_progress(job_id, 0.05)?;
    let input_count = workspace.query_layer().lake_event_count()?;
    queue.update_progress(job_id, 0.15)?;
    let chains = workspace
        .query_layer()
        .rebuild_correlation_chains(Some(limit))?;
    queue.update_progress(job_id, 0.75)?;
    workspace.replace_correlation_chains(&chains)?;
    queue.update_progress(job_id, 0.85)?;
    workspace.append_analyzer_runs(&[AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "correlation_chains".to_string(),
        name: "横断相関 read model 自動生成".to_string(),
        version: "taotie-auto-correlation-read-model-v1".to_string(),
        status: "succeeded".to_string(),
        started_at,
        finished_at: Some(now_utc()),
        input_count: input_count as i64,
        output_count: chains.len() as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "read_model": "read_models/correlation_chains",
            "source": "background_job",
            "job_id": job_id,
            "trigger": trigger,
            "limit": limit,
            "background_job": true,
            "source_event_count": input_count,
        })
        .to_string(),
    }])?;
    append_audit_log(
        workspace,
        "correlation_read_model_auto_rebuilt",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        &format!(
            "correlation read model auto rebuilt: {} chains",
            chains.len()
        ),
        serde_json::json!({
            "job_id": job_id,
            "trigger": trigger,
            "chain_count": chains.len(),
            "limit": limit,
            "source_event_count": input_count,
        }),
    )?;
    queue.update_progress(job_id, 0.95)?;
    Ok(())
}

fn maybe_start_auto_search_index_refresh(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    trigger: &str,
) -> Result<Option<JobRecord>> {
    let Some(metadata) = search_index_for_workspace(workspace).metadata()? else {
        return Ok(None);
    };
    let current_event_count = workspace.query_layer().case_summary()?.event_count;
    if metadata.indexed_event_count == current_event_count {
        return Ok(None);
    }
    if let Some(active) = active_search_index_job(queue)? {
        return Ok(Some(active));
    }
    let mode = format!("auto_{trigger}");
    let job = enqueue_search_index_job(workspace, queue, &mode, 30)?;
    spawn_search_index_job(&workspace.root().display().to_string(), queue, &job)?;
    Ok(Some(job))
}

fn spawn_search_index_job(case_root: &str, queue: &JobQueue, job: &JobRecord) -> Result<()> {
    let case_root = case_root.to_string();
    let job_id = job.job_id.clone();
    let worker_id = format!("taotie-search-index-{}", short_id(&job_id));
    let spawn_result = std::thread::Builder::new()
        .name(worker_id.clone())
        .spawn(move || {
            let _ = execute_search_index_job(&case_root, &job_id, &worker_id);
        });
    if let Err(error) = spawn_result {
        let _ = queue.fail(&job.job_id, &error.to_string());
        return Err(ApiError::Io(error));
    }
    Ok(())
}

fn execute_search_index_job(
    case_root: &str,
    job_id: &str,
    worker_id: &str,
) -> Result<SearchIndexMetadata> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    let started = queue.start(job_id, worker_id)?;
    let Some(started) = started else {
        return Err(ApiError::InvalidRequest(format!("unknown job: {job_id}")));
    };
    if started.status != JobStatus::Running {
        return Err(ApiError::InvalidRequest(format!(
            "search index job is not runnable: {job_id} status={}",
            started.status.as_str()
        )));
    }
    let started_at = started.started_at.clone().unwrap_or_else(now_utc);
    let build_result = build_search_index_for_workspace(&workspace, &queue, job_id, started_at);
    if let Err(error) = &build_result {
        let _ = queue.fail(job_id, &error.to_string());
    }
    let metadata = build_result?;
    queue.complete(job_id)?;
    Ok(metadata)
}

fn build_search_index_for_workspace(
    workspace: &CaseWorkspace,
    queue: &JobQueue,
    job_id: &str,
    started_at: String,
) -> Result<SearchIndexMetadata> {
    queue.update_progress(job_id, 0.05)?;
    let events = workspace
        .query_layer()
        .analyzer_events_full()?
        .into_iter()
        .map(index_event_from_full);
    queue.update_progress(job_id, 0.20)?;
    let metadata = search_index_for_workspace(workspace)
        .sync_from_events(workspace.manifest().case_id.as_str(), events)
        .map_err(ApiError::from)?;
    queue.update_progress(job_id, 0.85)?;
    let build_mode = metadata
        .build_mode
        .as_deref()
        .unwrap_or("full_rebuild")
        .to_string();
    let appended_event_count = metadata
        .appended_event_count
        .unwrap_or(metadata.indexed_event_count);
    let updated_event_count = metadata.updated_event_count.unwrap_or(0);
    let deleted_event_count = metadata.deleted_event_count.unwrap_or(0);
    let changed_event_count = appended_event_count + updated_event_count + deleted_event_count;
    workspace.append_analyzer_runs(&[AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "tantivy_event_index".to_string(),
        name: "Tantivy 全文検索インデックス".to_string(),
        version: metadata.index_version.clone(),
        status: "succeeded".to_string(),
        started_at,
        finished_at: Some(now_utc()),
        input_count: metadata.indexed_event_count,
        output_count: changed_event_count,
        error_message: None,
        metadata_json: serde_json::json!({
            "index_path": workspace.root().join("indexes").join("tantivy").display().to_string(),
            "updated_at": metadata.updated_at.as_deref(),
            "job_id": job_id,
            "build_mode": build_mode.as_str(),
            "appended_event_count": appended_event_count,
            "updated_event_count": updated_event_count,
            "deleted_event_count": deleted_event_count,
        })
        .to_string(),
    }])?;
    append_audit_log(
        workspace,
        "search_index_built",
        "case",
        Some(workspace.manifest().case_id.as_str()),
        &format!(
            "Tantivy search index {build_mode} for {} events (+{} ~{} -{})",
            metadata.indexed_event_count,
            appended_event_count,
            updated_event_count,
            deleted_event_count
        ),
        serde_json::json!({
            "index_version": metadata.index_version.as_str(),
            "indexed_event_count": metadata.indexed_event_count,
            "updated_at": metadata.updated_at.as_deref(),
            "job_id": job_id,
            "build_mode": build_mode.as_str(),
            "appended_event_count": appended_event_count,
            "updated_event_count": updated_event_count,
            "deleted_event_count": deleted_event_count,
        }),
    )?;
    queue.update_progress(job_id, 0.95)?;
    Ok(metadata)
}

fn short_id(value: &str) -> String {
    value.chars().take(8).collect()
}

fn sidecar_for_event(artifact_type: &str, event_action: &str) -> Option<String> {
    let lower_action = event_action.to_ascii_lowercase();
    match artifact_type {
        "network_capture" => Some("zeek_tshark_pcap_analysis".to_string()),
        "credential_store" => Some("dpapi_keepass_browser_secret_recovery".to_string()),
        "document" => Some("tika_oletools_document_triage".to_string()),
        "archive" => Some("archive_listing_and_carving".to_string()),
        "disk_image" | "filesystem_image" | "raw_image" => Some("deleted_file_carving".to_string()),
        "filezilla" if lower_action.contains("queue") => Some("sqlite_queue_parser".to_string()),
        _ if lower_action.contains("yara") => Some("yara_scan".to_string()),
        _ => None,
    }
}

fn sidecar_job_kind(sidecar: &str) -> JobKind {
    let lower = sidecar.to_ascii_lowercase();
    if lower.contains("zeek") || lower.contains("tshark") || lower.contains("pcap") {
        JobKind::RunNetworkSidecar
    } else if lower.contains("dpapi") || lower.contains("keepass") || lower.contains("secret") {
        JobKind::RunCredentialSidecar
    } else if lower.contains("tika") || lower.contains("oletools") || lower.contains("document") {
        JobKind::RunDocumentSidecar
    } else if lower.contains("archive")
        || lower.contains("carving")
        || lower.contains("deleted_file")
        || lower.contains("disk_image")
        || lower.contains("filesystem_image")
    {
        JobKind::RunArchiveSidecar
    } else if lower.contains("yara") {
        JobKind::RunYara
    } else {
        JobKind::RunSidecar
    }
}

fn sidecar_expected_outputs(sidecar: &str) -> Vec<String> {
    let lower = sidecar.to_ascii_lowercase();
    if lower.contains("zeek") || lower.contains("tshark") || lower.contains("pcap") {
        vec![
            "conn.log".to_string(),
            "dns.log".to_string(),
            "http.log".to_string(),
            "files.log".to_string(),
            "tshark.json".to_string(),
            "tcpflows/".to_string(),
        ]
    } else if lower.contains("dpapi") || lower.contains("keepass") || lower.contains("secret") {
        vec![
            "credential_recovery_report.json".to_string(),
            "dpapi_masterkey_candidates.jsonl".to_string(),
            "browser_secret_candidates.jsonl".to_string(),
            "keepass_entries.jsonl".to_string(),
        ]
    } else if lower.contains("tika") || lower.contains("oletools") || lower.contains("document") {
        vec![
            "document_metadata.json".to_string(),
            "embedded_indicators.jsonl".to_string(),
            "macro_triage.json".to_string(),
        ]
    } else if lower.contains("archive") || lower.contains("carving") {
        vec![
            "archive_listing.json".to_string(),
            "carved_file_hashes.jsonl".to_string(),
            "recovered_files/".to_string(),
            "carved_files/".to_string(),
        ]
    } else {
        vec!["sidecar_result.json".to_string()]
    }
}

fn sidecar_resource_limits(sidecar: &str) -> String {
    let lower = sidecar.to_ascii_lowercase();
    let timeout_ms = if lower.contains("archive") || lower.contains("pcap") {
        900_000
    } else {
        600_000
    };
    serde_json::json!({
        "timeout_ms": timeout_ms,
        "memory_mb": 2048,
        "concurrency": 1,
        "network_access": false,
        "write_scope": "case_sidecars",
        "max_output_mb": 512,
    })
    .to_string()
}

#[derive(Debug, Clone, Serialize)]
struct SidecarToolRun {
    tool: String,
    available: bool,
    command: Vec<String>,
    status: String,
    exit_code: Option<i32>,
    stdout_path: Option<String>,
    stderr_path: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SidecarSignal {
    record_kind: String,
    artifact_type: String,
    event_action: String,
    severity: String,
    message: String,
    host: Option<String>,
    user_name: Option<String>,
    process_name: Option<String>,
    file_path: Option<String>,
    ip: Option<String>,
    url: Option<String>,
    hash: Option<String>,
    tool: Option<String>,
    attributes: serde_json::Value,
}

#[derive(Debug, Clone)]
struct SidecarExecution {
    sidecar: String,
    output_dir: PathBuf,
    tools: Vec<SidecarToolRun>,
    records: Vec<SidecarSignal>,
}

impl SidecarExecution {
    fn new(sidecar: String, output_dir: PathBuf) -> Self {
        Self {
            sidecar,
            output_dir,
            tools: Vec::new(),
            records: Vec::new(),
        }
    }

    fn push(&mut self, signal: SidecarSignal) {
        self.records.push(signal);
    }

    fn write_outputs(&self) -> Result<()> {
        fs::write(
            self.output_dir.join("tools.json"),
            serde_json::to_vec_pretty(&self.tools)?,
        )?;
        let mut jsonl = fs::File::create(self.output_dir.join("records.jsonl"))?;
        for record in &self.records {
            writeln!(jsonl, "{}", serde_json::to_string(record)?)?;
        }
        fs::write(
            self.output_dir.join("result.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "sidecar": self.sidecar,
                "record_count": self.records.len(),
                "tool_count": self.tools.len(),
                "tools": self.tools,
            }))?,
        )?;
        Ok(())
    }
}

fn run_network_sidecar(
    input_path: &Path,
    bytes: &[u8],
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let tshark_args = vec![
        "-r".to_string(),
        input_path.display().to_string(),
        "-c".to_string(),
        "10000".to_string(),
        "-T".to_string(),
        "fields".to_string(),
        "-E".to_string(),
        "header=y".to_string(),
        "-E".to_string(),
        "separator=\t".to_string(),
        "-e".to_string(),
        "frame.number".to_string(),
        "-e".to_string(),
        "frame.time_epoch".to_string(),
        "-e".to_string(),
        "ip.src".to_string(),
        "-e".to_string(),
        "ip.dst".to_string(),
        "-e".to_string(),
        "dns.qry.name".to_string(),
        "-e".to_string(),
        "http.host".to_string(),
        "-e".to_string(),
        "http.request.uri".to_string(),
        "-e".to_string(),
        "http.user_agent".to_string(),
        "-e".to_string(),
        "tls.handshake.extensions_server_name".to_string(),
        "-e".to_string(),
        "ftp.request.command".to_string(),
        "-e".to_string(),
        "ftp.request.arg".to_string(),
        "-e".to_string(),
        "ftp.response.code".to_string(),
        "-e".to_string(),
        "ftp.response.arg".to_string(),
    ];
    let tshark = run_tool_capture(
        "tshark",
        &tshark_args,
        &execution.output_dir,
        "tshark_fields",
    );
    if let Some(stdout_path) = tshark.stdout_path.as_deref() {
        if tshark.exit_code == Some(0) {
            let text = fs::read_to_string(stdout_path).unwrap_or_default();
            parse_tshark_tsv(&text, detail, execution);
        }
    }
    execution.tools.push(tshark);

    let zeek_dir = execution.output_dir.join("zeek");
    fs::create_dir_all(&zeek_dir)?;
    let zeek = run_tool_capture_in_dir(
        "zeek",
        &["-Cr".to_string(), input_path.display().to_string()],
        &execution.output_dir,
        &zeek_dir,
        "zeek",
    );
    if zeek.exit_code == Some(0) {
        parse_zeek_logs(&zeek_dir, detail, execution);
    }
    execution.tools.push(zeek);

    for signal in native_network_signals(bytes, detail).into_iter().take(250) {
        execution.push(signal);
    }
    run_pcap_flow_reconstruction(input_path, detail, execution)?;
    Ok(())
}

fn run_document_sidecar(
    input_path: &Path,
    bytes: &[u8],
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let lower = detail
        .file_path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if lower.ends_with(".pdf") {
        let output_text = execution.output_dir.join("pdftotext.txt");
        let args = vec![
            "-layout".to_string(),
            input_path.display().to_string(),
            output_text.display().to_string(),
        ];
        let run = run_tool_capture("pdftotext", &args, &execution.output_dir, "pdftotext");
        if run.exit_code == Some(0) {
            if let Ok(text) = fs::read_to_string(&output_text) {
                extract_document_text_signals(&text, "pdftotext", detail, execution);
            }
        }
        execution.tools.push(run);
    }

    let tika = run_tool_capture(
        "tika",
        &["--text".to_string(), input_path.display().to_string()],
        &execution.output_dir,
        "tika_text",
    );
    if let Some(stdout_path) = tika.stdout_path.as_deref() {
        if tika.exit_code == Some(0) {
            let text = fs::read_to_string(stdout_path).unwrap_or_default();
            extract_document_text_signals(&text, "tika", detail, execution);
        }
    }
    let tika_succeeded = tika.exit_code == Some(0);
    execution.tools.push(tika);

    if !tika_succeeded {
        let tika_app = run_tool_capture(
            "tika-app",
            &["--text".to_string(), input_path.display().to_string()],
            &execution.output_dir,
            "tika_app_text",
        );
        if let Some(stdout_path) = tika_app.stdout_path.as_deref() {
            if tika_app.exit_code == Some(0) {
                let text = fs::read_to_string(stdout_path).unwrap_or_default();
                extract_document_text_signals(&text, "tika-app", detail, execution);
            }
        }
        execution.tools.push(tika_app);
    }

    let exif = run_tool_capture(
        "exiftool",
        &["-j".to_string(), input_path.display().to_string()],
        &execution.output_dir,
        "exiftool",
    );
    if let Some(stdout_path) = exif.stdout_path.as_deref() {
        if exif.exit_code == Some(0) {
            let metadata = fs::read_to_string(stdout_path).unwrap_or_default();
            if !metadata.trim().is_empty() {
                execution.push(sidecar_signal(
                    detail,
                    "document_metadata",
                    "document_metadata_extracted",
                    "info",
                    "Document metadata extracted by exiftool",
                    Some("exiftool"),
                    serde_json::json!({
                        "metadata_preview": truncate_str(&metadata, 4000),
                    }),
                ));
            }
        }
    }
    execution.tools.push(exif);

    let oleid = run_tool_capture(
        "oleid",
        &[input_path.display().to_string()],
        &execution.output_dir,
        "oleid",
    );
    if let Some(stdout_path) = oleid.stdout_path.as_deref() {
        if oleid.exit_code == Some(0) {
            let text = fs::read_to_string(stdout_path).unwrap_or_default();
            if text.to_ascii_lowercase().contains("vba")
                || text.to_ascii_lowercase().contains("macro")
            {
                execution.push(sidecar_signal(
                    detail,
                    "document_macro_triage",
                    "document_macro_triage_observed",
                    "medium",
                    "Office macro triage signal observed",
                    Some("oleid"),
                    serde_json::json!({ "oleid_preview": truncate_str(&text, 4000) }),
                ));
            }
        }
    }
    execution.tools.push(oleid);

    let strings = strings_text(bytes, 4, 50_000).join("\n");
    extract_document_text_signals(&strings, "native_strings", detail, execution);
    Ok(())
}

fn run_credential_sidecar(
    input_path: &Path,
    bytes: &[u8],
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let lower = detail
        .file_path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if lower.ends_with("login data")
        || lower.contains("/login data")
        || lower.contains("\\login data")
    {
        let sql = "SELECT origin_url, username_value, length(password_value), date_created FROM logins LIMIT 500;";
        let args = vec![
            "-readonly".to_string(),
            "-separator".to_string(),
            "\t".to_string(),
            input_path.display().to_string(),
            sql.to_string(),
        ];
        let sqlite = run_tool_capture("sqlite3", &args, &execution.output_dir, "sqlite_logins");
        if let Some(stdout_path) = sqlite.stdout_path.as_deref() {
            if sqlite.exit_code == Some(0) {
                parse_sqlite_login_rows(
                    &fs::read_to_string(stdout_path).unwrap_or_default(),
                    detail,
                    execution,
                );
            }
        }
        execution.tools.push(sqlite);
        emit_browser_secret_recovery_state(detail, execution);
        run_browser_dpapi_decryption(input_path, detail, execution);
    }
    let lower_strings = strings_text(bytes, 4, 20_000)
        .join("\n")
        .to_ascii_lowercase();
    let kind = if lower.ends_with(".kdbx") || lower_strings.contains("keepass") {
        "keepass_database_observed"
    } else if lower.contains("protect/")
        || lower.contains("\\protect\\")
        || lower.contains("masterkey")
    {
        "dpapi_masterkey_candidate"
    } else {
        "credential_store_inventory"
    };
    let required_inputs = if kind == "keepass_database_observed" {
        serde_json::json!(["database_password", "optional_keyfile", "case_approval"])
    } else if kind == "dpapi_masterkey_candidate" {
        serde_json::json!([
            "user_password_or_nt_hash",
            "masterkey",
            "system_hive",
            "security_hive",
            "case_approval"
        ])
    } else {
        serde_json::json!(["case_approval", "source_context"])
    };
    let sid_candidate = lower
        .split('/')
        .chain(lower.split('\\'))
        .find(|part| part.starts_with("s-1-5-21-"))
        .map(str::to_string);
    execution.push(sidecar_signal(
        detail,
        "credential_inventory",
        kind,
        if kind == "credential_store_inventory" { "info" } else { "medium" },
        &format!("Credential recovery preflight completed: {kind}"),
        Some("native_credential_triage"),
        serde_json::json!({
            "recovery_status": "requires_keys_or_passwords",
            "required_inputs": required_inputs,
            "sid_candidate": sid_candidate,
            "keepassxc_cli_available": find_executable("keepassxc-cli").is_some(),
            "pypykatz_available": find_executable("pypykatz").is_some(),
            "supported_external_tools": ["pypykatz", "keepassxc-cli", "sqlite3"],
            "note": "No credential material is decrypted without case-provided keys, hives, masterkeys, or passwords.",
        }),
    ));
    if kind == "keepass_database_observed" {
        run_keepass_metadata_recovery(input_path, detail, execution);
    }
    if kind == "dpapi_masterkey_candidate" || lower.contains("login data") {
        emit_dpapi_recovery_state(kind, detail, execution);
    }
    if kind == "dpapi_masterkey_candidate" {
        run_dpapi_masterkey_decryption(input_path, detail, execution);
    }
    Ok(())
}

fn run_archive_sidecar(
    input_path: &Path,
    bytes: &[u8],
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let seven_zip = run_tool_capture(
        "7z",
        &[
            "l".to_string(),
            "-slt".to_string(),
            input_path.display().to_string(),
        ],
        &execution.output_dir,
        "7z_list",
    );
    if let Some(stdout_path) = seven_zip.stdout_path.as_deref() {
        if seven_zip.exit_code == Some(0) {
            parse_7z_listing(
                &fs::read_to_string(stdout_path).unwrap_or_default(),
                detail,
                execution,
            );
        }
    }
    execution.tools.push(seven_zip);
    if execution.records.is_empty() {
        let unzip = run_tool_capture(
            "unzip",
            &["-l".to_string(), input_path.display().to_string()],
            &execution.output_dir,
            "unzip_list",
        );
        if let Some(stdout_path) = unzip.stdout_path.as_deref() {
            if unzip.exit_code == Some(0) {
                parse_unzip_listing(
                    &fs::read_to_string(stdout_path).unwrap_or_default(),
                    detail,
                    execution,
                );
            }
        }
        execution.tools.push(unzip);
    }
    if execution.records.is_empty() {
        let strings = strings_text(bytes, 4, 5000);
        for path in strings
            .iter()
            .filter(|value| looks_like_archive_member(value))
            .take(100)
        {
            let severity = if suspicious_archive_member(path) {
                "medium"
            } else {
                "info"
            };
            execution.push(sidecar_signal_with_file(
                detail,
                "archive_member",
                if severity == "medium" {
                    "archive_suspicious_member"
                } else {
                    "archive_member_observed"
                },
                severity,
                &format!("Archive member candidate: {path}"),
                Some("native_archive_strings"),
                Some(path.clone()),
                serde_json::json!({ "member_path": path }),
            ));
        }
    }
    if env_flag("TAOTIE4_ALLOW_ARCHIVE_EXTRACTION") {
        run_archive_extraction(input_path, detail, execution)?;
    }
    if execution.sidecar.to_ascii_lowercase().contains("carving")
        || env_flag("TAOTIE4_ALLOW_FILE_CARVING")
    {
        run_deleted_file_carving(input_path, detail, execution)?;
    }
    emit_archive_recovery_summary(detail, execution);
    Ok(())
}

fn run_archive_extraction(
    input_path: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let recovered_dir = execution.output_dir.join("recovered_files");
    fs::create_dir_all(&recovered_dir)?;
    let args = vec![
        "x".to_string(),
        "-y".to_string(),
        format!("-o{}", recovered_dir.display()),
        input_path.display().to_string(),
    ];
    let run = run_tool_capture("7z", &args, &execution.output_dir, "7z_extract");
    let succeeded = run.exit_code == Some(0);
    execution.tools.push(run);
    if !succeeded {
        execution.push(sidecar_signal(
            detail,
            "archive_recovery_state",
            "archive_extraction_failed_or_unavailable",
            "info",
            "Archive extraction was approved but 7z did not produce recovered files",
            Some("7z"),
            serde_json::json!({
                "recovery_status": "extraction_failed_or_tool_missing",
                "recovered_dir": recovered_dir.display().to_string(),
            }),
        ));
        return Ok(());
    }
    let recovered_count = collect_recovered_file_hashes(&recovered_dir, detail, execution)?;
    execution.push(sidecar_signal(
        detail,
        "archive_recovery_state",
        "archive_extraction_completed",
        if recovered_count == 0 {
            "info"
        } else {
            "medium"
        },
        &format!("Archive extraction completed: {recovered_count} files recovered"),
        Some("7z"),
        serde_json::json!({
            "recovery_status": "extracted_to_sidecar_workspace",
            "recovered_dir": recovered_dir.display().to_string(),
            "recovered_file_count": recovered_count,
        }),
    ));
    Ok(())
}

fn run_deleted_file_carving(
    input_path: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let carving_allowed = env_flag("TAOTIE4_ALLOW_FILE_CARVING");
    let tsk_available = find_executable("tsk_recover").is_some();
    let foremost_available = find_executable("foremost").is_some();
    if !carving_allowed {
        execution.push(sidecar_signal(
            detail,
            "deleted_file_carving_state",
            "deleted_file_carving_not_attempted",
            "info",
            "Deleted file recovery/carving was not attempted because TAOTIE4_ALLOW_FILE_CARVING is not set",
            Some("native_file_recovery_triage"),
            serde_json::json!({
                "recovery_status": "requires_explicit_file_carving_approval",
                "required_env": "TAOTIE4_ALLOW_FILE_CARVING=1",
                "tsk_recover_available": tsk_available,
                "foremost_available": foremost_available,
                "bulk_extractor_available": find_executable("bulk_extractor").is_some(),
                "source_path": input_path.display().to_string(),
            }),
        ));
        return Ok(());
    }

    let recovered_deleted = execution.output_dir.join("recovered_deleted");
    fs::create_dir_all(&recovered_deleted)?;
    let tsk = run_tool_capture(
        "tsk_recover",
        &[
            "-e".to_string(),
            input_path.display().to_string(),
            recovered_deleted.display().to_string(),
        ],
        &execution.output_dir,
        "tsk_recover_deleted",
    );
    let tsk_succeeded = tsk.exit_code == Some(0);
    execution.tools.push(tsk);
    let tsk_count = if tsk_succeeded {
        collect_recovered_file_hashes_as(
            &recovered_deleted,
            detail,
            execution,
            "deleted_file_recovered",
            "deleted_file_recovered",
            "tsk_recover",
            "deleted_file_recovered_to_sidecar_workspace",
        )?
    } else {
        0
    };

    let carved_root = execution.output_dir.join("carved_files");
    fs::create_dir_all(&carved_root)?;
    let foremost_dir = carved_root.join("foremost");
    let foremost = run_tool_capture(
        "foremost",
        &[
            "-i".to_string(),
            input_path.display().to_string(),
            "-o".to_string(),
            foremost_dir.display().to_string(),
        ],
        &execution.output_dir,
        "foremost_carve",
    );
    let foremost_succeeded = foremost.exit_code == Some(0);
    execution.tools.push(foremost);
    let foremost_count = if foremost_succeeded && foremost_dir.exists() {
        collect_recovered_file_hashes_as(
            &foremost_dir,
            detail,
            execution,
            "carved_file_recovered",
            "carved_file_recovered",
            "foremost",
            "carved_to_sidecar_workspace",
        )?
    } else {
        0
    };

    let bulk_enabled = env_flag("TAOTIE4_ALLOW_BULK_EXTRACTOR");
    if bulk_enabled {
        let bulk_dir = execution.output_dir.join("bulk_extractor");
        let bulk = run_tool_capture(
            "bulk_extractor",
            &[
                "-o".to_string(),
                bulk_dir.display().to_string(),
                input_path.display().to_string(),
            ],
            &execution.output_dir,
            "bulk_extractor",
        );
        let bulk_succeeded = bulk.exit_code == Some(0);
        execution.tools.push(bulk);
        if bulk_succeeded {
            summarize_bulk_extractor_outputs(&bulk_dir, detail, execution)?;
        }
    }

    execution.push(sidecar_signal(
        detail,
        "deleted_file_carving_state",
        "deleted_file_carving_completed",
        if tsk_count > 0 || foremost_count > 0 {
            "high"
        } else {
            "medium"
        },
        &format!(
            "Deleted file recovery/carving completed: tsk_recover={} foremost={}",
            tsk_count, foremost_count
        ),
        Some("taotie_file_recovery"),
        serde_json::json!({
            "recovery_status": "carving_completed",
            "tsk_recovered_file_count": tsk_count,
            "foremost_recovered_file_count": foremost_count,
            "bulk_extractor_enabled": bulk_enabled,
            "recovered_deleted_dir": recovered_deleted.display().to_string(),
            "carved_root": carved_root.display().to_string(),
        }),
    ));
    Ok(())
}

fn summarize_bulk_extractor_outputs(
    bulk_dir: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let mut files = fs::read_dir(bulk_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    files.sort();
    for path in files.into_iter().take(80) {
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let text = fs::read_to_string(&path).unwrap_or_default();
        let line_count = text.lines().filter(|line| !line.starts_with('#')).count();
        if line_count == 0 {
            continue;
        }
        execution.push(sidecar_signal_with_file(
            detail,
            "bulk_extractor_feature",
            "bulk_extractor_feature_observed",
            if contains_any(&name.to_ascii_lowercase(), &["email", "url", "domain"]) {
                "medium"
            } else {
                "info"
            },
            &format!("bulk_extractor feature file: {name} rows={line_count}"),
            Some("bulk_extractor"),
            Some(path.display().to_string()),
            serde_json::json!({
                "feature_file": name,
                "path": path.display().to_string(),
                "line_count": line_count,
                "preview": truncate_str(&text, 4000),
                "recovery_status": "bulk_extractor_completed",
            }),
        ));
    }
    Ok(())
}

fn collect_recovered_file_hashes(
    recovered_dir: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<usize> {
    collect_recovered_file_hashes_as(
        recovered_dir,
        detail,
        execution,
        "carved_file_hash",
        "archive_member_extracted",
        "7z",
        "extracted_to_sidecar_workspace",
    )
}

fn collect_recovered_file_hashes_as(
    recovered_dir: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
    record_kind: &str,
    event_action: &str,
    tool: &str,
    recovery_status: &str,
) -> Result<usize> {
    let mut stack = vec![recovered_dir.to_path_buf()];
    let mut count = 0usize;
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path.is_file() {
                continue;
            }
            if count >= 500 {
                return Ok(count);
            }
            let size = path.metadata().map(|meta| meta.len()).unwrap_or(0);
            let relative = path
                .strip_prefix(recovered_dir)
                .unwrap_or(path.as_path())
                .display()
                .to_string();
            let sha256 = if size <= 512 * 1024 * 1024 {
                hash_file(&path).ok()
            } else {
                None
            };
            let severity = if suspicious_archive_member(&relative) {
                "medium"
            } else {
                "info"
            };
            execution.push(sidecar_signal_with_file(
                detail,
                record_kind,
                event_action,
                severity,
                &format!("Recovered file observed: {relative}"),
                Some(tool),
                Some(relative.clone()),
                serde_json::json!({
                    "member_path": relative,
                    "recovered_path": path.display().to_string(),
                    "sha256": sha256,
                    "size": size,
                    "recovery_status": recovery_status,
                }),
            ));
            count += 1;
        }
    }
    Ok(count)
}

fn run_generic_sidecar(
    input_path: &Path,
    bytes: &[u8],
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let yara = run_tool_capture(
        "yara",
        &["--version".to_string()],
        &execution.output_dir,
        "yara_version",
    );
    execution.tools.push(yara);
    for signal in native_document_secret_lines(&strings_text(bytes, 4, 20_000).join("\n"))
        .into_iter()
        .take(100)
    {
        execution.push(sidecar_signal(
            detail,
            "sidecar_string_signal",
            "sidecar_string_signal_observed",
            "medium",
            &format!("Sidecar string signal: {}", truncate_str(&signal, 240)),
            Some("native_strings"),
            serde_json::json!({ "line": signal, "input_path": input_path.display().to_string() }),
        ));
    }
    Ok(())
}

fn parse_tshark_tsv(text: &str, detail: &EventDetailLight, execution: &mut SidecarExecution) {
    for (index, line) in text.lines().skip(1).enumerate().take(1000) {
        let cols = line.split('\t').collect::<Vec<_>>();
        if cols.len() < 13 {
            continue;
        }
        let src = clean_opt(cols.get(2).copied());
        let dst = clean_opt(cols.get(3).copied());
        let dns = clean_opt(cols.get(4).copied());
        let http_host = clean_opt(cols.get(5).copied());
        let uri = clean_opt(cols.get(6).copied());
        let sni = clean_opt(cols.get(8).copied());
        let ftp_cmd = clean_opt(cols.get(9).copied());
        let ftp_arg = clean_opt(cols.get(10).copied());
        let ftp_resp = clean_opt(cols.get(12).copied());
        if src.is_none()
            && dst.is_none()
            && dns.is_none()
            && http_host.is_none()
            && sni.is_none()
            && ftp_cmd.is_none()
            && ftp_resp.is_none()
        {
            continue;
        }
        let domain = dns.or(http_host).or(sni);
        let url = match (domain.as_deref(), uri.as_deref()) {
            (Some(host), Some(path)) if path.starts_with('/') => {
                Some(format!("http://{host}{path}"))
            }
            _ => None,
        };
        let message = format!(
            "Network sidecar packet {}: {} -> {} {}{}{}",
            index + 1,
            src.as_deref().unwrap_or("-"),
            dst.as_deref().unwrap_or("-"),
            domain.as_deref().unwrap_or("-"),
            ftp_cmd
                .as_deref()
                .map(|value| format!(" ftp_cmd={value}"))
                .unwrap_or_default(),
            ftp_arg
                .as_deref()
                .map(|value| format!(" arg={}", truncate_str(value, 120)))
                .unwrap_or_default()
        );
        let severity = if ftp_cmd.is_some()
            || ftp_arg
                .as_deref()
                .map(contains_secret_keyword)
                .unwrap_or(false)
        {
            "medium"
        } else {
            "info"
        };
        let mut signal = sidecar_signal(
            detail,
            "network_packet",
            "network_sidecar_signal",
            severity,
            &message,
            Some("tshark"),
            serde_json::json!({
                "frame_number": clean_opt(cols.first().copied()),
                "time_epoch": clean_opt(cols.get(1).copied()),
                "ip_src": src,
                "ip_dst": dst,
                "domain": domain,
                "uri": uri,
                "ftp_command": ftp_cmd,
                "ftp_arg": ftp_arg,
                "ftp_response": ftp_resp,
            }),
        );
        signal.ip = clean_opt(cols.get(3).copied()).or_else(|| clean_opt(cols.get(2).copied()));
        signal.url = url;
        execution.push(signal);
    }
}

fn parse_zeek_logs(dir: &Path, detail: &EventDetailLight, execution: &mut SidecarExecution) {
    for (name, limit) in [
        ("conn.log", 1500usize),
        ("dns.log", 1000),
        ("http.log", 1000),
        ("ftp.log", 1000),
        ("files.log", 1000),
    ] {
        let path = dir.join(name);
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        parse_zeek_log(name, &text, limit, detail, execution);
    }
}

fn parse_zeek_log(
    name: &str,
    text: &str,
    limit: usize,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let mut fields: Vec<String> = Vec::new();
    let mut rows = 0usize;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("#fields") {
            fields = rest
                .split('\t')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect();
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() || fields.is_empty() {
            continue;
        }
        let values = line.split('\t').collect::<Vec<_>>();
        let mut row = HashMap::new();
        for (field, value) in fields.iter().zip(values.iter()) {
            if let Some(clean) = clean_opt(Some(*value)) {
                row.insert(field.as_str(), clean);
            }
        }
        rows += 1;
        match name {
            "conn.log" => push_zeek_conn_signal(&row, detail, execution),
            "dns.log" => push_zeek_dns_signal(&row, detail, execution),
            "http.log" => push_zeek_http_signal(&row, detail, execution),
            "ftp.log" => push_zeek_ftp_signal(&row, detail, execution),
            "files.log" => push_zeek_file_signal(&row, detail, execution),
            _ => {}
        }
        if rows >= limit {
            break;
        }
    }
}

fn push_zeek_conn_signal(
    row: &HashMap<&str, String>,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let src = row.get("id.orig_h").cloned();
    let dst = row.get("id.resp_h").cloned();
    if src.is_none() && dst.is_none() {
        return;
    }
    let service = row
        .get("service")
        .cloned()
        .unwrap_or_else(|| "-".to_string());
    let proto = row.get("proto").cloned().unwrap_or_else(|| "-".to_string());
    let severity = if matches!(service.as_str(), "ftp" | "http" | "smb" | "rdp") {
        "medium"
    } else {
        "info"
    };
    let mut signal = sidecar_signal(
        detail,
        "network_conversation",
        "zeek_connection_observed",
        severity,
        &format!(
            "Zeek connection: {}:{} -> {}:{} proto={} service={}",
            src.as_deref().unwrap_or("-"),
            row.get("id.orig_p").map(String::as_str).unwrap_or("-"),
            dst.as_deref().unwrap_or("-"),
            row.get("id.resp_p").map(String::as_str).unwrap_or("-"),
            proto,
            service
        ),
        Some("zeek"),
        serde_json::json!({
            "ts": row.get("ts"),
            "uid": row.get("uid"),
            "src_ip": src,
            "src_port": row.get("id.orig_p"),
            "dst_ip": dst,
            "dst_port": row.get("id.resp_p"),
            "proto": proto,
            "service": service,
            "duration": row.get("duration"),
            "orig_bytes": row.get("orig_bytes"),
            "resp_bytes": row.get("resp_bytes"),
            "conn_state": row.get("conn_state"),
        }),
    );
    signal.ip = row
        .get("id.resp_h")
        .cloned()
        .or_else(|| row.get("id.orig_h").cloned());
    execution.push(signal);
}

fn push_zeek_dns_signal(
    row: &HashMap<&str, String>,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let Some(query) = row.get("query").cloned() else {
        return;
    };
    let severity = if suspicious_url_or_host(&query) {
        "medium"
    } else {
        "info"
    };
    let mut signal = sidecar_signal(
        detail,
        "network_dns_query",
        "zeek_dns_query_observed",
        severity,
        &format!("Zeek DNS query: {query}"),
        Some("zeek"),
        serde_json::json!({
            "ts": row.get("ts"),
            "uid": row.get("uid"),
            "src_ip": row.get("id.orig_h"),
            "dst_ip": row.get("id.resp_h"),
            "query": query,
            "answers": row.get("answers"),
            "rcode_name": row.get("rcode_name"),
        }),
    );
    signal.ip = row
        .get("id.resp_h")
        .cloned()
        .or_else(|| row.get("id.orig_h").cloned());
    execution.push(signal);
}

fn push_zeek_http_signal(
    row: &HashMap<&str, String>,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let host = row.get("host").cloned();
    let uri = row.get("uri").cloned();
    if host.is_none() && uri.is_none() {
        return;
    }
    let url = match (host.as_deref(), uri.as_deref()) {
        (Some(host), Some(uri)) if uri.starts_with('/') => Some(format!("http://{host}{uri}")),
        (Some(host), _) => Some(format!("http://{host}")),
        _ => uri.clone(),
    };
    let severity = if url.as_deref().map(suspicious_url_or_host).unwrap_or(false) {
        "medium"
    } else {
        "info"
    };
    let mut signal = sidecar_signal_with_url(
        detail,
        "network_http_request",
        "zeek_http_request_observed",
        severity,
        &format!(
            "Zeek HTTP request: {} {}",
            row.get("method").map(String::as_str).unwrap_or("-"),
            url.as_deref().unwrap_or("-")
        ),
        Some("zeek"),
        url,
        serde_json::json!({
            "ts": row.get("ts"),
            "uid": row.get("uid"),
            "src_ip": row.get("id.orig_h"),
            "dst_ip": row.get("id.resp_h"),
            "method": row.get("method"),
            "host": host,
            "uri": uri,
            "status_code": row.get("status_code"),
            "user_agent": row.get("user_agent"),
        }),
    );
    signal.ip = row
        .get("id.resp_h")
        .cloned()
        .or_else(|| row.get("id.orig_h").cloned());
    execution.push(signal);
}

fn push_zeek_ftp_signal(
    row: &HashMap<&str, String>,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let command = row.get("command").or_else(|| row.get("arg")).cloned();
    let user = row.get("user").cloned();
    let password = row.get("password").cloned();
    if command.is_none() && user.is_none() && password.is_none() {
        return;
    }
    let severity = if password.is_some()
        || command
            .as_deref()
            .map(contains_secret_keyword)
            .unwrap_or(false)
    {
        "high"
    } else {
        "medium"
    };
    let mut signal = sidecar_signal(
        detail,
        "network_ftp_command",
        "zeek_ftp_activity_observed",
        severity,
        &format!(
            "Zeek FTP activity: command={} user={} password_present={}",
            command.as_deref().unwrap_or("-"),
            user.as_deref().unwrap_or("-"),
            password.is_some()
        ),
        Some("zeek"),
        serde_json::json!({
            "ts": row.get("ts"),
            "uid": row.get("uid"),
            "src_ip": row.get("id.orig_h"),
            "dst_ip": row.get("id.resp_h"),
            "command": command,
            "arg": row.get("arg"),
            "user": user,
            "password_present": password.is_some(),
            "password_redacted": password.as_ref().map(|_| "(redacted)"),
            "reply_code": row.get("reply_code"),
            "reply_msg": row.get("reply_msg"),
        }),
    );
    signal.ip = row
        .get("id.resp_h")
        .cloned()
        .or_else(|| row.get("id.orig_h").cloned());
    execution.push(signal);
}

fn push_zeek_file_signal(
    row: &HashMap<&str, String>,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let filename = row
        .get("filename")
        .or_else(|| row.get("mime_type"))
        .or_else(|| row.get("source"))
        .cloned();
    let hash = row
        .get("sha256")
        .or_else(|| row.get("sha1"))
        .or_else(|| row.get("md5"))
        .cloned();
    if filename.is_none() && hash.is_none() {
        return;
    }
    let severity = if filename
        .as_deref()
        .map(suspicious_archive_member)
        .unwrap_or(false)
    {
        "medium"
    } else {
        "info"
    };
    let mut signal = sidecar_signal_with_file(
        detail,
        "network_file_transfer",
        "zeek_file_transfer_observed",
        severity,
        &format!(
            "Zeek file transfer: {} hash={}",
            filename.as_deref().unwrap_or("-"),
            hash.as_deref().unwrap_or("-")
        ),
        Some("zeek"),
        filename,
        serde_json::json!({
            "ts": row.get("ts"),
            "fuid": row.get("fuid"),
            "source": row.get("source"),
            "mime_type": row.get("mime_type"),
            "seen_bytes": row.get("seen_bytes"),
            "md5": row.get("md5"),
            "sha1": row.get("sha1"),
            "sha256": row.get("sha256"),
        }),
    );
    signal.hash = hash;
    execution.push(signal);
}

fn native_network_signals(bytes: &[u8], detail: &EventDetailLight) -> Vec<SidecarSignal> {
    let text = strings_text(bytes, 4, 25_000).join("\n");
    let mut out = Vec::new();
    for url in extract_url_like(&text).into_iter().take(100) {
        out.push(sidecar_signal_with_url(
            detail,
            "network_string_url",
            "network_url_observed",
            if suspicious_url_or_host(&url) {
                "medium"
            } else {
                "info"
            },
            &format!("Network URL string observed: {url}"),
            Some("native_network_strings"),
            Some(url.clone()),
            serde_json::json!({ "url": url }),
        ));
    }
    for host in extract_domain_like(&text).into_iter().take(100) {
        out.push(sidecar_signal(
            detail,
            "network_string_domain",
            "network_domain_observed",
            if suspicious_url_or_host(&host) {
                "medium"
            } else {
                "info"
            },
            &format!("Network domain string observed: {host}"),
            Some("native_network_strings"),
            serde_json::json!({ "domain": host }),
        ));
    }
    out
}

fn run_pcap_flow_reconstruction(
    input_path: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<()> {
    let reconstruction_allowed = env_flag("TAOTIE4_ALLOW_PCAP_RECONSTRUCTION");
    let tcpflow_available = find_executable("tcpflow").is_some();
    if !reconstruction_allowed || !tcpflow_available {
        execution.push(sidecar_signal(
            detail,
            "pcap_reconstruction_state",
            if tcpflow_available {
                "pcap_conversation_reconstruction_ready"
            } else {
                "pcap_conversation_reconstruction_tool_missing"
            },
            "info",
            if tcpflow_available {
                "PCAP conversation reconstruction is available; set TAOTIE4_ALLOW_PCAP_RECONSTRUCTION=1 to materialize tcpflow outputs"
            } else {
                "PCAP conversation reconstruction requires tcpflow"
            },
            Some("native_network_triage"),
            serde_json::json!({
                "recovery_status": if reconstruction_allowed { "external_tool_missing" } else { "requires_explicit_reconstruction_approval" },
                "tcpflow_available": tcpflow_available,
                "approval_env": "TAOTIE4_ALLOW_PCAP_RECONSTRUCTION",
                "secret_output_policy": "redacted_in_events_full_content_in_sidecar_workspace",
            }),
        ));
        return Ok(());
    }

    let flow_dir = execution.output_dir.join("tcpflows");
    fs::create_dir_all(&flow_dir)?;
    let args = vec![
        "-r".to_string(),
        input_path.display().to_string(),
        "-o".to_string(),
        flow_dir.display().to_string(),
        "-b".to_string(),
        (5 * 1024 * 1024).to_string(),
    ];
    let run = run_tool_capture("tcpflow", &args, &execution.output_dir, "tcpflow");
    let succeeded = run.exit_code == Some(0);
    execution.tools.push(run);
    if !succeeded {
        execution.push(sidecar_signal(
            detail,
            "pcap_reconstruction_state",
            "pcap_conversation_reconstruction_failed",
            "info",
            "tcpflow did not produce reconstructed conversations",
            Some("tcpflow"),
            serde_json::json!({
                "recovery_status": "tcpflow_failed",
                "tcpflow_dir": flow_dir.display().to_string(),
            }),
        ));
        return Ok(());
    }

    let count = collect_tcpflow_outputs(&flow_dir, detail, execution)?;
    execution.push(sidecar_signal(
        detail,
        "pcap_reconstruction_state",
        "pcap_conversation_reconstruction_completed",
        if count > 0 { "medium" } else { "info" },
        &format!("PCAP conversation reconstruction completed: {count} tcpflow files"),
        Some("tcpflow"),
        serde_json::json!({
            "recovery_status": "tcpflow_reconstructed_to_sidecar_workspace",
            "tcpflow_dir": flow_dir.display().to_string(),
            "conversation_file_count": count,
            "secret_output_policy": "redacted_in_events_full_content_in_sidecar_workspace",
        }),
    ));
    Ok(())
}

fn collect_tcpflow_outputs(
    flow_dir: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) -> Result<usize> {
    let mut files = fs::read_dir(flow_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    files.sort();
    let mut count = 0usize;
    for path in files.into_iter().take(300) {
        let size = path.metadata().map(|meta| meta.len()).unwrap_or(0);
        if size == 0 {
            continue;
        }
        let bytes = read_file_limited(&path, 64 * 1024).unwrap_or_default();
        let preview = conversation_text_preview(&bytes);
        let lower = preview.to_ascii_lowercase();
        let protocol = if contains_any(&lower, &["user ", "pass ", "stor ", "retr ", "ftp"]) {
            "ftp"
        } else if contains_any(&lower, &["get /", "post /", "host:", "http/1."]) {
            "http"
        } else {
            "tcp"
        };
        let password_present = lower
            .lines()
            .any(|line| line.trim_start().to_ascii_lowercase().starts_with("pass "));
        let command_preview = conversation_command_preview(&preview);
        let filename = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("tcpflow")
            .to_string();
        let sha256 = hash_file(&path).ok();
        let severity = if password_present || protocol == "ftp" {
            "high"
        } else if protocol == "http" {
            "medium"
        } else {
            "info"
        };
        let mut signal = sidecar_signal_with_file(
            detail,
            "pcap_reconstructed_conversation",
            "pcap_conversation_reconstructed",
            severity,
            &format!(
                "PCAP conversation reconstructed: {} protocol={} size={}",
                filename, protocol, size
            ),
            Some("tcpflow"),
            Some(path.display().to_string()),
            serde_json::json!({
                "tcpflow_file": path.display().to_string(),
                "tcpflow_filename": filename,
                "size": size,
                "sha256": sha256.clone(),
                "protocol_hint": protocol,
                "password_present": password_present,
                "command_preview": command_preview,
                "text_preview": redact_conversation_preview(&preview),
                "recovery_status": "tcpflow_reconstructed_to_sidecar_workspace",
                "secret_output_policy": "redacted_in_event_preview",
            }),
        );
        signal.hash = sha256;
        execution.push(signal);
        count += 1;
    }
    Ok(count)
}

fn conversation_text_preview(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .take(4096)
        .collect::<String>()
}

fn conversation_command_preview(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.starts_with("user ")
                || lower.starts_with("pass ")
                || lower.starts_with("stor ")
                || lower.starts_with("retr ")
                || lower.starts_with("get ")
                || lower.starts_with("post ")
                || lower.starts_with("host:")
        })
        .map(|line| {
            if line.to_ascii_lowercase().starts_with("pass ") {
                "PASS [redacted]".to_string()
            } else {
                truncate_str(line, 200)
            }
        })
        .take(30)
        .collect()
}

fn redact_conversation_preview(text: &str) -> String {
    text.lines()
        .take(80)
        .map(|line| {
            if line.trim_start().to_ascii_lowercase().starts_with("pass ") {
                "PASS [redacted]".to_string()
            } else {
                truncate_str(line, 240)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn extract_document_text_signals(
    text: &str,
    tool: &str,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let preview = truncate_str(text, 4000);
    if !preview.trim().is_empty() {
        execution.push(sidecar_signal(
            detail,
            "document_text",
            "document_text_extracted",
            "info",
            "Document text extracted",
            Some(tool),
            serde_json::json!({ "text_preview": preview }),
        ));
    }
    for line in native_document_secret_lines(text).into_iter().take(200) {
        let severity = if contains_secret_keyword(&line) {
            "high"
        } else {
            "medium"
        };
        execution.push(sidecar_signal(
            detail,
            "document_indicator",
            "document_sensitive_text_observed",
            severity,
            &format!(
                "Document sensitive text candidate: {}",
                truncate_str(&line, 240)
            ),
            Some(tool),
            serde_json::json!({ "line": line }),
        ));
    }
}

fn parse_sqlite_login_rows(
    text: &str,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    for line in text.lines().take(500) {
        let cols = line.split('\t').collect::<Vec<_>>();
        if cols.len() < 3 {
            continue;
        }
        let origin_url = cols[0].trim().to_string();
        let username = cols[1].trim().to_string();
        let password_len = cols[2].trim().to_string();
        if origin_url.is_empty() && username.is_empty() {
            continue;
        }
        execution.push(sidecar_signal_with_url(
            detail,
            "browser_login_candidate",
            "browser_encrypted_secret_candidate",
            "medium",
            &format!(
                "Browser encrypted credential candidate: {} user={} encrypted_password_len={}",
                origin_url,
                if username.is_empty() { "-" } else { &username },
                password_len
            ),
            Some("sqlite3"),
            if origin_url.is_empty() {
                None
            } else {
                Some(origin_url.clone())
            },
            serde_json::json!({
                "origin_url": origin_url,
                "username": username,
                "encrypted_password_length": password_len,
                "recovery_status": "dpapi_key_required",
            }),
        ));
    }
}

fn emit_browser_secret_recovery_state(detail: &EventDetailLight, execution: &mut SidecarExecution) {
    let secret_export_allowed = env_flag("TAOTIE4_ALLOW_SECRET_EXPORT");
    let dpapi_password_present = std::env::var("TAOTIE4_DPAPI_USER_PASSWORD").is_ok();
    let dpapi_hash_present = std::env::var("TAOTIE4_DPAPI_NT_HASH").is_ok();
    let pypykatz_available = find_executable("pypykatz").is_some();
    let ready = secret_export_allowed
        && pypykatz_available
        && (dpapi_password_present || dpapi_hash_present);
    execution.push(sidecar_signal(
        detail,
        "browser_secret_recovery_state",
        if ready {
            "browser_secret_decryption_ready"
        } else {
            "browser_secret_decryption_blocked"
        },
        if ready { "medium" } else { "info" },
        if ready {
            "Browser credential decryption inputs are present; secrets stay redacted unless explicitly exported"
        } else {
            "Browser credential candidates require DPAPI material and explicit secret export approval"
        },
        Some("native_credential_triage"),
        serde_json::json!({
            "recovery_status": if ready { "ready_for_approved_decryption" } else { "requires_dpapi_inputs_or_approval" },
            "secret_export_allowed": secret_export_allowed,
            "dpapi_password_present": dpapi_password_present,
            "dpapi_nt_hash_present": dpapi_hash_present,
            "pypykatz_available": pypykatz_available,
            "secret_output_policy": if secret_export_allowed { "approved_by_environment" } else { "redacted" },
        }),
    ));
}

fn emit_dpapi_recovery_state(
    kind: &str,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let dpapi_password_present = std::env::var("TAOTIE4_DPAPI_USER_PASSWORD").is_ok();
    let dpapi_hash_present = std::env::var("TAOTIE4_DPAPI_NT_HASH").is_ok();
    let system_hive_present = std::env::var("TAOTIE4_SYSTEM_HIVE").is_ok();
    let security_hive_present = std::env::var("TAOTIE4_SECURITY_HIVE").is_ok();
    let pypykatz_available = find_executable("pypykatz").is_some();
    let ready = pypykatz_available
        && (dpapi_password_present || dpapi_hash_present)
        && (system_hive_present || security_hive_present || kind == "dpapi_masterkey_candidate");
    execution.push(sidecar_signal(
        detail,
        "dpapi_recovery_state",
        if ready {
            "dpapi_decryption_ready"
        } else {
            "dpapi_decryption_blocked"
        },
        if ready { "medium" } else { "info" },
        if ready {
            "DPAPI recovery inputs are present for approved sidecar processing"
        } else {
            "DPAPI recovery requires user password/NT hash, relevant hives/masterkeys, and pypykatz"
        },
        Some("native_credential_triage"),
        serde_json::json!({
            "recovery_status": if ready { "ready_for_approved_decryption" } else { "requires_dpapi_inputs" },
            "dpapi_password_present": dpapi_password_present,
            "dpapi_nt_hash_present": dpapi_hash_present,
            "system_hive_present": system_hive_present,
            "security_hive_present": security_hive_present,
            "pypykatz_available": pypykatz_available,
            "secret_output_policy": if env_flag("TAOTIE4_ALLOW_SECRET_EXPORT") { "approved_by_environment" } else { "redacted" },
        }),
    ));
}

fn run_browser_dpapi_decryption(
    input_path: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let secret_export_allowed = env_flag("TAOTIE4_ALLOW_SECRET_EXPORT");
    let masterkey_file = std::env::var("TAOTIE4_DPAPI_MASTERKEY_FILE").ok();
    let local_state = std::env::var("TAOTIE4_BROWSER_LOCAL_STATE").ok();
    let pypykatz_available = find_executable("pypykatz").is_some();
    if !secret_export_allowed
        || masterkey_file.as_deref().unwrap_or_default().is_empty()
        || local_state.as_deref().unwrap_or_default().is_empty()
        || !pypykatz_available
    {
        execution.push(sidecar_signal(
            detail,
            "browser_secret_decryption_state",
            "browser_secret_decryption_not_attempted",
            "info",
            "Browser Login Data decryption was not attempted because approval or DPAPI inputs are missing",
            Some("native_credential_triage"),
            serde_json::json!({
                "recovery_status": "requires_approval_masterkey_file_and_local_state",
                "secret_export_allowed": secret_export_allowed,
                "pypykatz_available": pypykatz_available,
                "masterkey_file_present": masterkey_file.is_some(),
                "local_state_present": local_state.is_some(),
                "required_env": [
                    "TAOTIE4_ALLOW_SECRET_EXPORT=1",
                    "TAOTIE4_DPAPI_MASTERKEY_FILE",
                    "TAOTIE4_BROWSER_LOCAL_STATE"
                ],
            }),
        ));
        return;
    }
    let args = vec![
        "dpapi".to_string(),
        "chrome".to_string(),
        "--json".to_string(),
        "--logindata".to_string(),
        input_path.display().to_string(),
        masterkey_file.unwrap(),
        local_state.unwrap(),
    ];
    let run = run_tool_capture("pypykatz", &args, &execution.output_dir, "pypykatz_chrome");
    let stdout_path = run.stdout_path.clone();
    let succeeded = run.exit_code == Some(0);
    execution.tools.push(run);
    if !succeeded {
        execution.push(sidecar_signal(
            detail,
            "browser_secret_decryption_state",
            "browser_secret_decryption_failed",
            "medium",
            "pypykatz chrome DPAPI decryption failed",
            Some("pypykatz"),
            serde_json::json!({ "recovery_status": "pypykatz_failed" }),
        ));
        return;
    }
    let text = stdout_path
        .as_deref()
        .and_then(|path| fs::read_to_string(path).ok())
        .unwrap_or_default();
    let urls = extract_url_like(&text);
    let mut emitted = 0usize;
    for url in urls.into_iter().take(200) {
        execution.push(sidecar_signal_with_url(
            detail,
            "browser_secret_decrypted",
            "browser_secret_decrypted",
            "high",
            &format!("Browser credential decrypted for origin: {url}"),
            Some("pypykatz"),
            Some(url.clone()),
            serde_json::json!({
                "origin_url": url,
                "password_present": true,
                "password_redacted": "(redacted)",
                "recovery_status": "decrypted_to_sidecar_workspace",
                "secret_output_policy": "redacted_in_events_full_output_in_sidecar_stdout",
            }),
        ));
        emitted += 1;
    }
    execution.push(sidecar_signal(
        detail,
        "browser_secret_decryption_state",
        "browser_secret_decryption_completed",
        if emitted > 0 { "high" } else { "medium" },
        &format!("Browser DPAPI decryption completed: {emitted} origin candidates extracted"),
        Some("pypykatz"),
        serde_json::json!({
            "recovery_status": "decrypted_to_sidecar_workspace",
            "decrypted_origin_count": emitted,
            "secret_output_policy": "redacted_in_events_full_output_in_sidecar_stdout",
        }),
    ));
}

fn run_dpapi_masterkey_decryption(
    input_path: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let secret_export_allowed = env_flag("TAOTIE4_ALLOW_SECRET_EXPORT");
    let prekey_file = std::env::var("TAOTIE4_DPAPI_PREKEY_FILE").ok();
    let pypykatz_available = find_executable("pypykatz").is_some();
    if !secret_export_allowed
        || prekey_file.as_deref().unwrap_or_default().is_empty()
        || !pypykatz_available
    {
        execution.push(sidecar_signal(
            detail,
            "dpapi_masterkey_decryption_state",
            "dpapi_masterkey_decryption_not_attempted",
            "info",
            "DPAPI masterkey decryption was not attempted because approval or prekey input is missing",
            Some("native_credential_triage"),
            serde_json::json!({
                "recovery_status": "requires_approval_and_prekey_file",
                "secret_export_allowed": secret_export_allowed,
                "pypykatz_available": pypykatz_available,
                "prekey_file_present": prekey_file.is_some(),
                "required_env": [
                    "TAOTIE4_ALLOW_SECRET_EXPORT=1",
                    "TAOTIE4_DPAPI_PREKEY_FILE"
                ],
            }),
        ));
        return;
    }
    let output_path = execution.output_dir.join("dpapi_masterkeys.txt");
    let args = vec![
        "dpapi".to_string(),
        "masterkey".to_string(),
        "-o".to_string(),
        output_path.display().to_string(),
        input_path.display().to_string(),
        prekey_file.unwrap(),
    ];
    let run = run_tool_capture(
        "pypykatz",
        &args,
        &execution.output_dir,
        "pypykatz_masterkey",
    );
    let succeeded = run.exit_code == Some(0);
    execution.tools.push(run);
    execution.push(sidecar_signal(
        detail,
        "dpapi_masterkey_decryption_state",
        if succeeded {
            "dpapi_masterkey_decrypted"
        } else {
            "dpapi_masterkey_decryption_failed"
        },
        if succeeded { "high" } else { "medium" },
        if succeeded {
            "DPAPI masterkey decryption completed"
        } else {
            "DPAPI masterkey decryption failed"
        },
        Some("pypykatz"),
        serde_json::json!({
            "recovery_status": if succeeded { "decrypted_to_sidecar_workspace" } else { "pypykatz_failed" },
            "output_path": output_path.display().to_string(),
            "secret_output_policy": "sidecar_workspace_only",
        }),
    ));
}

fn run_keepass_metadata_recovery(
    input_path: &Path,
    detail: &EventDetailLight,
    execution: &mut SidecarExecution,
) {
    let keepass_available = find_executable("keepassxc-cli").is_some();
    let password = std::env::var("TAOTIE4_KEEPASS_PASSWORD").ok();
    if !keepass_available || password.is_none() {
        execution.push(sidecar_signal(
            detail,
            "keepass_recovery_state",
            if keepass_available {
                "keepass_password_required"
            } else {
                "keepass_tool_missing"
            },
            "medium",
            if keepass_available {
                "KeePass database observed; set TAOTIE4_KEEPASS_PASSWORD for approved metadata listing"
            } else {
                "KeePass database observed; keepassxc-cli is not available"
            },
            Some("native_credential_triage"),
            serde_json::json!({
                "recovery_status": if keepass_available { "requires_keepass_password" } else { "external_tool_missing" },
                "keepassxc_cli_available": keepass_available,
                "secret_output_policy": "entry_names_only",
            }),
        ));
        return;
    }
    let args = vec![
        "ls".to_string(),
        "-q".to_string(),
        input_path.display().to_string(),
    ];
    let stdin = format!("{}\n", password.unwrap());
    let run = run_tool_capture_with_stdin(
        "keepassxc-cli",
        &args,
        stdin.as_bytes(),
        &execution.output_dir,
        "keepass_ls",
    );
    if let Some(stdout_path) = run.stdout_path.as_deref() {
        if run.exit_code == Some(0) {
            let text = fs::read_to_string(stdout_path).unwrap_or_default();
            for entry in text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .take(500)
            {
                execution.push(sidecar_signal(
                    detail,
                    "keepass_entry_candidate",
                    "keepass_entry_metadata_observed",
                    "medium",
                    &format!(
                        "KeePass entry metadata observed: {}",
                        truncate_str(entry, 240)
                    ),
                    Some("keepassxc-cli"),
                    serde_json::json!({
                        "entry_path": entry,
                        "recovery_status": "metadata_listed_secret_redacted",
                        "secret_output_policy": "entry_names_only",
                    }),
                ));
            }
        }
    }
    execution.tools.push(run);

    if !env_flag("TAOTIE4_ALLOW_SECRET_EXPORT") {
        execution.push(sidecar_signal(
            detail,
            "keepass_decryption_state",
            "keepass_export_not_attempted",
            "info",
            "KeePass export was not attempted because TAOTIE4_ALLOW_SECRET_EXPORT is not set",
            Some("native_credential_triage"),
            serde_json::json!({
                "recovery_status": "requires_explicit_secret_export_approval",
                "required_env": ["TAOTIE4_ALLOW_SECRET_EXPORT=1", "TAOTIE4_KEEPASS_PASSWORD"],
                "secret_output_policy": "entry_names_only",
            }),
        ));
        return;
    }

    let Some(password) = std::env::var("TAOTIE4_KEEPASS_PASSWORD").ok() else {
        return;
    };
    let export_args = vec![
        "export".to_string(),
        "-q".to_string(),
        "-f".to_string(),
        "xml".to_string(),
        input_path.display().to_string(),
    ];
    let export_run = run_tool_capture_with_stdin(
        "keepassxc-cli",
        &export_args,
        format!("{password}\n").as_bytes(),
        &execution.output_dir,
        "keepass_export_xml",
    );
    let export_stdout = export_run.stdout_path.clone();
    let export_succeeded = export_run.exit_code == Some(0);
    execution.tools.push(export_run);
    if !export_succeeded {
        execution.push(sidecar_signal(
            detail,
            "keepass_decryption_state",
            "keepass_export_failed",
            "medium",
            "KeePass XML export failed",
            Some("keepassxc-cli"),
            serde_json::json!({ "recovery_status": "keepass_export_failed" }),
        ));
        return;
    }
    let text = export_stdout
        .as_deref()
        .and_then(|path| fs::read_to_string(path).ok())
        .unwrap_or_default();
    let entries = parse_keepass_xml_export(&text);
    for entry in entries.iter().take(500) {
        let title = entry
            .get("Title")
            .cloned()
            .unwrap_or_else(|| "(untitled)".to_string());
        let username = entry.get("UserName").cloned();
        let url = entry.get("URL").cloned();
        let password_present = entry
            .get("Password")
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        let mut signal = sidecar_signal_with_url(
            detail,
            "keepass_entry_decrypted",
            "keepass_entry_decrypted",
            if password_present { "high" } else { "medium" },
            &format!(
                "KeePass entry decrypted: {} user={}",
                truncate_str(&title, 160),
                username.as_deref().unwrap_or("-")
            ),
            Some("keepassxc-cli"),
            url.clone(),
            serde_json::json!({
                "title": title,
                "username": username,
                "url": url,
                "password_present": password_present,
                "password_redacted": password_present.then_some("(redacted)"),
                "recovery_status": "decrypted_to_sidecar_workspace",
                "secret_output_policy": "redacted_in_events_full_output_in_sidecar_stdout",
            }),
        );
        if let Some(username) = entry.get("UserName") {
            signal.user_name = Some(username.clone());
        }
        execution.push(signal);
    }
    execution.push(sidecar_signal(
        detail,
        "keepass_decryption_state",
        "keepass_export_completed",
        if entries.is_empty() { "medium" } else { "high" },
        &format!(
            "KeePass XML export completed: {} entries parsed",
            entries.len()
        ),
        Some("keepassxc-cli"),
        serde_json::json!({
            "recovery_status": "decrypted_to_sidecar_workspace",
            "entry_count": entries.len(),
            "secret_output_policy": "redacted_in_events_full_output_in_sidecar_stdout",
        }),
    ));
}

fn parse_keepass_xml_export(text: &str) -> Vec<HashMap<String, String>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<Entry>") {
        rest = &rest[start + "<Entry>".len()..];
        let Some(end) = rest.find("</Entry>") else {
            break;
        };
        let entry_xml = &rest[..end];
        let mut entry = HashMap::new();
        for key in ["Title", "UserName", "URL", "Password", "Notes"] {
            if let Some(value) = keepass_xml_string_value(entry_xml, key) {
                entry.insert(key.to_string(), value);
            }
        }
        if !entry.is_empty() {
            out.push(entry);
        }
        rest = &rest[end + "</Entry>".len()..];
    }
    out
}

fn keepass_xml_string_value(entry_xml: &str, key: &str) -> Option<String> {
    let key_marker = format!("<Key>{key}</Key>");
    let key_pos = entry_xml.find(&key_marker)?;
    let after_key = &entry_xml[key_pos + key_marker.len()..];
    let value_start_marker = "<Value";
    let value_start = after_key.find(value_start_marker)?;
    let after_value_start = &after_key[value_start..];
    let close = after_value_start.find('>')?;
    let value_text_start = close + 1;
    let value_text_end = after_value_start[value_text_start..].find("</Value>")?;
    let value =
        &after_value_start[value_text_start..value_text_start.saturating_add(value_text_end)];
    let decoded = decode_xml_entities(value);
    clean_opt(Some(decoded.as_str()))
}

fn decode_xml_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn parse_7z_listing(text: &str, detail: &EventDetailLight, execution: &mut SidecarExecution) {
    for line in text
        .lines()
        .filter_map(|line| line.strip_prefix("Path = "))
        .take(1000)
    {
        let member = line.trim();
        if member.is_empty() || member == detail.file_path.as_deref().unwrap_or_default() {
            continue;
        }
        let severity = if suspicious_archive_member(member) {
            "medium"
        } else {
            "info"
        };
        execution.push(sidecar_signal_with_file(
            detail,
            "archive_member",
            if severity == "medium" {
                "archive_suspicious_member"
            } else {
                "archive_member_observed"
            },
            severity,
            &format!("Archive member observed: {member}"),
            Some("7z"),
            Some(member.to_string()),
            serde_json::json!({ "member_path": member }),
        ));
    }
}

fn parse_unzip_listing(text: &str, detail: &EventDetailLight, execution: &mut SidecarExecution) {
    for line in text.lines().skip(3).take(1000) {
        let member = line.split_whitespace().last().unwrap_or("").trim();
        if !looks_like_archive_member(member) {
            continue;
        }
        let severity = if suspicious_archive_member(member) {
            "medium"
        } else {
            "info"
        };
        execution.push(sidecar_signal_with_file(
            detail,
            "archive_member",
            if severity == "medium" {
                "archive_suspicious_member"
            } else {
                "archive_member_observed"
            },
            severity,
            &format!("Archive member observed: {member}"),
            Some("unzip"),
            Some(member.to_string()),
            serde_json::json!({ "member_path": member }),
        ));
    }
}

fn emit_archive_recovery_summary(detail: &EventDetailLight, execution: &mut SidecarExecution) {
    let members = execution
        .records
        .iter()
        .filter(|record| record.record_kind == "archive_member")
        .filter_map(|record| {
            record
                .attributes
                .get("member_path")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .or_else(|| record.file_path.clone())
        })
        .collect::<Vec<_>>();
    if members.is_empty() {
        return;
    }
    let extracted_count = execution
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.record_kind.as_str(),
                "carved_file_hash" | "deleted_file_recovered" | "carved_file_recovered"
            )
        })
        .count();
    let suspicious = members
        .iter()
        .filter(|member| suspicious_archive_member(member))
        .take(50)
        .cloned()
        .collect::<Vec<_>>();
    execution.push(sidecar_signal(
        detail,
        "archive_recovery_candidate",
        "archive_recovery_candidate",
        if suspicious.is_empty() { "info" } else { "medium" },
        &format!(
            "Archive recovery candidate: {} members, {} suspicious",
            members.len(),
            suspicious.len()
        ),
        Some("taotie_archive_recovery"),
        serde_json::json!({
            "member_count": members.len(),
            "suspicious_member_count": suspicious.len(),
            "candidate_members": suspicious,
            "extracted_file_count": extracted_count,
            "recovery_status": if extracted_count > 0 { "extracted_to_sidecar_workspace" } else { "listed_not_extracted" },
            "next_action": if extracted_count > 0 {
                "Review recovered file hashes and extracted paths in the sidecar workspace."
            } else {
                "Set TAOTIE4_ALLOW_ARCHIVE_EXTRACTION=1 to extract in an isolated sidecar workspace when the case requires recovered content."
            },
        }),
    ));
}

fn sidecar_signal(
    detail: &EventDetailLight,
    record_kind: &str,
    event_action: &str,
    severity: &str,
    message: &str,
    tool: Option<&str>,
    attributes: serde_json::Value,
) -> SidecarSignal {
    SidecarSignal {
        record_kind: record_kind.to_string(),
        artifact_type: detail.artifact_type.clone(),
        event_action: event_action.to_string(),
        severity: severity.to_string(),
        message: message.to_string(),
        host: detail.host.clone(),
        user_name: detail.user_name.clone(),
        process_name: detail.process_name.clone(),
        file_path: detail.file_path.clone(),
        ip: detail.ip.clone(),
        url: detail.url.clone(),
        hash: detail.hash.clone(),
        tool: tool.map(str::to_string),
        attributes,
    }
}

fn sidecar_signal_with_url(
    detail: &EventDetailLight,
    record_kind: &str,
    event_action: &str,
    severity: &str,
    message: &str,
    tool: Option<&str>,
    url: Option<String>,
    attributes: serde_json::Value,
) -> SidecarSignal {
    let mut signal = sidecar_signal(
        detail,
        record_kind,
        event_action,
        severity,
        message,
        tool,
        attributes,
    );
    signal.url = url;
    signal
}

fn sidecar_signal_with_file(
    detail: &EventDetailLight,
    record_kind: &str,
    event_action: &str,
    severity: &str,
    message: &str,
    tool: Option<&str>,
    file_path: Option<String>,
    attributes: serde_json::Value,
) -> SidecarSignal {
    let mut signal = sidecar_signal(
        detail,
        record_kind,
        event_action,
        severity,
        message,
        tool,
        attributes,
    );
    signal.file_path = file_path;
    signal
}

fn sidecar_events_from_execution(
    workspace: &CaseWorkspace,
    detail: &EventDetailLight,
    parse_run_id: &str,
    job_id: &str,
    execution: &SidecarExecution,
    output_manifest: &serde_json::Value,
) -> Result<Vec<EventFull>> {
    let mut events = Vec::new();
    for signal in execution.records.iter().take(5000) {
        let event_id = new_id("event");
        let raw_record_ref = new_id("raw");
        let mut attrs = signal.attributes.clone();
        let recovery_status = attrs
            .get("recovery_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("sidecar_generated")
            .to_string();
        merge_json_object(
            &mut attrs,
            serde_json::json!({
                "sidecar_job_id": job_id,
                "sidecar": execution.sidecar,
                "sidecar_tool": signal.tool,
                "sidecar_record_kind": signal.record_kind,
                "sidecar_output_dir": execution.output_dir.display().to_string(),
                "sidecar_output_manifest": output_manifest,
                "source_event_id": detail.event_id,
                "source_parse_run_id": detail.parse_run_id,
                "recovery_status": recovery_status,
            }),
        );
        events.push(EventFull {
            event_id,
            case_id: workspace.manifest().case_id.clone(),
            event_time_utc: now_utc(),
            event_time_original: "sidecar_generated".to_string(),
            time_kind: "sidecar_generated".to_string(),
            time_confidence: 0.2,
            source_confidence: 0.8,
            artifact_type: signal.artifact_type.clone(),
            source_file_id: detail.source_file_id.clone(),
            parse_run_id: parse_run_id.to_string(),
            parser_name: "taotie-sidecar-worker".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            evidence_ref: detail.evidence_ref.clone(),
            host: signal.host.clone(),
            user_name: signal.user_name.clone(),
            process_name: signal.process_name.clone(),
            file_path: signal.file_path.clone(),
            ip: signal.ip.clone(),
            url: signal.url.clone(),
            hash: signal.hash.clone(),
            event_action: signal.event_action.clone(),
            severity: signal.severity.clone(),
            message_short: truncate_str(&signal.message, 240),
            message_full: signal.message.clone(),
            raw_record_ref,
            attributes_json: serde_json::to_string(&attrs)?,
        });
    }
    if events.is_empty() {
        let event_id = new_id("event");
        events.push(EventFull {
            event_id,
            case_id: workspace.manifest().case_id.clone(),
            event_time_utc: now_utc(),
            event_time_original: "sidecar_generated".to_string(),
            time_kind: "sidecar_generated".to_string(),
            time_confidence: 0.2,
            source_confidence: 0.7,
            artifact_type: detail.artifact_type.clone(),
            source_file_id: detail.source_file_id.clone(),
            parse_run_id: parse_run_id.to_string(),
            parser_name: "taotie-sidecar-worker".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            evidence_ref: detail.evidence_ref.clone(),
            host: detail.host.clone(),
            user_name: detail.user_name.clone(),
            process_name: detail.process_name.clone(),
            file_path: detail.file_path.clone(),
            ip: detail.ip.clone(),
            url: detail.url.clone(),
            hash: detail.hash.clone(),
            event_action: "sidecar_no_signal".to_string(),
            severity: "info".to_string(),
            message_short: format!(
                "Sidecar completed without extracted signals: {}",
                execution.sidecar
            ),
            message_full: format!(
                "Sidecar completed without extracted signals: {}",
                execution.sidecar
            ),
            raw_record_ref: new_id("raw"),
            attributes_json: serde_json::json!({
                "sidecar_job_id": job_id,
                "sidecar": execution.sidecar,
                "sidecar_output_dir": execution.output_dir.display().to_string(),
                "sidecar_output_manifest": output_manifest,
                "source_event_id": detail.event_id,
            })
            .to_string(),
        });
    }
    Ok(events)
}

fn sidecar_raw_records(events: &[EventFull], records: &[SidecarSignal]) -> Result<Vec<RawRecord>> {
    let mut out = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let raw_record_value = records
            .get(index)
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or_else(|| serde_json::json!({ "record_kind": "sidecar_no_signal" }));
        out.push(RawRecord {
            raw_record_ref: event.raw_record_ref.clone(),
            case_id: event.case_id.clone(),
            event_id: event.event_id.clone(),
            parse_run_id: event.parse_run_id.clone(),
            source_file_id: event.source_file_id.clone(),
            evidence_ref: event.evidence_ref.clone(),
            raw_record_json: serde_json::to_string(&raw_record_value)?,
        });
    }
    Ok(out)
}

fn append_sidecar_analyzer_run(
    workspace: &CaseWorkspace,
    job: &JobRecord,
    status: &str,
    output_count: i64,
    error_message: Option<String>,
    metadata: serde_json::Value,
) -> Result<()> {
    workspace.append_analyzer_runs(&[AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "sidecar_worker".to_string(),
        name: "Sidecar / import adapter worker".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: status.to_string(),
        started_at: job.started_at.clone().unwrap_or_else(now_utc),
        finished_at: Some(now_utc()),
        input_count: 1,
        output_count,
        error_message,
        metadata_json: metadata.to_string(),
    }])?;
    Ok(())
}

fn hash_sidecar_outputs(output_dir: &Path) -> Result<serde_json::Value> {
    let mut files = Vec::new();
    for entry in fs::read_dir(output_dir)? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_string();
        if name == "manifest.json" {
            continue;
        }
        let bytes = fs::read(&path)?;
        files.push(serde_json::json!({
            "path": path.display().to_string(),
            "name": name,
            "sha256": hex_digest(&bytes),
            "size": bytes.len(),
        }));
    }
    files.sort_by(|a, b| {
        a.get("name")
            .and_then(serde_json::Value::as_str)
            .cmp(&b.get("name").and_then(serde_json::Value::as_str))
    });
    Ok(serde_json::json!({
        "generated_at": now_utc(),
        "files": files,
    }))
}

fn run_tool_capture(tool: &str, args: &[String], output_dir: &Path, stem: &str) -> SidecarToolRun {
    let Some(program) = find_executable(tool) else {
        return SidecarToolRun {
            tool: tool.to_string(),
            available: false,
            command: std::iter::once(tool.to_string())
                .chain(args.iter().cloned())
                .collect(),
            status: "missing".to_string(),
            exit_code: None,
            stdout_path: None,
            stderr_path: None,
            error: Some("tool not found in PATH".to_string()),
        };
    };
    let stdout_path = output_dir.join(format!("{stem}.stdout"));
    let stderr_path = output_dir.join(format!("{stem}.stderr"));
    match Command::new(&program).args(args).output() {
        Ok(output) => {
            let _ = fs::write(&stdout_path, &output.stdout);
            let _ = fs::write(&stderr_path, &output.stderr);
            SidecarToolRun {
                tool: tool.to_string(),
                available: true,
                command: std::iter::once(program.display().to_string())
                    .chain(args.iter().cloned())
                    .collect(),
                status: if output.status.success() {
                    "succeeded".to_string()
                } else {
                    "failed".to_string()
                },
                exit_code: output.status.code(),
                stdout_path: Some(stdout_path.display().to_string()),
                stderr_path: Some(stderr_path.display().to_string()),
                error: if output.status.success() {
                    None
                } else {
                    Some(truncate_str(&String::from_utf8_lossy(&output.stderr), 2000))
                },
            }
        }
        Err(error) => SidecarToolRun {
            tool: tool.to_string(),
            available: true,
            command: std::iter::once(program.display().to_string())
                .chain(args.iter().cloned())
                .collect(),
            status: "failed_to_start".to_string(),
            exit_code: None,
            stdout_path: None,
            stderr_path: None,
            error: Some(error.to_string()),
        },
    }
}

fn run_tool_capture_with_stdin(
    tool: &str,
    args: &[String],
    stdin_bytes: &[u8],
    output_dir: &Path,
    stem: &str,
) -> SidecarToolRun {
    let Some(program) = find_executable(tool) else {
        return SidecarToolRun {
            tool: tool.to_string(),
            available: false,
            command: std::iter::once(tool.to_string())
                .chain(args.iter().cloned())
                .collect(),
            status: "missing".to_string(),
            exit_code: None,
            stdout_path: None,
            stderr_path: None,
            error: Some("tool not found in PATH".to_string()),
        };
    };
    let stdout_path = output_dir.join(format!("{stem}.stdout"));
    let stderr_path = output_dir.join(format!("{stem}.stderr"));
    let mut child = match Command::new(&program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return SidecarToolRun {
                tool: tool.to_string(),
                available: true,
                command: std::iter::once(program.display().to_string())
                    .chain(args.iter().cloned())
                    .collect(),
                status: "failed_to_start".to_string(),
                exit_code: None,
                stdout_path: None,
                stderr_path: None,
                error: Some(error.to_string()),
            };
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_bytes);
    }
    match child.wait_with_output() {
        Ok(output) => {
            let _ = fs::write(&stdout_path, &output.stdout);
            let _ = fs::write(&stderr_path, &output.stderr);
            SidecarToolRun {
                tool: tool.to_string(),
                available: true,
                command: std::iter::once(program.display().to_string())
                    .chain(args.iter().cloned())
                    .collect(),
                status: if output.status.success() {
                    "succeeded".to_string()
                } else {
                    "failed".to_string()
                },
                exit_code: output.status.code(),
                stdout_path: Some(stdout_path.display().to_string()),
                stderr_path: Some(stderr_path.display().to_string()),
                error: if output.status.success() {
                    None
                } else {
                    Some(truncate_str(&String::from_utf8_lossy(&output.stderr), 2000))
                },
            }
        }
        Err(error) => SidecarToolRun {
            tool: tool.to_string(),
            available: true,
            command: std::iter::once(program.display().to_string())
                .chain(args.iter().cloned())
                .collect(),
            status: "failed_to_wait".to_string(),
            exit_code: None,
            stdout_path: None,
            stderr_path: None,
            error: Some(error.to_string()),
        },
    }
}

fn run_tool_capture_in_dir(
    tool: &str,
    args: &[String],
    output_dir: &Path,
    current_dir: &Path,
    stem: &str,
) -> SidecarToolRun {
    let Some(program) = find_executable(tool) else {
        return SidecarToolRun {
            tool: tool.to_string(),
            available: false,
            command: std::iter::once(tool.to_string())
                .chain(args.iter().cloned())
                .collect(),
            status: "missing".to_string(),
            exit_code: None,
            stdout_path: None,
            stderr_path: None,
            error: Some("tool not found in PATH".to_string()),
        };
    };
    let stdout_path = output_dir.join(format!("{stem}.stdout"));
    let stderr_path = output_dir.join(format!("{stem}.stderr"));
    match Command::new(&program)
        .args(args)
        .current_dir(current_dir)
        .output()
    {
        Ok(output) => {
            let _ = fs::write(&stdout_path, &output.stdout);
            let _ = fs::write(&stderr_path, &output.stderr);
            SidecarToolRun {
                tool: tool.to_string(),
                available: true,
                command: std::iter::once(program.display().to_string())
                    .chain(args.iter().cloned())
                    .collect(),
                status: if output.status.success() {
                    "succeeded".to_string()
                } else {
                    "failed".to_string()
                },
                exit_code: output.status.code(),
                stdout_path: Some(stdout_path.display().to_string()),
                stderr_path: Some(stderr_path.display().to_string()),
                error: if output.status.success() {
                    None
                } else {
                    Some(truncate_str(&String::from_utf8_lossy(&output.stderr), 2000))
                },
            }
        }
        Err(error) => SidecarToolRun {
            tool: tool.to_string(),
            available: true,
            command: std::iter::once(program.display().to_string())
                .chain(args.iter().cloned())
                .collect(),
            status: "failed_to_start".to_string(),
            exit_code: None,
            stdout_path: None,
            stderr_path: None,
            error: Some(error.to_string()),
        },
    }
}

fn sidecar_tool_status() -> Vec<serde_json::Value> {
    [
        "tshark",
        "zeek",
        "pdftotext",
        "exiftool",
        "oleid",
        "tika",
        "tika-app",
        "sqlite3",
        "7z",
        "unzip",
        "yara",
        "keepassxc-cli",
        "pypykatz",
        "dpapi.py",
        "tcpflow",
        "tcpick",
        "tsk_recover",
        "foremost",
        "bulk_extractor",
        "icat",
        "fls",
        "istat",
    ]
    .into_iter()
    .map(|tool| {
        let path = find_executable(tool);
        serde_json::json!({
            "tool": tool,
            "available": path.is_some(),
            "path": path.map(|value| value.display().to_string()),
        })
    })
    .collect()
}

fn find_executable(tool: &str) -> Option<PathBuf> {
    if tool.contains('/') {
        let path = PathBuf::from(tool);
        return path.is_file().then_some(path);
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn read_file_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn strings_text(bytes: &[u8], min_len: usize, max_count: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for &byte in bytes {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            current.push(byte);
            if current.len() > 4096 {
                push_string_candidate(&mut out, &mut current, min_len);
            }
        } else {
            push_string_candidate(&mut out, &mut current, min_len);
        }
        if out.len() >= max_count {
            break;
        }
    }
    push_string_candidate(&mut out, &mut current, min_len);
    out
}

fn push_string_candidate(out: &mut Vec<String>, current: &mut Vec<u8>, min_len: usize) {
    if current.len() >= min_len {
        let text = String::from_utf8_lossy(current).trim().to_string();
        if !text.is_empty() {
            out.push(text);
        }
    }
    current.clear();
}

fn native_document_secret_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let clean = line.trim();
        if clean.len() < 4 || clean.len() > 500 {
            continue;
        }
        let lower = clean.to_ascii_lowercase();
        if contains_secret_keyword(&lower)
            || lower.contains("rdp")
            || lower.contains("ftp")
            || lower.contains("administrator")
            || lower.contains("admin")
            || lower.contains("user:")
            || lower.contains("username")
            || lower.contains("http://")
            || lower.contains("https://")
        {
            let key = clean.to_ascii_lowercase();
            if seen.insert(key) {
                out.push(clean.to_string());
            }
        }
    }
    out
}

fn contains_secret_keyword(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "credential",
        "private key",
        "ssh-rsa",
        "rdp",
        "keepass",
        "dpapi",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn extract_url_like(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for token in text.split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>')) {
        let clean = token.trim_matches(|ch: char| matches!(ch, ',' | ';' | ')' | ']' | '}'));
        if (clean.starts_with("http://") || clean.starts_with("https://"))
            && seen.insert(clean.to_ascii_lowercase())
        {
            out.push(clean.to_string());
        }
    }
    out
}

fn extract_domain_like(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for token in text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-') {
        let clean = token.trim_matches('.').to_ascii_lowercase();
        if clean.len() < 4 || clean.len() > 253 || !clean.contains('.') {
            continue;
        }
        if clean
            .split('.')
            .all(|part| !part.is_empty() && part.len() <= 63)
            && clean
                .rsplit('.')
                .next()
                .map(|tld| tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic()))
                .unwrap_or(false)
            && seen.insert(clean.clone())
        {
            out.push(clean);
        }
    }
    out
}

fn suspicious_url_or_host(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    contains_secret_keyword(&lower)
        || lower.ends_with(".ps1")
        || lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".bat")
        || lower.contains("/upload")
        || lower.contains("/download")
}

fn looks_like_archive_member(value: &str) -> bool {
    value.contains('/') || value.contains('\\') || Path::new(value).extension().is_some()
}

fn suspicious_archive_member(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        ".exe",
        ".dll",
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".hta",
        ".lnk",
        ".kdbx",
        ".sqlite",
        "login data",
        "password",
        "secret",
        "ntds.dit",
        "sam",
        "system",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn truncate_str(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn clean_opt(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn merge_json_object(target: &mut serde_json::Value, extra: serde_json::Value) {
    if !target.is_object() {
        *target = serde_json::json!({});
    }
    if let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_sidecar_job_kind(kind: &JobKind) -> bool {
    matches!(
        kind,
        JobKind::RunSidecar
            | JobKind::RunNetworkSidecar
            | JobKind::RunCredentialSidecar
            | JobKind::RunDocumentSidecar
            | JobKind::RunArchiveSidecar
            | JobKind::RunTika
            | JobKind::RunYara
    )
}

fn sidecar_job_event_id(job: &JobRecord) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(&job.payload_json)
        .ok()
        .and_then(|payload| {
            payload
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
}

pub fn get_file_page(case_root: &str, page: FilePageQuery) -> Result<Page<FileRecord>> {
    query(case_root)?.file_page(page).map_err(ApiError::from)
}

pub fn get_event_detail_light(case_root: &str, event_id: &str) -> Result<Option<EventDetailLight>> {
    query(case_root)?
        .event_detail_light(event_id)
        .map_err(ApiError::from)
}

pub fn get_event_context(
    case_root: &str,
    context_query: EventContextQuery,
) -> Result<Option<EventContext>> {
    query(case_root)?
        .event_context(context_query)
        .map_err(ApiError::from)
}

pub fn get_event_raw_record(case_root: &str, event_id: &str) -> Result<Option<RawRecord>> {
    query(case_root)?
        .event_raw_record(event_id)
        .map_err(ApiError::from)
}

pub fn get_event_artifact_objects(case_root: &str, event_id: &str) -> Result<Vec<ArtifactObject>> {
    query(case_root)?
        .event_artifact_objects(event_id)
        .map_err(ApiError::from)
}

pub fn get_event_evidence_offsets(case_root: &str, event_id: &str) -> Result<Vec<EvidenceOffset>> {
    query(case_root)?
        .event_evidence_offsets(event_id)
        .map_err(ApiError::from)
}

pub fn get_evidence_range(request: EvidenceRangeRequest) -> Result<EvidenceRange> {
    let offset = request.offset.unwrap_or(0).max(0) as u64;
    let requested = request
        .length
        .unwrap_or(4096)
        .clamp(1, MAX_EVIDENCE_RANGE_BYTES);
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let (object, bytes) =
        workspace
            .raw_object_store()
            .read_range(&request.object_ref, offset, requested)?;
    Ok(EvidenceRange {
        object_ref: object.object_ref,
        sha256: object.sha256,
        offset: offset as i64,
        length: bytes.len() as i64,
        total_size: object.size,
        hex_dump: format_hex_dump(offset, &bytes),
        ascii_preview: ascii_preview(&bytes),
        truncated: offset + (bytes.len() as u64) < object.size as u64,
    })
}

/// Scan a stored raw object for the first occurrence of `pattern` at or after `from_offset`.
/// `pattern` is interpreted as raw UTF-8 bytes, or as a hex byte string when `is_hex` is set
/// (e.g. "4d 5a" / "0x4d5a"). Reads the object in overlapping 1 MiB windows so matches that
/// straddle a window boundary are still found.
pub fn find_evidence_match(request: EvidenceFindRequest) -> Result<EvidenceFindResult> {
    let needle = if request.is_hex {
        parse_hex_pattern(&request.pattern)?
    } else {
        request.pattern.clone().into_bytes()
    };
    if needle.is_empty() {
        return Err(ApiError::InvalidRequest("検索パターンが空です".to_string()));
    }
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let store = workspace.raw_object_store();
    let (object, _) = store.read_range(&request.object_ref, 0, 1)?;
    let total = object.size.max(0) as u64;
    const CHUNK: usize = 1 << 20;
    // A needle longer than the object can never match; one longer than the scan window can't be
    // found by this windowed scan (avoids a byte-by-byte re-read hang). Report "no match" cleanly.
    if needle.len() as u64 > total || needle.len() > CHUNK {
        return Ok(EvidenceFindResult {
            offset: None,
            total_size: total as i64,
            pattern_len: needle.len() as i64,
        });
    }
    let mut pos = request.from_offset.unwrap_or(0).max(0) as u64;
    while pos < total {
        let want = (CHUNK as u64).min(total - pos) as usize;
        let (_obj, bytes) = store.read_range(&request.object_ref, pos, want)?;
        if bytes.is_empty() {
            break;
        }
        if let Some(rel) = find_subslice(&bytes, &needle) {
            return Ok(EvidenceFindResult {
                offset: Some((pos + rel as u64) as i64),
                total_size: total as i64,
                pattern_len: needle.len() as i64,
            });
        }
        let step = bytes
            .len()
            .saturating_sub(needle.len().saturating_sub(1))
            .max(1);
        pos = pos.saturating_add(step as u64);
    }
    Ok(EvidenceFindResult {
        offset: None,
        total_size: total as i64,
        pattern_len: needle.len() as i64,
    })
}

fn parse_hex_pattern(pattern: &str) -> Result<Vec<u8>> {
    let cleaned: String = pattern.chars().filter(|ch| !ch.is_whitespace()).collect();
    let cleaned = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(cleaned.as_str());
    if cleaned.is_empty() || cleaned.len() % 2 != 0 || !cleaned.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ApiError::InvalidRequest(format!(
            "HEXパターンが不正です: '{pattern}' (空白区切り可・偶数桁の16進数で指定)"
        )));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|error| ApiError::InvalidRequest(format!("HEXパース失敗: {error}")))
        })
        .collect()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn verify_evidence_page(
    request: EvidenceVerificationRequest,
) -> Result<Page<EvidenceVerification>> {
    let workspace = CaseWorkspace::open(&request.case_root)?;
    let limit = request.limit.unwrap_or(25).clamp(1, 50);
    let files = workspace.query_layer().file_page(FilePageQuery {
        limit: Some(limit),
        cursor: request.cursor,
    })?;
    let checked_at = now_utc();
    let rows = files
        .rows
        .iter()
        .map(|file| verify_file_record(&workspace, file, &checked_at))
        .collect::<Vec<_>>();
    save_latest_evidence_verification(&workspace, &rows)?;
    let verified_count = rows.iter().filter(|row| row.verified).count();
    append_audit_log(
        &workspace,
        "evidence_verified",
        "evidence_page",
        None,
        &format!(
            "evidence verification completed: {}/{} verified",
            verified_count,
            rows.len()
        ),
        serde_json::json!({
            "limit": limit,
            "cursor": files.next_cursor,
            "verified_count": verified_count,
            "checked_count": rows.len(),
        }),
    )?;
    Ok(Page {
        rows,
        next_cursor: files.next_cursor,
    })
}

pub fn export_events(
    case_root: &str,
    page: EventPageQuery,
    format: &str,
    output_path: Option<String>,
    max_rows: Option<usize>,
) -> Result<EventExportResult> {
    let workspace = CaseWorkspace::open(case_root)?;
    let format = match format {
        "jsonl" => "jsonl",
        _ => "csv",
    };
    let path = output_path
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let stamp = now_utc()
                .replace(':', "-")
                .replace('.', "-")
                .replace('+', "Z");
            workspace
                .root()
                .join("exports")
                .join(format!("events_{stamp}.{format}"))
        });
    workspace
        .query_layer()
        .export_event_rows(page, &path, format, max_rows)
        .map_err(ApiError::from)
}

pub fn get_recent_jobs(case_root: &str, limit: Option<usize>) -> Result<Vec<JobRecord>> {
    let workspace = CaseWorkspace::open(case_root)?;
    let queue = JobQueue::open(workspace.jobs_db_path())?;
    queue.recent(limit.unwrap_or(100)).map_err(ApiError::from)
}

fn query(case_root: &str) -> Result<DuckDbQueryLayer> {
    Ok(CaseWorkspace::open(case_root)?.query_layer())
}

fn file_record(
    workspace: &CaseWorkspace,
    file_id: &str,
    original_path: &str,
    artifact_type: &str,
    parser_status: ParserStatus,
    event_count: i64,
    object: &taotie_storage::StoredObject,
) -> FileRecord {
    let path = Path::new(original_path);
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(original_path)
        .to_string();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    FileRecord {
        file_id: file_id.to_string(),
        case_id: workspace.manifest().case_id.clone(),
        parent_file_id: None,
        original_path: original_path.to_string(),
        normalized_path: original_path.replace('\\', "/"),
        filename,
        extension,
        size: object.size,
        sha256: object.sha256.clone(),
        artifact_type: artifact_type.to_string(),
        parser_status,
        event_count,
        object_ref: object.object_ref.clone(),
    }
}

fn coverage_for_file(file: &FileRecord) -> CoverageSummary {
    CoverageSummary {
        case_id: file.case_id.clone(),
        artifact_type: file.artifact_type.clone(),
        total_files: 1,
        parsed_files: i64::from(file.parser_status == ParserStatus::Parsed),
        failed_files: i64::from(file.parser_status == ParserStatus::Failed),
        unsupported_files: i64::from(file.parser_status == ParserStatus::Unsupported),
        event_count: file.event_count,
    }
}

fn derive_artifact_objects(events: &[EventFull]) -> Vec<ArtifactObject> {
    events
        .iter()
        .filter(|event| should_derive_artifact_objects(event))
        .flat_map(derive_artifact_objects_from_event)
        .collect()
}

fn derive_evidence_offsets(events: &[EventFull]) -> Vec<EvidenceOffset> {
    events
        .iter()
        .flat_map(derive_evidence_offsets_from_event)
        .collect()
}

fn is_browser_profile_path(lower: &str) -> bool {
    lower.contains("/google/chrome/user data/")
        || lower.contains("\\google\\chrome\\user data\\")
        || lower.contains("/microsoft/edge/user data/")
        || lower.contains("\\microsoft\\edge\\user data\\")
        || lower.contains("/microsoftedge/user/")
        || lower.contains("\\microsoftedge\\user\\")
        || lower.contains("/mozilla/firefox/profiles/")
        || lower.contains("\\mozilla\\firefox\\profiles\\")
}

fn is_browser_profile_artifact(lower: &str) -> bool {
    let name = Path::new(lower)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(lower);
    matches!(
        name,
        "history"
            | "history-journal"
            | "cookies"
            | "cookies-journal"
            | "login data"
            | "login data-journal"
            | "web data"
            | "web data-journal"
            | "top sites"
            | "shortcuts"
            | "favicons"
            | "visited links"
            | "network action predictor"
            | "bookmarks"
            | "preferences"
            | "secure preferences"
            | "local state"
            | "downloadmetadata"
    ) || lower.contains("sessions/tabs_")
        || lower.contains("\\sessions\\tabs_")
        || lower.contains("sessions/session_")
        || lower.contains("\\sessions\\session_")
        || lower.contains("sync data/leveldb/")
        || lower.contains("\\sync data\\leveldb\\")
        || lower.contains("collections/collectionssqlite")
        || lower.contains("\\collections\\collectionssqlite")
}

fn detect_artifact_type(original_path: &str) -> String {
    let extension = Path::new(original_path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let lower = original_path.to_ascii_lowercase();
    if is_windows_search_log_path(&lower) {
        return "windows_search_log".to_string();
    }
    if lower.contains("/windows/system32/tasks/") || lower.contains("\\windows\\system32\\tasks\\")
    {
        return "scheduled_task".to_string();
    }
    if lower.ends_with(".lnk") {
        return "lnk".to_string();
    }
    if lower.ends_with(".automaticdestinations-ms") || lower.ends_with(".customdestinations-ms") {
        return "jump_list".to_string();
    }
    if lower.contains("mplog") || lower.contains("mpwpptracing") {
        return "defender_mplog".to_string();
    }
    if lower.contains("mpoperational")
        || lower.contains("windows defender")
        || lower.contains("defender")
    {
        return "defender_operational".to_string();
    }
    if lower.contains("/onedrive/logs/")
        || lower.contains("\\onedrive\\logs\\")
        || lower.contains("/onedrive/settings/")
        || lower.contains("\\onedrive\\settings\\")
        || (lower.contains("/onedrive/") || lower.contains("\\onedrive\\"))
        || lower.ends_with(".odl")
        || lower.ends_with(".aodl")
        || lower.ends_with(".odlgz")
        || lower.ends_with(".odlsent")
        || lower.ends_with(".loggz")
    {
        return "onedrive_log".to_string();
    }
    if lower.contains("/filezilla/")
        || lower.contains("\\filezilla\\")
        || lower.ends_with("recentservers.xml")
        || lower.ends_with("filezilla.xml")
        || lower.ends_with("sitemanager.xml")
        || lower.ends_with("queue.sqlite3")
    {
        return "filezilla".to_string();
    }
    if is_browser_profile_artifact(&lower)
        && (is_browser_profile_path(&lower)
            || !lower.contains('/')
            || lower.contains("sessions/")
            || lower.contains("sync data/")
            || lower.contains("collections/"))
    {
        return "browser".to_string();
    }
    if lower.ends_with("/login data")
        || lower.ends_with("\\login data")
        || lower.ends_with(".kdbx")
        || lower.contains("/microsoft/protect/")
        || lower.contains("\\microsoft\\protect\\")
    {
        return "credential_store".to_string();
    }
    if lower.ends_with(".pcap") || lower.ends_with(".pcapng") {
        return "network_capture".to_string();
    }
    if matches!(extension.as_str(), "zip" | "rar" | "7z" | "iso") {
        return "archive".to_string();
    }
    if matches!(
        extension.as_str(),
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "rtf"
    ) {
        return "document".to_string();
    }
    if lower.contains("$mft") || lower.ends_with("/mft") || lower.ends_with("\\mft") {
        return "mft".to_string();
    }
    if lower.contains("/$logfile") || lower.contains("\\$logfile") {
        return "ntfs_logfile".to_string();
    }
    if lower.contains("/$boot") || lower.contains("\\$boot") {
        return "ntfs_boot".to_string();
    }
    if lower.contains("/$secure") || lower.contains("\\$secure") {
        return "ntfs_secure".to_string();
    }
    if lower.ends_with(".pf") || lower.contains("prefetch") || lower.contains("pecmd") {
        return "prefetch".to_string();
    }
    if lower.contains("amcache") {
        return "amcache".to_string();
    }
    if lower.ends_with("ntuser.dat")
        || lower.ends_with("usrclass.dat")
        || lower.ends_with(".hve")
        || lower.ends_with("/sam")
        || lower.ends_with("/system")
        || lower.ends_with("/software")
        || lower.ends_with("/security")
    {
        return "registry_hive".to_string();
    }
    if lower.ends_with(".dat.log1")
        || lower.ends_with(".dat.log2")
        || lower.ends_with(".log1")
        || lower.ends_with(".log2")
    {
        return "registry_log".to_string();
    }
    if lower.contains("usnjrnl") || lower.contains("$j") || lower.contains("usn") {
        return "usn_jrnl".to_string();
    }
    if lower.contains("/sru/")
        || lower.contains("\\sru\\")
        || lower.contains("srudb.dat")
        || (lower.starts_with("sru") && lower.ends_with(".log"))
    {
        return "srum".to_string();
    }
    if lower.contains("/windows/webcache/")
        || lower.contains("\\windows\\webcache\\")
        || lower.contains("webcachev01.dat")
        || lower.contains("/inetcookies/")
        || lower.contains("\\inetcookies\\")
        || lower.contains("/cryptneturlcache/")
        || lower.contains("\\cryptneturlcache\\")
        || lower.contains("/microsoftedge/cache/")
        || lower.contains("\\microsoftedge\\cache\\")
        || lower.contains("/microsoftedge/cookies/")
        || lower.contains("\\microsoftedge\\cookies\\")
        || lower.contains("/microsoftedge/user/default/domstore/")
        || lower.contains("\\microsoftedge\\user\\default\\domstore\\")
        || lower.contains("/internet explorer/cachestorage/")
        || lower.contains("\\internet explorer\\cachestorage\\")
    {
        return "web_cache".to_string();
    }
    if lower.contains("thumbcache") {
        return "thumbcache".to_string();
    }
    if lower.contains("browser")
        || lower.contains("places.sqlite")
        || lower.contains("cookies.sqlite")
        || lower.contains("firefox")
        || lower.contains("microsoftedge")
        || (lower.contains("history") && lower.ends_with(".csv"))
    {
        return "browser".to_string();
    }
    if lower.ends_with(".edb") || lower.ends_with(".jrs") || lower.ends_with(".chk") {
        return "ese".to_string();
    }
    if lower.ends_with(".etl") {
        return "etl".to_string();
    }
    if lower.ends_with(".sqlite")
        || lower.ends_with(".sqlite-wal")
        || lower.ends_with(".sqlite-shm")
        || lower.ends_with(".db")
        || lower.ends_with(".db-wal")
        || lower.ends_with(".db-shm")
        || lower.ends_with(".otc")
        || lower.ends_with(".otc-wal")
        || lower.ends_with(".otc-shm")
    {
        return "sqlite".to_string();
    }
    match extension.as_str() {
        "evtx" => "evtx".to_string(),
        "xml" => "xml".to_string(),
        "mft" => "mft".to_string(),
        "csv" => "csv".to_string(),
        "json" => "json".to_string(),
        "jsonl" => "jsonl".to_string(),
        "jsonlz4" => "browser".to_string(),
        "txt" | "log" | "fake" => "text_log".to_string(),
        "htm" | "html" => "html".to_string(),
        "js" | "map" => "script".to_string(),
        "css" => "stylesheet".to_string(),
        "ini" | "cfg" | "config" => "config".to_string(),
        "jpg" | "jpeg" | "png" | "gif" | "ico" => "image".to_string(),
        "woff" => "font".to_string(),
        "bin" | "data" | "btr" | "appcache" | "keystore" => "binary".to_string(),
        "" => "binary".to_string(),
        other => other.to_string(),
    }
}

fn detect_artifact_type_from_bytes(original_path: &str, bytes: &[u8]) -> String {
    let by_path = detect_artifact_type(original_path);
    let lower = original_path.to_ascii_lowercase();
    if matches!(
        by_path.as_str(),
        "scheduled_task"
            | "filezilla"
            | "credential_store"
            | "document"
            | "network_capture"
            | "archive"
            | "windows_search_log"
    ) {
        return by_path;
    }
    if by_path == "mft" || bytes.starts_with(b"FILE") {
        return "mft".to_string();
    }
    if by_path == "evtx" || bytes.starts_with(b"ElfFile") {
        return "evtx".to_string();
    }
    if bytes.starts_with(b"SCCA") {
        return "prefetch".to_string();
    }
    if bytes.starts_with(b"SQLite format 3\0") {
        if matches!(
            by_path.as_str(),
            "thumbcache"
                | "srum"
                | "web_cache"
                | "webcache"
                | "onedrive_log"
                | "filezilla"
                | "browser"
        ) {
            return by_path;
        }
        return if lower.contains("firefox")
            || lower.contains("places.sqlite")
            || lower.contains("cookies.sqlite")
            || lower.contains("browser")
            || is_browser_profile_path(&lower)
        {
            "browser".to_string()
        } else {
            "sqlite".to_string()
        };
    }
    if bytes.starts_with(b"regf") && lower.contains("amcache") {
        return "amcache".to_string();
    }
    if bytes.starts_with(b"regf") {
        return "registry_hive".to_string();
    }
    if bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0]) && lower.ends_with(".lnk") {
        return "lnk".to_string();
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return if lower.contains("onedrive") {
            "onedrive_log".to_string()
        } else {
            "gzip".to_string()
        };
    }
    if bytes.starts_with(b"\x0a\x0d\x0d\x0a")
        || bytes.starts_with(&[0xd4, 0xc3, 0xb2, 0xa1])
        || bytes.starts_with(&[0xa1, 0xb2, 0xc3, 0xd4])
        || bytes.starts_with(&[0x4d, 0x3c, 0xb2, 0xa1])
        || bytes.starts_with(&[0xa1, 0xb2, 0x3c, 0x4d])
    {
        return "network_capture".to_string();
    }
    if bytes.starts_with(b"Rar!")
        || bytes.starts_with(b"7z\xbc\xaf\x27\x1c")
        || (bytes.starts_with(b"PK\x03\x04") && by_path == "archive")
    {
        return "archive".to_string();
    }
    if bytes.starts_with(b"%PDF")
        || (bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0]) && by_path == "document")
        || (bytes.starts_with(b"PK\x03\x04") && by_path == "document")
    {
        return "document".to_string();
    }
    let sample = std::str::from_utf8(&bytes[..bytes.len().min(4096)]).unwrap_or("");
    let compact = sample
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if compact.contains("filezilla3") || compact.contains("recentservers") {
        return "filezilla".to_string();
    }
    if compact.contains("login data") || compact.contains("dpapi") || compact.contains("keepass") {
        return "credential_store".to_string();
    }
    if compact.contains("microsoftwindowswindowsdefender")
        || compact.contains("windowsdefenderantivirus")
        || compact.contains("microsoftdefenderantivirus")
        || compact.contains("mpoperationalevents")
        || compact.contains("threatname")
    {
        return "defender_operational".to_string();
    }
    if lower.contains("mplog") || compact.contains("msmpeng") || compact.contains("mpcmdrun") {
        return "defender_mplog".to_string();
    }
    if lower.contains("mft")
        || (compact.contains("entrynumber") && compact.contains("sequence"))
        || (compact.contains("fullpath") && compact.contains("created0x10"))
    {
        return "mft".to_string();
    }
    if (compact.contains("executable") || compact.contains("sourcefilename"))
        && (compact.contains("runcount")
            || compact.contains("lastrun")
            || compact.contains("previousrun"))
    {
        return "prefetch".to_string();
    }
    if (compact.contains("sha1") || compact.contains("sha256"))
        && (compact.contains("programname")
            || compact.contains("filepath")
            || compact.contains("fullpath")
            || compact.contains("path"))
    {
        return "amcache".to_string();
    }
    if compact.contains("usn")
        && compact.contains("reason")
        && (compact.contains("filename") || compact.contains("filereference"))
    {
        return "usn_jrnl".to_string();
    }
    if compact.contains("url")
        && (compact.contains("visit") || compact.contains("lastvisit") || compact.contains("title"))
    {
        return "browser".to_string();
    }
    if (compact.contains("taskversion")
        || compact.contains("registrationinfo")
        || compact.contains("triggers"))
        && (compact.contains("actions") || compact.contains("exec"))
        && (compact.contains("command") || compact.contains("uri"))
    {
        return "scheduled_task".to_string();
    }
    if compact.contains("eventid")
        || compact.contains("timecreated")
        || sample.contains("<Event ")
        || sample.contains("<Event>")
    {
        return "evtx".to_string();
    }
    by_path
}

fn is_windows_search_log_path(lower_path: &str) -> bool {
    let extension = Path::new(lower_path)
        .extension()
        .and_then(|value| value.to_str());
    if matches!(extension, Some("gthr" | "crwl")) {
        return true;
    }
    let in_search_tree = lower_path.contains("/programdata/microsoft/search/")
        || lower_path.contains("\\programdata\\microsoft\\search\\")
        || lower_path.contains("/microsoft/search/data/applications/windows/")
        || lower_path.contains("\\microsoft\\search\\data\\applications\\windows\\");
    in_search_tree
        && (lower_path.contains("/gatherlogs/")
            || lower_path.contains("\\gatherlogs\\")
            || matches!(extension, Some("jtx" | "jcp" | "jfm" | "log" | "txt")))
}

struct EntityBuild {
    entity_type: String,
    canonical_value: String,
    display_name: String,
    host: Option<String>,
    first_seen_utc: Option<String>,
    last_seen_utc: Option<String>,
    event_ids: HashSet<String>,
}

struct EdgeBuild {
    src_entity_id: String,
    dst_entity_id: String,
    edge_type: String,
    first_seen_utc: Option<String>,
    last_seen_utc: Option<String>,
    evidence_event_ids: Vec<String>,
}

const EDGE_EVIDENCE_CAP: usize = 50;

fn derive_entities_edges(
    case_id: &str,
    events: &[EventFull],
) -> Result<(Vec<EntityRecord>, Vec<EdgeRecord>)> {
    let mut entity_order = Vec::new();
    let mut entities: HashMap<String, EntityBuild> = HashMap::new();
    let mut edge_order = Vec::new();
    let mut edges: HashMap<String, EdgeBuild> = HashMap::new();
    let mut high_cardinality_file_gate_cache: Option<(String, bool)> = None;

    for event in events {
        let host = event.host.as_deref();
        let t = Some(event.event_time_utc.as_str());
        if high_cardinality_artifact(&event.artifact_type) {
            let id_host = event.host.as_deref().and_then(|value| {
                upsert_entity(
                    "host",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
            let id_user = event.user_name.as_deref().and_then(|value| {
                upsert_entity(
                    "user",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
            let id_file = event.file_path.as_deref().and_then(|value| {
                if should_extract_high_cardinality_file_entity_cached(
                    event,
                    value,
                    &mut high_cardinality_file_gate_cache,
                ) {
                    upsert_entity(
                        "file",
                        value,
                        host,
                        t,
                        &event.event_id,
                        &mut entity_order,
                        &mut entities,
                    )
                } else {
                    None
                }
            });
            if let (Some(user), Some(host)) = (&id_user, &id_host) {
                upsert_edge(
                    "user_logged_on_host",
                    user,
                    host,
                    t,
                    &event.event_id,
                    &mut edge_order,
                    &mut edges,
                );
            }
            if let (Some(file), Some(host)) = (&id_file, &id_host) {
                upsert_edge(
                    "file_observed_on_host",
                    file,
                    host,
                    t,
                    &event.event_id,
                    &mut edge_order,
                    &mut edges,
                );
            }
            continue;
        }

        let attributes = serde_json::from_str::<serde_json::Value>(&event.attributes_json).ok();
        let id_host = event.host.as_deref().and_then(|value| {
            upsert_entity(
                "host",
                value,
                host,
                t,
                &event.event_id,
                &mut entity_order,
                &mut entities,
            )
        });
        let id_user = event.user_name.as_deref().and_then(|value| {
            upsert_entity(
                "user",
                value,
                host,
                t,
                &event.event_id,
                &mut entity_order,
                &mut entities,
            )
        });
        let id_process = event.process_name.as_deref().and_then(|value| {
            upsert_entity(
                "process",
                value,
                host,
                t,
                &event.event_id,
                &mut entity_order,
                &mut entities,
            )
        });
        let id_file = event
            .file_path
            .as_deref()
            .filter(|value| should_extract_file_entity(event, value, attributes.as_ref()))
            .and_then(|value| {
                upsert_entity(
                    "file",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
        let id_ip = event.ip.as_deref().and_then(|value| {
            upsert_entity(
                "ip",
                value,
                host,
                t,
                &event.event_id,
                &mut entity_order,
                &mut entities,
            )
        });
        let id_url = event.url.as_deref().and_then(|value| {
            upsert_entity(
                "url",
                value,
                host,
                t,
                &event.event_id,
                &mut entity_order,
                &mut entities,
            )
        });
        let id_hash = event.hash.as_deref().and_then(|value| {
            upsert_entity(
                "hash",
                value,
                host,
                t,
                &event.event_id,
                &mut entity_order,
                &mut entities,
            )
        });
        let id_command_line = attributes
            .as_ref()
            .and_then(|attributes| {
                event_attr_string_from_value(
                    attributes,
                    &[
                        "command_line",
                        "CommandLine",
                        "ProcessCommandLine",
                        "process_command_line",
                    ],
                )
            })
            .as_deref()
            .and_then(|value| {
                upsert_entity(
                    "command_line",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
        let id_parent_process = attributes
            .as_ref()
            .and_then(|attributes| {
                event_attr_string_from_value(
                    attributes,
                    &[
                        "parent_process",
                        "ParentImage",
                        "ParentProcessName",
                        "ParentCommandLine",
                    ],
                )
            })
            .as_deref()
            .and_then(parent_process_entity_value)
            .as_deref()
            .and_then(|value| {
                upsert_entity(
                    "process",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
        let id_logon_session = attributes
            .as_ref()
            .and_then(|attributes| {
                event_attr_string_from_value(
                    attributes,
                    &["logon_id", "LogonId", "TargetLogonId", "SubjectLogonId"],
                )
            })
            .as_deref()
            .and_then(|value| logon_session_entity_value(host, value))
            .as_deref()
            .and_then(|value| {
                upsert_entity(
                    "logon_session",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
        let id_service = attributes
            .as_ref()
            .and_then(|attributes| {
                event_attr_string_from_value(attributes, &["service_name", "ServiceName"])
            })
            .as_deref()
            .and_then(|value| {
                upsert_entity(
                    "service",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
        let id_task = attributes
            .as_ref()
            .and_then(|attributes| {
                event_attr_string_from_value(attributes, &["task_name", "TaskName", "TaskContent"])
            })
            .as_deref()
            .and_then(task_entity_value)
            .as_deref()
            .and_then(|value| {
                upsert_entity(
                    "scheduled_task",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
        let id_threat = attributes
            .as_ref()
            .and_then(|attributes| {
                event_attr_string_from_value(
                    attributes,
                    &[
                        "threat_name",
                        "ThreatName",
                        "defender_threat",
                        "Threat Name",
                    ],
                )
            })
            .as_deref()
            .and_then(|value| {
                upsert_entity(
                    "threat",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });
        let id_registry_key = attributes
            .as_ref()
            .and_then(|attributes| {
                event_attr_string_from_value(
                    attributes,
                    &["key_hint", "TargetObject", "ObjectName", "registry_key"],
                )
            })
            .as_deref()
            .filter(|value| event.event_action.starts_with("registry_") || value.contains('\\'))
            .and_then(|value| {
                upsert_entity(
                    "registry_key",
                    value,
                    host,
                    t,
                    &event.event_id,
                    &mut entity_order,
                    &mut entities,
                )
            });

        if let (Some(user), Some(host)) = (&id_user, &id_host) {
            upsert_edge(
                "user_logged_on_host",
                user,
                host,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(user), Some(session)) = (&id_user, &id_logon_session) {
            upsert_edge(
                "user_has_logon_session",
                user,
                session,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(session), Some(host)) = (&id_logon_session, &id_host) {
            upsert_edge(
                "logon_session_on_host",
                session,
                host,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(process), Some(file)) = (&id_process, &id_file) {
            upsert_edge(
                "process_touched_file",
                process,
                file,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(parent), Some(process)) = (&id_parent_process, &id_process) {
            upsert_edge(
                "process_spawned_process",
                parent,
                process,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(process), Some(command_line)) = (&id_process, &id_command_line) {
            upsert_edge(
                "process_has_command_line",
                process,
                command_line,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(process), Some(session)) = (&id_process, &id_logon_session) {
            upsert_edge(
                "process_in_logon_session",
                process,
                session,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(process), Some(ip)) = (&id_process, &id_ip) {
            upsert_edge(
                "process_connected_ip",
                process,
                ip,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(service), Some(file)) = (&id_service, &id_file) {
            upsert_edge(
                "service_runs_file",
                service,
                file,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(task), Some(file)) = (&id_task, &id_file) {
            upsert_edge(
                "scheduled_task_runs_file",
                task,
                file,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(threat), Some(file)) = (&id_threat, &id_file) {
            upsert_edge(
                "threat_affects_file",
                threat,
                file,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(registry_key), Some(file)) = (&id_registry_key, &id_file) {
            upsert_edge(
                "registry_key_references_file",
                registry_key,
                file,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(file), Some(hash)) = (&id_file, &id_hash) {
            upsert_edge(
                "file_has_hash",
                file,
                hash,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(process), Some(url)) = (&id_process, &id_url) {
            upsert_edge(
                "event_mentions_entity",
                process,
                url,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
        if let (Some(file), Some(url)) = (&id_file, &id_url) {
            upsert_edge(
                "file_linked_to_url",
                file,
                url,
                t,
                &event.event_id,
                &mut edge_order,
                &mut edges,
            );
        }
    }

    let entity_rows = entity_order
        .into_iter()
        .filter_map(|entity_id| {
            entities.remove(&entity_id).map(|build| EntityRecord {
                entity_id,
                case_id: case_id.to_string(),
                entity_type: build.entity_type,
                canonical_value: build.canonical_value,
                display_name: build.display_name,
                host: build.host,
                first_seen_utc: build.first_seen_utc,
                last_seen_utc: build.last_seen_utc,
                event_count: build.event_ids.len() as i64,
                attributes_json: serde_json::json!({}).to_string(),
            })
        })
        .collect();

    let edge_rows = edge_order
        .into_iter()
        .filter_map(|edge_id| {
            edges.remove(&edge_id).map(|build| EdgeRecord {
                edge_id,
                case_id: case_id.to_string(),
                src_entity_id: build.src_entity_id,
                dst_entity_id: build.dst_entity_id,
                edge_type: build.edge_type,
                first_seen_utc: build.first_seen_utc,
                last_seen_utc: build.last_seen_utc,
                confidence: 0.5,
                evidence_event_ids_json: serde_json::json!(build.evidence_event_ids).to_string(),
                attributes_json: serde_json::json!({}).to_string(),
            })
        })
        .collect();

    Ok((entity_rows, edge_rows))
}

fn parent_process_entity_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return None;
    }
    file_name_from_path_like(trimmed).or_else(|| {
        trimmed
            .split_whitespace()
            .find(|part| process_like(part))
            .and_then(file_name_from_path_like)
    })
}

fn task_entity_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return None;
    }
    let task = trimmed
        .lines()
        .next()
        .unwrap_or(trimmed)
        .split('<')
        .next()
        .unwrap_or(trimmed)
        .trim();
    if task.is_empty() {
        None
    } else {
        Some(truncate_for_entity(task, 180))
    }
}

fn logon_session_entity_value(host: Option<&str>, value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" || trimmed == "0x0" {
        return None;
    }
    Some(match host {
        Some(host) if !host.trim().is_empty() => format!("{}:{}", host.trim(), trimmed),
        _ => trimmed.to_string(),
    })
}

fn file_name_from_path_like(value: &str) -> Option<String> {
    let trimmed = value.trim_matches(|ch: char| {
        ch == '"' || ch == '\'' || ch == ',' || ch == ';' || ch == ')' || ch == ']'
    });
    trimmed
        .rsplit(|ch| ch == '\\' || ch == '/')
        .next()
        .filter(|name| process_like(name))
        .map(|name| name.to_string())
}

fn process_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    process_like_lower(&lower)
}

fn process_like_lower(lower: &str) -> bool {
    lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".ps1")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".vbs")
        || lower.ends_with(".js")
        || lower.ends_with(".scr")
        || lower.ends_with(".sys")
}

fn high_cardinality_artifact(artifact_type: &str) -> bool {
    matches!(artifact_type, "mft" | "usn_jrnl")
}

fn should_derive_artifact_objects(event: &EventFull) -> bool {
    if !high_cardinality_artifact(&event.artifact_type) {
        return true;
    }
    let action = event.event_action.as_str();
    matches!(
        action,
        "mft_ads_resident_content_observed"
            | "mft_resident_data_observed"
            | "mft_filename_deleted"
            | "mft_data_run_observed"
            | "usn_deleted"
            | "usn_created"
            | "usn_renamed"
    ) || event.severity.eq_ignore_ascii_case("high")
        || event.severity.eq_ignore_ascii_case("critical")
}

fn should_extract_high_cardinality_file_entity_cached(
    event: &EventFull,
    value: &str,
    cache: &mut Option<(String, bool)>,
) -> bool {
    if let Some((cached_value, cached_result)) = cache {
        if cached_value == value {
            return *cached_result;
        }
    }
    let result = should_extract_high_cardinality_file_entity(event, value);
    *cache = Some((value.to_string(), result));
    result
}

fn should_extract_high_cardinality_file_entity(event: &EventFull, value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return false;
    }
    if matches!(event.severity.as_str(), "critical" | "high") {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    process_like_lower(&lower) || high_signal_file_path_lower(&lower)
}

fn should_extract_file_entity(
    event: &EventFull,
    value: &str,
    attributes: Option<&serde_json::Value>,
) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return false;
    }
    if !matches!(event.artifact_type.as_str(), "mft" | "usn_jrnl") {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if process_like_lower(&lower) || high_signal_file_path_lower(&lower) {
        return true;
    }
    if matches!(event.severity.as_str(), "critical" | "high") {
        return true;
    }
    let deleted = attributes
        .and_then(|value| event_attr_string_from_value(value, &["deleted"]))
        .is_some_and(|value| boolish(&value));
    let timestamp_mismatch = attributes
        .and_then(|value| event_attr_string_from_value(value, &["si_fn_timestamp_mismatch"]))
        .is_some_and(|value| boolish(&value));
    deleted || timestamp_mismatch
}

fn high_signal_file_path_lower(lower: &str) -> bool {
    lower.contains("\\appdata\\")
        || lower.contains("/appdata/")
        || lower.contains("\\temp\\")
        || lower.contains("/temp/")
        || lower.contains("\\tmp\\")
        || lower.contains("/tmp/")
        || lower.contains("\\startup\\")
        || lower.contains("/startup/")
        || lower.contains("\\downloads\\")
        || lower.contains("/downloads/")
        || lower.contains("\\programdata\\")
        || lower.contains("/programdata/")
        || lower.contains("\\windows\\tasks\\")
        || lower.contains("/windows/tasks/")
        || lower.contains("\\system32\\tasks\\")
        || lower.contains("/system32/tasks/")
        || lower.contains("\\powershell\\")
        || lower.contains("/powershell/")
        || lower.contains("\\wmi\\")
        || lower.contains("/wmi/")
}

fn boolish(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "y"
    )
}

fn truncate_for_entity(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

fn upsert_entity(
    entity_type: &str,
    raw: &str,
    host: Option<&str>,
    t: Option<&str>,
    event_id: &str,
    entity_order: &mut Vec<String>,
    entities: &mut HashMap<String, EntityBuild>,
) -> Option<String> {
    let canonical = raw.trim().to_ascii_lowercase();
    if canonical.is_empty() || canonical == "-" {
        return None;
    }
    let entity_id = format!("ent_{}", sha256_16(&format!("{entity_type}|{canonical}")));
    let entry = entities.entry(entity_id.clone()).or_insert_with(|| {
        entity_order.push(entity_id.clone());
        EntityBuild {
            entity_type: entity_type.to_string(),
            canonical_value: canonical.clone(),
            display_name: raw.trim().to_string(),
            host: host.map(str::to_string),
            first_seen_utc: None,
            last_seen_utc: None,
            event_ids: HashSet::new(),
        }
    });
    if entry.host.is_none() {
        entry.host = host.map(str::to_string);
    }
    fold_seen(&mut entry.first_seen_utc, &mut entry.last_seen_utc, t);
    entry.event_ids.insert(event_id.to_string());
    Some(entity_id)
}

fn upsert_edge(
    edge_type: &str,
    src: &str,
    dst: &str,
    t: Option<&str>,
    event_id: &str,
    edge_order: &mut Vec<String>,
    edges: &mut HashMap<String, EdgeBuild>,
) {
    let edge_id = format!("edge_{}", sha256_16(&format!("{src}|{dst}|{edge_type}")));
    let entry = edges.entry(edge_id.clone()).or_insert_with(|| {
        edge_order.push(edge_id.clone());
        EdgeBuild {
            src_entity_id: src.to_string(),
            dst_entity_id: dst.to_string(),
            edge_type: edge_type.to_string(),
            first_seen_utc: None,
            last_seen_utc: None,
            evidence_event_ids: Vec::new(),
        }
    });
    fold_seen(&mut entry.first_seen_utc, &mut entry.last_seen_utc, t);
    if !event_id.is_empty()
        && entry.evidence_event_ids.len() < EDGE_EVIDENCE_CAP
        && !entry.evidence_event_ids.iter().any(|id| id == event_id)
    {
        entry.evidence_event_ids.push(event_id.to_string());
    }
}

fn fold_seen(first: &mut Option<String>, last: &mut Option<String>, t: Option<&str>) {
    let Some(t) = t.filter(|value| !value.is_empty()) else {
        return;
    };
    if first.as_deref().map_or(true, |current| t < current) {
        *first = Some(t.to_string());
    }
    if last.as_deref().map_or(true, |current| t > current) {
        *last = Some(t.to_string());
    }
}

fn sha256_16(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

const PER_RULE_CAP: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindingRebuildResult {
    input_event_count: usize,
    heuristic_count: usize,
    chain_count: usize,
    hayabusa_count: usize,
    ioc_count: usize,
    final_count: usize,
    override_count: usize,
    event_row_count: usize,
}

struct HeuristicRule {
    id: &'static str,
    engine: &'static str,
    title: &'static str,
    severity: &'static str,
    attack: &'static [&'static str],
    matcher: fn(&str) -> bool,
}

fn heuristic_rules() -> Vec<HeuristicRule> {
    vec![
        HeuristicRule {
            id: "lolbin-execution",
            engine: "heuristic",
            title: "LOLBin 実行の疑い (T1218 Signed Binary Proxy Execution)",
            severity: "high",
            attack: &["T1218"],
            matcher: match_lolbin,
        },
        HeuristicRule {
            id: "temp-execution",
            engine: "heuristic",
            title: "Temp/AppData からの実行 (T1036 Masquerading)",
            severity: "medium",
            attack: &["T1036"],
            matcher: match_temp_exec,
        },
        HeuristicRule {
            id: "credential-tooling",
            engine: "heuristic",
            title: "資格情報ダンプツールの痕跡 (T1003 OS Credential Dumping)",
            severity: "critical",
            attack: &["T1003"],
            matcher: match_cred_tooling,
        },
        HeuristicRule {
            id: "powershell-abuse",
            engine: "heuristic",
            title: "PowerShell 難読化/ダウンロードクレードル (T1059.001)",
            severity: "high",
            attack: &["T1059.001"],
            matcher: match_powershell_abuse,
        },
        HeuristicRule {
            id: "suspicious-download",
            engine: "heuristic",
            title: "実行ファイルのダウンロード URL (T1105 Ingress Tool Transfer)",
            severity: "medium",
            attack: &["T1105"],
            matcher: match_suspicious_download,
        },
        HeuristicRule {
            id: "filezilla-saved-credential",
            engine: "taotie-core-v4",
            title: "FileZilla 保存資格情報/接続先の復元候補",
            severity: "high",
            attack: &["T1552.001", "T1048"],
            matcher: match_filezilla_saved_credential,
        },
        HeuristicRule {
            id: "credential-store-recovery-required",
            engine: "taotie-core-v4",
            title: "資格情報ストア復号/復元が必要な証跡",
            severity: "high",
            attack: &["T1555", "T1552"],
            matcher: match_credential_store_recovery_required,
        },
        HeuristicRule {
            id: "document-recovery-required",
            engine: "taotie-core-v4",
            title: "文書本文/メタデータ復元が必要な証跡",
            severity: "medium",
            attack: &["T1204"],
            matcher: match_document_recovery_required,
        },
        HeuristicRule {
            id: "network-capture-exfil-review",
            engine: "taotie-core-v4",
            title: "PCAP/PCAPNG の通信・流出解析が必要",
            severity: "medium",
            attack: &["T1041", "T1048"],
            matcher: match_network_capture_exfil_review,
        },
        HeuristicRule {
            id: "archive-exploit-recovery-candidate",
            engine: "taotie-core-v4",
            title: "アーカイブ復元/脆弱性悪用確認が必要な証跡",
            severity: "high",
            attack: &["T1203", "T1027"],
            matcher: match_archive_exploit_recovery_candidate,
        },
        HeuristicRule {
            id: "prefetch-admin-lolbin-execution",
            engine: "taotie-core",
            title: "Prefetch に残る管理系/スクリプト系バイナリ実行",
            severity: "medium",
            attack: &["T1059", "T1218"],
            matcher: match_prefetch_admin_lolbin_execution,
        },
        HeuristicRule {
            id: "remote-access-tool-execution",
            engine: "taotie-core-v2",
            title: "Remote Access Tool 実行/利用痕跡 (T1219)",
            severity: "high",
            attack: &["T1219"],
            matcher: match_remote_access_tool_execution,
        },
        HeuristicRule {
            id: "c2-agent-execution",
            engine: "taotie-core-v2",
            title: "C2/攻撃フレームワークの実行痕跡",
            severity: "high",
            attack: &["T1105", "T1059"],
            matcher: match_c2_agent_execution,
        },
        HeuristicRule {
            id: "wevtutil-log-tamper",
            engine: "taotie-core-v2",
            title: "wevtutil/PowerShell によるログ改変",
            severity: "high",
            attack: &["T1070.001"],
            matcher: match_wevtutil_log_tamper,
        },
        HeuristicRule {
            id: "rundll32-suspicious-invocation",
            engine: "taotie-core-v2",
            title: "rundll32 の不審な呼び出し",
            severity: "high",
            attack: &["T1218.011"],
            matcher: match_rundll32_suspicious_invocation,
        },
        HeuristicRule {
            id: "regsvr32-suspicious-invocation",
            engine: "taotie-core-v2",
            title: "regsvr32 の不審な呼び出し",
            severity: "high",
            attack: &["T1218.010"],
            matcher: match_regsvr32_suspicious_invocation,
        },
        HeuristicRule {
            id: "mshta-suspicious-invocation",
            engine: "taotie-core-v2",
            title: "mshta/HTA の不審な実行",
            severity: "high",
            attack: &["T1218.005"],
            matcher: match_mshta_suspicious_invocation,
        },
        HeuristicRule {
            id: "certutil-transfer",
            engine: "taotie-core-v2",
            title: "certutil による転送/デコード",
            severity: "medium",
            attack: &["T1105", "T1140"],
            matcher: match_certutil_transfer,
        },
        HeuristicRule {
            id: "bitsadmin-transfer",
            engine: "taotie-core-v2",
            title: "bitsadmin による転送/永続化",
            severity: "medium",
            attack: &["T1197", "T1105"],
            matcher: match_bitsadmin_transfer,
        },
        HeuristicRule {
            id: "jumplist-executable-recent-item",
            engine: "taotie-core-v2",
            title: "JumpList/LNK に残る実行ファイル操作",
            severity: "medium",
            attack: &["T1204"],
            matcher: match_jumplist_executable_recent_item,
        },
        HeuristicRule {
            id: "lnk-network-share-executable",
            engine: "taotie-core-v2",
            title: "ネットワーク共有上の実行ファイルを指すLNK",
            severity: "medium",
            attack: &["T1204", "T1105"],
            matcher: match_lnk_network_share_executable,
        },
        HeuristicRule {
            id: "recentdocs-risky-document",
            engine: "taotie-core-v2",
            title: "RecentDocs に残る危険拡張子/アーカイブ操作",
            severity: "medium",
            attack: &["T1204"],
            matcher: match_recentdocs_risky_document,
        },
        HeuristicRule {
            id: "script-file-execution-artifact",
            engine: "taotie-core-v2",
            title: "スクリプトファイルの実行/参照痕跡",
            severity: "medium",
            attack: &["T1059"],
            matcher: match_script_file_execution_artifact,
        },
        HeuristicRule {
            id: "updater-masquerade-execution",
            engine: "taotie-core-v2",
            title: "Updater/Update 名称の実行ファイル痕跡",
            severity: "medium",
            attack: &["T1036"],
            matcher: match_updater_masquerade_execution,
        },
        HeuristicRule {
            id: "event-log-cleared",
            engine: "taotie-core",
            title: "イベントログ消去 (T1070.001 Indicator Removal)",
            severity: "high",
            attack: &["T1070.001"],
            matcher: match_event_log_clear,
        },
        HeuristicRule {
            id: "comsvcs-minidump",
            engine: "taotie-core",
            title: "comsvcs.dll MiniDump による LSASS ダンプ",
            severity: "critical",
            attack: &["T1003.001"],
            matcher: match_comsvcs_minidump,
        },
        HeuristicRule {
            id: "registry-hive-dump",
            engine: "taotie-core",
            title: "レジストリハイブ退避 (SAM/SYSTEM/SECURITY)",
            severity: "high",
            attack: &["T1003.002"],
            matcher: match_registry_hive_dump,
        },
        HeuristicRule {
            id: "ntds-extraction",
            engine: "taotie-core",
            title: "NTDS.dit 抽出の痕跡",
            severity: "critical",
            attack: &["T1003.003"],
            matcher: match_ntds_extract,
        },
        HeuristicRule {
            id: "lsa-secrets",
            engine: "taotie-core",
            title: "LSA Secrets / キャッシュ資格情報取得",
            severity: "high",
            attack: &["T1003.004"],
            matcher: match_lsa_secrets,
        },
        HeuristicRule {
            id: "wdigest-enabled",
            engine: "taotie-core",
            title: "WDigest 平文資格情報の有効化",
            severity: "high",
            attack: &["T1112"],
            matcher: match_wdigest_enabled,
        },
        HeuristicRule {
            id: "psexec-service",
            engine: "taotie-core",
            title: "PsExec 系サービスのインストール",
            severity: "high",
            attack: &["T1569.002"],
            matcher: match_psexec_service,
        },
        HeuristicRule {
            id: "wmi-process-spawn",
            engine: "taotie-core",
            title: "WMI 経由のプロセス生成",
            severity: "high",
            attack: &["T1047"],
            matcher: match_wmi_process_spawn,
        },
        HeuristicRule {
            id: "remote-service-sc",
            engine: "taotie-core",
            title: "sc.exe によるリモートサービス操作",
            severity: "high",
            attack: &["T1021.002"],
            matcher: match_remote_service_sc,
        },
        HeuristicRule {
            id: "scheduled-task-payload",
            engine: "taotie-core",
            title: "スケジュールタスク作成による実行/永続化",
            severity: "high",
            attack: &["T1053.005"],
            matcher: match_scheduled_task_payload,
        },
        HeuristicRule {
            id: "defender-threat-detected",
            engine: "taotie-core",
            title: "Microsoft Defender による脅威検出/隔離",
            severity: "high",
            attack: &[],
            matcher: match_defender_threat_detected,
        },
        HeuristicRule {
            id: "remote-script-host",
            engine: "taotie-core",
            title: "mshta/regsvr32/rundll32 のリモートスクリプト実行",
            severity: "high",
            attack: &["T1218"],
            matcher: match_remote_script_host,
        },
        HeuristicRule {
            id: "wsh-script-execution",
            engine: "taotie-core",
            title: "WSH スクリプト実行 (wscript/cscript)",
            severity: "medium",
            attack: &["T1059.005"],
            matcher: match_wsh_script_execution,
        },
        HeuristicRule {
            id: "bloodhound-collection",
            engine: "taotie-core",
            title: "BloodHound/SharpHound による AD 列挙",
            severity: "high",
            attack: &["T1059.001"],
            matcher: match_bloodhound_collection,
        },
        HeuristicRule {
            id: "wmi-event-subscription",
            engine: "taotie-core",
            title: "WMI イベントサブスクリプションによる永続化",
            severity: "high",
            attack: &["T1546.003"],
            matcher: match_wmi_event_subscription,
        },
        HeuristicRule {
            id: "ifeo-accessibility-backdoor",
            engine: "taotie-core",
            title: "アクセシビリティ機能のバックドア化",
            severity: "critical",
            attack: &["T1546.008"],
            matcher: match_ifeo_accessibility_backdoor,
        },
        HeuristicRule {
            id: "winlogon-tamper",
            engine: "taotie-core",
            title: "Winlogon Shell/Userinit の改変",
            severity: "high",
            attack: &["T1547.004"],
            matcher: match_winlogon_tamper,
        },
        HeuristicRule {
            id: "run-key-persistence",
            engine: "taotie-core",
            title: "Run/RunOnce キーへの不審な永続化",
            severity: "high",
            attack: &["T1547.001"],
            matcher: match_run_key_persistence,
        },
        HeuristicRule {
            id: "admin-group-add",
            engine: "taotie-core",
            title: "特権グループへのメンバー追加",
            severity: "high",
            attack: &["T1098"],
            matcher: match_admin_group_add,
        },
        HeuristicRule {
            id: "bits-persistence",
            engine: "taotie-core",
            title: "BITS ジョブによる永続化/ダウンロード",
            severity: "medium",
            attack: &["T1197"],
            matcher: match_bits_persistence,
        },
        HeuristicRule {
            id: "suspicious-service-image",
            engine: "taotie-core",
            title: "不審な ImagePath の新規サービス",
            severity: "high",
            attack: &["T1543.003"],
            matcher: match_suspicious_service_image,
        },
        HeuristicRule {
            id: "amsi-bypass",
            engine: "taotie-core",
            title: "AMSI バイパスの兆候",
            severity: "high",
            attack: &["T1562.001"],
            matcher: match_amsi_bypass,
        },
        HeuristicRule {
            id: "etw-patch",
            engine: "taotie-core",
            title: "ETW パッチ/テレメトリ無効化の兆候",
            severity: "high",
            attack: &["T1562.006"],
            matcher: match_etw_patch,
        },
        HeuristicRule {
            id: "shadowcopy-delete",
            engine: "taotie-core",
            title: "シャドウコピー削除/回復無効化",
            severity: "critical",
            attack: &["T1490"],
            matcher: match_shadowcopy_delete,
        },
        HeuristicRule {
            id: "safeboot-tamper",
            engine: "taotie-core",
            title: "セーフブート改変",
            severity: "high",
            attack: &["T1562.009"],
            matcher: match_safeboot_tamper,
        },
        HeuristicRule {
            id: "firewall-disable",
            engine: "taotie-core",
            title: "Windows ファイアウォール無効化",
            severity: "high",
            attack: &["T1562.004"],
            matcher: match_firewall_disable,
        },
        HeuristicRule {
            id: "byovd-driver",
            engine: "taotie-core",
            title: "脆弱/未署名ドライバのロード",
            severity: "critical",
            attack: &["T1068"],
            matcher: match_byovd_driver,
        },
        HeuristicRule {
            id: "remote-thread-injection",
            engine: "taotie-core",
            title: "プロセスインジェクション (CreateRemoteThread)",
            severity: "high",
            attack: &["T1055"],
            matcher: match_remote_thread_injection,
        },
        HeuristicRule {
            id: "kerberoast-rc4",
            engine: "taotie-core",
            title: "Kerberoasting 兆候 (RC4 TGS 要求)",
            severity: "medium",
            attack: &["T1558.003"],
            matcher: match_kerberoast_rc4,
        },
        HeuristicRule {
            id: "dcsync-replication-rights",
            engine: "taotie-core",
            title: "DCSync 権限利用の兆候",
            severity: "critical",
            attack: &["T1003.006"],
            matcher: match_dcsync,
        },
        HeuristicRule {
            id: "lsass-high-priv-access",
            engine: "taotie-core",
            title: "LSASS への高権限アクセス",
            severity: "critical",
            attack: &["T1003.001"],
            matcher: match_lsass_high_priv_access,
        },
        HeuristicRule {
            id: "dcom-lateral-exec",
            engine: "taotie-core",
            title: "DCOM 経由のリモート実行",
            severity: "high",
            attack: &["T1021.003"],
            matcher: match_dcom_lateral_exec,
        },
        HeuristicRule {
            id: "domain-trust-discovery",
            engine: "taotie-core",
            title: "ドメイン信頼関係の列挙",
            severity: "medium",
            attack: &["T1482"],
            matcher: match_domain_trust_discovery,
        },
        HeuristicRule {
            id: "pkinit-logon",
            engine: "taotie-core",
            title: "証明書ベース Kerberos 認証 (PKINIT)",
            severity: "high",
            attack: &["T1649"],
            matcher: match_pkinit_logon,
        },
        HeuristicRule {
            id: "asrep-roast",
            engine: "taotie-core",
            title: "AS-REP Roasting の兆候",
            severity: "high",
            attack: &["T1558.004"],
            matcher: match_asrep_roast,
        },
        HeuristicRule {
            id: "upn-swap",
            engine: "taotie-core",
            title: "UPN 改変による証明書マッピング悪用の兆候",
            severity: "high",
            attack: &["T1649"],
            matcher: match_upn_swap,
        },
        HeuristicRule {
            id: "force-change-password",
            engine: "taotie-core",
            title: "ForceChangePassword によるアカウント乗っ取りの兆候",
            severity: "high",
            attack: &["T1098"],
            matcher: match_force_change_password,
        },
        HeuristicRule {
            id: "shadow-credentials",
            engine: "taotie-core",
            title: "Shadow Credentials の兆候",
            severity: "critical",
            attack: &["T1649"],
            matcher: match_shadow_credentials,
        },
        HeuristicRule {
            id: "timestomp-file-create-time",
            engine: "taotie-core",
            title: "タイムストンプ (FileCreateTime 改変)",
            severity: "high",
            attack: &["T1070.006"],
            matcher: match_timestomp_file_create_time,
        },
    ]
}

fn rebuild_findings_after_override_change(
    workspace: &CaseWorkspace,
    operation: &str,
) -> Result<FindingRebuildResult> {
    let started_at = now_utc();
    let chains = workspace.query_layer().correlation_chains(Some(500))?;
    let result = rebuild_findings_and_event_rows(workspace, &chains)?;
    workspace.append_analyzer_runs(&[AnalyzerRunSummary {
        run_id: new_id("analyzer"),
        case_id: workspace.manifest().case_id.clone(),
        analyzer_id: "finding_overrides".to_string(),
        name: "Finding 抑制/上書き".to_string(),
        version: "taotie-port-of-taotie-v1".to_string(),
        status: "succeeded".to_string(),
        started_at,
        finished_at: Some(now_utc()),
        input_count: result.input_event_count as i64,
        output_count: result.final_count as i64,
        error_message: None,
        metadata_json: serde_json::json!({
            "operation": operation,
            "override_count": result.override_count,
            "event_row_count": result.event_row_count,
        })
        .to_string(),
    }])?;
    Ok(result)
}

fn rebuild_findings_and_event_rows(
    workspace: &CaseWorkspace,
    chains: &[CorrelationChainSummary],
) -> Result<FindingRebuildResult> {
    let lake_event_count = workspace.query_layer().lake_event_count()?;
    let events = if lake_event_count > 500_000 {
        workspace
            .query_layer()
            .analyzer_events_for_detection_candidates()?
    } else {
        workspace.query_layer().analyzer_events_full()?
    };
    let heuristic_findings = run_heuristic_findings(&workspace.manifest().case_id, &events)?;
    let hayabusa_findings = run_hayabusa_findings(&workspace.manifest().case_id, &events)?;
    let ioc_indicators = load_ioc_indicators(workspace)?;
    let ioc_findings =
        run_ioc_finding_records(&workspace.manifest().case_id, &events, &ioc_indicators)?;
    let chain_findings = run_correlation_chain_findings(&workspace.manifest().case_id, chains)?;
    let sigma_findings = sigma::run_sigma_findings(&workspace.manifest().case_id, &events);
    let mut findings = heuristic_findings.clone();
    findings.extend(hayabusa_findings.clone());
    findings.extend(ioc_findings.clone());
    findings.extend(chain_findings.clone());
    findings.extend(sigma_findings);
    let overrides = load_finding_overrides(workspace)?;
    let findings = apply_finding_overrides(findings, &overrides);
    workspace.replace_findings(&findings)?;
    let event_row_count = workspace.query_layer().rebuild_event_rows_from_lake()?;
    Ok(FindingRebuildResult {
        input_event_count: lake_event_count,
        heuristic_count: heuristic_findings.len(),
        chain_count: chain_findings.len(),
        hayabusa_count: hayabusa_findings.len(),
        ioc_count: ioc_findings.len(),
        final_count: findings.len(),
        override_count: overrides.iter().filter(|row| row.enabled).count(),
        event_row_count,
    })
}

fn rebuild_derived_evidence_models(
    workspace: &CaseWorkspace,
    lake_event_count: usize,
) -> Result<(usize, usize)> {
    workspace.replace_artifact_objects(&[])?;
    workspace.replace_evidence_offsets(&[])?;
    if lake_event_count == 0 {
        return Ok((0, 0));
    }

    let batch_size = std::env::var("TAOTIE4_STRUCTURE_REBUILD_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50_000)
        .clamp(1_000, 100_000);
    let mut after: Option<(String, String)> = None;
    let mut artifact_object_count = 0usize;
    let mut evidence_offset_count = 0usize;
    loop {
        let events = workspace.query_layer().analyzer_events_full_batch(
            after
                .as_ref()
                .map(|(event_time, event_id)| (event_time.as_str(), event_id.as_str())),
            batch_size,
        )?;
        if events.is_empty() {
            break;
        }
        if let Some(last) = events.last() {
            after = Some((last.event_time_utc.clone(), last.event_id.clone()));
        }
        let artifact_objects = derive_artifact_objects(&events);
        let evidence_offsets = derive_evidence_offsets(&events);
        artifact_object_count += artifact_objects.len();
        evidence_offset_count += evidence_offsets.len();
        workspace.append_artifact_objects(&artifact_objects)?;
        workspace.append_evidence_offsets(&evidence_offsets)?;
        if events.len() < batch_size {
            break;
        }
    }
    Ok((artifact_object_count, evidence_offset_count))
}

fn build_answer_candidates(case_id: &str, events: &[EventFull]) -> Result<Vec<AnswerCandidate>> {
    let mut out: HashMap<(String, String), AnswerCandidate> = HashMap::new();
    let context = detect_answer_candidate_context(events);
    for event in events {
        let attrs = serde_json::from_str::<serde_json::Value>(&event.attributes_json)
            .unwrap_or_else(|_| serde_json::json!({}));
        let hay = answer_event_text(event, &attrs);
        let lower = hay.to_ascii_lowercase();

        if context.moveit
            && contains_any(
                &lower,
                &[
                    "moveit",
                    "move.aspx",
                    "moveit.asp",
                    "moveitsvc",
                    "guestaccess.aspx",
                    "api/v1/token",
                    "instlogos",
                ],
            )
        {
            add_moveit_answer_candidates(case_id, event, &attrs, &lower, &mut out);
        }

        if lower.contains("systemhealthcheck") || lower.contains(".hta") || lower.contains("mshta")
        {
            push_answer_candidate(
                &mut out,
                answer_candidate(
                    case_id,
                    "initial_access.execution_technique",
                    "初期侵入手法候補",
                    if lower.contains("mshta") {
                        "T1218.005 / T1204.002"
                    } else {
                        "T1204.002"
                    },
                    0.72,
                    "needs_review",
                    "high",
                    "initial_access",
                    "HTA/MSHTA/SystemHealthCheck系の実行またはダウンロード痕跡",
                    event,
                    vec!["HTAのダウンロード時刻と実行時刻を分けて確認"],
                    Some("HTA/MSHTA関連イベントを時系列で確認"),
                    serde_json::json!({ "matched": "hta_mshta_systemhealthcheck" }),
                ),
            );
            push_answer_candidate(
                &mut out,
                answer_candidate(
                    case_id,
                    "initial_access.foothold_time",
                    "初期侵入/足掛かり時刻候補",
                    &event.event_time_utc,
                    0.68,
                    "candidate",
                    "medium",
                    "initial_access",
                    "SystemHealthCheck/HTA関連イベントの時刻",
                    event,
                    vec!["download時刻かfirst execution時刻かを根拠イベントで確認"],
                    Some("前後15分のBrowser/Prefetch/EVTXを確認"),
                    serde_json::json!({ "time_kind": event.time_kind }),
                ),
            );
        }

        if lower.contains("whoami.exe") || lower.contains("whoami ") || lower.ends_with("whoami") {
            push_answer_candidate(
                &mut out,
                answer_candidate(
                    case_id,
                    "discovery.identity_command_time",
                    "環境確認コマンド実行時刻候補",
                    &event.event_time_utc,
                    0.76,
                    "candidate",
                    "medium",
                    "execution",
                    "whoami実行痕跡",
                    event,
                    vec!["Prefetch run timeとプロセス作成ログを突合"],
                    Some("whoami.exeで横断検索"),
                    serde_json::json!({ "process_name": event.process_name }),
                ),
            );
        }

        if is_rdp_logon_candidate(event, &attrs, &lower) {
            push_answer_candidate(
                &mut out,
                answer_candidate(
                    case_id,
                    "remote_access.rdp_initial_auth_time",
                    "RDP/対話ログオン初回候補",
                    &event.event_time_utc,
                    0.82,
                    "candidate",
                    "high",
                    "lateral_movement",
                    "RDP/LogonType 10/RemoteConnectionManager系の認証痕跡",
                    event,
                    vec!["同一ユーザー/IPの初回成功ログオンであることを確認"],
                    Some("LogonType 10、1149、LocalSessionManagerを時系列確認"),
                    serde_json::json!({
                        "user": event.user_name,
                        "ip": event.ip,
                    }),
                ),
            );
        }

        add_windows_semantic_answer_candidates(case_id, event, &attrs, &mut out);
        add_generic_windows_investigation_candidates(
            case_id, event, &attrs, &hay, &lower, &mut out,
        );

        if lower.contains("powerview.ps1") {
            push_answer_candidate(
                &mut out,
                answer_candidate(
                    case_id,
                    "tooling.powershell_script",
                    "PowerShell調査対象スクリプト候補",
                    "PowerView.ps1",
                    0.86,
                    "candidate",
                    "high",
                    "tooling",
                    "PowerView.ps1のダウンロード/参照痕跡",
                    event,
                    vec!["実行名や保存名とダウンロード名の差分を確認"],
                    Some("PowerView.ps1と.ps1実行痕跡を横断検索"),
                    serde_json::json!({ "matched": "powerview.ps1" }),
                ),
            );
        }

        if lower.contains("keepass") || lower.contains(".kdbx") {
            push_answer_candidate(
                &mut out,
                answer_candidate(
                    case_id,
                    "credential_access.target_application",
                    "資格情報アクセス対象アプリ候補",
                    "KeePass",
                    0.78,
                    "candidate",
                    "medium",
                    "credential_access",
                    "KeePass/KDBXへのアクセスまたは検索痕跡",
                    event,
                    vec!["Process Hacker実行後のアプリ列挙/アクセス順序を確認"],
                    Some("KeePass/KDBX/Process Hacker周辺のタイムラインを確認"),
                    serde_json::json!({ "matched": "keepass_kdbx" }),
                ),
            );
        }

        if lower.contains(".dmp") || lower.contains("minidump") || lower.contains("lsass") {
            let value = event
                .file_path
                .as_deref()
                .and_then(filename_from_path)
                .filter(|name| name.to_ascii_lowercase().ends_with(".dmp"))
                .unwrap_or("dump file candidate");
            push_answer_candidate(
                &mut out,
                answer_candidate(
                    case_id,
                    "credential_access.dump_file",
                    "メモリ/資格情報dumpファイル候補",
                    value,
                    if value.ends_with(".dmp") { 0.78 } else { 0.58 },
                    "candidate",
                    "high",
                    "credential_access",
                    "dump/LSASS/MiniDump関連痕跡",
                    event,
                    vec!["Process Hacker/comsvcs/LSASS周辺イベントと突合"],
                    Some("*.dmpとLSASS関連イベントを横断検索"),
                    serde_json::json!({ "file_path": event.file_path }),
                ),
            );
        }

        if lower.contains("filezilla_saved_password_recovered")
            || lower.contains("filezilla server observed")
            || lower.contains("remote_path_normalized")
        {
            add_filezilla_answer_candidates(case_id, event, &attrs, &mut out);
        }

        if lower.contains("zeek_")
            || lower.contains("network_http_request")
            || lower.contains("network_ftp_command")
            || lower.contains("network_file_transfer")
            || lower.contains("network_url_observed")
            || lower.contains("pcap_conversation_reconstructed")
        {
            add_network_answer_candidates(case_id, event, &attrs, &mut out);
        }

        if lower.contains("archive_recovery_candidate")
            || lower.contains("archive_suspicious_member")
            || lower.contains("archive_member_observed")
        {
            add_archive_answer_candidates(case_id, event, &attrs, &mut out);
        }

        if lower.contains("deleted_file_recovered")
            || lower.contains("carved_file_recovered")
            || lower.contains("mft_ads_resident_content_observed")
            || lower.contains("mft_resident_data_observed")
        {
            add_recovered_content_answer_candidates(case_id, event, &attrs, &mut out);
        }

        if lower.contains("cve-2023-38831") {
            push_answer_candidate(
                &mut out,
                answer_candidate(
                    case_id,
                    "exploit.cve_candidate",
                    "悪用脆弱性候補",
                    "CVE-2023-38831",
                    0.64,
                    "needs_review",
                    "medium",
                    "exploit",
                    "RAR/archive exploit候補の検出",
                    event,
                    vec!["実際のpayload/拡張子偽装/展開痕跡を確認"],
                    Some("archive sidecar結果とWinRAR実行痕跡を確認"),
                    serde_json::json!({ "matched": "cve-2023-38831" }),
                ),
            );
        }

        if lower.contains("document_sensitive_text_observed")
            || lower.contains("document text extracted")
            || lower.contains("document_recovery_candidate")
        {
            add_document_answer_candidates(case_id, event, &attrs, &mut out);
        }

        if lower.contains("browser_encrypted_secret_candidate")
            || lower.contains("browser_secret_decrypted")
            || lower.contains("keepass_database_observed")
            || lower.contains("keepass_entry_decrypted")
            || lower.contains("dpapi_masterkey")
        {
            add_credential_answer_candidates(case_id, event, &attrs, &mut out);
        }

        if lower.contains(".bat") || lower.contains("batch") {
            if let Some(url) = event
                .url
                .clone()
                .or_else(|| event_attr_string(event, &["url"]))
            {
                push_answer_candidate(
                    &mut out,
                    answer_candidate(
                        case_id,
                        "network.script_url",
                        "スクリプト通信先URL候補",
                        &url,
                        0.62,
                        "needs_review",
                        "medium",
                        "c2",
                        "BAT/BatchとURLが同一イベントに出現",
                        event,
                        vec!["BAT本体復元とURLの出所確認"],
                        Some("BAT/URL/PCAP/Browser cacheを横断確認"),
                        serde_json::json!({ "url": url }),
                    ),
                );
            }
            if let Some(hash) = event
                .hash
                .clone()
                .or_else(|| event_attr_string(event, &["md5", "hash"]))
            {
                push_answer_candidate(
                    &mut out,
                    answer_candidate(
                        case_id,
                        "file_recovery.script_hash",
                        "スクリプト/復元ファイルhash候補",
                        &hash,
                        0.56,
                        "needs_review",
                        "medium",
                        "file_recovery",
                        "BAT/Batchに関連するhash候補",
                        event,
                        vec!["復元されたBAT本体からMD5を再計算"],
                        Some("復元ファイルhashを確認"),
                        serde_json::json!({ "hash": hash }),
                    ),
                );
            }
        }
    }

    if context.moveit {
        add_moveit_account_change_answer_candidates(case_id, events, &mut out);
        add_moveit_rdp_chain_answer_candidates(case_id, events, &mut out);
    }

    let mut rows = out.into_values().collect::<Vec<_>>();
    if context.moveit {
        for required in moveit_recovery_gap_candidates(case_id) {
            out_insert_missing(&mut rows, required);
        }
    }
    rows.sort_by(answer_candidate_question_order);
    rows = cap_answer_candidates_per_question(rows);
    rows.sort_by(answer_candidate_display_order);
    Ok(rows)
}

fn answer_candidate_question_order(
    left: &AnswerCandidate,
    right: &AnswerCandidate,
) -> std::cmp::Ordering {
    left.question_key
        .cmp(&right.question_key)
        .then_with(|| answer_candidate_score(right).total_cmp(&answer_candidate_score(left)))
        .then_with(|| left.candidate_value.cmp(&right.candidate_value))
}

fn answer_candidate_display_order(
    left: &AnswerCandidate,
    right: &AnswerCandidate,
) -> std::cmp::Ordering {
    answer_candidate_score(right)
        .total_cmp(&answer_candidate_score(left))
        .then_with(|| left.question_key.cmp(&right.question_key))
        .then_with(|| left.candidate_value.cmp(&right.candidate_value))
}

fn answer_candidate_score(candidate: &AnswerCandidate) -> f64 {
    let mut score = candidate.confidence;
    score += match candidate.severity.as_str() {
        "critical" => 0.14,
        "high" => 0.10,
        "medium" => 0.03,
        "low" => -0.03,
        _ => 0.0,
    };
    score += match candidate.status.as_str() {
        "candidate" => 0.04,
        "needs_recovery" => 0.03,
        "needs_review" => -0.02,
        status if status.contains("blocked") => -0.06,
        _ => 0.0,
    };
    score += match candidate.question_key.as_str() {
        "webshell.file_name"
        | "webshell.retrieval_command"
        | "network.source_ip_candidate"
        | "account.service_account_password_change_time"
        | "malware.defender_threat"
        | "credential_access.kerberos_roastable_account"
        | "exploit.cve_candidate" => 0.10,
        "remote_access.protocol" | "remote_access.time" | "remote_access.rdp_initial_auth_time" => {
            0.06
        }
        "file_recovery.ads_or_zone_identifier"
        | "file_recovery.script_hash"
        | "network.script_url" => 0.05,
        "persistence.scheduled_task_exec" => -0.15,
        "file_recovery.recovered_content" => -0.04,
        _ => 0.0,
    };
    let value = candidate.candidate_value.to_ascii_lowercase();
    if contains_any(
        &value,
        &[
            "hosturl",
            "zone.identifier",
            "invoice.bat",
            "move.aspx",
            "moveit.asp",
            "merlin.exe",
            "sharphound",
            "rubeus",
            "filezilla",
            "keepass",
            "cve-",
            "ftp.",
            "http://",
            "https://",
        ],
    ) {
        score += 0.08;
    }
    if value.contains("microsoft\\windows")
        || value.contains("googleupdate")
        || value.contains("createexplorershellunelevatedtask")
        || value.contains("diskdiagnostic")
    {
        score -= 0.12;
    }
    if candidate.question_key == "remote_access.rdp_initial_auth_time" {
        if let Ok(attrs) = serde_json::from_str::<serde_json::Value>(&candidate.attributes_json) {
            let user = attrs
                .get("user")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            let ip = attrs
                .get("ip")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if user.is_empty()
                || user == "system"
                || user == "null"
                || user.ends_with('$')
                || ip.is_empty()
                || ip == "::1"
                || ip == "127.0.0.1"
                || ip == "-"
            {
                score -= 0.12;
            } else {
                score += 0.04;
            }
        }
    }
    score
}

fn cap_answer_candidates_per_question(rows: Vec<AnswerCandidate>) -> Vec<AnswerCandidate> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut kept = Vec::with_capacity(rows.len());
    for row in rows {
        let count = counts.entry(row.question_key.clone()).or_insert(0);
        let cap = answer_candidate_question_cap(&row);
        if *count < cap || row.status == "needs_recovery" {
            *count += 1;
            kept.push(row);
        }
    }
    kept
}

fn answer_candidate_question_cap(candidate: &AnswerCandidate) -> usize {
    match candidate.question_key.as_str() {
        "remote_access.rdp_initial_auth_time" => 4,
        "persistence.scheduled_task_exec" => 5,
        "file_recovery.recovered_content" => 8,
        "network.http_request" | "network.url_observed" | "exfiltration.remote_path" => 10,
        _ => 12,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AnswerCandidateContext {
    moveit: bool,
}

fn detect_answer_candidate_context(events: &[EventFull]) -> AnswerCandidateContext {
    let mut context = AnswerCandidateContext::default();
    for event in events {
        let text = [
            event.artifact_type.as_str(),
            event.event_action.as_str(),
            event.message_short.as_str(),
            event.message_full.as_str(),
            event.file_path.as_deref().unwrap_or_default(),
            event.process_name.as_deref().unwrap_or_default(),
            event.url.as_deref().unwrap_or_default(),
            event.user_name.as_deref().unwrap_or_default(),
            event.attributes_json.as_str(),
        ]
        .join(" ")
        .to_ascii_lowercase();
        if contains_any(
            &text,
            &[
                "moveit",
                "move.aspx",
                "moveit.asp",
                "moveitsvc",
                "guestaccess.aspx",
                "api/v1/token",
                "instlogos",
            ],
        ) {
            context.moveit = true;
        }
        if context.moveit {
            break;
        }
    }
    context
}

fn answer_candidate(
    case_id: &str,
    question_key: &str,
    question_label: &str,
    candidate_value: &str,
    confidence: f64,
    status: &str,
    severity: &str,
    category: &str,
    reason: &str,
    event: &EventFull,
    missing_steps: Vec<&str>,
    next_action: Option<&str>,
    attributes: serde_json::Value,
) -> AnswerCandidate {
    let evidence_event_ids = vec![event.event_id.clone()];
    let evidence_refs = vec![event.evidence_ref.clone()];
    let missing_steps = missing_steps
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let id_seed = format!(
        "{}|{}|{}|{}",
        case_id, question_key, candidate_value, event.event_id
    );
    AnswerCandidate {
        candidate_id: stable_prefixed_id("answer", &id_seed),
        case_id: case_id.to_string(),
        question_key: question_key.to_string(),
        question_label: question_label.to_string(),
        candidate_value: candidate_value.to_string(),
        confidence: confidence.clamp(0.0, 1.0),
        status: status.to_string(),
        severity: severity.to_string(),
        category: category.to_string(),
        reason: reason.to_string(),
        evidence_event_ids_json: serde_json::to_string(&evidence_event_ids)
            .unwrap_or_else(|_| "[]".to_string()),
        evidence_refs_json: serde_json::to_string(&evidence_refs)
            .unwrap_or_else(|_| "[]".to_string()),
        missing_steps_json: serde_json::to_string(&missing_steps)
            .unwrap_or_else(|_| "[]".to_string()),
        next_action: next_action.map(str::to_string),
        first_seen_utc: Some(event.event_time_utc.clone()),
        last_seen_utc: Some(event.event_time_utc.clone()),
        attributes_json: attributes.to_string(),
    }
}

fn push_answer_candidate(
    out: &mut HashMap<(String, String), AnswerCandidate>,
    candidate: AnswerCandidate,
) {
    let key = (
        candidate.question_key.clone(),
        candidate.candidate_value.clone(),
    );
    match out.get_mut(&key) {
        Some(existing) => {
            if candidate.confidence > existing.confidence {
                existing.confidence = candidate.confidence;
                existing.status = candidate.status.clone();
                existing.severity = candidate.severity.clone();
                existing.reason = candidate.reason.clone();
                existing.next_action = candidate.next_action.clone();
                existing.attributes_json = candidate.attributes_json.clone();
            }
            existing.first_seen_utc = min_opt_time(
                existing.first_seen_utc.as_deref(),
                candidate.first_seen_utc.as_deref(),
            );
            existing.last_seen_utc = max_opt_time(
                existing.last_seen_utc.as_deref(),
                candidate.last_seen_utc.as_deref(),
            );
            existing.evidence_event_ids_json = merge_json_string_arrays(
                &existing.evidence_event_ids_json,
                &candidate.evidence_event_ids_json,
            );
            existing.evidence_refs_json = merge_json_string_arrays(
                &existing.evidence_refs_json,
                &candidate.evidence_refs_json,
            );
        }
        None => {
            out.insert(key, candidate);
        }
    }
}

fn add_filezilla_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    if let Some(host) = event_attr_string_from_value(attrs, &["remote_host", "host"]) {
        let password = event_attr_string_from_value(attrs, &["password_decoded"])
            .map(|value| redact_secret_candidate(&value))
            .unwrap_or_else(|| "(password not recovered)".to_string());
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "credential_access.ftp_destination_secret",
                "FTP認証/送信先候補",
                &format!("{host} / {password}"),
                if password == "(password not recovered)" {
                    0.55
                } else {
                    0.88
                },
                "candidate",
                "high",
                "exfiltration",
                "FileZilla保存接続情報",
                event,
                vec!["passwordは必要時のみ監査付きで表示"],
                Some("FileZilla XML/queueのhost/user/passwordを確認"),
                serde_json::json!({ "remote_host": host, "password_status": if password == "(password not recovered)" { "missing" } else { "redacted" } }),
            ),
        );
    }
    if let Some(remote_path) =
        event_attr_string_from_value(attrs, &["remote_path_normalized", "remote_path"])
    {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "exfiltration.remote_path",
                "外部送信先パス候補",
                &remote_path,
                0.9,
                "candidate",
                "high",
                "exfiltration",
                "FileZilla RemotePathの復元",
                event,
                vec!["queue/transfer logで実際の送信先か確認"],
                Some("同一host/userのFileZillaイベントを確認"),
                serde_json::json!({ "remote_path": remote_path }),
            ),
        );
    }
    if let Some(local_path) = event_attr_string_from_value(attrs, &["local_path"]) {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "exfiltration.staging_directory",
                "外部送信準備ディレクトリ候補",
                &local_path,
                0.82,
                "candidate",
                "high",
                "exfiltration",
                "FileZilla LocalPathの復元",
                event,
                vec!["archive作成/アップロード対象と突合"],
                Some("LocalPath配下のMFT/USN/RecentDocsを確認"),
                serde_json::json!({ "local_path": local_path }),
            ),
        );
    }
}

fn add_windows_semantic_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    if semantic_label(attrs, "kerberoast_candidate")
        || semantic_label(attrs, "asrep_roast_candidate")
    {
        let user = event
            .user_name
            .clone()
            .or_else(|| event_attr_string_from_value(attrs, &["TargetUserName", "AccountName"]))
            .unwrap_or_else(|| "-".to_string());
        let service = semantic_string(attrs, "service_name").unwrap_or_else(|| "-".to_string());
        let enc =
            semantic_string(attrs, "ticket_encryption_name").unwrap_or_else(|| "-".to_string());
        let label = if semantic_label(attrs, "asrep_roast_candidate") {
            "ASREP roast候補"
        } else {
            "Kerberoast候補"
        };
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "credential_access.kerberos_roastable_account",
                "Kerberos弱暗号/roast候補",
                &format!("{label}: user={user} service={service} enc={enc}"),
                0.88,
                "candidate",
                "high",
                "credential_access",
                "Kerberos TicketEncryptionType/PreAuthTypeから弱いチケット利用を検出",
                event,
                vec!["同一ユーザー/サービスの4768/4769を時系列で確認"],
                Some("Kerberosイベント、ログオン、プロセス実行を横断確認"),
                serde_json::json!({
                    "user": user,
                    "service": service,
                    "ticket_encryption": enc,
                    "labels": semantic_labels(attrs),
                }),
            ),
        );
    }

    if semantic_label(attrs, "rdp_logon_type_10")
        || semantic_label(attrs, "rdp_1149_authentication")
    {
        add_rdp_answer_candidates(case_id, event, attrs, out, 0.86);
    }

    if semantic_label(attrs, "psexec_service") || semantic_label(attrs, "psexec_named_pipe") {
        let service = semantic_string(attrs, "service_name")
            .or_else(|| event_attr_string_from_value(attrs, &["ServiceName"]))
            .unwrap_or_else(|| "PSEXESVC".to_string());
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "lateral_movement.psexec_evidence",
                "PsExec/管理共有横展開候補",
                &service,
                0.84,
                "candidate",
                "high",
                "lateral_movement",
                "PSEXESVCサービスまたはnamed pipe痕跡",
                event,
                vec!["サービス作成、named pipe、4624/4648、管理共有アクセスを同一時間帯で確認"],
                Some("PSEXESVC/pipe/7045/Sysmon 17/18を横断検索"),
                serde_json::json!({ "labels": semantic_labels(attrs) }),
            ),
        );
    }

    if semantic_label(attrs, "firewall_outbound")
        || semantic_label(attrs, "firewall_block")
        || semantic_kind(attrs)
            .map(|kind| kind.starts_with("firewall_"))
            .unwrap_or(false)
    {
        let rule = semantic_string(attrs, "rule_name").unwrap_or_else(|| "-".to_string());
        let direction =
            semantic_string(attrs, "firewall_direction").unwrap_or_else(|| "-".to_string());
        let action = semantic_string(attrs, "firewall_action").unwrap_or_else(|| "-".to_string());
        if !suspicious_firewall_candidate(event, &rule, &direction, &action) {
            return;
        }
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "defense_evasion.firewall_change_or_flow",
                "Firewall変更/通信方向候補",
                &format!("rule={rule} direction={direction} action={action}"),
                if direction == "outbound" || action == "blocked" {
                    0.72
                } else {
                    0.58
                },
                "needs_review",
                "medium",
                "defense_evasion",
                "Firewallルール/Filtering Platformイベントの構造化結果",
                event,
                vec!["ルール変更か通信許可/遮断かをEventIDと前後イベントで確認"],
                Some("Firewall EventID 4946/5156/5157とプロセス/IPを確認"),
                serde_json::json!({
                    "rule": rule,
                    "direction": direction,
                    "action": action,
                    "labels": semantic_labels(attrs),
                }),
            ),
        );
    }

    if semantic_kind(attrs)
        .map(|kind| kind.contains("audit_policy") || kind == "privilege_rights_changed")
        .unwrap_or(false)
    {
        let subcategory =
            semantic_string(attrs, "audit_subcategory").unwrap_or_else(|| "-".to_string());
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "defense_evasion.audit_policy_change",
                "監査ポリシー/権限変更候補",
                &subcategory,
                0.76,
                "candidate",
                "medium",
                "defense_evasion",
                "監査ポリシーまたはユーザー権限変更イベント",
                event,
                vec!["変更主体、変更対象、直前のログオン/プロセス実行を確認"],
                Some("4719/490x/4703を前後イベントで確認"),
                serde_json::json!({ "subcategory": subcategory, "labels": semantic_labels(attrs) }),
            ),
        );
    }
}

fn add_generic_windows_investigation_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    hay: &str,
    lower: &str,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    add_scheduled_task_investigation_candidate(case_id, event, attrs, hay, lower, out);
    add_defender_threat_investigation_candidate(case_id, event, attrs, hay, lower, out);
    add_powershell_investigation_candidates(case_id, event, attrs, hay, lower, out);
    add_firewall_text_investigation_candidate(case_id, event, attrs, hay, lower, out);
    add_audit_policy_text_investigation_candidate(case_id, event, attrs, hay, lower, out);
}

fn add_scheduled_task_investigation_candidate(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    hay: &str,
    lower: &str,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    if !(event.event_action.contains("scheduled_task")
        || lower.contains("scheduled task")
        || lower.contains("task created")
        || event_attr_string_from_value(attrs, &["event_id"]).as_deref() == Some("4698"))
    {
        return;
    }
    let task_name = event_attr_string_from_value(attrs, &["task_name", "TaskName", "Name", "URI"])
        .or_else(|| embedded_field(hay, &["TaskName", "Name", "URI"]))
        .or_else(|| xml_tag_value(hay, "URI"))
        .or_else(|| scheduled_task_name_from_message(hay))
        .unwrap_or_else(|| "-".to_string());
    let task_name = trim_inline_labeled_value(
        &task_name,
        &[" command=", " trigger=", " eventid ", " user="],
    );
    let command = event_attr_string_from_value(
        attrs,
        &[
            "command_line",
            "CommandLine",
            "ProcessCommandLine",
            "Command",
            "TaskContent",
        ],
    )
    .and_then(|value| xml_tag_value(&value, "Command").or(Some(value)))
    .or_else(|| xml_tag_value(hay, "Command"))
    .or_else(|| embedded_field(hay, &["Command", "Action"]))
    .or_else(|| script_path_like(hay))
    .unwrap_or_else(|| "-".to_string());
    let command = trim_inline_labeled_value(
        &command,
        &[" scheduled task ", " eventid ", " task=", " user="],
    );
    if !suspicious_scheduled_task(&task_name, &command, lower) {
        return;
    }
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            "persistence.scheduled_task_exec",
            "スケジュールタスク実行候補",
            &format!(
                "task={} command={}",
                truncate_candidate_value(&task_name, 80),
                truncate_candidate_value(&command, 140)
            ),
            0.82,
            "candidate",
            "high",
            "persistence",
            "作成/更新されたScheduled Taskに調査対象コマンドが含まれる",
            event,
            vec!["タスク作成者、実行ユーザー、直後のプロセス/ネットワークを確認"],
            Some("同一タスク名と実行ファイル名で横断検索"),
            serde_json::json!({
                "task_name": task_name,
                "command": command,
            }),
        ),
    );
}

fn add_defender_threat_investigation_candidate(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    hay: &str,
    lower: &str,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let looks_defender = event.artifact_type == "defender"
        || event.event_action.starts_with("defender_")
        || lower.contains("defender")
        || lower.contains("antivirus");
    if !looks_defender {
        return;
    }
    let Some(threat) = event_attr_string_from_value(
        attrs,
        &[
            "defender_threat",
            "threat_name",
            "Threat Name",
            "Threat",
            "ThreatName",
        ],
    )
    .or_else(|| embedded_field(hay, &["Threat", "Threat Name"])) else {
        return;
    };
    let threat = trim_inline_labeled_value(
        &threat,
        &[
            " path=",
            " severity=",
            " type=",
            " user=",
            " proc=",
            " status=",
            " eventid ",
        ],
    );
    if threat.is_empty() {
        return;
    }
    let path = event_attr_string_from_value(
        attrs,
        &["defender_path", "Path", "FilePath", "TargetFilename"],
    )
    .or_else(|| embedded_field(hay, &["Path", "File", "TargetFilename"]))
    .or_else(|| event.file_path.clone())
    .unwrap_or_else(|| "-".to_string());
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            "malware.defender_threat",
            "Defender脅威検知候補",
            &format!(
                "threat={} path={}",
                truncate_candidate_value(&threat, 100),
                truncate_candidate_value(&path, 140)
            ),
            if contains_any(&threat.to_ascii_lowercase(), &["hacktool", "sharphound"]) {
                0.88
            } else {
                0.76
            },
            "candidate",
            if event.severity == "critical" || event.severity == "high" {
                "high"
            } else {
                "medium"
            },
            "malware",
            "Defender Operational/MPLog/検知行から脅威名と対象パスを抽出",
            event,
            vec!["検疫/修復結果、ダウンロード元、実行痕跡を確認"],
            Some("脅威名、対象パス、Defender EventID 1116/1117を確認"),
            serde_json::json!({
                "threat": threat,
                "path": path,
            }),
        ),
    );
}

fn add_powershell_investigation_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    hay: &str,
    lower: &str,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let looks_file_hash_output = lower.contains("get-filehash")
        || (lower.contains("hash=")
            && (lower.contains("algorithm=md5")
                || lower.contains("algorithm=sha")
                || lower.contains("getstreamhash")));
    if looks_file_hash_output {
        if let Some(hash_raw) = event
            .hash
            .clone()
            .or_else(|| event_attr_string_from_value(attrs, &["hash", "md5", "sha1", "sha256"]))
            .or_else(|| embedded_field(hay, &["Hash"]))
            .or_else(|| hash_like(hay))
        {
            let Some(hash) = hash_like(&hash_raw) else {
                return;
            };
            push_answer_candidate(
                out,
                answer_candidate(
                    case_id,
                    "file.hash_observed",
                    "ファイルhash確認候補",
                    &hash,
                    0.8,
                    "candidate",
                    "medium",
                    "file_analysis",
                    "PowerShell Get-FileHashまたは同等出力からhashを抽出",
                    event,
                    vec!["対象パス、アルゴリズム、元ファイルの存在/復元状態を確認"],
                    Some("同一hashと対象パスで横断検索"),
                    serde_json::json!({ "hash": hash }),
                ),
            );
        }
    }

    if !(lower.contains("powershell")
        || lower.contains("pwsh")
        || lower.contains("scriptblock")
        || event.event_action.contains("powershell"))
    {
        return;
    }
    if let Some(script) = script_path_like(hay) {
        if benign_powershell_script(&script) {
            return;
        }
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "execution.powershell_script",
                "PowerShellスクリプト実行/参照候補",
                &truncate_candidate_value(&script, 160),
                if contains_any(
                    lower,
                    &["encodedcommand", "downloadstring", "invoke-", "bypass"],
                ) {
                    0.86
                } else {
                    0.72
                },
                "candidate",
                if contains_any(
                    lower,
                    &["encodedcommand", "downloadstring", "invoke-", "bypass"],
                ) {
                    "high"
                } else {
                    "medium"
                },
                "execution",
                "PowerShellログ/コマンドからスクリプトパスを抽出",
                event,
                vec!["ScriptBlock、Pipeline、Prefetch、MFT/USNの前後関係を確認"],
                Some("同一スクリプト名で横断検索"),
                serde_json::json!({ "script": script }),
            ),
        );
    }
}

fn add_firewall_text_investigation_candidate(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    hay: &str,
    lower: &str,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    if event.artifact_type == "defender" || event.event_action.starts_with("defender_") {
        return;
    }
    if !(lower.contains("firewall")
        || lower.contains("rule added")
        || lower.contains("rulename:")
        || event.event_action.starts_with("firewall_"))
    {
        return;
    }
    let rule = semantic_string(attrs, "rule_name")
        .or_else(|| event_attr_string_from_value(attrs, &["RuleName", "Rule Name"]))
        .or_else(|| embedded_field(hay, &["RuleName", "Rule Name"]))
        .unwrap_or_else(|| "-".to_string());
    let rule = trim_inline_labeled_value(&rule, &[" direction=", " action=", " eventid "]);
    let direction = semantic_string(attrs, "firewall_direction")
        .or_else(|| embedded_field(hay, &["Direction"]))
        .map(|value| trim_inline_labeled_value(&value, &[" action=", " rule=", " eventid "]))
        .and_then(|value| normalize_firewall_direction_api(&value).or(Some(value)))
        .unwrap_or_else(|| "-".to_string());
    let action = semantic_string(attrs, "firewall_action")
        .or_else(|| embedded_field(hay, &["Action"]))
        .map(|value| trim_inline_labeled_value(&value, &[" direction=", " rule=", " eventid "]))
        .and_then(|value| normalize_firewall_action_api(&value).or(Some(value)))
        .unwrap_or_else(|| "-".to_string());
    if !suspicious_firewall_candidate(event, &rule, &direction, &action) {
        return;
    }
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            "defense_evasion.firewall_change_or_flow",
            "Firewall変更/通信方向候補",
            &format!("rule={rule} direction={direction} action={action}"),
            if contains_any(
                &format!("{} {}", rule, hay).to_ascii_lowercase(),
                &["metasploit", "bypass", "c2", "4444"],
            ) {
                0.86
            } else {
                0.72
            },
            "needs_review",
            "medium",
            "defense_evasion",
            "Firewallルール/Filtering Platformイベントの構造化結果",
            event,
            vec!["ルール変更か通信許可/遮断かをEventIDと前後イベントで確認"],
            Some("Firewall EventID 4946/5156/5157/2004とプロセス/IPを確認"),
            serde_json::json!({
                "rule": rule,
                "direction": direction,
                "action": action,
            }),
        ),
    );
}

fn add_audit_policy_text_investigation_candidate(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    hay: &str,
    lower: &str,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    if !(event.event_action == "audit_policy_changed"
        || lower.contains("audit policy")
        || lower.contains("other object access events")
        || event_attr_string_from_value(attrs, &["event_id"]).as_deref() == Some("4719"))
    {
        return;
    }
    let subcategory = semantic_string(attrs, "audit_subcategory")
        .or_else(|| event_attr_string_from_value(attrs, &["SubcategoryName", "Subcategory"]))
        .or_else(|| embedded_field(hay, &["Subcategory", "Category"]))
        .unwrap_or_else(|| "-".to_string());
    let subcategory = trim_inline_labeled_value(
        &subcategory,
        &[
            " eventid ",
            " user=",
            " process=",
            " host=",
            " category=",
            " audit_policy_changed",
            " {}",
        ],
    );
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            "defense_evasion.audit_policy_change",
            "監査ポリシー/権限変更候補",
            &subcategory,
            if subcategory
                .to_ascii_lowercase()
                .contains("other object access")
            {
                0.84
            } else {
                0.76
            },
            "candidate",
            "medium",
            "defense_evasion",
            "監査ポリシーまたはユーザー権限変更イベント",
            event,
            vec!["変更主体、変更対象、直前のログオン/プロセス実行を確認"],
            Some("4719/490x/4703を前後イベントで確認"),
            serde_json::json!({ "subcategory": subcategory }),
        ),
    );
}

fn suspicious_firewall_candidate(
    event: &EventFull,
    rule: &str,
    direction: &str,
    action: &str,
) -> bool {
    let rule_lc = rule.trim().to_ascii_lowercase();
    if rule_lc.is_empty() || rule_lc == "-" {
        return false;
    }
    if benign_firewall_rule(&rule_lc) || guid_like(&rule_lc) {
        return false;
    }
    let lower = format!(
        "{} {} {} {} {}",
        rule, direction, action, event.message_full, event.message_short
    )
    .to_ascii_lowercase();
    if action == "blocked" || event.severity == "high" || event.severity == "critical" {
        return true;
    }
    if contains_any(
        &lower,
        &[
            "windefend",
            "defender",
            "metasploit",
            "bypass",
            "powershell",
            "automation",
            "c2",
            "payload",
            "malware",
            "trojan",
            "4444",
        ],
    ) {
        return true;
    }
    direction == "outbound" && !rule.trim().is_empty() && rule != "-"
}

fn benign_firewall_rule(rule_lc: &str) -> bool {
    rule_lc.starts_with("@{")
        || rule_lc.contains("ms-resource://")
        || rule_lc.starts_with("microsoft ")
        || rule_lc.starts_with("windows.")
        || rule_lc == "cortana"
        || rule_lc.starts_with("cortana ")
        || rule_lc == "capturepicker"
        || rule_lc.starts_with("capturepicker ")
        || rule_lc == "bytecodegeneration"
        || rule_lc.starts_with("bytecodegeneration ")
        || rule_lc.starts_with("file and printer sharing ")
        || rule_lc.starts_with("network discovery ")
        || rule_lc.starts_with("network discovery(")
        || rule_lc == "office"
        || rule_lc.starts_with("office")
        || rule_lc == "onenote"
        || rule_lc.starts_with("onenote")
        || rule_lc == "pinningconfirmationdialog"
        || rule_lc.starts_with("pinningconfirmationdialog")
        || rule_lc.starts_with("solitaire ")
        || rule_lc == "xbox"
        || rule_lc.starts_with("xbox ")
        || rule_lc.starts_with("xbox game ")
        || rule_lc.contains("service restriction rule for windefend")
}

fn guid_like(value: &str) -> bool {
    let value = value.trim_matches(['{', '}']);
    let mut parts = value.split('-');
    matches!(
        (
            parts.next().map(str::len),
            parts.next().map(str::len),
            parts.next().map(str::len),
            parts.next().map(str::len),
            parts.next().map(str::len),
            parts.next(),
        ),
        (Some(8), Some(4), Some(4), Some(4), Some(12), None)
    ) && value.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
}

fn benign_powershell_script(script: &str) -> bool {
    let lower = script.to_ascii_lowercase().replace("\\\\", "\\");
    lower.contains("\\windows\\temp\\sdiag_") && lower.ends_with("\\cl_utility.ps1")
}

fn scheduled_task_name_from_message(text: &str) -> Option<String> {
    for marker in [
        "Scheduled task exec action:",
        "Scheduled task observed:",
        "Scheduled task trigger:",
    ] {
        let Some(offset) = text.find(marker) else {
            continue;
        };
        let after = text[offset + marker.len()..].trim();
        let end = after
            .find(" command=")
            .or_else(|| after.find(" trigger="))
            .unwrap_or(after.len());
        let task = after[..end].trim();
        if !task.is_empty() && task != "-" {
            return Some(task.to_string());
        }
    }
    None
}

fn benign_scheduled_task(task_name: &str, command: &str) -> bool {
    let task = task_name.to_ascii_lowercase().replace("\\\\", "\\");
    let command = command.to_ascii_lowercase().replace("\\\\", "\\");
    let normalized = format!("{task} {command}");
    if command.contains("\\windows\\temp\\sdiag_")
        || command.contains("\\rs_programcompatibilitywizard.ps1")
        || command.contains("\\cl_utility.ps1")
    {
        return true;
    }
    if task.starts_with("\\microsoft\\windows\\")
        && !contains_any(
            &command,
            &[
                "\\users\\",
                "\\appdata\\",
                "\\programdata\\",
                "\\temp\\",
                ".ps1",
                ".bat",
                ".cmd",
                "powershell",
                "pwsh",
                "cmd.exe",
                "mshta",
                "rundll32",
                "regsvr32",
                "http://",
                "https://",
            ],
        )
    {
        return true;
    }
    if contains_any(
        &normalized,
        &[
            "createexplorershellunelevatedtask",
            "\\microsoft\\windows\\applicationdata\\cleanuptemporarystate",
            "\\microsoft\\windows\\autochk\\proxy",
            "\\microsoft\\windows\\diskdiagnostic\\microsoft-windows-diskdiagnosticdatacollector",
            "\\microsoft\\windows\\maintenance\\winsat",
            "\\microsoft\\windows\\servicing\\startcomponentcleanup",
            "\\microsoft\\windows\\shell\\familyrefresh",
            "\\microsoft\\windows\\updateorchestrator\\",
            "\\microsoft\\windows\\windowsupdate\\",
            "microsoft\\windows\\applicationdata\\cleanuptemporarystate",
            "microsoft\\windows\\autochk\\proxy",
            "microsoft\\windows\\diskdiagnostic\\microsoft-windows-diskdiagnosticdatacollector",
            "microsoft\\windows\\application experience\\pcapatchdbtask",
            "microsoft\\windows\\application experience\\startupapptask",
            "microsoft\\windows\\appxdeploymentclient\\pre-staged app cleanup",
            "microsoft\\windows\\sharedpc\\account cleanup",
            "microsoft\\windows\\staterepository\\maintenancetasks",
            "microsoft\\windows\\sysmain\\wsswapassessmenttask",
            "microsoft\\windows\\windows defender\\windows defender",
            "microsoft\\windows\\workplace join\\automatic-device-join",
            "microsoft\\windows\\workplace join\\recovery-check",
            "googleupdatetaskmachinecore",
            "googleupdatetaskmachineua",
            "microsoftedgeupdatetaskmachinecore",
            "microsoftedgeupdatetaskmachineua",
            "mozilla\\firefox background update",
            "mozilla\\firefox default browser agent",
            "onedrive reporting task-",
            "onedrive standalone update task-",
        ],
    ) {
        return true;
    }
    if task.contains("microsoft\\windows\\")
        && command.contains("\\system32\\rundll32.exe")
        && !contains_any(
            &command,
            &[
                "\\users\\",
                "\\appdata\\",
                "\\temp\\",
                "http://",
                "https://",
                "powershell",
                "pwsh",
                ".ps1",
                ".bat",
                ".cmd",
            ],
        )
    {
        return true;
    }
    if task.contains("microsoft\\windows\\")
        && (command.starts_with("%systemroot%\\system32\\")
            || command.starts_with("%windir%\\system32\\")
            || command.starts_with("c:\\windows\\system32\\"))
        && !contains_any(
            &command,
            &[
                "\\users\\",
                "\\appdata\\",
                "\\temp\\",
                "http://",
                "https://",
                "powershell",
                "pwsh",
                "cmd.exe",
                "wscript",
                "cscript",
                "mshta",
                "regsvr32",
                ".ps1",
                ".bat",
                ".cmd",
            ],
        )
    {
        return true;
    }
    if command.contains("\\program files")
        && contains_any(
            &command,
            &[
                "\\google\\update\\googleupdate.exe",
                "\\microsoft\\edgeupdate\\microsoftedgeupdate.exe",
                "\\mozilla firefox\\firefox.exe",
                "\\mozilla firefox\\default-browser-agent.exe",
                "\\onedrive",
            ],
        )
        && !contains_any(
            &command,
            &["http://", "https://", "powershell", "cmd.exe", ".ps1"],
        )
    {
        return true;
    }
    false
}

fn suspicious_scheduled_task(task_name: &str, command: &str, lower: &str) -> bool {
    if benign_scheduled_task(task_name, command) {
        return false;
    }
    let combined = format!("{task_name} {command} {lower}").to_ascii_lowercase();
    contains_any(
        &combined,
        &[
            "powershell",
            "pwsh",
            ".ps1",
            "cmd.exe",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
            "encodedcommand",
            "downloadstring",
            "http://",
            "https://",
            "\\users\\",
            "\\appdata\\",
            "\\temp\\",
            "\\public\\",
        ],
    )
}

fn normalize_firewall_direction_api(value: &str) -> Option<String> {
    let lower = value.trim().to_ascii_lowercase();
    if lower.contains("out") || lower.contains("%%14593") || lower == "2" {
        Some("outbound".to_string())
    } else if lower.contains("in") || lower.contains("%%14592") || lower == "1" {
        Some("inbound".to_string())
    } else {
        None
    }
}

fn normalize_firewall_action_api(value: &str) -> Option<String> {
    let lower = value.trim().to_ascii_lowercase();
    if lower.contains("block")
        || lower.contains("deny")
        || lower.contains("%%14598")
        || lower == "2"
    {
        Some("blocked".to_string())
    } else if lower.contains("allow")
        || lower.contains("permit")
        || lower.contains("%%14597")
        || lower == "3"
    {
        Some("allowed".to_string())
    } else {
        None
    }
}

fn embedded_field(text: &str, names: &[&str]) -> Option<String> {
    for name in names {
        let wanted = normalize_loose_key(name);
        for segment in text.split(['¦', '|', '\n', '\r', ';']) {
            let segment = segment.trim().trim_matches('"').trim_matches('\'').trim();
            if let Some((key, value)) = segment.split_once(':').or_else(|| segment.split_once('='))
            {
                if normalize_loose_key(key) == wanted {
                    let value = value.trim().trim_matches('"').trim();
                    if !value.is_empty() && value != "-" {
                        return Some(value.to_string());
                    }
                }
            }
            if let Some(value) = labeled_value_anywhere(segment, name) {
                return Some(value);
            }
        }
    }
    None
}

fn labeled_value_anywhere(segment: &str, name: &str) -> Option<String> {
    let lower = segment.to_ascii_lowercase();
    for sep in [":", "="] {
        let pattern = format!("{}{}", name.to_ascii_lowercase(), sep);
        let Some(pos) = lower.find(&pattern) else {
            continue;
        };
        if pos > 0 {
            let before = lower[..pos].chars().next_back();
            if before.is_some_and(|ch| ch.is_ascii_alphanumeric()) {
                continue;
            }
        }
        let start = pos + pattern.len();
        let value = segment.get(start..)?.trim().trim_matches('"').trim();
        if !value.is_empty() && value != "-" {
            return Some(value.to_string());
        }
    }
    None
}

fn normalize_loose_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn xml_tag_value(text: &str, tag: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start_tag = format!("<{}>", tag.to_ascii_lowercase());
    let end_tag = format!("</{}>", tag.to_ascii_lowercase());
    let start = lower.find(&start_tag)? + start_tag.len();
    let end = lower[start..].find(&end_tag)? + start;
    let value = text.get(start..end)?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn script_path_like(text: &str) -> Option<String> {
    for token in text
        .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ',' | ';'))
    {
        let cleaned = token.trim().trim_matches(['(', ')', '{', '}', '[', ']']);
        let lower = cleaned.to_ascii_lowercase();
        let path_like = cleaned.contains('\\') || cleaned.contains('/') || cleaned.starts_with('.');
        if path_like
            && (lower.ends_with(".ps1")
                || lower.ends_with(".bat")
                || lower.ends_with(".cmd")
                || lower.ends_with(".vbs")
                || lower.ends_with(".js"))
        {
            return Some(cleaned.to_string());
        }
    }
    None
}

fn hash_like(text: &str) -> Option<String> {
    let mut current = String::new();
    for ch in text.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_hexdigit() {
            current.push(ch);
            continue;
        }
        if matches!(current.len(), 32 | 40 | 64) {
            return Some(current.to_ascii_uppercase());
        }
        current.clear();
    }
    None
}

fn trim_inline_labeled_value(value: &str, labels: &[&str]) -> String {
    let lower = value.to_ascii_lowercase();
    let mut end = value.len();
    for label in labels {
        if let Some(pos) = lower.find(label) {
            end = end.min(pos);
        }
    }
    value[..end]
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn truncate_candidate_value(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let mut out = value
        .chars()
        .take(limit.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

fn add_network_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let url = event
        .url
        .clone()
        .or_else(|| event_attr_string_from_value(attrs, &["url"]))
        .or_else(|| {
            let host = event_attr_string_from_value(attrs, &["host"]);
            let uri = event_attr_string_from_value(attrs, &["uri"]);
            match (host, uri) {
                (Some(host), Some(uri)) if uri.starts_with('/') => {
                    Some(format!("http://{host}{uri}"))
                }
                (Some(host), _) => Some(format!("http://{host}")),
                _ => None,
            }
        });
    if let Some(url) = url {
        let is_batch = url.to_ascii_lowercase().contains(".bat")
            || event.message_full.to_ascii_lowercase().contains("batch");
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "network.script_url",
                "スクリプト通信先URL候補",
                &url,
                if is_batch { 0.74 } else { 0.56 },
                if is_batch {
                    "candidate"
                } else {
                    "needs_review"
                },
                if suspicious_url_or_host(&url) {
                    "medium"
                } else {
                    "low"
                },
                "network",
                "PCAP/Zeek/TSharkから抽出したHTTP/URL通信候補",
                event,
                if is_batch {
                    vec!["BAT本体の復元結果とURLを突合"]
                } else {
                    vec!["このURLがbatch/script由来かをPCAP会話とファイル復元で確認"]
                },
                Some("URLでイベント一覧とnetwork_captureを横断検索"),
                serde_json::json!({ "source": "network_sidecar", "url": url }),
            ),
        );
    }

    if let Some(arg) = event_attr_string_from_value(attrs, &["arg", "ftp_arg", "remote_path"]) {
        if arg.contains('/') || arg.contains('\\') {
            push_answer_candidate(
                out,
                answer_candidate(
                    case_id,
                    "exfiltration.remote_path",
                    "外部送信先パス候補",
                    &arg,
                    0.66,
                    "needs_review",
                    "medium",
                    "exfiltration",
                    "FTP/PCAPから抽出したremote path候補",
                    event,
                    vec!["FTP commandのSTOR/RETR方向と認証ユーザーを確認"],
                    Some("Zeek ftp/http と FileZilla 設定復元を突合"),
                    serde_json::json!({ "source": "network_sidecar", "remote_path": arg }),
                ),
            );
        }
    }

    if event_attr_string_from_value(attrs, &["password_present"]).as_deref() == Some("true") {
        let user =
            event_attr_string_from_value(attrs, &["user"]).unwrap_or_else(|| "-".to_string());
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "credential_access.ftp_destination_secret",
                "FTP認証/送信先候補",
                &format!("FTP credential observed for user={user} / password=(redacted)"),
                0.72,
                "needs_approved_recovery",
                "high",
                "credential_access",
                "PCAPにFTP credentialが存在する可能性",
                event,
                vec!["承認済み手順でPCAP原本またはZeek ftp.logを確認"],
                Some("証拠範囲と監査ログを残してcredentialを確認"),
                serde_json::json!({ "password_present": true, "user": user }),
            ),
        );
    }

    if let Some(hash) = event
        .hash
        .clone()
        .or_else(|| event_attr_string_from_value(attrs, &["md5", "sha1", "sha256"]))
    {
        let file_path = event
            .file_path
            .clone()
            .or_else(|| event_attr_string_from_value(attrs, &["filename", "file_path"]));
        if file_path
            .as_deref()
            .map(|path| path.to_ascii_lowercase().ends_with(".bat"))
            .unwrap_or(false)
        {
            push_answer_candidate(
                out,
                answer_candidate(
                    case_id,
                    "file_recovery.script_hash",
                    "スクリプト/復元ファイルhash候補",
                    &hash,
                    if hash.len() == 32 { 0.76 } else { 0.58 },
                    "needs_review",
                    "medium",
                    "file_recovery",
                    "PCAP/Zeek files.logから抽出したbatch file hash候補",
                    event,
                    vec!["復元されたBAT本体のMD5と一致するか確認"],
                    Some("network_file_transfer と復元ファイルを突合"),
                    serde_json::json!({ "hash": hash, "file_path": file_path }),
                ),
            );
        }
    }
}

fn add_archive_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let mut members = attrs
        .get("candidate_members")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Some(member) = event_attr_string_from_value(attrs, &["member_path"]) {
        members.push(member);
    }
    members.sort();
    members.dedup();

    let suspicious = members
        .iter()
        .filter(|member| suspicious_archive_member(member))
        .cloned()
        .collect::<Vec<_>>();
    let hay = format!(
        "{} {} {}",
        event.message_full,
        event.file_path.as_deref().unwrap_or_default(),
        suspicious.join(" ")
    )
    .to_ascii_lowercase();

    if hay.contains("cve-2023-38831")
        || hay.contains(".rar")
        || hay.contains("winrar")
        || (suspicious.iter().any(|member| member.contains(' ')) && suspicious.len() >= 2)
    {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "exploit.cve_candidate",
                "悪用脆弱性候補",
                "CVE-2023-38831",
                if hay.contains("cve-2023-38831") {
                    0.78
                } else {
                    0.58
                },
                "needs_review",
                "medium",
                "exploit",
                "アーカイブ構造/WinRAR exploit候補",
                event,
                vec!["展開順序、偽装拡張子、実際に実行されたpayloadを確認"],
                Some("archive sidecar、RecentDocs、Prefetch、MFTを突合"),
                serde_json::json!({ "candidate_members": suspicious }),
            ),
        );
    }

    if let Some(member) = suspicious
        .iter()
        .find(|member| member.to_ascii_lowercase().ends_with(".bat"))
    {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "file_recovery.script_hash",
                "スクリプト/復元ファイルhash候補",
                "復元されたBATのMD5確認待ち",
                0.42,
                "needs_recovery",
                "medium",
                "file_recovery",
                "アーカイブ内にBAT復元候補",
                event,
                vec![
                    "隔離された証拠作業領域でBATを復元",
                    "復元ファイルのMD5を計算",
                ],
                Some("archive memberを復元してhashを算出"),
                serde_json::json!({ "member_path": member }),
            ),
        );
    }
}

fn add_recovered_content_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let path = event
        .file_path
        .clone()
        .or_else(|| event_attr_string_from_value(attrs, &["recovered_path", "member_path", "path"]))
        .unwrap_or_else(|| "recovered content".to_string());
    let hash = event
        .hash
        .clone()
        .or_else(|| event_attr_string_from_value(attrs, &["sha256", "hash"]));
    let preview = event_attr_string_from_value(attrs, &["preview", "text_preview"])
        .map(|value| redact_secret_candidate(&truncate_str(&value, 160)));
    let is_ads = event.event_action.contains("ads") || path.to_ascii_lowercase().contains(":zone");
    let candidate_value = match (&hash, &preview) {
        (Some(hash), Some(preview)) => format!("{path} sha256={hash} preview={preview}"),
        (Some(hash), None) => format!("{path} sha256={hash}"),
        (None, Some(preview)) => format!("{path} preview={preview}"),
        (None, None) => path.clone(),
    };
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            if is_ads {
                "file_recovery.ads_or_zone_identifier"
            } else {
                "file_recovery.recovered_content"
            },
            if is_ads {
                "ADS/Zone.Identifier復元候補"
            } else {
                "復元ファイル/内容候補"
            },
            &candidate_value,
            if hash.is_some() { 0.82 } else { 0.68 },
            "candidate",
            if is_ads { "medium" } else { "high" },
            "file_recovery",
            "MFT resident/ADSまたはsidecar復元結果",
            event,
            vec!["証拠オブジェクトのpath/hash/previewと原本位置を確認"],
            Some("復元物、MFT、USN、実行履歴を時系列で突合"),
            serde_json::json!({
                "path": path,
                "sha256": hash,
                "preview": preview,
                "is_ads": is_ads,
            }),
        ),
    );
}

fn add_document_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let line = event_attr_string_from_value(attrs, &["line"])
        .or_else(|| event_attr_string_from_value(attrs, &["text_preview"]))
        .unwrap_or_else(|| event.message_short.clone());
    let redacted = redact_secret_candidate(&truncate_str(&line, 180));
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            "credential_access.document_secret",
            "文書内認証情報候補",
            &redacted,
            if contains_any(&line.to_ascii_lowercase(), &["password", "rdp", "admin"]) {
                0.68
            } else {
                0.45
            },
            "needs_review",
            "medium",
            "content_recovery",
            "文書本文/機微文字列候補",
            event,
            vec!["PDF/Office本文を開き、対象文書とRDP認証の関連を確認"],
            Some("document sidecarの本文抽出結果を確認"),
            serde_json::json!({ "redacted_preview": redacted }),
        ),
    );
    if contains_any(
        &line.to_ascii_lowercase(),
        &["ssn", "social security", "arthur"],
    ) {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "pii.document_identifier",
                "PII/個人情報候補",
                &redact_secret_candidate(&truncate_str(&line, 120)),
                0.62,
                "needs_review",
                "high",
                "pii",
                "SSN/PII候補を含む文書行",
                event,
                vec!["PIIは監査付き表示で確認"],
                Some("PII候補と文書パスを確認"),
                serde_json::json!({ "pii_candidate": true }),
            ),
        );
    }
    if contains_any(
        &line.to_ascii_lowercase(),
        &["app", "application", "project"],
    ) {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "business_context.internal_app_name",
                "内部アプリ/業務システム名候補",
                &truncate_str(&line, 120),
                0.5,
                "needs_review",
                "medium",
                "content_recovery",
                "内部アプリ/プロジェクト名候補を含む文書行",
                event,
                vec!["文書全体の文脈で候補名を確認"],
                Some("Tika本文抽出結果を確認"),
                serde_json::json!({ "project_candidate": true }),
            ),
        );
    }
}

fn add_credential_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let origin = event_attr_string_from_value(attrs, &["origin_url"]).or_else(|| event.url.clone());
    let username =
        event_attr_string_from_value(attrs, &["username"]).or_else(|| event.user_name.clone());
    let decrypted = event.event_action.ends_with("_decrypted")
        || event_attr_string_from_value(attrs, &["recovery_status"]).as_deref()
            == Some("decrypted_to_sidecar_workspace");
    let password_state = if decrypted {
        "(redacted; recovered in sidecar workspace)"
    } else {
        "(requires approved recovery)"
    };
    let value = match (origin.as_deref(), username.as_deref()) {
        (Some(origin), Some(user)) if !user.is_empty() => {
            format!("{origin} / user={user} / password={password_state}")
        }
        (Some(origin), _) => format!("{origin} / password={password_state}"),
        (_, Some(user)) if !user.is_empty() => {
            format!("user={user} / password={password_state}")
        }
        _ if decrypted => "credential store decrypted metadata is available".to_string(),
        _ => "credential store requires approved recovery".to_string(),
    };
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            "credential_access.approved_decryption_required",
            "管理者資格情報復号候補",
            &value,
            if decrypted { 0.82 } else { 0.58 },
            if decrypted {
                "candidate"
            } else {
                "needs_review"
            },
            "high",
            "credential_access",
            if decrypted {
                "Browser/KeePass/DPAPI資格情報の復号済みメタデータ"
            } else {
                "Browser/KeePass/DPAPI資格情報候補"
            },
            event,
            if decrypted {
                vec!["監査ログ付きでsidecar workspaceの復号結果を確認"]
            } else {
                vec!["承認済みDPAPI/KeePass復号workflowを実行"]
            },
            if decrypted {
                Some("復号結果のorigin/userとログオン/ブラウザ履歴を突合")
            } else {
                Some("credential sidecar結果とProtect/masterkeyを確認")
            },
            serde_json::json!({ "recovery_required": !decrypted, "decrypted": decrypted }),
        ),
    );
}

fn add_moveit_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    lower: &str,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    if lower.contains("move.aspx") {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "webshell.file_name",
                "Webshellファイル名候補",
                "move.aspx",
                0.9,
                "candidate",
                "high",
                "moveit_webshell",
                "MOVEit wwwroot/IIS/PowerShell履歴に出現するASPX webshell候補",
                event,
                vec!["MFT作成時刻、IIS初回アクセス、PowerShell取得コマンドを突合"],
                Some("move.aspx の同一ファイル名コンテキストを確認"),
                serde_json::json!({ "artifact": "moveit", "filename": "move.aspx" }),
            ),
        );
        let upload_time_context = event.artifact_type == "mft"
            || contains_any(lower, &["w3svc", "u_ex", "iis"]);
        if upload_time_context {
            push_answer_candidate(
                out,
                answer_candidate(
                    case_id,
                    "webshell.creation_or_upload_time",
                    "Webshell配置時刻候補",
                    &event.event_time_utc,
                    if event.artifact_type == "mft" {
                        0.78
                    } else {
                        0.62
                    },
                    "candidate",
                    "high",
                    "moveit_webshell",
                    "move.aspxに紐づく作成/HTTP/取得痕跡の時刻",
                    event,
                    vec!["MFT $SI/$FN、USN Close、IIS GET/POST のどれを正答基準にするか確認"],
                    Some("move.aspx のMFT/USN/IIS/PowerShellを時系列で確認"),
                    serde_json::json!({
                        "artifact_type": event.artifact_type,
                        "time_kind": event.time_kind,
                    }),
                ),
            );
        }
        if let Some(user_agent) = moveit_user_agent(event, attrs) {
            push_answer_candidate(
                out,
                answer_candidate(
                    case_id,
                    "web.user_agent_candidate",
                    "WebshellアクセスUser-Agent候補",
                    &user_agent,
                    0.74,
                    "candidate",
                    "medium",
                    "web",
                    "move.aspxアクセスに紐づくUser-Agent候補",
                    event,
                    vec!["GET/POST /move.aspx のIIS行で確認"],
                    Some("move.aspx と User-Agent を同一IIS行で確認"),
                    serde_json::json!({ "user_agent": user_agent }),
                ),
            );
        }
    }

    if lower.contains("ruby") {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "web.initial_access_user_agent",
                "初期アクセスUser-Agent候補",
                &moveit_user_agent(event, attrs).unwrap_or_else(|| "Ruby".to_string()),
                0.78,
                "candidate",
                "medium",
                "web",
                "MOVEit API/guestaccessアクセスにRuby系User-Agentが出現",
                event,
                vec!["初回のMOVEit API/guestaccessアクセスであることをIIS時刻で確認"],
                Some("Ruby User-Agent と api/v1/token/guestaccess.aspx を突合"),
                serde_json::json!({ "matched": "ruby_user_agent" }),
            ),
        );
    }

    if lower.contains("nmap") {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "recon.tool_candidate",
                "初期偵察ツール候補",
                "Nmap",
                0.84,
                "candidate",
                "medium",
                "recon",
                "IIS User-AgentにNmap Scripting Engineが出現",
                event,
                vec!["WinSxS等の文字列ノイズではなくIISアクセスログのUser-Agentで確認"],
                Some("Nmap User-Agent の最初のIISアクセスを確認"),
                serde_json::json!({ "matched": "nmap_user_agent" }),
            ),
        );
    }

    if lower.contains("moveit.asp") {
        let size = moveit_file_size_candidate(event, attrs)
            .unwrap_or_else(|| "(未確定: MFT/Defender quarantine/USN復元が必要)".to_string());
        let resolved = !size.starts_with("(未確定");
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "file_recovery.suspicious_webshell_size",
                "失敗/隔離Webshellサイズ候補",
                &size,
                if resolved { 0.82 } else { 0.35 },
                if resolved {
                    "candidate"
                } else {
                    "needs_recovery"
                },
                "high",
                "file_recovery",
                "moveit.aspの取得/検知/隔離痕跡",
                event,
                vec!["MFT file size、USN close/delete、Defender quarantine metadataを確認"],
                Some("moveit.asp のMFT/USN/Defenderイベントを確認"),
                serde_json::json!({
                    "filename": "moveit.asp",
                    "size_status": if resolved { "candidate" } else { "missing" },
                }),
            ),
        );
    }

    if let Some(inst_id) = extract_moveit_inst_id(&event.message_full)
        .or_else(|| extract_moveit_inst_id(&event.message_short))
        .or_else(|| extract_moveit_inst_id(&event.attributes_json))
    {
        let attack_context = contains_any(
            lower,
            &[
                "guestaccess.aspx",
                "api/v1/token",
                "move.aspx",
                "wwwfileaudit",
            ],
        );
        if attack_context {
            push_answer_candidate(
                out,
                answer_candidate(
                    case_id,
                    "application.audit_identifier",
                    "アプリケーション監査ID候補",
                    &inst_id,
                    0.76,
                    "candidate",
                    "medium",
                    "moveit",
                    "MOVEit InstLogos/SQL監査に現れるInstID候補",
                    event,
                    vec!["MOVEit SQL wwwfileaudit とIIS画像アクセスを突合"],
                    Some("InstIDでSQL/IISを横断検索"),
                    serde_json::json!({ "inst_id": inst_id }),
                ),
            );
        }
    }

    if let Some(command) = extract_moveit_download_command(&event.message_full)
        .or_else(|| extract_moveit_download_command(&event.message_short))
        .or_else(|| extract_moveit_download_command(&event.attributes_json))
    {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "webshell.retrieval_command",
                "Webshell取得コマンド候補",
                &command,
                0.88,
                "candidate",
                "high",
                "execution",
                "PSReadLine/ConsoleHost履歴に残るwebshell取得コマンド",
                event,
                vec!["PowerShell履歴のユーザー、作業ディレクトリ、前後コマンドを確認"],
                Some("ConsoleHost_history.txt の前後行を確認"),
                serde_json::json!({ "command": command }),
            ),
        );
    }

    if (lower.contains("webshell") || lower.contains("backdoor:asp"))
        && (lower.contains("defender") || lower.contains("quarantine"))
    {
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "webshell.content_recovery",
                "Webshell本文復元候補",
                "(未確定: Defender隔離/削除ファイル/メモリからwebshell本文復元が必要)",
                0.3,
                "needs_recovery",
                "high",
                "file_recovery",
                "Defenderがwebshell/backdoorを検知・隔離した痕跡",
                event,
                vec!["Defender quarantine復元、USN/MFT carving、vmem stringsを実施"],
                Some("隔離/削除復元sidecarを実行してwebshell本文を確認"),
                serde_json::json!({ "recovery_required": true, "target": "webshell_title" }),
            ),
        );
    }
}

fn add_moveit_rdp_chain_answer_candidates(
    case_id: &str,
    events: &[EventFull],
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let password_reset_anchor_ts = moveit_password_reset_anchor_timestamp(events);
    let anchor_ts = password_reset_anchor_ts.or_else(|| moveit_attack_anchor_timestamp(events));
    let max_window_seconds = if password_reset_anchor_ts.is_some() {
        21_600
    } else {
        86_400
    };
    let mut ranked = events
        .iter()
        .filter_map(|event| {
            let attrs = serde_json::from_str::<serde_json::Value>(&event.attributes_json)
                .unwrap_or_else(|_| serde_json::json!({}));
            let lower = answer_event_text(event, &attrs).to_ascii_lowercase();
            if !is_moveit_rdp_answer_event(event, &attrs, &lower) {
                return None;
            }
            let event_ts = parse_utc(&event.event_time_utc)
                .ok()
                .map(|value| value.timestamp());
            let distance = anchor_ts
                .zip(event_ts)
                .map(|(anchor, event)| event - anchor)
                .unwrap_or(i64::MAX);
            if anchor_ts.is_some()
                && (distance == i64::MAX
                    || distance < 0
                    || distance > max_window_seconds)
            {
                return None;
            }
            let score = moveit_rdp_answer_score(event, &attrs, &lower, distance);
            if score < 45 {
                return None;
            }
            Some((score, distance.abs(), event.event_time_utc.clone(), event))
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    let mut emitted_times = HashSet::new();
    for (score, _distance, _time, event) in ranked.into_iter().take(5) {
        if !emitted_times.insert(event.event_time_utc.clone()) {
            continue;
        }
        let attrs = serde_json::from_str::<serde_json::Value>(&event.attributes_json)
            .unwrap_or_else(|_| serde_json::json!({}));
        let confidence = (0.62_f64 + (score as f64 / 220.0)).min(0.9);
        add_moveit_rdp_answer_candidates(case_id, event, &attrs, confidence, out);
    }
}

fn add_moveit_account_change_answer_candidates(
    case_id: &str,
    events: &[EventFull],
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    let Some(anchor_ts) = moveit_attack_anchor_timestamp(events) else {
        return;
    };
    let mut ranked = events
        .iter()
        .filter_map(|event| {
            let attrs = serde_json::from_str::<serde_json::Value>(&event.attributes_json)
                .unwrap_or_else(|_| serde_json::json!({}));
            let lower = answer_event_text(event, &attrs).to_ascii_lowercase();
            if !is_moveit_password_reset_event(&lower) {
                return None;
            }
            let event_ts = parse_utc(&event.event_time_utc)
                .ok()
                .map(|value| value.timestamp())?;
            let distance = event_ts - anchor_ts;
            if !(0..=86_400).contains(&distance) {
                return None;
            }
            let mut score = 70;
            if lower.contains("4724") {
                score += 20;
            }
            if lower.contains("forcechangepassword") {
                score += 10;
            }
            if (0..=7_200).contains(&distance) {
                score += 15;
            }
            Some((score, distance, event.event_time_utc.clone(), event))
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    let mut emitted_times = HashSet::new();
    for (_score, _distance, _time, event) in ranked.into_iter().take(3) {
        if !emitted_times.insert(event.event_time_utc.clone()) {
            continue;
        }
        push_answer_candidate(
            out,
            answer_candidate(
                case_id,
                "account.service_account_password_change_time",
                "サービスアカウント変更時刻候補",
                &event.event_time_utc,
                0.88,
                "candidate",
                "high",
                "account",
                "攻撃開始後のSecurity 4724/ForceChangePassword系moveitsvc対象イベント",
                event,
                vec!["対象SID、実行者、同時刻の4624/4672/管理操作を確認"],
                Some("moveitsvc と EID 4724 の前後イベントを確認"),
                serde_json::json!({ "event_id": "4724", "target_user": "moveitsvc" }),
            ),
        );
    }
}

fn moveit_attack_anchor_timestamp(events: &[EventFull]) -> Option<i64> {
    events
        .iter()
        .filter_map(|event| {
            let attrs = serde_json::from_str::<serde_json::Value>(&event.attributes_json)
                .unwrap_or_else(|_| serde_json::json!({}));
            let lower = answer_event_text(event, &attrs).to_ascii_lowercase();
            let moveit_attack_signal = contains_any(
                &lower,
                &[
                    "guestaccess.aspx",
                    "api/v1/token",
                    "move.aspx",
                    "moveit.asp",
                ],
            );
            if moveit_attack_signal {
                parse_utc(&event.event_time_utc)
                    .ok()
                    .map(|value| value.timestamp())
            } else {
                None
            }
        })
        .min()
}

fn moveit_password_reset_anchor_timestamp(events: &[EventFull]) -> Option<i64> {
    let attack_anchor_ts = moveit_attack_anchor_timestamp(events)?;
    events
        .iter()
        .filter_map(|event| {
            let attrs = serde_json::from_str::<serde_json::Value>(&event.attributes_json)
                .unwrap_or_else(|_| serde_json::json!({}));
            let lower = answer_event_text(event, &attrs).to_ascii_lowercase();
            if !is_moveit_password_reset_event(&lower) {
                return None;
            }
            let event_ts = parse_utc(&event.event_time_utc)
                .ok()
                .map(|value| value.timestamp())?;
            let distance = event_ts - attack_anchor_ts;
            if (0..=86_400).contains(&distance) {
                Some(event_ts)
            } else {
                None
            }
        })
        .min()
}

fn is_moveit_password_reset_event(lower: &str) -> bool {
    lower.contains("moveitsvc")
        && (lower.contains("4724")
            || lower.contains("forcechangepassword")
            || lower.contains("password reset")
            || lower.contains("password changed"))
}

fn is_moveit_rdp_answer_event(event: &EventFull, attrs: &serde_json::Value, lower: &str) -> bool {
    is_rdp_logon_candidate(event, attrs, lower)
        || lower.contains("remoteconnectionmanager")
        || (lower.contains("terminalservices") && lower.contains("1149"))
        || (lower.contains("logontype") && lower.contains("10"))
}

fn moveit_rdp_answer_score(
    event: &EventFull,
    attrs: &serde_json::Value,
    lower: &str,
    distance_from_anchor_seconds: i64,
) -> i32 {
    let mut score = 0;
    if is_rdp_logon_candidate(event, attrs, lower) {
        score += 40;
    }
    if lower.contains("remoteconnectionmanager") {
        score += 25;
    }
    if lower.contains("terminalservices") {
        score += 20;
    }
    if lower.contains("1149") {
        score += 20;
    }
    if lower.contains("logontype") && lower.contains("10") {
        score += 15;
    }
    if lower.contains("moveitsvc") {
        score += 25;
    }
    if (0..=21_600).contains(&distance_from_anchor_seconds) {
        score += 20;
    } else if (0..=86_400).contains(&distance_from_anchor_seconds) {
        score += 10;
    }
    score
}

fn add_moveit_rdp_answer_candidates(
    case_id: &str,
    event: &EventFull,
    _attrs: &serde_json::Value,
    confidence: f64,
    out: &mut HashMap<(String, String), AnswerCandidate>,
) {
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            "remote_access.protocol",
            "リモート接続プロトコル候補",
            "RDP",
            confidence.max(0.82),
            "candidate",
            "high",
            "remote_access",
            "TerminalServices 1149 / LogonType 10系のリモート接続痕跡",
            event,
            vec!["1149、4624 LogonType 10、LocalSessionManagerを突合"],
            Some("RDP接続カードで同一ユーザー/IPの時系列を確認"),
            serde_json::json!({ "protocol": "RDP" }),
        ),
    );
    push_answer_candidate(
        out,
        answer_candidate(
            case_id,
            "remote_access.time",
            "リモートアクセス時刻候補",
            &event.event_time_utc,
            confidence,
            "candidate",
            "high",
            "remote_access",
            "RDP認証/接続イベントの時刻",
            event,
            vec!["初回アクセスか再接続かを同一IP/ユーザーで確認"],
            Some("RDP周辺の前後15分イベントを確認"),
            serde_json::json!({
                "user": event.user_name,
                "ip": event.ip,
            }),
        ),
    );
}

fn add_rdp_answer_candidates(
    case_id: &str,
    event: &EventFull,
    attrs: &serde_json::Value,
    out: &mut HashMap<(String, String), AnswerCandidate>,
    confidence: f64,
) {
    add_moveit_rdp_answer_candidates(case_id, event, attrs, confidence, out);
}

fn is_rdp_logon_candidate(event: &EventFull, attrs: &serde_json::Value, lower: &str) -> bool {
    let logon_type =
        event_attr_string_from_value(attrs, &["LogonType", "logon_type"]).unwrap_or_default();
    logon_type == "10"
        || (lower.contains("remoteconnectionmanager") && lower.contains("1149"))
        || (event
            .event_action
            .to_ascii_lowercase()
            .contains("windows_event")
            && lower.contains("logontype")
            && lower.contains("10"))
        || (lower.contains("logontype")
            && lower.contains("10")
            && (lower.contains("4624") || lower.contains("security")))
}

fn semantic_kind(attrs: &serde_json::Value) -> Option<&str> {
    attrs
        .get("semantics")
        .and_then(|semantics| semantics.get("event_kind"))
        .and_then(serde_json::Value::as_str)
}

fn semantic_string(attrs: &serde_json::Value, key: &str) -> Option<String> {
    attrs
        .get("semantics")
        .and_then(|semantics| semantics.get(key))
        .and_then(json_value_string)
}

fn semantic_label(attrs: &serde_json::Value, label: &str) -> bool {
    attrs
        .get("semantics")
        .and_then(|semantics| semantics.get("labels"))
        .and_then(serde_json::Value::as_array)
        .map(|labels| labels.iter().any(|value| value.as_str() == Some(label)))
        .unwrap_or(false)
}

fn semantic_labels(attrs: &serde_json::Value) -> Vec<String> {
    attrs
        .get("semantics")
        .and_then(|semantics| semantics.get("labels"))
        .and_then(serde_json::Value::as_array)
        .map(|labels| {
            labels
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn answer_event_text(event: &EventFull, attrs: &serde_json::Value) -> String {
    let mut parts = vec![
        event.artifact_type.clone(),
        event.event_action.clone(),
        event.severity.clone(),
        event.message_short.clone(),
        event.message_full.clone(),
        event.attributes_json.clone(),
    ];
    for value in [
        event.host.as_deref(),
        event.user_name.as_deref(),
        event.process_name.as_deref(),
        event.file_path.as_deref(),
        event.ip.as_deref(),
        event.url.as_deref(),
        event.hash.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        parts.push(value.to_string());
    }
    if let Some(data) = attrs.get("data") {
        if let Ok(text) = serde_json::to_string(data) {
            parts.push(text);
        }
    }
    parts.join(" ")
}

fn filename_from_path(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\'])
        .next()
        .filter(|value| !value.is_empty())
}

fn moveit_user_agent(event: &EventFull, attrs: &serde_json::Value) -> Option<String> {
    event_attr_string_from_value(
        attrs,
        &[
            "user_agent",
            "UserAgent",
            "User-Agent",
            "cs(User-Agent)",
            "cs_user_agent",
            "useragent",
        ],
    )
    .or_else(|| {
        let lower = format!(
            "{} {} {}",
            event.message_full, event.message_short, event.attributes_json
        )
        .to_ascii_lowercase();
        if lower.contains("nmap scripting engine") {
            Some(
                "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
                    .to_string(),
            )
        } else if lower.contains("ruby") {
            Some("Ruby".to_string())
        } else if lower.contains("firefox") && lower.contains("linux") {
            Some("Firefox/Linux".to_string())
        } else {
            None
        }
    })
}

fn moveit_file_size_candidate(event: &EventFull, attrs: &serde_json::Value) -> Option<String> {
    event_attr_string_from_value(
        attrs,
        &[
            "file_size",
            "FileSize",
            "size",
            "Size",
            "file_size_bytes",
            "FileSizeBytes",
            "logical_size",
        ],
    )
    .or_else(|| {
        let text = format!(
            "{} {} {}",
            event.message_full, event.message_short, event.attributes_json
        );
        extract_size_near_moveit_asp(&text)
    })
}

fn extract_size_near_moveit_asp(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("moveit.asp")?;
    let window = &text[start..text.len().min(start + 320)];
    for key in ["file_size", "filesize", "size", "length"] {
        let Some(pos) = window.to_ascii_lowercase().find(key) else {
            continue;
        };
        if let Some(value) = first_number_after(&window[pos + key.len()..]) {
            return Some(value);
        }
    }
    None
}

fn extract_moveit_inst_id(text: &str) -> Option<String> {
    for marker in ["logobig_", "logoright_", "instid=", "instid:", "inst id "] {
        if let Some(pos) = text.to_ascii_lowercase().find(marker) {
            if let Some(value) = first_number_after(&text[pos + marker.len()..]) {
                if value != "0" && value.len() >= 2 {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn extract_moveit_download_command(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if (lower.contains("wget ")
            || lower.contains("invoke-webrequest")
            || lower.contains("curl "))
            && (lower.contains("move.aspx") || lower.contains("moveit.asp"))
        {
            return Some(truncate_str(line.trim(), 240));
        }
    }
    let lower = text.to_ascii_lowercase();
    if (lower.contains("wget ") || lower.contains("invoke-webrequest") || lower.contains("curl "))
        && (lower.contains("move.aspx") || lower.contains("moveit.asp"))
    {
        return Some(truncate_str(text.trim(), 240));
    }
    None
}

fn first_number_after(text: &str) -> Option<String> {
    let mut started = false;
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            started = true;
            out.push(ch);
        } else if started {
            break;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn redact_secret_candidate(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("password") || lower.contains("passwd") || lower.contains("pwd") {
        return format!("{} [secret-redacted]", truncate_str(trimmed, 80));
    }
    if trimmed.len() > 24 && trimmed.chars().any(|ch| ch.is_ascii_digit()) {
        return format!("{}...", trimmed.chars().take(8).collect::<String>());
    }
    truncate_str(trimmed, 120)
}

fn stable_prefixed_id(prefix: &str, value: &str) -> String {
    let digest = hex_digest(value.as_bytes());
    format!("{prefix}_{}", &digest[..32])
}

fn merge_json_string_arrays(left: &str, right: &str) -> String {
    let mut values = json_string_values(left);
    for value in json_string_values(right) {
        if values.len() >= MAX_ANSWER_CANDIDATE_EVIDENCE_VALUES {
            break;
        }
        if !values.iter().any(|existing| existing == &value) {
            values.push(value);
        }
    }
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

fn min_opt_time(left: Option<&str>, right: Option<&str>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left <= right { left } else { right }.to_string()),
        (Some(value), None) | (None, Some(value)) => Some(value.to_string()),
        (None, None) => None,
    }
}

fn max_opt_time(left: Option<&str>, right: Option<&str>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left >= right { left } else { right }.to_string()),
        (Some(value), None) | (None, Some(value)) => Some(value.to_string()),
        (None, None) => None,
    }
}

fn moveit_recovery_gap_candidates(case_id: &str) -> Vec<AnswerCandidate> {
    [
        (
            "file_recovery.suspicious_webshell_size",
            "失敗/隔離Webshellサイズ候補",
            "MFT file size、USN close/delete、Defender quarantine metadataの復元が必要",
        ),
        (
            "webshell.content_recovery",
            "Webshell本文復元候補",
            "Defender隔離、削除ファイル、またはメモリからwebshell本文復元が必要",
        ),
        (
            "credential_access.service_account_password_recovery_required",
            "サービスアカウント変更後パスワード復元候補",
            "EVTX 4724には新パスワードが残らないため、vmem/credential/command履歴の承認済み復元が必要",
        ),
    ]
    .into_iter()
    .map(|(key, label, missing)| {
        let seed = format!("{case_id}|{key}|recovery_gap");
        AnswerCandidate {
            candidate_id: stable_prefixed_id("answer", &seed),
            case_id: case_id.to_string(),
            question_key: key.to_string(),
            question_label: label.to_string(),
            candidate_value: "要復元/復号".to_string(),
            confidence: 0.0,
            status: "needs_recovery".to_string(),
            severity: "high".to_string(),
            category: "gap".to_string(),
            reason: "確定には追加の復元、復号、または外部worker処理が必要".to_string(),
            evidence_event_ids_json: "[]".to_string(),
            evidence_refs_json: "[]".to_string(),
            missing_steps_json: serde_json::to_string(&vec![missing])
                .unwrap_or_else(|_| "[]".to_string()),
            next_action: Some(missing.to_string()),
            first_seen_utc: None,
            last_seen_utc: None,
            attributes_json: serde_json::json!({
                "gap_candidate": true,
                "scenario": "incident_response_recovery_gap",
                "source_context": "moveit_indicators"
            })
            .to_string(),
        }
    })
    .collect()
}

fn out_insert_missing(rows: &mut Vec<AnswerCandidate>, candidate: AnswerCandidate) {
    if !rows
        .iter()
        .any(|row| row.question_key == candidate.question_key)
    {
        rows.push(candidate);
    }
}

fn finding_overrides_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace.root().join("meta").join("finding_overrides.json")
}

fn load_finding_overrides(workspace: &CaseWorkspace) -> Result<Vec<FindingOverride>> {
    let path = finding_overrides_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice::<Vec<FindingOverride>>(&fs::read(
        path,
    )?)?)
}

fn save_finding_overrides(workspace: &CaseWorkspace, rows: &[FindingOverride]) -> Result<()> {
    let path = finding_overrides_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(rows)?)?;
    Ok(())
}

fn ioc_indicators_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace.root().join("meta").join("ioc_indicators.json")
}

fn load_ioc_indicators(workspace: &CaseWorkspace) -> Result<Vec<String>> {
    let path = ioc_indicators_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let rows = serde_json::from_slice::<Vec<String>>(&fs::read(path)?)?;
    Ok(normalize_ioc_indicators(&rows, 500))
}

fn save_ioc_indicators(workspace: &CaseWorkspace, rows: &[String]) -> Result<()> {
    let path = ioc_indicators_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(rows)?)?;
    Ok(())
}

fn normalize_ioc_indicators(indicators: &[String], limit: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for indicator in indicators
        .iter()
        .map(|value| value.trim())
        .filter(|value| value.chars().count() >= 3)
    {
        let key = indicator.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(indicator.to_string());
        }
        if out.len() >= limit.clamp(1, 500) {
            break;
        }
    }
    out
}

fn event_bookmarks_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace.root().join("meta").join("bookmarks.json")
}

fn case_custody_profile_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace
        .root()
        .join("meta")
        .join("case_custody_profile.json")
}

fn default_case_custody_profile(workspace: &CaseWorkspace) -> CaseCustodyProfile {
    CaseCustodyProfile {
        case_id: workspace.manifest().case_id.clone(),
        investigator: None,
        custodian: None,
        organization: None,
        evidence_source: None,
        acquisition_method: None,
        acquired_at: None,
        legal_authority: None,
        chain_of_custody_note: None,
        updated_at: workspace.manifest().created_at.clone(),
    }
}

fn load_case_custody_profile(workspace: &CaseWorkspace) -> Result<CaseCustodyProfile> {
    let path = case_custody_profile_path(workspace);
    if !path.exists() {
        return Ok(default_case_custody_profile(workspace));
    }
    let mut profile = serde_json::from_slice::<CaseCustodyProfile>(&fs::read(path)?)?;
    if profile.case_id != workspace.manifest().case_id {
        profile.case_id = workspace.manifest().case_id.clone();
    }
    Ok(profile)
}

fn save_case_custody_profile(
    workspace: &CaseWorkspace,
    profile: &CaseCustodyProfile,
) -> Result<()> {
    let path = case_custody_profile_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(profile)?)?;
    Ok(())
}

fn report_signing_key_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace
        .root()
        .join("meta")
        .join("report_signing_key.json")
}

fn load_report_signing_key(workspace: &CaseWorkspace) -> Result<Option<ReportSigningKeyRecord>> {
    let path = report_signing_key_path(workspace);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice::<ReportSigningKeyRecord>(
        &fs::read(path)?,
    )?))
}

fn load_or_create_report_signing_key(
    workspace: &CaseWorkspace,
) -> Result<(ReportSigningKeyRecord, bool)> {
    if let Some(record) = load_report_signing_key(workspace)? {
        return Ok((record, false));
    }
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|error| {
        ApiError::InvalidRequest(format!("failed to create signing key: {error}"))
    })?;
    let signing_key = SigningKey::from_bytes(&secret);
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_sha256 = sha256_bytes(&public_key);
    let record = ReportSigningKeyRecord {
        key_id: format!("ed25519:{}", &public_key_sha256[..16]),
        algorithm: "ed25519".to_string(),
        created_at: now_utc(),
        public_key_base64: BASE64_STANDARD.encode(public_key),
        secret_key_base64: BASE64_STANDARD.encode(secret),
    };
    let path = report_signing_key_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(&record)?)?;
    Ok((record, true))
}

fn sign_report_payload(
    record: &ReportSigningKeyRecord,
    payload_bytes: &[u8],
    payload_sha256: &str,
) -> Result<ReportBundleSignature> {
    if record.algorithm != "ed25519" {
        return Err(ApiError::InvalidRequest(format!(
            "unsupported report signing algorithm: {}",
            record.algorithm
        )));
    }
    let secret = decode_base64_array::<32>("report signing secret key", &record.secret_key_base64)?;
    let signing_key = SigningKey::from_bytes(&secret);
    let public_key = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());
    if public_key != record.public_key_base64 {
        return Err(ApiError::InvalidRequest(
            "report signing key public/private mismatch".to_string(),
        ));
    }
    let signature = signing_key.sign(payload_bytes);
    Ok(ReportBundleSignature {
        algorithm: record.algorithm.clone(),
        key_id: record.key_id.clone(),
        public_key_base64: record.public_key_base64.clone(),
        signed_sha256: payload_sha256.to_string(),
        signature_base64: BASE64_STANDARD.encode(signature.to_bytes()),
    })
}

fn verify_report_payload_signature(
    workspace: &CaseWorkspace,
    payload: &serde_json::Value,
    computed_payload_sha256: Option<&str>,
    signature_value: Option<&serde_json::Value>,
) -> ReportSignatureVerification {
    let Some(signature_value) = signature_value else {
        return ReportSignatureVerification {
            algorithm: None,
            key_id: None,
            present: false,
            payload_hash_ok: false,
            valid: false,
            key_matches_case_key: false,
        };
    };
    let signature = match serde_json::from_value::<ReportBundleSignature>(signature_value.clone()) {
        Ok(signature) => signature,
        Err(_) => {
            return ReportSignatureVerification {
                algorithm: json_string_at(signature_value, &["algorithm"]),
                key_id: json_string_at(signature_value, &["key_id"]),
                present: true,
                payload_hash_ok: false,
                valid: false,
                key_matches_case_key: false,
            };
        }
    };
    let payload_hash_ok = computed_payload_sha256.is_some()
        && computed_payload_sha256 == Some(signature.signed_sha256.as_str());
    let payload_signature_metadata_ok = payload.get("signature").is_some_and(|metadata| {
        metadata
            .get("algorithm")
            .and_then(serde_json::Value::as_str)
            == Some(signature.algorithm.as_str())
            && metadata.get("key_id").and_then(serde_json::Value::as_str)
                == Some(signature.key_id.as_str())
            && metadata
                .get("public_key_sha256")
                .and_then(serde_json::Value::as_str)
                == decode_base64_array::<32>(
                    "report signing public key",
                    &signature.public_key_base64,
                )
                .ok()
                .map(|public_key| sha256_bytes(&public_key))
                .as_deref()
    });
    let public_key =
        decode_base64_array::<32>("report signing public key", &signature.public_key_base64);
    let signature_bytes =
        decode_base64_array::<64>("report bundle signature", &signature.signature_base64);
    let signature_valid = payload_hash_ok
        && payload_signature_metadata_ok
        && public_key
            .as_ref()
            .ok()
            .and_then(|public_key| VerifyingKey::from_bytes(public_key).ok())
            .zip(signature_bytes.as_ref().ok().map(Signature::from_bytes))
            .and_then(|(verifying_key, signature)| {
                serde_json::to_vec_pretty(payload)
                    .ok()
                    .map(|payload_bytes| (verifying_key, signature, payload_bytes))
            })
            .is_some_and(|(verifying_key, signature, payload_bytes)| {
                verifying_key.verify(&payload_bytes, &signature).is_ok()
            });
    let key_matches_case_key = load_report_signing_key(workspace)
        .ok()
        .flatten()
        .is_some_and(|record| {
            record.algorithm == signature.algorithm
                && record.key_id == signature.key_id
                && record.public_key_base64 == signature.public_key_base64
        });
    ReportSignatureVerification {
        algorithm: Some(signature.algorithm),
        key_id: Some(signature.key_id),
        present: true,
        payload_hash_ok,
        valid: signature_valid,
        key_matches_case_key,
    }
}

fn load_event_bookmarks(workspace: &CaseWorkspace) -> Result<Vec<EventBookmark>> {
    let path = event_bookmarks_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice::<Vec<EventBookmark>>(&fs::read(
        path,
    )?)?)
}

fn save_event_bookmarks(workspace: &CaseWorkspace, rows: &[EventBookmark]) -> Result<()> {
    let path = event_bookmarks_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(rows)?)?;
    Ok(())
}

fn finding_reviews_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace.root().join("meta").join("finding_reviews.json")
}

fn case_approvals_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace.root().join("meta").join("case_approvals.json")
}

fn saved_searches_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace.root().join("meta").join("saved_searches.json")
}

fn load_case_approvals(workspace: &CaseWorkspace) -> Result<Vec<CaseApprovalRecord>> {
    let path = case_approvals_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice::<Vec<CaseApprovalRecord>>(
        &fs::read(path)?,
    )?)
}

fn save_case_approvals(workspace: &CaseWorkspace, rows: &[CaseApprovalRecord]) -> Result<()> {
    let path = case_approvals_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(rows)?)?;
    Ok(())
}

fn load_saved_searches(workspace: &CaseWorkspace) -> Result<Vec<SavedSearch>> {
    let path = saved_searches_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice::<Vec<SavedSearch>>(&fs::read(
        path,
    )?)?)
}

fn save_saved_searches(workspace: &CaseWorkspace, rows: &[SavedSearch]) -> Result<()> {
    let path = saved_searches_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(rows)?)?;
    Ok(())
}

fn load_finding_reviews(workspace: &CaseWorkspace) -> Result<Vec<FindingReview>> {
    let path = finding_reviews_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice::<Vec<FindingReview>>(&fs::read(
        path,
    )?)?)
}

fn save_finding_reviews(workspace: &CaseWorkspace, rows: &[FindingReview]) -> Result<()> {
    let path = finding_reviews_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(rows)?)?;
    Ok(())
}

fn build_triage_actions(
    workspace: &CaseWorkspace,
    limit: Option<usize>,
) -> Result<Vec<TriageAction>> {
    let limit = limit.unwrap_or(100).clamp(1, 500);
    let query = workspace.query_layer();
    let findings = query.finding_summary(Some(200))?;
    let chains = query.correlation_chains(Some(100))?;
    let failed_parsers = query.failed_parser_summary()?;
    let reviews = load_finding_reviews(workspace)?;
    let mut rows = Vec::new();
    let mut finding_source_keys = HashSet::new();

    for finding in findings {
        let source_key =
            finding_source_key(&finding.engine, finding.rule_id.as_deref(), &finding.title);
        finding_source_keys.insert(source_key.clone());
        let review = reviews.iter().find(|row| {
            row.engine == finding.engine
                && row.rule_id == finding.rule_id
                && row.title == finding.title
        });
        let status = review
            .map(|row| row.status.as_str())
            .filter(|status| !status.is_empty())
            .unwrap_or("new");
        if !is_open_review_status(status) {
            continue;
        }
        let overdue = review.is_some_and(|row| finding_review_is_overdue(row));
        let priority = severity_rank(&finding.severity) * 1_000
            + finding.event_count.clamp(0, 500)
            + if overdue { 700 } else { 0 }
            + if status == "needs_context" { 250 } else { 0 };
        rows.push(TriageAction {
            action_id: stable_triage_action_id("finding", &source_key),
            case_id: workspace.manifest().case_id.clone(),
            priority,
            category: "finding".to_string(),
            title: format!("検知確認: {}", finding.title),
            reason: finding
                .sample_message
                .clone()
                .unwrap_or_else(|| "Finding group requires review".to_string()),
            severity: finding.severity.clone(),
            status: status.to_string(),
            source_kind: "finding".to_string(),
            source_key,
            event_count: finding.event_count,
            first_seen_utc: finding.first_seen_utc.clone(),
            last_seen_utc: finding.last_seen_utc.clone(),
            evidence_json: serde_json::json!({
                "engine": finding.engine,
                "rule_id": finding.rule_id,
                "attack": finding.attack_json,
                "finding_count": finding.finding_count,
                "reviewer": review.and_then(|row| row.reviewer.as_deref()),
                "assignee": review.and_then(|row| row.assignee.as_deref()),
                "due_at": review.and_then(|row| row.due_at.as_deref()),
                "tags": review.map(finding_review_tags).unwrap_or_default(),
            })
            .to_string(),
        });
    }

    for chain in chains {
        if severity_rank(&chain.severity) < severity_rank("medium") {
            continue;
        }
        let source_key = format!("{}={}", chain.key_kind, chain.key_value);
        let priority = severity_rank(&chain.severity) * 900
            + chain.score.clamp(0, 2_000)
            + chain.event_count.clamp(0, 500);
        rows.push(TriageAction {
            action_id: stable_triage_action_id("correlation", &source_key),
            case_id: workspace.manifest().case_id.clone(),
            priority,
            category: "correlation".to_string(),
            title: format!("相関確認: {}", chain.title),
            reason: chain.explanation.clone(),
            severity: chain.severity.clone(),
            status: "open".to_string(),
            source_kind: "correlation_chain".to_string(),
            source_key,
            event_count: chain.event_count,
            first_seen_utc: Some(chain.first_seen_utc.clone()),
            last_seen_utc: Some(chain.last_seen_utc.clone()),
            evidence_json: serde_json::json!({
                "key_kind": chain.key_kind,
                "key_value": chain.key_value,
                "artifact_types": chain.artifact_types,
                "step_count": chain.step_count,
                "steps": chain.steps_json,
            })
            .to_string(),
        });
    }

    for failure in failed_parsers {
        let source_key = format!("{}:{}", failure.parser_name, failure.artifact_type);
        rows.push(TriageAction {
            action_id: stable_triage_action_id("parser_failure", &source_key),
            case_id: workspace.manifest().case_id.clone(),
            priority: 2_000 + (failure.failure_count * 25).clamp(0, 1_000),
            category: "parser_failure".to_string(),
            title: format!("パーサ失敗確認: {}", failure.artifact_type),
            reason: failure.last_error.clone(),
            severity: "medium".to_string(),
            status: "open".to_string(),
            source_kind: "parser_failure".to_string(),
            source_key,
            event_count: failure.failure_count,
            first_seen_utc: None,
            last_seen_utc: Some(failure.last_seen_at.clone()),
            evidence_json: serde_json::json!({
                "parser_name": failure.parser_name,
                "artifact_type": failure.artifact_type,
                "failure_count": failure.failure_count,
            })
            .to_string(),
        });
    }

    for review in reviews
        .iter()
        .filter(|row| is_open_review_status(&row.status))
        .filter(|row| {
            !finding_source_keys.contains(&finding_source_key(
                &row.engine,
                row.rule_id.as_deref(),
                &row.title,
            ))
        })
    {
        let source_key =
            finding_source_key(&review.engine, review.rule_id.as_deref(), &review.title);
        let overdue = finding_review_is_overdue(review);
        rows.push(TriageAction {
            action_id: stable_triage_action_id("review", &source_key),
            case_id: workspace.manifest().case_id.clone(),
            priority: 2_600 + if overdue { 700 } else { 0 },
            category: "review".to_string(),
            title: format!("レビュー未完了: {}", review.title),
            reason: review.comment.clone().unwrap_or_else(|| {
                "Review remains open but current finding summary did not include it".to_string()
            }),
            severity: if overdue { "high" } else { "medium" }.to_string(),
            status: review.status.clone(),
            source_kind: "finding_review".to_string(),
            source_key,
            event_count: 0,
            first_seen_utc: None,
            last_seen_utc: Some(review.updated_at.clone()),
            evidence_json: serde_json::json!({
                "engine": review.engine,
                "rule_id": review.rule_id,
                "reviewer": review.reviewer,
                "assignee": review.assignee,
                "due_at": review.due_at,
                "tags": finding_review_tags(review),
            })
            .to_string(),
        });
    }

    let evaluation = build_case_detection_evaluation(workspace)?;
    for gate in evaluation
        .quality_gates
        .iter()
        .filter(|gate| gate.status != "pass")
    {
        let source_key = gate.gate_id.clone();
        rows.push(TriageAction {
            action_id: stable_triage_action_id("quality_gate", &source_key),
            case_id: workspace.manifest().case_id.clone(),
            priority: severity_rank(&gate.severity) * 850
                + if gate.status == "fail" { 600 } else { 250 },
            category: format!("quality_{}", gate.category),
            title: format!("品質ゲート確認: {}", gate.title),
            reason: gate.detail.clone(),
            severity: gate.severity.clone(),
            status: gate.status.clone(),
            source_kind: "case_quality_gate".to_string(),
            source_key,
            event_count: 0,
            first_seen_utc: None,
            last_seen_utc: Some(evaluation.evaluated_at.clone()),
            evidence_json: serde_json::json!({
                "gate_id": gate.gate_id,
                "category": gate.category,
                "metric": gate.metric,
                "recommended_action": gate.recommended_action,
                "overall_score": evaluation.overall_score,
                "detection_coverage_rate": evaluation.detection_coverage_rate,
                "investigation_readiness_score": evaluation.investigation_readiness_score,
                "report_quality_score": evaluation.report_quality_score,
            })
            .to_string(),
        });
    }

    rows.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| severity_rank(&right.severity).cmp(&severity_rank(&left.severity)))
            .then_with(|| right.event_count.cmp(&left.event_count))
            .then_with(|| right.last_seen_utc.cmp(&left.last_seen_utc))
            .then_with(|| left.title.cmp(&right.title))
    });
    rows.truncate(limit);
    Ok(rows)
}

fn finding_source_key(engine: &str, rule_id: Option<&str>, title: &str) -> String {
    format!("{}:{}:{}", engine, rule_id.unwrap_or("-"), title)
}

fn stable_triage_action_id(category: &str, source_key: &str) -> String {
    let digest = sha256_bytes(format!("{category}\0{source_key}").as_bytes());
    format!("triage_{}", &digest[..16])
}

fn finding_review_is_overdue(row: &FindingReview) -> bool {
    row.due_at
        .as_deref()
        .and_then(|value| parse_utc(value).ok())
        .is_some_and(|due_at| due_at < Utc::now())
}

fn audit_log_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace.root().join("meta").join("audit_log.jsonl")
}

fn append_audit_log(
    workspace: &CaseWorkspace,
    action: &str,
    target_kind: &str,
    target_id: Option<&str>,
    summary: &str,
    metadata: serde_json::Value,
) -> Result<()> {
    let path = audit_log_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    let row = AuditLogEntry {
        audit_id: new_id("audit"),
        case_id: workspace.manifest().case_id.clone(),
        occurred_at: now_utc(),
        actor: "local_analyst".to_string(),
        action: action.to_string(),
        target_kind: target_kind.to_string(),
        target_id: target_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        summary: summary.to_string(),
        metadata_json: metadata.to_string(),
    };
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", serde_json::to_string(&row)?)?;
    Ok(())
}

fn load_audit_log(workspace: &CaseWorkspace, limit: Option<usize>) -> Result<Vec<AuditLogEntry>> {
    let path = audit_log_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut rows = Vec::new();
    for line in fs::read_to_string(path)?.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        rows.push(serde_json::from_str::<AuditLogEntry>(line)?);
    }
    rows.reverse();
    rows.truncate(limit.unwrap_or(200).clamp(1, 1000));
    Ok(rows)
}

fn evidence_verification_path(workspace: &CaseWorkspace) -> std::path::PathBuf {
    workspace
        .root()
        .join("meta")
        .join("evidence_verification.json")
}

fn load_latest_evidence_verification(
    workspace: &CaseWorkspace,
) -> Result<Vec<EvidenceVerification>> {
    let path = evidence_verification_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice::<Vec<EvidenceVerification>>(
        &fs::read(path)?,
    )?)
}

fn save_latest_evidence_verification(
    workspace: &CaseWorkspace,
    rows: &[EvidenceVerification],
) -> Result<()> {
    let path = evidence_verification_path(workspace);
    fs::create_dir_all(path.parent().unwrap_or_else(|| workspace.root()))?;
    fs::write(path, serde_json::to_vec_pretty(rows)?)?;
    Ok(())
}

fn verify_file_record(
    workspace: &CaseWorkspace,
    file: &FileRecord,
    checked_at: &str,
) -> EvidenceVerification {
    match workspace
        .raw_object_store()
        .read_range(&file.object_ref, 0, 0)
    {
        Ok((object, _)) => match hash_file(&object.path) {
            Ok(actual_sha256) => {
                let hash_ok = actual_sha256.eq_ignore_ascii_case(&file.sha256)
                    && actual_sha256.eq_ignore_ascii_case(&object.sha256);
                let size_ok = object.size == file.size;
                let verified = hash_ok && size_ok;
                EvidenceVerification {
                    file_id: file.file_id.clone(),
                    original_path: file.original_path.clone(),
                    object_ref: file.object_ref.clone(),
                    expected_sha256: file.sha256.clone(),
                    actual_sha256: Some(actual_sha256),
                    size: file.size,
                    verified,
                    error_message: if verified {
                        None
                    } else if !hash_ok {
                        Some("sha256 mismatch".to_string())
                    } else {
                        Some(format!(
                            "size mismatch: expected {}, actual {}",
                            file.size, object.size
                        ))
                    },
                    checked_at: checked_at.to_string(),
                }
            }
            Err(error) => evidence_verification_error(file, checked_at, error.to_string()),
        },
        Err(error) => evidence_verification_error(file, checked_at, error.to_string()),
    }
}

fn evidence_verification_error(
    file: &FileRecord,
    checked_at: &str,
    error_message: String,
) -> EvidenceVerification {
    EvidenceVerification {
        file_id: file.file_id.clone(),
        original_path: file.original_path.clone(),
        object_ref: file.object_ref.clone(),
        expected_sha256: file.sha256.clone(),
        actual_sha256: None,
        size: file.size,
        verified: false,
        error_message: Some(error_message),
        checked_at: checked_at.to_string(),
    }
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn decode_base64_array<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    let bytes = BASE64_STANDARD.decode(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        ApiError::InvalidRequest(format!(
            "{field} must decode to {N} bytes, got {}",
            bytes.len()
        ))
    })
}

fn collect_file_inventory_for_manifest(workspace: &CaseWorkspace) -> Result<Vec<FileRecord>> {
    let query = workspace.query_layer();
    let mut cursor = None;
    let mut out = Vec::new();
    loop {
        let page = query.file_page(FilePageQuery {
            limit: Some(500),
            cursor,
        })?;
        out.extend(page.rows);
        cursor = page.next_cursor;
        if cursor.is_none() || out.len() >= 100_000 {
            break;
        }
    }
    Ok(out)
}

fn verify_manifest_evidence_hashes(
    workspace: &CaseWorkspace,
    payload: &serde_json::Value,
    limit: Option<usize>,
) -> Result<(i64, i64)> {
    let limit = limit.unwrap_or(500).clamp(1, 5_000);
    let Some(files) = payload
        .get("evidence_files")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok((0, 0));
    };
    let mut checked = 0i64;
    let mut mismatches = 0i64;
    for file in files.iter().take(limit) {
        let expected_sha = file
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let object_ref = file
            .get("object_ref")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if expected_sha.is_empty() || object_ref.is_empty() {
            mismatches += 1;
            checked += 1;
            continue;
        }
        let actual = workspace
            .raw_object_store()
            .read_range(object_ref, 0, 0)
            .map_err(ApiError::from)
            .and_then(|(object, _)| hash_file(&object.path));
        checked += 1;
        match actual {
            Ok(actual) if actual.eq_ignore_ascii_case(expected_sha) => {}
            _ => mismatches += 1,
        }
    }
    Ok((checked, mismatches))
}

fn report_bundle_verification_error(
    workspace: &CaseWorkspace,
    bundle_path: String,
    checked_at: String,
    error_message: String,
) -> ReportBundleVerification {
    ReportBundleVerification {
        bundle_path,
        bundle_sha256: None,
        computed_bundle_sha256: None,
        bundle_hash_ok: false,
        bundle_type_ok: false,
        case_id_matches: false,
        report_path: None,
        report_sha256_at_generation: None,
        current_report_sha256: None,
        report_hash_ok: false,
        custody_manifest_path: None,
        custody_manifest_sha256_at_generation: None,
        current_custody_manifest_sha256: None,
        custody_manifest_hash_ok: false,
        custody_manifest_internal_hash_ok: false,
        custody_manifest_type_ok: false,
        case_custody_profile_sha256_at_generation: None,
        current_case_custody_profile_sha256: hash_file(&case_custody_profile_path(workspace)).ok(),
        case_custody_profile_hash_ok: false,
        signature_algorithm: None,
        signature_key_id: None,
        signature_present: false,
        signature_payload_hash_ok: false,
        signature_valid: false,
        signature_key_matches_case_key: false,
        audit_log_sha256_at_generation: None,
        current_audit_log_sha256: hash_file(&audit_log_path(workspace)).ok(),
        audit_log_unchanged: false,
        checked_at,
        error_message: Some(error_message),
    }
}

fn json_string_at(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(str::to_string)
}

fn hash_path_string(path: Option<&str>) -> Option<String> {
    path.and_then(|path| hash_file(Path::new(path)).ok())
}

fn custody_manifest_document_status(path: Option<&str>) -> (bool, bool) {
    let Some(path) = path else {
        return (false, false);
    };
    let Ok(bytes) = fs::read(path) else {
        return (false, false);
    };
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (false, false);
    };
    let manifest_sha256 = document
        .get("manifest_sha256")
        .and_then(serde_json::Value::as_str);
    let payload = document
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let computed_manifest_sha256 = serde_json::to_vec_pretty(&payload)
        .ok()
        .map(|bytes| sha256_bytes(&bytes));
    let manifest_hash_ok =
        manifest_sha256.is_some() && manifest_sha256 == computed_manifest_sha256.as_deref();
    let manifest_type_ok = payload
        .get("manifest_type")
        .and_then(serde_json::Value::as_str)
        == Some("taotie_custody_manifest_v1");
    (manifest_hash_ok, manifest_type_ok)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn case_custody_profile_from_request(
    workspace: &CaseWorkspace,
    request: CaseCustodyProfileRequest,
) -> Result<CaseCustodyProfile> {
    let acquired_at = normalize_optional_utc("acquired_at", request.acquired_at)?;
    Ok(CaseCustodyProfile {
        case_id: workspace.manifest().case_id.clone(),
        investigator: clean_request_string(request.investigator),
        custodian: clean_request_string(request.custodian),
        organization: clean_request_string(request.organization),
        evidence_source: clean_request_string(request.evidence_source),
        acquisition_method: clean_request_string(request.acquisition_method),
        acquired_at,
        legal_authority: clean_request_string(request.legal_authority),
        chain_of_custody_note: clean_request_string(request.chain_of_custody_note),
        updated_at: now_utc(),
    })
}

fn case_approval_from_request(
    workspace: &CaseWorkspace,
    request: CaseApprovalRequest,
) -> Result<CaseApprovalRecord> {
    let target_kind = request.target_kind.trim().to_ascii_lowercase();
    if target_kind.is_empty() || target_kind.chars().count() > 80 {
        return Err(ApiError::InvalidRequest(
            "case approval requires a target_kind up to 80 characters".to_string(),
        ));
    }
    let status = request.status.trim().to_ascii_lowercase();
    if !is_valid_case_approval_status(&status) {
        return Err(ApiError::InvalidRequest(format!(
            "unsupported case approval status: {}",
            request.status
        )));
    }
    let target_id = clean_request_string(request.target_id);
    let target_path = clean_request_string(request.target_path);
    if target_id.is_none() && target_path.is_none() {
        return Err(ApiError::InvalidRequest(
            "case approval requires target_id or target_path".to_string(),
        ));
    }
    let target_sha256 = clean_request_string(request.target_sha256).or_else(|| {
        target_path
            .as_deref()
            .and_then(|path| hash_file(Path::new(path)).ok())
    });
    let now = now_utc();
    Ok(CaseApprovalRecord {
        approval_id: new_id("approval"),
        case_id: workspace.manifest().case_id.clone(),
        target_kind,
        target_id,
        target_path,
        target_sha256,
        status,
        approver: clean_request_string(request.approver),
        role: clean_request_string(request.role),
        comment: clean_request_string(request.comment),
        created_at: now.clone(),
        updated_at: now,
    })
}

fn saved_search_from_request(
    workspace: &CaseWorkspace,
    request: SavedSearchRequest,
) -> Result<SavedSearch> {
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        return Err(ApiError::InvalidRequest(
            "saved search requires a name up to 120 characters".to_string(),
        ));
    }
    let now = now_utc();
    Ok(SavedSearch {
        search_id: new_id("search"),
        case_id: workspace.manifest().case_id.clone(),
        name: name.to_string(),
        query: sanitize_saved_event_query(request.query),
        description: clean_limited_string(request.description, 500),
        created_by: clean_saved_search_principal(request.created_by),
        visibility: clean_saved_search_visibility(request.visibility),
        shared_with: clean_saved_search_shared_with(request.shared_with),
        created_at: now.clone(),
        updated_at: now,
    })
}

fn clean_saved_search_visibility(value: Option<String>) -> String {
    match clean_request_string(value)
        .unwrap_or_else(|| "case".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "private" => "private".to_string(),
        "restricted" | "shared" => "restricted".to_string(),
        _ => "case".to_string(),
    }
}

fn clean_saved_search_principal(value: Option<String>) -> Option<String> {
    clean_limited_string(value, 120).map(|value| value.trim().to_ascii_lowercase())
}

fn clean_saved_search_shared_with(values: Option<Vec<String>>) -> Vec<String> {
    let mut out = values
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| clean_saved_search_principal(Some(value)))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out.truncate(50);
    out
}

fn saved_search_owner(row: &SavedSearch) -> Option<&str> {
    row.created_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn saved_search_visible_to(row: &SavedSearch, viewer: Option<&str>) -> bool {
    let Some(viewer) = viewer.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    if saved_search_owner(row).is_some_and(|owner| owner.eq_ignore_ascii_case(viewer)) {
        return true;
    }
    match row.visibility.as_str() {
        "private" => false,
        "restricted" => row
            .shared_with
            .iter()
            .any(|principal| principal.eq_ignore_ascii_case(viewer)),
        _ => true,
    }
}

fn saved_search_manageable_by(row: &SavedSearch, actor: Option<&str>) -> bool {
    let Some(actor) = actor.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    saved_search_owner(row).is_some_and(|owner| owner.eq_ignore_ascii_case(actor))
}

fn sanitize_saved_event_query(query: EventPageQuery) -> EventPageQuery {
    EventPageQuery {
        limit: query.limit.map(|limit| limit.clamp(1, 500)).or(Some(100)),
        cursor: None,
        artifact_type: clean_limited_string(query.artifact_type, 120),
        user_name: clean_limited_string(query.user_name, 200),
        search: clean_limited_string(query.search, 500),
        sort_by: clean_event_sort_by(query.sort_by),
        sort_dir: clean_event_sort_dir(query.sort_dir),
    }
}

fn clean_event_sort_by(value: Option<String>) -> Option<String> {
    clean_request_string(value).and_then(|value| {
        if is_valid_event_sort_by(&value) {
            Some(value)
        } else {
            None
        }
    })
}

fn clean_event_sort_dir(value: Option<String>) -> Option<String> {
    clean_request_string(value).and_then(|value| {
        let value = value.to_ascii_lowercase();
        if value == "asc" || value == "desc" {
            Some(value)
        } else {
            None
        }
    })
}

fn is_valid_event_sort_by(value: &str) -> bool {
    matches!(
        value,
        "event_time_utc"
            | "severity"
            | "artifact_type"
            | "host"
            | "user_name"
            | "process_name"
            | "file_path"
            | "ip"
            | "url"
            | "hash"
            | "event_code"
            | "channel"
            | "level"
            | "event_action"
            | "message_short"
            | "parser_name"
    )
}

fn finding_review_from_request(
    workspace: &CaseWorkspace,
    request: FindingReviewRequest,
) -> Result<FindingReview> {
    let status = request.status.trim().to_ascii_lowercase();
    if !is_valid_finding_review_status(&status) {
        return Err(ApiError::InvalidRequest(format!(
            "unsupported finding review status: {}",
            request.status
        )));
    }
    let title = request.title.trim();
    let engine = request.engine.trim();
    if title.is_empty() || engine.is_empty() {
        return Err(ApiError::InvalidRequest(
            "finding review requires engine and title".to_string(),
        ));
    }
    let now = now_utc();
    Ok(FindingReview {
        review_id: new_id("review"),
        case_id: workspace.manifest().case_id.clone(),
        engine: engine.to_string(),
        rule_id: clean_request_string(request.rule_id),
        title: title.to_string(),
        status,
        reviewer: clean_request_string(request.reviewer),
        assignee: clean_request_string(request.assignee),
        tags_json: tags_json_from_request(request.tags)?,
        due_at: normalize_due_at(request.due_at)?,
        comment: clean_request_string(request.comment),
        created_at: now.clone(),
        updated_at: now,
    })
}

fn is_valid_finding_review_status(status: &str) -> bool {
    matches!(
        status,
        "new" | "in_review" | "confirmed" | "false_positive" | "benign" | "needs_context"
    )
}

fn is_valid_case_approval_status(status: &str) -> bool {
    matches!(status, "pending" | "approved" | "rejected" | "revoked")
}

fn case_approval_target_key(row: &CaseApprovalRecord) -> String {
    format!(
        "{}:{}:{}",
        row.target_kind,
        row.target_id.as_deref().unwrap_or("-"),
        row.target_path.as_deref().unwrap_or("-")
    )
}

fn approval_target_label(row: &CaseApprovalRecord) -> String {
    row.target_path
        .as_deref()
        .or(row.target_id.as_deref())
        .unwrap_or("-")
        .to_string()
}

fn saved_search_filter_label(query: &EventPageQuery) -> String {
    let mut parts = Vec::new();
    if let Some(value) = query.search.as_deref().filter(|value| !value.is_empty()) {
        parts.push(format!("search={value}"));
    }
    if let Some(value) = query
        .artifact_type
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("artifact={value}"));
    }
    if let Some(value) = query.user_name.as_deref().filter(|value| !value.is_empty()) {
        parts.push(format!("user={value}"));
    }
    if let Some(limit) = query.limit {
        parts.push(format!("limit={limit}"));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(", ")
    }
}

fn saved_search_sort_label(query: &EventPageQuery) -> String {
    format!(
        "{} {}",
        query.sort_by.as_deref().unwrap_or("event_time_utc"),
        query.sort_dir.as_deref().unwrap_or("asc")
    )
}

fn saved_search_shared_with_label(row: &SavedSearch) -> String {
    if row.shared_with.is_empty() {
        "-".to_string()
    } else {
        row.shared_with.join(", ")
    }
}

fn same_finding_review_target(left: &FindingReview, right: &FindingReview) -> bool {
    left.engine == right.engine && left.rule_id == right.rule_id && left.title == right.title
}

fn tags_json_from_request(tags: Option<Vec<String>>) -> Result<Option<String>> {
    let Some(tags) = tags else {
        return Ok(None);
    };
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for tag in tags {
        let tag = tag.trim();
        if tag.is_empty() {
            continue;
        }
        if tag.chars().count() > 64 {
            return Err(ApiError::InvalidRequest(format!(
                "finding review tag is too long: {tag}"
            )));
        }
        let key = tag.to_ascii_lowercase();
        if seen.insert(key) {
            normalized.push(tag.to_string());
        }
        if normalized.len() >= 20 {
            break;
        }
    }
    if normalized.is_empty() {
        Ok(None)
    } else {
        Ok(Some(serde_json::to_string(&normalized)?))
    }
}

fn finding_review_tags(row: &FindingReview) -> Vec<String> {
    row.tags_json
        .as_deref()
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect()
}

fn normalize_due_at(value: Option<String>) -> Result<Option<String>> {
    normalize_optional_utc("due_at", value)
}

fn normalize_optional_utc(field_name: &str, value: Option<String>) -> Result<Option<String>> {
    let Some(value) = clean_request_string(value) else {
        return Ok(None);
    };
    parse_utc(&value).map_err(|_| {
        ApiError::InvalidRequest(format!(
            "{field_name} must be RFC3339 UTC-compatible timestamp: {value}"
        ))
    })?;
    Ok(Some(value))
}

fn build_finding_review_summary(
    workspace: &CaseWorkspace,
    reviews: &[FindingReview],
) -> FindingReviewSummary {
    let mut summary = FindingReviewSummary {
        case_id: workspace.manifest().case_id.clone(),
        total_reviews: reviews.len() as i64,
        new_count: 0,
        in_review_count: 0,
        confirmed_count: 0,
        false_positive_count: 0,
        benign_count: 0,
        needs_context_count: 0,
        open_count: 0,
        overdue_count: 0,
        unassigned_count: 0,
        tagged_count: 0,
        updated_at: now_utc(),
    };
    for row in reviews {
        match row.status.as_str() {
            "new" => summary.new_count += 1,
            "in_review" => summary.in_review_count += 1,
            "confirmed" => summary.confirmed_count += 1,
            "false_positive" => summary.false_positive_count += 1,
            "benign" => summary.benign_count += 1,
            "needs_context" => summary.needs_context_count += 1,
            _ => {}
        }
        if is_open_review_status(&row.status) {
            summary.open_count += 1;
            if row.assignee.as_deref().unwrap_or("").trim().is_empty() {
                summary.unassigned_count += 1;
            }
            if finding_review_is_overdue(row) {
                summary.overdue_count += 1;
            }
        }
        if !finding_review_tags(row).is_empty() {
            summary.tagged_count += 1;
        }
    }
    summary
}

fn is_open_review_status(status: &str) -> bool {
    !matches!(status, "confirmed" | "false_positive" | "benign")
}

fn finding_override_from_request(
    workspace: &CaseWorkspace,
    request: FindingOverrideRequest,
) -> Result<FindingOverride> {
    let action = request.action.trim().to_ascii_lowercase();
    if action != "suppress" && action != "severity_override" {
        return Err(ApiError::InvalidRequest(format!(
            "unsupported finding override action: {}",
            request.action
        )));
    }
    let severity = clean_request_string(request.severity);
    if action == "severity_override" {
        let Some(severity) = severity.as_deref() else {
            return Err(ApiError::InvalidRequest(
                "severity_override requires severity".to_string(),
            ));
        };
        if !valid_severity(severity) {
            return Err(ApiError::InvalidRequest(format!(
                "unsupported severity override: {severity}"
            )));
        }
    }
    let engine = clean_request_string(request.engine);
    let rule_id = clean_request_string(request.rule_id);
    let title = clean_request_string(request.title);
    if engine.is_none() && rule_id.is_none() && title.is_none() {
        return Err(ApiError::InvalidRequest(
            "finding override requires engine, rule_id, or title".to_string(),
        ));
    }
    Ok(FindingOverride {
        override_id: new_id("override"),
        case_id: workspace.manifest().case_id.clone(),
        enabled: true,
        action,
        engine,
        rule_id,
        title,
        severity,
        reason: clean_request_string(request.reason),
        created_at: now_utc(),
    })
}

fn clean_request_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn clean_limited_string(value: Option<String>, limit: usize) -> Option<String> {
    clean_request_string(value).map(|value| truncate_chars(&value, limit))
}

fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn same_override(left: &FindingOverride, right: &FindingOverride) -> bool {
    left.enabled == right.enabled
        && left.action == right.action
        && left.engine == right.engine
        && left.rule_id == right.rule_id
        && left.title == right.title
        && left.severity == right.severity
}

fn apply_finding_overrides(
    findings: Vec<FindingRecord>,
    overrides: &[FindingOverride],
) -> Vec<FindingRecord> {
    let active = overrides
        .iter()
        .filter(|row| row.enabled)
        .collect::<Vec<_>>();
    if active.is_empty() {
        return findings;
    }

    let mut out = Vec::with_capacity(findings.len());
    'findings: for mut finding in findings {
        for override_row in &active {
            if !finding_override_matches(override_row, &finding) {
                continue;
            }
            if override_row.action == "suppress" {
                continue 'findings;
            }
            if override_row.action == "severity_override" {
                if let Some(severity) = override_row
                    .severity
                    .as_deref()
                    .filter(|value| valid_severity(value))
                {
                    finding.severity = severity.to_string();
                }
            }
        }
        out.push(finding);
    }
    out
}

fn finding_override_matches(override_row: &FindingOverride, finding: &FindingRecord) -> bool {
    if let Some(engine) = override_row.engine.as_deref() {
        if finding.engine != engine {
            return false;
        }
    }
    if let Some(rule_id) = override_row.rule_id.as_deref() {
        if finding.rule_id.as_deref() != Some(rule_id) {
            return false;
        }
    }
    if let Some(title) = override_row.title.as_deref() {
        if finding.title != title {
            return false;
        }
    }
    true
}

fn valid_severity(value: &str) -> bool {
    matches!(value, "critical" | "high" | "medium" | "low" | "info")
}

fn run_heuristic_findings(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut findings = Vec::new();
    let rules = heuristic_rules();
    let mut emitted_by_rule = vec![0usize; rules.len()];
    let mut high_cardinality_scan_cache: Option<(String, bool)> = None;
    for event in events {
        if high_cardinality_artifact(&event.artifact_type)
            && !high_cardinality_heuristic_scan_candidate_cached(
                event,
                &mut high_cardinality_scan_cache,
            )
        {
            continue;
        }
        let signal = if high_cardinality_artifact(&event.artifact_type) {
            high_cardinality_heuristic_candidate_text(event)
        } else {
            heuristic_candidate_text(event)
        };
        if signal.is_empty() || !event_needs_heuristic_scan(event, &signal) {
            continue;
        }
        let mut hay: Option<String> = None;
        for (idx, rule) in rules.iter().enumerate() {
            if emitted_by_rule[idx] >= PER_RULE_CAP
                || !rule_applies_to_event(rule.id, event)
                || !rule_candidate(rule.id, &signal)
            {
                continue;
            }
            let hay_ref = hay
                .get_or_insert_with(|| searchable_event_text(event))
                .as_str();
            if !(rule.matcher)(hay_ref) {
                continue;
            }
            let attack = rule
                .attack
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>();
            let event_ids = vec![event.event_id.clone()];
            findings.push(FindingRecord {
                detection_id: format!("finding_{}_{}", rule.id.replace('-', "_"), event.event_id),
                case_id: case_id.to_string(),
                engine: rule.engine.to_string(),
                rule_id: Some(rule.id.to_string()),
                title: rule.title.to_string(),
                severity: rule.severity.to_string(),
                attack_json: serde_json::to_string(&attack)?,
                event_ids_json: serde_json::to_string(&event_ids)?,
                entity_ids_json: "[]".to_string(),
                enrichment_json: "{}".to_string(),
                first_seen_utc: Some(event.event_time_utc.clone()),
                message: Some(short_finding_message(rule, event)),
            });
            emitted_by_rule[idx] += 1;
        }
    }
    findings.extend(run_aggregate_findings(case_id, events)?);
    Ok(findings)
}

fn heuristic_candidate_text(event: &EventFull) -> String {
    let mut parts = [
        event.process_name.as_deref(),
        event.file_path.as_deref(),
        event.ip.as_deref(),
        event.url.as_deref(),
        event.hash.as_deref(),
        Some(event.artifact_type.as_str()),
        Some(event.event_action.as_str()),
        Some(event.message_short.as_str()),
    ]
    .into_iter()
    .flatten()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>();
    if event.artifact_type == "lnk" {
        parts.push(event.attributes_json.as_str());
    }
    parts.join(" ").to_ascii_lowercase()
}

fn high_cardinality_heuristic_candidate_text(event: &EventFull) -> String {
    let mut parts = Vec::new();
    if let Some(value) = event
        .file_path
        .as_deref()
        .and_then(basename_key)
        .or_else(|| event.process_name.as_deref().and_then(basename_key))
    {
        parts.push(value);
    }
    if let Some(path) = event.file_path.as_deref() {
        let lower = path.to_ascii_lowercase();
        for marker in [
            "\\temp\\",
            "\\appdata\\",
            "\\startup\\",
            "\\downloads\\",
            "\\programdata\\",
            "\\windows\\tasks\\",
            "\\system32\\tasks\\",
            "/tmp/",
            "/appdata/",
            "/startup/",
            "/downloads/",
            "/programdata/",
            "/windows/tasks/",
            "/system32/tasks/",
        ] {
            if lower.contains(marker) {
                parts.push(marker.to_string());
                break;
            }
        }
    }
    for value in [
        event.ip.as_deref(),
        event.url.as_deref(),
        event.hash.as_deref(),
        Some(event.artifact_type.as_str()),
        Some(event.event_action.as_str()),
    ]
    .into_iter()
    .flatten()
    .filter(|part| !part.is_empty())
    {
        parts.push(value.to_ascii_lowercase());
    }
    parts.join(" ")
}

fn rule_candidate(rule_id: &str, hay: &str) -> bool {
    match rule_id {
        "lolbin-execution" => contains_any(
            hay,
            &[
                "rundll32",
                "regsvr32",
                "mshta",
                "wmic",
                "certutil",
                "bitsadmin",
                "cscript",
                "wscript",
            ],
        ),
        "temp-execution" => contains_any(hay, &["\\temp\\", "\\appdata\\local\\temp", "/tmp/"]),
        "credential-tooling" => contains_any(hay, &["mimikatz", "procdump", "lsass"]),
        "powershell-abuse" => contains_any(
            hay,
            &[
                "powershell",
                "pwsh",
                "-enc",
                "-encodedcommand",
                "downloadstring",
                "iex(",
            ],
        ),
        "suspicious-download" => {
            contains_any(hay, &["http://", "https://", "ftp://"])
                && contains_any(hay, &[".exe", ".ps1", ".scr", ".dll"])
        }
        "filezilla-saved-credential" => contains_any(
            hay,
            &[
                "filezilla",
                "filezilla_saved_password_recovered",
                "remote_path_normalized",
            ],
        ),
        "credential-store-recovery-required" => contains_any(
            hay,
            &[
                "credential_store",
                "browser_login_data_observed",
                "keepass_database_observed",
                "dpapi_masterkey_observed",
                "chromium_dpapi",
            ],
        ),
        "document-recovery-required" => contains_any(
            hay,
            &[
                "document_recovery_candidate",
                "tika_oletools_document_recovery",
                "pdf",
                "docx",
            ],
        ),
        "network-capture-exfil-review" => contains_any(
            hay,
            &[
                "network_capture",
                "network_capture_observed",
                "zeek_tshark_pcap_analysis",
                "pcap",
            ],
        ),
        "archive-exploit-recovery-candidate" => contains_any(
            hay,
            &[
                "archive_recovery_candidate",
                "archive_listing_and_carving",
                "cve-2023-38831",
                "rar",
            ],
        ),
        "prefetch-admin-lolbin-execution" => {
            hay.contains("prefetch")
                && contains_any(
                    hay,
                    &[
                        "powershell",
                        "pwsh",
                        "cmd.exe",
                        "rundll32",
                        "regsvr32",
                        "mshta",
                        "wscript",
                        "cscript",
                        "wmic",
                        "certutil",
                        "bitsadmin",
                        "schtasks",
                    ],
                )
        }
        "remote-access-tool-execution" => contains_any(
            hay,
            &[
                "teamviewer",
                "anydesk",
                "screenconnect",
                "connectwise",
                "splashtop",
                "ammyy",
                "radmin",
                "vnc",
                "logmein",
            ],
        ),
        "c2-agent-execution" => contains_any(
            hay,
            &[
                "merlin",
                "sliver",
                "cobalt",
                "beacon",
                "meterpreter",
                "havoc",
                "mythic",
                "poshc2",
            ],
        ),
        "wevtutil-log-tamper" => contains_any(
            hay,
            &[
                "wevtutil",
                "clear-eventlog",
                "remove-eventlog",
                "1102",
                "104",
            ],
        ),
        "rundll32-suspicious-invocation" => hay.contains("rundll32"),
        "regsvr32-suspicious-invocation" => hay.contains("regsvr32"),
        "mshta-suspicious-invocation" => hay.contains("mshta") || hay.contains(".hta"),
        "certutil-transfer" => hay.contains("certutil"),
        "bitsadmin-transfer" => hay.contains("bitsadmin"),
        "jumplist-executable-recent-item" => {
            contains_any(hay, &["jump_list", "jumplist", ".lnk"])
                && contains_any(
                    hay,
                    &[".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js"],
                )
        }
        "lnk-network-share-executable" => {
            hay.contains("lnk")
                && contains_any(hay, &["network_share_path", "\\\\\\\\", " unc "])
                && contains_any(
                    hay,
                    &[
                        ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
                    ],
                )
        }
        "recentdocs-risky-document" => {
            contains_any(hay, &["recentdocs", "registry_recentdocs_document"])
                && contains_any(
                    hay,
                    &[
                        ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk",
                        ".zip", ".rar", ".7z", ".iso",
                    ],
                )
        }
        "script-file-execution-artifact" => contains_any(
            hay,
            &[".ps1", ".vbs", ".jse", ".wsf", ".hta", ".bat", ".cmd"],
        ),
        "updater-masquerade-execution" => {
            contains_any(hay, &["updater.exe", "update.exe", "update_", "updater_"])
        }
        "event-log-cleared" => contains_any(
            hay,
            &[
                "1102",
                "104",
                "wevtutil",
                "clear-eventlog",
                "remove-eventlog",
            ],
        ),
        "comsvcs-minidump" => contains_any(hay, &["comsvcs", "minidump", "rundll32"]),
        "registry-hive-dump" => contains_any(
            hay,
            &[
                "reg save",
                "reg.exe save",
                "hklm\\sam",
                "hklm\\system",
                "hklm\\security",
            ],
        ),
        "ntds-extraction" => contains_any(hay, &["ntdsutil", "ntds.dit", "vssadmin", "shadow"]),
        "lsa-secrets" => contains_any(hay, &["policy\\secrets", "lsadump", "secretsdump"]),
        "wdigest-enabled" => hay.contains("wdigest"),
        "psexec-service" => contains_any(hay, &["7045", "psexesvc", "psexec", "paexec", "remcom"]),
        "wmi-process-spawn" => contains_any(hay, &["wmiprvse", "wmi"]),
        "remote-service-sc" => contains_any(hay, &["sc.exe", " sc "]),
        "scheduled-task-payload" => contains_any(
            hay,
            &["4698", "schtasks", "scheduled_task", "scheduled task"],
        ),
        "defender-threat-detected" => contains_any(
            hay,
            &["defender", "threat", "quarantine", "malware", "trojan"],
        ),
        "remote-script-host" => contains_any(hay, &["mshta", "regsvr32", "rundll32"]),
        "wsh-script-execution" => contains_any(hay, &["wscript", "cscript", ".vbs", ".js"]),
        "bloodhound-collection" => contains_any(
            hay,
            &["bloodhound", "sharphound", "get-domain", "collectionmethod"],
        ),
        "wmi-event-subscription" => {
            contains_any(hay, &["eventconsumer", "filtertoconsumerbinding", "wmi"])
        }
        "ifeo-accessibility-backdoor" => contains_any(
            hay,
            &[
                "image file execution options",
                "debugger",
                "sethc.exe",
                "utilman.exe",
            ],
        ),
        "winlogon-tamper" => hay.contains("winlogon"),
        "run-key-persistence" => contains_any(hay, &["currentversion\\run", "runonce"]),
        "admin-group-add" => contains_any(
            hay,
            &["4728", "4732", "4756", "administrators", "domain admins"],
        ),
        "bits-persistence" => hay.contains("bitsadmin"),
        "suspicious-service-image" => contains_any(hay, &["7045", "4697", "service_installed"]),
        "amsi-bypass" => contains_any(hay, &["amsi", "amsiutils"]),
        "etw-patch" => contains_any(hay, &["etweventwrite", "etw", "psetwlogprovider"]),
        "shadowcopy-delete" => contains_any(hay, &["vssadmin", "shadowcopy", "wbadmin", "bcdedit"]),
        "safeboot-tamper" => hay.contains("safeboot"),
        "firewall-disable" => contains_any(hay, &["netsh", "firewall", "netfirewallprofile"]),
        "byovd-driver" => contains_any(
            hay,
            &[
                ".sys",
                "imageloaded",
                "rtcore64",
                "gdrv",
                "dbutil",
                "iqvw64",
                "mhyprot",
            ],
        ),
        "remote-thread-injection" => contains_any(
            hay,
            &["createremotethread", "eventid 8", "\"event_id\":\"8\""],
        ),
        "kerberoast-rc4" => contains_any(hay, &["4769", "kerberoast", "rubeus"]),
        "dcsync-replication-rights" => {
            contains_any(hay, &["dcsync", "drsuapi", "replicating directory changes"])
        }
        "lsass-high-priv-access" => {
            contains_any(hay, &["lsass.exe", "\"event_id\":\"10\"", "eventid 10"])
        }
        "dcom-lateral-exec" => contains_any(
            hay,
            &[
                "mmc.exe",
                "excel.exe",
                "outlook.exe",
                "dcom",
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "rundll32.exe",
                "regsvr32.exe",
            ],
        ),
        "domain-trust-discovery" => contains_any(
            hay,
            &[
                "domain_trusts",
                "trusted_domains",
                "get-domaintrust",
                "nltest",
            ],
        ),
        "pkinit-logon" => contains_any(hay, &["4768", "pkinit", "preauthtype"]),
        "asrep-roast" => contains_any(hay, &["4768", "asrep", "as-rep", "preauth"]),
        "upn-swap" => contains_any(hay, &["4738", "userprincipalname"]),
        "force-change-password" => contains_any(hay, &["4724", "password reset"]),
        "shadow-credentials" => contains_any(hay, &["5136", "keycredentiallink"]),
        "timestomp-file-create-time" => contains_any(
            hay,
            &[
                "filecreatetime",
                "timestomp",
                "\"event_id\":\"2\"",
                ".exe",
                ".dll",
                ".ps1",
                ".bat",
                ".cmd",
                ".vbs",
                ".js",
                ".scr",
                ".sys",
            ],
        ),
        _ => true,
    }
}

fn event_needs_heuristic_scan(event: &EventFull, signal: &str) -> bool {
    match event.artifact_type.as_str() {
        "mft" | "usn_jrnl" => contains_any(signal, HIGH_VOLUME_SUSPICIOUS_ANCHORS),
        "prefetch" | "amcache" | "lnk" | "jump_list" | "scheduled_task" | "browser"
        | "web_cache" | "defender" | "filezilla" | "credential_store" | "document"
        | "network_capture" | "archive" => true,
        "onedrive_log" | "text_log" | "sqlite" | "ese" | "srum" => {
            contains_any(signal, HIGH_VOLUME_SUSPICIOUS_ANCHORS)
        }
        _ => true,
    }
}

fn rule_applies_to_event(rule_id: &str, event: &EventFull) -> bool {
    if !high_cardinality_artifact(&event.artifact_type) {
        return true;
    }
    matches!(
        rule_id,
        "lolbin-execution"
            | "temp-execution"
            | "credential-tooling"
            | "powershell-abuse"
            | "remote-access-tool-execution"
            | "c2-agent-execution"
            | "rundll32-suspicious-invocation"
            | "regsvr32-suspicious-invocation"
            | "mshta-suspicious-invocation"
            | "certutil-transfer"
            | "bitsadmin-transfer"
            | "script-file-execution-artifact"
            | "updater-masquerade-execution"
            | "remote-script-host"
            | "wsh-script-execution"
            | "shadowcopy-delete"
            | "byovd-driver"
            | "timestomp-file-create-time"
    )
}

fn high_cardinality_heuristic_scan_candidate_cached(
    event: &EventFull,
    cache: &mut Option<(String, bool)>,
) -> bool {
    if !matches!(event.severity.as_str(), "critical" | "high") {
        return false;
    }
    let key = event
        .file_path
        .as_deref()
        .or(event.process_name.as_deref())
        .or(event.url.as_deref())
        .or(event.hash.as_deref())
        .unwrap_or("");
    if key.is_empty() {
        return false;
    }
    if let Some((cached_key, cached_result)) = cache {
        if cached_key == key {
            return *cached_result;
        }
    }
    let result = basename_key(key)
        .is_some_and(|value| contains_any(&value, HIGH_VOLUME_SUSPICIOUS_ANCHORS))
        || event
            .file_path
            .as_deref()
            .is_some_and(|value| high_signal_file_path_lower(&value.to_ascii_lowercase()))
        || event.url.as_deref().is_some_and(|value| {
            contains_any(&value.to_ascii_lowercase(), &["http://", "https://"])
        });
    *cache = Some((key.to_string(), result));
    result
}

const HIGH_VOLUME_SUSPICIOUS_ANCHORS: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "wmic",
    "certutil",
    "bitsadmin",
    "wevtutil",
    "mimikatz",
    "procdump",
    "lsass",
    "teamviewer",
    "anydesk",
    "screenconnect",
    "connectwise",
    "splashtop",
    "merlin",
    "sliver",
    "beacon",
    "meterpreter",
    "updater.exe",
    "update.exe",
    "schtasks",
    "scheduled_task",
    "defender_threat",
    "quarantine",
    "trojan",
    "malware",
    "http://",
    "https://",
    ".ps1",
    ".vbs",
    ".jse",
    ".wsf",
    ".hta",
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    "\\temp\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\users\\public",
    "/tmp/",
    "filecreatetime",
    "shadow",
    "vssadmin",
    "bcdedit",
    "firewall",
    "keycredential",
];

fn run_correlation_chain_findings(
    case_id: &str,
    chains: &[CorrelationChainSummary],
) -> Result<Vec<FindingRecord>> {
    let mut findings = Vec::new();
    for chain in chains {
        if severity_rank(&chain.severity) < severity_rank("medium") {
            continue;
        }
        let event_ids = parse_chain_event_ids(&chain.steps_json);
        if event_ids.is_empty() {
            continue;
        }
        let rule_id = chain_rule_id(chain);
        let attack = chain_attack_techniques(&rule_id)
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        findings.push(FindingRecord {
            detection_id: stable_chain_detection_id(chain),
            case_id: case_id.to_string(),
            engine: "correlation".to_string(),
            rule_id: Some(rule_id),
            title: chain.title.clone(),
            severity: chain.severity.clone(),
            attack_json: serde_json::to_string(&attack)?,
            event_ids_json: serde_json::to_string(&event_ids)?,
            entity_ids_json: "[]".to_string(),
            enrichment_json: "{}".to_string(),
            first_seen_utc: Some(chain.first_seen_utc.clone()),
            message: Some(format!(
                "{}: {}={} / artifacts={} / events={} / score={}",
                chain.explanation,
                chain.key_kind,
                chain.key_value,
                chain.artifact_types,
                chain.event_count,
                chain.score
            )),
        });
    }
    Ok(findings)
}

fn run_hayabusa_findings(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut findings = Vec::new();
    for event in events
        .iter()
        .filter(|event| event.artifact_type == "hayabusa")
    {
        let title = event_attr_string(event, &["rule_title", "RuleTitle"])
            .unwrap_or_else(|| event.message_short.clone());
        let rule_id = event_attr_string(event, &["rule_id", "RuleID", "RuleId"])
            .or_else(|| Some(stable_text_id("hayabusa-rule", &title)));
        let attack = hayabusa_attack_tags(event);
        findings.push(FindingRecord {
            detection_id: format!("finding_hayabusa_{}", event.event_id),
            case_id: case_id.to_string(),
            engine: "hayabusa".to_string(),
            rule_id,
            title: format!("Hayabusa: {title}"),
            severity: event.severity.clone(),
            attack_json: serde_json::to_string(&attack)?,
            event_ids_json: serde_json::to_string(&vec![event.event_id.clone()])?,
            entity_ids_json: "[]".to_string(),
            enrichment_json: "{}".to_string(),
            first_seen_utc: Some(event.event_time_utc.clone()),
            message: Some(event.message_full.clone()),
        });
    }
    Ok(findings)
}

fn run_ioc_finding_records(
    case_id: &str,
    events: &[EventFull],
    indicators: &[String],
) -> Result<Vec<FindingRecord>> {
    struct IocBuild<'a> {
        match_kind: String,
        artifact_types: HashSet<String>,
        rows: Vec<&'a EventFull>,
    }

    let mut out = Vec::new();
    for indicator in normalize_ioc_indicators(indicators, 500) {
        let indicator_lc = indicator.to_ascii_lowercase();
        let mut build: Option<IocBuild<'_>> = None;
        let mut seen_events = HashSet::new();
        for event in events {
            let Some(kind) = event_ioc_match_kind(event, &indicator_lc) else {
                continue;
            };
            if !seen_events.insert(event.event_id.clone()) {
                continue;
            }
            let entry = build.get_or_insert_with(|| IocBuild {
                match_kind: kind.clone(),
                artifact_types: HashSet::new(),
                rows: Vec::new(),
            });
            if ioc_match_kind_rank(&kind) > ioc_match_kind_rank(&entry.match_kind) {
                entry.match_kind = kind;
            }
            entry.artifact_types.insert(event.artifact_type.clone());
            entry.rows.push(event);
        }

        let Some(build) = build else {
            continue;
        };
        let attack: Vec<String> = Vec::new();
        let severity = ioc_finding_severity(&build.match_kind, build.rows.len());
        let artifact_types = sorted_join(&build.artifact_types);
        let event_ids = build
            .rows
            .iter()
            .take(500)
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        let first_seen = build
            .rows
            .iter()
            .map(|event| event.event_time_utc.as_str())
            .min()
            .map(str::to_string);
        out.push(FindingRecord {
            detection_id: stable_ioc_detection_id(case_id, &indicator),
            case_id: case_id.to_string(),
            engine: "ioc".to_string(),
            rule_id: Some(format!("ioc-{}", build.match_kind)),
            title: format!("IOC hit: {indicator}"),
            severity: severity.to_string(),
            attack_json: serde_json::to_string(&attack)?,
            event_ids_json: serde_json::to_string(&event_ids)?,
            entity_ids_json: "[]".to_string(),
            enrichment_json: "{}".to_string(),
            first_seen_utc: first_seen,
            message: Some(format!(
                "IOC '{}' matched {} events (kind={}, artifacts={})",
                indicator,
                build.rows.len(),
                build.match_kind,
                artifact_types
            )),
        });
    }
    Ok(out)
}

fn parse_chain_event_ids(value: &str) -> Vec<String> {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value) else {
        return Vec::new();
    };
    let Some(items) = parsed.as_array() else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items {
        let event_id = item.as_str().map(str::to_string).or_else(|| {
            item.get("event_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        });
        if let Some(event_id) = event_id {
            if seen.insert(event_id.clone()) {
                out.push(event_id);
            }
        }
    }
    out
}

fn chain_rule_id(chain: &CorrelationChainSummary) -> String {
    if chain.title.contains("Defender") && chain.title.contains("実行") {
        "chain-defender-threat-executed"
    } else if chain.title.contains("Registry") && chain.title.contains("実行") {
        "chain-registry-persistence-executed"
    } else if chain.title.contains("Scheduled Task") && chain.title.contains("実行") {
        "chain-scheduled-task-executed"
    } else if chain.title.contains("サービス") && chain.title.contains("実行") {
        "chain-service-executed"
    } else if chain.title.contains("ダウンロード") && chain.title.contains("実行") {
        "chain-download-execute"
    } else if chain.title.contains("削除") || chain.title.contains("変更") {
        "chain-execute-delete-or-change"
    } else if chain.title.contains("作成され実行") {
        "chain-created-executed"
    } else if chain.key_kind == "hash" {
        "chain-hash-cross-artifact"
    } else if chain.key_kind == "url" {
        "chain-url-cross-artifact"
    } else {
        "chain-cross-artifact-activity"
    }
    .to_string()
}

fn chain_attack_techniques(rule_id: &str) -> Vec<&'static str> {
    match rule_id {
        "chain-defender-threat-executed" => vec!["T1204", "T1059", "T1562"],
        "chain-registry-persistence-executed" => vec!["T1547.001", "T1543.003", "T1059"],
        "chain-scheduled-task-executed" => vec!["T1053.005", "T1059"],
        "chain-service-executed" => vec!["T1543.003", "T1569.002"],
        "chain-download-execute" => vec!["T1105", "T1204"],
        "chain-execute-delete-or-change" => vec!["T1070.004", "T1204"],
        "chain-created-executed" => vec!["T1204"],
        "chain-hash-cross-artifact" | "chain-url-cross-artifact" => vec!["T1105"],
        _ => vec!["T1204"],
    }
}

fn stable_chain_detection_id(chain: &CorrelationChainSummary) -> String {
    let mut hasher = Sha256::new();
    hasher.update(chain.case_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(chain.key_kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(chain.key_value.as_bytes());
    hasher.update(b"\0");
    hasher.update(chain.title.as_bytes());
    let digest = hasher.finalize();
    format!("finding_chain_{digest:x}")
}

fn searchable_event_text(event: &EventFull) -> String {
    [
        event.process_name.as_deref(),
        event.file_path.as_deref(),
        event.ip.as_deref(),
        event.url.as_deref(),
        event.hash.as_deref(),
        Some(event.event_action.as_str()),
        Some(event.message_short.as_str()),
        Some(event.message_full.as_str()),
        Some(event.attributes_json.as_str()),
    ]
    .into_iter()
    .flatten()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" ")
    .to_lowercase()
}

fn event_ioc_match_kind(event: &EventFull, indicator_lc: &str) -> Option<String> {
    if field_eq(event.hash.as_deref(), indicator_lc) {
        return Some("hash".to_string());
    }
    if field_eq(event.ip.as_deref(), indicator_lc) {
        return Some("ip".to_string());
    }
    if field_eq(event.process_name.as_deref(), indicator_lc) {
        return Some("process".to_string());
    }
    if path_or_basename_eq(event.file_path.as_deref(), indicator_lc) {
        return Some("file".to_string());
    }
    if field_eq(event.url.as_deref(), indicator_lc) {
        return Some("url".to_string());
    }
    if indicator_lc.chars().count() >= 4 && searchable_event_text(event).contains(indicator_lc) {
        return Some("text".to_string());
    }
    None
}

fn field_eq(value: Option<&str>, expected_lc: &str) -> bool {
    value
        .map(|value| value.trim().eq_ignore_ascii_case(expected_lc))
        .unwrap_or(false)
}

fn path_or_basename_eq(value: Option<&str>, expected_lc: &str) -> bool {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    value.eq_ignore_ascii_case(expected_lc)
        || value
            .rsplit(['\\', '/'])
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(expected_lc))
}

fn ioc_match_kind_rank(kind: &str) -> i64 {
    match kind {
        "hash" => 6,
        "ip" => 5,
        "process" => 4,
        "file" => 3,
        "url" => 2,
        "text" => 1,
        _ => 0,
    }
}

fn ioc_finding_severity(kind: &str, hit_count: usize) -> &'static str {
    if kind == "hash" || hit_count >= 10 {
        "high"
    } else if matches!(kind, "ip" | "process" | "file" | "url") {
        "medium"
    } else {
        "low"
    }
}

fn stable_ioc_detection_id(case_id: &str, indicator: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(case_id.as_bytes());
    hasher.update(b"\0ioc\0");
    hasher.update(indicator.to_ascii_lowercase().as_bytes());
    let digest = hasher.finalize();
    format!("finding_ioc_{}", hex16(&digest))
}

fn stable_text_id(prefix: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(b"\0");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    format!("{prefix}-{}", hex16(&digest))
}

fn sorted_join(values: &HashSet<String>) -> String {
    let mut values = values.iter().cloned().collect::<Vec<_>>();
    values.sort();
    values.join(", ")
}

fn hayabusa_attack_tags(event: &EventFull) -> Vec<String> {
    let raw = [
        event_attr_string(event, &["mitre_tags", "MitreTags", "MITRE", "Attack"]),
        event_attr_string(event, &["mitre_tactics", "MitreTactics"]),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ");
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for token in raw.split(|ch: char| {
        ch.is_whitespace() || matches!(ch, ',' | ';' | '|' | '[' | ']' | '"' | '\'')
    }) {
        let token = token
            .trim()
            .trim_start_matches("attack.")
            .trim_start_matches("ATTACK.")
            .trim_matches(|ch: char| matches!(ch, '(' | ')' | '{' | '}'));
        if !token
            .chars()
            .next()
            .is_some_and(|first| matches!(first, 'T' | 't'))
        {
            continue;
        }
        let normalized = token.to_ascii_uppercase();
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn contains_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| hay.contains(needle))
}

fn contains_all(hay: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| hay.contains(needle))
}

fn match_lolbin(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "rundll32",
            "regsvr32",
            "mshta",
            "wmic",
            "certutil",
            "bitsadmin",
            "cscript",
            "wscript",
        ],
    )
}

fn match_event_log_clear(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "eventid 1102",
            "\"event_id\":\"1102\"",
            "eventid 104",
            "\"event_id\":\"104\"",
        ],
    ) || contains_any(
        hay,
        &[
            "wevtutil cl",
            "wevtutil clear-log",
            "clear-eventlog",
            "remove-eventlog",
            "limit-eventlog",
        ],
    )
}

fn match_temp_exec(hay: &str) -> bool {
    contains_any(hay, &["\\temp\\", "\\appdata\\local\\temp", "/tmp/"])
}

fn match_cred_tooling(hay: &str) -> bool {
    contains_any(hay, &["mimikatz", "procdump", "lsass"])
}

fn match_powershell_abuse(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "-enc",
            "-encodedcommand",
            " bypass",
            "downloadstring",
            "iex(",
        ],
    )
}

fn match_suspicious_download(hay: &str) -> bool {
    let has_scheme = contains_any(hay, &["http://", "https://", "ftp://"]);
    let has_payload_ext = contains_any(hay, &[".exe", ".ps1", ".scr", ".dll"]);
    has_scheme && has_payload_ext
}

fn match_filezilla_saved_credential(hay: &str) -> bool {
    hay.contains("filezilla")
        && contains_any(
            hay,
            &[
                "filezilla_saved_password_recovered",
                "password_decoded",
                "remote_path_normalized",
                "exfil_path_candidate",
            ],
        )
}

fn match_credential_store_recovery_required(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "browser_login_data_observed",
            "keepass_database_observed",
            "dpapi_masterkey_observed",
            "credential_store_observed",
            "chromium_dpapi_credential_recovery",
        ],
    )
}

fn match_document_recovery_required(hay: &str) -> bool {
    hay.contains("document_recovery_candidate")
        && contains_any(
            hay,
            &[
                "tika_oletools_document_recovery",
                "\"file_signature\":\"pdf\"",
                "\"file_signature\":\"ole\"",
                "\"file_signature\":\"zip\"",
            ],
        )
}

fn match_network_capture_exfil_review(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "network_capture_observed",
            "zeek_tshark_pcap_analysis",
            "\"file_signature\":\"pcap\"",
            "\"file_signature\":\"pcapng\"",
        ],
    )
}

fn match_archive_exploit_recovery_candidate(hay: &str) -> bool {
    hay.contains("archive_recovery_candidate")
        && contains_any(
            hay,
            &[
                "archive_listing_and_carving",
                "cve-2023-38831",
                "\"file_signature\":\"rar\"",
                "\"file_signature\":\"zip\"",
                "\"file_signature\":\"7z\"",
            ],
        )
}

fn match_prefetch_admin_lolbin_execution(hay: &str) -> bool {
    hay.contains("prefetch")
        && contains_any(
            hay,
            &[
                "powershell",
                "pwsh",
                "cmd.exe",
                "rundll32",
                "regsvr32",
                "mshta",
                "wscript",
                "cscript",
                "wmic",
                "certutil",
                "bitsadmin",
                "schtasks",
            ],
        )
}

fn match_remote_access_tool_execution(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "teamviewer",
            "anydesk",
            "screenconnect",
            "connectwisecontrol",
            "connectwise control",
            "splashtop",
            "ammyy",
            "radmin",
            "tightvnc",
            "ultravnc",
            "logmein",
        ],
    ) && !contains_any(hay, &["uninstall", "setupapi.dev.log"])
}

fn match_c2_agent_execution(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "merlin.exe",
            "merlin-agent",
            "sliver.exe",
            "sliver-client",
            "cobalt strike",
            "beacon.exe",
            "meterpreter",
            "havoc.exe",
            "mythic",
            "poshc2",
        ],
    )
}

fn match_wevtutil_log_tamper(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "eventid 1102",
            "\"event_id\":\"1102\"",
            "eventid 104",
            "\"event_id\":\"104\"",
            "clear-eventlog",
            "remove-eventlog",
        ],
    ) || (hay.contains("wevtutil")
        && contains_any(
            hay,
            &[
                " cl ",
                " clear-log",
                "clearlog",
                " sl ",
                "set-log",
                "/e:false",
            ],
        ))
}

fn match_rundll32_suspicious_invocation(hay: &str) -> bool {
    hay.contains("rundll32")
        && contains_any(
            hay,
            &[
                "http://",
                "https://",
                "\\temp\\",
                "\\\\temp\\\\",
                "\\appdata\\",
                "\\\\appdata\\\\",
                "\\programdata\\",
                "\\\\programdata\\\\",
                "\\users\\public",
                "javascript:",
                "vbscript:",
                "comsvcs.dll",
                "minidump",
                "#1",
                ".dat,",
                ".tmp,",
                ".jpg,",
                ".png,",
            ],
        )
}

fn match_regsvr32_suspicious_invocation(hay: &str) -> bool {
    hay.contains("regsvr32")
        && contains_any(
            hay,
            &[
                "/s",
                "/u",
                "/i:",
                "scrobj.dll",
                "http://",
                "https://",
                ".sct",
                "\\temp\\",
                "\\\\temp\\\\",
                "\\appdata\\",
                "\\\\appdata\\\\",
                "\\users\\public",
            ],
        )
}

fn match_mshta_suspicious_invocation(hay: &str) -> bool {
    contains_any(hay, &["mshta", ".hta"])
        && contains_any(
            hay,
            &[
                "http://",
                "https://",
                "javascript:",
                "vbscript:",
                "\\temp\\",
                "\\\\temp\\\\",
                "\\appdata\\",
                "\\\\appdata\\\\",
                "\\users\\public",
                "powershell",
                "cmd.exe",
            ],
        )
}

fn match_certutil_transfer(hay: &str) -> bool {
    hay.contains("certutil")
        && contains_any(
            hay,
            &[
                "-urlcache",
                "-split",
                "-f",
                "-decode",
                "-decodehex",
                "http://",
                "https://",
                ".exe",
                ".dll",
                ".ps1",
            ],
        )
}

fn match_bitsadmin_transfer(hay: &str) -> bool {
    hay.contains("bitsadmin")
        && contains_any(
            hay,
            &[
                "/transfer",
                "/create",
                "/addfile",
                "setnotifycmdline",
                "http://",
                "https://",
                ".exe",
                ".ps1",
            ],
        )
}

fn match_jumplist_executable_recent_item(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "jump_list",
            "jumplist_destlist_entry_observed",
            "lnk_file_observed",
            ".lnk",
        ],
    ) && contains_any(
        hay,
        &[
            ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
        ],
    )
}

fn match_lnk_network_share_executable(hay: &str) -> bool {
    hay.contains("lnk")
        && contains_any(hay, &["network_share_path", "\\\\\\\\", " unc "])
        && contains_any(
            hay,
            &[
                ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
            ],
        )
}

fn match_recentdocs_risky_document(hay: &str) -> bool {
    contains_any(hay, &["recentdocs", "registry_recentdocs_document"])
        && contains_any(
            hay,
            &[
                ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk", ".zip",
                ".rar", ".7z", ".iso",
            ],
        )
}

fn match_script_file_execution_artifact(hay: &str) -> bool {
    contains_any(
        hay,
        &[".ps1", ".vbs", ".jse", ".wsf", ".hta", ".bat", ".cmd"],
    ) && contains_any(
        hay,
        &[
            "prefetch",
            "amcache",
            "jump_list",
            "lnk",
            "process_created",
            "scheduled_task",
            "registry",
            "\\temp\\",
            "\\\\temp\\\\",
            "\\appdata\\",
            "\\\\appdata\\\\",
            "\\users\\public",
        ],
    )
}

fn match_updater_masquerade_execution(hay: &str) -> bool {
    contains_any(hay, &["updater.exe", "update.exe"])
        && contains_any(
            hay,
            &[
                "\\temp\\",
                "\\\\temp\\\\",
                "\\appdata\\",
                "\\\\appdata\\\\",
                "\\programdata\\",
                "\\\\programdata\\\\",
                "\\users\\public",
                "prefetch",
                "amcache",
                "process_created",
            ],
        )
}

fn match_comsvcs_minidump(hay: &str) -> bool {
    hay.contains("comsvcs.dll")
        && (hay.contains("minidump") || hay.contains("#24") || hay.contains(" 24"))
}

fn match_registry_hive_dump(hay: &str) -> bool {
    contains_any(
        hay,
        &["reg save", "reg.exe save", "reg export", "reg.exe export"],
    ) && contains_any(
        hay,
        &[
            "\\sam",
            "\\\\sam",
            "\\system",
            "\\\\system",
            "\\security",
            "\\\\security",
            "hklm\\sam",
            "hklm\\\\sam",
            "hklm\\system",
            "hklm\\\\system",
            "hklm\\security",
            "hklm\\\\security",
        ],
    )
}

fn match_ntds_extract(hay: &str) -> bool {
    hay.contains("ntdsutil")
        || hay.contains("ntds.dit")
        || contains_all(hay, &["vssadmin", "shadow"])
        || contains_all(hay, &["wmic", "shadowcopy", "create"])
        || contains_all(hay, &["ifm", "create"])
}

fn match_lsa_secrets(hay: &str) -> bool {
    hay.contains("policy\\secrets")
        || hay.contains("policy\\\\secrets")
        || hay.contains("lsadump")
        || hay.contains("secretsdump")
        || contains_all(hay, &["cache", "dump"])
        || hay.contains("get-lsasecret")
}

fn match_wdigest_enabled(hay: &str) -> bool {
    hay.contains("wdigest")
        && hay.contains("uselogoncredential")
        && contains_any(
            hay,
            &["0x00000001", "dword (0x1)", "details\":\"1", "details=1"],
        )
}

fn match_psexec_service(hay: &str) -> bool {
    (contains_any(
        hay,
        &["eventid 7045", "\"event_id\":\"7045\"", "service_installed"],
    ) || hay.contains("service"))
        && contains_any(hay, &["psexesvc", "psexec", "paexec", "remcom", "csexec"])
}

fn match_wmi_process_spawn(hay: &str) -> bool {
    hay.contains("wmiprvse")
        && contains_any(
            hay,
            &[
                "\\cmd.exe",
                "\\\\cmd.exe",
                "\\powershell.exe",
                "\\\\powershell.exe",
                "\\pwsh.exe",
                "\\\\pwsh.exe",
                "\\wscript.exe",
                "\\\\wscript.exe",
                "\\cscript.exe",
                "\\\\cscript.exe",
                "\\mshta.exe",
                "\\\\mshta.exe",
            ],
        )
}

fn match_remote_service_sc(hay: &str) -> bool {
    contains_any(hay, &["sc.exe", " sc "])
        && contains_any(hay, &[" create ", " config ", " start ", " failure "])
        && (hay.contains("\\\\") || hay.contains("\\\\\\\\"))
}

fn match_scheduled_task_payload(hay: &str) -> bool {
    (contains_any(
        hay,
        &[
            "eventid 4698",
            "\"event_id\":\"4698\"",
            "schtasks",
            "scheduled_task_suspicious_exec",
            "scheduled task observed",
            "\"parser_mode\":\"scheduled_task_xml\"",
        ],
    ) && contains_any(
        hay,
        &[
            "/create",
            "taskname",
            "scheduled task",
            "scheduled-task",
            "scheduled_task",
            "command=",
        ],
    )) && contains_any(
        hay,
        &[
            "cmd.exe",
            "powershell",
            "pwsh",
            "\\temp\\",
            "\\\\temp\\\\",
            "\\programdata\\",
            "\\\\programdata\\\\",
            "\\public\\",
            "\\\\public\\\\",
            "\\appdata\\",
            "\\\\appdata\\\\",
            "-enc",
            "-encodedcommand",
            "downloadstring",
            " mshta",
            "regsvr32",
            "rundll32",
            "bitsadmin",
            "certutil",
        ],
    )
}

fn match_defender_threat_detected(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "defender_threat_detected",
            "defender_quarantined",
            "microsoft-windows-windows defender",
            "microsoft defender antivirus",
            "windows defender antivirus",
            "threat name",
        ],
    ) && contains_any(
        hay,
        &[
            "trojan",
            "malware",
            "virus",
            "threat",
            "quarantine",
            "remediat",
            "detected",
            "severe",
            "high",
        ],
    )
}

fn match_remote_script_host(hay: &str) -> bool {
    contains_any(hay, &["mshta", "regsvr32", "rundll32"])
        && contains_any(
            hay,
            &[
                "http://",
                "https://",
                "scrobj.dll",
                "javascript:",
                "vbscript:",
                "/i:http",
                ".sct",
                "about:",
                "\\\\",
            ],
        )
}

fn match_wsh_script_execution(hay: &str) -> bool {
    contains_any(hay, &["wscript", "cscript"])
        && contains_any(hay, &[".vbs", ".js", ".jse", ".wsf", ".vbe"])
        && !contains_any(
            hay,
            &[
                "\\program files\\",
                "\\\\program files\\\\",
                "\\windows\\system32\\",
                "\\\\windows\\\\system32\\\\",
                "\\netlogon\\",
                "\\\\netlogon\\\\",
                "\\sysvol\\",
                "\\\\sysvol\\\\",
            ],
        )
}

fn match_bloodhound_collection(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "invoke-bloodhound",
            "sharphound",
            "bloodhound",
            "azurehound",
            "get-domainuser",
            "get-domaincomputer",
            "get-domaingroup",
            "invoke-aclscanner",
            "invoke-userhunter",
            "invoke-sharefinder",
            "collectionmethod",
        ],
    )
}

fn match_wmi_event_subscription(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "eventid 19",
            "\"event_id\":\"19\"",
            "eventid 20",
            "\"event_id\":\"20\"",
            "eventid 21",
            "\"event_id\":\"21\"",
        ],
    ) && contains_any(
        hay,
        &[
            "wmi",
            "consumer",
            "filtertoconsumerbinding",
            "eventconsumer",
        ],
    )
}

fn match_ifeo_accessibility_backdoor(hay: &str) -> bool {
    hay.contains("image file execution options")
        && hay.contains("debugger")
        && contains_any(
            hay,
            &[
                "sethc.exe",
                "utilman.exe",
                "osk.exe",
                "magnify.exe",
                "narrator.exe",
                "displayswitch.exe",
            ],
        )
}

fn match_winlogon_tamper(hay: &str) -> bool {
    hay.contains("winlogon")
        && contains_any(hay, &["\\shell", "\\\\shell", "\\userinit", "\\\\userinit"])
        && !contains_any(
            hay,
            &[
                "explorer.exe",
                "c:\\windows\\system32\\userinit.exe",
                "c:\\\\windows\\\\system32\\\\userinit.exe",
            ],
        )
}

fn match_run_key_persistence(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "currentversion\\run\\",
            "currentversion\\\\run\\\\",
            "currentversion\\runonce\\",
            "currentversion\\\\runonce\\\\",
        ],
    ) && contains_any(
        hay,
        &[
            "powershell",
            "pwsh",
            "cmd.exe",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
            "-enc",
            "\\temp\\",
            "\\\\temp\\\\",
            "\\appdata\\",
            "\\\\appdata\\\\",
            "\\programdata\\",
            "\\\\programdata\\\\",
            "\\public\\",
            "\\\\public\\\\",
            ".ps1",
            ".vbs",
            ".js",
            ".bat",
            ".hta",
        ],
    )
}

fn match_admin_group_add(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "eventid 4728",
            "\"event_id\":\"4728\"",
            "eventid 4732",
            "\"event_id\":\"4732\"",
            "eventid 4756",
            "\"event_id\":\"4756\"",
        ],
    ) && contains_any(
        hay,
        &[
            "administrators",
            "-544",
            "domain admins",
            "enterprise admins",
        ],
    )
}

fn match_bits_persistence(hay: &str) -> bool {
    hay.contains("bitsadmin")
        && contains_any(
            hay,
            &["setnotifycmdline", "addfile", " create ", " resume "],
        )
}

fn match_suspicious_service_image(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "eventid 7045",
            "\"event_id\":\"7045\"",
            "eventid 4697",
            "\"event_id\":\"4697\"",
            "service_installed",
        ],
    ) && contains_any(
        hay,
        &[
            "\\temp\\",
            "\\\\temp\\\\",
            "\\appdata\\",
            "\\\\appdata\\\\",
            "\\users\\public",
            "\\\\users\\\\public",
            "\\programdata\\",
            "\\\\programdata\\\\",
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
            "powershell",
            "cmd /c",
            "cmd.exe /c",
        ],
    )
}

fn match_amsi_bypass(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "amsiinitfailed",
            "amsiscanbuffer",
            "amsicontext",
            "amsiutils",
            "amsi.dll",
        ],
    )
}

fn match_etw_patch(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "etweventwrite",
            "etwpeventwritefull",
            "psetwlogprovider",
            "system.diagnostics.eventing",
            "m_enabled",
        ],
    )
}

fn match_shadowcopy_delete(hay: &str) -> bool {
    contains_all(hay, &["vssadmin", "delete", "shadows"])
        || contains_all(hay, &["wmic", "shadowcopy", "delete"])
        || contains_all(hay, &["wbadmin", "delete"])
        || contains_all(hay, &["bcdedit", "recoveryenabled", "no"])
        || contains_all(hay, &["bcdedit", "bootstatuspolicy", "ignoreallfailures"])
        || hay.contains("delete-vsssnapshot")
        || hay.contains("deletevsssnapshot")
        || contains_all(hay, &["win32_shadowcopy", "delete"])
}

fn match_safeboot_tamper(hay: &str) -> bool {
    hay.contains("safeboot") && (hay.contains("bcdedit") || hay.contains("/set"))
}

fn match_firewall_disable(hay: &str) -> bool {
    contains_all(hay, &["netsh", "advfirewall", "set", "state", "off"])
        || contains_all(hay, &["netsh", "firewall", "opmode", "disable"])
        || contains_all(hay, &["set-netfirewallprofile", "-enabled", "false"])
}

fn match_byovd_driver(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "rtcore64.sys",
            "gdrv.sys",
            "dbutil_2_3.sys",
            "dbutil.sys",
            "iqvw64.sys",
            "kprocesshacker.sys",
            "mhyprot.sys",
            "procexp152.sys",
            "aswarpot.sys",
        ],
    ) || (hay.contains("imageloaded")
        && hay.contains(".sys")
        && hay.contains("signed")
        && hay.contains("false"))
}

fn match_remote_thread_injection(hay: &str) -> bool {
    contains_any(
        hay,
        &["eventid 8", "\"event_id\":\"8\"", "createremotethread"],
    ) && contains_any(
        hay,
        &[
            "loadlibrary",
            "virtualalloc",
            "rtlcreateuserthread",
            "reflectiveloader",
            "lsass.exe",
            "winlogon.exe",
            "services.exe",
        ],
    )
}

fn match_kerberoast_rc4(hay: &str) -> bool {
    contains_any(hay, &["eventid 4769", "\"event_id\":\"4769\""])
        && contains_any(
            hay,
            &[
                "ticketencryptiontype\":\"0x17",
                "ticket encryption type: 0x17",
                "rc4",
                "rubeus kerberoast",
                "kerberoast",
            ],
        )
}

fn match_dcsync(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
            "89e95b76-444d-4c62-991a-0facbeda640c",
            "drsuapi",
            "dcsync",
            "replicating directory changes",
        ],
    )
}

fn match_lsass_high_priv_access(hay: &str) -> bool {
    contains_any(hay, &["eventid 10", "\"event_id\":\"10\""])
        && hay.contains("lsass.exe")
        && contains_any(
            hay,
            &[
                "0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f1fff", "0x1f3fff",
            ],
        )
        && (!contains_any(
            hay,
            &[
                "msmpeng.exe",
                "wininit.exe",
                "csrss.exe",
                "services.exe",
                "svchost.exe",
                "taskmgr.exe",
                "wmiprvse.exe",
            ],
        ) || hay.contains("unknown"))
}

fn match_dcom_lateral_exec(hay: &str) -> bool {
    contains_any(hay, &["eventid 1", "\"event_id\":\"1\"", "eventid 4688"])
        && contains_any(
            hay,
            &[
                "parentimage",
                "parent process",
                "parent_process",
                "mmc.exe",
                "excel.exe",
                "outlook.exe",
                "explorer.exe",
            ],
        )
        && contains_any(
            hay,
            &[
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "rundll32.exe",
                "regsvr32.exe",
            ],
        )
        && (contains_any(hay, &["mmc.exe", "excel.exe", "outlook.exe"])
            || contains_any(hay, &["-enc", "-nop", "hidden", "frombase64", "iex"]))
}

fn match_domain_trust_discovery(hay: &str) -> bool {
    contains_any(
        hay,
        &[
            "/domain_trusts",
            "/trusted_domains",
            "get-domaintrust",
            "get-addomaintrust",
            "get-adtrust",
            "trusteddomain",
            "/dclist",
            "/dsgetdc",
        ],
    ) || (hay.contains("nltest") && contains_any(hay, &["/domain_trusts", "/dclist", "/dsgetdc"]))
}

fn match_pkinit_logon(hay: &str) -> bool {
    contains_any(hay, &["eventid 4768", "\"event_id\":\"4768\""])
        && contains_any(hay, &["preauthtype\":\"16", "preauth type: 16", "pkinit"])
}

fn match_asrep_roast(hay: &str) -> bool {
    contains_any(hay, &["eventid 4768", "\"event_id\":\"4768\""])
        && contains_any(
            hay,
            &[
                "preauthtype\":\"0",
                "preauth type: 0",
                "does not require preauth",
                "as-rep",
                "asrep",
            ],
        )
}

fn match_upn_swap(hay: &str) -> bool {
    contains_any(hay, &["eventid 4738", "\"event_id\":\"4738\""])
        && hay.contains("userprincipalname")
        && !contains_any(hay, &["<value not set>", "\"userprincipalname\":\"-\""])
}

fn match_force_change_password(hay: &str) -> bool {
    contains_any(hay, &["eventid 4724", "\"event_id\":\"4724\""])
        && contains_any(
            hay,
            &["subjectusername", "targetusername", "password reset"],
        )
}

fn match_shadow_credentials(hay: &str) -> bool {
    contains_any(hay, &["eventid 5136", "\"event_id\":\"5136\""])
        && contains_any(hay, &["keycredentiallink", "msds-keycredentiallink"])
}

fn match_timestomp_file_create_time(hay: &str) -> bool {
    contains_any(hay, &["eventid 2", "\"event_id\":\"2\"", "filecreatetime"])
        && contains_any(
            hay,
            &[
                "previouscreationutctime",
                "creationutctime",
                "creation time changed",
                "timestomp",
            ],
        )
        && contains_any(
            hay,
            &[
                ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".sys",
            ],
        )
        && !contains_any(
            hay,
            &[
                "\\windows\\servicing",
                "\\windows\\softwaredistribution",
                "\\windows\\winsxs",
                "\\windows\\installer",
                "\\windows defender\\",
            ],
        )
}

fn run_aggregate_findings(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut findings = Vec::new();
    findings.extend(aggregate_bruteforce_failures(case_id, events)?);
    findings.extend(aggregate_failures_then_success(case_id, events)?);
    findings.extend(aggregate_account_created_then_privileged(case_id, events)?);
    findings.extend(aggregate_pass_the_hash(case_id, events)?);
    findings.extend(aggregate_rdp_sources(case_id, events)?);
    findings.extend(aggregate_psexec_chain(case_id, events)?);
    findings.extend(aggregate_mass_executable_deletion(case_id, events)?);
    findings.extend(aggregate_password_spray_distinct(case_id, events)?);
    findings.extend(aggregate_forged_ticket(case_id, events)?);
    findings.extend(aggregate_off_hours_logon(case_id, events)?);
    findings.extend(aggregate_service_installs(case_id, events)?);
    findings.extend(aggregate_intrusion_chain(case_id, events)?);
    findings.extend(aggregate_mft_si_fn_timestomp(case_id, events)?);
    findings.extend(aggregate_file_artifact_chains(case_id, events)?);
    findings.extend(aggregate_suspicious_execution_inventory(case_id, events)?);
    Ok(findings)
}

fn aggregate_bruteforce_failures(
    case_id: &str,
    events: &[EventFull],
) -> Result<Vec<FindingRecord>> {
    let mut groups: HashMap<(String, String), Vec<&EventFull>> = HashMap::new();
    for event in events.iter().filter(|event| event_code_is(event, "4625")) {
        let user = event_user(event).unwrap_or_else(|| "(unknown)".to_string());
        let ip = event_ip_or_workstation(event).unwrap_or_else(|| "(unknown)".to_string());
        groups.entry((user, ip)).or_default().push(event);
    }
    let mut out = Vec::new();
    for ((user, ip), rows) in groups {
        if rows.len() < 10 {
            continue;
        }
        out.push(aggregate_finding(
            case_id,
            "core-bruteforce-failures",
            "taotie-core",
            "ブルートフォースの兆候 (同一ユーザー/IPへ集中失敗)",
            "high",
            &["T1110"],
            format!("{user}|{ip}"),
            &rows,
            format!(
                "ログオン失敗(4625)が user={user} ip={ip} に{}件集中",
                rows.len()
            ),
        )?);
    }
    Ok(out)
}

fn aggregate_failures_then_success(
    case_id: &str,
    events: &[EventFull],
) -> Result<Vec<FindingRecord>> {
    #[derive(Default)]
    struct LoginStats<'a> {
        failures: Vec<&'a EventFull>,
        successes: Vec<&'a EventFull>,
    }
    let mut groups: HashMap<String, LoginStats<'_>> = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event_code_is(event, "4624") || event_code_is(event, "4625"))
    {
        let Some(user) = event_user(event).filter(|user| !is_builtin_user(user)) else {
            continue;
        };
        let entry = groups.entry(user).or_default();
        if event_code_is(event, "4625") {
            entry.failures.push(event);
        } else {
            entry.successes.push(event);
        }
    }
    let mut out = Vec::new();
    for (user, stats) in groups {
        if stats.failures.len() < 5 || stats.successes.is_empty() {
            continue;
        }
        let mut rows = stats.failures;
        rows.extend(stats.successes);
        out.push(aggregate_finding(
            case_id,
            "core-auth-failures-then-success",
            "taotie-core",
            "認証突破の可能性 (失敗多発後に成功)",
            "critical",
            &["T1110"],
            user.clone(),
            &rows,
            format!(
                "user={user} でログオン失敗{}件後に成功{}件。ブルートフォース成功の可能性",
                rows.iter()
                    .filter(|event| event_code_is(event, "4625"))
                    .count(),
                rows.iter()
                    .filter(|event| event_code_is(event, "4624"))
                    .count()
            ),
        )?);
    }
    Ok(out)
}

fn aggregate_account_created_then_privileged(
    case_id: &str,
    events: &[EventFull],
) -> Result<Vec<FindingRecord>> {
    let created = events
        .iter()
        .filter(|event| event_code_is(event, "4720"))
        .collect::<Vec<_>>();
    let privileged = events
        .iter()
        .filter(|event| event_code_is_any(event, &["4728", "4732", "4756"]))
        .collect::<Vec<_>>();
    if created.is_empty() || privileged.is_empty() {
        return Ok(Vec::new());
    }
    let mut rows = created;
    rows.extend(privileged);
    Ok(vec![aggregate_finding(
        case_id,
        "core-account-create-privileged-group",
        "taotie-core",
        "アカウント作成 + 特権グループ追加",
        "high",
        &["T1136.001", "T1098"],
        "case".to_string(),
        &rows,
        format!(
            "アカウント作成(4720){}件 + 特権/グループ追加(4728/4732/4756){}件",
            rows.iter()
                .filter(|event| event_code_is(event, "4720"))
                .count(),
            rows.iter()
                .filter(|event| event_code_is_any(event, &["4728", "4732", "4756"]))
                .count()
        ),
    )?])
}

fn aggregate_pass_the_hash(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut groups: HashMap<(String, String), Vec<&EventFull>> = HashMap::new();
    for event in events.iter().filter(|event| event_code_is(event, "4624")) {
        let logon_type = event_attr_string(event, &["LogonType", "logon_type"]).unwrap_or_default();
        if logon_type.trim() != "3" {
            continue;
        }
        let auth = event_attr_string(event, &["AuthenticationPackageName", "auth_package"])
            .unwrap_or_default();
        if !auth.eq_ignore_ascii_case("ntlm") {
            continue;
        }
        let Some(user) = event_user(event).filter(|user| !is_builtin_user(user)) else {
            continue;
        };
        let source = event_ip_or_workstation(event).unwrap_or_else(|| "?".to_string());
        if is_loopback_source(&source) {
            continue;
        }
        groups.entry((user, source)).or_default().push(event);
    }
    let mut out = Vec::new();
    for ((user, source), rows) in groups {
        let ntlm_v1 = rows.iter().any(|event| {
            event_attr_string(event, &["LmPackageName", "lm_package"])
                .unwrap_or_default()
                .to_ascii_lowercase()
                .replace(' ', "")
                .contains("ntlmv1")
        });
        if rows.len() < 5 && !ntlm_v1 {
            continue;
        }
        out.push(aggregate_finding(
            case_id,
            "core-pass-the-hash",
            "taotie-core",
            "Pass-the-Hash の兆候 (Type3 + NTLM)",
            "high",
            &["T1550.002"],
            format!("{user}|{source}"),
            &rows,
            format!(
                "4624 Type3 + NTLM が user={user} source={source} に{}件集中",
                rows.len()
            ),
        )?);
    }
    Ok(out)
}

fn aggregate_rdp_sources(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut groups: HashMap<String, Vec<&EventFull>> = HashMap::new();
    for event in events.iter().filter(|event| event_code_is(event, "1149")) {
        let Some(ip) = event_ip_or_workstation(event) else {
            continue;
        };
        groups.entry(ip).or_default().push(event);
    }
    let mut out = Vec::new();
    for (ip, rows) in groups {
        let external = !is_private_or_loopback_ip(&ip);
        if rows.len() < 2 && !external {
            continue;
        }
        let title = if external {
            "RDP 接続元の集約 (外部IPあり)"
        } else {
            "RDP 接続元の集約"
        };
        let severity = if external { "high" } else { "medium" };
        out.push(aggregate_finding(
            case_id,
            "core-rdp-source-aggregation",
            "taotie-core",
            title,
            severity,
            &["T1021.001"],
            ip.clone(),
            &rows,
            format!("RDP 認証(1149)の接続元 ip={ip} count={}", rows.len()),
        )?);
    }
    Ok(out)
}

fn aggregate_psexec_chain(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    #[derive(Default)]
    struct HostActivity<'a> {
        network_logons: Vec<&'a EventFull>,
        service_installs: Vec<&'a EventFull>,
    }
    let mut groups: HashMap<String, HostActivity<'_>> = HashMap::new();
    for event in events {
        let host = event
            .host
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string());
        if event_code_is(event, "4624")
            && event_attr_string(event, &["LogonType", "logon_type"]).as_deref() == Some("3")
        {
            groups
                .entry(host.clone())
                .or_default()
                .network_logons
                .push(event);
        }
        if event_code_is_any(event, &["7045", "4697"]) || event.event_action == "service_installed"
        {
            groups.entry(host).or_default().service_installs.push(event);
        }
    }
    let mut out = Vec::new();
    for (host, activity) in groups {
        if activity.network_logons.is_empty() || activity.service_installs.is_empty() {
            continue;
        }
        let mut rows = activity.network_logons;
        rows.extend(activity.service_installs);
        out.push(aggregate_finding(
            case_id,
            "core-network-logon-service-install-chain",
            "taotie-core",
            "ネットワークログオン後のサービス作成 (PsExec 型横展開)",
            "high",
            &["T1021.002", "T1569.002"],
            host.clone(),
            &rows,
            format!("host={host} で 4624 Type3 と 7045/4697 サービス作成が同時期に存在"),
        )?);
    }
    Ok(out)
}

fn aggregate_mass_executable_deletion(
    case_id: &str,
    events: &[EventFull],
) -> Result<Vec<FindingRecord>> {
    let rows = events
        .iter()
        .filter(|event| {
            (event.artifact_type == "usn_jrnl" || event.event_action.starts_with("usn_"))
                && (event.event_action.contains("deleted")
                    || event.event_action.contains("delete")
                    || event
                        .file_path
                        .as_deref()
                        .map(|path| {
                            let path = path.to_ascii_lowercase();
                            [
                                ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr",
                            ]
                            .iter()
                            .any(|ext| path.ends_with(ext))
                        })
                        .unwrap_or(false))
        })
        .collect::<Vec<_>>();
    if rows.len() < 30 {
        return Ok(Vec::new());
    }
    Ok(vec![aggregate_finding(
        case_id,
        "core-mass-executable-deletion",
        "taotie-core",
        "実行ファイル大量削除 (痕跡消去/ワイプの兆候)",
        "high",
        &["T1070.004"],
        "case".to_string(),
        &rows,
        format!("USN/FS 証跡で実行系ファイル削除/変更が {} 件", rows.len()),
    )?])
}

fn aggregate_password_spray_distinct(
    case_id: &str,
    events: &[EventFull],
) -> Result<Vec<FindingRecord>> {
    #[derive(Default)]
    struct Spray<'a> {
        users: HashSet<String>,
        rows: Vec<&'a EventFull>,
    }
    let mut groups: HashMap<String, Spray<'_>> = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event_code_is_any(event, &["4625", "4771"]))
    {
        let Some(source) =
            event_ip_or_workstation(event).filter(|value| !is_loopback_source(value))
        else {
            continue;
        };
        let Some(user) = event_user(event).filter(|value| !is_builtin_user(value)) else {
            continue;
        };
        let entry = groups.entry(source).or_default();
        entry.users.insert(user);
        entry.rows.push(event);
    }

    let mut out = Vec::new();
    for (source, spray) in groups {
        if spray.users.len() < 5 {
            continue;
        }
        out.push(aggregate_finding(
            case_id,
            "core-password-spray-distinct-users",
            "taotie-core",
            "パスワードスプレーの兆候 (1IP から多数ユーザー)",
            "high",
            &["T1110.003"],
            source.clone(),
            &spray.rows,
            format!(
                "source={source} から {} ユーザーへ認証失敗が集中 (events={})",
                spray.users.len(),
                spray.rows.len()
            ),
        )?);
    }
    Ok(out)
}

fn aggregate_forged_ticket(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut tgt_accounts = HashSet::new();
    for event in events.iter().filter(|event| event_code_is(event, "4768")) {
        if let Some(user) = event_user(event).filter(|value| !value.ends_with('$')) {
            tgt_accounts.insert(user);
        }
    }

    let mut tgs_by_account: HashMap<String, Vec<&EventFull>> = HashMap::new();
    for event in events.iter().filter(|event| event_code_is(event, "4769")) {
        let Some(user) = event_user(event).filter(|value| !value.ends_with('$')) else {
            continue;
        };
        tgs_by_account.entry(user).or_default().push(event);
    }

    let mut out = Vec::new();
    for (account, rows) in tgs_by_account {
        if tgt_accounts.contains(&account) {
            continue;
        }
        out.push(aggregate_finding(
            case_id,
            "core-forged-ticket-no-tgt",
            "taotie-core",
            "Golden/Silver Ticket の兆候 (4769 に対応する 4768 が無い)",
            "high",
            &["T1558"],
            account.clone(),
            &rows,
            format!(
                "account={account} はサービスチケット要求(4769)が {} 件あるが TGT 要求(4768)が無い",
                rows.len()
            ),
        )?);
    }
    Ok(out)
}

fn aggregate_off_hours_logon(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut night_rows = Vec::new();
    let mut day_count = 0usize;
    for event in events.iter().filter(|event| event_code_is(event, "4624")) {
        let logon_type = event_attr_string(event, &["LogonType", "logon_type"]).unwrap_or_default();
        if !matches!(logon_type.trim(), "2" | "10") {
            continue;
        }
        let Ok(time) = parse_utc(&event.event_time_utc) else {
            continue;
        };
        let hour = time.hour();
        if !(6..22).contains(&hour) {
            night_rows.push(event);
        } else {
            day_count += 1;
        }
    }
    let threshold = ((day_count as f64) * 0.2).max(3.0);
    if night_rows.is_empty() || (night_rows.len() as f64) < threshold {
        return Ok(Vec::new());
    }
    Ok(vec![aggregate_finding(
        case_id,
        "core-off-hours-interactive-logon",
        "taotie-core",
        "時間外の対話/RDP ログオン",
        "medium",
        &["T1078"],
        "case".to_string(),
        &night_rows,
        format!(
            "深夜帯(22-6時 UTC)の対話/RDP ログオン成功が {} 件 (日中 {} 件)",
            night_rows.len(),
            day_count
        ),
    )?])
}

fn aggregate_service_installs(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut by_host: HashMap<String, Vec<&EventFull>> = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event_code_is_any(event, &["7045", "4697"]))
    {
        let host = event
            .host
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string());
        by_host.entry(host).or_default().push(event);
    }

    let mut out = Vec::new();
    for (host, rows) in by_host {
        out.push(aggregate_finding(
            case_id,
            "core-service-install-aggregate",
            "taotie-core",
            "サービスインストールの集約",
            "high",
            &["T1543.003"],
            host.clone(),
            &rows,
            format!(
                "host={host} で新規サービス登録(7045/4697)が {} 件",
                rows.len()
            ),
        )?);
    }
    Ok(out)
}

fn aggregate_intrusion_chain(case_id: &str, events: &[EventFull]) -> Result<Vec<FindingRecord>> {
    let mut by_host: HashMap<String, Vec<(i64, &'static str, &EventFull)>> = HashMap::new();
    for event in events {
        let Some(stage) = intrusion_chain_stage(event) else {
            continue;
        };
        let Some(host) = event
            .host
            .as_deref()
            .filter(|value| !value.is_empty() && *value != "-")
        else {
            continue;
        };
        let Ok(time) = parse_utc(&event.event_time_utc) else {
            continue;
        };
        by_host
            .entry(host.to_string())
            .or_default()
            .push((time.timestamp(), stage, event));
    }

    let mut out = Vec::new();
    for (host, mut rows) in by_host {
        rows.sort_by_key(|(ts, _, _)| *ts);
        let mut best: Option<(usize, Vec<&EventFull>, Vec<&'static str>)> = None;
        let mut lo = 0usize;
        for hi in 0..rows.len() {
            while rows[hi].0 - rows[lo].0 > 3600 {
                lo += 1;
            }
            let window = &rows[lo..=hi];
            let stages = window
                .iter()
                .map(|(_, stage, _)| *stage)
                .collect::<HashSet<_>>();
            let has_serious = stages
                .iter()
                .any(|stage| matches!(*stage, "cred" | "exec" | "cleanup"));
            if stages.len() < 2 || !has_serious {
                continue;
            }
            let better = best.as_ref().map_or(true, |(best_count, best_rows, _)| {
                stages.len() > *best_count
                    || (stages.len() == *best_count && window.len() > best_rows.len())
            });
            if better {
                let mut ordered = Vec::new();
                for (_, stage, _) in window {
                    if !ordered.contains(stage) {
                        ordered.push(*stage);
                    }
                }
                best = Some((
                    stages.len(),
                    window.iter().map(|(_, _, event)| *event).collect(),
                    ordered,
                ));
            }
        }

        if let Some((stage_count, evidence, ordered)) = best {
            let sequence = ordered
                .iter()
                .map(|stage| intrusion_stage_label(stage))
                .collect::<Vec<_>>()
                .join(" -> ");
            let severity = if stage_count >= 3 { "critical" } else { "high" };
            out.push(aggregate_finding(
                case_id,
                "core-intrusion-chain-window",
                "taotie-core",
                "侵入チェーンの兆候 (時間窓内の多段イベント)",
                severity,
                &["T1570"],
                host.clone(),
                &evidence,
                format!("host={host} で1時間以内に {stage_count} ステージ連続: {sequence}"),
            )?);
        }
    }
    Ok(out)
}

fn intrusion_chain_stage(event: &EventFull) -> Option<&'static str> {
    if !event_code_bearing_artifact(&event.artifact_type) {
        return None;
    }
    let logon_type = event_attr_string(event, &["LogonType", "logon_type"]).unwrap_or_default();
    let channel = event_attr_string(event, &["channel", "Channel"]).unwrap_or_default();
    if (event_code_is_any(event, &["4624", "4648"])
        && matches!(logon_type.trim(), "3" | "9" | "10"))
        || event_code_is(event, "1149")
        || (event_code_is(event, "91") && channel.contains("WinRM"))
    {
        return Some("access");
    }

    if event_code_is_any(event, &["4769", "4662", "10"]) {
        let hay = searchable_event_text(event);
        if (event_code_is(event, "4769") && match_kerberoast_rc4(&hay))
            || (event_code_is(event, "4662") && match_dcsync(&hay))
            || event_code_is(event, "10")
        {
            return Some("cred");
        }
    }

    if event_code_is_any(event, &["7045", "4697", "4698", "106", "4720"]) {
        return Some("exec");
    }

    if event_code_is_any(event, &["1102", "104", "4719"]) {
        return Some("cleanup");
    }

    None
}

fn intrusion_stage_label(stage: &str) -> &'static str {
    match stage {
        "access" => "リモート/特権アクセス",
        "cred" => "資格情報アクセス",
        "exec" => "実行/永続化",
        "cleanup" => "痕跡消去/防御無効化",
        _ => "その他",
    }
}

fn aggregate_mft_si_fn_timestomp(
    case_id: &str,
    events: &[EventFull],
) -> Result<Vec<FindingRecord>> {
    #[derive(Default)]
    struct MftFileTimes<'a> {
        rows: Vec<&'a EventFull>,
        si_created: Option<&'a EventFull>,
        si_modified: Option<&'a EventFull>,
        fn_created: Option<&'a EventFull>,
        fn_modified: Option<&'a EventFull>,
    }

    let mut by_path: HashMap<String, MftFileTimes<'_>> = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event.artifact_type == "mft" || event.event_action.starts_with("mft_"))
    {
        let Some(path) = event
            .file_path
            .as_deref()
            .filter(|path| !path.trim().is_empty() && *path != "-")
        else {
            continue;
        };
        if !is_executable_or_script_path(path) {
            continue;
        }

        let entry = by_path.entry(normalize_path_key(path)).or_default();
        entry.rows.push(event);
        match event.event_action.as_str() {
            "mft_created" => entry.si_created = earliest_event(entry.si_created, event),
            "mft_modified" => entry.si_modified = earliest_event(entry.si_modified, event),
            "mft_filename_created" => entry.fn_created = earliest_event(entry.fn_created, event),
            "mft_filename_modified" => entry.fn_modified = earliest_event(entry.fn_modified, event),
            _ => {}
        }
    }

    let mut out = Vec::new();
    for (path, times) in by_path {
        let mut mismatches = Vec::new();
        if let Some(delta) = mft_pair_delta_seconds(times.si_created, times.fn_created) {
            if delta >= 3600 {
                mismatches.push(("created", delta));
            }
        }
        if let Some(delta) = mft_pair_delta_seconds(times.si_modified, times.fn_modified) {
            if delta >= 3600 {
                mismatches.push(("modified", delta));
            }
        }
        if mismatches.is_empty() {
            continue;
        }

        let max_delta = mismatches
            .iter()
            .map(|(_, delta)| *delta)
            .max()
            .unwrap_or_default();
        let severity = if max_delta >= 86_400 {
            "high"
        } else {
            "medium"
        };
        let summary = mismatches
            .iter()
            .map(|(kind, delta)| format!("{kind} delta={}s", delta))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(aggregate_finding(
            case_id,
            "core-mft-si-fn-timestomp",
            "taotie-core",
            "$MFT SI/FN タイムスタンプ不整合 (timestomp 兆候)",
            severity,
            &["T1070.006"],
            path.clone(),
            &times.rows,
            format!("path={path} の $STANDARD_INFORMATION と $FILE_NAME の時刻差: {summary}"),
        )?);
    }
    Ok(out)
}

fn aggregate_file_artifact_chains(
    case_id: &str,
    events: &[EventFull],
) -> Result<Vec<FindingRecord>> {
    #[derive(Default)]
    struct FileActivity<'a> {
        downloads: Vec<&'a EventFull>,
        executions: Vec<&'a EventFull>,
        defenders: Vec<&'a EventFull>,
        registry_persistence: Vec<&'a EventFull>,
        scheduled_tasks: Vec<&'a EventFull>,
        deletions: Vec<&'a EventFull>,
    }

    let mut groups: HashMap<String, FileActivity<'_>> = HashMap::new();
    for event in events {
        let Some(key) = file_chain_key(event) else {
            continue;
        };
        let entry = groups.entry(key).or_default();
        if is_download_artifact_event(event) {
            entry.downloads.push(event);
        }
        if is_execution_artifact_event(event) {
            entry.executions.push(event);
        }
        if is_defender_event(event) {
            entry.defenders.push(event);
        }
        if is_registry_persistence_event(event) {
            entry.registry_persistence.push(event);
        }
        if is_scheduled_task_event(event) {
            entry.scheduled_tasks.push(event);
        }
        if is_deletion_event(event) {
            entry.deletions.push(event);
        }
    }

    let mut out = Vec::new();
    for (key, activity) in groups {
        if activity.downloads.is_empty()
            && activity.defenders.is_empty()
            && activity.registry_persistence.is_empty()
            && activity.scheduled_tasks.is_empty()
        {
            continue;
        }
        if activity.executions.is_empty() && activity.deletions.is_empty() {
            continue;
        }

        if !activity.downloads.is_empty() && !activity.executions.is_empty() {
            let rows = unique_event_refs([&activity.downloads, &activity.executions]);
            out.push(aggregate_finding(
                case_id,
                "core-download-execute-chain",
                "taotie-core-v2",
                "ダウンロード後に実行された可能性",
                "critical",
                &["T1105", "T1204", "T1059"],
                key.clone(),
                &rows,
                format!(
                    "file={key} にダウンロード痕跡{}件と実行痕跡{}件が連結",
                    activity.downloads.len(),
                    activity.executions.len()
                ),
            )?);
        }

        if !activity.defenders.is_empty() && !activity.executions.is_empty() {
            let rows = unique_event_refs([&activity.defenders, &activity.executions]);
            out.push(aggregate_finding(
                case_id,
                "core-defender-threat-executed",
                "taotie-core-v2",
                "Defender 検知対象の実行痕跡",
                "critical",
                &["T1204", "T1059", "T1562"],
                key.clone(),
                &rows,
                format!(
                    "file={key} に Defender 関連{}件と実行痕跡{}件が連結",
                    activity.defenders.len(),
                    activity.executions.len()
                ),
            )?);
        }

        if !activity.registry_persistence.is_empty() && !activity.executions.is_empty() {
            let rows = unique_event_refs([&activity.registry_persistence, &activity.executions]);
            out.push(aggregate_finding(
                case_id,
                "core-registry-persistence-executed",
                "taotie-core-v2",
                "Registry 永続化対象の実行痕跡",
                "high",
                &["T1547.001", "T1543.003", "T1059"],
                key.clone(),
                &rows,
                format!(
                    "file={key} に Registry 永続化{}件と実行痕跡{}件が連結",
                    activity.registry_persistence.len(),
                    activity.executions.len()
                ),
            )?);
        }

        if !activity.scheduled_tasks.is_empty() && !activity.executions.is_empty() {
            let rows = unique_event_refs([&activity.scheduled_tasks, &activity.executions]);
            out.push(aggregate_finding(
                case_id,
                "core-scheduled-task-executed",
                "taotie-core-v2",
                "Scheduled Task と実行痕跡の連結",
                "high",
                &["T1053.005", "T1059"],
                key.clone(),
                &rows,
                format!(
                    "file={key} に Scheduled Task{}件と実行痕跡{}件が連結",
                    activity.scheduled_tasks.len(),
                    activity.executions.len()
                ),
            )?);
        }

        if !activity.executions.is_empty() && !activity.deletions.is_empty() {
            let rows = unique_event_refs([&activity.executions, &activity.deletions]);
            out.push(aggregate_finding(
                case_id,
                "core-execution-then-delete",
                "taotie-core-v2",
                "実行後に削除された可能性",
                "high",
                &["T1070.004", "T1059"],
                key.clone(),
                &rows,
                format!(
                    "file={key} に実行痕跡{}件と削除痕跡{}件が連結",
                    activity.executions.len(),
                    activity.deletions.len()
                ),
            )?);
        }

        if out.len() >= 500 {
            break;
        }
    }
    Ok(out)
}

fn aggregate_suspicious_execution_inventory(
    case_id: &str,
    events: &[EventFull],
) -> Result<Vec<FindingRecord>> {
    #[derive(Default)]
    struct ExecutionGroup<'a> {
        rows: Vec<&'a EventFull>,
        artifacts: HashSet<String>,
        hosts: HashSet<String>,
        users: HashSet<String>,
    }

    let mut groups: HashMap<(String, &'static str, &'static str), ExecutionGroup<'_>> =
        HashMap::new();
    for event in events {
        if !execution_inventory_candidate_event(event) {
            continue;
        }
        let signal = heuristic_candidate_text(event);
        if !has_execution_inventory_signal(event, &signal) {
            continue;
        }
        let Some((key, label, severity)) = suspicious_execution_inventory_class(event, &signal)
        else {
            continue;
        };
        let entry = groups.entry((key, label, severity)).or_default();
        entry.rows.push(event);
        entry.artifacts.insert(event.artifact_type.clone());
        if let Some(host) = event.host.as_deref().filter(|value| !value.is_empty()) {
            entry.hosts.insert(host.to_string());
        }
        if let Some(user) = event_user(event) {
            entry.users.insert(user);
        }
    }

    let mut out = Vec::new();
    for ((key, label, severity), group) in groups {
        if group.rows.is_empty() {
            continue;
        }
        let (rule_id, attack): (&str, &[&str]) = match label {
            "Remote Access Tool" => ("core-rat-execution-inventory", &["T1219"]),
            "C2 Agent" => ("core-c2-agent-execution-inventory", &["T1105", "T1059"]),
            "LOLBin/Admin Tool" => ("core-lolbin-execution-inventory", &["T1218", "T1059"]),
            "Script Artifact" => ("core-script-execution-inventory", &["T1059"]),
            "Updater Masquerade" => ("core-updater-masquerade-inventory", &["T1036"]),
            "User-writable Path" => ("core-user-writable-execution-inventory", &["T1036"]),
            _ => ("core-suspicious-execution-inventory", &["T1059"]),
        };
        let title = format!("{label} の横断実行痕跡: {key}");
        let artifacts = sorted_join(&group.artifacts);
        let hosts = sorted_join(&group.hosts);
        let users = sorted_join(&group.users);
        out.push(aggregate_finding(
            case_id,
            rule_id,
            "taotie-core-v2",
            &title,
            severity,
            attack,
            format!("{label}|{key}"),
            &group.rows,
            format!(
                "{label} key={key} artifacts=[{artifacts}] hosts=[{hosts}] users=[{users}] events={}",
                group.rows.len()
            ),
        )?);
        if out.len() >= 500 {
            break;
        }
    }
    Ok(out)
}

fn execution_inventory_candidate_event(event: &EventFull) -> bool {
    is_execution_artifact_event(event)
        || matches!(
            event.artifact_type.as_str(),
            "evtx" | "windows_event" | "sysmon" | "defender" | "registry_hive" | "scheduled_task"
        )
        || matches!(
            event.event_action.as_str(),
            "process_created" | "process_exited" | "service_installed"
        )
        || event.event_action.contains("execution")
        || event.event_action.contains("exec")
        || event.event_action.contains("process")
}

fn has_execution_inventory_signal(event: &EventFull, hay: &str) -> bool {
    is_execution_artifact_event(event)
        || matches!(
            event.event_action.as_str(),
            "process_created" | "process_exited" | "service_installed"
        )
        || event.event_action.contains("execution")
        || event.event_action.contains("exec")
        || event.event_action.contains("process")
        || contains_any(hay, HIGH_VOLUME_SUSPICIOUS_ANCHORS)
}

fn suspicious_execution_inventory_class(
    event: &EventFull,
    signal: &str,
) -> Option<(String, &'static str, &'static str)> {
    let key = suspicious_execution_key(event, signal)?;
    if match_remote_access_tool_execution(signal) {
        return Some((key, "Remote Access Tool", "high"));
    }
    if match_c2_agent_execution(signal) {
        return Some((key, "C2 Agent", "high"));
    }
    if match_updater_masquerade_execution(signal) {
        return Some((key, "Updater Masquerade", "medium"));
    }
    if is_admin_or_lolbin_key(&key) {
        let severity = if contains_any(
            signal,
            &[
                "http://",
                "https://",
                "-enc",
                "-encodedcommand",
                "downloadstring",
                "\\temp\\",
                "\\\\temp\\\\",
                "\\appdata\\",
                "\\\\appdata\\\\",
                "\\users\\public",
                "comsvcs.dll",
                "minidump",
            ],
        ) {
            "high"
        } else {
            "medium"
        };
        return Some((key, "LOLBin/Admin Tool", severity));
    }
    if is_script_key(&key) || match_script_file_execution_artifact(signal) {
        return Some((key, "Script Artifact", "medium"));
    }
    if is_executable_or_script_path(&key)
        && contains_any(
            signal,
            &[
                "\\temp\\",
                "\\\\temp\\\\",
                "\\appdata\\",
                "\\\\appdata\\\\",
                "\\programdata\\",
                "\\\\programdata\\\\",
                "\\users\\public",
            ],
        )
    {
        return Some((key, "User-writable Path", "medium"));
    }
    None
}

fn suspicious_execution_key(event: &EventFull, signal: &str) -> Option<String> {
    event
        .process_name
        .as_deref()
        .and_then(basename_key)
        .or_else(|| event.file_path.as_deref().and_then(basename_key))
        .or_else(|| event.url.as_deref().and_then(basename_key))
        .or_else(|| {
            [
                "teamviewer",
                "anydesk",
                "screenconnect",
                "merlin",
                "sliver",
                "beacon",
                "meterpreter",
            ]
            .iter()
            .find(|needle| signal.contains(**needle))
            .map(|needle| (*needle).to_string())
        })
}

fn is_admin_or_lolbin_key(key: &str) -> bool {
    matches!(
        key,
        "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "mshta.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "wmic.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
            | "wevtutil.exe"
            | "schtasks.exe"
            | "sc.exe"
    )
}

fn is_script_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta",
    ]
    .iter()
    .any(|ext| key.ends_with(ext))
}

fn earliest_event<'a>(
    current: Option<&'a EventFull>,
    candidate: &'a EventFull,
) -> Option<&'a EventFull> {
    match current {
        Some(existing) if existing.event_time_utc <= candidate.event_time_utc => Some(existing),
        _ => Some(candidate),
    }
}

fn mft_pair_delta_seconds(left: Option<&EventFull>, right: Option<&EventFull>) -> Option<i64> {
    let left = parse_utc(&left?.event_time_utc).ok()?.timestamp();
    let right = parse_utc(&right?.event_time_utc).ok()?.timestamp();
    Some((left - right).abs())
}

fn normalize_path_key(path: &str) -> String {
    path.trim().replace('\\', "/").to_ascii_lowercase()
}

fn is_executable_or_script_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        ".exe", ".dll", ".sys", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf",
        ".hta", ".msi", ".cpl", ".lnk",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
}

fn file_chain_key(event: &EventFull) -> Option<String> {
    let key = event
        .file_path
        .as_deref()
        .and_then(basename_key)
        .or_else(|| event.process_name.as_deref().and_then(basename_key))
        .or_else(|| event.url.as_deref().and_then(basename_key))?;
    if is_noise_chain_key(&key) {
        return None;
    }
    Some(key)
}

fn basename_key(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value == "-" {
        return None;
    }
    let without_fragment = value.split('#').next().unwrap_or(value);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    let name = without_query
        .rsplit(|ch| ch == '\\' || ch == '/')
        .next()
        .unwrap_or(without_query)
        .trim()
        .trim_matches(|ch: char| ch == '"' || ch == '\'' || ch == ',' || ch == ';');
    if name.len() < 4 || !name.contains('.') {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

fn is_noise_chain_key(key: &str) -> bool {
    matches!(
        key,
        "desktop.ini"
            | "thumbs.db"
            | "iconcache.db"
            | "ntuser.dat"
            | "usrclass.dat"
            | "edb.log"
            | "edb.chk"
            | "setupapi.dev.log"
            | "security.evtx"
            | "system.evtx"
            | "application.evtx"
            | "windows"
            | "desktop"
            | "inetcache"
            | "downloads"
            | "favorites"
            | "documents"
            | "pictures"
            | "videos"
            | "music"
            | "recent"
            | "history"
            | "cookies"
            | "cache"
            | "temp"
            | "tmp"
            | "logs"
            | "programdata"
            | "appdata"
            | "local"
            | "locallow"
            | "roaming"
            | "microsoft"
            | "google"
            | "chrome"
            | "edge"
            | "mozilla"
            | "firefox"
            | "default"
            | "profile"
            | "profiles"
            | "system32"
            | "syswow64"
            | "winsxs"
            | "dismhost.exe"
            | "mighost.exe"
            | "setuphost.exe"
            | "setupdiag.exe"
            | "tiworker.exe"
            | "trustedinstaller.exe"
            | "wimserv.exe"
            | "wermgr.exe"
            | "werfault.exe"
            | "mrt.exe"
            | "gatherosstate.exe"
            | "onedrivesetup.exe"
            | "onedrivestandaloneupdater.exe"
            | "microsoftedgeupdate.exe"
            | "wmiadap.exe"
            | "conhost.exe"
            | "services.exe"
            | "explorer.exe"
            | "winlogon.exe"
            | "vds.exe"
            | "smss.exe"
            | "wininit.exe"
            | "taskmgr.exe"
            | "userinit.exe"
            | "csrss.exe"
            | "compattelrunner.exe"
            | "svchost.exe"
            | "wmiprvse.exe"
            | "am_engine.exe"
            | "microsoft.sharepoint.exe"
            | "onedrive.exe"
            | "diagerr.xml"
            | "opcservices.dll"
            | "clusapi.dll"
            | "storagewmi.dll"
            | "software.log1"
            | "software.log2"
            | "system.log1"
            | "system.log2"
            | "security.log1"
            | "security.log2"
            | "sam.log1"
            | "sam.log2"
            | "default.log1"
            | "default.log2"
            | "ntuser.dat.log1"
            | "ntuser.dat.log2"
            | "usrclass.dat.log1"
            | "usrclass.dat.log2"
            | "amcache.hve.log1"
            | "amcache.hve.log2"
            | "software"
            | "system"
    )
}

fn is_download_artifact_event(event: &EventFull) -> bool {
    matches!(
        event.artifact_type.as_str(),
        "browser" | "web_cache" | "onedrive_log"
    ) || event.event_action.contains("download")
        || event
            .url
            .as_deref()
            .is_some_and(|url| is_executable_or_script_path(url) || url.ends_with(".zip"))
}

fn is_execution_artifact_event(event: &EventFull) -> bool {
    matches!(
        event.artifact_type.as_str(),
        "prefetch" | "amcache" | "lnk" | "jump_list"
    ) || matches!(
        event.event_action.as_str(),
        "process_created"
            | "process_exited"
            | "prefetch_execution"
            | "prefetch_last_run"
            | "prefetch_previous_run"
            | "amcache_program_seen"
            | "scheduled_task_suspicious_exec"
            | "scheduled_task_action_started"
            | "service_installed"
            | "registry_userassist_execution"
            | "registry_shimcache_execution"
    )
}

fn is_defender_event(event: &EventFull) -> bool {
    event.artifact_type == "defender"
        || event.event_action.starts_with("defender_")
        || event
            .message_short
            .to_ascii_lowercase()
            .contains("defender")
}

fn is_registry_persistence_event(event: &EventFull) -> bool {
    matches!(
        event.event_action.as_str(),
        "registry_run_key_persistence"
            | "registry_service_image"
            | "registry_winlogon_config"
            | "registry_wdigest_config"
            | "registry_suspicious_value"
    )
}

fn is_scheduled_task_event(event: &EventFull) -> bool {
    event.artifact_type == "scheduled_task" || event.event_action.starts_with("scheduled_task_")
}

fn is_deletion_event(event: &EventFull) -> bool {
    let action = event.event_action.to_ascii_lowercase();
    action.contains("delete") || action.contains("removed") || action == "usn_deleted"
}

fn unique_event_refs<'a, const N: usize>(groups: [&[&'a EventFull]; N]) -> Vec<&'a EventFull> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for group in groups {
        for event in group.iter().copied() {
            if seen.insert(event.event_id.clone()) {
                out.push(event);
            }
        }
    }
    out.sort_by(|left, right| {
        left.event_time_utc
            .cmp(&right.event_time_utc)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    out
}

fn aggregate_finding(
    case_id: &str,
    rule_id: &str,
    engine: &str,
    title: &str,
    severity: &str,
    attack: &[&str],
    key: String,
    rows: &[&EventFull],
    message: String,
) -> Result<FindingRecord> {
    let mut event_ids = Vec::new();
    let mut seen = HashSet::new();
    let mut first_seen = None;
    for row in rows {
        if seen.insert(row.event_id.clone()) && event_ids.len() < 500 {
            event_ids.push(row.event_id.clone());
        }
        if first_seen
            .as_deref()
            .map_or(true, |current| row.event_time_utc.as_str() < current)
        {
            first_seen = Some(row.event_time_utc.clone());
        }
    }
    let attack = attack
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    Ok(FindingRecord {
        detection_id: stable_aggregate_detection_id(case_id, rule_id, &key),
        case_id: case_id.to_string(),
        engine: engine.to_string(),
        rule_id: Some(rule_id.to_string()),
        title: title.to_string(),
        severity: severity.to_string(),
        attack_json: serde_json::to_string(&attack)?,
        event_ids_json: serde_json::to_string(&event_ids)?,
        entity_ids_json: "[]".to_string(),
        enrichment_json: "{}".to_string(),
        first_seen_utc: first_seen,
        message: Some(message),
    })
}

fn stable_aggregate_detection_id(case_id: &str, rule_id: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(case_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    format!("finding_{rule_id}_{}", hex16(&digest))
}

fn hex16(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn format_hex_dump(base_offset: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    for (line_idx, chunk) in bytes.chunks(16).enumerate() {
        let offset = base_offset + (line_idx * 16) as u64;
        out.push_str(&format!("{offset:08x}  "));
        for idx in 0..16 {
            if let Some(byte) = chunk.get(idx) {
                out.push_str(&format!("{byte:02x} "));
            } else {
                out.push_str("   ");
            }
            if idx == 7 {
                out.push(' ');
            }
        }
        out.push(' ');
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            out.push(ch);
        }
        out.push('\n');
    }
    out
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' || matches!(*byte, b'\r' | b'\n' | b'\t') {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn event_code_is(event: &EventFull, code: &str) -> bool {
    event_code_matches(event, code)
}

fn event_code_is_any(event: &EventFull, codes: &[&str]) -> bool {
    codes.iter().any(|code| event_code_matches(event, code))
}

fn event_code_matches(event: &EventFull, code: &str) -> bool {
    if !event_code_bearing_artifact(&event.artifact_type) {
        return false;
    }
    let attrs = event.attributes_json.as_str();
    let string_patterns = [
        format!("\"event_id\":\"{code}\""),
        format!("\"EventID\":\"{code}\""),
        format!("\"event_code\":\"{code}\""),
        format!("\"Id\":\"{code}\""),
    ];
    if string_patterns
        .iter()
        .any(|pattern| attrs.contains(pattern))
    {
        return true;
    }
    let numeric_patterns = [
        format!("\"event_id\":{code}"),
        format!("\"EventID\":{code}"),
        format!("\"event_code\":{code}"),
        format!("\"Id\":{code}"),
    ];
    if numeric_patterns
        .iter()
        .any(|pattern| attrs.contains(pattern))
    {
        return true;
    }
    false
}

fn event_code_bearing_artifact(artifact_type: &str) -> bool {
    matches!(
        artifact_type,
        "evtx" | "windows_event" | "sysmon" | "defender"
    )
}

fn event_user(event: &EventFull) -> Option<String> {
    event
        .user_name
        .clone()
        .or_else(|| {
            event_attr_string(
                event,
                &[
                    "TargetUserName",
                    "SubjectUserName",
                    "AccountName",
                    "UserName",
                    "User",
                ],
            )
        })
        .filter(|value| !value.trim().is_empty() && value != "-")
}

fn event_ip_or_workstation(event: &EventFull) -> Option<String> {
    event
        .ip
        .clone()
        .or_else(|| {
            event_attr_string(
                event,
                &[
                    "IpAddress",
                    "SourceNetworkAddress",
                    "ClientAddress",
                    "SourceIp",
                    "WorkstationName",
                ],
            )
        })
        .filter(|value| !value.trim().is_empty() && value != "-")
}

fn event_attr_string(event: &EventFull, keys: &[&str]) -> Option<String> {
    let parsed = serde_json::from_str::<serde_json::Value>(&event.attributes_json).ok()?;
    event_attr_string_from_value(&parsed, keys)
}

fn event_attr_string_from_value(parsed: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = parsed.get(*key).and_then(json_value_string) {
            return Some(value);
        }
        if let Some(value) = parsed
            .get("data")
            .and_then(|data| data.get(*key))
            .and_then(json_value_string)
        {
            return Some(value);
        }
    }
    let data = parsed.get("data")?.as_object()?;
    for key in keys {
        let key_lc = normalize_loose_key(key);
        for (data_key, value) in data {
            if normalize_loose_key(data_key) == key_lc {
                if let Some(value) = json_value_string(value) {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn json_value_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Object(map) => map
            .get("#text")
            .and_then(json_value_string)
            .or_else(|| map.get("value").and_then(json_value_string)),
        _ => None,
    }
}

fn is_builtin_user(user: &str) -> bool {
    let user = user.trim().to_ascii_uppercase();
    user.is_empty()
        || user.ends_with('$')
        || matches!(
            user.as_str(),
            "ANONYMOUS LOGON" | "SYSTEM" | "LOCAL SERVICE" | "NETWORK SERVICE" | "DWM-1"
        )
        || user.starts_with("DWM-")
        || user.starts_with("UMFD-")
}

fn is_loopback_source(source: &str) -> bool {
    let source = source.trim();
    source.is_empty()
        || source == "-"
        || source == "::1"
        || source == "0.0.0.0"
        || source.starts_with("127.")
        || source.starts_with("::ffff:127.")
}

fn is_private_or_loopback_ip(ip: &str) -> bool {
    let ip = ip.trim().to_ascii_lowercase();
    ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
        || ip.starts_with("::1")
        || ip.starts_with("fe80")
        || ip.starts_with("169.254.")
        || ip
            .strip_prefix("172.")
            .and_then(|rest| rest.split('.').next())
            .and_then(|octet| octet.parse::<u8>().ok())
            .is_some_and(|octet| (16..=31).contains(&octet))
}

fn short_finding_message(rule: &HeuristicRule, event: &EventFull) -> String {
    let context = event
        .message_full
        .as_str()
        .trim()
        .split('\n')
        .next()
        .filter(|value| !value.is_empty())
        .or(event.process_name.as_deref())
        .or(event.file_path.as_deref())
        .or(event.url.as_deref())
        .unwrap_or("");
    let mut snippet = context.chars().take(120).collect::<String>();
    if context.chars().count() > 120 {
        snippet.push('…');
    }
    if snippet.is_empty() {
        format!("[{}] heuristic match", rule.id)
    } else {
        format!("[{}] {}", rule.id, snippet)
    }
}

fn build_timeline_bins(events: &[taotie_schema::EventFull]) -> Vec<TimelineBin> {
    let mut bins: HashMap<(String, String), (i64, Option<String>)> = HashMap::new();
    for event in events {
        let bin = parse_utc(&event.event_time_utc)
            .map(|dt| {
                dt.with_minute(0)
                    .and_then(|dt| dt.with_second(0))
                    .and_then(|dt| dt.with_nanosecond(0))
                    .unwrap_or(dt)
                    .to_rfc3339()
            })
            .unwrap_or_else(|_| event.event_time_utc.clone());
        let key = (bin, event.artifact_type.clone());
        let entry = bins.entry(key).or_insert((0, None));
        entry.0 += 1;
        entry.1 = max_severity(entry.1.as_deref(), &event.severity).map(str::to_string);
    }
    let mut out = bins
        .into_iter()
        .map(
            |((bin_start_utc, artifact_type), (event_count, severity_max))| TimelineBin {
                case_id: events
                    .first()
                    .map(|event| event.case_id.clone())
                    .unwrap_or_default(),
                granularity: "hour".to_string(),
                bin_start_utc,
                artifact_type,
                event_count,
                severity_max,
            },
        )
        .collect::<Vec<_>>();
    out.sort_by(|a, b| {
        a.bin_start_utc
            .cmp(&b.bin_start_utc)
            .then_with(|| a.artifact_type.cmp(&b.artifact_type))
    });
    out
}

fn max_severity<'a>(left: Option<&'a str>, right: &'a str) -> Option<&'a str> {
    match left {
        None => Some(right),
        Some(left) if severity_rank(right) > severity_rank(left) => Some(right),
        Some(left) => Some(left),
    }
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

fn default_resource_limits() -> &'static str {
    r#"{"timeout_ms":30000,"memory_mb":256,"concurrency":1}"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use std::time::Duration;

    fn test_event(event_id: &str, artifact_type: &str, action: &str, message: &str) -> EventFull {
        EventFull {
            event_id: event_id.to_string(),
            case_id: "case_test".into(),
            event_time_utc: "2026-01-01T00:00:00Z".into(),
            event_time_original: "2026-01-01T00:00:00Z".into(),
            time_kind: "test".into(),
            time_confidence: 0.5,
            source_confidence: 0.8,
            artifact_type: artifact_type.into(),
            source_file_id: "file_test".into(),
            parse_run_id: "parse_test".into(),
            parser_name: "test".into(),
            parser_version: "0.1.0".into(),
            schema_version: CURRENT_SCHEMA_VERSION.into(),
            evidence_ref: "raw://sha256/test".into(),
            host: Some("HOST1".into()),
            user_name: None,
            process_name: None,
            file_path: None,
            ip: None,
            url: None,
            hash: None,
            event_action: action.into(),
            severity: "medium".into(),
            message_short: message.into(),
            message_full: message.into(),
            raw_record_ref: format!("raw_{event_id}"),
            attributes_json: "{}".into(),
        }
    }

    fn detail_from_event(event: &EventFull) -> EventDetailLight {
        EventDetailLight {
            event_id: event.event_id.clone(),
            case_id: event.case_id.clone(),
            event_time_utc: event.event_time_utc.clone(),
            event_time_original: event.event_time_original.clone(),
            time_kind: event.time_kind.clone(),
            time_confidence: event.time_confidence,
            source_confidence: event.source_confidence,
            artifact_type: event.artifact_type.clone(),
            source_file_id: event.source_file_id.clone(),
            parse_run_id: event.parse_run_id.clone(),
            parser_name: event.parser_name.clone(),
            parser_version: event.parser_version.clone(),
            schema_version: event.schema_version.clone(),
            evidence_ref: event.evidence_ref.clone(),
            host: event.host.clone(),
            user_name: event.user_name.clone(),
            process_name: event.process_name.clone(),
            file_path: event.file_path.clone(),
            ip: event.ip.clone(),
            url: event.url.clone(),
            hash: event.hash.clone(),
            event_action: event.event_action.clone(),
            severity: event.severity.clone(),
            message_short: event.message_short.clone(),
            message_full: event.message_full.clone(),
            raw_record_ref: event.raw_record_ref.clone(),
            attributes_json: event.attributes_json.clone(),
        }
    }

    fn wait_for_auto_analysis_jobs(case_root: &std::path::Path) {
        let workspace = CaseWorkspace::open(case_root).unwrap();
        let queue = JobQueue::open(workspace.jobs_db_path()).unwrap();
        for _ in 0..200 {
            let current_event_count = workspace.query_layer().lake_event_count().unwrap();
            let correlation_fresh =
                correlation_read_model_is_fresh(&workspace, current_event_count).unwrap();
            let detection_fresh =
                detection_read_model_is_fresh(&workspace, current_event_count).unwrap();
            let active = queue
                .recent(200)
                .unwrap()
                .into_iter()
                .filter(|job| {
                    matches!(job.status, JobStatus::Queued | JobStatus::Running)
                        && matches!(
                            job.kind,
                            JobKind::BuildCorrelationChains
                                | JobKind::RunFindings
                                | JobKind::BuildTantivyIndex
                        )
                })
                .count();
            if active == 0 && correlation_fresh && detection_fresh {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("auto analysis jobs did not finish in time");
    }

    #[test]
    fn fake_pipeline_records_lineage_and_lazy_detail() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        let summary = create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "demo".into(),
        })
        .unwrap();
        assert_eq!(summary.file_count, 0);
        let custody_profile = set_case_custody_profile(CaseCustodyProfileRequest {
            case_root: case_root.display().to_string(),
            investigator: Some("Analyst One".into()),
            custodian: Some("Evidence Custodian".into()),
            organization: Some("DFIR Team".into()),
            evidence_source: Some("host demo".into()),
            acquisition_method: Some("triage collection".into()),
            acquired_at: Some("2026-06-25T00:00:00Z".into()),
            legal_authority: Some("engagement ticket".into()),
            chain_of_custody_note: Some("stored in taotie case workspace".into()),
        })
        .unwrap();
        assert_eq!(custody_profile.investigator.as_deref(), Some("Analyst One"));

        let summary = ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/demo.log".into(),
            content: "INFO start\nERROR stopped\n".into(),
        })
        .unwrap();
        assert_eq!(summary.file_count, 1);
        assert_eq!(summary.event_count, 2);

        let files = get_file_page(
            case_root.to_str().unwrap(),
            FilePageQuery {
                limit: Some(10),
                cursor: None,
            },
        )
        .unwrap();
        assert_eq!(files.rows.len(), 1);
        assert_eq!(files.rows[0].parser_status, ParserStatus::Parsed);
        let verification = verify_evidence_page(EvidenceVerificationRequest {
            case_root: case_root.display().to_string(),
            limit: Some(10),
            cursor: None,
        })
        .unwrap();
        assert_eq!(verification.rows.len(), 1);
        assert!(verification.rows[0].verified);

        let events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(1),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: None,
                sort_by: None,
                sort_dir: None,
            },
        )
        .unwrap();
        assert_eq!(events.rows.len(), 1);
        assert!(events.next_cursor.is_some());
        let list_json = serde_json::to_value(&events.rows[0]).unwrap();
        assert!(list_json.get("raw_record_ref").is_none());

        let detail = get_event_detail_light(case_root.to_str().unwrap(), &events.rows[0].event_id)
            .unwrap()
            .unwrap();
        assert_eq!(detail.source_file_id, files.rows[0].file_id);
        let raw = get_event_raw_record(case_root.to_str().unwrap(), &events.rows[0].event_id)
            .unwrap()
            .unwrap();
        assert_eq!(raw.event_id, events.rows[0].event_id);

        let facets = get_event_facets(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(100),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some("ERROR".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
            Some(5),
        )
        .unwrap();
        assert!(facets
            .iter()
            .any(|row| row.field == "artifact_type" && row.count >= 1));

        let timeline = get_event_timeline(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: None,
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: None,
                sort_by: None,
                sort_dir: None,
            },
            "hour",
        )
        .unwrap();
        assert!(!timeline.is_empty(), "timeline bins should be produced");
        // String-prefix bucketing must normalize to an ISO hour boundary.
        assert!(timeline
            .iter()
            .all(|bin| bin.bin_start_utc.ends_with(":00:00Z")));
        // Per-severity counts never exceed the bin total.
        assert!(timeline
            .iter()
            .all(|bin| bin.total >= bin.critical + bin.high + bin.medium + bin.low + bin.info));
        assert!(timeline.iter().map(|bin| bin.total).sum::<i64>() >= 1);

        let dsl_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some("message:stopped severity:high -message:start".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(dsl_events.rows.len(), 1);
        assert!(dsl_events.rows[0].message_short.contains("stopped"));
        let regex_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some("re:/stopp.*/".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(regex_events.rows.len(), 1);
        let boolean_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some("(message:start OR message:stopped) severity:high".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(boolean_events.rows.len(), 1);
        assert!(boolean_events.rows[0].message_short.contains("stopped"));
        let explicit_not_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some("message:stopped AND NOT message:start".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(explicit_not_events.rows.len(), 1);
        let all_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: None,
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert!(all_events.rows.len() >= 2);
        let id_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some(format!("id:{}", all_events.rows[1].event_id)),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(id_events.rows.len(), 1);
        assert_eq!(id_events.rows[0].event_id, all_events.rows[1].event_id);
        let time_window_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some(format!(
                    "after:{} before:{}",
                    all_events.rows[1].event_time_utc, all_events.rows[1].event_time_utc
                )),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(time_window_events.rows.len(), 1);
        assert_eq!(
            time_window_events.rows[0].event_id,
            all_events.rows[1].event_id
        );
        let search_metadata = build_search_index(BuildSearchIndexRequest {
            case_root: case_root.display().to_string(),
        })
        .unwrap();
        assert_eq!(search_metadata.indexed_event_count, 2);
        let loaded_search_metadata = get_search_index_metadata(case_root.to_str().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded_search_metadata.indexed_event_count,
            search_metadata.indexed_event_count
        );
        let search_status = get_search_index_status(case_root.to_str().unwrap()).unwrap();
        assert_eq!(search_status.current_event_count, 2);
        assert!(!search_status.is_stale);
        assert!(search_status.active_job.is_none());
        let indexed_hits = search_indexed_events(EventSearchIndexRequest {
            case_root: case_root.display().to_string(),
            text: "stopped".into(),
            limit: Some(10),
            cursor: None,
        })
        .unwrap();
        assert_eq!(indexed_hits.rows.len(), 1);
        assert!(indexed_hits.rows[0].message_short.contains("stopped"));
        let indexed_first_page = search_indexed_events(EventSearchIndexRequest {
            case_root: case_root.display().to_string(),
            text: String::new(),
            limit: Some(1),
            cursor: None,
        })
        .unwrap();
        assert_eq!(indexed_first_page.rows.len(), 1);
        assert!(indexed_first_page.next_cursor.is_some());
        let saved_searches = save_saved_search(SavedSearchRequest {
            case_root: case_root.display().to_string(),
            name: "Errors only".into(),
            query: EventPageQuery {
                limit: Some(100),
                cursor: Some("ignored_cursor".into()),
                artifact_type: None,
                user_name: None,
                search: Some("ERROR".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
            description: Some("error investigation pivot".into()),
            created_by: Some("analyst".into()),
            visibility: Some("restricted".into()),
            shared_with: Some(vec!["lead".into()]),
        })
        .unwrap();
        assert_eq!(saved_searches.len(), 1);
        assert_eq!(saved_searches[0].query.cursor, None);
        assert_eq!(saved_searches[0].visibility, "restricted");
        assert_eq!(saved_searches[0].shared_with, vec!["lead".to_string()]);
        let saved_search_id = saved_searches[0].search_id.clone();
        let loaded_searches = get_saved_searches(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert_eq!(loaded_searches[0].name, "Errors only");
        let lead_searches =
            get_saved_searches_for(case_root.to_str().unwrap(), Some(10), Some("lead")).unwrap();
        assert_eq!(lead_searches.len(), 1);
        let outsider_searches =
            get_saved_searches_for(case_root.to_str().unwrap(), Some(10), Some("outsider"))
                .unwrap();
        assert!(outsider_searches.is_empty());
        assert!(delete_saved_search(DeleteSavedSearchRequest {
            case_root: case_root.display().to_string(),
            search_id: saved_search_id.clone(),
            requested_by: Some("lead".into()),
        })
        .is_err());

        let coverage = get_coverage_summary(case_root.to_str().unwrap()).unwrap();
        assert_eq!(coverage[0].parsed_files, 1);
        let jobs = get_recent_jobs(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert!(jobs.iter().any(|job| job.kind == JobKind::ParseArtifact));
        assert!(jobs
            .iter()
            .any(|job| job.kind == JobKind::BuildTantivyIndex));
        let reviews = set_finding_review(FindingReviewRequest {
            case_root: case_root.display().to_string(),
            engine: "taotie-test".into(),
            rule_id: Some("demo-rule".into()),
            title: "demo finding".into(),
            status: "confirmed".into(),
            reviewer: Some("analyst".into()),
            assignee: Some("lead".into()),
            tags: Some(vec!["initial_access".into(), "reviewed".into()]),
            due_at: Some("2026-07-01T00:00:00Z".into()),
            comment: Some("reviewed".into()),
        })
        .unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].status, "confirmed");
        assert_eq!(reviews[0].assignee.as_deref(), Some("lead"));
        assert_eq!(
            get_finding_review_summary(case_root.to_str().unwrap())
                .unwrap()
                .tagged_count,
            1
        );
        let triage_actions = get_triage_actions(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert!(triage_actions.len() <= 10);
        let audit = get_audit_log(case_root.to_str().unwrap(), Some(50)).unwrap();
        assert!(audit.iter().any(|row| row.action == "case_created"));
        assert!(audit
            .iter()
            .any(|row| row.action == "case_custody_profile_updated"));
        assert!(audit.iter().any(|row| row.action == "artifact_ingested"));
        assert!(audit.iter().any(|row| row.action == "search_index_built"));
        assert!(audit
            .iter()
            .any(|row| row.action == "finding_review_updated"));
        assert!(audit.iter().any(|row| row.action == "saved_search_saved"));
        let report_path = generate_case_report(case_root.to_str().unwrap(), None).unwrap();
        let report = std::fs::read_to_string(report_path).unwrap();
        assert!(report.contains("## ケース概要"));
        assert!(report.contains("## Case Custody"));
        assert!(report.contains("Analyst One"));
        assert!(report.contains("## Parser Coverage"));
        assert!(report.contains("## 実ケース検知評価"));
        assert!(report.contains("### 検知目的別カバレッジ"));
        assert!(report.contains("### 調査/報告品質ゲート"));
        assert!(report.contains("## Evidence Ledger"));
        assert!(report.contains("## Evidence Verification"));
        assert!(report.contains("## Triage Queue"));
        assert!(report.contains("## Review Summary"));
        assert!(report.contains("## Review Status"));
        assert!(report.contains("## Saved Searches"));
        assert!(report.contains("## Audit Trail"));
        assert!(report.contains("demo finding"));
        assert!(report.contains("Errors only"));
        assert!(report.contains("initial_access"));
        assert!(report.contains("raw://sha256/"));
        let evaluation = get_case_detection_evaluation(case_root.to_str().unwrap()).unwrap();
        assert!(evaluation.applicable_objective_count > 0);
        assert!(evaluation
            .quality_gates
            .iter()
            .any(|row| row.gate_id == "evidence_verification"));
        let deleted_searches = delete_saved_search(DeleteSavedSearchRequest {
            case_root: case_root.display().to_string(),
            search_id: saved_search_id,
            requested_by: Some("analyst".into()),
        })
        .unwrap();
        assert!(deleted_searches.is_empty());
        let manifest_path = generate_custody_manifest(case_root.to_str().unwrap(), None).unwrap();
        let manifest = std::fs::read_to_string(&manifest_path).unwrap();
        assert!(manifest.contains("taotie_custody_manifest_v1"));
        assert!(manifest.contains("manifest_sha256"));
        assert!(manifest.contains("Analyst One"));
        let verification = verify_custody_manifest(CustodyManifestVerificationRequest {
            case_root: case_root.display().to_string(),
            manifest_path,
            evidence_limit: Some(10),
        })
        .unwrap();
        assert!(verification.manifest_hash_ok);
        assert!(verification.manifest_type_ok);
        assert!(verification.case_id_matches);
        assert_eq!(verification.evidence_hash_mismatch_count, 0);
        let bundle_path = generate_report_bundle(case_root.to_str().unwrap(), None).unwrap();
        let bundle = std::fs::read_to_string(&bundle_path).unwrap();
        assert!(bundle.contains("taotie_report_bundle_v1"));
        assert!(bundle.contains("case_custody_profile_sha256"));
        assert!(bundle.contains("case_detection_evaluation"));
        assert!(bundle.contains("\"signature\""));
        assert!(bundle.contains("ed25519"));
        let bundle_verification = verify_report_bundle(ReportBundleVerificationRequest {
            case_root: case_root.display().to_string(),
            bundle_path: bundle_path.clone(),
        })
        .unwrap();
        assert!(bundle_verification.bundle_hash_ok);
        assert!(bundle_verification.bundle_type_ok);
        assert!(bundle_verification.case_id_matches);
        assert!(bundle_verification.report_hash_ok);
        assert!(bundle_verification.custody_manifest_hash_ok);
        assert!(bundle_verification.custody_manifest_internal_hash_ok);
        assert!(bundle_verification.custody_manifest_type_ok);
        assert!(bundle_verification.case_custody_profile_hash_ok);
        assert!(bundle_verification.signature_present);
        assert!(bundle_verification.signature_payload_hash_ok);
        assert!(bundle_verification.signature_valid);
        assert!(bundle_verification.signature_key_matches_case_key);
        assert!(bundle_verification.audit_log_unchanged);
        let mut tampered_bundle =
            serde_json::from_str::<serde_json::Value>(&bundle).expect("bundle json");
        tampered_bundle["payload"]["schema_version"] = serde_json::json!("tampered");
        let tampered_bundle_path = case_root
            .join("reports")
            .join("tampered_report_bundle.json");
        std::fs::write(
            &tampered_bundle_path,
            serde_json::to_vec_pretty(&tampered_bundle).unwrap(),
        )
        .unwrap();
        let tampered_verification = verify_report_bundle(ReportBundleVerificationRequest {
            case_root: case_root.display().to_string(),
            bundle_path: tampered_bundle_path.display().to_string(),
        })
        .unwrap();
        assert!(!tampered_verification.bundle_hash_ok);
        assert!(tampered_verification.signature_present);
        assert!(!tampered_verification.signature_payload_hash_ok);
        assert!(!tampered_verification.signature_valid);
        let approvals = set_case_approval(CaseApprovalRequest {
            case_root: case_root.display().to_string(),
            target_kind: "report_bundle".into(),
            target_id: None,
            target_path: Some(bundle_path.clone()),
            target_sha256: bundle_verification.bundle_sha256.clone(),
            status: "approved".into(),
            approver: Some("Lead Reviewer".into()),
            role: Some("case supervisor".into()),
            comment: Some("signed bundle verified and approved".into()),
        })
        .unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].status, "approved");
        assert_eq!(approvals[0].approver.as_deref(), Some("Lead Reviewer"));
        assert!(approvals[0].target_sha256.is_some());
        let approval_report_path = generate_case_report(case_root.to_str().unwrap(), None).unwrap();
        let approval_report = std::fs::read_to_string(approval_report_path).unwrap();
        assert!(approval_report.contains("## Case Approvals"));
        assert!(approval_report.contains("Lead Reviewer"));
        assert!(approval_report.contains("signed bundle verified and approved"));
        let audit = get_audit_log(case_root.to_str().unwrap(), Some(20)).unwrap();
        assert!(audit
            .iter()
            .any(|row| row.action == "case_report_generated"));
        assert!(audit.iter().any(|row| row.action == "evidence_verified"));
        assert!(audit
            .iter()
            .any(|row| row.action == "custody_manifest_generated"));
        assert!(audit
            .iter()
            .any(|row| row.action == "custody_manifest_verified"));
        assert!(audit
            .iter()
            .any(|row| row.action == "report_signing_key_created"));
        assert!(audit
            .iter()
            .any(|row| row.action == "case_approval_updated"));
        assert!(audit.iter().any(|row| row.action == "saved_search_deleted"));
        assert!(audit
            .iter()
            .any(|row| row.action == "report_bundle_generated"));
        assert!(audit
            .iter()
            .any(|row| row.action == "report_bundle_verified"));
    }

    #[test]
    fn search_index_build_can_run_in_background_job() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "background-search".into(),
        })
        .unwrap();
        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/demo.log".into(),
            content: "INFO service started\nERROR powershell encoded command\n".into(),
        })
        .unwrap();
        let pre_status = get_search_index_status(case_root.to_str().unwrap()).unwrap();
        assert_eq!(pre_status.current_event_count, 2);
        assert!(pre_status.is_stale);
        assert!(pre_status.metadata.is_none());
        assert!(pre_status.active_job.is_none());

        let job = start_search_index_build(StartSearchIndexBuildRequest {
            case_root: case_root.display().to_string(),
        })
        .unwrap();
        assert_eq!(job.kind, JobKind::BuildTantivyIndex);

        let mut finished = None;
        for _ in 0..100 {
            let jobs = get_recent_jobs(case_root.to_str().unwrap(), Some(20)).unwrap();
            let Some(current) = jobs.into_iter().find(|row| row.job_id == job.job_id) else {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            if matches!(current.status, JobStatus::Succeeded | JobStatus::Failed) {
                finished = Some(current);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let finished = finished.expect("background search index job should finish");
        assert_eq!(finished.status, JobStatus::Succeeded);
        let metadata = get_search_index_metadata(case_root.to_str().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(metadata.indexed_event_count, 2);
        let post_status = get_search_index_status(case_root.to_str().unwrap()).unwrap();
        assert_eq!(post_status.current_event_count, 2);
        assert!(!post_status.is_stale);
        assert!(post_status.metadata.is_some());
        assert!(post_status.active_job.is_none());
        let hits = search_indexed_events(EventSearchIndexRequest {
            case_root: case_root.display().to_string(),
            text: "encoded".into(),
            limit: Some(10),
            cursor: None,
        })
        .unwrap();
        assert_eq!(hits.rows.len(), 1);

        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/later.log".into(),
            content: "WARN new event after index\n".into(),
        })
        .unwrap();
        let mut refreshed_status = None;
        for _ in 0..100 {
            let status = get_search_index_status(case_root.to_str().unwrap()).unwrap();
            if status
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.indexed_event_count == 3)
                && !status.is_stale
            {
                refreshed_status = Some(status);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let refreshed_status = refreshed_status.expect("auto search index refresh should finish");
        assert_eq!(refreshed_status.current_event_count, 3);
        assert!(!refreshed_status.is_stale);
        let incremental_metadata = refreshed_status.metadata.unwrap();
        assert_eq!(
            incremental_metadata.build_mode.as_deref(),
            Some("incremental_append")
        );
        assert_eq!(incremental_metadata.appended_event_count, Some(1));
        let refreshed_hits = search_indexed_events(EventSearchIndexRequest {
            case_root: case_root.display().to_string(),
            text: "later".into(),
            limit: Some(10),
            cursor: None,
        })
        .unwrap();
        assert_eq!(refreshed_hits.rows.len(), 1);
    }

    #[test]
    fn search_index_start_reuses_active_job() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "dedupe-search".into(),
        })
        .unwrap();
        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/demo.log".into(),
            content: "INFO service started\n".into(),
        })
        .unwrap();

        let workspace = CaseWorkspace::open(&case_root).unwrap();
        let queue = JobQueue::open(workspace.jobs_db_path()).unwrap();
        let existing = enqueue_search_index_job(&workspace, &queue, "test", 35).unwrap();
        let returned = start_search_index_build(StartSearchIndexBuildRequest {
            case_root: case_root.display().to_string(),
        })
        .unwrap();
        assert_eq!(returned.job_id, existing.job_id);
        let active_status = get_search_index_status(case_root.to_str().unwrap()).unwrap();
        assert_eq!(
            active_status
                .active_job
                .as_ref()
                .map(|job| job.job_id.as_str()),
            Some(existing.job_id.as_str())
        );
        let real_active_count = get_recent_jobs(case_root.to_str().unwrap(), Some(20))
            .unwrap()
            .into_iter()
            .filter(|job| matches!(job.status, JobStatus::Queued | JobStatus::Running))
            .filter(is_real_search_index_job)
            .count();
        assert_eq!(real_active_count, 1);
    }

    #[test]
    fn recursive_ingest_auto_refreshes_existing_search_index() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "auto-refresh-recursive-search".into(),
        })
        .unwrap();
        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/before.log".into(),
            content: "INFO baseline event\n".into(),
        })
        .unwrap();
        let initial = build_search_index(BuildSearchIndexRequest {
            case_root: case_root.display().to_string(),
        })
        .unwrap();
        assert_eq!(initial.indexed_event_count, 1);

        let source_dir = temp.path().join("collection");
        let nested_dir = source_dir.join("nested");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(
            source_dir.join("one.log"),
            b"ERROR powershell encoded command\n",
        )
        .unwrap();
        std::fs::write(nested_dir.join("two.log"), b"WARN merlin beacon observed\n").unwrap();
        let result = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: source_dir.display().to_string(),
            recursive: Some(true),
        })
        .unwrap();
        assert_eq!(result.file_count, 2);
        assert_eq!(result.failed_count, 0);

        let mut refreshed_status = None;
        for _ in 0..100 {
            let status = get_search_index_status(case_root.to_str().unwrap()).unwrap();
            if status
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.indexed_event_count == status.current_event_count)
                && !status.is_stale
                && status.current_event_count >= 3
            {
                refreshed_status = Some(status);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let refreshed_status =
            refreshed_status.expect("recursive ingest should auto-refresh existing search index");
        let metadata = refreshed_status.metadata.unwrap();
        assert_eq!(metadata.build_mode.as_deref(), Some("incremental_append"));
        assert_eq!(metadata.appended_event_count, Some(4));
        let hits = search_indexed_events(EventSearchIndexRequest {
            case_root: case_root.display().to_string(),
            text: "merlin".into(),
            limit: Some(10),
            cursor: None,
        })
        .unwrap();
        assert_eq!(hits.rows.len(), 2);
    }

    #[test]
    fn auto_correlation_read_model_job_rebuilds_missing_model() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            CaseWorkspace::create(temp.path().join("case"), "auto-correlation").unwrap();
        let case_id = workspace.manifest().case_id.clone();
        let mut download = test_event(
            "event_download",
            "browser",
            "browser_download",
            "downloaded C:\\Temp\\evil.exe",
        );
        download.case_id = case_id.clone();
        download.event_time_utc = "2026-01-01T00:00:00Z".into();
        download.file_path = Some("C:\\Temp\\evil.exe".into());
        download.process_name = Some("msedge.exe".into());
        let mut execution = test_event(
            "event_execution",
            "prefetch",
            "prefetch_execution",
            "Prefetch execution observed: EVIL.EXE",
        );
        execution.case_id = case_id;
        execution.event_time_utc = "2026-01-01T00:02:00Z".into();
        execution.process_name = Some("evil.exe".into());
        workspace
            .append_events_full(&[download, execution])
            .unwrap();
        let queue = JobQueue::open(workspace.jobs_db_path()).unwrap();

        let job = maybe_start_auto_correlation_read_model_refresh(
            &workspace,
            &queue,
            "test_missing_model",
        )
        .unwrap()
        .expect("missing correlation read model should enqueue a background job");

        let mut completed = None;
        for _ in 0..400 {
            let current_queue = JobQueue::open(workspace.jobs_db_path()).unwrap();
            let current = current_queue.get(&job.job_id).unwrap().unwrap();
            if matches!(current.status, JobStatus::Succeeded | JobStatus::Failed) {
                completed = Some(current);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let completed = completed.expect("correlation read model job should complete");
        assert_eq!(completed.status, JobStatus::Succeeded);
        let chains = workspace
            .query_layer()
            .correlation_chains(Some(10))
            .unwrap();
        assert!(chains
            .iter()
            .any(|chain| chain.key_value == "evil.exe" && chain.event_count >= 2));
    }

    #[test]
    fn auto_correlation_read_model_skips_fresh_empty_result() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "fresh-empty-correlation".into(),
        })
        .unwrap();
        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/single.log".into(),
            content: "INFO service started\n".into(),
        })
        .unwrap();
        let workspace = CaseWorkspace::open(&case_root).unwrap();
        let queue = JobQueue::open(workspace.jobs_db_path()).unwrap();

        let job =
            maybe_start_auto_correlation_read_model_refresh(&workspace, &queue, "fresh_empty")
                .unwrap();
        assert!(job.is_none());
    }

    #[test]
    fn auto_analysis_jobs_chain_correlation_then_detection_risk() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        let workspace = CaseWorkspace::create(&case_root, "auto-analysis-chain").unwrap();
        let case_id = workspace.manifest().case_id.clone();
        let mut download = test_event(
            "event_download",
            "browser",
            "browser_download",
            "downloaded C:\\Temp\\evil.exe",
        );
        download.case_id = case_id.clone();
        download.event_time_utc = "2026-01-01T00:00:00Z".into();
        download.file_path = Some("C:\\Temp\\evil.exe".into());
        download.process_name = Some("msedge.exe".into());
        let mut execution = test_event(
            "event_execution",
            "prefetch",
            "prefetch_execution",
            "Prefetch execution observed: EVIL.EXE",
        );
        execution.case_id = case_id;
        execution.event_time_utc = "2026-01-01T00:02:00Z".into();
        execution.process_name = Some("evil.exe".into());
        workspace
            .append_events_full(&[download, execution])
            .unwrap();

        let jobs =
            start_analysis_read_model_jobs(case_root.to_str().unwrap(), Some("test_reload".into()))
                .unwrap();
        assert!(jobs
            .iter()
            .any(|job| job.kind == JobKind::BuildCorrelationChains));

        let mut detection_finished = None;
        for _ in 0..500 {
            let jobs = get_recent_jobs(case_root.to_str().unwrap(), Some(50)).unwrap();
            if let Some(job) = jobs
                .into_iter()
                .find(|job| job.kind == JobKind::RunFindings && job.status == JobStatus::Succeeded)
            {
                detection_finished = Some(job);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let detection_finished = detection_finished.expect("detection/risk job should complete");
        assert_eq!(detection_finished.status, JobStatus::Succeeded);
        let risks = get_risk_summary(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert!(risks.iter().any(|row| row.technique == "T1105"));
        assert!(risks.iter().any(|row| row.technique == "T1204"));
    }

    #[test]
    fn unsupported_files_are_visible() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "demo".into(),
        })
        .unwrap();

        let summary = ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/security.evtx".into(),
            content: "not parsed by fake parser".into(),
        })
        .unwrap();
        assert_eq!(summary.unsupported_file_count, 1);
        let coverage = get_coverage_summary(case_root.to_str().unwrap()).unwrap();
        assert_eq!(coverage[0].unsupported_files, 1);
    }

    #[test]
    fn local_path_ingest_supports_evidence_range_hex_view() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "local-path".into(),
        })
        .unwrap();
        let source_dir = temp.path().join("triage");
        std::fs::create_dir_all(&source_dir).unwrap();
        let source_file = source_dir.join("sample.bin");
        std::fs::write(&source_file, b"MZ\x90\x00demo-evidence").unwrap();

        let result = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: source_dir.display().to_string(),
            recursive: Some(true),
        })
        .unwrap();
        assert_eq!(result.file_count, 1);
        assert_eq!(result.failed_count, 0);
        assert_eq!(result.summary.file_count, 1);

        let files = get_file_page(
            case_root.to_str().unwrap(),
            FilePageQuery {
                limit: Some(10),
                cursor: None,
            },
        )
        .unwrap();
        let range = get_evidence_range(EvidenceRangeRequest {
            case_root: case_root.display().to_string(),
            object_ref: files.rows[0].object_ref.clone(),
            offset: Some(0),
            length: Some(16),
        })
        .unwrap();
        assert_eq!(range.offset, 0);
        assert_eq!(range.length, 16);
        assert!(range.hex_dump.contains("4d 5a 90 00"));
        assert!(range.ascii_preview.contains("MZ"));
    }

    #[test]
    fn recursive_local_path_reingest_skips_existing_parsed_files() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "local-path-dedupe".into(),
        })
        .unwrap();
        let source_dir = temp.path().join("triage");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("alpha.log"), b"INFO alpha\n").unwrap();
        std::fs::write(source_dir.join("beta.log"), b"INFO beta\n").unwrap();

        let first = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: source_dir.display().to_string(),
            recursive: Some(true),
        })
        .unwrap();
        assert_eq!(first.file_count, 2);
        assert_eq!(first.skipped_count, 0);
        assert_eq!(first.failed_count, 0);

        let second = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: source_dir.display().to_string(),
            recursive: Some(true),
        })
        .unwrap();
        assert_eq!(second.file_count, 0);
        assert_eq!(second.skipped_count, 2);
        assert_eq!(second.failed_count, 0);
        assert_eq!(second.summary.file_count, 2);
    }

    #[test]
    fn local_original_path_strips_common_collection_wrapper() {
        assert_eq!(
            normalize_local_original_path("Triage/uploads/auto/C%3A/Windows/System32/config/SAM"),
            "uploads/auto/C%3A/Windows/System32/config/SAM"
        );
        assert_eq!(
            normalize_local_original_path("Collection/C/Windows/System32/config/SAM"),
            "C/Windows/System32/config/SAM"
        );
        assert_eq!(normalize_local_original_path("Triage.zip"), "Triage.zip");
    }

    #[test]
    fn recursive_local_path_ingest_batches_analysis_rebuild() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "recursive-local-path".into(),
        })
        .unwrap();
        let source_dir = temp.path().join("collection");
        let nested_dir = source_dir.join("C").join("Windows");
        let task_dir = nested_dir.join("System32").join("Tasks");
        std::fs::create_dir_all(&task_dir).unwrap();
        std::fs::write(
            source_dir.join("Security.evtx.xml"),
            br#"<Events>
              <Event><System><EventID>4688</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Computer>HOST1</Computer></System><EventData><Data Name="SubjectUserName">alice</Data><Data Name="NewProcessName">C:\Temp\evil.exe</Data></EventData></Event>
            </Events>"#,
        )
        .unwrap();
        std::fs::write(
            nested_dir.join("MFT_Output.csv"),
            b"EntryNumber,SequenceNumber,FullPath,Created0x10\n1,1,C:\\Temp\\evil.exe,2026-01-01 00:02:00\n",
        )
        .unwrap();
        std::fs::write(
            source_dir.join("browser_history.json"),
            br#"[{"url":"https://example.test/download/evil.exe","title":"download","last_visit_time":"2026-01-01T00:00:30Z"}]"#,
        )
        .unwrap();
        std::fs::write(
            source_dir.join("PECmd_Output.csv"),
            b"SourceFilename,ExecutableName,RunCount,LastRun\nC:\\Windows\\Prefetch\\EVIL.EXE-1234ABCD.pf,evil.exe,2,2026-01-01 00:03:00\n",
        )
        .unwrap();
        std::fs::write(
            nested_dir.join("UsnJrnl_Output.csv"),
            b"Timestamp,FileName,FileReferenceNumber,Reason\n2026-01-01 00:04:00,C:\\Temp\\evil.exe,42,File_Delete\n",
        )
        .unwrap();
        std::fs::write(
            task_dir.join("EvilTask"),
            br#"<Task version="1.4"><RegistrationInfo><URI>\EvilTask</URI></RegistrationInfo><Triggers><TimeTrigger><StartBoundary>2026-01-01T00:05:00</StartBoundary></TimeTrigger></Triggers><Principals><Principal><UserId>alice</UserId></Principal></Principals><Actions><Exec><Command>C:\Temp\evil.exe</Command><Arguments>-run</Arguments></Exec></Actions></Task>"#,
        )
        .unwrap();

        let result = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: source_dir.display().to_string(),
            recursive: Some(true),
        })
        .unwrap();
        assert_eq!(result.file_count, 6);
        assert_eq!(result.failed_count, 0);
        assert_eq!(result.summary.file_count, 6);
        assert!(result.summary.event_count >= 6);

        let files = get_file_page(
            case_root.to_str().unwrap(),
            FilePageQuery {
                limit: Some(10),
                cursor: None,
            },
        )
        .unwrap();
        assert_eq!(files.rows.len(), 6);
        assert!(files
            .rows
            .iter()
            .any(|file| file.original_path.ends_with("C/Windows/MFT_Output.csv")));
        assert!(files.rows.iter().any(|file| {
            file.artifact_type == "scheduled_task" && file.original_path.ends_with("Tasks/EvilTask")
        }));
        wait_for_auto_analysis_jobs(&case_root);

        let chains = get_correlation_chains(case_root.to_str().unwrap(), Some(20)).unwrap();
        assert!(chains
            .iter()
            .any(|row| row.key_value.contains("evil.exe") && row.event_count >= 5));
        let findings = get_finding_summary(case_root.to_str().unwrap(), Some(20)).unwrap();
        assert!(findings.iter().any(|row| {
            row.engine == "correlation"
                && row.title.contains("ダウンロードされたファイルが実行された")
        }));
        assert!(findings
            .iter()
            .any(|row| row.rule_id.as_deref() == Some("scheduled-task-payload")));

        let evaluation = get_case_detection_evaluation(case_root.to_str().unwrap()).unwrap();
        assert!(evaluation.detection_coverage_rate > 0.0);
        assert!(
            evaluation
                .objectives
                .iter()
                .any(|row| row.objective_id == "cross_artifact_correlation"
                    && row.status == "covered")
        );
        assert!(evaluation
            .quality_gates
            .iter()
            .any(|row| row.gate_id == "evidence_verification" && row.status != "pass"));
        let triage_actions = get_triage_actions(case_root.to_str().unwrap(), Some(50)).unwrap();
        assert!(triage_actions
            .iter()
            .any(|row| row.source_kind == "case_quality_gate"));

        let analyzer_runs = get_analyzer_runs(case_root.to_str().unwrap(), Some(50)).unwrap();
        assert_eq!(
            analyzer_runs
                .iter()
                .filter(|run| matches!(
                    run.analyzer_id.as_str(),
                    "heuristic_findings" | "detection_findings"
                ))
                .count(),
            1
        );
        assert_eq!(
            analyzer_runs
                .iter()
                .filter(|run| run.analyzer_id == "correlation_chains")
                .count(),
            1
        );
    }

    #[test]
    fn recursive_local_path_ingest_prioritizes_ntfs_core_artifacts() {
        let base = std::path::PathBuf::from("/collection");
        let mut files = vec![
            base.join("memory-capture-01.vmem"),
            base.join("Triage/uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx"),
            base.join("Triage/uploads/ntfs/%5C%5C.%5CC%3A/$MFT"),
            base.join("Triage/uploads/auto/C%3A/Windows/Prefetch/POWERSHELL.EXE-1234.pf"),
            base.join("Triage/uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl/$J"),
            base.join("Triage/uploads/auto/C%3A/Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"),
        ];

        sort_local_source_files(&mut files, &base);
        let ordered = files
            .iter()
            .map(|path| local_original_path(path, &base))
            .collect::<Vec<_>>();

        assert_eq!(ordered[0], "uploads/ntfs/%5C%5C.%5CC%3A/$MFT");
        assert_eq!(
            ordered[1],
            "uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl/$J"
        );
        assert!(ordered[2].ends_with("Security.evtx"));
        assert!(ordered[3].ends_with("POWERSHELL.EXE-1234.pf"));
        assert!(ordered.last().is_some_and(|path| path.ends_with(".vmem")));
    }

    #[test]
    fn artifact_ingest_defers_synchronous_analysis_rebuild() {
        assert!(!should_defer_synchronous_analysis_rebuild("mft", 1));
        assert!(should_defer_synchronous_analysis_rebuild("mft", 1_001));
        assert!(should_defer_synchronous_analysis_rebuild("usn_jrnl", 1_001));
        assert!(should_defer_synchronous_analysis_rebuild(
            "ntfs_logfile",
            1_001
        ));
        assert!(!should_defer_synchronous_analysis_rebuild("evtx", 1));
        assert!(should_defer_synchronous_analysis_rebuild(
            "evtx",
            SYNC_ANALYSIS_EVENT_LIMIT + 1
        ));
        assert!(!should_defer_synchronous_analysis_rebuild("text_log", 1));
    }

    #[test]
    fn stale_background_jobs_are_not_considered_active() {
        let fresh = test_background_job(JobStatus::Running, 1, Some(1));
        let stale = test_background_job(
            JobStatus::Running,
            BACKGROUND_JOB_STALE_AFTER_MINUTES + 30,
            Some(BACKGROUND_JOB_STALE_AFTER_MINUTES + 30),
        );
        let old_queued = test_background_job(
            JobStatus::Queued,
            BACKGROUND_JOB_STALE_AFTER_MINUTES + 30,
            None,
        );

        assert!(background_job_is_fresh(&fresh));
        assert!(!background_job_is_fresh(&stale));
        assert!(!background_job_is_fresh(&old_queued));
    }

    fn test_background_job(
        status: JobStatus,
        updated_minutes_ago: i64,
        heartbeat_minutes_ago: Option<i64>,
    ) -> JobRecord {
        let updated_at = (Utc::now() - chrono::Duration::minutes(updated_minutes_ago)).to_rfc3339();
        let heartbeat_at = heartbeat_minutes_ago
            .map(|minutes| (Utc::now() - chrono::Duration::minutes(minutes)).to_rfc3339());
        JobRecord {
            job_id: "job_test".into(),
            case_id: "case_test".into(),
            kind: JobKind::BuildCorrelationChains,
            status,
            priority: 1,
            progress: 0.0,
            attempts: 0,
            max_attempts: 3,
            created_at: updated_at.clone(),
            updated_at,
            started_at: None,
            finished_at: None,
            worker_id: None,
            heartbeat_at,
            cancel_requested: false,
            resource_limits_json: "{}".into(),
            payload_json: "{}".into(),
            error_message: None,
        }
    }

    #[test]
    fn recursive_ingest_surfaces_hunter_recovery_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "hunter-recovery".into(),
        })
        .unwrap();
        let source_dir = temp.path().join("HunterCollection");
        let filezilla_dir = source_dir
            .join("C")
            .join("Users")
            .join("alice")
            .join("AppData")
            .join("Roaming")
            .join("FileZilla");
        let chrome_dir = source_dir
            .join("C")
            .join("Users")
            .join("alice")
            .join("AppData")
            .join("Local")
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default");
        let protect_dir = source_dir
            .join("C")
            .join("Users")
            .join("alice")
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Protect")
            .join("S-1-5-21");
        std::fs::create_dir_all(&filezilla_dir).unwrap();
        std::fs::create_dir_all(&chrome_dir).unwrap();
        std::fs::create_dir_all(&protect_dir).unwrap();
        std::fs::create_dir_all(source_dir.join("Documents")).unwrap();
        std::fs::create_dir_all(source_dir.join("Network")).unwrap();
        std::fs::create_dir_all(source_dir.join("Downloads")).unwrap();
        std::fs::write(
            filezilla_dir.join("recentservers.xml"),
            br#"<FileZilla3><RecentServers><Server><Host>203.0.113.10</Host><Port>21</Port><User>ftpuser</User><Pass encoding="base64">c2VjcmV0</Pass><RemotePath>1 0 4 home 7 ftpuser 8 projects 6 site-a</RemotePath></Server></RecentServers></FileZilla3>"#,
        )
        .unwrap();
        std::fs::write(
            chrome_dir.join("Login Data"),
            b"SQLite format 3\0login-store",
        )
        .unwrap();
        std::fs::write(protect_dir.join("masterkey"), b"dpapi masterkey bytes").unwrap();
        std::fs::write(
            source_dir.join("Documents").join("briefing.pdf"),
            b"%PDF-1.7\n1 0 obj\n",
        )
        .unwrap();
        std::fs::write(
            source_dir.join("Network").join("exfil.pcapng"),
            b"\x0a\x0d\x0d\x0a\x00\x00\x00\x1c",
        )
        .unwrap();
        std::fs::write(
            source_dir.join("Downloads").join("payload.rar"),
            b"Rar!\x1a\x07\x00",
        )
        .unwrap();

        let result = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: source_dir.display().to_string(),
            recursive: Some(true),
        })
        .unwrap();
        assert_eq!(result.file_count, 6);
        assert_eq!(result.failed_count, 0);

        let files = get_file_page(
            case_root.to_str().unwrap(),
            FilePageQuery {
                limit: Some(20),
                cursor: None,
            },
        )
        .unwrap();
        for artifact_type in [
            "filezilla",
            "credential_store",
            "document",
            "network_capture",
            "archive",
        ] {
            assert!(
                files
                    .rows
                    .iter()
                    .any(|file| file.artifact_type == artifact_type),
                "{artifact_type}"
            );
        }
        wait_for_auto_analysis_jobs(&case_root);

        let findings = get_finding_summary(case_root.to_str().unwrap(), Some(100)).unwrap();
        for rule_id in [
            "filezilla-saved-credential",
            "credential-store-recovery-required",
            "document-recovery-required",
            "network-capture-exfil-review",
            "archive-exploit-recovery-candidate",
        ] {
            assert!(
                findings
                    .iter()
                    .any(|row| row.rule_id.as_deref() == Some(rule_id)),
                "{rule_id}"
            );
        }

        let evaluation = get_case_detection_evaluation(case_root.to_str().unwrap()).unwrap();
        for objective_id in [
            "credential_recovery",
            "content_recovery",
            "exfil_reconstruction",
        ] {
            assert!(
                evaluation
                    .objectives
                    .iter()
                    .any(|row| row.objective_id == objective_id && row.status == "covered"),
                "{objective_id}"
            );
        }
    }

    #[test]
    fn local_mft_csv_uses_export_parser_and_detects_si_fn_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "mft-csv".into(),
        })
        .unwrap();
        let source_file = temp.path().join("$MFT");
        std::fs::write(
            &source_file,
            b"EntryNumber,SequenceNumber,FullPath,Created0x10,Created0x30,LastModified0x10,LastModified0x30\n1,1,C:\\Users\\Public\\evil.exe,2026-01-01 00:00:00,2020-01-01 00:00:00,2026-01-01 00:05:00,2026-01-01 00:05:30\n",
        )
        .unwrap();

        let result = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: source_file.display().to_string(),
            recursive: Some(false),
        })
        .unwrap();
        assert_eq!(result.file_count, 1);
        assert_eq!(result.failed_count, 0);
        assert!(result.summary.event_count >= 4);

        let events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: Some("mft".into()),
                user_name: None,
                search: Some("evil.exe".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert!(events
            .rows
            .iter()
            .any(|row| row.event_action == "mft_created"));
        assert!(events
            .rows
            .iter()
            .any(|row| row.event_action == "mft_filename_created"));
        wait_for_auto_analysis_jobs(&case_root);

        let findings = get_finding_summary(case_root.to_str().unwrap(), Some(100)).unwrap();
        let finding = findings
            .iter()
            .find(|row| {
                row.engine == "taotie-core"
                    && row.rule_id.as_deref() == Some("core-mft-si-fn-timestomp")
            })
            .expect("mft si/fn mismatch finding");
        assert_eq!(finding.severity, "high");
        assert!(finding.event_count >= 4);
    }

    #[test]
    fn local_path_ingest_reads_raw_evtx_path_fixture_when_configured() {
        let Some(path) = std::env::var_os("TAOTIE4_RAW_EVTX_FIXTURE") else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "local-raw-evtx".into(),
        })
        .unwrap();

        let result = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: path.display().to_string(),
            recursive: Some(false),
        })
        .unwrap();
        assert_eq!(result.file_count, 1);
        assert_eq!(result.failed_count, 0);
        assert!(result.summary.event_count > 0);

        let files = get_file_page(
            case_root.to_str().unwrap(),
            FilePageQuery {
                limit: Some(10),
                cursor: None,
            },
        )
        .unwrap();
        assert_eq!(files.rows[0].artifact_type, "evtx");
        assert_eq!(files.rows[0].parser_status, ParserStatus::Parsed);
        assert!(files.rows[0].event_count > 0);

        let events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(1),
                cursor: None,
                artifact_type: Some("evtx".into()),
                user_name: None,
                search: None,
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(events.rows.len(), 1);
        let raw = get_event_raw_record(case_root.to_str().unwrap(), &events.rows[0].event_id)
            .unwrap()
            .expect("raw record");
        assert!(raw
            .raw_record_json
            .contains("\"parser_mode\":\"evtx_native\""));
    }

    #[test]
    fn local_path_ingest_reads_raw_mft_path_fixture_when_configured() {
        let Some(path) = std::env::var_os("TAOTIE4_RAW_MFT_FIXTURE") else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "local-raw-mft".into(),
        })
        .unwrap();

        let result = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: path.display().to_string(),
            recursive: Some(false),
        })
        .unwrap();
        assert_eq!(result.file_count, 1);
        assert_eq!(result.failed_count, 0);
        assert!(result.summary.event_count > 0);

        let events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: Some("mft".into()),
                user_name: None,
                search: Some("move.aspx".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert!(
            events.rows.iter().any(|row| row
                .file_path
                .as_deref()
                .is_some_and(|path| path.contains("move.aspx"))),
            "raw MFT fixture should surface move.aspx in MFT events"
        );
    }

    #[test]
    fn local_path_ingest_keeps_empty_or_corrupt_evtx_as_observed_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "local-raw-evtx-empty".into(),
        })
        .unwrap();
        let source_dir = temp.path().join("triage");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("Security.evtx"), b"ElfFile\0\0demo").unwrap();

        let result = ingest_local_path(LocalPathIngestRequest {
            case_root: case_root.display().to_string(),
            input_path: source_dir.display().to_string(),
            recursive: Some(true),
        })
        .unwrap();
        assert_eq!(result.file_count, 1);
        assert_eq!(result.failed_count, 0);
        assert_eq!(result.summary.failed_parse_count, 0);

        let failed = get_failed_parser_summary(case_root.to_str().unwrap()).unwrap();
        assert!(failed.is_empty());
        let files = get_file_page(
            case_root.to_str().unwrap(),
            FilePageQuery {
                limit: Some(10),
                cursor: None,
            },
        )
        .unwrap();
        assert_eq!(files.rows[0].artifact_type, "evtx");
        assert_eq!(files.rows[0].parser_status, ParserStatus::Parsed);
        assert_eq!(files.rows[0].event_count, 1);

        let events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: Some("evtx".into()),
                user_name: None,
                search: None,
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(events.rows[0].event_action, "evtx_file_observed");
    }

    #[test]
    fn uploaded_sample_representative_files_are_ingested() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "sample".into(),
        })
        .unwrap();

        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(b"2023-05-04 10:35:00 SyncEngine downloaded https://example.test/a.txt\n")
            .unwrap();
        let onedrive_gz = gzip.finish().unwrap();

        let samples: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "C/Windows/System32/winevt/logs/Security.evtx",
                b"ElfFile\0demo".to_vec(),
                "evtx",
            ),
            ("C/$MFT", b"FILE0demo".to_vec(), "mft"),
            (
                "C/Windows/prefetch/POWERSHELL.EXE-022A1004.pf",
                b"SCCA\x1e\0\0\0powershell.exe".to_vec(),
                "prefetch",
            ),
            (
                "C/Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/EVIL.lnk",
                b"L\0\0\0C:\\Temp\\evil.exe\0".to_vec(),
                "lnk",
            ),
            (
                "C/Users/jdoe/AppData/Local/Microsoft/OneDrive/logs/Personal/SyncEngine-2023-05-04.odlgz",
                onedrive_gz,
                "onedrive_log",
            ),
            (
                "C/Users/jdoe/AppData/Local/Microsoft/OneDrive/settings/Personal/global.ini",
                b"UserCid=1234567890abcdef\nLocalRoot=C:\\Users\\jdoe\\OneDrive\nUpload https://contoso-my.sharepoint.com/personal/jdoe/Documents/loot.zip\n".to_vec(),
                "onedrive_log",
            ),
            (
                "C/Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/default/places.sqlite",
                b"SQLite format 3\0demo".to_vec(),
                "browser",
            ),
            (
                "C/Users/jdoe/AppData/Local/Microsoft/Edge/User Data/Default/History",
                b"SQLite format 3\0urls visits https://example.test/download/evil.exe".to_vec(),
                "browser",
            ),
            (
                "C/Users/jdoe/AppData/Local/Microsoft/Edge/User Data/Default/Preferences",
                br#"{"download":{"default_directory":"C:\\Users\\jdoe\\Downloads"},"safebrowsing":{"enabled":false}}"#.to_vec(),
                "browser",
            ),
            (
                "C/Users/jdoe/AppData/Local/Microsoft/Edge/User Data/Default/Sessions/Tabs_13331820747538276",
                b"\x00\x01https://example.test/page\x00powershell.exe".to_vec(),
                "browser",
            ),
            (
                "C/Users/jdoe/AppData/Local/Microsoft/Windows/Explorer/thumbcache_32.db",
                b"SQLite format 3\0demo".to_vec(),
                "thumbcache",
            ),
            (
                "C/Users/jdoe/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
                b"SQLite format 3\0demo".to_vec(),
                "web_cache",
            ),
            (
                "C/Users/jdoe/AppData/Local/MicrosoftEdge/Cache/GNBF218X/sysmon[1].htm",
                b"Visited https://example.test/download/sysmon.exe example.test C:\\Users\\jdoe\\Downloads\\sysmon.exe\n".to_vec(),
                "web_cache",
            ),
            (
                "C/Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms",
                vec![0xd0, 0xcf, 0x11, 0xe0, 0x00, 0x00],
                "jump_list",
            ),
            (
                "C/Users/jdoe/Pictures/screenshot.jpg",
                vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10],
                "image",
            ),
            (
                "C/ProgramData/Microsoft/search/data/applications/windows/Windows.edb",
                vec![0xef, 0xcd, 0xab, 0x89],
                "ese",
            ),
            (
                "C/ProgramData/Microsoft/search/data/applications/windows/GatherLogs/SystemIndex/SystemIndex.14.gthr",
                b"c926baa1\t1d9a28c\tfile:C:/Users/alice/Downloads/evil.exe\t80000003\r\n"
                    .to_vec(),
                "windows_search_log",
            ),
            ("C/$Extend/$J", vec![0, 1, 2, 3], "usn_jrnl"),
        ];

        for (path, bytes, expected_type) in samples {
            ingest_uploaded_artifact(UploadedArtifactRequest {
                case_root: case_root.display().to_string(),
                original_path: path.into(),
                content_base64: BASE64_STANDARD.encode(bytes),
            })
            .unwrap();
            let files = get_file_page(
                case_root.to_str().unwrap(),
                FilePageQuery {
                    limit: Some(100),
                    cursor: None,
                },
            )
            .unwrap();
            let file = files
                .rows
                .iter()
                .find(|file| file.original_path == path)
                .unwrap();
            assert_eq!(file.parser_status, ParserStatus::Parsed, "{path}");
            assert_eq!(file.artifact_type, expected_type, "{path}");
            assert!(file.event_count >= 1, "{path}");
        }
    }

    #[test]
    fn sidecar_analysis_can_be_enqueued_from_recommended_event() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "sidecar-plan".into(),
        })
        .unwrap();
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 0, 0, 0, 0];
        bytes.extend_from_slice(b"GET /payload.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n");
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "capture.pcap".into(),
            content_base64: BASE64_STANDARD.encode(bytes),
        })
        .unwrap();
        let events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(20),
                cursor: None,
                artifact_type: Some("network_capture".into()),
                user_name: None,
                search: None,
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        let event_id = events
            .rows
            .iter()
            .find(|row| row.event_action.contains("network"))
            .map(|row| row.event_id.clone())
            .unwrap_or_else(|| events.rows[0].event_id.clone());

        let job = enqueue_sidecar_analysis(SidecarPlanRequest {
            case_root: case_root.display().to_string(),
            event_id,
            sidecar: None,
        })
        .unwrap();
        assert_eq!(job.kind, JobKind::RunNetworkSidecar);
        assert!(job.payload_json.contains("zeek_tshark_pcap_analysis"));
        assert!(job.payload_json.contains("background_worker_only"));
        assert!(job
            .resource_limits_json
            .contains("\"network_access\":false"));
    }

    #[test]
    fn sidecar_worker_generates_recovery_events() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "sidecar-worker".into(),
        })
        .unwrap();
        let bytes = b"%PDF-1.4\nRDP administrator password: HunterPassw0rd!\n%%EOF".to_vec();
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "evidence/admin-note.pdf".into(),
            content_base64: BASE64_STANDARD.encode(bytes),
        })
        .unwrap();
        let events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(20),
                cursor: None,
                artifact_type: Some("document".into()),
                user_name: None,
                search: None,
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        let event_id = events.rows[0].event_id.clone();
        let job = enqueue_sidecar_analysis(SidecarPlanRequest {
            case_root: case_root.display().to_string(),
            event_id,
            sidecar: Some("tika_oletools_document_triage".into()),
        })
        .unwrap();
        let finished = execute_sidecar_job(
            case_root.to_str().unwrap(),
            &job.job_id,
            "test-sidecar-worker",
        )
        .unwrap();
        assert_eq!(finished.status, JobStatus::Succeeded);
        assert!(case_root
            .join("sidecars")
            .join(&job.job_id)
            .join("records.jsonl")
            .exists());
        let rows = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(50),
                cursor: None,
                artifact_type: Some("document".into()),
                user_name: None,
                search: Some("HunterPassw0rd".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert!(
            rows.rows
                .iter()
                .any(|row| row.event_action == "document_sensitive_text_observed"),
            "{rows:#?}"
        );
    }

    #[test]
    fn keepass_xml_export_parser_redacts_secret_but_keeps_context() {
        let xml = r#"
        <KeePassFile><Root><Group><Entry>
          <String><Key>Title</Key><Value>VPN Portal</Value></String>
          <String><Key>UserName</Key><Value>alice</Value></String>
          <String><Key>URL</Key><Value>https://vpn.example.test</Value></String>
          <String><Key>Password</Key><Value>SuperSecret!</Value></String>
        </Entry></Group></Root></KeePassFile>
        "#;
        let entries = parse_keepass_xml_export(xml);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].get("Title").map(String::as_str),
            Some("VPN Portal")
        );
        assert_eq!(
            entries[0].get("UserName").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            entries[0].get("URL").map(String::as_str),
            Some("https://vpn.example.test")
        );
        assert_eq!(
            entries[0].get("Password").map(String::as_str),
            Some("SuperSecret!")
        );
    }

    #[test]
    fn tcpflow_outputs_are_summarized_with_redacted_ftp_passwords() {
        let temp = tempfile::tempdir().unwrap();
        let flow_dir = temp.path().join("tcpflows");
        std::fs::create_dir_all(&flow_dir).unwrap();
        std::fs::write(
            flow_dir.join("010.000.000.001.49152-010.000.000.002.00021"),
            b"USER admin\r\nPASS dont-show-this\r\nSTOR loot.zip\r\n",
        )
        .unwrap();
        let event = test_event(
            "event_pcap",
            "network_capture",
            "network_capture_observed",
            "pcap",
        );
        let detail = detail_from_event(&event);
        let mut execution = SidecarExecution::new(
            "zeek_tshark_pcap_analysis".into(),
            temp.path().to_path_buf(),
        );
        let count = collect_tcpflow_outputs(&flow_dir, &detail, &mut execution).unwrap();
        assert_eq!(count, 1);
        let signal = execution
            .records
            .iter()
            .find(|record| record.event_action == "pcap_conversation_reconstructed")
            .expect("tcpflow signal");
        assert_eq!(signal.severity, "high");
        assert_eq!(signal.attributes["protocol_hint"].as_str(), Some("ftp"));
        assert_eq!(signal.attributes["password_present"].as_bool(), Some(true));
        let preview = signal.attributes["text_preview"].as_str().unwrap();
        assert!(preview.contains("PASS [redacted]"));
        assert!(!preview.contains("dont-show-this"));
    }

    #[test]
    fn answer_candidates_are_persisted_and_queryable() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "answers".into(),
        })
        .unwrap();
        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/demo.log".into(),
            content: "WARN mshta.exe launched SystemHealthCheck.hta\nINFO whoami.exe executed\n"
                .into(),
        })
        .unwrap();

        let candidates = get_answer_candidates(AnswerCandidateQuery {
            case_root: case_root.display().to_string(),
            question_key: None,
            limit: Some(100),
        })
        .unwrap();
        assert!(candidates
            .iter()
            .any(|row| row.question_key == "initial_access.execution_technique"));
        assert!(candidates
            .iter()
            .any(|row| row.question_key == "discovery.identity_command_time"));

        let filtered = get_answer_candidates(AnswerCandidateQuery {
            case_root: case_root.display().to_string(),
            question_key: Some("discovery.identity_command_time".into()),
            limit: Some(10),
        })
        .unwrap();
        assert!(!filtered.is_empty());
        assert!(filtered
            .iter()
            .all(|row| row.question_key == "discovery.identity_command_time"));
    }

    #[test]
    fn answer_candidate_job_reuses_unchanged_input_read_model() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "answer-job-reuse".into(),
        })
        .unwrap();
        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/demo.log".into(),
            content: "WARN mshta.exe launched SystemHealthCheck.hta\nINFO whoami.exe executed\n"
                .into(),
        })
        .unwrap();

        let workspace = CaseWorkspace::open(&case_root).unwrap();
        let queue = JobQueue::open(workspace.jobs_db_path()).unwrap();
        let first = enqueue_answer_candidate_job(&workspace, &queue, "test", 42).unwrap();
        execute_answer_candidate_job(case_root.to_str().unwrap(), &first.job_id, "test-worker-1")
            .unwrap();
        let second = enqueue_answer_candidate_job(&workspace, &queue, "test", 42).unwrap();
        execute_answer_candidate_job(case_root.to_str().unwrap(), &second.job_id, "test-worker-2")
            .unwrap();

        let runs = CaseWorkspace::open(&case_root)
            .unwrap()
            .query_layer()
            .analyzer_runs(Some(50))
            .unwrap();
        let reused = runs
            .into_iter()
            .find(|run| {
                run.analyzer_id == "answer_candidates"
                    && serde_json::from_str::<serde_json::Value>(&run.metadata_json)
                        .ok()
                        .and_then(|metadata| {
                            metadata
                                .get("job_id")
                                .and_then(serde_json::Value::as_str)
                                .map(|value| value == second.job_id)
                                .zip(
                                    metadata
                                        .get("reused_existing_read_model")
                                        .and_then(serde_json::Value::as_bool),
                                )
                        })
                        == Some((true, true))
            })
            .expect("second job should reuse the answer candidate read model");
        assert_eq!(reused.input_count, 0);
        assert!(reused.output_count > 0);
    }

    #[test]
    fn answer_candidate_job_reuses_fresh_legacy_read_model_without_fingerprint() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "answer-job-legacy-reuse".into(),
        })
        .unwrap();
        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "host/demo.log".into(),
            content: "WARN mshta.exe launched SystemHealthCheck.hta\nINFO whoami.exe executed\n"
                .into(),
        })
        .unwrap();

        let workspace = CaseWorkspace::open(&case_root).unwrap();
        let current_count = workspace.query_layer().answer_candidate_count().unwrap();
        assert!(current_count > 0);
        workspace
            .append_analyzer_runs(&[AnalyzerRunSummary {
                run_id: new_id("analyzer"),
                case_id: workspace.manifest().case_id.clone(),
                analyzer_id: "answer_candidates".to_string(),
                name: "legacy answer candidates".to_string(),
                version: "taotie-answer-candidates-v1".to_string(),
                status: "succeeded".to_string(),
                started_at: now_utc(),
                finished_at: Some(now_utc()),
                input_count: 1,
                output_count: current_count as i64,
                error_message: None,
                metadata_json: serde_json::json!({
                    "read_model": "read_models/answer_candidates",
                    "source": "legacy_background_job",
                })
                .to_string(),
            }])
            .unwrap();

        let fingerprint = answer_candidate_input_fingerprint(&workspace).unwrap();
        let reused = reusable_answer_candidate_count(&workspace, &fingerprint).unwrap();
        assert_eq!(reused, Some(current_count));
    }

    #[test]
    fn rebuild_derived_evidence_models_promotes_existing_resident_ads_events() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            CaseWorkspace::create(temp.path().join("case"), "structure-rebuild").unwrap();
        let case_id = workspace.manifest().case_id.clone();
        workspace
            .append_events_full(&[EventFull {
                event_id: "event_ads".into(),
                case_id,
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
            }])
            .unwrap();

        let source_events = workspace
            .query_layer()
            .analyzer_events_full_batch(None, 10)
            .unwrap();
        assert_eq!(source_events.len(), 1);
        assert!(!derive_artifact_objects(&source_events).is_empty());
        let (object_count, offset_count) = rebuild_derived_evidence_models(&workspace, 1).unwrap();
        assert!(object_count > 0);
        assert!(offset_count > 0);

        let objects =
            get_event_artifact_objects(workspace.root().to_str().unwrap(), "event_ads").unwrap();
        assert!(objects
            .iter()
            .any(|row| row.object_kind == "ntfs_ads_resident_content"));
        let offsets =
            get_event_evidence_offsets(workspace.root().to_str().unwrap(), "event_ads").unwrap();
        assert!(offsets
            .iter()
            .any(|row| row.structure_kind == "mft_ads_resident_content"));
    }

    #[test]
    fn answer_candidates_use_network_and_archive_sidecar_signals() {
        let mut network = test_event(
            "event_network",
            "network_capture",
            "zeek_http_request_observed",
            "SystemHealthCheck Zeek HTTP request: GET http://c2.example/update.bat",
        );
        network.url = Some("http://c2.example/update.bat".into());
        network.attributes_json = serde_json::json!({
            "url": "http://c2.example/update.bat",
            "host": "c2.example",
            "uri": "/update.bat"
        })
        .to_string();

        let mut ftp = test_event(
            "event_ftp",
            "network_capture",
            "zeek_ftp_activity_observed",
            "Zeek FTP activity: command=STOR user=admin password_present=true",
        );
        ftp.attributes_json = serde_json::json!({
            "arg": "/uploads/loot.zip",
            "user": "admin",
            "password_present": true
        })
        .to_string();

        let mut archive = test_event(
            "event_archive",
            "archive",
            "archive_recovery_candidate",
            "Archive recovery candidate from suspicious WinRAR package",
        );
        archive.file_path = Some("evidence/payload.rar".into());
        archive.attributes_json = serde_json::json!({
            "candidate_members": ["invoice.pdf ", "invoice.pdf /payload.bat", "readme.txt"],
            "suspicious_member_count": 2
        })
        .to_string();

        let candidates = build_answer_candidates("case_test", &[network, ftp, archive]).unwrap();
        assert!(candidates.iter().any(|row| {
            row.question_key == "network.script_url"
                && row.candidate_value == "http://c2.example/update.bat"
        }));
        assert!(candidates.iter().any(|row| {
            row.question_key == "exfiltration.remote_path"
                && row.candidate_value == "/uploads/loot.zip"
        }));
        assert!(candidates.iter().any(|row| row.question_key
            == "credential_access.ftp_destination_secret"
            && row.candidate_value.contains("redacted")));
        assert!(candidates.iter().any(|row| {
            row.question_key == "exploit.cve_candidate" && row.candidate_value == "CVE-2023-38831"
        }));
        assert!(candidates.iter().any(|row| {
            row.question_key == "file_recovery.script_hash" && row.status == "needs_recovery"
        }));
    }

    #[test]
    fn answer_candidates_use_windows_semantic_enrichment() {
        let mut kerberos = test_event(
            "event_kerberos",
            "evtx",
            "kerberos_service_ticket_requested",
            "EventID 4769 kerberos_service_ticket_requested ticket_encryption=0x17 service=MSSQLSvc/sql.lab",
        );
        kerberos.user_name = Some("svc-mssql".into());
        kerberos.attributes_json = serde_json::json!({
            "event_id": "4769",
            "data": {
                "TargetUserName": "svc-mssql",
                "ServiceName": "MSSQLSvc/sql.lab",
                "TicketEncryptionType": "0x17"
            },
            "semantics": {
                "event_family": "kerberos",
                "event_kind": "kerberos_tgs_request",
                "labels": ["kerberos_tgs_req", "kerberos_rc4_ticket", "kerberoast_candidate"],
                "service_name": "MSSQLSvc/sql.lab",
                "ticket_encryption_name": "rc4_hmac"
            }
        })
        .to_string();

        let mut firewall = test_event(
            "event_firewall",
            "evtx",
            "firewall_connection_allowed",
            "EventID 2004 firewall_rule_added rule=Outbound service restriction rule for WinDefend direction=Outbound",
        );
        firewall.attributes_json = serde_json::json!({
            "event_id": "2004",
            "semantics": {
                "event_family": "firewall",
                "event_kind": "firewall_rule_added",
                "labels": ["firewall_rule_added", "firewall_outbound"],
                "rule_name": "Outbound service restriction rule for WinDefend",
                "firewall_direction": "outbound",
                "firewall_action": "allowed"
            }
        })
        .to_string();

        let mut benign_firewall = test_event(
            "event_benign_firewall",
            "hayabusa",
            "firewall_rule_added",
            "RuleName: Network Discovery (LLMNR-UDP-Out) | Direction: 2 | Action: 3",
        );
        benign_firewall.attributes_json = serde_json::json!({
            "event_id": "2004",
            "semantics": {
                "event_family": "firewall",
                "event_kind": "firewall_rule_added",
                "labels": ["firewall_rule_added", "firewall_outbound"],
                "rule_name": "Network Discovery (LLMNR-UDP-Out)",
                "firewall_direction": "outbound",
                "firewall_action": "allowed"
            }
        })
        .to_string();

        let suspicious_firewall = test_event(
            "event_metasploit_firewall",
            "hayabusa",
            "firewall_rule_added",
            "Uncommon New Firewall Rule Added In Windows Firewall Exception List | RuleName: Metasploit C2 Bypass ¦ Direction: 2 ¦ Action: 3 ¦ RemotePort: 4444",
        );

        let scheduled_task = test_event(
            "event_task",
            "hayabusa",
            "scheduled_task_created",
            "Task Created | Name: \\DAILY-MAINT ¦ Content: <Task><Actions><Exec><Command>C:\\Users\\analyst\\Desktop\\maintenance.ps1</Command></Exec></Actions></Task>",
        );
        let benign_scheduled_task = test_event(
            "event_update_task",
            "scheduled_task",
            "scheduled_task_observed",
            "Scheduled task observed: \\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan command=%systemroot%\\system32\\usoclient.exe",
        );
        let diagnostic_task = test_event(
            "event_sdiag_task",
            "scheduled_task",
            "scheduled_task_observed",
            "Scheduled task observed: - command=C:\\Windows\\TEMP\\SDIAG_dea1\\RS_ProgramCompatibilityWizard.ps1",
        );

        let defender = test_event(
            "event_defender",
            "defender",
            "defender_threat_detected",
            "Threat: HackTool:PowerShell/SharpHound.B ¦ Path: C:\\Users\\analyst\\Downloads\\SharpHound.ps1",
        );

        let file_hash = test_event(
            "event_get_filehash",
            "evtx",
            "powershell_activity_observed",
            "ScriptBlock: Get-FileHash -Algorithm md5 .\\Desktop\\maintenance.ps1 ¦ Hash=0123456789ABCDEF0123456789ABCDEF",
        );
        let file_hash_command_only = test_event(
            "event_get_filehash_command_only",
            "evtx",
            "powershell_activity_observed",
            "ScriptBlock: Get-FileHash -Algorithm md5 .\\Desktop\\maintenance.ps1",
        );

        let mut psexec = test_event(
            "event_psexec",
            "evtx",
            "named_pipe_created",
            "Sysmon named pipe created \\PSEXESVC",
        );
        psexec.attributes_json = serde_json::json!({
            "event_id": "17",
            "semantics": {
                "event_family": "execution",
                "event_kind": "named_pipe_created",
                "labels": ["named_pipe_created", "psexec_named_pipe"],
                "pipe_name": "\\\\PSEXESVC"
            }
        })
        .to_string();

        let candidates = build_answer_candidates(
            "case_semantics",
            &[
                kerberos,
                firewall,
                benign_firewall,
                suspicious_firewall,
                scheduled_task,
                benign_scheduled_task,
                diagnostic_task,
                defender,
                file_hash,
                file_hash_command_only,
                psexec,
            ],
        )
        .unwrap();
        assert!(candidates.iter().any(|row| {
            row.question_key == "credential_access.kerberos_roastable_account"
                && row.candidate_value.contains("MSSQLSvc")
        }));
        assert!(candidates.iter().any(|row| {
            row.question_key == "defense_evasion.firewall_change_or_flow"
                && row.candidate_value.contains("outbound")
        }));
        assert!(candidates.iter().any(|row| {
            row.question_key == "defense_evasion.firewall_change_or_flow"
                && row.candidate_value.contains("Metasploit C2 Bypass")
        }));
        assert!(!candidates.iter().any(|row| {
            row.question_key == "defense_evasion.firewall_change_or_flow"
                && row.candidate_value.contains("Network Discovery")
        }));
        assert!(candidates.iter().any(|row| {
            row.question_key == "persistence.scheduled_task_exec"
                && row.candidate_value.contains("maintenance.ps1")
        }));
        assert!(!candidates.iter().any(|row| {
            row.question_key == "persistence.scheduled_task_exec"
                && (row.candidate_value.contains("usoclient.exe")
                    || row.candidate_value.contains("ProgramCompatibilityWizard"))
        }));
        assert!(candidates.iter().any(|row| {
            row.question_key == "malware.defender_threat"
                && row.candidate_value.contains("SharpHound")
        }));
        assert!(candidates.iter().any(|row| {
            row.question_key == "file.hash_observed"
                && row.candidate_value == "0123456789ABCDEF0123456789ABCDEF"
        }));
        assert!(!candidates.iter().any(|row| {
            row.question_key == "file.hash_observed"
                && row.candidate_value.contains("maintenance.ps1")
        }));
        assert!(candidates.iter().any(|row| {
            row.question_key == "lateral_movement.psexec_evidence"
                && row.candidate_value.contains("PSEXESVC")
        }));
    }

    #[test]
    fn investigation_leads_use_generic_rule_keys_without_case_context() {
        let events = vec![
            test_event(
                "event_powerview",
                "prefetch",
                "prefetch_execution",
                "Prefetch execution: POWERVIEW.PS1 run_count=1",
            ),
            test_event(
                "event_rdp",
                "evtx",
                "windows_logon_success",
                "EventID 4624 LogonType=10 user=analyst",
            ),
        ];
        let candidates = build_answer_candidates("case_generic", &events).unwrap();
        assert!(candidates.iter().any(|row| {
            row.question_key == "tooling.powershell_script"
                && row.question_label == "PowerShell調査対象スクリプト候補"
        }));
        assert!(candidates
            .iter()
            .any(|row| row.question_key == "remote_access.rdp_initial_auth_time"));
        let legacy_prefix_a = ["hun", "ter."].concat();
        let legacy_prefix_b = ["i", "like."].concat();
        assert!(
            candidates
                .iter()
                .all(|row| !row.question_key.starts_with(&legacy_prefix_a)
                    && !row.question_key.starts_with(&legacy_prefix_b)),
            "{candidates:#?}"
        );
    }

    #[test]
    fn uploaded_evtx_export_supports_users_and_correlation() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "demo".into(),
        })
        .unwrap();

        let evtx_xml = br#"<Events>
          <Event><System><EventID>4688</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Computer>HOST1</Computer></System><EventData><Data Name="SubjectUserName">alice</Data><Data Name="NewProcessName">C:\Temp\evil.exe</Data></EventData></Event>
          <Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-01-01T00:01:00Z"/><Computer>HOST1</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">10.0.0.5</Data></EventData></Event>
        </Events>"#;
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "Security.evtx.xml".into(),
            content_base64: BASE64_STANDARD.encode(evtx_xml),
        })
        .unwrap();

        let mft_csv = b"EntryNumber,SequenceNumber,FullPath,Created0x10\n1,1,C:\\Temp\\evil.exe,2026-01-01 00:02:00\n";
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "MFT_Output.csv".into(),
            content_base64: BASE64_STANDARD.encode(mft_csv),
        })
        .unwrap();
        let browser_json = br#"[{"url":"https://example.test/download/evil.exe","title":"download","last_visit_time":"2026-01-01T00:00:30Z"}]"#;
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "browser_history.json".into(),
            content_base64: BASE64_STANDARD.encode(browser_json),
        })
        .unwrap();
        let prefetch_csv = b"SourceFilename,ExecutableName,RunCount,LastRun\nC:\\Windows\\Prefetch\\EVIL.EXE-1234ABCD.pf,evil.exe,2,2026-01-01 00:03:00\n";
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "PECmd_Output.csv".into(),
            content_base64: BASE64_STANDARD.encode(prefetch_csv),
        })
        .unwrap();
        let usn_csv = b"Timestamp,FileName,FileReferenceNumber,Reason\n2026-01-01 00:04:00,C:\\Temp\\evil.exe,42,File_Delete\n";
        let summary = ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "UsnJrnl_Output.csv".into(),
            content_base64: BASE64_STANDARD.encode(usn_csv),
        })
        .unwrap();
        assert!(summary.event_count >= 6);
        wait_for_auto_analysis_jobs(&case_root);

        let users = get_user_activity_summary(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert_eq!(users[0].user_name, "alice");
        assert!(users[0].event_count >= 2);

        let user_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: Some("alice".into()),
                search: None,
                sort_by: None,
                sort_dir: None,
            },
        )
        .unwrap();
        assert!(user_events.rows.len() >= 2);

        let searched_events = get_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some("evil.exe".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert!(searched_events.rows.iter().any(|row| row
            .file_path
            .as_deref()
            .is_some_and(|path| path.contains("evil.exe"))));
        let context = get_event_context(
            case_root.to_str().unwrap(),
            EventContextQuery {
                event_id: searched_events.rows[0].event_id.clone(),
                window_minutes: Some(10),
                per_group_limit: Some(20),
                same_host_only: Some(false),
            },
        )
        .unwrap()
        .expect("event context");
        assert!(context
            .groups
            .iter()
            .any(|group| group.relation == "same_file_basename" && group.rows.len() >= 4));
        assert!(context
            .groups
            .iter()
            .any(|group| group.relation == "time_window" && group.rows.len() >= 4));

        let export_result = export_events(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: None,
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some("evil.exe".into()),
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
            "csv",
            None,
            Some(100),
        )
        .unwrap();
        assert!(!export_result.truncated);
        assert!(export_result.row_count >= 4);
        let export_text = std::fs::read_to_string(&export_result.output_path).unwrap();
        assert!(export_text.contains("evil.exe"));

        let ioc_hits = get_ioc_matches(IocMatchRequest {
            case_root: case_root.display().to_string(),
            indicators: vec!["evil.exe".into(), "10.0.0.5".into(), "missing.exe".into()],
            limit: Some(10),
        })
        .unwrap();
        assert!(ioc_hits
            .iter()
            .any(|hit| hit.ioc == "evil.exe" && hit.hit_count >= 4));
        assert!(ioc_hits
            .iter()
            .any(|hit| hit.ioc == "10.0.0.5" && hit.match_kind == "ip"));
        assert!(!ioc_hits.iter().any(|hit| hit.ioc == "missing.exe"));
        let ioc_events = get_ioc_event_page(
            case_root.to_str().unwrap(),
            IocEventPageQuery {
                ioc: "evil.exe".into(),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".into()),
                    sort_dir: Some("asc".into()),
                },
            },
        )
        .unwrap();
        assert!(ioc_events.rows.len() >= 4);
        assert!(ioc_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "prefetch"));
        let prefetch_summary = get_prefetch_summary(case_root.to_str().unwrap(), Some(10)).unwrap();
        let prefetch_evil = prefetch_summary
            .iter()
            .find(|row| row.process_name == "evil.exe")
            .expect("prefetch summary for evil.exe");
        assert_eq!(prefetch_evil.run_count_max, Some(2));
        assert!(prefetch_evil.actions.contains("process_executed"));

        let defender_xml = br#"<Events>
          <Event><System><Provider Name="Microsoft-Windows-Windows Defender"/><EventID>1116</EventID><TimeCreated SystemTime="2026-01-01T00:05:00Z"/><Computer>HOST1</Computer><Channel>Microsoft-Windows-Windows Defender/Operational</Channel></System><EventData><Data Name="Threat Name">Trojan:Win32/Demo</Data><Data Name="Path">C:\Temp\evil.exe</Data></EventData></Event>
        </Events>"#;
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "MPOperationalEvents.txt".into(),
            content_base64: BASE64_STANDARD.encode(defender_xml),
        })
        .unwrap();
        let defender_summary = get_defender_summary(case_root.to_str().unwrap(), Some(10)).unwrap();
        let defender_detected = defender_summary
            .iter()
            .find(|row| row.category == "defender_threat_detected")
            .expect("defender threat category");
        assert_eq!(defender_detected.severity_max.as_deref(), Some("high"));
        let defender_events = get_defender_event_page(
            case_root.to_str().unwrap(),
            DefenderEventPageQuery {
                category: Some("defender_threat_detected".into()),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".into()),
                    sort_dir: Some("asc".into()),
                },
            },
        )
        .unwrap();
        assert!(defender_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "defender"));

        let findings = get_finding_summary(case_root.to_str().unwrap(), Some(50)).unwrap();
        assert!(findings
            .iter()
            .any(|row| row.rule_id.as_deref() == Some("defender-threat-detected")));
        let temp_finding = findings
            .iter()
            .find(|row| row.title.contains("Temp"))
            .expect("temp execution finding");
        let finding_events = get_finding_event_page(
            case_root.to_str().unwrap(),
            FindingEventPageQuery {
                title: temp_finding.title.clone(),
                engine: Some(temp_finding.engine.clone()),
                rule_id: temp_finding.rule_id.clone(),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".into()),
                    sort_dir: Some("asc".into()),
                },
            },
        )
        .unwrap();
        assert!(!finding_events.rows.is_empty());
        assert!(finding_events.rows[0].has_finding);

        let correlations = get_correlation_summary(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert!(correlations
            .iter()
            .any(|row| row.key_value.contains("evil.exe") && row.artifact_types.contains("mft")));
        let chains = get_correlation_chains(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert!(chains
            .iter()
            .any(|row| row.key_value.contains("evil.exe") && row.event_count >= 2));
        let chain_read_model = case_root.join("read_models").join("correlation_chains");
        assert!(std::fs::read_dir(&chain_read_model)
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext == "parquet")));
        let analyzer_runs = get_analyzer_runs(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert!(analyzer_runs
            .iter()
            .any(|run| run.analyzer_id == "correlation_chains"));
        assert!(analyzer_runs
            .iter()
            .any(|run| run.analyzer_id == "correlation_findings"));
        let evil_chain = chains
            .iter()
            .find(|row| row.key_value.contains("evil.exe"))
            .expect("evil.exe chain");
        assert_eq!(evil_chain.title, "Defender 検知対象の実行痕跡");
        assert_eq!(evil_chain.severity, "critical");
        let chain_finding = findings
            .iter()
            .find(|row| row.engine == "correlation" && row.title == evil_chain.title)
            .expect("correlation finding");
        assert_eq!(chain_finding.severity, "critical");
        let risks = get_risk_summary(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert!(risks.iter().any(|row| row.technique == "T1105"));
        assert!(risks.iter().any(|row| row.technique == "T1204"));
        let chain_events = get_correlation_chain_event_page(
            case_root.to_str().unwrap(),
            CorrelationChainEventPageQuery {
                key_kind: evil_chain.key_kind.clone(),
                key_value: evil_chain.key_value.clone(),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".into()),
                    sort_dir: Some("asc".into()),
                },
            },
        )
        .unwrap();
        assert!(chain_events.rows.len() >= 2);
        assert!(chain_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "evtx"));
        assert!(chain_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "mft"));
        assert!(chain_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "browser"));
        assert!(chain_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "prefetch"));
        assert!(chain_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "usn_jrnl"));
        let chain_finding_events = get_finding_event_page(
            case_root.to_str().unwrap(),
            FindingEventPageQuery {
                title: chain_finding.title.clone(),
                engine: Some(chain_finding.engine.clone()),
                rule_id: chain_finding.rule_id.clone(),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".into()),
                    sort_dir: Some("asc".into()),
                },
            },
        )
        .unwrap();
        assert!(chain_finding_events.rows.len() >= 4);
        assert!(chain_finding_events.rows.iter().all(|row| row.has_finding));

        add_finding_override(FindingOverrideRequest {
            case_root: case_root.display().to_string(),
            engine: Some(chain_finding.engine.clone()),
            rule_id: chain_finding.rule_id.clone(),
            title: Some(chain_finding.title.clone()),
            action: "severity_override".into(),
            severity: Some("low".into()),
            reason: Some("test severity override".into()),
        })
        .unwrap();
        let findings_after_override =
            get_finding_summary(case_root.to_str().unwrap(), Some(20)).unwrap();
        let overridden_chain = findings_after_override
            .iter()
            .find(|row| row.engine == "correlation" && row.title == evil_chain.title)
            .expect("overridden correlation finding");
        assert_eq!(overridden_chain.severity, "low");

        let overrides = add_finding_override(FindingOverrideRequest {
            case_root: case_root.display().to_string(),
            engine: Some(chain_finding.engine.clone()),
            rule_id: chain_finding.rule_id.clone(),
            title: Some(chain_finding.title.clone()),
            action: "suppress".into(),
            severity: None,
            reason: Some("test suppress".into()),
        })
        .unwrap();
        let findings_after_suppress =
            get_finding_summary(case_root.to_str().unwrap(), Some(20)).unwrap();
        assert!(!findings_after_suppress
            .iter()
            .any(|row| row.engine == "correlation" && row.title == evil_chain.title));

        let suppress_override = overrides
            .iter()
            .find(|row| row.action == "suppress" && row.title.as_deref() == Some(&evil_chain.title))
            .expect("suppress override");
        remove_finding_override(case_root.to_str().unwrap(), &suppress_override.override_id)
            .unwrap();
        let findings_after_remove =
            get_finding_summary(case_root.to_str().unwrap(), Some(20)).unwrap();
        let restored_chain = findings_after_remove
            .iter()
            .find(|row| row.engine == "correlation" && row.title == evil_chain.title)
            .expect("restored correlation finding");
        assert_eq!(restored_chain.severity, "low");

        let bookmarked_event_id = chain_finding_events.rows[0].event_id.clone();
        let bookmarks = add_event_bookmark(EventBookmarkRequest {
            case_root: case_root.display().to_string(),
            event_id: bookmarked_event_id.clone(),
            label: Some("report candidate".into()),
            note: Some("bookmark test".into()),
        })
        .unwrap();
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].event_id, bookmarked_event_id);
        let bookmark_events = get_bookmark_event_page(
            case_root.to_str().unwrap(),
            EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: None,
                sort_by: Some("event_time_utc".into()),
                sort_dir: Some("asc".into()),
            },
        )
        .unwrap();
        assert_eq!(bookmark_events.rows.len(), 1);
        assert_eq!(bookmark_events.rows[0].event_id, bookmarked_event_id);
        let bookmarks_after_remove =
            remove_event_bookmark(case_root.to_str().unwrap(), &bookmarks[0].bookmark_id).unwrap();
        assert!(bookmarks_after_remove.is_empty());
    }

    #[test]
    fn ioc_findings_and_hayabusa_import_integrate_with_drilldown() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "ioc-hayabusa".into(),
        })
        .unwrap();

        let evtx_xml = br#"<Events>
          <Event><System><EventID>4688</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">alice</Data><Data Name="NewProcessName">C:\Temp\evil.exe</Data><Data Name="CommandLine">evil.exe -enc AAA</Data></EventData></Event>
        </Events>"#;
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "Security.evtx.xml".into(),
            content_base64: BASE64_STANDARD.encode(evtx_xml),
        })
        .unwrap();

        let hayabusa_csv = b"Timestamp,RuleTitle,Level,EventID,Computer,Channel,Details,MitreTags\n2026-01-01 00:00:01,Encoded PowerShell,high,4688,HOST1,Security,C:\\Temp\\evil.exe -enc AAA,attack.t1059.001\n";
        ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "hayabusa-results.csv".into(),
            content_base64: BASE64_STANDARD.encode(hayabusa_csv),
        })
        .unwrap();

        let findings = run_ioc_findings(IocFindingRequest {
            case_root: case_root.display().to_string(),
            indicators: vec!["evil.exe".into()],
            limit: Some(100),
        })
        .unwrap();
        let ioc_finding = findings
            .iter()
            .find(|row| row.engine == "ioc" && row.title == "IOC hit: evil.exe")
            .expect("ioc finding");
        assert_eq!(ioc_finding.severity, "medium");
        assert!(ioc_finding.event_count >= 2);

        let hayabusa_finding = findings
            .iter()
            .find(|row| row.engine == "hayabusa" && row.title.contains("Encoded PowerShell"))
            .expect("hayabusa finding");
        assert_eq!(hayabusa_finding.severity, "high");
        assert!(hayabusa_finding.attack_json.contains("T1059.001"));

        let ioc_events = get_finding_event_page(
            case_root.to_str().unwrap(),
            FindingEventPageQuery {
                title: ioc_finding.title.clone(),
                engine: Some(ioc_finding.engine.clone()),
                rule_id: ioc_finding.rule_id.clone(),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".into()),
                    sort_dir: Some("asc".into()),
                },
            },
        )
        .unwrap();
        assert!(ioc_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "evtx"));
        assert!(ioc_events
            .rows
            .iter()
            .any(|row| row.artifact_type == "hayabusa"));
        assert!(ioc_events.rows.iter().all(|row| row.has_finding));

        let analyzer_runs = get_analyzer_runs(case_root.to_str().unwrap(), Some(10)).unwrap();
        assert!(analyzer_runs
            .iter()
            .any(|run| run.analyzer_id == "ioc_findings"));
    }

    #[test]
    fn taotie_core_rules_emit_deterministic_findings_and_drilldown() {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "core-rules".into(),
        })
        .unwrap();

        let mut evtx_xml = String::from("<Events>");
        for idx in 0..10 {
            evtx_xml.push_str(&format!(
                r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-02-01T00:00:{idx:02}Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">victim</Data><Data Name="IpAddress">203.0.113.44</Data><Data Name="WorkstationName">ATTACKBOX</Data></EventData></Event>"#
            ));
        }
        for idx in 0..5 {
            evtx_xml.push_str(&format!(
                r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-02-01T00:00:{:02}Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">spray{idx}</Data><Data Name="IpAddress">198.51.100.77</Data><Data Name="WorkstationName">SPRAYBOX</Data></EventData></Event>"#,
                idx + 20
            ));
        }
        for idx in 0..5 {
            evtx_xml.push_str(&format!(
                r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2026-02-01T00:01:{idx:02}Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">victim</Data><Data Name="IpAddress">203.0.113.44</Data><Data Name="WorkstationName">ATTACKBOX</Data><Data Name="LogonType">3</Data><Data Name="AuthenticationPackageName">NTLM</Data><Data Name="LmPackageName">NTLM V2</Data></EventData></Event>"#
            ));
        }
        for idx in 0..3 {
            evtx_xml.push_str(&format!(
                r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2026-02-01T23:01:{idx:02}Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">nightadmin</Data><Data Name="IpAddress">203.0.113.88</Data><Data Name="LogonType">10</Data></EventData></Event>"#
            ));
        }
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><TimeCreated SystemTime="2026-02-01T00:02:00Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">admin</Data><Data Name="NewProcessName">C:\Windows\System32\rundll32.exe</Data><Data Name="CommandLine">rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 500 C:\Temp\lsass.dmp full</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Service Control Manager"/><EventID>7045</EventID><TimeCreated SystemTime="2026-02-01T00:03:00Z"/><Computer>HOST1</Computer><Channel>System</Channel></System><EventData><Data Name="ServiceName">PSEXESVC</Data><Data Name="ServiceFileName">C:\Windows\PSEXESVC.exe</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><TimeCreated SystemTime="2026-02-01T00:04:00Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">admin</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4720</EventID><TimeCreated SystemTime="2026-02-01T00:05:00Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">admin</Data><Data Name="TargetUserName">backdoor</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4732</EventID><TimeCreated SystemTime="2026-02-01T00:06:00Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">admin</Data><Data Name="MemberName">backdoor</Data><Data Name="GroupName">Administrators</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4769</EventID><TimeCreated SystemTime="2026-02-01T00:07:00Z"/><Computer>DC1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">svc-web</Data><Data Name="ServiceName">HTTP/web</Data><Data Name="TicketEncryptionType">0x17</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4768</EventID><TimeCreated SystemTime="2026-02-01T00:08:00Z"/><Computer>DC1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">admincert</Data><Data Name="PreAuthType">16</Data><Data Name="IpAddress">203.0.113.50</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4768</EventID><TimeCreated SystemTime="2026-02-01T00:09:00Z"/><Computer>DC1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">roastable</Data><Data Name="PreAuthType">0</Data><Data Name="IpAddress">203.0.113.51</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4738</EventID><TimeCreated SystemTime="2026-02-01T00:10:00Z"/><Computer>DC1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">admin</Data><Data Name="TargetUserName">victim</Data><Data Name="UserPrincipalName">victim-admin@example.local</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4724</EventID><TimeCreated SystemTime="2026-02-01T00:11:00Z"/><Computer>DC1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">operator</Data><Data Name="TargetUserName">victim</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5136</EventID><TimeCreated SystemTime="2026-02-01T00:12:00Z"/><Computer>DC1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">operator</Data><Data Name="TargetUserName">victim</Data><Data Name="AttributeLDAPDisplayName">msDS-KeyCredentialLink</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><TimeCreated SystemTime="2026-02-01T00:13:00Z"/><Computer>DC1</Computer><Channel>Security</Channel></System><EventData><Data Name="SubjectUserName">operator</Data><Data Name="NewProcessName">C:\Windows\System32\nltest.exe</Data><Data Name="CommandLine">nltest /domain_trusts</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-02-01T00:14:00Z"/><Computer>HOST1</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData><Data Name="ParentImage">C:\Windows\System32\mmc.exe</Data><Data Name="Image">C:\Windows\System32\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c whoami</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>10</EventID><TimeCreated SystemTime="2026-02-01T00:15:00Z"/><Computer>HOST1</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData><Data Name="SourceImage">C:\Temp\evil.exe</Data><Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data><Data Name="GrantedAccess">0x1410</Data></EventData></Event>"#,
        );
        evtx_xml.push_str(
            r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>2</EventID><TimeCreated SystemTime="2026-02-01T00:16:00Z"/><Computer>HOST1</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData><Data Name="Image">C:\Temp\evil.exe</Data><Data Name="TargetFilename">C:\Temp\evil.exe</Data><Data Name="PreviousCreationUtcTime">2026-02-01T00:15:30Z</Data><Data Name="CreationUtcTime">2020-01-01T00:00:00Z</Data></EventData></Event>"#,
        );
        evtx_xml.push_str("</Events>");

        let summary = ingest_uploaded_artifact(UploadedArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: "Security.evtx.xml".into(),
            content_base64: BASE64_STANDARD.encode(evtx_xml.as_bytes()),
        })
        .unwrap();
        assert!(summary.event_count >= 38);

        let findings = get_finding_summary(case_root.to_str().unwrap(), Some(100)).unwrap();
        for rule_id in [
            "comsvcs-minidump",
            "psexec-service",
            "event-log-cleared",
            "admin-group-add",
            "core-bruteforce-failures",
            "core-auth-failures-then-success",
            "core-pass-the-hash",
            "core-network-logon-service-install-chain",
            "core-account-create-privileged-group",
            "core-password-spray-distinct-users",
            "core-forged-ticket-no-tgt",
            "core-off-hours-interactive-logon",
            "core-service-install-aggregate",
            "core-intrusion-chain-window",
            "kerberoast-rc4",
            "pkinit-logon",
            "asrep-roast",
            "upn-swap",
            "force-change-password",
            "shadow-credentials",
            "domain-trust-discovery",
            "dcom-lateral-exec",
            "lsass-high-priv-access",
            "timestomp-file-create-time",
        ] {
            assert!(
                findings
                    .iter()
                    .any(|row| row.engine == "taotie-core"
                        && row.rule_id.as_deref() == Some(rule_id)),
                "{rule_id}"
            );
        }

        // The native Sigma engine must produce findings end-to-end through the
        // same pipeline (this data has 1102/4720/4732 events + LSASS/PsExec text).
        assert!(
            findings.iter().any(|row| row.engine == "sigma"),
            "expected at least one engine=sigma finding"
        );

        let psexec = findings
            .iter()
            .find(|row| {
                row.engine == "taotie-core" && row.rule_id.as_deref() == Some("psexec-service")
            })
            .expect("psexec-service finding");
        let psexec_events = get_finding_event_page(
            case_root.to_str().unwrap(),
            FindingEventPageQuery {
                title: psexec.title.clone(),
                engine: Some(psexec.engine.clone()),
                rule_id: psexec.rule_id.clone(),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".into()),
                    sort_dir: Some("asc".into()),
                },
            },
        )
        .unwrap();
        assert!(psexec_events.rows.iter().any(|row| row.has_finding));

        let auth_chain = findings
            .iter()
            .find(|row| {
                row.engine == "taotie-core"
                    && row.rule_id.as_deref() == Some("core-auth-failures-then-success")
            })
            .expect("auth chain finding");
        assert!(auth_chain.event_count >= 15);
        assert_eq!(auth_chain.severity, "critical");
    }

    #[test]
    fn clear_case_workspace_removes_only_managed_case_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("source_collection");
        std::fs::create_dir_all(&source_dir).unwrap();
        let source_file = source_dir.join("Security.evtx.xml");
        std::fs::write(&source_file, b"<Events></Events>").unwrap();

        let case_root = temp.path().join("case");
        create_case(CaseRequest {
            case_root: case_root.display().to_string(),
            name: "clear-case".into(),
        })
        .unwrap();
        ingest_fake_artifact(FakeArtifactRequest {
            case_root: case_root.display().to_string(),
            original_path: source_file.display().to_string(),
            content: "INFO original source should remain\n".into(),
        })
        .unwrap();
        std::fs::write(
            case_root.join("analyst-note.txt"),
            b"keep this sidecar note",
        )
        .unwrap();

        let result = clear_case_workspace(ClearCaseRequest {
            case_root: case_root.display().to_string(),
        })
        .unwrap();

        assert!(result
            .removed_paths
            .iter()
            .any(|path| path.ends_with("/raw") || path.ends_with("\\raw")));
        assert!(source_file.exists());
        assert!(case_root.join("analyst-note.txt").exists());
        assert!(!case_root.join("meta").join("case.json").exists());
        assert!(!case_root.join("lake").exists());
        assert!(!result.root_removed);
    }

    #[test]
    fn lnk_network_share_target_emits_finding() {
        let mut lnk_bytes = vec![0u8; 0x4c];
        lnk_bytes[0..4].copy_from_slice(&0x4cu32.to_le_bytes());
        lnk_bytes[0x14..0x18].copy_from_slice(&0x2u32.to_le_bytes());
        let network_share = b"\\\\FILESRV\\drop\0";
        let suffix = b"evil.exe\0";
        let network_offset = 0x1cusize;
        let network_size = 0x14 + network_share.len();
        let suffix_offset = network_offset + network_size;
        let link_info_size = suffix_offset + suffix.len();
        let mut link_info = vec![0u8; link_info_size];
        link_info[0..4].copy_from_slice(&(link_info_size as u32).to_le_bytes());
        link_info[4..8].copy_from_slice(&0x1cu32.to_le_bytes());
        link_info[8..12].copy_from_slice(&0x2u32.to_le_bytes());
        link_info[0x14..0x18].copy_from_slice(&(network_offset as u32).to_le_bytes());
        link_info[0x18..0x1c].copy_from_slice(&(suffix_offset as u32).to_le_bytes());
        link_info[network_offset..network_offset + 4]
            .copy_from_slice(&(network_size as u32).to_le_bytes());
        link_info[network_offset + 4..network_offset + 8].copy_from_slice(&0x2u32.to_le_bytes());
        link_info[network_offset + 8..network_offset + 12].copy_from_slice(&0x14u32.to_le_bytes());
        link_info[network_offset + 16..network_offset + 20]
            .copy_from_slice(&0x0002_0000u32.to_le_bytes());
        link_info[network_offset + 0x14..network_offset + 0x14 + network_share.len()]
            .copy_from_slice(network_share);
        link_info[suffix_offset..suffix_offset + suffix.len()].copy_from_slice(suffix);
        lnk_bytes.extend(link_info);

        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_lnk".into(),
            object_ref: "raw://sha256/lnk".into(),
            original_path: "C/Users/jdoe/Desktop/drop.lnk".into(),
            artifact_type: "lnk".into(),
            parse_run_id: "parse_lnk".into(),
            bytes: lnk_bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(
            parsed.events[0].file_path.as_deref(),
            Some("\\\\FILESRV\\drop\\evil.exe")
        );
        let findings = run_heuristic_findings("case_1", &parsed.events).unwrap();
        assert!(findings
            .iter()
            .any(|row| row.rule_id.as_deref() == Some("lnk-network-share-executable")));
    }
}
