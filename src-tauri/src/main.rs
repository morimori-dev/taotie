// Hide the console window on Windows release builds (GUI subsystem).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use taotie_api::{
    AnswerCandidateQuery, BuildSearchIndexRequest, CaseApprovalRequest, CaseCustodyProfileRequest,
    CaseRequest, ClearCaseRequest, CustodyManifestVerificationRequest, DeleteSavedSearchRequest,
    EventBookmarkRequest, EventSearchIndexRequest, EvidenceFindRequest, EvidenceRangeRequest,
    EvidenceVerificationRequest,
    FakeArtifactRequest, FindingOverrideRequest, FindingReviewRequest, IocFindingRequest,
    IocMatchRequest, LocalPathIngestRequest, LocalPathScanRequest, OpenCaseRequest,
    ReportBundleVerificationRequest, SavedSearchRequest, SidecarBatchRequest, SidecarPlanRequest,
    StartAnswerCandidateBuildRequest, StartSearchIndexBuildRequest, UploadedArtifactRequest,
};
use taotie_schema::{
    CorrelationChainEventPageQuery, DefenderEventPageQuery, EventContextQuery, EventPageQuery,
    FilePageQuery, FindingEventPageQuery, IocEventPageQuery,
};

type CommandResult<T> = std::result::Result<T, String>;

#[tauri::command]
fn create_case(request: CaseRequest) -> CommandResult<taotie_schema::CaseSummary> {
    taotie_api::create_case(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn open_case(request: OpenCaseRequest) -> CommandResult<taotie_schema::CaseSummary> {
    taotie_api::open_case(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn clear_case_workspace(request: ClearCaseRequest) -> CommandResult<taotie_api::ClearCaseResult> {
    taotie_api::clear_case_workspace(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn rebuild_analysis_read_models(case_root: String) -> CommandResult<taotie_schema::CaseSummary> {
    taotie_api::rebuild_analysis_read_models(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn select_case_directory() -> CommandResult<Option<String>> {
    let selected = rfd::FileDialog::new()
        .set_title("ケースフォルダを選択")
        .pick_folder()
        .map(|path| path.display().to_string());
    Ok(selected)
}

#[tauri::command]
fn select_ingest_directory() -> CommandResult<Option<String>> {
    let selected = rfd::FileDialog::new()
        .set_title("取り込む証跡フォルダを選択")
        .pick_folder()
        .map(|path| path.display().to_string());
    Ok(selected)
}

#[tauri::command]
fn get_case_custody_profile(
    case_root: String,
) -> CommandResult<taotie_schema::CaseCustodyProfile> {
    taotie_api::get_case_custody_profile(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn set_case_custody_profile(
    request: CaseCustodyProfileRequest,
) -> CommandResult<taotie_schema::CaseCustodyProfile> {
    taotie_api::set_case_custody_profile(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn ingest_fake_artifact(
    request: FakeArtifactRequest,
) -> CommandResult<taotie_schema::CaseSummary> {
    taotie_api::ingest_fake_artifact(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn ingest_uploaded_artifact(
    request: UploadedArtifactRequest,
) -> CommandResult<taotie_schema::CaseSummary> {
    taotie_api::ingest_uploaded_artifact(request).map_err(|error| error.to_string())
}

#[tauri::command]
async fn scan_local_path(
    request: LocalPathScanRequest,
) -> CommandResult<taotie_api::LocalPathScanResult> {
    tauri::async_runtime::spawn_blocking(move || {
        taotie_api::scan_local_path(request).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn ingest_local_path(
    request: LocalPathIngestRequest,
) -> CommandResult<taotie_api::LocalPathIngestResult> {
    tauri::async_runtime::spawn_blocking(move || {
        taotie_api::ingest_local_path(request).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
fn get_case_summary(case_root: String) -> CommandResult<taotie_schema::CaseSummary> {
    taotie_api::get_case_summary(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_file_page(
    case_root: String,
    page: FilePageQuery,
) -> CommandResult<taotie_schema::Page<taotie_schema::FileRecord>> {
    taotie_api::get_file_page(&case_root, page).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_page(
    case_root: String,
    page: EventPageQuery,
) -> CommandResult<taotie_schema::Page<taotie_schema::EventRow>> {
    taotie_api::get_event_page(&case_root, page).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_facets(
    case_root: String,
    page: EventPageQuery,
    per_field_limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::EventFacetValue>> {
    taotie_api::get_event_facets(&case_root, page, per_field_limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn build_search_index(
    request: BuildSearchIndexRequest,
) -> CommandResult<taotie_api::SearchIndexMetadata> {
    taotie_api::build_search_index(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn start_search_index_build(
    request: StartSearchIndexBuildRequest,
) -> CommandResult<taotie_schema::JobRecord> {
    taotie_api::start_search_index_build(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn enqueue_sidecar_analysis(request: SidecarPlanRequest) -> CommandResult<taotie_schema::JobRecord> {
    taotie_api::enqueue_sidecar_analysis(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn run_sidecar_batch(request: SidecarBatchRequest) -> CommandResult<taotie_api::SidecarBatchResult> {
    taotie_api::run_sidecar_batch(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_search_index_metadata(
    case_root: String,
) -> CommandResult<Option<taotie_api::SearchIndexMetadata>> {
    taotie_api::get_search_index_metadata(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_search_index_status(case_root: String) -> CommandResult<taotie_api::SearchIndexStatus> {
    taotie_api::get_search_index_status(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_answer_candidates(
    request: AnswerCandidateQuery,
) -> CommandResult<Vec<taotie_schema::AnswerCandidate>> {
    taotie_api::get_answer_candidates(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn start_answer_candidate_build(
    request: StartAnswerCandidateBuildRequest,
) -> CommandResult<taotie_schema::JobRecord> {
    taotie_api::start_answer_candidate_build(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn start_analysis_read_model_jobs(
    case_root: String,
    trigger: Option<String>,
) -> CommandResult<Vec<taotie_schema::JobRecord>> {
    taotie_api::start_analysis_read_model_jobs(&case_root, trigger)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn search_indexed_events(
    request: EventSearchIndexRequest,
) -> CommandResult<taotie_schema::Page<taotie_api::EventSearchHit>> {
    taotie_api::search_indexed_events(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_detail_light(
    case_root: String,
    event_id: String,
) -> CommandResult<Option<taotie_schema::EventDetailLight>> {
    taotie_api::get_event_detail_light(&case_root, &event_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_context(
    case_root: String,
    query: EventContextQuery,
) -> CommandResult<Option<taotie_schema::EventContext>> {
    taotie_api::get_event_context(&case_root, query).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_raw_record(
    case_root: String,
    event_id: String,
) -> CommandResult<Option<taotie_schema::RawRecord>> {
    taotie_api::get_event_raw_record(&case_root, &event_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_artifact_objects(
    case_root: String,
    event_id: String,
) -> CommandResult<Vec<taotie_schema::ArtifactObject>> {
    taotie_api::get_event_artifact_objects(&case_root, &event_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_evidence_offsets(
    case_root: String,
    event_id: String,
) -> CommandResult<Vec<taotie_schema::EvidenceOffset>> {
    taotie_api::get_event_evidence_offsets(&case_root, &event_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_evidence_range(
    request: EvidenceRangeRequest,
) -> CommandResult<taotie_schema::EvidenceRange> {
    taotie_api::get_evidence_range(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn find_evidence_match(
    request: EvidenceFindRequest,
) -> CommandResult<taotie_api::EvidenceFindResult> {
    taotie_api::find_evidence_match(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn verify_evidence_page(
    request: EvidenceVerificationRequest,
) -> CommandResult<taotie_schema::Page<taotie_schema::EvidenceVerification>> {
    taotie_api::verify_evidence_page(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn export_events(
    case_root: String,
    page: EventPageQuery,
    format: String,
    output_path: Option<String>,
    max_rows: Option<usize>,
) -> CommandResult<taotie_schema::EventExportResult> {
    taotie_api::export_events(&case_root, page, &format, output_path, max_rows)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_timeline_bins(
    case_root: String,
    granularity: String,
) -> CommandResult<Vec<taotie_schema::TimelineBin>> {
    taotie_api::get_timeline_bins(&case_root, &granularity).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_timeline(
    case_root: String,
    page: EventPageQuery,
    granularity: String,
) -> CommandResult<Vec<taotie_schema::EventTimelineBin>> {
    taotie_api::get_event_timeline(&case_root, page, &granularity)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_timestomp_scatter(
    case_root: String,
) -> CommandResult<Vec<taotie_schema::TimestompPoint>> {
    taotie_api::get_timestomp_scatter(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_process_tree(case_root: String) -> CommandResult<Vec<taotie_schema::ProcessTreeEdge>> {
    taotie_api::get_process_tree(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_process_tree_instances(
    case_root: String,
) -> CommandResult<Vec<taotie_schema::ProcessNode>> {
    taotie_api::get_process_tree_instances(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_file_op_timeline(case_root: String) -> CommandResult<Vec<taotie_schema::FileOpBin>> {
    taotie_api::get_file_op_timeline(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_beacon_intervals(
    case_root: String,
) -> CommandResult<Vec<taotie_schema::BeaconIntervalBin>> {
    taotie_api::get_beacon_intervals(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_coverage_summary(case_root: String) -> CommandResult<Vec<taotie_schema::CoverageSummary>> {
    taotie_api::get_coverage_summary(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_failed_parser_summary(
    case_root: String,
) -> CommandResult<Vec<taotie_schema::FailedParserSummary>> {
    taotie_api::get_failed_parser_summary(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_finding_summary(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::FindingSummary>> {
    taotie_api::get_finding_summary(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_triage_actions(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::TriageAction>> {
    taotie_api::get_triage_actions(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_case_detection_evaluation(
    case_root: String,
) -> CommandResult<taotie_schema::CaseDetectionEvaluation> {
    taotie_api::get_case_detection_evaluation(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_finding_event_page(
    case_root: String,
    query_page: FindingEventPageQuery,
) -> CommandResult<taotie_schema::Page<taotie_schema::EventRow>> {
    taotie_api::get_finding_event_page(&case_root, query_page).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_ioc_matches(request: IocMatchRequest) -> CommandResult<Vec<taotie_schema::IocHit>> {
    taotie_api::get_ioc_matches(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn run_ioc_findings(
    request: IocFindingRequest,
) -> CommandResult<Vec<taotie_schema::FindingSummary>> {
    taotie_api::run_ioc_findings(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_ioc_event_page(
    case_root: String,
    query_page: IocEventPageQuery,
) -> CommandResult<taotie_schema::Page<taotie_schema::EventRow>> {
    taotie_api::get_ioc_event_page(&case_root, query_page).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_defender_summary(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::DefenderSummary>> {
    taotie_api::get_defender_summary(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_defender_event_page(
    case_root: String,
    query_page: DefenderEventPageQuery,
) -> CommandResult<taotie_schema::Page<taotie_schema::EventRow>> {
    taotie_api::get_defender_event_page(&case_root, query_page)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_prefetch_summary(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::PrefetchSummary>> {
    taotie_api::get_prefetch_summary(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_finding_overrides(
    case_root: String,
) -> CommandResult<Vec<taotie_schema::FindingOverride>> {
    taotie_api::get_finding_overrides(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_finding_reviews(case_root: String) -> CommandResult<Vec<taotie_schema::FindingReview>> {
    taotie_api::get_finding_reviews(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_finding_review_summary(
    case_root: String,
) -> CommandResult<taotie_schema::FindingReviewSummary> {
    taotie_api::get_finding_review_summary(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn set_finding_review(
    request: FindingReviewRequest,
) -> CommandResult<Vec<taotie_schema::FindingReview>> {
    taotie_api::set_finding_review(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_case_approvals(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::CaseApprovalRecord>> {
    taotie_api::get_case_approvals(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn set_case_approval(
    request: CaseApprovalRequest,
) -> CommandResult<Vec<taotie_schema::CaseApprovalRecord>> {
    taotie_api::set_case_approval(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_saved_searches(
    case_root: String,
    limit: Option<usize>,
    viewer: Option<String>,
) -> CommandResult<Vec<taotie_schema::SavedSearch>> {
    taotie_api::get_saved_searches_for(&case_root, limit, viewer.as_deref())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn save_saved_search(request: SavedSearchRequest) -> CommandResult<Vec<taotie_schema::SavedSearch>> {
    taotie_api::save_saved_search(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_saved_search(
    request: DeleteSavedSearchRequest,
) -> CommandResult<Vec<taotie_schema::SavedSearch>> {
    taotie_api::delete_saved_search(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_audit_log(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::AuditLogEntry>> {
    taotie_api::get_audit_log(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn add_finding_override(
    request: FindingOverrideRequest,
) -> CommandResult<Vec<taotie_schema::FindingOverride>> {
    taotie_api::add_finding_override(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn remove_finding_override(
    case_root: String,
    override_id: String,
) -> CommandResult<Vec<taotie_schema::FindingOverride>> {
    taotie_api::remove_finding_override(&case_root, &override_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_event_bookmarks(
    case_root: String,
) -> CommandResult<Vec<taotie_schema::EventBookmark>> {
    taotie_api::get_event_bookmarks(&case_root).map_err(|error| error.to_string())
}

#[tauri::command]
fn add_event_bookmark(
    request: EventBookmarkRequest,
) -> CommandResult<Vec<taotie_schema::EventBookmark>> {
    taotie_api::add_event_bookmark(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn remove_event_bookmark(
    case_root: String,
    bookmark_id: String,
) -> CommandResult<Vec<taotie_schema::EventBookmark>> {
    taotie_api::remove_event_bookmark(&case_root, &bookmark_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_bookmark_event_page(
    case_root: String,
    page: EventPageQuery,
) -> CommandResult<taotie_schema::Page<taotie_schema::EventRow>> {
    taotie_api::get_bookmark_event_page(&case_root, page).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_risk_summary(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::RiskSummary>> {
    taotie_api::get_risk_summary(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_analyzer_runs(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::AnalyzerRunSummary>> {
    taotie_api::get_analyzer_runs(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_entity_summary(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::EntityRecord>> {
    taotie_api::get_entity_summary(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_subgraph(
    case_root: String,
    entity_id: String,
    hops: Option<usize>,
    edge_limit: Option<usize>,
) -> CommandResult<taotie_schema::Subgraph> {
    taotie_api::get_subgraph(&case_root, &entity_id, hops, edge_limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_correlation_summary(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::CorrelationSummary>> {
    taotie_api::get_correlation_summary(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_correlation_chains(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::CorrelationChainSummary>> {
    taotie_api::get_correlation_chains(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn rebuild_correlation_read_model(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::CorrelationChainSummary>> {
    taotie_api::rebuild_correlation_read_model(&case_root, limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_correlation_chain_event_page(
    case_root: String,
    query_page: CorrelationChainEventPageQuery,
) -> CommandResult<taotie_schema::Page<taotie_schema::EventRow>> {
    taotie_api::get_correlation_chain_event_page(&case_root, query_page)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_user_activity_summary(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::UserActivitySummary>> {
    taotie_api::get_user_activity_summary(&case_root, limit).map_err(|error| error.to_string())
}

#[tauri::command]
fn generate_case_report(
    case_root: String,
    output_path: Option<String>,
) -> CommandResult<String> {
    taotie_api::generate_case_report(&case_root, output_path).map_err(|error| error.to_string())
}

#[tauri::command]
fn generate_custody_manifest(
    case_root: String,
    output_path: Option<String>,
) -> CommandResult<String> {
    taotie_api::generate_custody_manifest(&case_root, output_path)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn generate_report_bundle(case_root: String, output_path: Option<String>) -> CommandResult<String> {
    taotie_api::generate_report_bundle(&case_root, output_path).map_err(|error| error.to_string())
}

#[tauri::command]
fn verify_report_bundle(
    request: ReportBundleVerificationRequest,
) -> CommandResult<taotie_schema::ReportBundleVerification> {
    taotie_api::verify_report_bundle(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn verify_custody_manifest(
    request: CustodyManifestVerificationRequest,
) -> CommandResult<taotie_schema::CustodyManifestVerification> {
    taotie_api::verify_custody_manifest(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_recent_jobs(
    case_root: String,
    limit: Option<usize>,
) -> CommandResult<Vec<taotie_schema::JobRecord>> {
    taotie_api::get_recent_jobs(&case_root, limit).map_err(|error| error.to_string())
}

fn main() {
    tracing_subscriber::fmt::init();
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            create_case,
            open_case,
            clear_case_workspace,
            rebuild_analysis_read_models,
            select_case_directory,
            select_ingest_directory,
            get_case_custody_profile,
            set_case_custody_profile,
            ingest_fake_artifact,
            ingest_uploaded_artifact,
            scan_local_path,
            ingest_local_path,
            get_case_summary,
            get_file_page,
            get_event_page,
            get_event_facets,
            build_search_index,
            start_search_index_build,
            enqueue_sidecar_analysis,
            run_sidecar_batch,
            get_search_index_metadata,
            get_search_index_status,
            search_indexed_events,
            get_event_detail_light,
            get_event_context,
            get_event_raw_record,
            get_event_artifact_objects,
            get_event_evidence_offsets,
            get_evidence_range,
            find_evidence_match,
            verify_evidence_page,
            export_events,
            get_timeline_bins,
            get_event_timeline,
            get_timestomp_scatter,
            get_process_tree,
            get_process_tree_instances,
            get_file_op_timeline,
            get_beacon_intervals,
            get_coverage_summary,
            get_failed_parser_summary,
            get_finding_summary,
            get_answer_candidates,
            start_answer_candidate_build,
            start_analysis_read_model_jobs,
            get_triage_actions,
            get_case_detection_evaluation,
            get_finding_event_page,
            get_ioc_matches,
            run_ioc_findings,
            get_ioc_event_page,
            get_defender_summary,
            get_defender_event_page,
            get_prefetch_summary,
            get_finding_overrides,
            get_finding_reviews,
            get_finding_review_summary,
            set_finding_review,
            get_case_approvals,
            set_case_approval,
            get_saved_searches,
            save_saved_search,
            delete_saved_search,
            get_audit_log,
            add_finding_override,
            remove_finding_override,
            get_event_bookmarks,
            add_event_bookmark,
            remove_event_bookmark,
            get_bookmark_event_page,
            get_risk_summary,
            get_analyzer_runs,
            get_entity_summary,
            get_subgraph,
            get_correlation_summary,
            get_correlation_chains,
            rebuild_correlation_read_model,
            get_correlation_chain_event_page,
            get_user_activity_summary,
            generate_case_report,
            generate_custody_manifest,
            generate_report_bundle,
            verify_report_bundle,
            verify_custody_manifest,
            get_recent_jobs
        ])
        .run(tauri::generate_context!())
        .expect("taotie tauri application failed");
}
