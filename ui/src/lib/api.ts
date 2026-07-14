import { invoke } from '@tauri-apps/api/core';
import type {
  AnswerCandidate,
  AuditLogEntry,
  CaseDetectionEvaluation,
  ClearCaseResult,
  CaseApprovalRecord,
  CaseApprovalStatus,
  CaseCustodyProfile,
  CaseSummary,
  CorrelationChainSummary,
  CorrelationSummary,
  CoverageSummary,
  CustodyManifestVerification,
  DefenderSummary,
  EdgeRecord,
  EntityRecord,
  EventBookmark,
  EventContext,
  EventContextGroup,
  EventDetailLight,
  EventExportResult,
  EventFacetValue,
  EventPageQuery,
  EventRow,
  EventSearchHit,
  EventSortBy,
  EventSortDir,
  ArtifactObject,
  EvidenceOffset,
  EvidenceRange,
  EvidenceFindResult,
  EvidenceVerification,
  FailedParserSummary,
  FileRecord,
  AnalyzerRunSummary,
  FindingOverride,
  FindingReview,
  FindingReviewSummary,
  FindingReviewStatus,
  FindingSummary,
  IocHit,
  LocalPathIngestResult,
  LocalPathScanResult,
  Subgraph,
  JobRecord,
  Page,
  PrefetchSummary,
  RawRecord,
  ReportBundleVerification,
  RiskSummary,
  SavedSearch,
  SearchIndexMetadata,
  SearchIndexStatus,
  SidecarBatchResult,
  TimelineBin,
  EventTimelineBin,
  TimestompPoint,
  ProcessNode,
  ProcessRelatedEvent,
  ProcessTreeEdge,
  FileOpBin,
  BeaconIntervalBin,
  TriageAction,
  UserActivitySummary
} from './types';

type TauriWindow = Window & { __TAURI_INTERNALS__?: unknown };

const mock = createMockState();
const MOCK_UPLOAD_PREVIEW_BYTES = 1024 * 1024;

type EventPageFilters = {
  artifactType?: string | null;
  userName?: string | null;
  search?: string | null;
  sortBy?: EventSortBy | null;
  sortDir?: EventSortDir | null;
};

function eventFiltersToPage(
  limit: number,
  cursor: string | null | undefined,
  filters: EventPageFilters
): EventPageQuery {
  return {
    limit,
    cursor,
    artifact_type: filters.artifactType ?? null,
    user_name: filters.userName ?? null,
    search: filters.search ?? null,
    sort_by: filters.sortBy ?? null,
    sort_dir: filters.sortDir ?? null
  };
}

function isTauri(): boolean {
  return typeof window !== 'undefined' && Boolean((window as TauriWindow).__TAURI_INTERNALS__);
}

async function call<T>(command: string, args: Record<string, unknown>, fallback: () => T): Promise<T> {
  if (!isTauri()) {
    return fallback();
  }
  return invoke<T>(command, args);
}

export function createCase(caseRoot: string, name: string): Promise<CaseSummary> {
  return call('create_case', { request: { case_root: caseRoot, name } }, () => {
    mock.case = {
      case_id: 'case_mock',
      name,
      root_path: caseRoot,
      created_at: new Date().toISOString(),
      schema_version: 'taotie-lite-v1',
      file_count: mock.files.length,
      event_count: mock.events.length,
      failed_parse_count: 0,
      unsupported_file_count: 0
    };
    return mock.case;
  });
}

export function openCase(caseRoot: string): Promise<CaseSummary> {
  return call('open_case', { request: { case_root: caseRoot } }, () => mock.summary(caseRoot));
}

export function clearCaseWorkspace(caseRoot: string): Promise<ClearCaseResult> {
  return call(
    'clear_case_workspace',
    { request: { case_root: caseRoot } },
    () => ({
      case_root: caseRoot,
      removed_paths: [],
      root_removed: false
    })
  );
}

export function selectCaseDirectory(): Promise<string | null> {
  return call('select_case_directory', {}, () => null);
}

export function selectIngestDirectory(): Promise<string | null> {
  return call('select_ingest_directory', {}, () => null);
}

export function getCaseCustodyProfile(caseRoot: string): Promise<CaseCustodyProfile> {
  return call('get_case_custody_profile', { caseRoot }, () => mock.caseCustodyProfile());
}

export function setCaseCustodyProfile(
  caseRoot: string,
  profile: Omit<CaseCustodyProfile, 'case_id' | 'updated_at'>
): Promise<CaseCustodyProfile> {
  return call(
    'set_case_custody_profile',
    {
      request: {
        case_root: caseRoot,
        investigator: profile.investigator ?? null,
        custodian: profile.custodian ?? null,
        organization: profile.organization ?? null,
        evidence_source: profile.evidence_source ?? null,
        acquisition_method: profile.acquisition_method ?? null,
        acquired_at: profile.acquired_at ?? null,
        legal_authority: profile.legal_authority ?? null,
        chain_of_custody_note: profile.chain_of_custody_note ?? null
      }
    },
    () => mock.setCaseCustodyProfile(profile)
  );
}

export function ingestFakeArtifact(
  caseRoot: string,
  originalPath: string,
  content: string
): Promise<CaseSummary> {
  return call(
    'ingest_fake_artifact',
    { request: { case_root: caseRoot, original_path: originalPath, content } },
    () => mock.ingest(caseRoot, originalPath, content)
  );
}

export function ingestUploadedArtifact(
  caseRoot: string,
  originalPath: string,
  contentBase64: string
): Promise<CaseSummary> {
  return call(
    'ingest_uploaded_artifact',
    { request: { case_root: caseRoot, original_path: originalPath, content_base64: contentBase64 } },
    () => mock.ingest(caseRoot, originalPath, decodeBase64TextPreview(contentBase64), true)
  );
}

export function ingestLocalPath(
  caseRoot: string,
  inputPath: string,
  recursive = true
): Promise<LocalPathIngestResult> {
  return call(
    'ingest_local_path',
    { request: { case_root: caseRoot, input_path: inputPath, recursive } },
    () => {
      const summary = mock.summary(caseRoot);
      return {
        summary,
        file_count: 0,
        skipped_count: 0,
        failed_count: 1,
        errors: ['local path ingest requires Tauri']
      };
    }
  );
}

export function scanLocalPath(inputPath: string, recursive = true): Promise<LocalPathScanResult> {
  return call(
    'scan_local_path',
    { request: { input_path: inputPath, recursive } },
    () => ({
      file_count: 0,
      total_bytes: 0
    })
  );
}

export async function ingestUploadedFile(
  caseRoot: string,
  originalPath: string,
  file: File
): Promise<CaseSummary> {
  if (isTauri()) {
    return ingestUploadedArtifact(caseRoot, originalPath, await fileToBase64(file));
  }
  const preview = await fileTextPreview(file, MOCK_UPLOAD_PREVIEW_BYTES);
  return mock.ingest(caseRoot, originalPath, preview, true, file.size);
}

export function getEvidenceRange(
  caseRoot: string,
  objectRef: string,
  offset = 0,
  length = 4096
): Promise<EvidenceRange> {
  return call(
    'get_evidence_range',
    { request: { case_root: caseRoot, object_ref: objectRef, offset, length } },
    () => mock.evidenceRange(objectRef, offset, length)
  );
}

export function findEvidenceMatch(
  caseRoot: string,
  objectRef: string,
  pattern: string,
  isHex: boolean,
  fromOffset = 0
): Promise<EvidenceFindResult> {
  return call(
    'find_evidence_match',
    {
      request: {
        case_root: caseRoot,
        object_ref: objectRef,
        pattern,
        is_hex: isHex,
        from_offset: fromOffset
      }
    },
    () => ({ offset: null, total_size: 0, pattern_len: 0 })
  );
}

export function verifyEvidencePage(
  caseRoot: string,
  limit = 25,
  cursor?: string | null
): Promise<Page<EvidenceVerification>> {
  return call(
    'verify_evidence_page',
    { request: { case_root: caseRoot, limit, cursor: cursor ?? null } },
    () => mock.verifyEvidencePage(limit, cursor)
  );
}

export function getCaseSummary(caseRoot: string): Promise<CaseSummary> {
  return call('get_case_summary', { caseRoot }, () => mock.summary(caseRoot));
}

export function rebuildAnalysisReadModels(caseRoot: string): Promise<CaseSummary> {
  return call('rebuild_analysis_read_models', { caseRoot }, () => mock.rebuildAnalysisReadModels(caseRoot));
}

export function getFilePage(
  caseRoot: string,
  limit = 100,
  cursor?: string | null
): Promise<Page<FileRecord>> {
  return call('get_file_page', { caseRoot, page: { limit, cursor } }, () => ({
    rows: mock.files.slice(0, limit),
    next_cursor: null
  }));
}

export function getEventPage(
  caseRoot: string,
  limit = 100,
  cursor?: string | null,
  filters: EventPageFilters = {}
): Promise<Page<EventRow>> {
  return call(
    'get_event_page',
    {
      caseRoot,
      page: eventFiltersToPage(limit, cursor, filters)
    },
    () => {
      const sorted = filteredMockEvents(mock.events, filters);
      const start = cursor ? Number(cursor) : 0;
      const rows = sorted.slice(start, start + limit);
      const next = start + limit < sorted.length ? String(start + limit) : null;
      return { rows, next_cursor: next };
    }
  );
}

export function getEventFacets(
  caseRoot: string,
  filters: EventPageFilters = {},
  perFieldLimit = 8
): Promise<EventFacetValue[]> {
  return call(
    'get_event_facets',
    {
      caseRoot,
      page: eventFiltersToPage(100, null, filters),
      perFieldLimit
    },
    () => mock.eventFacets(filters, perFieldLimit)
  );
}

export function buildSearchIndex(caseRoot: string): Promise<SearchIndexMetadata> {
  return call(
    'build_search_index',
    { request: { case_root: caseRoot } },
    () => mock.buildSearchIndex()
  );
}

export function startSearchIndexBuild(caseRoot: string): Promise<JobRecord> {
  return call(
    'start_search_index_build',
    { request: { case_root: caseRoot } },
    () => mock.startSearchIndexBuild()
  );
}

export function enqueueSidecarAnalysis(
  caseRoot: string,
  eventId: string,
  sidecar?: string | null
): Promise<JobRecord> {
  return call(
    'enqueue_sidecar_analysis',
    { request: { case_root: caseRoot, event_id: eventId, sidecar } },
    () => mockJob(sidecar?.includes('pcap') ? 'run_network_sidecar' : 'run_sidecar')
  );
}

export function runSidecarBatch(
  caseRoot: string,
  limit = 25,
  execute = true,
  rebuildAfterExecute = true
): Promise<SidecarBatchResult> {
  return call(
    'run_sidecar_batch',
    { request: { case_root: caseRoot, limit, execute, rebuild_after_execute: rebuildAfterExecute } },
    () => ({
      queued_count: execute ? 0 : 1,
      executed_count: execute ? 1 : 0,
      succeeded_count: execute ? 1 : 0,
      failed_count: 0,
      skipped_count: 0,
      jobs: [mockJob('run_sidecar')],
      tool_status_json: JSON.stringify([{ tool: 'mock', available: true }])
    })
  );
}

export function getSearchIndexMetadata(caseRoot: string): Promise<SearchIndexMetadata | null> {
  return call('get_search_index_metadata', { caseRoot }, () => mock.searchIndexMetadata);
}

export function getSearchIndexStatus(caseRoot: string): Promise<SearchIndexStatus> {
  return call('get_search_index_status', { caseRoot }, () => mock.searchIndexStatus);
}

export function searchIndexedEvents(
  caseRoot: string,
  text: string,
  limit = 50,
  cursor?: string | null
): Promise<Page<EventSearchHit>> {
  return call(
    'search_indexed_events',
    { request: { case_root: caseRoot, text, limit, cursor: cursor ?? null } },
    () => mock.searchIndexedEvents(text, limit, cursor ?? null)
  );
}

export function getEventDetailLight(
  caseRoot: string,
  eventId: string
): Promise<EventDetailLight | null> {
  return call('get_event_detail_light', { caseRoot, eventId }, () => mock.details.get(eventId) ?? null);
}

export function getEventContext(
  caseRoot: string,
  eventId: string,
  windowMinutes = 15,
  perGroupLimit = 50,
  sameHostOnly = false
): Promise<EventContext | null> {
  return call(
    'get_event_context',
    {
      caseRoot,
      query: {
        event_id: eventId,
        window_minutes: windowMinutes,
        per_group_limit: perGroupLimit,
        same_host_only: sameHostOnly
      }
    },
    () => mock.eventContext(eventId, windowMinutes, perGroupLimit, sameHostOnly)
  );
}

export function getEventRawRecord(caseRoot: string, eventId: string): Promise<RawRecord | null> {
  return call('get_event_raw_record', { caseRoot, eventId }, () => mock.raw.get(eventId) ?? null);
}

export function getEventArtifactObjects(caseRoot: string, eventId: string): Promise<ArtifactObject[]> {
  return call('get_event_artifact_objects', { caseRoot, eventId }, () => mock.artifactObjects(eventId));
}

export function getEventEvidenceOffsets(caseRoot: string, eventId: string): Promise<EvidenceOffset[]> {
  return call('get_event_evidence_offsets', { caseRoot, eventId }, () => mock.evidenceOffsets(eventId));
}

export function exportEvents(
  caseRoot: string,
  filters: EventPageFilters = {},
  format: 'csv' | 'jsonl' = 'csv',
  maxRows = 100_000
): Promise<EventExportResult> {
  const outputFormat = format === 'jsonl' ? 'jsonl' : 'csv';
  return call(
    'export_events',
    {
      caseRoot,
      page: {
        limit: null,
        cursor: null,
        artifact_type: filters.artifactType ?? null,
        user_name: filters.userName ?? null,
        search: filters.search ?? null,
        sort_by: filters.sortBy ?? null,
        sort_dir: filters.sortDir ?? null
      },
      format: outputFormat,
      outputPath: null,
      maxRows
    },
    () => mock.exportEvents(filters, outputFormat, maxRows)
  );
}

export function getTimelineBins(caseRoot: string): Promise<TimelineBin[]> {
  return call('get_timeline_bins', { caseRoot, granularity: 'hour' }, () => mock.timeline);
}

export function getEventTimeline(
  caseRoot: string,
  filters: EventPageFilters = {},
  granularity: 'minute' | 'hour' | 'day' = 'hour'
): Promise<EventTimelineBin[]> {
  return call(
    'get_event_timeline',
    {
      caseRoot,
      page: eventFiltersToPage(100, null, filters),
      granularity
    },
    () => []
  );
}

export function getTimestompScatter(caseRoot: string): Promise<TimestompPoint[]> {
  return call('get_timestomp_scatter', { caseRoot }, () => []);
}

export function getProcessTree(caseRoot: string): Promise<ProcessTreeEdge[]> {
  return call('get_process_tree', { caseRoot }, () => []);
}

export function getProcessTreeInstances(caseRoot: string): Promise<ProcessNode[]> {
  return call('get_process_tree_instances', { caseRoot }, () => []);
}

export function getProcessRelatedEvents(
  caseRoot: string,
  guid: string
): Promise<ProcessRelatedEvent[]> {
  return call('get_process_related_events', { caseRoot, guid }, () => []);
}

export function getFileOpTimeline(caseRoot: string): Promise<FileOpBin[]> {
  return call('get_file_op_timeline', { caseRoot }, () => []);
}

export function getBeaconIntervals(caseRoot: string): Promise<BeaconIntervalBin[]> {
  return call('get_beacon_intervals', { caseRoot }, () => []);
}

export function getCoverageSummary(caseRoot: string): Promise<CoverageSummary[]> {
  return call('get_coverage_summary', { caseRoot }, () => mock.coverage);
}

export function getFailedParserSummary(caseRoot: string): Promise<FailedParserSummary[]> {
  return call('get_failed_parser_summary', { caseRoot }, () => []);
}

export function getFindingSummary(caseRoot: string, limit = 100): Promise<FindingSummary[]> {
  return call('get_finding_summary', { caseRoot, limit }, () => mock.findings(limit));
}

export function getAnswerCandidates(
  caseRoot: string,
  questionKey: string | null = null,
  limit = 200
): Promise<AnswerCandidate[]> {
  return call(
    'get_answer_candidates',
    { request: { case_root: caseRoot, question_key: questionKey, limit } },
    () => mock.answerCandidates(questionKey, limit)
  );
}

export function startAnswerCandidateBuild(caseRoot: string): Promise<JobRecord> {
  return call(
    'start_answer_candidate_build',
    { request: { case_root: caseRoot } },
    () => mock.startAnswerCandidateBuild()
  );
}

export function startAnalysisReadModelJobs(caseRoot: string, trigger = 'manual_refresh'): Promise<JobRecord[]> {
  return call(
    'start_analysis_read_model_jobs',
    { caseRoot, trigger },
    () => mock.startAnalysisReadModelJobs()
  );
}

export function getTriageActions(caseRoot: string, limit = 100): Promise<TriageAction[]> {
  return call('get_triage_actions', { caseRoot, limit }, () => mock.triageActions(limit));
}

export function getCaseDetectionEvaluation(caseRoot: string): Promise<CaseDetectionEvaluation> {
  return call('get_case_detection_evaluation', { caseRoot }, () => mock.caseDetectionEvaluation());
}

export function getFindingOverrides(caseRoot: string): Promise<FindingOverride[]> {
  return call('get_finding_overrides', { caseRoot }, () => mock.findingOverrides);
}

export function getFindingReviews(caseRoot: string): Promise<FindingReview[]> {
  return call('get_finding_reviews', { caseRoot }, () => mock.findingReviews);
}

export function getFindingReviewSummary(caseRoot: string): Promise<FindingReviewSummary> {
  return call('get_finding_review_summary', { caseRoot }, () => mock.findingReviewSummary());
}

export function setFindingReview(
  caseRoot: string,
  finding: Pick<FindingSummary, 'title' | 'engine' | 'rule_id'>,
  status: FindingReviewStatus,
  reviewer?: string | null,
  assignee?: string | null,
  tags?: string[] | null,
  dueAt?: string | null,
  comment?: string | null
): Promise<FindingReview[]> {
  return call(
    'set_finding_review',
    {
      request: {
        case_root: caseRoot,
        engine: finding.engine,
        rule_id: finding.rule_id ?? null,
        title: finding.title,
        status,
        reviewer: reviewer ?? null,
        assignee: assignee ?? null,
        tags: tags ?? null,
        due_at: dueAt ?? null,
        comment: comment ?? null
      }
    },
    () => mock.setFindingReview(finding, status, reviewer ?? null, assignee ?? null, tags ?? null, dueAt ?? null, comment ?? null)
  );
}

export function getCaseApprovals(caseRoot: string, limit = 100): Promise<CaseApprovalRecord[]> {
  return call('get_case_approvals', { caseRoot, limit }, () => mock.caseApprovals.slice(0, limit));
}

export function setCaseApproval(
  caseRoot: string,
  targetKind: string,
  status: CaseApprovalStatus,
  approver?: string | null,
  role?: string | null,
  comment?: string | null,
  targetPath?: string | null,
  targetId?: string | null,
  targetSha256?: string | null
): Promise<CaseApprovalRecord[]> {
  return call(
    'set_case_approval',
    {
      request: {
        case_root: caseRoot,
        target_kind: targetKind,
        target_id: targetId ?? null,
        target_path: targetPath ?? null,
        target_sha256: targetSha256 ?? null,
        status,
        approver: approver ?? null,
        role: role ?? null,
        comment: comment ?? null
      }
    },
    () =>
      mock.setCaseApproval(
        targetKind,
        status,
        approver ?? null,
        role ?? null,
        comment ?? null,
        targetPath ?? null,
        targetId ?? null,
        targetSha256 ?? null
      )
  );
}

export function getSavedSearches(
  caseRoot: string,
  limit = 100,
  viewer?: string | null
): Promise<SavedSearch[]> {
  return call('get_saved_searches', { caseRoot, limit, viewer: viewer ?? null }, () =>
    mock.visibleSavedSearches(limit, viewer ?? null)
  );
}

export function saveSavedSearch(
  caseRoot: string,
  name: string,
  filters: EventPageFilters,
  description?: string | null,
  createdBy?: string | null,
  visibility?: string | null,
  sharedWith?: string[] | null
): Promise<SavedSearch[]> {
  return call(
    'save_saved_search',
    {
      request: {
        case_root: caseRoot,
        name,
        query: eventFiltersToPage(100, null, filters),
        description: description ?? null,
        created_by: createdBy ?? null,
        visibility: visibility ?? null,
        shared_with: sharedWith ?? null
      }
    },
    () =>
      mock.saveSavedSearch(
        name,
        eventFiltersToPage(100, null, filters),
        description ?? null,
        createdBy ?? null,
        visibility ?? null,
        sharedWith ?? null
      )
  );
}

export function deleteSavedSearch(
  caseRoot: string,
  searchId: string,
  requestedBy?: string | null
): Promise<SavedSearch[]> {
  return call(
    'delete_saved_search',
    { request: { case_root: caseRoot, search_id: searchId, requested_by: requestedBy ?? null } },
    () => mock.deleteSavedSearch(searchId, requestedBy ?? null)
  );
}

export function getAuditLog(caseRoot: string, limit = 200): Promise<AuditLogEntry[]> {
  return call('get_audit_log', { caseRoot, limit }, () => mock.auditLog.slice(0, limit));
}

export function addFindingOverride(
  caseRoot: string,
  finding: Pick<FindingSummary, 'title' | 'engine' | 'rule_id'>,
  action: 'suppress' | 'severity_override',
  severity?: string | null,
  reason?: string | null
): Promise<FindingOverride[]> {
  return call(
    'add_finding_override',
    {
      request: {
        case_root: caseRoot,
        engine: finding.engine,
        rule_id: finding.rule_id ?? null,
        title: finding.title,
        action,
        severity: severity ?? null,
        reason: reason ?? null
      }
    },
    () => mock.addFindingOverride(finding, action, severity ?? null, reason ?? null)
  );
}

export function removeFindingOverride(caseRoot: string, overrideId: string): Promise<FindingOverride[]> {
  return call('remove_finding_override', { caseRoot, overrideId }, () => mock.removeFindingOverride(overrideId));
}

export function getEventBookmarks(caseRoot: string): Promise<EventBookmark[]> {
  return call('get_event_bookmarks', { caseRoot }, () => mock.bookmarks);
}

export function addEventBookmark(
  caseRoot: string,
  eventId: string,
  label?: string | null,
  note?: string | null
): Promise<EventBookmark[]> {
  return call(
    'add_event_bookmark',
    { request: { case_root: caseRoot, event_id: eventId, label: label ?? null, note: note ?? null } },
    () => mock.addBookmark(eventId, label ?? null, note ?? null)
  );
}

export function removeEventBookmark(caseRoot: string, bookmarkId: string): Promise<EventBookmark[]> {
  return call('remove_event_bookmark', { caseRoot, bookmarkId }, () => mock.removeBookmark(bookmarkId));
}

export function getBookmarkEventPage(
  caseRoot: string,
  limit = 100,
  cursor?: string | null,
  sortBy: EventSortBy = 'event_time_utc',
  sortDir: EventSortDir = 'asc',
  search?: string | null
): Promise<Page<EventRow>> {
  return call(
    'get_bookmark_event_page',
    {
      caseRoot,
      page: {
        limit,
        cursor,
        artifact_type: null,
        user_name: null,
        search: search ?? null,
        sort_by: sortBy,
        sort_dir: sortDir
      }
    },
    () => mock.bookmarkEventPage(limit, cursor, sortBy, sortDir, search ?? null)
  );
}

export function getFindingEventPage(
  caseRoot: string,
  finding: Pick<FindingSummary, 'title' | 'engine' | 'rule_id'>,
  limit = 100,
  cursor?: string | null,
  sortBy: EventSortBy = 'event_time_utc',
  sortDir: EventSortDir = 'asc',
  search?: string | null
): Promise<Page<EventRow>> {
  return call(
    'get_finding_event_page',
    {
      caseRoot,
      queryPage: {
        title: finding.title,
        engine: finding.engine,
        rule_id: finding.rule_id ?? null,
        page: {
          limit,
          cursor,
          artifact_type: null,
          user_name: null,
          search: search ?? null,
          sort_by: sortBy,
          sort_dir: sortDir
        }
      }
    },
    () => {
      const eventIds = mock.findingEventIds(finding);
      const filtered = [...mock.events]
        .filter((event) => eventIds.has(event.event_id) && (!search || eventMatchesSearch(event, search)))
        .sort(compareEventRows(sortBy, sortDir));
      const start = cursor ? Number(cursor) : 0;
      const rows = filtered.slice(start, start + limit);
      const next = start + limit < filtered.length ? String(start + limit) : null;
      return { rows, next_cursor: next };
    }
  );
}

export function getIocMatches(
  caseRoot: string,
  indicators: string[],
  limit = 100
): Promise<IocHit[]> {
  return call(
    'get_ioc_matches',
    { request: { case_root: caseRoot, indicators, limit } },
    () => mock.iocMatches(indicators, limit)
  );
}

export function runIocFindings(
  caseRoot: string,
  indicators: string[],
  limit = 500
): Promise<FindingSummary[]> {
  return call(
    'run_ioc_findings',
    { request: { case_root: caseRoot, indicators, limit } },
    () => mock.findings(100)
  );
}

export function getIocEventPage(
  caseRoot: string,
  ioc: string,
  limit = 100,
  cursor?: string | null,
  sortBy: EventSortBy = 'event_time_utc',
  sortDir: EventSortDir = 'asc',
  search?: string | null
): Promise<Page<EventRow>> {
  return call(
    'get_ioc_event_page',
    {
      caseRoot,
      queryPage: {
        ioc,
        page: {
          limit,
          cursor,
          artifact_type: null,
          user_name: null,
          search: search ?? null,
          sort_by: sortBy,
          sort_dir: sortDir
        }
      }
    },
    () => mock.iocEventPage(ioc, limit, cursor, sortBy, sortDir, search ?? null)
  );
}

export function getDefenderSummary(caseRoot: string, limit = 100): Promise<DefenderSummary[]> {
  return call('get_defender_summary', { caseRoot, limit }, () => mock.defenderSummary(limit));
}

export function getPrefetchSummary(caseRoot: string, limit = 100): Promise<PrefetchSummary[]> {
  return call('get_prefetch_summary', { caseRoot, limit }, () => mock.prefetchSummary(limit));
}

export function getDefenderEventPage(
  caseRoot: string,
  category: string | null,
  limit = 100,
  cursor?: string | null,
  sortBy: EventSortBy = 'event_time_utc',
  sortDir: EventSortDir = 'asc',
  search?: string | null
): Promise<Page<EventRow>> {
  return call(
    'get_defender_event_page',
    {
      caseRoot,
      queryPage: {
        category,
        page: {
          limit,
          cursor,
          artifact_type: null,
          user_name: null,
          search: search ?? null,
          sort_by: sortBy,
          sort_dir: sortDir
        }
      }
    },
    () => mock.defenderEventPage(category, limit, cursor, sortBy, sortDir, search ?? null)
  );
}

function eventMatchesSearch(event: EventRow, search: string): boolean {
  const expression = parseMockSearchExpression(search);
  if (expression) return mockSearchExpressionMatches(event, expression);
  const terms = parseMockSearchTerms(search);
  if (terms.length > 0) {
    return terms.every((term) => {
      const matched = mockSearchTermMatches(event, term);
      return term.negated ? !matched : matched;
    });
  }
  const needle = search.trim().toLowerCase();
  if (!needle) return true;
  return mockEventHaystack(event).includes(needle);
}

function mockEventHaystack(event: EventRow): string {
  return [
    event.event_id,
    event.event_time_utc,
    event.artifact_type,
    event.host,
    event.user_name,
    event.process_name,
    event.file_path,
    event.ip,
    event.url,
    event.hash,
    event.event_code,
    event.channel,
    event.level,
    event.event_action,
    event.severity,
    event.message_short,
    event.source_file_id,
    event.parser_name
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

type MockSearchTerm = {
  field: string | null;
  value: string;
  regex: boolean;
  negated: boolean;
  word?: boolean;
  extension?: boolean;
  comparison?: 'gte' | 'lte';
};

type MockSearchExpressionToken =
  | { kind: 'term'; value: string }
  | { kind: 'and' | 'or' | 'not' | 'lparen' | 'rparen' };

type MockSearchExpression =
  | { kind: 'term'; term: MockSearchTerm }
  | { kind: 'and' | 'or'; nodes: MockSearchExpression[] }
  | { kind: 'not'; node: MockSearchExpression };

function parseMockSearchExpression(search: string): MockSearchExpression | null {
  const tokens = tokenizeMockSearchExpression(search);
  if (tokens.length === 0) return null;
  let pos = 0;
  let termCount = 0;
  let depth = 0;

  function parseOr(): MockSearchExpression | null {
    const first = parseAnd();
    if (!first) return null;
    const nodes = [first];
    while (tokens[pos]?.kind === 'or') {
      pos += 1;
      const next = parseAnd();
      if (!next) return null;
      nodes.push(next);
    }
    return flattenMockSearchExpression('or', nodes);
  }

  function parseAnd(): MockSearchExpression | null {
    const first = parseUnary();
    if (!first) return null;
    const nodes = [first];
    while (tokens[pos]?.kind === 'and' || nextMockTokenStartsUnary(tokens[pos])) {
      if (tokens[pos]?.kind === 'and') pos += 1;
      const next = parseUnary();
      if (!next) return null;
      nodes.push(next);
    }
    return flattenMockSearchExpression('and', nodes);
  }

  function parseUnary(): MockSearchExpression | null {
    if (tokens[pos]?.kind === 'not') {
      pos += 1;
      const node = parseUnary();
      return node ? { kind: 'not', node } : null;
    }
    return parsePrimary();
  }

  function parsePrimary(): MockSearchExpression | null {
    const token = tokens[pos];
    if (!token) return null;
    if (token.kind === 'term') {
      pos += 1;
      termCount += 1;
      if (termCount > 16) return null;
      const term = parseMockSearchToken(token.value);
      return term ? { kind: 'term', term } : null;
    }
    if (token.kind === 'lparen') {
      if (depth >= 8) return null;
      pos += 1;
      depth += 1;
      const expression = parseOr();
      depth -= 1;
      if (!expression || tokens[pos]?.kind !== 'rparen') return null;
      pos += 1;
      return expression;
    }
    return null;
  }

  const expression = parseOr();
  return expression && pos === tokens.length && termCount > 0 ? expression : null;
}

function nextMockTokenStartsUnary(token: MockSearchExpressionToken | undefined): boolean {
  return Boolean(token && (token.kind === 'term' || token.kind === 'not' || token.kind === 'lparen'));
}

function flattenMockSearchExpression(
  kind: 'and' | 'or',
  nodes: MockSearchExpression[]
): MockSearchExpression {
  const flattened = nodes.flatMap((node) => (node.kind === kind ? node.nodes : [node]));
  return flattened.length === 1 ? flattened[0] : { kind, nodes: flattened };
}

function mockSearchExpressionMatches(event: EventRow, expression: MockSearchExpression): boolean {
  if (expression.kind === 'term') {
    const matched = mockSearchTermMatches(event, expression.term);
    return expression.term.negated ? !matched : matched;
  }
  if (expression.kind === 'not') return !mockSearchExpressionMatches(event, expression.node);
  if (expression.kind === 'and') return expression.nodes.every((node) => mockSearchExpressionMatches(event, node));
  return expression.nodes.some((node) => mockSearchExpressionMatches(event, node));
}

function parseMockSearchTerms(search: string): MockSearchTerm[] {
  return tokenizeMockSearch(search)
    .slice(0, 16)
    .map(parseMockSearchToken)
    .filter((term): term is MockSearchTerm => Boolean(term));
}

function parseMockSearchToken(token: string): MockSearchTerm | null {
  let value = token.trim();
  let negated = false;
  if (value.startsWith('-') || value.startsWith('!')) {
    negated = true;
    value = value.slice(1).trim();
  }
  if (!value) return null;
  const colon = value.indexOf(':');
  if (colon > 0) {
    const field = value.slice(0, colon).trim().toLowerCase();
    const raw = value.slice(colon + 1).trim();
    if (isMockTimeAfterField(field) || isMockTimeBeforeField(field)) {
      const parsed = normalizeMockSearchValue(raw);
      return parsed.value
        ? {
            field: 'event_time_utc',
            value: parsed.value,
            regex: false,
            negated,
            comparison: isMockTimeAfterField(field) ? 'gte' : 'lte'
          }
        : null;
    }
    if (field === 're' || field === 'regex') {
      const parsed = normalizeMockSearchValue(raw);
      return parsed.value ? { field: null, value: parsed.value, regex: true, negated } : null;
    }
    if (field === 'word' || field === 'exact' || field === 'token') {
      const parsed = normalizeMockSearchValue(raw);
      return parsed.value ? { field: null, ...parsed, word: !parsed.regex, negated } : null;
    }
    if (field === 'ext' || field === 'extension' || field === 'suffix') {
      const parsed = normalizeMockSearchValue(raw);
      return parsed.value ? { field: null, ...parsed, extension: !parsed.regex, negated } : null;
    }
    if (isMockSearchField(field)) {
      const parsed = normalizeMockSearchValue(raw);
      return parsed.value ? { field, ...parsed, negated } : null;
    }
  }
  const quoted = isQuotedMockSearchValue(value);
  const bare = unquoteMockSearchValue(value).slice(0, 256);
  return bare ? { field: null, value: bare, regex: false, word: quoted, negated } : null;
}

function mockSearchTermMatches(event: EventRow, term: MockSearchTerm): boolean {
  const source = term.field ? mockSearchFieldValue(event, term.field) : mockEventHaystack(event);
  if (term.comparison === 'gte' || term.comparison === 'lte') {
    const left = Date.parse(String(source ?? ''));
    const right = Date.parse(term.value);
    if (Number.isNaN(left) || Number.isNaN(right)) return false;
    return term.comparison === 'gte' ? left >= right : left <= right;
  }
  if (source === undefined) return mockEventHaystack(event).includes(term.value.toLowerCase());
  const haystack = String(source ?? '').toLowerCase();
  const needle = term.value.toLowerCase();
  if (term.regex) {
    try {
      return new RegExp(needle, 'i').test(haystack);
    } catch {
      return false;
    }
  }
  if (term.extension) return mockExtensionMatches(event, term.value);
  if (term.word) return mockWordMatches(haystack, needle);
  if (mockSearchFieldIsExact(term.field)) return haystack === needle;
  return haystack.includes(needle);
}

function mockWordMatches(haystack: string, needle: string): boolean {
  try {
    return new RegExp(`(^|[^A-Za-z0-9_])${escapeMockRegexLiteral(needle)}($|[^A-Za-z0-9_])`, 'i').test(haystack);
  } catch {
    return false;
  }
}

function mockExtensionMatches(event: EventRow, value: string): boolean {
  const extension = value.trim().replace(/^\./, '').toLowerCase();
  if (!extension) return false;
  const haystack = [event.file_path, event.process_name, event.message_short].filter(Boolean).join(' ').toLowerCase();
  try {
    return new RegExp(`\\.${escapeMockRegexLiteral(extension)}($|[^A-Za-z0-9_])`, 'i').test(haystack);
  } catch {
    return false;
  }
}

function escapeMockRegexLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function mockSearchFieldValue(event: EventRow, field: string): string | boolean | undefined {
  switch (field) {
    case 'id':
    case 'event':
    case 'event_id':
      return event.event_id;
    case 'time':
    case 'ts':
    case 'event_time':
    case 'event_time_utc':
      return event.event_time_utc;
    case 'type':
    case 'artifact':
    case 'artifact_type':
      return event.artifact_type;
    case 'host':
    case 'hostname':
      return event.host ?? '';
    case 'user':
    case 'username':
    case 'user_name':
      return event.user_name ?? '';
    case 'process':
    case 'proc':
    case 'process_name':
    case 'exe':
      return event.process_name ?? '';
    case 'file':
    case 'path':
    case 'file_path':
      return event.file_path ?? '';
    case 'ip':
      return event.ip ?? '';
    case 'url':
      return event.url ?? '';
    case 'hash':
      return event.hash ?? '';
    case 'eid':
    case 'eventid':
    case 'event_id_code':
    case 'event_code':
      return event.event_code ?? '';
    case 'channel':
      return event.channel ?? '';
    case 'level':
      return event.level ?? '';
    case 'action':
    case 'event_action':
      return event.event_action;
    case 'severity':
    case 'sev':
      return event.severity;
    case 'message':
    case 'msg':
    case 'message_short':
      return event.message_short;
    case 'parser':
    case 'parser_name':
      return event.parser_name;
    case 'source':
    case 'source_file':
    case 'source_file_id':
      return event.source_file_id;
    case 'finding':
    case 'has_finding':
      return event.has_finding ? 'true' : 'false';
    default:
      return undefined;
  }
}

function isMockTimeAfterField(field: string): boolean {
  return ['after', 'since', 'from', 'start', 'start_utc', 'time_after'].includes(field);
}

function isMockTimeBeforeField(field: string): boolean {
  return ['before', 'until', 'to', 'end', 'end_utc', 'time_before'].includes(field);
}

function isMockSearchField(field: string): boolean {
  return [
    'id',
    'event',
    'event_id',
    'time',
    'ts',
    'event_time',
    'event_time_utc',
    'type',
    'artifact',
    'artifact_type',
    'host',
    'hostname',
    'user',
    'username',
    'user_name',
    'process',
    'proc',
    'process_name',
    'exe',
    'file',
    'path',
    'file_path',
    'ip',
    'url',
    'hash',
    'eid',
    'eventid',
    'event_id_code',
    'event_code',
    'channel',
    'level',
    'action',
    'event_action',
    'severity',
    'sev',
    'message',
    'msg',
    'message_short',
    'parser',
    'parser_name',
    'source',
    'source_file',
    'source_file_id',
    'finding',
    'has_finding'
  ].includes(field);
}

function mockSearchFieldIsExact(field: string | null): boolean {
  return Boolean(
    field &&
      [
        'type',
        'artifact',
        'artifact_type',
        'hash',
        'eid',
        'eventid',
        'event_id_code',
        'event_code',
        'action',
        'event_action',
        'severity',
        'sev',
        'parser',
        'parser_name',
        'finding',
        'has_finding'
      ].includes(field)
  );
}

function tokenizeMockSearch(search: string): string[] {
  const out: string[] = [];
  let current = '';
  let quote: string | null = null;
  let inRegex = false;
  let escaped = false;
  for (const char of search) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if ((quote || inRegex) && char === '\\') {
      current += char;
      escaped = true;
      continue;
    }
    if (quote) {
      current += char;
      if (char === quote) quote = null;
      continue;
    }
    if (inRegex) {
      current += char;
      if (char === '/') inRegex = false;
      continue;
    }
    if (char === '"' || char === "'") {
      current += char;
      quote = char;
      continue;
    }
    if (char === '/' && currentIsMockFieldPrefix(current)) {
      current += char;
      inRegex = true;
      continue;
    }
    if (/\s/.test(char)) {
      if (current.trim()) out.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

function tokenizeMockSearchExpression(search: string): MockSearchExpressionToken[] {
  const out: MockSearchExpressionToken[] = [];
  let current = '';
  let quote: string | null = null;
  let inRegex = false;
  let escaped = false;
  for (const char of search) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if ((quote || inRegex) && char === '\\') {
      current += char;
      escaped = true;
      continue;
    }
    if (quote) {
      current += char;
      if (char === quote) quote = null;
      continue;
    }
    if (inRegex) {
      current += char;
      if (char === '/') inRegex = false;
      continue;
    }
    if (char === '"' || char === "'") {
      current += char;
      quote = char;
      continue;
    }
    if (char === '/' && currentIsMockFieldPrefix(current)) {
      current += char;
      inRegex = true;
      continue;
    }
    if (char === '(' || char === ')') {
      pushMockSearchExpressionToken(out, current);
      current = '';
      out.push({ kind: char === '(' ? 'lparen' : 'rparen' });
      if (out.length >= 96) break;
      continue;
    }
    if (/\s/.test(char)) {
      pushMockSearchExpressionToken(out, current);
      current = '';
      if (out.length >= 96) break;
    } else {
      current += char;
    }
  }
  pushMockSearchExpressionToken(out, current);
  return out.slice(0, 96);
}

function pushMockSearchExpressionToken(out: MockSearchExpressionToken[], raw: string): void {
  const token = raw.trim();
  if (!token) return;
  const upper = token.toUpperCase();
  if (upper === 'AND') out.push({ kind: 'and' });
  else if (upper === 'OR') out.push({ kind: 'or' });
  else if (upper === 'NOT') out.push({ kind: 'not' });
  else out.push({ kind: 'term', value: token });
}

function currentIsMockFieldPrefix(value: string): boolean {
  const colon = value.indexOf(':');
  return colon > 0 && colon + 1 === value.length;
}

function normalizeMockSearchValue(value: string): { value: string; regex: boolean } {
  const regex = regexDelimitedMockValue(value);
  if (regex !== null) return { value: regex.slice(0, 256), regex: true };
  return { value: unquoteMockSearchValue(value).slice(0, 256), regex: false };
}

function regexDelimitedMockValue(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed.startsWith('/')) return null;
  let escaped = false;
  for (let index = 1; index < trimmed.length; index += 1) {
    const char = trimmed[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '/') {
      const trailing = trimmed.slice(index + 1).trim();
      if (!trailing || trailing === 'i') return trimmed.slice(1, index).replaceAll('\\/', '/');
      return null;
    }
  }
  return null;
}

function unquoteMockSearchValue(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return trimmed.slice(1, -1).replaceAll('\\"', '"').replaceAll("\\'", "'");
    }
  }
  return trimmed;
}

function isQuotedMockSearchValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 2) return false;
  const first = trimmed[0];
  const last = trimmed[trimmed.length - 1];
  return (first === '"' && last === '"') || (first === "'" && last === "'");
}

function normalizeMockVisibility(value: string | null | undefined): string {
  const normalized = (value ?? 'case').trim().toLowerCase();
  if (normalized === 'private') return 'private';
  if (normalized === 'restricted' || normalized === 'shared') return 'restricted';
  return 'case';
}

function normalizeMockPrincipal(value: string | null | undefined): string | null {
  const normalized = (value ?? '').trim().toLowerCase();
  return normalized || null;
}

function normalizeMockSharedWith(values: string[] | null | undefined): string[] {
  return [...new Set((values ?? []).map(normalizeMockPrincipal).filter((value): value is string => Boolean(value)))]
    .sort()
    .slice(0, 50);
}

function mockSavedSearchVisibleTo(row: SavedSearch, viewer: string | null): boolean {
  if (!viewer) return true;
  const owner = normalizeMockPrincipal(row.created_by);
  if (owner && owner === viewer) return true;
  if (row.visibility === 'private') return false;
  if (row.visibility === 'restricted') {
    return (row.shared_with ?? []).some((principal) => normalizeMockPrincipal(principal) === viewer);
  }
  return true;
}

function filteredMockEvents(source: EventRow[], filters: EventPageFilters): EventRow[] {
  return [...source]
    .filter((event) => {
      if (filters.artifactType && event.artifact_type !== filters.artifactType) return false;
      if (filters.userName && event.user_name !== filters.userName) return false;
      if (filters.search && !eventMatchesSearch(event, filters.search)) return false;
      return true;
    })
    .sort(compareEventRows(filters.sortBy ?? 'event_time_utc', filters.sortDir ?? 'asc'));
}

function eventMatchesIoc(event: EventRow, ioc: string): boolean {
  const needle = ioc.trim().toLowerCase();
  if (!needle) return false;
  if ((event.hash ?? '').toLowerCase() === needle) return true;
  if ((event.ip ?? '').toLowerCase() === needle) return true;
  if ((event.process_name ?? '').toLowerCase() === needle) return true;
  return eventMatchesSearch(event, needle);
}

function eventIsDefender(event: EventRow): boolean {
  return (
    event.artifact_type === 'defender' ||
    (event.channel ?? '').toLowerCase().includes('defender') ||
    event.event_action.toLowerCase().startsWith('defender_') ||
    event.message_short.toLowerCase().includes('microsoft defender') ||
    event.message_short.toLowerCase().includes('windows defender')
  );
}

function mockIocMatchKind(events: EventRow[], ioc: string): string {
  const needle = ioc.trim().toLowerCase();
  if (events.some((event) => (event.hash ?? '').toLowerCase() === needle)) return 'hash';
  if (events.some((event) => (event.ip ?? '').toLowerCase() === needle)) return 'ip';
  if (events.some((event) => (event.process_name ?? '').toLowerCase() === needle)) return 'process';
  return 'text';
}

function mockChainKey(event: EventRow, keyKind: string): string | null {
  if (keyKind === 'file_basename') {
    const value = event.file_path ?? event.process_name;
    return value ? value.split(/[\\/]/).pop()?.toLowerCase() ?? null : null;
  }
  if (keyKind === 'ip') return event.ip ?? null;
  if (keyKind === 'hash') return event.hash?.toLowerCase() ?? null;
  if (keyKind === 'url') return event.url?.toLowerCase() ?? null;
  if (keyKind === 'user_name') return event.user_name?.toLowerCase() ?? null;
  return null;
}

function mockPrimaryChainKey(event: EventRow): { kind: string; value: string } | null {
  for (const kind of ['file_basename', 'ip', 'hash', 'url', 'user_name']) {
    const value = mockChainKey(event, kind);
    if (value && value !== '-') return { kind, value };
  }
  return null;
}

function semanticChain(
  keyKind: string,
  artifactTypes: Set<string>,
  events: EventRow[]
): { title: string; severity: string; score: number; explanation: string } {
  const hasExecution = events.some(
    (event) =>
      event.artifact_type === 'prefetch' ||
      event.artifact_type === 'amcache' ||
      event.event_action === 'process_created' ||
      event.event_action === 'process_exited'
  );
  const hasBrowser = artifactTypes.has('browser');
  const hasMft = artifactTypes.has('mft') || events.some((event) => event.event_action.startsWith('mft_'));
  const hasUsn = artifactTypes.has('usn_jrnl') || events.some((event) => event.event_action.startsWith('usn_'));
  const hasDeleted = events.some((event) => /delete|removed/i.test(event.event_action));
  const baseScore =
    artifactTypes.size * 30 +
    Math.min(events.length, 20) +
    (hasExecution ? 10 : 0) +
    (hasBrowser ? 15 : 0) +
    (hasUsn ? 20 : 0) +
    (hasDeleted ? 20 : 0);

  if (keyKind === 'file_basename' && hasBrowser && hasExecution) {
    return {
      title: 'ダウンロードされたファイルが実行された',
      severity: 'critical',
      score: baseScore,
      explanation: 'ダウンロード痕跡と実行痕跡が同一ファイル名で連結'
    };
  }
  if (keyKind === 'file_basename' && hasExecution && (hasUsn || hasDeleted)) {
    return {
      title: '実行後に削除/変更された痕跡',
      severity: 'critical',
      score: baseScore,
      explanation: '実行痕跡と削除/変更痕跡が同一ファイル名で連結'
    };
  }
  if (keyKind === 'file_basename' && hasExecution && hasMft) {
    return {
      title: '作成され実行されたファイル',
      severity: 'medium',
      score: baseScore,
      explanation: 'ファイルシステム痕跡と実行痕跡が同一ファイル名で連結'
    };
  }
  if (keyKind === 'file_basename' && artifactTypes.size >= 2) {
    return {
      title: '複数アーティファクトに跨るファイル活動',
      severity: artifactTypes.size >= 3 ? 'high' : 'low',
      score: baseScore,
      explanation: '複数アーティファクトにまたがる活動チェーン'
    };
  }
  if (keyKind === 'hash') return { title: '同一ハッシュの横断出現', severity: 'medium', score: baseScore, explanation: '同一キーの反復活動チェーン' };
  if (keyKind === 'url') return { title: '同一URLの横断出現', severity: 'medium', score: baseScore, explanation: '同一キーの反復活動チェーン' };
  if (keyKind === 'ip') return { title: '同一IPの横断出現', severity: 'low', score: baseScore, explanation: '同一キーの反復活動チェーン' };
  if (keyKind === 'user_name') return { title: '同一ユーザーの反復活動', severity: 'low', score: baseScore, explanation: '同一キーの反復活動チェーン' };
  return { title: '同一キーの反復活動チェーン', severity: 'low', score: baseScore, explanation: '同一キーの反復活動チェーン' };
}

function mockChainRuleId(chain: CorrelationChainSummary): string {
  if (chain.title.includes('ダウンロード') && chain.title.includes('実行')) {
    return 'chain-download-execute';
  }
  if (chain.title.includes('削除') || chain.title.includes('変更')) {
    return 'chain-execute-delete-or-change';
  }
  if (chain.title.includes('作成され実行')) {
    return 'chain-created-executed';
  }
  if (chain.key_kind === 'hash') return 'chain-hash-cross-artifact';
  if (chain.key_kind === 'url') return 'chain-url-cross-artifact';
  return 'chain-cross-artifact-activity';
}

function mockChainAttackTechniques(ruleId: string): string[] {
  if (ruleId === 'chain-download-execute') return ['T1105', 'T1204'];
  if (ruleId === 'chain-execute-delete-or-change') return ['T1070.004', 'T1204'];
  if (ruleId === 'chain-created-executed') return ['T1204'];
  if (ruleId === 'chain-hash-cross-artifact' || ruleId === 'chain-url-cross-artifact') return ['T1105'];
  return ['T1204'];
}

function mockChainEventIds(chain: CorrelationChainSummary): string[] {
  try {
    const parsed = JSON.parse(chain.steps_json) as unknown;
    if (!Array.isArray(parsed)) return [];
    const seen = new Set<string>();
    const out: string[] = [];
    for (const item of parsed) {
      const eventId =
        typeof item === 'string'
          ? item
          : item && typeof item === 'object' && 'event_id' in item
            ? String((item as { event_id?: unknown }).event_id ?? '')
            : '';
      if (eventId && !seen.has(eventId)) {
        seen.add(eventId);
        out.push(eventId);
      }
    }
    return out;
  } catch {
    return [];
  }
}

function parseJsonStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

function applyMockFindingOverrides(rows: FindingSummary[], overrides: FindingOverride[]): FindingSummary[] {
  const active = overrides.filter((row) => row.enabled);
  if (active.length === 0) return rows;
  const out: FindingSummary[] = [];
  findings: for (const row of rows) {
    const next = { ...row };
    for (const override of active) {
      if (!mockFindingOverrideMatches(override, row)) continue;
      if (override.action === 'suppress') continue findings;
      if (override.action === 'severity_override' && override.severity) {
        next.severity = override.severity;
      }
    }
    out.push(next);
  }
  return out;
}

function mockFindingOverrideMatches(override: FindingOverride, finding: FindingSummary): boolean {
  if (override.engine && override.engine !== finding.engine) return false;
  if (override.rule_id && override.rule_id !== (finding.rule_id ?? null)) return false;
  if (override.title && override.title !== finding.title) return false;
  return true;
}

function sameMockFindingOverride(left: FindingOverride, right: FindingOverride): boolean {
  return (
    left.enabled === right.enabled &&
    left.action === right.action &&
    (left.engine ?? null) === (right.engine ?? null) &&
    (left.rule_id ?? null) === (right.rule_id ?? null) &&
    (left.title ?? null) === (right.title ?? null) &&
    (left.severity ?? null) === (right.severity ?? null)
  );
}

function sameMockFindingReview(
  left: FindingReview,
  finding: Pick<FindingSummary, 'title' | 'engine' | 'rule_id'>
): boolean {
  return left.engine === finding.engine && (left.rule_id ?? null) === (finding.rule_id ?? null) && left.title === finding.title;
}

function mockReviewTags(tagsJson: string | null | undefined): string[] {
  if (!tagsJson) return [];
  try {
    const parsed = JSON.parse(tagsJson);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((tag) => String(tag).trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function mockTriageId(category: string, sourceKey: string): string {
  let hash = 2166136261;
  const input = `${category}\0${sourceKey}`;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `triage_${(hash >>> 0).toString(16).padStart(8, '0')}`;
}

function mockFindingSourceKey(finding: Pick<FindingSummary, 'title' | 'engine' | 'rule_id'>): string {
  return `${finding.engine}:${finding.rule_id ?? '-'}:${finding.title}`;
}

export function getRiskSummary(caseRoot: string, limit = 100): Promise<RiskSummary[]> {
  return call('get_risk_summary', { caseRoot, limit }, () => mock.risk(limit));
}

export function getAnalyzerRuns(caseRoot: string, limit = 100): Promise<AnalyzerRunSummary[]> {
  return call('get_analyzer_runs', { caseRoot, limit }, () => mock.analyzerRuns.slice(0, limit));
}

export function getEntitySummary(caseRoot: string, limit = 100): Promise<EntityRecord[]> {
  return call('get_entity_summary', { caseRoot, limit }, () => mock.entities(limit));
}

export function getSubgraph(
  caseRoot: string,
  entityId: string,
  hops = 1,
  edgeLimit = 200
): Promise<Subgraph> {
  return call('get_subgraph', { caseRoot, entityId, hops, edgeLimit }, () => mock.subgraph(entityId, edgeLimit));
}

export function getCorrelationSummary(caseRoot: string, limit = 100): Promise<CorrelationSummary[]> {
  return call('get_correlation_summary', { caseRoot, limit }, () => mock.correlations(limit));
}

export function getCorrelationChains(caseRoot: string, limit = 100): Promise<CorrelationChainSummary[]> {
  return call('get_correlation_chains', { caseRoot, limit }, () => mock.correlationChains(limit));
}

export function rebuildCorrelationReadModel(caseRoot: string, limit = 500): Promise<CorrelationChainSummary[]> {
  return call('rebuild_correlation_read_model', { caseRoot, limit }, () => mock.correlationChains(limit));
}

export function generateCaseReport(caseRoot: string, outputPath?: string | null): Promise<string> {
  return call(
    'generate_case_report',
    { caseRoot, outputPath: outputPath ?? null },
    () => '/tmp/taotie-mock-report.md'
  );
}

export function generateCustodyManifest(caseRoot: string, outputPath?: string | null): Promise<string> {
  return call(
    'generate_custody_manifest',
    { caseRoot, outputPath: outputPath ?? null },
    () => '/tmp/taotie-custody-manifest.json'
  );
}

export function generateReportBundle(caseRoot: string, outputPath?: string | null): Promise<string> {
  return call(
    'generate_report_bundle',
    { caseRoot, outputPath: outputPath ?? null },
    () => '/tmp/taotie-report-bundle.json'
  );
}

export function verifyReportBundle(caseRoot: string, bundlePath: string): Promise<ReportBundleVerification> {
  return call(
    'verify_report_bundle',
    { request: { case_root: caseRoot, bundle_path: bundlePath } },
    () => mock.verifyReportBundle(bundlePath)
  );
}

export function verifyCustodyManifest(
  caseRoot: string,
  manifestPath: string,
  evidenceLimit = 500
): Promise<CustodyManifestVerification> {
  return call(
    'verify_custody_manifest',
    { request: { case_root: caseRoot, manifest_path: manifestPath, evidence_limit: evidenceLimit } },
    () => mock.verifyCustodyManifest(manifestPath)
  );
}

export function getCorrelationChainEventPage(
  caseRoot: string,
  chain: Pick<CorrelationChainSummary, 'key_kind' | 'key_value'>,
  limit = 100,
  cursor?: string | null,
  sortBy: EventSortBy = 'event_time_utc',
  sortDir: EventSortDir = 'asc',
  search?: string | null
): Promise<Page<EventRow>> {
  return call(
    'get_correlation_chain_event_page',
    {
      caseRoot,
      queryPage: {
        key_kind: chain.key_kind,
        key_value: chain.key_value,
        page: {
          limit,
          cursor,
          artifact_type: null,
          user_name: null,
          search: search ?? null,
          sort_by: sortBy,
          sort_dir: sortDir
        }
      }
    },
    () => {
      const filtered = [...mock.events]
        .filter((event) => mockChainKey(event, chain.key_kind) === chain.key_value)
        .filter((event) => !search || eventMatchesSearch(event, search))
        .sort(compareEventRows(sortBy, sortDir));
      const start = cursor ? Number(cursor) : 0;
      const rows = filtered.slice(start, start + limit);
      const next = start + limit < filtered.length ? String(start + limit) : null;
      return { rows, next_cursor: next };
    }
  );
}

export function getUserActivitySummary(
  caseRoot: string,
  limit = 100
): Promise<UserActivitySummary[]> {
  return call('get_user_activity_summary', { caseRoot, limit }, () => mock.users(limit));
}

export function getRecentJobs(caseRoot: string, limit = 100): Promise<JobRecord[]> {
  return call('get_recent_jobs', { caseRoot, limit }, () => mock.jobs.slice(0, limit));
}

function createMockState() {
  const events: EventRow[] = [];
  const details = new Map<string, EventDetailLight>();
  const raw = new Map<string, RawRecord>();
  const files: FileRecord[] = [];
  const coverage: CoverageSummary[] = [];
  const timeline: TimelineBin[] = [];
  const jobs: JobRecord[] = [];
  const analyzerRuns: AnalyzerRunSummary[] = [];
  const findingOverrides: FindingOverride[] = [];
  const findingReviews: FindingReview[] = [];
  const caseApprovals: CaseApprovalRecord[] = [];
  const auditLog: AuditLogEntry[] = [];
  const bookmarks: EventBookmark[] = [];
  const savedSearches: SavedSearch[] = [];
  let currentCase: CaseSummary | null = null;
  let custodyProfile: CaseCustodyProfile | null = null;
  let searchIndexMetadata: SearchIndexMetadata | null = null;

  function rebuildReadModels() {
    const groupedCoverage = new Map<string, CoverageSummary>();
    for (const file of files) {
      const row =
        groupedCoverage.get(file.artifact_type) ??
        {
          case_id: 'case_mock',
          artifact_type: file.artifact_type,
          total_files: 0,
          parsed_files: 0,
          failed_files: 0,
          unsupported_files: 0,
          event_count: 0
        };
      row.total_files += 1;
      row.parsed_files += file.parser_status === 'parsed' ? 1 : 0;
      row.failed_files += file.parser_status === 'failed' ? 1 : 0;
      row.unsupported_files += file.parser_status === 'unsupported' ? 1 : 0;
      row.event_count += file.event_count;
      groupedCoverage.set(file.artifact_type, row);
    }
    coverage.splice(0, coverage.length, ...Array.from(groupedCoverage.values()));

    const groupedTimeline = new Map<string, TimelineBin>();
    for (const event of events) {
      const bin = event.event_time_utc.slice(0, 13) + ':00:00.000Z';
      const key = `${bin}|${event.artifact_type}`;
      const row =
        groupedTimeline.get(key) ??
        {
          case_id: 'case_mock',
          granularity: 'hour',
          bin_start_utc: bin,
          artifact_type: event.artifact_type,
          event_count: 0,
          severity_max: 'info'
        };
      row.event_count += 1;
      row.severity_max = maxSeverity(row.severity_max ?? 'info', event.severity);
      groupedTimeline.set(key, row);
    }
    timeline.splice(
      0,
      timeline.length,
      ...Array.from(groupedTimeline.values()).sort((left, right) =>
        left.bin_start_utc.localeCompare(right.bin_start_utc)
      )
    );
  }

  return {
    get case() {
      return currentCase;
    },
    set case(value: CaseSummary | null) {
      currentCase = value;
    },
    events,
    details,
    raw,
    files,
    coverage,
    timeline,
    jobs,
    analyzerRuns,
    findingOverrides,
    findingReviews,
    caseApprovals,
    auditLog,
    bookmarks,
    savedSearches,
    rebuildAnalysisReadModels(caseRoot: string): CaseSummary {
      rebuildReadModels();
      return this.summary(caseRoot);
    },
    get searchIndexMetadata() {
      return searchIndexMetadata;
    },
    get searchIndexStatus(): SearchIndexStatus {
      const activeJob =
        jobs.find(
          (job) =>
            job.kind === 'build_tantivy_index' &&
            (job.status === 'queued' || job.status === 'running')
        ) ?? null;
      return {
        metadata: searchIndexMetadata,
        current_event_count: events.length,
        is_stale: searchIndexMetadata
          ? searchIndexMetadata.indexed_event_count !== events.length
          : events.length > 0,
        active_job: activeJob
      };
    },
    caseCustodyProfile(): CaseCustodyProfile {
      const summary = this.summary(currentCase?.root_path ?? '/tmp/taotie-demo-case');
      custodyProfile ??= {
        case_id: summary.case_id,
        investigator: null,
        custodian: null,
        organization: null,
        evidence_source: null,
        acquisition_method: null,
        acquired_at: null,
        legal_authority: null,
        chain_of_custody_note: null,
        updated_at: summary.created_at
      };
      return { ...custodyProfile, case_id: summary.case_id };
    },
    setCaseCustodyProfile(profile: Omit<CaseCustodyProfile, 'case_id' | 'updated_at'>): CaseCustodyProfile {
      const now = new Date().toISOString();
      const summary = this.summary(currentCase?.root_path ?? '/tmp/taotie-demo-case');
      custodyProfile = {
        case_id: summary.case_id,
        investigator: profile.investigator?.trim() || null,
        custodian: profile.custodian?.trim() || null,
        organization: profile.organization?.trim() || null,
        evidence_source: profile.evidence_source?.trim() || null,
        acquisition_method: profile.acquisition_method?.trim() || null,
        acquired_at: profile.acquired_at?.trim() || null,
        legal_authority: profile.legal_authority?.trim() || null,
        chain_of_custody_note: profile.chain_of_custody_note?.trim() || null,
        updated_at: now
      };
      auditLog.unshift({
        audit_id: `audit_${auditLog.length + 1}`,
        case_id: summary.case_id,
        occurred_at: now,
        actor: 'local_analyst',
        action: 'case_custody_profile_updated',
        target_kind: 'case',
        target_id: summary.case_id,
        summary: 'case custody profile updated',
        metadata_json: JSON.stringify({ source: 'mock' })
      });
      return custodyProfile;
    },
    summary(caseRoot: string): CaseSummary {
      currentCase ??= {
        case_id: 'case_mock',
        name: 'demo',
        root_path: caseRoot,
        created_at: new Date().toISOString(),
        schema_version: 'taotie-lite-v1',
        file_count: files.length,
        event_count: events.length,
        failed_parse_count: 0,
        unsupported_file_count: coverage.reduce((sum, row) => sum + row.unsupported_files, 0)
      };
      return {
        ...currentCase,
        root_path: caseRoot,
        file_count: files.length,
        event_count: events.length,
        unsupported_file_count: files.filter((item) => item.parser_status === 'unsupported').length
      };
    },
    evidenceRange(objectRef: string, offset: number, length: number): EvidenceRange {
      const text = `mock evidence ${objectRef}\n`;
      const repeated = text.repeat(Math.max(1, Math.ceil((offset + length) / text.length)));
      const bytes = new TextEncoder().encode(repeated).slice(offset, offset + length);
      return {
        object_ref: objectRef,
        sha256: objectRef.replace('raw://sha256/', '') || 'mock',
        offset,
        length: bytes.length,
        total_size: repeated.length,
        hex_dump: formatHexDump(offset, bytes),
        ascii_preview: asciiPreview(bytes),
        truncated: offset + bytes.length < repeated.length
      };
    },
    artifactObjects(eventId: string): ArtifactObject[] {
      const detail = details.get(eventId);
      if (!detail) return [];
      const attrs = parseMockAttributes(detail.attributes_json);
      const rows: ArtifactObject[] = [];
      const offset = numericMockAttr(attrs.record_offset ?? attrs.offset);
      const length = numericMockAttr(attrs.record_size ?? attrs.record_length ?? attrs.length);
      const push = (objectKind: string, key: string, display: string, confidence: number) => {
        if (!key || !display) return;
        rows.push({
          object_id: `aobj_${eventId}_${rows.length + 1}`,
          case_id: detail.case_id,
          event_id: eventId,
          source_file_id: detail.source_file_id,
          parse_run_id: detail.parse_run_id,
          artifact_type: detail.artifact_type,
          object_kind: objectKind,
          object_key: key,
          display_name: display,
          event_time_utc: detail.event_time_utc,
          evidence_ref: detail.evidence_ref,
          evidence_offset: offset,
          evidence_length: length,
          confidence,
          attributes_json: detail.attributes_json
        });
      };
      const subject = detail.file_path ?? detail.process_name ?? detail.ip ?? detail.url ?? detail.user_name ?? '';
      if (detail.artifact_type === 'mft' && attrs.record_number != null) {
        push('ntfs_file_record', `mft:${attrs.record_number}:${attrs.sequence_number ?? '-'}`, subject || `MFT ${attrs.record_number}`, 0.95);
      } else if (detail.artifact_type === 'usn_jrnl' && (attrs.usn != null || offset != null)) {
        push('usn_record', attrs.usn != null ? `usn:${attrs.usn}` : `usn_offset:${offset}`, subject || `USN ${attrs.usn ?? offset}`, 0.95);
      } else if (subject) {
        push(`${detail.artifact_type}_reference`, `${detail.artifact_type}:${subject.toLowerCase()}`, subject, 0.6);
      }
      return rows;
    },
    evidenceOffsets(eventId: string): EvidenceOffset[] {
      const detail = details.get(eventId);
      if (!detail) return [];
      const attrs = parseMockAttributes(detail.attributes_json);
      const offset = numericMockAttr(attrs.record_offset ?? attrs.offset);
      if (offset == null) return [];
      const length = numericMockAttr(attrs.record_size ?? attrs.record_length ?? attrs.length) ?? 4096;
      const kind = detail.artifact_type === 'mft' ? 'mft_record' : detail.artifact_type === 'usn_jrnl' ? 'usn_record' : 'artifact_structure';
      return [
        {
          offset_id: `evoff_${eventId}_1`,
          case_id: detail.case_id,
          event_id: eventId,
          source_file_id: detail.source_file_id,
          parse_run_id: detail.parse_run_id,
          object_ref: detail.evidence_ref,
          label: attrs.record_number != null ? `MFT record ${attrs.record_number}` : `${kind} offset ${offset}`,
          structure_kind: kind,
          offset,
          length,
          parser_name: detail.parser_name,
          confidence: 0.9,
          attributes_json: detail.attributes_json
        }
      ];
    },
    verifyEvidencePage(limit: number, cursor: string | null | undefined): Page<EvidenceVerification> {
      const start = cursor ? Number(cursor) : 0;
      const rows = files.slice(start, start + limit).map((file) => ({
        file_id: file.file_id,
        original_path: file.original_path,
        object_ref: file.object_ref,
        expected_sha256: file.sha256,
        actual_sha256: file.sha256,
        size: file.size,
        verified: true,
        error_message: null,
        checked_at: new Date().toISOString()
      }));
      const next = start + limit < files.length ? String(start + limit) : null;
      auditLog.unshift({
        audit_id: `audit_${auditLog.length + 1}`,
        case_id: 'case_mock',
        occurred_at: new Date().toISOString(),
        actor: 'local_analyst',
        action: 'evidence_verified',
        target_kind: 'evidence_page',
        target_id: null,
        summary: `evidence verification completed: ${rows.length}/${rows.length} verified`,
        metadata_json: JSON.stringify({ source: 'mock', checked_count: rows.length })
      });
      return { rows, next_cursor: next };
    },
    verifyCustodyManifest(manifestPath: string): CustodyManifestVerification {
      const now = new Date().toISOString();
      auditLog.unshift({
        audit_id: `audit_${auditLog.length + 1}`,
        case_id: 'case_mock',
        occurred_at: now,
        actor: 'local_analyst',
        action: 'custody_manifest_verified',
        target_kind: 'report',
        target_id: manifestPath,
        summary: 'custody manifest verified: manifest_hash_ok=true, evidence_mismatch=0',
        metadata_json: JSON.stringify({ source: 'mock' })
      });
      return {
        manifest_path: manifestPath,
        manifest_sha256: 'mock',
        computed_manifest_sha256: 'mock',
        manifest_hash_ok: true,
        manifest_type_ok: true,
        case_id_matches: true,
        evidence_file_count: files.length,
        evidence_hash_checked_count: files.length,
        evidence_hash_mismatch_count: 0,
        audit_log_sha256_at_generation: 'mock-before',
        current_audit_log_sha256: 'mock-after',
        audit_log_unchanged: false,
        checked_at: now,
        error_message: null
      };
    },
    verifyReportBundle(bundlePath: string): ReportBundleVerification {
      const now = new Date().toISOString();
      auditLog.unshift({
        audit_id: `audit_${auditLog.length + 1}`,
        case_id: 'case_mock',
        occurred_at: now,
        actor: 'local_analyst',
        action: 'report_bundle_verified',
        target_kind: 'report',
        target_id: bundlePath,
        summary: 'report bundle verified: bundle_hash_ok=true, report_hash_ok=true, custody_hash_ok=true',
        metadata_json: JSON.stringify({ source: 'mock' })
      });
      return {
        bundle_path: bundlePath,
        bundle_sha256: 'mock',
        computed_bundle_sha256: 'mock',
        bundle_hash_ok: true,
        bundle_type_ok: true,
        case_id_matches: true,
        report_path: '/tmp/taotie-mock-report.md',
        report_sha256_at_generation: 'mock-report',
        current_report_sha256: 'mock-report',
        report_hash_ok: true,
        custody_manifest_path: '/tmp/taotie-custody-manifest.json',
        custody_manifest_sha256_at_generation: 'mock-custody',
        current_custody_manifest_sha256: 'mock-custody',
        custody_manifest_hash_ok: true,
        custody_manifest_internal_hash_ok: true,
        custody_manifest_type_ok: true,
        case_custody_profile_sha256_at_generation: 'mock-profile',
        current_case_custody_profile_sha256: 'mock-profile',
        case_custody_profile_hash_ok: true,
        signature_algorithm: 'ed25519',
        signature_key_id: 'ed25519:mock',
        signature_present: true,
        signature_payload_hash_ok: true,
        signature_valid: true,
        signature_key_matches_case_key: true,
        audit_log_sha256_at_generation: 'mock-audit',
        current_audit_log_sha256: 'mock-audit',
        audit_log_unchanged: true,
        checked_at: now,
        error_message: null
      };
    },
    ingest(
      caseRoot: string,
      originalPath: string,
      content: string,
      upload = false,
      sizeHint?: number
    ): CaseSummary {
      const fileId = `file_${files.length + 1}`;
      const parsed = parseMockArtifact(originalPath, content, upload);
      const artifactType = parsed[0]?.artifactType ?? detectMockArtifactType(originalPath, content);
      const isSupported = parsed.length > 0;
      const file: FileRecord = {
        file_id: fileId,
        case_id: 'case_mock',
        parent_file_id: null,
        original_path: originalPath,
        normalized_path: originalPath.replaceAll('\\', '/'),
        filename: originalPath.split(/[\\/]/).pop() ?? originalPath,
        extension: originalPath.split('.').pop()?.toLowerCase() ?? '',
        size: sizeHint ?? content.length,
        sha256: 'mock-sha256',
        artifact_type: artifactType,
        parser_status: isSupported ? 'parsed' : 'unsupported',
        event_count: parsed.length,
        object_ref: 'raw://sha256/mock'
      };
      files.push(file);

      if (parsed.length > 0) {
        for (const record of parsed) {
          const id = `event_${events.length + 1}`;
          const event: EventRow = {
            event_id: id,
            case_id: 'case_mock',
            event_time_utc: record.time,
            artifact_type: record.artifactType,
            host: record.host,
            user_name: record.userName,
            process_name: record.processName,
            file_path: record.filePath ?? originalPath,
            ip: record.ip,
            url: record.url,
            hash: record.hash,
            event_code: record.eventCode,
            channel: record.channel,
            level: record.level,
            event_action: record.action,
            severity: record.severity,
            message_short: record.message.slice(0, 120),
            source_file_id: fileId,
            parser_name: upload ? 'structured_artifact_parser' : 'fake_text_parser',
            has_finding: mockHasFinding(record)
          };
          events.push(event);
          details.set(id, {
            ...event,
            event_time_original: event.event_time_utc,
            time_kind: 'textlog_line_timestamp',
            time_confidence: record.timeConfidence,
            source_confidence: 0.85,
            parse_run_id: 'parse_mock',
            parser_version: '0.1.0',
            schema_version: 'taotie-lite-v1',
            evidence_ref: file.object_ref,
            process_name: record.processName,
            file_path: record.filePath ?? originalPath,
            ip: record.ip,
            url: record.url,
            hash: record.hash,
            message_full: record.message,
            raw_record_ref: `rawrec_${id}`,
            attributes_json: JSON.stringify({ mock: true, artifact_type: record.artifactType })
          });
          raw.set(id, {
            raw_record_ref: `rawrec_${id}`,
            case_id: 'case_mock',
            event_id: id,
            parse_run_id: 'parse_mock',
            source_file_id: fileId,
            evidence_ref: file.object_ref,
            raw_record_json: JSON.stringify(record.raw, null, 2)
          });
        }
      }

      rebuildReadModels();
      const findingCount = parsed.filter(mockHasFinding).length;
      const chainFindingCount = this.findings(1000).filter((finding) => finding.engine === 'correlation').length;
      analyzerRuns.unshift({
        run_id: `analyzer_${analyzerRuns.length + 1}`,
        case_id: 'case_mock',
        analyzer_id: 'heuristic_findings',
        name: 'ヒューリスティック検知',
        version: 'taotie-port-of-taotie-v1',
        status: 'succeeded',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        input_count: parsed.length,
        output_count: findingCount,
        error_message: null,
        metadata_json: JSON.stringify({ source: 'mock' })
      });
      analyzerRuns.unshift({
        run_id: `analyzer_${analyzerRuns.length + 1}`,
        case_id: 'case_mock',
        analyzer_id: 'correlation_findings',
        name: '相関 Finding 化',
        version: 'taotie-port-of-taotie-v1',
        status: 'succeeded',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        input_count: this.correlationChains(500).length,
        output_count: chainFindingCount,
        error_message: null,
        metadata_json: JSON.stringify({ source: 'mock' })
      });
      const graph = buildMockGraph(events, details);
      analyzerRuns.unshift({
        run_id: `analyzer_${analyzerRuns.length + 1}`,
        case_id: 'case_mock',
        analyzer_id: 'entity_edge_extraction',
        name: 'Entity / Edge 抽出',
        version: 'taotie-port-of-taotie-v1',
        status: 'succeeded',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        input_count: parsed.length,
        output_count: graph.nodes.length + graph.edges.length,
        error_message: null,
        metadata_json: JSON.stringify({ source: 'mock' })
      });
      jobs.unshift(
        mockJob('parse_artifact'),
        mockJob('extract_entities'),
        mockJob('build_edges'),
        mockJob('build_correlation_chains'),
        mockJob('build_event_rows'),
        mockJob('build_timeline_bins')
      );
      return this.summary(caseRoot);
    },
    entities(limit: number): EntityRecord[] {
      return buildMockGraph(events, details).nodes.slice(0, limit);
    },
    eventContext(
      eventId: string,
      windowMinutes: number,
      perGroupLimit: number,
      sameHostOnly: boolean
    ): EventContext | null {
      const anchor = details.get(eventId);
      if (!anchor) return null;
      const limit = Math.max(1, Math.min(Math.trunc(perGroupLimit || 50), 200));
      const groups: EventContextGroup[] = [];
      const addGroup = (
        label: string,
        relation: string,
        value: string,
        predicate: (event: EventRow) => boolean
      ) => {
        const rows = events.filter(predicate).sort(compareEventRows('event_time_utc', 'asc')).slice(0, limit);
        if (rows.length === 0) return;
        groups.push({ label, relation, value, rows });
      };

      const anchorMs = Date.parse(anchor.event_time_utc);
      if (Number.isFinite(anchorMs)) {
        const windowMs = Math.max(1, Math.min(Math.trunc(windowMinutes || 15), 1440)) * 60 * 1000;
        addGroup('前後時間', 'time_window', `±${Math.round(windowMs / 60000)}m`, (event) => {
          const eventMs = Date.parse(event.event_time_utc);
          return (
            Number.isFinite(eventMs) &&
            Math.abs(eventMs - anchorMs) <= windowMs &&
            (!sameHostOnly || !anchor.host || event.host === anchor.host)
          );
        });
      }
      for (const [label, relation, value, field] of [
        ['同一ユーザー', 'same_user', anchor.user_name, 'user_name'],
        ['同一ホスト', 'same_host', anchor.host, 'host'],
        ['同一プロセス', 'same_process', anchor.process_name, 'process_name'],
        ['同一ファイル', 'same_file', anchor.file_path, 'file_path'],
        ['同一IP', 'same_ip', anchor.ip, 'ip'],
        ['同一URL', 'same_url', anchor.url, 'url'],
        ['同一ハッシュ', 'same_hash', anchor.hash, 'hash']
      ] as const) {
        const key = value?.trim();
        if (!key) continue;
        addGroup(label, relation, key, (event) => event[field] === key);
      }
      const basename = (anchor.file_path ?? anchor.process_name)?.split(/[\\/]/).pop()?.toLowerCase();
      if (basename) {
        addGroup('同一ファイル名', 'same_file_basename', basename, (event) => {
          const value = (event.file_path ?? event.process_name)?.split(/[\\/]/).pop()?.toLowerCase();
          return value === basename;
        });
      }
      return { anchor, groups };
    },
    exportEvents(filters: EventPageFilters, format: 'csv' | 'jsonl', maxRows: number): EventExportResult {
      const limit = Math.max(1, Math.min(Math.trunc(maxRows || 100_000), 1_000_000));
      const rows = filteredMockEvents(events, filters);
      return {
        output_path: `mock://events.${format}`,
        format,
        row_count: Math.min(rows.length, limit),
        truncated: rows.length > limit
      };
    },
    eventFacets(filters: EventPageFilters, perFieldLimit: number): EventFacetValue[] {
      const limit = Math.max(1, Math.min(Math.trunc(perFieldLimit || 8), 30));
      const source = filteredMockEvents(events, filters);
      const specs: Array<[string, (event: EventRow) => string | null | undefined]> = [
        ['artifact_type', (event) => event.artifact_type],
        ['severity', (event) => event.severity],
        ['channel', (event) => event.channel ?? '-'],
        ['level', (event) => event.level ?? '-'],
        ['event_code', (event) => event.event_code ?? '-'],
        ['host', (event) => event.host ?? '-'],
        ['user_name', (event) => event.user_name ?? '-'],
        ['event_action', (event) => event.event_action],
        ['parser_name', (event) => event.parser_name]
      ];
      const out: EventFacetValue[] = [];
      for (const [field, getter] of specs) {
        const counts = new Map<string, number>();
        for (const event of source) {
          const value = getter(event)?.trim() || '-';
          counts.set(value, (counts.get(value) ?? 0) + 1);
        }
        out.push(
          ...Array.from(counts.entries())
            .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
            .slice(0, limit)
            .map(([value, count]) => ({ field, value, count }))
        );
      }
      return out;
    },
    buildSearchIndex(): SearchIndexMetadata {
      const now = new Date().toISOString();
      searchIndexMetadata = {
        case_id: 'case_mock',
        index_version: 'taotie-tantivy-events-v1',
        indexed_event_count: events.length,
        updated_at: now,
        build_mode: searchIndexMetadata ? 'incremental_append' : 'full_rebuild',
        appended_event_count: searchIndexMetadata
          ? Math.max(0, events.length - searchIndexMetadata.indexed_event_count)
          : events.length,
        updated_event_count: 0,
        deleted_event_count: 0
      };
      auditLog.unshift({
        audit_id: `audit_${auditLog.length + 1}`,
        case_id: 'case_mock',
        occurred_at: now,
        actor: 'local_analyst',
        action: 'search_index_built',
        target_kind: 'case',
        target_id: 'case_mock',
        summary: `Tantivy search index built for ${events.length} events`,
        metadata_json: JSON.stringify({ source: 'mock' })
      });
      return searchIndexMetadata;
    },
    startSearchIndexBuild(): JobRecord {
      const job = mockJob('build_tantivy_index');
      jobs.unshift(job);
      this.buildSearchIndex();
      return job;
    },
    startAnswerCandidateBuild(): JobRecord {
      const job = mockJob('build_answer_candidates');
      jobs.unshift(job);
      return job;
    },
    startAnalysisReadModelJobs(): JobRecord[] {
      const correlation = mockJob('build_correlation_chains');
      const findings = mockJob('run_findings');
      jobs.unshift(findings, correlation);
      return [correlation, findings];
    },
    searchIndexedEvents(text: string, limit: number, cursor: string | null): Page<EventSearchHit> {
      const boundedLimit = Math.max(1, Math.min(Math.trunc(limit || 50), 200));
      const source = filteredMockEvents(events, {
        search: text.trim() || null,
        sortBy: 'event_time_utc',
        sortDir: 'asc'
      });
      const start = cursor ? Number(cursor) : 0;
      const rows = source.slice(start, start + boundedLimit).map((event) => ({
        event_id: event.event_id,
        event_time_utc: event.event_time_utc,
        artifact_type: event.artifact_type,
        severity: event.severity,
        event_action: event.event_action,
        host: event.host,
        user_name: event.user_name,
        process_name: event.process_name,
        file_path: event.file_path,
        message_short: event.message_short,
        score_basis: 'mock'
      }));
      const next = start + boundedLimit < source.length ? String(start + boundedLimit) : null;
      return { rows, next_cursor: next };
    },
    visibleSavedSearches(limit: number, viewer: string | null): SavedSearch[] {
      const principal = normalizeMockPrincipal(viewer);
      return savedSearches
        .filter((row) => mockSavedSearchVisibleTo(row, principal))
        .slice(0, Math.max(1, Math.min(Math.trunc(limit || 100), 500)));
    },
    saveSavedSearch(
      name: string,
      query: EventPageQuery,
      description: string | null,
      createdBy: string | null,
      visibility: string | null,
      sharedWith: string[] | null
    ): SavedSearch[] {
      const trimmedName = name.trim();
      if (!trimmedName) throw new Error('saved search name is required');
      const now = new Date().toISOString();
      const owner = normalizeMockPrincipal(createdBy);
      const searchVisibility = normalizeMockVisibility(visibility);
      const shared = normalizeMockSharedWith(sharedWith);
      const existing = savedSearches.find(
        (row) =>
          row.name.toLowerCase() === trimmedName.toLowerCase() &&
          normalizeMockPrincipal(row.created_by) === owner
      );
      const normalizedQuery: EventPageQuery = { ...query, cursor: null, limit: query.limit ?? 100 };
      if (existing) {
        existing.name = trimmedName;
        existing.query = normalizedQuery;
        existing.description = description?.trim() || null;
        existing.created_by = owner;
        existing.visibility = searchVisibility;
        existing.shared_with = shared;
        existing.updated_at = now;
      } else {
        savedSearches.unshift({
          search_id: `search_${savedSearches.length + 1}`,
          case_id: 'case_mock',
          name: trimmedName,
          query: normalizedQuery,
          description: description?.trim() || null,
          created_by: owner,
          visibility: searchVisibility,
          shared_with: shared,
          created_at: now,
          updated_at: now
        });
      }
      savedSearches.sort((left, right) => right.updated_at.localeCompare(left.updated_at));
      savedSearches.splice(200);
      auditLog.unshift({
        audit_id: `audit_${auditLog.length + 1}`,
        case_id: 'case_mock',
        occurred_at: now,
        actor: 'local_analyst',
        action: 'saved_search_saved',
        target_kind: 'saved_search',
        target_id: existing?.search_id ?? savedSearches[0]?.search_id ?? null,
        summary: `saved search: ${trimmedName}`,
        metadata_json: JSON.stringify({
          source: 'mock',
          query: normalizedQuery,
          visibility: searchVisibility,
          shared_with: shared
        })
      });
      return savedSearches.filter((row) => mockSavedSearchVisibleTo(row, owner)).slice(0, 200);
    },
    deleteSavedSearch(searchId: string, requestedBy: string | null): SavedSearch[] {
      const index = savedSearches.findIndex((row) => row.search_id === searchId);
      if (index >= 0) {
        const requestedPrincipal = normalizeMockPrincipal(requestedBy);
        const owner = normalizeMockPrincipal(savedSearches[index].created_by);
        if (requestedPrincipal && owner && requestedPrincipal !== owner) {
          throw new Error('saved search can only be deleted by its owner');
        }
        const [removed] = savedSearches.splice(index, 1);
        const now = new Date().toISOString();
        auditLog.unshift({
          audit_id: `audit_${auditLog.length + 1}`,
          case_id: 'case_mock',
          occurred_at: now,
          actor: 'local_analyst',
          action: 'saved_search_deleted',
          target_kind: 'saved_search',
          target_id: removed.search_id,
          summary: `deleted saved search: ${removed.name}`,
          metadata_json: JSON.stringify({
            source: 'mock',
            requested_by: requestedPrincipal,
            visibility: removed.visibility,
            shared_with: removed.shared_with
          })
        });
      }
      return savedSearches
        .filter((row) => mockSavedSearchVisibleTo(row, normalizeMockPrincipal(requestedBy)))
        .slice(0, 200);
    },
    subgraph(entityId: string, edgeLimit: number): Subgraph {
      const graph = buildMockGraph(events, details);
      const edges = graph.edges
        .filter((edge) => edge.src_entity_id === entityId || edge.dst_entity_id === entityId)
        .slice(0, edgeLimit);
      const nodeIds = new Set([entityId]);
      for (const edge of edges) {
        nodeIds.add(edge.src_entity_id);
        nodeIds.add(edge.dst_entity_id);
      }
      return {
        nodes: graph.nodes.filter((node) => nodeIds.has(node.entity_id)),
        edges
      };
    },
    addBookmark(eventId: string, label: string | null, note: string | null): EventBookmark[] {
      if (!bookmarks.some((row) => row.event_id === eventId) && events.some((event) => event.event_id === eventId)) {
        bookmarks.push({
          bookmark_id: `bookmark_${bookmarks.length + 1}`,
          case_id: 'case_mock',
          event_id: eventId,
          label,
          note,
          created_at: new Date().toISOString()
        });
      }
      return bookmarks;
    },
    removeBookmark(bookmarkId: string): EventBookmark[] {
      const index = bookmarks.findIndex((row) => row.bookmark_id === bookmarkId);
      if (index >= 0) bookmarks.splice(index, 1);
      return bookmarks;
    },
    bookmarkEventPage(
      limit: number,
      cursor: string | null | undefined,
      sortBy: EventSortBy,
      sortDir: EventSortDir,
      search: string | null
    ): Page<EventRow> {
      const eventIds = new Set(bookmarks.map((row) => row.event_id));
      const sorted = [...events]
        .filter((event) => eventIds.has(event.event_id) && (!search || eventMatchesSearch(event, search)))
        .sort(compareEventRows(sortBy, sortDir));
      const start = cursor ? Number(cursor) : 0;
      const rows = sorted.slice(start, start + limit);
      const next = start + limit < sorted.length ? String(start + limit) : null;
      return { rows, next_cursor: next };
    },
    iocMatches(indicators: string[], limit: number): IocHit[] {
      const seen = new Set<string>();
      const rows: IocHit[] = [];
      for (const rawIndicator of indicators) {
        const ioc = rawIndicator.trim();
        const key = ioc.toLowerCase();
        if (!ioc || seen.has(key)) continue;
        seen.add(key);
        const matched = events.filter((event) => eventMatchesIoc(event, ioc));
        if (matched.length === 0) continue;
        const sorted = [...matched].sort(compareEventRows('event_time_utc', 'asc'));
        rows.push({
          case_id: 'case_mock',
          ioc,
          match_kind: mockIocMatchKind(matched, ioc),
          hit_count: matched.length,
          artifact_types: Array.from(new Set(matched.map((event) => event.artifact_type))).join(', '),
          event_ids_json: JSON.stringify(sorted.slice(0, 500).map((event) => event.event_id)),
          first_seen_utc: sorted[0]?.event_time_utc ?? null,
          last_seen_utc: sorted[sorted.length - 1]?.event_time_utc ?? null
        });
        if (seen.size >= 500) break;
      }
      return rows
        .sort(
          (left, right) =>
            right.hit_count - left.hit_count ||
            (right.last_seen_utc ?? '').localeCompare(left.last_seen_utc ?? '') ||
            left.ioc.localeCompare(right.ioc)
        )
        .slice(0, limit);
    },
    iocEventPage(
      ioc: string,
      limit: number,
      cursor: string | null | undefined,
      sortBy: EventSortBy,
      sortDir: EventSortDir,
      search: string | null
    ): Page<EventRow> {
      const sorted = [...events]
        .filter((event) => eventMatchesIoc(event, ioc) && (!search || eventMatchesSearch(event, search)))
        .sort(compareEventRows(sortBy, sortDir));
      const start = cursor ? Number(cursor) : 0;
      const rows = sorted.slice(start, start + limit);
      const next = start + limit < sorted.length ? String(start + limit) : null;
      return { rows, next_cursor: next };
    },
    defenderSummary(limit: number): DefenderSummary[] {
      const grouped = new Map<string, DefenderSummary>();
      for (const event of events.filter(eventIsDefender)) {
        const row =
          grouped.get(event.event_action) ??
          {
            case_id: 'case_mock',
            category: event.event_action,
            severity_max: event.severity,
            event_count: 0,
            artifact_types: '',
            first_seen_utc: event.event_time_utc,
            last_seen_utc: event.event_time_utc,
            sample_message: event.message_short
          };
        row.event_count += 1;
        row.severity_max = maxSeverity(row.severity_max ?? 'info', event.severity);
        if (event.event_time_utc < row.first_seen_utc) row.first_seen_utc = event.event_time_utc;
        if (event.event_time_utc > row.last_seen_utc) row.last_seen_utc = event.event_time_utc;
        const artifactTypes = new Set(row.artifact_types.split(', ').filter(Boolean));
        artifactTypes.add(event.artifact_type);
        row.artifact_types = Array.from(artifactTypes).join(', ');
        grouped.set(event.event_action, row);
      }
      return Array.from(grouped.values())
        .sort(
          (left, right) =>
            severityRank(right.severity_max ?? '') - severityRank(left.severity_max ?? '') ||
            right.event_count - left.event_count ||
            right.last_seen_utc.localeCompare(left.last_seen_utc)
        )
        .slice(0, limit);
    },
    prefetchSummary(limit: number): PrefetchSummary[] {
      const grouped = new Map<string, PrefetchSummary>();
      for (const event of events.filter((row) => row.artifact_type === 'prefetch')) {
        const processName = event.process_name ?? fileNameFromPath(event.file_path ?? '') ?? 'unknown';
        const row =
          grouped.get(processName) ??
          {
            case_id: event.case_id,
            process_name: processName,
            file_path: event.file_path ?? null,
            prefetch_file_name: fileNameFromPath(event.file_path ?? '') ?? null,
            prefetch_hash: null,
            run_count_max: null,
            referenced_file_count_max: null,
            source_file_count: 0,
            event_count: 0,
            first_seen_utc: event.event_time_utc,
            last_seen_utc: event.event_time_utc,
            severity_max: event.severity,
            actions: '',
            suspicion: event.severity !== 'info' ? 'prefetch_suspicious_execution' : null,
            sample_message: event.message_short
          };
        row.event_count += 1;
        row.source_file_count = Math.max(row.source_file_count, 1);
        const runCount = Number(event.message_short.match(/run_count=(\d+)/i)?.[1] ?? '');
        if (Number.isFinite(runCount) && runCount > 0) {
          row.run_count_max = Math.max(row.run_count_max ?? 0, runCount);
        }
        row.severity_max = maxSeverity(row.severity_max ?? 'info', event.severity);
        if (event.event_time_utc < row.first_seen_utc) row.first_seen_utc = event.event_time_utc;
        if (event.event_time_utc > row.last_seen_utc) row.last_seen_utc = event.event_time_utc;
        const actions = new Set(row.actions.split(', ').filter(Boolean));
        actions.add(event.event_action);
        row.actions = Array.from(actions).join(', ');
        grouped.set(processName, row);
      }
      return Array.from(grouped.values())
        .sort(
          (left, right) =>
            severityRank(right.severity_max ?? '') - severityRank(left.severity_max ?? '') ||
            (right.run_count_max ?? 0) - (left.run_count_max ?? 0) ||
            right.last_seen_utc.localeCompare(left.last_seen_utc)
        )
        .slice(0, limit);
    },
    defenderEventPage(
      category: string | null,
      limit: number,
      cursor: string | null | undefined,
      sortBy: EventSortBy,
      sortDir: EventSortDir,
      search: string | null
    ): Page<EventRow> {
      const sorted = [...events]
        .filter(
          (event) =>
            eventIsDefender(event) &&
            (!category || event.event_action === category) &&
            (!search || eventMatchesSearch(event, search))
        )
        .sort(compareEventRows(sortBy, sortDir));
      const start = cursor ? Number(cursor) : 0;
      const rows = sorted.slice(start, start + limit);
      const next = start + limit < sorted.length ? String(start + limit) : null;
      return { rows, next_cursor: next };
    },
    findings(limit: number): FindingSummary[] {
      const suspicious = events.filter((event) => event.has_finding);
      const rows: FindingSummary[] = [];
      if (suspicious.length > 0) {
        rows.push({
          case_id: 'case_mock',
          title: 'ヒューリスティック検知',
          severity: suspicious.reduce((max, event) => maxSeverity(max, event.severity), 'info'),
          engine: 'heuristic',
          rule_id: 'mock-heuristic',
          attack_json: JSON.stringify(['T1059.001']),
          finding_count: suspicious.length,
          event_count: suspicious.length,
          first_seen_utc: suspicious[0]?.event_time_utc ?? null,
          last_seen_utc: suspicious[suspicious.length - 1]?.event_time_utc ?? null,
          sample_message: suspicious[0]?.message_short ?? null
        });
      }
      for (const chain of this.correlationChains(500).filter((row) => severityRank(row.severity) >= severityRank('medium'))) {
        const eventIds = mockChainEventIds(chain);
        rows.push({
          case_id: 'case_mock',
          title: chain.title,
          severity: chain.severity,
          engine: 'correlation',
          rule_id: mockChainRuleId(chain),
          attack_json: JSON.stringify(mockChainAttackTechniques(mockChainRuleId(chain))),
          finding_count: 1,
          event_count: eventIds.length || chain.event_count,
          first_seen_utc: chain.first_seen_utc,
          last_seen_utc: chain.last_seen_utc,
          sample_message: `${chain.explanation}: ${chain.key_kind}=${chain.key_value}`
        });
      }
      return applyMockFindingOverrides(rows, findingOverrides)
        .sort(
          (left, right) =>
            severityRank(right.severity) - severityRank(left.severity) ||
            right.finding_count - left.finding_count ||
            (right.last_seen_utc ?? '').localeCompare(left.last_seen_utc ?? '')
        )
        .slice(0, limit);
    },
    answerCandidates(questionKey: string | null, limit: number): AnswerCandidate[] {
      const suspicious = events.filter((event) => event.has_finding);
      const evidenceIds = suspicious.slice(0, 3).map((event) => event.event_id);
      const rows: AnswerCandidate[] = [
        {
          candidate_id: 'mock_answer_initial_access',
          case_id: 'case_mock',
          question_key: 'initial_access.execution_technique',
          question_label: '初期侵入手法候補',
          candidate_value: 'T1204.002',
          confidence: 0.72,
          status: evidenceIds.length > 0 ? 'suggested' : 'needs_evidence',
          severity: 'medium',
          category: 'execution',
          reason: 'HTA/MSHTA/PowerShell などの初期実行痕跡から候補化',
          evidence_event_ids_json: JSON.stringify(evidenceIds),
          evidence_refs_json: JSON.stringify([]),
          missing_steps_json: JSON.stringify(evidenceIds.length > 0 ? [] : ['イベント取り込み後に再解析']),
          next_action: '候補イベントの前後関係と原本を確認',
          first_seen_utc: suspicious[0]?.event_time_utc ?? null,
          last_seen_utc: suspicious[suspicious.length - 1]?.event_time_utc ?? null,
          attributes_json: JSON.stringify({ source: 'mock' })
        },
        {
          candidate_id: 'mock_answer_keepass',
          case_id: 'case_mock',
          question_key: 'credential_access.target_application',
          question_label: '資格情報アクセス対象アプリ候補',
          candidate_value: 'KeePass',
          confidence: 0.68,
          status: 'suggested',
          severity: 'medium',
          category: 'credential_access',
          reason: 'KeePass/KDBX/credential store の痕跡から候補化',
          evidence_event_ids_json: JSON.stringify(evidenceIds.slice(0, 1)),
          evidence_refs_json: JSON.stringify([]),
          missing_steps_json: JSON.stringify(['KDBX と DPAPI/masterkey の突合']),
          next_action: 'credential sidecar の出力と証拠オフセットを確認',
          first_seen_utc: suspicious[0]?.event_time_utc ?? null,
          last_seen_utc: suspicious[0]?.event_time_utc ?? null,
          attributes_json: JSON.stringify({ source: 'mock', recovery_required: true })
        }
      ];
      return rows
        .filter((row) => !questionKey || row.question_key === questionKey)
        .sort((left, right) => right.confidence - left.confidence)
        .slice(0, limit);
    },
    triageActions(limit: number): TriageAction[] {
      const rows: TriageAction[] = [];
      const findingKeys = new Set<string>();
      for (const finding of this.findings(200)) {
        const review = findingReviews.find((row) => sameMockFindingReview(row, finding));
        const status = review?.status ?? 'new';
        if (status === 'confirmed' || status === 'false_positive' || status === 'benign') continue;
        const sourceKey = mockFindingSourceKey(finding);
        findingKeys.add(sourceKey);
        const overdue = review?.due_at ? Date.parse(review.due_at) < Date.now() : false;
        rows.push({
          action_id: mockTriageId('finding', sourceKey),
          case_id: 'case_mock',
          priority:
            severityRank(finding.severity) * 1000 +
            Math.min(Math.max(finding.event_count, 0), 500) +
            (overdue ? 700 : 0) +
            (status === 'needs_context' ? 250 : 0),
          category: 'finding',
          title: `検知確認: ${finding.title}`,
          reason: finding.sample_message ?? 'Finding group requires review',
          severity: finding.severity,
          status,
          source_kind: 'finding',
          source_key: sourceKey,
          event_count: finding.event_count,
          first_seen_utc: finding.first_seen_utc ?? null,
          last_seen_utc: finding.last_seen_utc ?? null,
          evidence_json: JSON.stringify({
            engine: finding.engine,
            rule_id: finding.rule_id ?? null,
            attack: finding.attack_json,
            review
          })
        });
      }
      for (const chain of this.correlationChains(100).filter((row) => severityRank(row.severity) >= severityRank('medium'))) {
        const sourceKey = `${chain.key_kind}=${chain.key_value}`;
        rows.push({
          action_id: mockTriageId('correlation', sourceKey),
          case_id: 'case_mock',
          priority: severityRank(chain.severity) * 900 + Math.min(Math.max(chain.score, 0), 2000) + Math.min(chain.event_count, 500),
          category: 'correlation',
          title: `相関確認: ${chain.title}`,
          reason: chain.explanation,
          severity: chain.severity,
          status: 'open',
          source_kind: 'correlation_chain',
          source_key: sourceKey,
          event_count: chain.event_count,
          first_seen_utc: chain.first_seen_utc,
          last_seen_utc: chain.last_seen_utc,
          evidence_json: JSON.stringify({
            key_kind: chain.key_kind,
            key_value: chain.key_value,
            artifact_types: chain.artifact_types,
            steps: chain.steps_json
          })
        });
      }
      for (const row of coverage.filter((item) => item.failed_files > 0)) {
        const sourceKey = `mock:${row.artifact_type}`;
        rows.push({
          action_id: mockTriageId('parser_failure', sourceKey),
          case_id: 'case_mock',
          priority: 2000 + Math.min(row.failed_files * 25, 1000),
          category: 'parser_failure',
          title: `パーサ失敗確認: ${row.artifact_type}`,
          reason: `${row.failed_files} failed files`,
          severity: 'medium',
          status: 'open',
          source_kind: 'parser_failure',
          source_key: sourceKey,
          event_count: row.failed_files,
          first_seen_utc: null,
          last_seen_utc: new Date().toISOString(),
          evidence_json: JSON.stringify(row)
        });
      }
      for (const review of findingReviews.filter(
        (row) =>
          row.status !== 'confirmed' &&
          row.status !== 'false_positive' &&
          row.status !== 'benign' &&
          !findingKeys.has(mockFindingSourceKey(row))
      )) {
        const sourceKey = mockFindingSourceKey(review);
        const overdue = review.due_at ? Date.parse(review.due_at) < Date.now() : false;
        rows.push({
          action_id: mockTriageId('review', sourceKey),
          case_id: 'case_mock',
          priority: 2600 + (overdue ? 700 : 0),
          category: 'review',
          title: `レビュー未完了: ${review.title}`,
          reason: review.comment ?? 'Review remains open but current finding summary did not include it',
          severity: overdue ? 'high' : 'medium',
          status: review.status,
          source_kind: 'finding_review',
          source_key: sourceKey,
          event_count: 0,
          first_seen_utc: null,
          last_seen_utc: review.updated_at,
          evidence_json: JSON.stringify(review)
        });
      }
      return rows
        .sort(
          (left, right) =>
            right.priority - left.priority ||
            severityRank(right.severity) - severityRank(left.severity) ||
            right.event_count - left.event_count ||
            (right.last_seen_utc ?? '').localeCompare(left.last_seen_utc ?? '')
        )
        .slice(0, limit);
    },
    caseDetectionEvaluation(): CaseDetectionEvaluation {
      const findingRows = this.findings(500);
      const chainRows = this.correlationChains(500);
      const totalFiles = coverage.reduce((sum, row) => sum + row.total_files, 0);
      const parsedFiles = coverage.reduce((sum, row) => sum + row.parsed_files, 0);
      const parsedRate = totalFiles > 0 ? Math.round((parsedFiles * 1000) / totalFiles) / 10 : 100;
      const highFindings = findingRows.filter((row) => severityRank(row.severity) >= severityRank('high'));
      const confirmed = findingRows.filter((finding) =>
        findingReviews.some((review) => sameMockFindingReview(review, finding) && review.status === 'confirmed')
      );
      const openFindings = findingRows.filter((finding) => {
        const review = findingReviews.find((row) => sameMockFindingReview(row, finding));
        return !review || !['confirmed', 'false_positive', 'benign'].includes(review.status);
      });
      const unreviewedHigh = highFindings.filter((finding) => {
        const review = findingReviews.find((row) => sameMockFindingReview(row, finding));
        return !review || !['confirmed', 'false_positive', 'benign'].includes(review.status);
      });
      const objectiveSpecs = [
        ['execution', '実行痕跡', ['prefetch', 'amcache', 'evtx'], ['execution', 'powershell', 'lolbin', 'scheduled'], ['T1059', 'T1204']],
        ['credential_access', '資格情報アクセス', ['evtx', 'defender'], ['credential', 'lsass', 'password'], ['T1003', 'T1110']],
        ['persistence', '永続化', ['registry', 'scheduled_task', 'evtx'], ['persistence', 'service', 'scheduled'], ['T1547', 'T1543', 'T1053']],
        ['defense_evasion', '防御回避/痕跡消去', ['defender', 'mft', 'usn_jrnl'], ['defender', 'delete', 'tamper'], ['T1070', 'T1562']],
        ['lateral_movement', '横展開/リモート実行', ['evtx', 'prefetch'], ['psexec', 'remote', 'wmi'], ['T1021', 'T1570']],
        ['filesystem_timeline', 'ファイルシステム時系列', ['mft', 'usn_jrnl', 'lnk', 'prefetch'], ['mft', 'download', 'delete'], ['T1070', 'T1105']],
        ['network_ioc', '通信/IOC', ['browser', 'srum', 'evtx'], ['download', 'c2', 'ioc'], ['T1105', 'T1071']]
      ] as const;
      const objectives: CaseDetectionEvaluation['objectives'] = objectiveSpecs.map(([id, name, artifactHints, ruleHints, attackHints]) => {
        const artifacts = coverage
          .filter((row) => artifactHints.some((hint) => row.artifact_type.includes(hint)))
          .map((row) => row.artifact_type);
        const matches = findingRows.filter((finding) => {
          const hay = `${finding.engine} ${finding.rule_id ?? ''} ${finding.title} ${finding.sample_message ?? ''}`.toLowerCase();
          const attacks = mockJsonList(finding.attack_json);
          return (
            ruleHints.some((hint) => hay.includes(hint)) ||
            attackHints.some((hint) => attacks.some((value: string) => value.startsWith(hint)))
          );
        });
        const status =
          events.length === 0 && files.length === 0
            ? 'not_observed'
            : matches.length > 0
              ? 'covered'
              : artifacts.length > 0
                ? 'partial'
                : 'missing';
        return {
          objective_id: id,
          objective_name: name,
          status,
          severity_max: matches.reduce((max, row) => maxSeverity(max, row.severity), 'info'),
          finding_count: matches.reduce((sum, row) => sum + Math.max(row.finding_count, 1), 0),
          event_count: matches.reduce((sum, row) => sum + Math.max(row.event_count, 0), 0),
          artifact_types: [...new Set(artifacts)].sort().join(', '),
          attack_techniques: [...new Set(matches.flatMap((row) => mockJsonList(row.attack_json)))].sort().join(', '),
          evidence_note:
            status === 'covered'
              ? `${matches.length} 件の検知グループで確認`
              : status === 'partial'
                ? '関連アーティファクトはあるが検知グループが未生成'
                : status === 'missing'
                  ? 'ケース内でこの調査目的を満たす検知/アーティファクトが不足'
                  : '評価対象データなし'
        };
      });
      objectives.push({
        objective_id: 'cross_artifact_correlation',
        objective_name: 'アーティファクト横断相関',
        status: chainRows.length > 0 ? 'covered' : coverage.length >= 2 ? 'partial' : events.length > 0 ? 'missing' : 'not_observed',
        severity_max: chainRows.reduce((max, row) => maxSeverity(max, row.severity), 'info'),
        finding_count: chainRows.length,
        event_count: chainRows.reduce((sum, row) => sum + row.event_count, 0),
        artifact_types: coverage.map((row) => row.artifact_type).sort().join(', '),
        attack_techniques: '',
        evidence_note: chainRows.length > 0 ? `${chainRows.length} 件の相関チェーンを生成` : '横断相関に必要なデータが不足'
      });
      const applicable = objectives.filter((row) => row.status !== 'not_observed');
      const covered = objectives.filter((row) => row.status === 'covered').length;
      const partial = objectives.filter((row) => row.status === 'partial').length;
      const missing = objectives.filter((row) => row.status === 'missing').length;
      const detectionCoverage = applicable.length > 0 ? Math.round(((covered + partial * 0.5) * 1000) / applicable.length) / 10 : 0;
      const reportApproved = caseApprovals.some((row) => row.status === 'approved' && row.target_kind.includes('report'));
      const qualityGates = [
        {
          gate_id: 'parser_coverage',
          category: 'detection',
          status: parsedRate >= 95 ? 'pass' : parsedRate >= 80 ? 'warn' : 'fail',
          severity: parsedRate >= 95 ? 'info' : parsedRate >= 80 ? 'medium' : 'high',
          title: 'パーサカバレッジ',
          detail: `parsed_rate=${parsedRate.toFixed(1)}%`,
          metric: `${parsedRate.toFixed(1)}%`,
          recommended_action: 'failed/unsupported を優先して解消し、再取り込み後に分析を再構築する'
        },
        {
          gate_id: 'high_finding_review',
          category: 'investigation',
          status: unreviewedHigh.length === 0 ? 'pass' : unreviewedHigh.length <= 3 ? 'warn' : 'fail',
          severity: unreviewedHigh.length === 0 ? 'info' : unreviewedHigh.length <= 3 ? 'high' : 'critical',
          title: '高優先度検知レビュー',
          detail: `unreviewed_high_findings=${unreviewedHigh.length} open_findings=${openFindings.length}`,
          metric: String(unreviewedHigh.length),
          recommended_action: 'critical/high の検知を確認し confirmed/false_positive/benign に分類する'
        },
        {
          gate_id: 'correlation_drilldown',
          category: 'investigation',
          status: chainRows.length > 0 || events.length < 5 ? 'pass' : 'fail',
          severity: chainRows.length > 0 || events.length < 5 ? 'info' : 'high',
          title: '横断相関ドリルダウン',
          detail: `chains=${chainRows.length}`,
          metric: String(chainRows.length),
          recommended_action: '相関チェーンからイベントへ入り、同一ファイル/ユーザー/ホストで前後関係を確認する'
        },
        {
          gate_id: 'evidence_verification',
          category: 'report',
          status: totalFiles === 0 ? 'pass' : 'fail',
          severity: totalFiles === 0 ? 'info' : 'high',
          title: '証拠ハッシュ検証',
          detail: 'mock UI では実証拠検証は未実行',
          metric: totalFiles === 0 ? '100.0%' : '0.0%',
          recommended_action: '証拠台帳タブでハッシュ検証を完了し、レポートバンドルに含める'
        },
        {
          gate_id: 'report_bundle_approval',
          category: 'report',
          status: reportApproved ? 'pass' : 'warn',
          severity: reportApproved ? 'info' : 'medium',
          title: '成果物承認',
          detail: reportApproved ? 'approved report bundle exists' : 'approved report bundle not found',
          metric: reportApproved ? 'approved' : 'pending',
          recommended_action: 'レポートバンドル生成後、検証結果とあわせて承認レコードを残す'
        }
      ];
      const readiness = Math.max(0, Math.round((100 - unreviewedHigh.length * 7 - missing * 8) * 10) / 10);
      const reportQuality = Math.max(0, Math.min(100, (totalFiles === 0 ? 45 : 0) + (reportApproved ? 25 : 0) + 20));
      return {
        case_id: 'case_mock',
        evaluated_at: new Date().toISOString(),
        overall_score: Math.round((detectionCoverage * 0.45 + readiness * 0.35 + reportQuality * 0.2) * 10) / 10,
        detection_coverage_rate: detectionCoverage,
        investigation_readiness_score: readiness,
        report_quality_score: reportQuality,
        applicable_objective_count: applicable.length,
        covered_objective_count: covered,
        partial_objective_count: partial,
        missing_objective_count: missing,
        total_findings: findingRows.reduce((sum, row) => sum + row.finding_count, 0),
        critical_findings: findingRows.filter((row) => row.severity === 'critical').length,
        high_findings: highFindings.length,
        confirmed_findings: confirmed.length,
        open_findings: openFindings.length,
        unreviewed_high_findings: unreviewedHigh.length,
        correlation_chain_count: chainRows.length,
        high_correlation_chain_count: chainRows.filter((row) => severityRank(row.severity) >= severityRank('high')).length,
        risk_technique_count: this.risk(100).length,
        parsed_file_rate: parsedRate,
        evidence_verification_rate: totalFiles === 0 ? 100 : 0,
        parser_gap_count: coverage.reduce((sum, row) => sum + row.failed_files + row.unsupported_files, 0),
        unsupported_file_count: coverage.reduce((sum, row) => sum + row.unsupported_files, 0),
        report_gap_count: qualityGates.filter((row) => row.category === 'report' && row.status !== 'pass').length,
        objectives,
        quality_gates: qualityGates
      };
    },
    findingReviewSummary(): FindingReviewSummary {
      const now = Date.now();
      const openStatuses = new Set(['new', 'in_review', 'needs_context']);
      const summary: FindingReviewSummary = {
        case_id: 'case_mock',
        total_reviews: findingReviews.length,
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
        updated_at: new Date().toISOString()
      };
      for (const row of findingReviews) {
        if (row.status === 'new') summary.new_count += 1;
        if (row.status === 'in_review') summary.in_review_count += 1;
        if (row.status === 'confirmed') summary.confirmed_count += 1;
        if (row.status === 'false_positive') summary.false_positive_count += 1;
        if (row.status === 'benign') summary.benign_count += 1;
        if (row.status === 'needs_context') summary.needs_context_count += 1;
        if (openStatuses.has(row.status)) {
          summary.open_count += 1;
          if (!row.assignee?.trim()) summary.unassigned_count += 1;
          const dueAt = row.due_at ? Date.parse(row.due_at) : Number.NaN;
          if (Number.isFinite(dueAt) && dueAt < now) summary.overdue_count += 1;
        }
        if (mockReviewTags(row.tags_json).length > 0) summary.tagged_count += 1;
      }
      return summary;
    },
    setFindingReview(
      finding: Pick<FindingSummary, 'title' | 'engine' | 'rule_id'>,
      status: FindingReviewStatus,
      reviewer: string | null,
      assignee: string | null,
      tags: string[] | null,
      dueAt: string | null,
      comment: string | null
    ): FindingReview[] {
      const now = new Date().toISOString();
      const tagsJson = tags && tags.length > 0 ? JSON.stringify(tags) : null;
      const existing = findingReviews.find((row) => sameMockFindingReview(row, finding));
      if (existing) {
        existing.status = status;
        existing.reviewer = reviewer;
        existing.assignee = assignee;
        existing.tags_json = tagsJson;
        existing.due_at = dueAt;
        existing.comment = comment;
        existing.updated_at = now;
      } else {
        findingReviews.push({
          review_id: `review_${findingReviews.length + 1}`,
          case_id: 'case_mock',
          engine: finding.engine,
          rule_id: finding.rule_id ?? null,
          title: finding.title,
          status,
          reviewer,
          assignee,
          tags_json: tagsJson,
          due_at: dueAt,
          comment,
          created_at: now,
          updated_at: now
        });
      }
      auditLog.unshift({
        audit_id: `audit_${auditLog.length + 1}`,
        case_id: 'case_mock',
        occurred_at: now,
        actor: 'local_analyst',
        action: 'finding_review_updated',
        target_kind: 'finding',
        target_id: existing?.review_id ?? findingReviews[findingReviews.length - 1]?.review_id ?? null,
        summary: `review ${status}: ${finding.title}`,
        metadata_json: JSON.stringify({ source: 'mock', status, assignee, tags, due_at: dueAt })
      });
      return findingReviews;
    },
    setCaseApproval(
      targetKind: string,
      status: CaseApprovalStatus,
      approver: string | null,
      role: string | null,
      comment: string | null,
      targetPath: string | null,
      targetId: string | null,
      targetSha256: string | null
    ): CaseApprovalRecord[] {
      const now = new Date().toISOString();
      const key = `${targetKind}:${targetId ?? '-'}:${targetPath ?? '-'}`;
      const existing = caseApprovals.find(
        (row) => `${row.target_kind}:${row.target_id ?? '-'}:${row.target_path ?? '-'}` === key
      );
      if (existing) {
        existing.status = status;
        existing.approver = approver?.trim() || null;
        existing.role = role?.trim() || null;
        existing.comment = comment?.trim() || null;
        existing.target_sha256 = (targetSha256?.trim() || existing.target_sha256) ?? null;
        existing.updated_at = now;
      } else {
        caseApprovals.unshift({
          approval_id: `approval_${caseApprovals.length + 1}`,
          case_id: 'case_mock',
          target_kind: targetKind,
          target_id: targetId?.trim() || null,
          target_path: targetPath?.trim() || null,
          target_sha256: targetSha256?.trim() || null,
          status,
          approver: approver?.trim() || null,
          role: role?.trim() || null,
          comment: comment?.trim() || null,
          created_at: now,
          updated_at: now
        });
      }
      auditLog.unshift({
        audit_id: `audit_${auditLog.length + 1}`,
        case_id: 'case_mock',
        occurred_at: now,
        actor: 'local_analyst',
        action: 'case_approval_updated',
        target_kind: targetKind,
        target_id: targetId ?? targetPath ?? null,
        summary: `approval ${status}: ${targetPath ?? targetId ?? targetKind}`,
        metadata_json: JSON.stringify({ source: 'mock', status, approver, role, target_sha256: targetSha256 })
      });
      return caseApprovals;
    },
    addFindingOverride(
      finding: Pick<FindingSummary, 'title' | 'engine' | 'rule_id'>,
      action: 'suppress' | 'severity_override',
      severity: string | null,
      reason: string | null
    ): FindingOverride[] {
      const row: FindingOverride = {
        override_id: `override_${findingOverrides.length + 1}`,
        case_id: 'case_mock',
        enabled: true,
        action,
        engine: finding.engine,
        rule_id: finding.rule_id ?? null,
        title: finding.title,
        severity,
        reason,
        created_at: new Date().toISOString()
      };
      if (!findingOverrides.some((existing) => sameMockFindingOverride(existing, row))) {
        findingOverrides.push(row);
      }
      analyzerRuns.unshift({
        run_id: `analyzer_${analyzerRuns.length + 1}`,
        case_id: 'case_mock',
        analyzer_id: 'finding_overrides',
        name: 'Finding 抑制/上書き',
        version: 'taotie-port-of-taotie-v1',
        status: 'succeeded',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        input_count: events.length,
        output_count: this.findings(1000).length,
        error_message: null,
        metadata_json: JSON.stringify({ source: 'mock', action })
      });
      return findingOverrides;
    },
    removeFindingOverride(overrideId: string): FindingOverride[] {
      const index = findingOverrides.findIndex((row) => row.override_id === overrideId);
      if (index >= 0) {
        findingOverrides.splice(index, 1);
        analyzerRuns.unshift({
          run_id: `analyzer_${analyzerRuns.length + 1}`,
          case_id: 'case_mock',
          analyzer_id: 'finding_overrides',
          name: 'Finding 抑制/上書き',
          version: 'taotie-port-of-taotie-v1',
          status: 'succeeded',
          started_at: new Date().toISOString(),
          finished_at: new Date().toISOString(),
          input_count: events.length,
          output_count: this.findings(1000).length,
          error_message: null,
          metadata_json: JSON.stringify({ source: 'mock', action: 'remove' })
        });
      }
      return findingOverrides;
    },
    findingEventIds(finding: Pick<FindingSummary, 'title' | 'engine' | 'rule_id'>): Set<string> {
      if (finding.engine === 'correlation') {
        const chain = this.correlationChains(500).find(
          (row) =>
            row.title === finding.title &&
            (!finding.rule_id || mockChainRuleId(row) === finding.rule_id)
        );
        return new Set(chain ? mockChainEventIds(chain) : []);
      }
      return new Set(events.filter((event) => event.has_finding).map((event) => event.event_id));
    },
    risk(limit: number): RiskSummary[] {
      const grouped = new Map<string, RiskSummary>();
      for (const finding of this.findings(1000)) {
        const techniques = parseJsonStringArray(finding.attack_json);
        for (const technique of techniques) {
          const row =
            grouped.get(technique) ??
            {
              case_id: 'case_mock',
              technique,
              severity_max: null,
              finding_count: 0,
              event_count: 0,
              first_seen_utc: finding.first_seen_utc ?? null,
              last_seen_utc: finding.last_seen_utc ?? null
            };
          row.finding_count += finding.finding_count;
          row.event_count += finding.event_count;
          row.severity_max = row.severity_max ? maxSeverity(row.severity_max, finding.severity) : finding.severity;
          if (finding.first_seen_utc && (!row.first_seen_utc || finding.first_seen_utc < row.first_seen_utc)) {
            row.first_seen_utc = finding.first_seen_utc;
          }
          if (finding.last_seen_utc && (!row.last_seen_utc || finding.last_seen_utc > row.last_seen_utc)) {
            row.last_seen_utc = finding.last_seen_utc;
          }
          grouped.set(technique, row);
        }
      }
      return Array.from(grouped.values())
        .sort(
          (left, right) =>
            severityRank(right.severity_max ?? '') - severityRank(left.severity_max ?? '') ||
            right.finding_count - left.finding_count
        )
        .slice(0, limit);
    },
    correlations(limit: number): CorrelationSummary[] {
      const groups = new Map<
        string,
        {
          keyKind: string;
          keyValue: string;
          userName: string | null;
          host: string | null;
          ip: string | null;
          filePath: string | null;
          artifactTypes: Set<string>;
          eventCount: number;
          firstSeen: string;
          lastSeen: string;
          severityMax: string;
        }
      >();
      for (const event of events) {
        const detail = details.get(event.event_id);
        const key = detail?.file_path ?? detail?.process_name ?? event.user_name ?? event.host;
        if (!key) continue;
        const keyKind = detail?.file_path ? 'file_path' : detail?.process_name ? 'process_name' : event.user_name ? 'user_name' : 'host';
        const mapKey = `${keyKind}|${key.toLowerCase()}`;
        const group =
          groups.get(mapKey) ??
          {
            keyKind,
            keyValue: key.toLowerCase(),
            userName: event.user_name ?? null,
            host: event.host ?? null,
            ip: detail?.ip ?? null,
            filePath: detail?.file_path ?? detail?.process_name ?? null,
            artifactTypes: new Set<string>(),
            eventCount: 0,
            firstSeen: event.event_time_utc,
            lastSeen: event.event_time_utc,
            severityMax: event.severity
          };
        group.artifactTypes.add(event.artifact_type);
        group.eventCount += 1;
        group.firstSeen = event.event_time_utc < group.firstSeen ? event.event_time_utc : group.firstSeen;
        group.lastSeen = event.event_time_utc > group.lastSeen ? event.event_time_utc : group.lastSeen;
        group.severityMax = maxSeverity(group.severityMax, event.severity);
        groups.set(mapKey, group);
      }
      return Array.from(groups.values())
        .filter((group) => group.eventCount > 1 || group.artifactTypes.size > 1)
        .sort((left, right) => right.eventCount - left.eventCount)
        .slice(0, limit)
        .map((group) => ({
          case_id: 'case_mock',
          key_kind: group.keyKind,
          key_value: group.keyValue,
          user_name: group.userName,
          host: group.host,
          ip: group.ip,
          file_path: group.filePath,
          artifact_types: Array.from(group.artifactTypes).join(', '),
          event_count: group.eventCount,
          first_seen_utc: group.firstSeen,
          last_seen_utc: group.lastSeen,
          severity_max: group.severityMax,
          explanation:
            group.artifactTypes.size > 1
              ? '複数アーティファクトで同一キーを確認'
              : '同一キーで複数イベントを確認'
        }));
    },
    correlationChains(limit: number): CorrelationChainSummary[] {
      const groups = new Map<
        string,
        {
          keyKind: string;
          keyValue: string;
          artifactTypes: Set<string>;
          events: EventRow[];
          firstSeen: string;
          lastSeen: string;
          severityMax: string;
        }
      >();
      for (const event of events) {
        const key = mockPrimaryChainKey(event);
        if (!key) continue;
        const mapKey = `${key.kind}|${key.value}`;
        const group =
          groups.get(mapKey) ??
          {
            keyKind: key.kind,
            keyValue: key.value,
            artifactTypes: new Set<string>(),
            events: [],
            firstSeen: event.event_time_utc,
            lastSeen: event.event_time_utc,
            severityMax: event.severity
          };
        group.artifactTypes.add(event.artifact_type);
        group.events.push(event);
        group.firstSeen = event.event_time_utc < group.firstSeen ? event.event_time_utc : group.firstSeen;
        group.lastSeen = event.event_time_utc > group.lastSeen ? event.event_time_utc : group.lastSeen;
        group.severityMax = maxSeverity(group.severityMax, event.severity);
        groups.set(mapKey, group);
      }
      return Array.from(groups.values())
        .filter((group) => group.events.length >= 2 || group.artifactTypes.size >= 2)
        .sort((left, right) => right.artifactTypes.size - left.artifactTypes.size || right.events.length - left.events.length)
        .slice(0, limit)
        .map((group) => {
          const steps = group.events
            .slice()
            .sort(compareEventRows('event_time_utc', 'asc'))
            .slice(0, 50)
            .map((event) => ({
              ts: event.event_time_utc,
              artifact: event.artifact_type,
              action: event.event_action,
              event_id: event.event_id
            }));
          const semantic = semanticChain(group.keyKind, group.artifactTypes, group.events);
          return {
            case_id: 'case_mock',
            key_kind: group.keyKind,
            key_value: group.keyValue,
            title: semantic.title,
            severity: semantic.severity,
            artifact_types: Array.from(group.artifactTypes).join(', '),
            event_count: group.events.length,
            step_count: group.events.length,
            first_seen_utc: group.firstSeen,
            last_seen_utc: group.lastSeen,
            severity_max: group.severityMax,
            score: semantic.score + severityRank(group.severityMax),
            explanation: semantic.explanation,
            steps_json: JSON.stringify(steps)
          };
        })
    },
    users(limit: number): UserActivitySummary[] {
      const groups = new Map<
        string,
        {
          eventCount: number;
          hosts: Set<string>;
          artifactTypes: Set<string>;
          firstSeen: string;
          lastSeen: string;
          severityMax: string;
        }
      >();
      for (const event of events) {
        if (!event.user_name) continue;
        const group =
          groups.get(event.user_name) ??
          {
            eventCount: 0,
            hosts: new Set<string>(),
            artifactTypes: new Set<string>(),
            firstSeen: event.event_time_utc,
            lastSeen: event.event_time_utc,
            severityMax: event.severity
          };
        group.eventCount += 1;
        if (event.host) group.hosts.add(event.host);
        group.artifactTypes.add(event.artifact_type);
        group.firstSeen = event.event_time_utc < group.firstSeen ? event.event_time_utc : group.firstSeen;
        group.lastSeen = event.event_time_utc > group.lastSeen ? event.event_time_utc : group.lastSeen;
        group.severityMax = maxSeverity(group.severityMax, event.severity);
        groups.set(event.user_name, group);
      }
      return Array.from(groups.entries())
        .sort((left, right) => right[1].eventCount - left[1].eventCount)
        .slice(0, limit)
        .map(([userName, group]) => ({
          case_id: 'case_mock',
          user_name: userName,
          event_count: group.eventCount,
          host_count: group.hosts.size,
          artifact_types: Array.from(group.artifactTypes).join(', '),
          first_seen_utc: group.firstSeen,
          last_seen_utc: group.lastSeen,
          severity_max: group.severityMax
        }));
    }
  };
}

function parseMockAttributes(attributesJson: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(attributesJson);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function numericMockAttr(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function compareEventRows(sortBy: EventSortBy, sortDir: EventSortDir) {
  const dir = sortDir === 'desc' ? -1 : 1;
  return (left: EventRow, right: EventRow) => {
    const leftValue = eventSortValue(left, sortBy);
    const rightValue = eventSortValue(right, sortBy);
    const primary =
      typeof leftValue === 'number' && typeof rightValue === 'number'
        ? leftValue - rightValue
        : String(leftValue).localeCompare(String(rightValue));
    if (primary !== 0) return primary * dir;
    return left.event_id.localeCompare(right.event_id);
  };
}

function eventSortValue(row: EventRow, sortBy: EventSortBy): string | number {
  if (sortBy === 'severity') return severityRank(row.severity);
  if (sortBy === 'artifact_type') return row.artifact_type;
  if (sortBy === 'host') return row.host ?? '';
  if (sortBy === 'user_name') return row.user_name ?? '';
  if (sortBy === 'process_name') return row.process_name ?? '';
  if (sortBy === 'file_path') return row.file_path ?? '';
  if (sortBy === 'ip') return row.ip ?? '';
  if (sortBy === 'url') return row.url ?? '';
  if (sortBy === 'hash') return row.hash ?? '';
  if (sortBy === 'event_code') return row.event_code ?? '';
  if (sortBy === 'channel') return row.channel ?? '';
  if (sortBy === 'level') return row.level ?? '';
  if (sortBy === 'event_action') return row.event_action;
  if (sortBy === 'message_short') return row.message_short;
  if (sortBy === 'parser_name') return row.parser_name;
  return row.event_time_utc;
}

type MockEntityBuild = EntityRecord & { eventIds: Set<string> };
type MockEdgeBuild = EdgeRecord & { evidenceIds: Set<string> };

function buildMockGraph(events: EventRow[], details: Map<string, EventDetailLight>): Subgraph {
  const entities = new Map<string, MockEntityBuild>();
  const edges = new Map<string, MockEdgeBuild>();

  const upsertEntity = (
    entityType: string,
    value: string | null | undefined,
    host: string | null | undefined,
    event: EventRow
  ) => {
    const displayName = value?.trim() ?? '';
    const canonical = displayName.toLowerCase();
    if (!canonical || canonical === '-') return null;
    const entityId = mockEntityId(entityType, canonical);
    const row =
      entities.get(entityId) ??
      {
        entity_id: entityId,
        case_id: 'case_mock',
        entity_type: entityType,
        canonical_value: canonical,
        display_name: displayName,
        host: host ?? null,
        first_seen_utc: event.event_time_utc,
        last_seen_utc: event.event_time_utc,
        event_count: 0,
        attributes_json: '{}',
        eventIds: new Set<string>()
      };
    row.host ??= host ?? null;
    row.first_seen_utc =
      row.first_seen_utc && row.first_seen_utc < event.event_time_utc ? row.first_seen_utc : event.event_time_utc;
    row.last_seen_utc =
      row.last_seen_utc && row.last_seen_utc > event.event_time_utc ? row.last_seen_utc : event.event_time_utc;
    row.eventIds.add(event.event_id);
    row.event_count = row.eventIds.size;
    entities.set(entityId, row);
    return entityId;
  };

  const upsertEdge = (edgeType: string, src: string | null, dst: string | null, event: EventRow) => {
    if (!src || !dst) return;
    const edgeId = mockEntityId('edge', `${src}|${dst}|${edgeType}`);
    const row =
      edges.get(edgeId) ??
      {
        edge_id: edgeId,
        case_id: 'case_mock',
        src_entity_id: src,
        dst_entity_id: dst,
        edge_type: edgeType,
        first_seen_utc: event.event_time_utc,
        last_seen_utc: event.event_time_utc,
        confidence: 0.5,
        evidence_event_ids_json: '[]',
        attributes_json: '{}',
        evidenceIds: new Set<string>()
      };
    row.first_seen_utc =
      row.first_seen_utc && row.first_seen_utc < event.event_time_utc ? row.first_seen_utc : event.event_time_utc;
    row.last_seen_utc =
      row.last_seen_utc && row.last_seen_utc > event.event_time_utc ? row.last_seen_utc : event.event_time_utc;
    if (row.evidenceIds.size < 50) row.evidenceIds.add(event.event_id);
    row.evidence_event_ids_json = JSON.stringify(Array.from(row.evidenceIds));
    edges.set(edgeId, row);
  };

  for (const event of events) {
    const detail = details.get(event.event_id);
    const host = event.host ?? null;
    const idHost = upsertEntity('host', event.host, host, event);
    const idUser = upsertEntity('user', event.user_name, host, event);
    const idProcess = upsertEntity('process', detail?.process_name, host, event);
    const idFile = upsertEntity('file', detail?.file_path, host, event);
    const idIp = upsertEntity('ip', detail?.ip, host, event);
    const idUrl = upsertEntity('url', detail?.url, host, event);
    const idHash = upsertEntity('hash', detail?.hash, host, event);
    upsertEdge('user_logged_on_host', idUser, idHost, event);
    upsertEdge('process_touched_file', idProcess, idFile, event);
    upsertEdge('process_connected_ip', idProcess, idIp, event);
    upsertEdge('file_has_hash', idFile, idHash, event);
    upsertEdge('event_mentions_entity', idProcess, idUrl, event);
  }

  return {
    nodes: Array.from(entities.values())
      .map(({ eventIds: _eventIds, ...node }) => node)
      .sort((left, right) => right.event_count - left.event_count || left.canonical_value.localeCompare(right.canonical_value)),
    edges: Array.from(edges.values()).map(({ evidenceIds: _evidenceIds, ...edge }) => edge)
  };
}

function mockEntityId(entityType: string, canonical: string): string {
  return `${entityType}_${normalizeKey(canonical).slice(0, 48) || 'value'}`;
}

type MockParsedRecord = {
  artifactType: string;
  time: string;
  timeConfidence: number;
  host: string | null;
  userName: string | null;
  processName: string | null;
  filePath: string | null;
  ip: string | null;
  url: string | null;
  hash: string | null;
  eventCode: string | null;
  channel: string | null;
  level: string | null;
  action: string;
  severity: string;
  message: string;
  raw: unknown;
};

function decodeBase64Text(value: string): string {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function decodeBase64TextPreview(value: string): string {
  const base64Chars = Math.ceil(MOCK_UPLOAD_PREVIEW_BYTES / 3) * 4;
  const alignedChars = Math.min(value.length, base64Chars - (base64Chars % 4));
  return decodeBase64Text(value.slice(0, alignedChars));
}

async function fileTextPreview(file: File, maxBytes: number): Promise<string> {
  const buffer = await file.slice(0, maxBytes).arrayBuffer();
  return new TextDecoder().decode(buffer);
}

async function fileToBase64(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const chunks: string[] = [];
  const chunkSize = 0xc000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize);
    let binary = '';
    for (let idx = 0; idx < chunk.length; idx += 0x8000) {
      binary += String.fromCharCode(...chunk.subarray(idx, idx + 0x8000));
    }
    chunks.push(btoa(binary));
  }
  return chunks.join('');
}

function formatHexDump(baseOffset: number, bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.subarray(offset, offset + 16);
    const hex = Array.from(chunk, (byte) => byte.toString(16).padStart(2, '0'));
    const left = hex.slice(0, 8).join(' ').padEnd(23, ' ');
    const right = hex.slice(8).join(' ').padEnd(23, ' ');
    const ascii = Array.from(chunk, (byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.')).join('');
    lines.push(`${(baseOffset + offset).toString(16).padStart(8, '0')}  ${left}  ${right}  ${ascii}`);
  }
  return lines.join('\n');
}

function asciiPreview(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) =>
    byte >= 0x20 && byte <= 0x7e || byte === 0x0a || byte === 0x0d || byte === 0x09
      ? String.fromCharCode(byte)
      : '.'
  ).join('');
}

function parseMockArtifact(path: string, content: string, upload: boolean): MockParsedRecord[] {
  const type = detectMockArtifactType(path, content);
  if (!upload || type === 'text_log') {
    return content
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line, index) => ({
        artifactType: 'text_log',
        time: new Date(Date.now() + index * 1000).toISOString(),
        timeConfidence: 0.5,
        host: 'local',
        userName: null,
        processName: null,
        filePath: path,
        ip: null,
        url: null,
        hash: null,
        eventCode: null,
        channel: null,
        level: /ERROR|FAIL/i.test(line) ? 'error' : /WARN/i.test(line) ? 'warning' : 'info',
        action: 'observed',
        severity: /ERROR|FAIL/i.test(line) ? 'high' : /WARN/i.test(line) ? 'medium' : 'info',
        message: line,
        raw: { line }
      }));
  }
  if (type === 'evtx') {
    const records = [...content.matchAll(/<Event[\s\S]*?<\/Event>/g)];
    if (records.length > 0) {
      return records.map((match, index) => {
        const xml = match[0];
        const eventId = xmlValue(xml, 'EventID');
        const level = xmlValue(xml, 'Level') ?? xmlData(xml, 'Level');
        const userName =
          xmlData(xml, 'TargetUserName') ?? xmlData(xml, 'SubjectUserName') ?? xmlData(xml, 'UserName');
        const processName = xmlData(xml, 'NewProcessName') ?? xmlData(xml, 'ProcessName') ?? xmlData(xml, 'Image');
        const time = xml.match(/TimeCreated[^>]*SystemTime="([^"]+)"/)?.[1] ?? null;
        const action = windowsAction(eventId);
        return {
          artifactType: 'evtx',
          time: normalizeMockTime(time, index),
          timeConfidence: time ? 0.95 : 0.4,
          host: xmlValue(xml, 'Computer'),
          userName,
          processName,
          filePath: xmlData(xml, 'TargetFilename') ?? processName,
          ip: xmlData(xml, 'IpAddress') ?? xmlData(xml, 'SourceNetworkAddress'),
          url: xmlData(xml, 'Url') ?? xmlData(xml, 'URL'),
          hash: xmlData(xml, 'Hash') ?? xmlData(xml, 'Hashes'),
          eventCode: eventId,
          channel: xmlValue(xml, 'Channel'),
          level,
          action,
          severity: windowsSeverity(eventId),
          message: `EventID ${eventId ?? '-'} ${action}${userName ? ` user=${userName}` : ''}`,
          raw: { xml }
        };
      });
    }
  }
  if (type === 'mft') {
    const lines = content.split(/\r?\n/).filter(Boolean);
    const headers = splitCsvLine(lines.shift() ?? '').map(normalizeKey);
    const out: MockParsedRecord[] = [];
    for (const [rowIndex, line] of lines.entries()) {
      const cells = splitCsvLine(line);
      const row = new Map(headers.map((header, index) => [header, cells[index] ?? '']));
      const filePath = pick(row, ['fullpath', 'path', 'filepath', 'filename', 'name']) ?? path;
      for (const [column, action] of [
        ['created0x10', 'mft_created'],
        ['lastmodified0x10', 'mft_modified'],
        ['lastrecordchange0x10', 'mft_record_changed'],
        ['lastaccess0x10', 'mft_accessed'],
        ['created', 'mft_created'],
        ['lastmodified', 'mft_modified'],
        ['lastrecordchange', 'mft_record_changed'],
        ['lastaccess', 'mft_accessed']
      ] as const) {
        const value = pick(row, [column]);
        if (!value) continue;
        out.push({
          artifactType: 'mft',
          time: normalizeMockTime(value, rowIndex),
          timeConfidence: 0.9,
          host: null,
          userName: null,
          processName: null,
          filePath,
          ip: null,
          url: null,
          hash: null,
          eventCode: null,
          channel: null,
          level: null,
          action,
          severity: 'info',
          message: `${action}: ${filePath}`,
          raw: Object.fromEntries(row)
        });
      }
    }
    return out;
  }
  if (type === 'prefetch' || type === 'amcache' || type === 'usn_jrnl' || type === 'browser') {
    return parseMockStructuredExport(type, path, content);
  }
  return [];
}

type MockFlatRow = {
  index: number;
  row: Map<string, string>;
  raw: unknown;
};

function parseMockStructuredExport(type: string, path: string, content: string): MockParsedRecord[] {
  const rows = mockFlatRows(content);
  const out: MockParsedRecord[] = [];
  for (const record of rows) {
    if (type === 'prefetch') {
      const filePath =
        pick(record.row, ['fullpath', 'filepath', 'path', 'executable', 'executablename', 'filename', 'sourcefilename']) ??
        path;
      const processName =
        pick(record.row, ['executablename', 'executable', 'processname', 'application']) ?? fileNameFromPath(filePath);
      const runCount = pick(record.row, ['runcount', 'run_count']);
      let emitted = false;
      for (const [column, timeKind] of [
        ['lastrun', 'prefetch_last_run'],
        ['lastruntime', 'prefetch_last_run'],
        ['lastrun0', 'prefetch_last_run'],
        ['previousrun0', 'prefetch_previous_run'],
        ['previousrun1', 'prefetch_previous_run'],
        ['previousrun2', 'prefetch_previous_run'],
        ['previousrun3', 'prefetch_previous_run'],
        ['previousrun4', 'prefetch_previous_run'],
        ['previousrun5', 'prefetch_previous_run'],
        ['previousrun6', 'prefetch_previous_run'],
        ['previousrun7', 'prefetch_previous_run']
      ] as const) {
        const value = pick(record.row, [column]);
        if (!value) continue;
        out.push({
          artifactType: 'prefetch',
          time: normalizeMockTime(value, record.index),
          timeConfidence: 0.95,
          host: pick(record.row, ['computername', 'computer', 'host', 'hostname']),
          userName: pick(record.row, ['username', 'user', 'profile']),
          processName,
          filePath,
          ip: null,
          url: null,
          hash: pick(record.row, ['hash', 'sha1', 'sha256', 'md5']),
          eventCode: null,
          channel: null,
          level: timeKind,
          action: 'process_executed',
          severity: 'info',
          message: `Prefetch execution: ${processName ?? filePath}${runCount ? ` run_count=${runCount}` : ''}`,
          raw: record.raw
        });
        emitted = true;
      }
      if (!emitted) {
        out.push({
          artifactType: 'prefetch',
          time: normalizeMockTime(pick(record.row, ['timestamp', 'datetime', 'time']), record.index),
          timeConfidence: 0.3,
          host: pick(record.row, ['computername', 'computer', 'host', 'hostname']),
          userName: pick(record.row, ['username', 'user', 'profile']),
          processName,
          filePath,
          ip: null,
          url: null,
          hash: pick(record.row, ['hash', 'sha1', 'sha256', 'md5']),
          eventCode: null,
          channel: null,
          level: 'prefetch_observed',
          action: 'process_executed',
          severity: 'info',
          message: `Prefetch execution observed: ${processName ?? filePath}`,
          raw: record.raw
        });
      }
    } else if (type === 'amcache') {
      const filePath =
        pick(record.row, ['fullpath', 'filepath', 'path', 'filename', 'name', 'programname', 'value']) ?? path;
      const processName =
        pick(record.row, ['programname', 'executablename', 'name', 'filename', 'productname']) ??
        fileNameFromPath(filePath);
      out.push({
        artifactType: 'amcache',
        time: normalizeMockTime(
          pick(record.row, [
            'lastwritetimestamp',
            'lastwrite',
            'lastmodified',
            'lastmodifiedtime',
            'timestamp',
            'datetime',
            'created',
            'firstseen'
          ]),
          record.index
        ),
        timeConfidence: 0.9,
        host: pick(record.row, ['computername', 'computer', 'host', 'hostname']),
        userName: pick(record.row, ['username', 'user', 'profile']),
        processName,
        filePath,
        ip: null,
        url: null,
        hash: pick(record.row, ['sha1', 'sha256', 'md5', 'hash']),
        eventCode: null,
        channel: null,
        level: null,
        action: 'amcache_program_seen',
        severity: 'info',
        message: `Amcache program observed: ${processName ?? filePath}`,
        raw: record.raw
      });
    } else if (type === 'usn_jrnl') {
      const filePath = pick(record.row, ['fullpath', 'filepath', 'path', 'filename', 'name']) ?? path;
      const reason = pick(record.row, ['reason', 'reasons']);
      const action = mockUsnAction(reason);
      out.push({
        artifactType: 'usn_jrnl',
        time: normalizeMockTime(
          pick(record.row, ['timestamp', 'datetime', 'time', 'date', 'eventtime', 'usntime', 'changedtime']),
          record.index
        ),
        timeConfidence: 0.9,
        host: pick(record.row, ['computername', 'computer', 'host', 'hostname']),
        userName: pick(record.row, ['username', 'user']),
        processName: null,
        filePath,
        ip: null,
        url: null,
        hash: null,
        eventCode: null,
        channel: null,
        level: reason,
        action,
        severity: action === 'usn_deleted' || action === 'usn_renamed' ? 'medium' : 'info',
        message: `USN ${action}: ${filePath}${reason ? ` reason=${reason}` : ''}`,
        raw: record.raw
      });
    } else if (type === 'browser') {
      const url = pick(record.row, ['url', 'typedurl', 'destinationurl', 'sourceurl', 'downloadurl']);
      const title = pick(record.row, ['title', 'pagetitle', 'name']);
      const filePath =
        pick(record.row, ['targetfilename', 'downloadpath', 'downloadfilepath', 'fullpath', 'filepath', 'path', 'filename']) ??
        (url ? fileNameFromUrl(url) : null);
      out.push({
        artifactType: 'browser',
        time: normalizeMockTime(
          pick(record.row, [
            'visittime',
            'lastvisittime',
            'lastvisit',
            'lastvisited',
            'timestamp',
            'datetime',
            'time',
            'visitdate',
            'lastaccessed'
          ]),
          record.index
        ),
        timeConfidence: 0.9,
        host: pick(record.row, ['computername', 'computer', 'host', 'hostname']),
        userName: pick(record.row, ['username', 'user', 'profile']),
        processName: null,
        filePath,
        ip: null,
        url,
        hash: pick(record.row, ['sha1', 'sha256', 'md5', 'hash']),
        eventCode: null,
        channel: null,
        level: null,
        action: 'browser_visit',
        severity: 'info',
        message: url ? `Browser visit: ${url}${title ? ` title=${title}` : ''}` : `Browser visit: ${title ?? path}`,
        raw: record.raw
      });
    }
  }
  return out;
}

function mockFlatRows(content: string): MockFlatRow[] {
  const trimmed = content.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      const values = Array.isArray(parsed) ? parsed : [parsed];
      return values.map((value, index) => {
        const row = new Map<string, string>();
        flattenMockJson(value, row);
        return { index: index + 1, row, raw: value };
      });
    } catch {
      return [];
    }
  }
  const lines = content.split(/\r?\n/).filter(Boolean);
  const headers = splitCsvLine(lines.shift() ?? '').map(normalizeKey);
  return lines.map((line, index) => {
    const cells = splitCsvLine(line);
    const row = new Map(headers.map((header, cellIndex) => [header, cells[cellIndex] ?? '']));
    return { index: index + 1, row, raw: Object.fromEntries(row) };
  });
}

function flattenMockJson(value: unknown, out: Map<string, string>): void {
  if (Array.isArray(value)) {
    for (const item of value) flattenMockJson(item, out);
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (item && typeof item === 'object') {
      flattenMockJson(item, out);
    } else if (item !== null && item !== undefined) {
      out.set(normalizeKey(key), String(item));
    }
  }
}

function mockHasFinding(record: MockParsedRecord): boolean {
  const hay = [
    record.processName,
    record.filePath,
    record.ip,
    record.url,
    record.hash,
    record.action,
    record.message,
    JSON.stringify(record.raw)
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  const contains = (needles: string[]) => needles.some((needle) => hay.includes(needle));
  return (
    contains(['rundll32', 'regsvr32', 'mshta', 'wmic', 'certutil', 'bitsadmin', 'cscript', 'wscript']) ||
    contains(['\\temp\\', '\\appdata\\local\\temp', '/tmp/']) ||
    contains(['mimikatz', 'procdump', 'lsass']) ||
    contains(['-enc', '-encodedcommand', ' bypass', 'downloadstring', 'iex(']) ||
    ((hay.includes('http://') || hay.includes('https://') || hay.includes('ftp://')) &&
      contains(['.exe', '.ps1', '.scr', '.dll']))
  );
}

function detectMockArtifactType(path: string, content: string): string {
  const lower = path.toLowerCase();
  const header = content.split(/\r?\n/).find(Boolean) ?? '';
  const normalizedHeader = normalizeKey(header);
  if (
    lower.endsWith('.pf') ||
    lower.includes('prefetch') ||
    lower.includes('pecmd') ||
    ((normalizedHeader.includes('executable') || normalizedHeader.includes('sourcefilename')) &&
      (normalizedHeader.includes('runcount') ||
        normalizedHeader.includes('lastrun') ||
        normalizedHeader.includes('previousrun')))
  ) {
    return 'prefetch';
  }
  if (
    lower.includes('amcache') ||
    ((normalizedHeader.includes('sha1') || normalizedHeader.includes('sha256')) &&
      (normalizedHeader.includes('programname') ||
        normalizedHeader.includes('filepath') ||
        normalizedHeader.includes('fullpath') ||
        normalizedHeader.includes('path')))
  ) {
    return 'amcache';
  }
  if (
    lower.includes('usnjrnl') ||
    lower.includes('$j') ||
    (lower.includes('usn') && lower.endsWith('.csv')) ||
    (normalizedHeader.includes('usn') &&
      normalizedHeader.includes('reason') &&
      (normalizedHeader.includes('filename') || normalizedHeader.includes('filereference')))
  ) {
    return 'usn_jrnl';
  }
  if (
    lower.includes('browser') ||
    lower.includes('places.sqlite') ||
    (lower.includes('history') && lower.endsWith('.csv')) ||
    (normalizedHeader.includes('url') &&
      (normalizedHeader.includes('visit') ||
        normalizedHeader.includes('lastvisit') ||
        normalizedHeader.includes('title')))
  ) {
    return 'browser';
  }
  if (lower.includes('$mft') || lower.includes('mft') || normalizedHeader.includes('entrynumber')) {
    return 'mft';
  }
  if (lower.endsWith('.evtx') || lower.endsWith('.xml') || content.includes('<EventID') || normalizedHeader.includes('eventid')) {
    return 'evtx';
  }
  if (/\.(txt|log|fake)$/i.test(path)) {
    return 'text_log';
  }
  return lower.split('.').pop() || 'unknown';
}

function normalizeMockTime(value: string | null, offset: number): string {
  if (!value) return new Date(Date.now() + offset * 1000).toISOString();
  const integer = value.trim().split('.')[0];
  if (/^\d{10,}$/.test(integer)) {
    const numeric = BigInt(integer);
    const seconds =
      integer.length >= 18 && numeric > 116444736000000000n
        ? Number((numeric - 116444736000000000n) / 10000000n)
        : integer.length >= 16 && numeric > 11644473600000000n
          ? Number((numeric - 11644473600000000n) / 1000000n)
          : integer.length >= 16
            ? Number(numeric / 1000000n)
            : integer.length >= 13
              ? Number(numeric / 1000n)
              : Number(numeric);
    if (seconds >= 631152000 && seconds <= 4102444800) {
      return new Date(seconds * 1000).toISOString();
    }
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? new Date(Date.now() + offset * 1000).toISOString() : parsed.toISOString();
}

function xmlValue(xml: string, tag: string): string | null {
  return clean(xml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`))?.[1]);
}

function xmlData(xml: string, name: string): string | null {
  return clean(xml.match(new RegExp(`<Data[^>]*Name="${name}"[^>]*>([\\s\\S]*?)<\\/Data>`))?.[1]);
}

function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let current = '';
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"' && quoted && line[index + 1] === '"') {
      current += '"';
      index += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === ',' && !quoted) {
      out.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  out.push(current.trim());
  return out;
}

function normalizeKey(value: string): string {
  return value.replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function pick(row: Map<string, string>, keys: string[]): string | null {
  for (const key of keys) {
    const value = clean(row.get(normalizeKey(key)));
    if (value) return value;
  }
  return null;
}

function fileNameFromPath(value: string): string | null {
  return clean(value.split(/[\\/]/).pop());
}

function fileNameFromUrl(value: string): string | null {
  const withoutFragment = value.split('#')[0] ?? value;
  const withoutQuery = withoutFragment.split('?')[0] ?? withoutFragment;
  const name = fileNameFromPath(withoutQuery);
  return name?.includes('.') ? name : null;
}

function mockUsnAction(reason: string | null): string {
  const lower = reason?.toLowerCase() ?? '';
  if (lower.includes('delete')) return 'usn_deleted';
  if (lower.includes('rename')) return 'usn_renamed';
  if (lower.includes('create')) return 'usn_created';
  if (lower.includes('overwrite') || lower.includes('extend') || lower.includes('truncate') || lower.includes('data')) {
    return 'usn_modified';
  }
  return 'usn_changed';
}

function clean(value: string | undefined | null): string | null {
  const trimmed = value?.trim();
  if (!trimmed || trimmed === '-' || /^null$/i.test(trimmed)) return null;
  return trimmed;
}

function windowsAction(eventId: string | null): string {
  if (eventId === '4624') return 'logon_success';
  if (eventId === '4625') return 'logon_failure';
  if (eventId === '4688') return 'process_created';
  if (eventId === '1102') return 'audit_log_cleared';
  return 'windows_event';
}

function windowsSeverity(eventId: string | null): string {
  if (eventId === '1102') return 'critical';
  if (eventId === '4625') return 'high';
  return 'info';
}

function maxSeverity(left: string, right: string): string {
  return severityRank(right) > severityRank(left) ? right : left;
}

function severityRank(value: string): number {
  const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return rank[value] ?? 0;
}

function mockJsonList(value: string): string[] {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map((item) => String(item)).filter(Boolean) : [];
  } catch {
    return [];
  }
}

function mockJob(kind: JobRecord['kind']): JobRecord {
  const now = new Date().toISOString();
  return {
    job_id: `job_${Math.random().toString(16).slice(2)}`,
    case_id: 'case_mock',
    kind,
    status: 'succeeded',
    priority: 1,
    progress: 1,
    attempts: 1,
    max_attempts: 3,
    created_at: now,
    updated_at: now,
    started_at: now,
    finished_at: now,
    worker_id: 'mock',
    heartbeat_at: now,
    cancel_requested: false,
    resource_limits_json: '{}',
    payload_json: '{}',
    error_message: null
  };
}
