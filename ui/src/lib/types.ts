export type ParserStatus = 'pending' | 'parsed' | 'failed' | 'unsupported';
export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
export type JobKind =
  | 'intake_file'
  | 'detect_artifact_type'
  | 'parse_artifact'
  | 'build_event_rows'
  | 'build_timeline_bins'
  | 'build_tantivy_index'
  | 'build_answer_candidates'
  | 'extract_entities'
  | 'build_edges'
  | 'build_correlation_chains'
  | 'run_findings'
  | 'import_plaso'
  | 'import_kape'
  | 'run_tika'
  | 'run_yara'
  | 'run_sidecar'
  | 'run_network_sidecar'
  | 'run_credential_sidecar'
  | 'run_document_sidecar'
  | 'run_archive_sidecar';

export interface CaseSummary {
  case_id: string;
  name: string;
  root_path: string;
  created_at: string;
  schema_version: string;
  file_count: number;
  event_count: number;
  failed_parse_count: number;
  unsupported_file_count: number;
}

export interface ClearCaseResult {
  case_root: string;
  removed_paths: string[];
  root_removed: boolean;
}

export interface CaseCustodyProfile {
  case_id: string;
  investigator?: string | null;
  custodian?: string | null;
  organization?: string | null;
  evidence_source?: string | null;
  acquisition_method?: string | null;
  acquired_at?: string | null;
  legal_authority?: string | null;
  chain_of_custody_note?: string | null;
  updated_at: string;
}

export interface FileRecord {
  file_id: string;
  case_id: string;
  parent_file_id?: string | null;
  original_path: string;
  normalized_path: string;
  filename: string;
  extension: string;
  size: number;
  sha256: string;
  artifact_type: string;
  parser_status: ParserStatus;
  event_count: number;
  object_ref: string;
}

export interface EventRow {
  event_id: string;
  case_id: string;
  event_time_utc: string;
  artifact_type: string;
  host?: string | null;
  user_name?: string | null;
  process_name?: string | null;
  file_path?: string | null;
  ip?: string | null;
  url?: string | null;
  hash?: string | null;
  event_code?: string | null;
  channel?: string | null;
  level?: string | null;
  event_action: string;
  severity: string;
  message_short: string;
  source_file_id: string;
  parser_name: string;
  has_finding: boolean;
  command_line?: string | null;
}

export type EventSortBy =
  | 'event_time_utc'
  | 'severity'
  | 'artifact_type'
  | 'host'
  | 'user_name'
  | 'process_name'
  | 'file_path'
  | 'ip'
  | 'url'
  | 'hash'
  | 'event_code'
  | 'channel'
  | 'level'
  | 'event_action'
  | 'message_short'
  | 'command_line'
  | 'parser_name';

export type EventSortDir = 'asc' | 'desc';

export interface EventPageQuery {
  limit?: number | null;
  cursor?: string | null;
  artifact_type?: string | null;
  user_name?: string | null;
  search?: string | null;
  sort_by?: EventSortBy | string | null;
  sort_dir?: EventSortDir | string | null;
}

export interface EventFacetValue {
  field: string;
  value: string;
  count: number;
}

export interface SavedSearch {
  search_id: string;
  case_id: string;
  name: string;
  query: EventPageQuery;
  description?: string | null;
  created_by?: string | null;
  visibility: string;
  shared_with: string[];
  created_at: string;
  updated_at: string;
}

export interface SearchIndexMetadata {
  case_id: string;
  index_version: string;
  indexed_event_count: number;
  updated_at?: string | null;
  build_mode?: string | null;
  appended_event_count?: number | null;
  updated_event_count?: number | null;
  deleted_event_count?: number | null;
}

export interface SearchIndexStatus {
  metadata?: SearchIndexMetadata | null;
  current_event_count: number;
  is_stale: boolean;
  active_job?: JobRecord | null;
}

export interface EventSearchHit {
  event_id: string;
  event_time_utc: string;
  artifact_type: string;
  severity: string;
  event_action: string;
  host?: string | null;
  user_name?: string | null;
  process_name?: string | null;
  file_path?: string | null;
  message_short: string;
  score_basis: string;
}

export interface EventDetailLight {
  event_id: string;
  case_id: string;
  event_time_utc: string;
  event_time_original: string;
  time_kind: string;
  time_confidence: number;
  source_confidence: number;
  artifact_type: string;
  source_file_id: string;
  parse_run_id: string;
  parser_name: string;
  parser_version: string;
  schema_version: string;
  evidence_ref: string;
  host?: string | null;
  user_name?: string | null;
  process_name?: string | null;
  file_path?: string | null;
  ip?: string | null;
  url?: string | null;
  hash?: string | null;
  event_action: string;
  severity: string;
  message_short: string;
  message_full: string;
  raw_record_ref: string;
  attributes_json: string;
}

export interface RawRecord {
  raw_record_ref: string;
  case_id: string;
  event_id: string;
  parse_run_id: string;
  source_file_id: string;
  evidence_ref: string;
  raw_record_json: string;
}

export interface ArtifactObject {
  object_id: string;
  case_id: string;
  event_id: string;
  source_file_id: string;
  parse_run_id: string;
  artifact_type: string;
  object_kind: string;
  object_key: string;
  display_name: string;
  event_time_utc?: string | null;
  evidence_ref: string;
  evidence_offset?: number | null;
  evidence_length?: number | null;
  confidence: number;
  attributes_json: string;
}

export interface EvidenceOffset {
  offset_id: string;
  case_id: string;
  event_id: string;
  source_file_id: string;
  parse_run_id: string;
  object_ref: string;
  label: string;
  structure_kind: string;
  offset: number;
  length: number;
  parser_name: string;
  confidence: number;
  attributes_json: string;
}

export interface LocalPathIngestResult {
  summary: CaseSummary;
  file_count: number;
  skipped_count?: number;
  failed_count: number;
  worker_count?: number;
  errors: string[];
}

export interface LocalPathScanResult {
  file_count: number;
  total_bytes: number;
}

export interface EvidenceRange {
  object_ref: string;
  sha256: string;
  offset: number;
  length: number;
  total_size: number;
  hex_dump: string;
  ascii_preview: string;
  truncated: boolean;
}

export interface EvidenceFindResult {
  offset: number | null;
  total_size: number;
  pattern_len: number;
}

export interface EvidenceVerification {
  file_id: string;
  original_path: string;
  object_ref: string;
  expected_sha256: string;
  actual_sha256?: string | null;
  size: number;
  verified: boolean;
  error_message?: string | null;
  checked_at: string;
}

export interface CustodyManifestVerification {
  manifest_path: string;
  manifest_sha256?: string | null;
  computed_manifest_sha256?: string | null;
  manifest_hash_ok: boolean;
  manifest_type_ok: boolean;
  case_id_matches: boolean;
  evidence_file_count: number;
  evidence_hash_checked_count: number;
  evidence_hash_mismatch_count: number;
  audit_log_sha256_at_generation?: string | null;
  current_audit_log_sha256?: string | null;
  audit_log_unchanged: boolean;
  checked_at: string;
  error_message?: string | null;
}

export interface ReportBundleVerification {
  bundle_path: string;
  bundle_sha256?: string | null;
  computed_bundle_sha256?: string | null;
  bundle_hash_ok: boolean;
  bundle_type_ok: boolean;
  case_id_matches: boolean;
  report_path?: string | null;
  report_sha256_at_generation?: string | null;
  current_report_sha256?: string | null;
  report_hash_ok: boolean;
  custody_manifest_path?: string | null;
  custody_manifest_sha256_at_generation?: string | null;
  current_custody_manifest_sha256?: string | null;
  custody_manifest_hash_ok: boolean;
  custody_manifest_internal_hash_ok: boolean;
  custody_manifest_type_ok: boolean;
  case_custody_profile_sha256_at_generation?: string | null;
  current_case_custody_profile_sha256?: string | null;
  case_custody_profile_hash_ok: boolean;
  signature_algorithm?: string | null;
  signature_key_id?: string | null;
  signature_present: boolean;
  signature_payload_hash_ok: boolean;
  signature_valid: boolean;
  signature_key_matches_case_key: boolean;
  audit_log_sha256_at_generation?: string | null;
  current_audit_log_sha256?: string | null;
  audit_log_unchanged: boolean;
  checked_at: string;
  error_message?: string | null;
}

export interface EventContextGroup {
  label: string;
  relation: string;
  value: string;
  rows: EventRow[];
}

export interface EventContext {
  anchor: EventDetailLight;
  groups: EventContextGroup[];
}

export interface EventExportResult {
  output_path: string;
  format: string;
  row_count: number;
  truncated: boolean;
}

export interface TimelineBin {
  case_id: string;
  granularity: string;
  bin_start_utc: string;
  artifact_type: string;
  event_count: number;
  severity_max?: string | null;
}

export interface EventTimelineBin {
  bin_start_utc: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface TimestompPoint {
  file_path: string;
  si_created_utc: string;
  fn_created_utc: string;
  delta_seconds: number;
  mismatch: boolean;
}

export interface ProcessTreeEdge {
  parent: string;
  child: string;
  count: number;
}

export interface ProcessNode {
  key: string;
  parent_key: string | null;
  name: string;
  image: string | null;
  pid: string | null;
  guid: string | null;
  command_line: string | null;
  hash: string | null;
  user_name: string | null;
  first_seen_utc: string | null;
  event_id: string;
  severity: string | null;
  has_finding: boolean;
  finding_titles: string[];
  attack: string[];
}

export interface ProcessRelatedEvent {
  event_id: string;
  event_time_utc: string | null;
  artifact_type: string;
  event_action: string;
  message: string | null;
}

export interface FileOpBin {
  bin_start_utc: string;
  created: number;
  deleted: number;
  renamed: number;
  modified: number;
}

export interface BeaconIntervalBin {
  label: string;
  lower_seconds: number;
  upper_seconds: number;
  count: number;
  top_ip?: string | null;
}

export interface EntityRecord {
  entity_id: string;
  case_id: string;
  entity_type: string;
  canonical_value: string;
  display_name: string;
  host?: string | null;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
  event_count: number;
  attributes_json: string;
}

export interface EdgeRecord {
  edge_id: string;
  case_id: string;
  src_entity_id: string;
  dst_entity_id: string;
  edge_type: string;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
  confidence: number;
  evidence_event_ids_json: string;
  attributes_json: string;
}

export interface Subgraph {
  nodes: EntityRecord[];
  edges: EdgeRecord[];
}

export interface CoverageSummary {
  case_id: string;
  artifact_type: string;
  total_files: number;
  parsed_files: number;
  failed_files: number;
  unsupported_files: number;
  event_count: number;
}

export interface FailedParserSummary {
  case_id: string;
  parser_name: string;
  artifact_type: string;
  failure_count: number;
  last_error: string;
  last_seen_at: string;
}

export interface FindingSummary {
  case_id: string;
  title: string;
  severity: string;
  engine: string;
  rule_id?: string | null;
  attack_json: string;
  finding_count: number;
  event_count: number;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
  sample_message?: string | null;
  enrichment_json?: string | null;
  affected_entities?: string[];
}

export interface AnswerCandidate {
  candidate_id: string;
  case_id: string;
  question_key: string;
  question_label: string;
  candidate_value: string;
  confidence: number;
  status: string;
  severity: string;
  category: string;
  reason: string;
  evidence_event_ids_json: string;
  evidence_refs_json: string;
  missing_steps_json: string;
  next_action?: string | null;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
  attributes_json: string;
}

export interface DetectionObjectiveEvaluation {
  objective_id: string;
  objective_name: string;
  status: string;
  severity_max?: string | null;
  finding_count: number;
  event_count: number;
  artifact_types: string;
  attack_techniques: string;
  evidence_note: string;
}

export interface CaseQualityGate {
  gate_id: string;
  category: string;
  status: string;
  severity: string;
  title: string;
  detail: string;
  metric: string;
  recommended_action: string;
}

export interface CaseDetectionEvaluation {
  case_id: string;
  evaluated_at: string;
  overall_score: number;
  detection_coverage_rate: number;
  investigation_readiness_score: number;
  report_quality_score: number;
  applicable_objective_count: number;
  covered_objective_count: number;
  partial_objective_count: number;
  missing_objective_count: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  confirmed_findings: number;
  open_findings: number;
  unreviewed_high_findings: number;
  correlation_chain_count: number;
  high_correlation_chain_count: number;
  risk_technique_count: number;
  parsed_file_rate: number;
  evidence_verification_rate: number;
  parser_gap_count: number;
  unsupported_file_count: number;
  report_gap_count: number;
  objectives: DetectionObjectiveEvaluation[];
  quality_gates: CaseQualityGate[];
}

export interface IocHit {
  case_id: string;
  ioc: string;
  match_kind: string;
  hit_count: number;
  artifact_types: string;
  event_ids_json: string;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
}

export interface DefenderSummary {
  case_id: string;
  category: string;
  severity_max?: string | null;
  event_count: number;
  artifact_types: string;
  first_seen_utc: string;
  last_seen_utc: string;
  sample_message?: string | null;
}

export interface PrefetchSummary {
  case_id: string;
  process_name: string;
  file_path?: string | null;
  prefetch_file_name?: string | null;
  prefetch_hash?: string | null;
  run_count_max?: number | null;
  referenced_file_count_max?: number | null;
  source_file_count: number;
  event_count: number;
  first_seen_utc: string;
  last_seen_utc: string;
  severity_max?: string | null;
  actions: string;
  suspicion?: string | null;
  sample_message?: string | null;
}

export interface FindingOverride {
  override_id: string;
  case_id: string;
  enabled: boolean;
  action: 'suppress' | 'severity_override' | string;
  engine?: string | null;
  rule_id?: string | null;
  title?: string | null;
  severity?: string | null;
  reason?: string | null;
  created_at: string;
}

export type FindingReviewStatus =
  | 'new'
  | 'in_review'
  | 'confirmed'
  | 'false_positive'
  | 'benign'
  | 'needs_context';

export interface FindingReview {
  review_id: string;
  case_id: string;
  engine: string;
  rule_id?: string | null;
  title: string;
  status: FindingReviewStatus | string;
  reviewer?: string | null;
  assignee?: string | null;
  tags_json?: string | null;
  due_at?: string | null;
  comment?: string | null;
  created_at: string;
  updated_at: string;
}

export type CaseApprovalStatus = 'pending' | 'approved' | 'rejected' | 'revoked';

export interface CaseApprovalRecord {
  approval_id: string;
  case_id: string;
  target_kind: string;
  target_id?: string | null;
  target_path?: string | null;
  target_sha256?: string | null;
  status: CaseApprovalStatus | string;
  approver?: string | null;
  role?: string | null;
  comment?: string | null;
  created_at: string;
  updated_at: string;
}

export interface FindingReviewSummary {
  case_id: string;
  total_reviews: number;
  new_count: number;
  in_review_count: number;
  confirmed_count: number;
  false_positive_count: number;
  benign_count: number;
  needs_context_count: number;
  open_count: number;
  overdue_count: number;
  unassigned_count: number;
  tagged_count: number;
  updated_at: string;
}

export interface TriageAction {
  action_id: string;
  case_id: string;
  priority: number;
  category: string;
  title: string;
  reason: string;
  severity: string;
  status: string;
  source_kind: string;
  source_key: string;
  event_count: number;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
  evidence_json: string;
}

export interface AuditLogEntry {
  audit_id: string;
  case_id: string;
  occurred_at: string;
  actor: string;
  action: string;
  target_kind: string;
  target_id?: string | null;
  summary: string;
  metadata_json: string;
}

export interface EventBookmark {
  bookmark_id: string;
  case_id: string;
  event_id: string;
  label?: string | null;
  note?: string | null;
  created_at: string;
}

export interface RiskSummary {
  case_id: string;
  technique: string;
  severity_max?: string | null;
  finding_count: number;
  event_count: number;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
}

export interface AnalyzerRunSummary {
  run_id: string;
  case_id: string;
  analyzer_id: string;
  name: string;
  version: string;
  status: string;
  started_at: string;
  finished_at?: string | null;
  input_count: number;
  output_count: number;
  error_message?: string | null;
  metadata_json: string;
}

export interface CorrelationSummary {
  case_id: string;
  key_kind: string;
  key_value: string;
  user_name?: string | null;
  host?: string | null;
  ip?: string | null;
  file_path?: string | null;
  artifact_types: string;
  event_count: number;
  first_seen_utc: string;
  last_seen_utc: string;
  severity_max?: string | null;
  explanation: string;
}

export interface CorrelationChainSummary {
  case_id: string;
  key_kind: string;
  key_value: string;
  title: string;
  severity: string;
  artifact_types: string;
  event_count: number;
  step_count: number;
  first_seen_utc: string;
  last_seen_utc: string;
  severity_max?: string | null;
  score: number;
  explanation: string;
  steps_json: string;
}

export interface UserActivitySummary {
  case_id: string;
  user_name: string;
  event_count: number;
  host_count: number;
  artifact_types: string;
  first_seen_utc: string;
  last_seen_utc: string;
  severity_max?: string | null;
}

export interface JobRecord {
  job_id: string;
  case_id: string;
  kind: JobKind;
  status: JobStatus;
  priority: number;
  progress: number;
  attempts: number;
  max_attempts: number;
  created_at: string;
  updated_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  worker_id?: string | null;
  heartbeat_at?: string | null;
  cancel_requested: boolean;
  resource_limits_json: string;
  payload_json: string;
  error_message?: string | null;
}

export interface SidecarBatchResult {
  queued_count: number;
  executed_count: number;
  succeeded_count: number;
  failed_count: number;
  skipped_count: number;
  jobs: JobRecord[];
  tool_status_json: string;
}

export interface Page<T> {
  rows: T[];
  next_cursor?: string | null;
}
