<script lang="ts">
  import { tick, onMount } from 'svelte';
  import NavIcon from './lib/NavIcon.svelte';
  import { attackName } from './lib/attack';
  import {
    createCase,
    clearCaseWorkspace,
    addEventBookmark,
    getCaseCustodyProfile,
    getCorrelationChainEventPage,
    getCorrelationChains,
    getBookmarkEventPage,
    getCorrelationSummary,
    getCoverageSummary,
    getDefenderEventPage,
    getDefenderSummary,
    getAuditLog,
    exportEvents,
    generateReportBundle,
    getCaseSummary,
    getEventContext,
    getEventArtifactObjects,
    getEventDetailLight,
    getEventEvidenceOffsets,
    getEventFacets,
    getEvidenceRange,
    findEvidenceMatch,
    getEventPage,
    getEventRawRecord,
    getEventBookmarks,
    getFailedParserSummary,
    getFilePage,
    generateCustodyManifest,
    verifyCustodyManifest,
    verifyReportBundle,
    getAnalyzerRuns,
    getCaseApprovals,
    getEntitySummary,
    getFindingEventPage,
    getFindingOverrides,
    getFindingReviewSummary,
    getFindingReviews,
    getFindingSummary,
    getAnswerCandidates,
    getIocEventPage,
    getIocMatches,
    getPrefetchSummary,
    getRecentJobs,
    getRiskSummary,
    getSavedSearches,
    getSearchIndexStatus,
    getSubgraph,
    getTimelineBins,
    getEventTimeline,
    getTimestompScatter,
    getProcessTree,
    getProcessTreeInstances,
    getProcessRelatedEvents,
    getFileOpTimeline,
    getBeaconIntervals,
    getTriageActions,
    getUserActivitySummary,
    ingestFakeArtifact,
    ingestLocalPath,
    ingestUploadedFile,
    runIocFindings,
    searchIndexedEvents,
    scanLocalPath,
    selectCaseDirectory,
    selectIngestDirectory,
    startAnswerCandidateBuild,
    startAnalysisReadModelJobs,
    startSearchIndexBuild,
    addFindingOverride,
    setCaseApproval,
    setCaseCustodyProfile,
    setFindingReview,
    verifyEvidencePage,
	    saveSavedSearch,
	    deleteSavedSearch,
    getCaseDetectionEvaluation,
    removeFindingOverride,
    removeEventBookmark,
    rebuildAnalysisReadModels,
    openCase
  } from './lib/api';
  import type {
    AnswerCandidate,
    AuditLogEntry,
    CaseApprovalRecord,
    CaseApprovalStatus,
    CaseCustodyProfile,
    CaseDetectionEvaluation,
    CaseSummary,
    CorrelationChainSummary,
    CorrelationSummary,
    CoverageSummary,
    CustodyManifestVerification,
    DefenderSummary,
    EntityRecord,
    EventBookmark,
    EventContext,
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
    JobRecord,
    PrefetchSummary,
    RawRecord,
    ReportBundleVerification,
    RiskSummary,
    SavedSearch,
    SearchIndexMetadata,
    SearchIndexStatus,
    Subgraph,
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
  } from './lib/types';
  import { locale, t, fontScale, LOCALES, FONT_SCALES } from './lib/i18n';

  type Tab =
    | 'overview'
    | 'evidence_ledger'
    | 'files'
    | 'hex'
    | 'coverage'
    | 'timeline'
    | 'events'
    | 'saved_searches'
    | 'search_index'
    | 'triage'
    | 'evaluation'
    | 'answers'
    | 'findings'
    | 'ioc'
    | 'defender'
    | 'risk'
    | 'correlation'
    | 'chains'
    | 'graph'
    | 'process_tree'
    | 'artifact_mft'
    | 'artifact_prefetch'
    | 'artifact_usn'
    | 'artifact_amcache'
    | 'artifact_srum'
    | 'artifact_text_observation'
    | 'artifact_registry'
    | 'users'
    | 'bookmarks'
    | 'approvals'
    | 'audit'
    | 'analyzers'
    | 'jobs'
    | 'settings';
  type ArtifactTab =
    | 'artifact_mft'
    | 'artifact_prefetch'
    | 'artifact_usn'
    | 'artifact_amcache'
    | 'artifact_srum'
    | 'artifact_text_observation'
    | 'artifact_registry';
  type DetailTab = 'summary' | 'context' | 'raw' | 'evidence';
  type EventSubtab = 'all' | 'users';
  type NavIconName =
    | 'bar-chart-2'
    | 'alert-triangle'
    | 'list'
    | 'clock'
    | 'share-2'
    | 'git-branch'
    | 'git-merge'
    | 'target'
    | 'trending-up'
    | 'database'
    | 'play'
    | 'rotate-ccw'
    | 'table'
    | 'line-chart'
    | 'code'
    | 'user'
    | 'bookmark'
    | 'folder'
    | 'settings'
    | 'search'
    | 'hash'
    | 'clipboard-list'
    | 'file-question'
    | 'check-circle'
    | 'crosshair'
    | 'shield'
    | 'gauge'
    | 'file-text'
    | 'list-check'
    | 'activity'
    | 'server-cog';
  type ViewState = {
    tab: Tab;
    eventSubtab: EventSubtab;
  };
  type ArtifactView = {
    label: string;
    artifactType: string;
  };
  type ArtifactEventColumn = {
    label: string;
    sortBy?: EventSortBy;
    className?: string;
    kind?: 'severity';
    width?: number;
    minWidth?: number;
    value: (row: EventRow) => string | null | undefined;
  };
  type ArtifactEventStats = {
    loaded: number;
    findings: number;
    highPriority: number;
    hosts: number;
    users: number;
  };
  type ArtifactQuickFilter = {
    id: string;
    label: string;
    query: string;
  };
  type DetailField = {
    label: string;
    value: string;
    className?: string;
    pivot?: PivotField;
  };
  type PivotField = 'file' | 'process' | 'hash' | 'ip' | 'url' | 'user' | 'host';
  type PivotAction = {
    label: string;
    field: PivotField;
    value: string;
  };
  type FacetGroup = {
    field: string;
    label: string;
    values: EventFacetValue[];
  };

  type OverviewTimelineRow = {
    binStartUtc: string;
    eventCount: number;
    artifactTypes: string[];
    severityMax: string | null;
  };

  type OverviewChartGroup = {
    field: string;
    label: string;
    values: EventFacetValue[];
  };
  type OverviewChartPoint = {
    x: number;
    y: number;
  };
  type CacheRead<T> = {
    hit: boolean;
    value: T | undefined;
  };
  type EventStructureCacheEntry = {
    artifactObjects: ArtifactObject[];
    evidenceOffsets: EvidenceOffset[];
  };
  type PagedList =
    | 'events'
    | 'user_events'
    | 'artifact_events'
    | 'indexed_search'
    | 'evidence_verification'
    | 'finding_events'
    | 'ioc_events'
    | 'defender_events'
    | 'chain_events'
    | 'bookmark_events'
    | 'timeline_events';

  type LoginOutcomeRow = {
    label: string;
    eventCode: string;
    count: number;
    tone: 'success' | 'failure';
  };
  type EventArtifactOption = {
    artifactType: string;
    count: number;
  };
  type IntakeStatusSummary = {
    total: number;
    parsed: number;
    failed: number;
    unsupported: number;
    pending: number;
    events: number;
    bytes: number;
  };

  const eventSortByValues = new Set<EventSortBy>([
    'event_time_utc',
    'severity',
    'artifact_type',
    'host',
    'user_name',
    'process_name',
    'file_path',
    'ip',
    'url',
    'hash',
    'event_code',
    'channel',
    'level',
    'event_action',
    'message_short',
    'parser_name'
  ]);
  const investigationColors = [
    '#4e9e8d', '#46c78f', '#f5b44a', '#c58cff', '#f06f8f', '#47c7d9',
    '#ff9f5a', '#6cb6ff', '#ff7b72', '#7ee787', '#8aa0ff', '#e288d9',
  ];
  const eventDetailCacheLimit = 80;
  const eventContextCacheLimit = 32;
  const eventStructureCacheLimit = 64;

  // DFIR調査フロー順にグループ化(サマリ→探索→検知→相関→ワークフロー→運用)。
  // Registry は artifact なのでトップレベルではなくイベント一覧のサブナビ側に置く。
  // ナビ/ラベルは翻訳キーで持ち、$t で描画時に現在ロケールへ解決する(reactive)。
  $: navGroups = [
    {
      label: $t('nav.summary'),
      items: [
        { id: 'overview' as Tab, label: $t('tab.overview'), icon: 'bar-chart-2' as NavIconName },
        { id: 'timeline' as Tab, label: $t('tab.timeline'), icon: 'clock' as NavIconName },
        { id: 'risk' as Tab, label: $t('tab.risk'), icon: 'target' as NavIconName }
      ]
    },
    {
      label: $t('nav.events'),
      items: [
        { id: 'events' as Tab, label: $t('tab.events'), icon: 'list' as NavIconName },
        { id: 'search_index' as Tab, label: $t('tab.search'), icon: 'hash' as NavIconName },
        { id: 'saved_searches' as Tab, label: $t('tab.saved_searches'), icon: 'search' as NavIconName },
        { id: 'hex' as Tab, label: $t('tab.hex'), icon: 'file-text' as NavIconName }
      ]
    },
    {
      label: $t('nav.detection'),
      items: [
        { id: 'findings' as Tab, label: $t('tab.findings'), icon: 'alert-triangle' as NavIconName },
        { id: 'ioc' as Tab, label: $t('tab.ioc'), icon: 'crosshair' as NavIconName },
        { id: 'defender' as Tab, label: $t('tab.defender'), icon: 'shield' as NavIconName },
        { id: 'answers' as Tab, label: $t('tab.answers'), icon: 'file-question' as NavIconName }
      ]
    },
    {
      label: $t('nav.correlation'),
      items: [
        { id: 'correlation' as Tab, label: $t('tab.correlation'), icon: 'git-branch' as NavIconName },
        { id: 'chains' as Tab, label: $t('tab.chains'), icon: 'git-merge' as NavIconName },
        { id: 'graph' as Tab, label: $t('tab.graph'), icon: 'share-2' as NavIconName },
        { id: 'process_tree' as Tab, label: $t('tab.process_tree'), icon: 'git-merge' as NavIconName }
      ]
    },
    {
      label: $t('nav.workflow'),
      items: [
        { id: 'triage' as Tab, label: $t('tab.triage'), icon: 'clipboard-list' as NavIconName },
        { id: 'bookmarks' as Tab, label: $t('tab.bookmarks'), icon: 'bookmark' as NavIconName },
        { id: 'evaluation' as Tab, label: $t('tab.evaluation'), icon: 'check-circle' as NavIconName },
        { id: 'approvals' as Tab, label: $t('tab.approvals'), icon: 'check-circle' as NavIconName }
      ]
    },
    {
      label: $t('nav.evidence'),
      items: [
        { id: 'evidence_ledger' as Tab, label: $t('tab.evidence_ledger'), icon: 'file-text' as NavIconName },
        { id: 'files' as Tab, label: $t('tab.files'), icon: 'folder' as NavIconName },
        { id: 'coverage' as Tab, label: $t('tab.coverage'), icon: 'gauge' as NavIconName },
        { id: 'audit' as Tab, label: $t('tab.audit'), icon: 'list-check' as NavIconName },
        { id: 'analyzers' as Tab, label: $t('tab.analyzers'), icon: 'activity' as NavIconName },
        { id: 'jobs' as Tab, label: $t('tab.jobs'), icon: 'server-cog' as NavIconName }
      ]
    },
    {
      label: $t('nav.settings'),
      items: [{ id: 'settings' as Tab, label: $t('tab.settings'), icon: 'settings' as NavIconName }]
    }
  ];
  $: tabs = navGroups.flatMap((group) => group.items);
  $: artifactViews = {
    artifact_mft: { label: $t('artifact.mft'), artifactType: 'mft' },
    artifact_prefetch: { label: $t('artifact.prefetch'), artifactType: 'prefetch' },
    artifact_usn: { label: $t('artifact.usn'), artifactType: 'usn_jrnl' },
    artifact_amcache: { label: $t('artifact.amcache'), artifactType: 'amcache' },
    artifact_srum: { label: $t('artifact.srum'), artifactType: 'srum' },
    artifact_text_observation: { label: $t('artifact.text_observation'), artifactType: 'text_observation' },
    artifact_registry: { label: $t('artifact.registry'), artifactType: 'registry' }
  } as Record<ArtifactTab, ArtifactView>;
  $: eventArtifactSubtabs = [
    { id: 'artifact_mft' as ArtifactTab, label: 'MFT', icon: 'database' as NavIconName },
    { id: 'artifact_prefetch' as ArtifactTab, label: 'Prefetch', icon: 'play' as NavIconName },
    { id: 'artifact_usn' as ArtifactTab, label: 'USN', icon: 'rotate-ccw' as NavIconName },
    { id: 'artifact_amcache' as ArtifactTab, label: 'Amcache', icon: 'table' as NavIconName },
    { id: 'artifact_srum' as ArtifactTab, label: 'SRUM', icon: 'line-chart' as NavIconName },
    { id: 'artifact_registry' as ArtifactTab, label: $t('artifact.registry'), icon: 'settings' as NavIconName },
    { id: 'artifact_text_observation' as ArtifactTab, label: $t('artifact.text_observation'), icon: 'file-text' as NavIconName }
  ];

  let activeTab: Tab = 'overview';
  let detailTab: DetailTab = 'summary';
  let eventSubtab: EventSubtab = 'all';
  let viewHistory: ViewState[] = [];
  let caseRoot = '';
  let caseName = 'taotie';
  let artifactPath = 'host/demo.log';
  let artifactContent = 'INFO service started\nWARN unusual login source\nERROR service stopped';
  let localPathInput = '';
  let summary: CaseSummary | null = null;
  let custodyProfile: CaseCustodyProfile | null = null;
  let custodyInvestigator = '';
  let custodyCustodian = '';
  let custodyOrganization = '';
  let custodyEvidenceSource = '';
  let custodyAcquisitionMethod = '';
  let custodyAcquiredAt = '';
  let custodyLegalAuthority = '';
  let custodyChainNote = '';
  let files: FileRecord[] = [];
  let evidenceVerifications: EvidenceVerification[] = [];
  let nextEvidenceVerificationCursor: string | null | undefined = null;
  let custodyManifestPath = '';
  let custodyManifestVerification: CustodyManifestVerification | null = null;
  let reportBundlePath = '';
  let reportBundleVerification: ReportBundleVerification | null = null;
  let caseApprovals: CaseApprovalRecord[] = [];
  let approvalTargetKind = 'report_bundle';
  let approvalTargetPath = '';
  let approvalTargetId = '';
  let approvalStatus: CaseApprovalStatus = 'approved';
  let approvalApprover = 'lead_analyst';
  let approvalRole = 'reviewer';
  let approvalComment = '';
  let coverage: CoverageSummary[] = [];
  let failedParsers: FailedParserSummary[] = [];
  let triageActions: TriageAction[] = [];
  let caseDetectionEvaluation: CaseDetectionEvaluation | null = null;
  let timeline: TimelineBin[] = [];
  let overviewSeverityBins: EventTimelineBin[] = [];
  // グラフタブの高度チャート(バックエンド集計)。
  let timestompPoints: TimestompPoint[] = [];
  let processTreeEdges: ProcessTreeEdge[] = [];
  // 個体単位プロセスツリー(process_tree タブ)。
  let processNodes: ProcessNode[] = [];
  let processTreeStatus = '';
  let processTreeFilter = '';
  let processTreeExpanded: Set<string> = new Set();
  let processDangerOnly = false;
  let selectedProcessNode: ProcessNode | null = null;
  let processRelated: ProcessRelatedEvent[] = [];
  let processRelatedToken = 0;
  let processRelatedLoading = false;
  let fileOpBins: FileOpBin[] = [];
  let beaconBins: BeaconIntervalBin[] = [];
  let timelineSelectedBin: { startUtc: string; label: string } | null = null;
  let timelineWindowStart = '';
  let timelineWindowEnd = '';
  let timelineEventRows: EventRow[] = [];
  let nextTimelineEventCursor: string | null | undefined = null;
  // 強化タイムライン: read-time severity集計チャート + フィルタ + ヒートマップ
  let timelineSeverityBins: EventTimelineBin[] = [];
  let timelineHeatmapBins: EventTimelineBin[] = [];
  let timelineGranularity: 'minute' | 'hour' | 'day' | 'week' = 'hour';
  let timelineView: 'chart' | 'heatmap' = 'chart';
  let timelineSelectedBinData: EventTimelineBin | null = null;
  let timelineSevFilter = '';
  let timelineHostFilter = '';
  let timelineUserFilter = '';
  let timelineSearchText = '';
  let timelineSearchRegex = false;
  let timelineFindingOnly = false;
  // タイムライン上に重畳する finding/IOC/bookmark のマーカー(絶対時刻ベース)
  let timelineMarkersOn = true;
  let timelineFindingMarks: Array<{ t: string; label: string }> = [];
  let timelineIocMarks: Array<{ t: string; label: string }> = [];
  let timelineBookmarkMarks: Array<{ t: string; label: string }> = [];
  let correlations: CorrelationSummary[] = [];
  let correlationChains: CorrelationChainSummary[] = [];
  let correlationStatus = '';
  let correlationChainsStatus = '';
  let selectedChain: CorrelationChainSummary | null = null;
  let chainEventRows: EventRow[] = [];
  let nextChainEventCursor: string | null | undefined = null;
  let entities: EntityRecord[] = [];
  let subgraph: Subgraph = { nodes: [], edges: [] };
  let findings: FindingSummary[] = [];
  let findingOverrides: FindingOverride[] = [];
  let findingReviews: FindingReview[] = [];
  let findingReviewSummary: FindingReviewSummary | null = null;
  let selectedFinding: FindingSummary | null = null;
  let selectedFindingReview: FindingReview | null = null;
  let findingEventRows: EventRow[] = [];
  let nextFindingEventCursor: string | null | undefined = null;
  let answerCandidates: AnswerCandidate[] = [];
  let selectedAnswerCandidate: AnswerCandidate | null = null;
  let answerQuestionFilter = '';
  let reviewStatus: FindingReviewStatus = 'in_review';
  let reviewReviewer = 'analyst';
  let reviewAssignee = '';
  let reviewTags = '';
  let reviewDueAt = '';
  let reviewComment = '';
  let iocInput = 'evil.exe\n10.0.0.5';
  let iocHits: IocHit[] = [];
  let selectedIoc: IocHit | null = null;
  let iocEventRows: EventRow[] = [];
  let nextIocEventCursor: string | null | undefined = null;
  let defenderSummaries: DefenderSummary[] = [];
  let selectedDefenderCategory: DefenderSummary | null = null;
  let defenderEventRows: EventRow[] = [];
  let nextDefenderEventCursor: string | null | undefined = null;
  let prefetchSummaries: PrefetchSummary[] = [];
  let selectedPrefetchSummary: PrefetchSummary | null = null;
  let risks: RiskSummary[] = [];
  let riskStatus = '';
  let users: UserActivitySummary[] = [];
  let bookmarks: EventBookmark[] = [];
  let bookmarkEventRows: EventRow[] = [];
  let nextBookmarkEventCursor: string | null | undefined = null;
  let auditLog: AuditLogEntry[] = [];
  let analyzerRuns: AnalyzerRunSummary[] = [];
  let eventRows: EventRow[] = [];
  let nextEventCursor: string | null | undefined = null;
  let eventFacets: EventFacetValue[] = [];
  let overviewFacets: EventFacetValue[] = [];
  let savedSearches: SavedSearch[] = [];
  let searchIndexMetadata: SearchIndexMetadata | null = null;
  let searchIndexStatus: SearchIndexStatus | null = null;
  let indexedSearchText = '';
  let indexedSearchNotice = '';
  let indexedSearchHits: EventSearchHit[] = [];
  let nextIndexedSearchCursor: string | null | undefined = null;
  let artifactEventRows: EventRow[] = [];
  let nextArtifactEventCursor: string | null | undefined = null;
  let autoPageLoading: PagedList | '' = '';
  let artifactSeverityFilter = '';
  let artifactFindingOnly = false;
  let artifactHighOnly = false;
  let artifactQuickFilter = '';
  let userEventRows: EventRow[] = [];
  let nextUserEventCursor: string | null | undefined = null;
  let jobs: JobRecord[] = [];
  let selectedEvent: EventRow | null = null;
  let investigationTrail: EventRow[] = [];
  let investigationIndex = -1;
  let contextWindowMinutes = 15;
  let contextSameHostOnly = true;
  let selectedEntity: EntityRecord | null = null;
  let selectedUser: UserActivitySummary | null = null;
  let detail: EventDetailLight | null = null;
  let eventContext: EventContext | null = null;
  let rawRecord: RawRecord | null = null;
  let artifactObjects: ArtifactObject[] = [];
  let evidenceOffsets: EvidenceOffset[] = [];
  let evidenceRange: EvidenceRange | null = null;
  let hexFiles: FileRecord[] = [];
  let hexSelectedFile: FileRecord | null = null;
  let hexRange: EvidenceRange | null = null;
  let hexOffset = 0;
  let hexLoading = false;
  let hexError: string | null = null;
  let hexGotoInput = '';
  let hexSearchInput = '';
  let hexSearchHex = false;
  let hexSearchStatus = '';
  let hexSearchBusy = false;
  let evidenceOffset = 0;
  let evidenceLength = 4096;
  let contextLoading = false;
  let rawLoading = false;
  let evidenceLoading = false;
  let detailLoading = false;
  let structureLoading = false;
  let structureLoaded = false;
  let busy = false;
  let errorMessage = '';
  let uploadStatus = '';
  let exportStatus = '';
  let uploadStatusToken = 0;
  let exportStatusToken = 0;
  let exportMenuOpen = false;
  let eventScrollTop = 0;
  let eventSearchText = '';
  let appliedEventSearch = '';
  let eventIdFilter = '';
  let eventIpFilter = '';
  let eventHostFilter = '';
  let eventStartUtc = '';
  let eventEndUtc = '';
  let eventSearchRegex = false;
  let eventArtifactFilter = '';
  let eventUserFilter = '';
  let eventFacetField = '';
  let eventFacetValue = '';
  let savedSearchName = '';
  let savedSearchDescription = '';
  let savedSearchOwner = 'analyst';
  let savedSearchViewer = 'analyst';
  let savedSearchVisibility = 'case';
  let savedSearchSharedWith = '';
  let eventSortBy: EventSortBy = 'event_time_utc';
  let eventSortDir: EventSortDir = 'asc';
  let overrideSeverity = 'low';
  let selectedEventBookmark: EventBookmark | null = null;
  let detailToken = 0;
  let detailLoadTimer: number | null = null;
  let fileInput: HTMLInputElement | null = null;
  let folderInput: HTMLInputElement | null = null;
  let eventScroller: HTMLDivElement | null = null;
  let artifactScroller: HTMLDivElement | null = null;
  let advancedIntakeOpen = false;
  let eventHorizontalScroll = 0;
  let artifactScrollTop = 0;
  // 既定は通常画面にほぼ収まる幅(合計を詰めて右見切れを軽減)。Message は長文なので
  // 既定は控えめにし、必要なら列リサイズで広げられる(全文は下の調査ペインに表示)。
  // 列: Time / EventID / Severity / Type / Host / User / Process / Command / Message(最右・可変)
  const eventColumnStandardWidths = [170, 74, 72, 104, 122, 122, 180, 224, 260];
  const eventColumnMinWidths = [148, 64, 62, 84, 92, 92, 130, 140, 220];
  let eventColumnWidths = [...eventColumnStandardWidths];
  let eventColumnResize:
    | {
        index: number;
        startX: number;
        startWidth: number;
      }
    | null = null;
  let artifactColumnWidths: Record<string, number[]> = {};
  let artifactColumnResize:
    | {
        artifactType: string;
        index: number;
        startX: number;
        startWidth: number;
      }
    | null = null;
  let intakeActive = false;
  let intakeTotal = 0;
  let intakeCompleted = 0;
  let intakeBaselineFileCount = 0;
  let intakeCurrentPath = '';
  let intakeCurrentSize = 0;
  let intakeFinalizePending = false;
  let intakeCompleteVisible = false;
  let intakeHideTimer: number | null = null;
  let intakeJobPollTimer: number | null = null;
  let eventDetailCache = new Map<string, EventDetailLight | null>();
  let eventContextCache = new Map<string, EventContext | null>();
  let eventStructureCache = new Map<string, EventStructureCacheEntry>();

  const rowHeight = 42;
  let eventViewportPx = 470;
  $: eventViewportRows = Math.max(10, Math.ceil(eventViewportPx / rowHeight) + 2);
  const artifactRowHeight = 42;
  const artifactViewportRows = 18;
  const artifactEventPageSize = 200;

  $: visibleStart = Math.max(0, Math.floor(eventScrollTop / rowHeight) - 6);
  $: visibleEnd = Math.min(eventRows.length, visibleStart + eventViewportRows + 12);
  $: visibleEventRows = eventRows.slice(visibleStart, visibleEnd);
  $: topPad = visibleStart * rowHeight;
  $: bottomPad = Math.max(0, (eventRows.length - visibleEnd) * rowHeight);
  $: visibleArtifactStart = Math.max(0, Math.floor(artifactScrollTop / artifactRowHeight) - 6);
  $: visibleArtifactEnd = Math.min(artifactEventRows.length, visibleArtifactStart + artifactViewportRows + 12);
  $: visibleArtifactRows = artifactEventRows.slice(visibleArtifactStart, visibleArtifactEnd);
  $: artifactTopPad = visibleArtifactStart * artifactRowHeight;
  $: artifactBottomPad = Math.max(0, (artifactEventRows.length - visibleArtifactEnd) * artifactRowHeight);
  // 最終列(Message)は minmax(px,1fr) で余白を吸収=表を右端まで詰める(見切れ防止)。
  // 他列は固定px。キャンバスは width:100% で container 幅にフィットし、狭いときは
  // min-width(=全列最小幅の合計)で水平スクロールに切り替わる。
  $: eventGridTemplateColumns = eventColumnWidths
    .map((width, i) =>
      i === eventColumnWidths.length - 1 ? `minmax(${width}px, 1fr)` : `${width}px`
    )
    .join(' ');
  $: eventGridWidth = eventColumnWidths.reduce((total, width) => total + width, 0) + 94;
  $: eventGridColumnsStyle = `grid-template-columns: ${eventGridTemplateColumns};`;
  $: eventTableCanvasStyle = `min-width: ${eventGridWidth}px; width: 100%;`;
  $: eventHeaderGridStyle = `${eventGridColumnsStyle} ${eventTableCanvasStyle} transform: translateX(-${eventHorizontalScroll}px);`;
  const eventBearingTabs = new Set([
    'events', 'timeline', 'defender', 'findings', 'ioc', 'chains', 'bookmarks',
    'artifact_mft', 'artifact_prefetch', 'artifact_usn', 'artifact_amcache',
    'artifact_srum', 'artifact_text_observation', 'artifact_registry',
  ]);
  // 画面下の調査ペインはログ系タブ(イベント行を持つタブ)でのみ共有表示する
  $: showDetailPane = selectedEvent != null && eventBearingTabs.has(activeTab);
  let detailPaneHeight = 320;
  let detailPaneResizing = false;
  function startDetailPaneResize(event: PointerEvent) {
    detailPaneResizing = true;
    const startY = event.clientY;
    const startHeight = detailPaneHeight;
    const onMove = (move: PointerEvent) => {
      const delta = startY - move.clientY;
      detailPaneHeight = Math.max(120, Math.min(window.innerHeight - 180, startHeight + delta));
    };
    const onUp = () => {
      detailPaneResizing = false;
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    event.preventDefault();
  }

  // --- ユーザー一覧 (taotie風: ソート可能ヘッダ + イベント数バー, taotieネイティブ) ---
  const USER_SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  type UserSortKey = 'user_name' | 'event_count' | 'host_count' | 'first_seen_utc' | 'last_seen_utc' | 'severity_max';
  let userSortKey: UserSortKey = 'event_count';
  let userSortDir = -1;
  function setUserSort(key: UserSortKey) {
    if (userSortKey === key) userSortDir = -userSortDir;
    else {
      userSortKey = key;
      userSortDir = key === 'user_name' ? 1 : -1;
    }
  }
  function userSortMark(key: UserSortKey) {
    return userSortKey === key ? (userSortDir < 0 ? ' ▼' : ' ▲') : '';
  }
  $: maxUserEvents = Math.max(1, ...users.map((u) => u.event_count));
  $: userView = [...users].sort((a, b) => {
    let cmp = 0;
    switch (userSortKey) {
      case 'user_name':
        cmp = (a.user_name ?? '').localeCompare(b.user_name ?? '');
        break;
      case 'host_count':
        cmp = (a.host_count ?? 0) - (b.host_count ?? 0);
        break;
      case 'first_seen_utc':
        cmp = String(a.first_seen_utc ?? '').localeCompare(String(b.first_seen_utc ?? ''));
        break;
      case 'last_seen_utc':
        cmp = String(a.last_seen_utc ?? '').localeCompare(String(b.last_seen_utc ?? ''));
        break;
      case 'severity_max':
        cmp = (USER_SEV_RANK[a.severity_max ?? 'info'] ?? 0) - (USER_SEV_RANK[b.severity_max ?? 'info'] ?? 0);
        break;
      default:
        cmp = (a.event_count ?? 0) - (b.event_count ?? 0);
    }
    if (cmp === 0) cmp = (a.user_name ?? '').localeCompare(b.user_name ?? '');
    return cmp * userSortDir;
  });

  // --- Defender (taotie風の色付きバー + EID名 + ソースpill, taotieネイティブ) ---
  $: DEFENDER_EID_NAMES = ($locale === 'en'
    ? {
        '1000': 'Scan started', '1001': 'Scan completed', '1002': 'Scan cancelled',
        '1006': 'Malware detected', '1007': 'Malware remediation executed', '1008': 'Remediation failed',
        '1009': 'Restored from quarantine', '1011': 'Quarantine item deleted', '1015': 'Suspicious behavior detected',
        '1116': 'Malware detected', '1117': 'Malware remediation executed', '1118': 'Remediation failed', '1119': 'Critical remediation error',
        '2000': 'Definition update succeeded', '2001': 'Definition update failed', '2002': 'Engine updated',
        '2003': 'Definition rollback', '2010': 'Dynamic signature obtained', '2011': 'Dynamic signature removed',
        '5001': 'Real-time protection disabled', '5004': 'Protection config changed', '5007': 'Setting changed',
        '5010': 'Antispyware disabled', '5012': 'Antivirus disabled',
        '5100': 'Protection expired', '5101': 'Protection disabled', '101': 'Health report (WHC)'
      }
    : {
        '1000': 'スキャン開始', '1001': 'スキャン完了', '1002': 'スキャン中止',
        '1006': 'マルウェア検出', '1007': 'マルウェア対処実行', '1008': '対処失敗',
        '1009': '隔離から復元', '1011': '隔離項目を削除', '1015': '不審な動作を検出',
        '1116': 'マルウェア検出', '1117': 'マルウェア対処を実行', '1118': '対処失敗', '1119': '対処で重大エラー',
        '2000': '定義更新成功', '2001': '定義更新失敗', '2002': 'エンジン更新',
        '2003': '定義ロールバック', '2010': '動的署名を取得', '2011': '動的署名を削除',
        '5001': 'リアルタイム保護を無効化', '5004': '保護構成の変更', '5007': '設定変更',
        '5010': 'スパイウェア対策を無効化', '5012': 'ウイルス対策を無効化',
        '5100': '保護が期限切れ', '5101': '保護を無効化', '101': 'ヘルスレポート(WHC)'
      }) as Record<string, string>;
  // Defender集約カテゴリ(event_action)の日本語ラベル。明示マップ + トークン翻訳フォールバック。
  $: DEFENDER_CATEGORY_NAMES = ($locale === 'en'
    ? {
        registry_suspicious_value: 'Suspicious registry value',
        defender_threat_detected: 'Defender threat detected',
        defender_quarantined: 'Defender quarantined',
        defender_configuration_changed: 'Defender configuration changed',
        defender_remediation_action: 'Defender remediation action',
        defender_operational_event: 'Defender operational event',
        defender_mplog_observed: 'Defender MPLog observed',
        defender_scan: 'Defender scan',
        defender_error: 'Defender error',
        scheduled_task_exec_action: 'Scheduled task execution',
        scheduled_task_suspicious_exec: 'Suspicious scheduled task execution',
        scheduled_task_observed: 'Scheduled task observed',
        scheduled_task_created: 'Scheduled task created',
        scheduled_task_action_started: 'Scheduled task started',
        scheduled_task_trigger_observed: 'Scheduled task trigger observed',
        scheduled_task_runs_file: 'Scheduled task runs a file'
      }
    : {
        registry_suspicious_value: 'レジストリの不審な値',
        defender_threat_detected: 'Defender 脅威検出',
        defender_quarantined: 'Defender 隔離',
        defender_configuration_changed: 'Defender 構成変更',
        defender_remediation_action: 'Defender 対処アクション',
        defender_operational_event: 'Defender 運用イベント',
        defender_mplog_observed: 'Defender MPLog 観測',
        defender_scan: 'Defender スキャン',
        defender_error: 'Defender エラー',
        scheduled_task_exec_action: 'スケジュールタスク実行',
        scheduled_task_suspicious_exec: 'スケジュールタスクの不審な実行',
        scheduled_task_observed: 'スケジュールタスク観測',
        scheduled_task_created: 'スケジュールタスク作成',
        scheduled_task_action_started: 'スケジュールタスク開始',
        scheduled_task_trigger_observed: 'スケジュールタスク トリガ観測',
        scheduled_task_runs_file: 'スケジュールタスクがファイルを実行'
      }) as Record<string, string>;
  $: DEF_CAT_TOKENS = ($locale === 'en'
    ? {
        defender: 'Defender', registry: 'Registry', scheduled: 'Scheduled', task: 'Task',
        suspicious: 'suspicious', value: 'value', exec: 'exec', action: 'action', observed: 'observed',
        detected: 'detected', changed: 'changed', created: 'created', remediation: 'remediation', threat: 'threat',
        quarantined: 'quarantined', scan: 'scan', started: 'started', completed: 'completed', mplog: 'MPLog',
        operational: 'operational', event: 'event', configuration: 'configuration', config: 'config', error: 'error',
        usn: 'USN', parent: 'parent', reference: 'reference', webcache: 'Web cache', cache: 'cache',
        artifact: 'artifact', onedrive: 'OneDrive', path: 'path', url: 'URL', download: 'download',
        upload: 'upload', delete: 'delete', text: 'text', observation: '', line: 'line',
        evtx: 'evtx', record: 'record', context: 'context', indexed: 'indexed',
        windows: 'Windows', webhistory: 'Web history',
        log: 'log', network: 'network', warning: 'warning', srum: 'SRUM', resource: 'resource',
        process: 'process', mft: 'MFT', ads: 'ADS', resident: 'resident', content: 'content',
        data: 'data', browser: 'browser', string: 'string', signal: 'signal', binary: 'binary',
        jumplist: 'JumpList', destlist: 'DestList', entry: 'entry', lnk: 'LNK', account: 'account',
        ese: 'ESE', file: 'file', trigger: 'trigger', rename: 'rename', move: 'move', or: '/',
        amcache: 'Amcache', program: 'program', modified: 'modified', prefetch: 'Prefetch',
        runs: 'runs', not: 'not', user: 'user', xml: 'XML', flat: 'flat', export: 'export',
        time: 'time'
      }
    : {
        defender: 'Defender', registry: 'レジストリ', scheduled: 'スケジュール', task: 'タスク',
        suspicious: '不審な', value: '値', exec: '実行', action: 'アクション', observed: '観測',
        detected: '検出', changed: '変更', created: '作成', remediation: '対処', threat: '脅威',
        quarantined: '隔離', scan: 'スキャン', started: '開始', completed: '完了', mplog: 'MPLog',
        operational: '運用', event: 'イベント', configuration: '構成', config: '構成', error: 'エラー',
        usn: 'USN', parent: '親', reference: '参照', webcache: 'Webキャッシュ', cache: 'キャッシュ',
        artifact: '成果物', onedrive: 'OneDrive', path: 'パス', url: 'URL', download: 'ダウンロード',
        upload: 'アップロード', delete: '削除', text: 'テキスト', observation: '', line: '行',
        evtx: 'evtx', record: 'レコード', context: 'コンテキスト', indexed: 'インデックス済',
        windows: 'Windows', webhistory: 'Web履歴',
        log: 'ログ', network: 'ネットワーク', warning: '警告', srum: 'SRUM', resource: 'リソース',
        process: 'プロセス', mft: 'MFT', ads: 'ADS', resident: '常駐', content: 'コンテンツ',
        data: 'データ', browser: 'ブラウザ', string: '文字列', signal: 'シグナル', binary: 'バイナリ',
        jumplist: 'JumpList', destlist: 'DestList', entry: 'エントリ', lnk: 'LNK', account: 'アカウント',
        ese: 'ESE', file: 'ファイル', trigger: 'トリガ', rename: 'リネーム', move: '移動', or: '/',
        amcache: 'Amcache', program: 'プログラム', modified: '変更', prefetch: 'Prefetch',
        runs: '実行', not: '未', user: 'ユーザー', xml: 'XML', flat: 'フラット', export: 'エクスポート',
        time: '時刻'
      }) as Record<string, string>;
  $: defenderCategoryLabel = (category: string): string => {
    if (!category) return '-';
    const hit = DEFENDER_CATEGORY_NAMES[category];
    if (hit) return hit;
    return category
      .split('_')
      .map((tok) => (tok in DEF_CAT_TOKENS ? DEF_CAT_TOKENS[tok] : tok))
      .filter((tok) => tok)
      .join(' ');
  };
  $: defenderEventName = (row: EventRow): string => {
    const id = row.event_code ?? '';
    if (id && DEFENDER_EID_NAMES[id]) return DEFENDER_EID_NAMES[id];
    return row.event_action ? defenderCategoryLabel(row.event_action) : displayText(row.event_code, '-');
  };
  function defenderAccent(category: string): string {
    const c = (category || '').toLowerCase();
    if (/malware|threat|detect|quarantine/.test(c)) return 'def-bar-malware';
    if (/config|tamper|disable|setting|protect/.test(c)) return 'def-bar-config';
    if (/scan/.test(c)) return 'def-bar-scan';
    if (/signature|definition|update|engine/.test(c)) return 'def-bar-update';
    if (/mplog|log/.test(c)) return 'def-bar-log';
    if (/task|schedule/.test(c)) return 'def-bar-task';
    return 'def-bar-other';
  }
  $: defenderCatMax = Math.max(1, ...defenderSummaries.map((r) => r.event_count));
  $: defenderSources = Array.from(
    new Set(
      defenderSummaries.flatMap((r) => (r.artifact_types || '').split(',').map((s) => s.trim()).filter(Boolean))
    )
  );

  $: activeArtifactView = artifactViewFor(activeTab);
  $: currentViewTitle = (void $locale, viewTitleFor(activeTab, eventSubtab, activeArtifactView));
  $: currentViewFilterSummary = (void $locale, viewFilterSummaryFor(
    activeTab,
    eventSubtab,
    appliedEventSearch,
    eventArtifactFilter,
    eventUserFilter,
    eventIdFilter,
    artifactQuickFilter
  ));
  $: eventFacetGroups = (void $locale, groupEventFacets(eventFacets));
  $: eventArtifactOptions = buildEventArtifactOptions(coverage, eventFacets, eventRows);
  $: selectedEventFacetGroup = eventFacetGroups.find((group) => group.field === eventFacetField) ?? null;
  $: selectedEventFacetValues = selectedEventFacetGroup?.values ?? [];
  $: overviewTimelineRows = buildOverviewTimelineRows(timeline);
  $: overviewVisibleTimelineRows = overviewTimelineRows.slice(-48);
  $: maxOverviewTimelineCount = Math.max(1, ...overviewTimelineRows.map((row) => row.eventCount));
  // 概要タイムラインを severity 積み上げ(セグメント)バーで描くための集約列。
  $: overviewSeverityColumns = aggregateTimelineColumns(overviewSeverityBins, 60);
  $: overviewSeverityMax = Math.max(1, ...overviewSeverityColumns.map((c) => c.total));
  $: overviewSeverityLegend = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .map((sev) => ({
      sev,
      label: OVERVIEW_SEV_LABEL[sev],
      total: overviewSeverityColumns.reduce((a, c) => a + (c[sev] || 0), 0)
    }))
    .filter((x) => x.total > 0);
  $: overviewChartGroups = (void $locale, buildOverviewChartGroups(overviewFacets));
  $: triageFunnel = (void $locale, buildTriageFunnel(summary, findings));
  $: timestompView = buildTimestompView(timestompPoints);
  $: attackHeatmap = (void $locale, buildAttackHeatmap(findings));
  $: processTree = buildProcessTree(processTreeEdges);
  $: fileOpView = buildFileOpView(fileOpBins);
  $: beaconMax = Math.max(1, ...beaconBins.map((b) => b.count));
  $: beaconTotal = beaconBins.reduce((a, b) => a + b.count, 0);
  $: beaconPeak = beaconBins.reduce(
    (best, b) => (b.count > (best?.count ?? -1) ? b : best),
    null as BeaconIntervalBin | null
  );
  $: loginOutcomeRows = (void $locale, buildLoginOutcomeRows(overviewFacets));
  $: maxLoginOutcomeCount = Math.max(1, ...loginOutcomeRows.map((row) => row.count));
  $: timelineDowLabels =
    $locale === 'en'
      ? ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
      : ['日', '月', '火', '水', '木', '金', '土'];
  $: activeSearchIndexJob = searchIndexStatus?.active_job ?? null;
  $: activeAnswerCandidateJob =
    jobs.find((job) => job.kind === 'build_answer_candidates' && ['queued', 'running'].includes(job.status)) ?? null;
  $: activeDetectionReadModelJob =
    jobs.find((job) => job.kind === 'run_findings' && ['queued', 'running'].includes(job.status)) ?? null;
  $: activeArtifactColumns = artifactEventColumns(activeArtifactView?.artifactType ?? '');
  $: activeArtifactColumnWidths = resolvedArtifactColumnWidths(
    activeArtifactView?.artifactType ?? '',
    activeArtifactColumns
  );
  $: activeArtifactTableWidth = activeArtifactColumnWidths.reduce((total, width) => total + width, 0);
  $: activeArtifactStats = artifactEventStats(artifactEventRows);
  $: activeArtifactQuickFilters = (void $locale, artifactQuickFiltersFor(activeArtifactView?.artifactType ?? ''));
  $: activeArtifactCoverage = activeArtifactView
    ? coverage.find((row) => row.artifact_type === activeArtifactView.artifactType) ?? null
    : null;
  $: activeDetailAttributes = parseDetailAttributes(detail?.attributes_json);
  $: activeArtifactDetailFields = artifactDetailFields(selectedEvent, detail, activeDetailAttributes);
  $: activePivotActions = (void $locale, pivotActionsFor(selectedEvent, detail));
  $: intakeStatusSummary = buildIntakeStatusSummary(summary, coverage, files);
  $: intakeCoverageRows = buildIntakeCoverageRows(coverage);
  $: activeIntakeJobs = jobs.filter(isActiveIntakeJob).slice(0, 8);
  $: intakeOverlayVisible = intakeActive || intakeCompleteVisible;
  // Intake top-bar progress (reactive). In Svelte5 legacy mode a $: / markup binding must
  // reference the reactive state DIRECTLY; calling a zero-arg helper gets $.untrack-wrapped and
  // freezes the bar (see svelte-legacy-binding-staleness). So the logic is inlined here.
  $: intakeBarJobPercent = Math.max(
    8,
    Math.min(96, (activeIntakeJobs.find((job) => job.progress > 0)?.progress ?? 0) * 100)
  );
  $: intakeBarFilePercent =
    !intakeActive && intakeTotal <= 0
      ? ratioPercent(intakeStatusSummary.parsed, intakeStatusSummary.total)
      : intakeTotal <= 0
        ? 0
        : ratioPercent(intakeCompleted, intakeTotal);
  $: intakeBarPercent =
    intakeCompleteVisible || intakeFinalizePending
      ? 100
      : !intakeActive && busy && isIntakeStatus(uploadStatus)
        ? activeIntakeJobs.length > 0
          ? intakeBarJobPercent
          : 0
        : intakeTotal > 0
          ? intakeTotal === 1 && activeIntakeJobs.length > 0
            ? Math.max(intakeBarFilePercent, intakeBarJobPercent)
            : intakeBarFilePercent
          : activeIntakeJobs.length > 0
            ? intakeBarJobPercent
            : 0;
  $: intakeBarIndeterminate =
    intakeOverlayVisible &&
    !intakeCompleteVisible &&
    !intakeFinalizePending &&
    intakeTotal <= 0 &&
    activeIntakeJobs.length === 0;
  $: intakeBarTitle =
    intakeCompleteVisible || intakeFinalizePending
      ? $t('intake.done')
      : !intakeActive && busy && isIntakeStatus(uploadStatus)
        ? $t('intake.loading')
        : intakeTotal > 0
          ? $t('intake.ingesting')
          : activeIntakeJobs.length > 0
            ? $t('intake.parsing')
            : $t('intake.loading');
  $: intakeBarStatus =
    intakeCompleteVisible || intakeFinalizePending
      ? `${intakeCompleted.toLocaleString()} / ${Math.max(intakeTotal, intakeCompleted, 1).toLocaleString()} files`
      : !intakeActive && busy && isIntakeStatus(uploadStatus)
        ? uploadStatus || $t('intake.scanning')
        : intakeTotal > 0
          ? `${intakeCompleted.toLocaleString()} / ${Math.max(intakeTotal, 0).toLocaleString()} files`
          : activeIntakeJobs[0]
            ? `${activeIntakeJobs[0].kind} ${activeIntakeJobs[0].status} ${Math.round(activeIntakeJobs[0].progress * 100)}%`
            : $t('intake.scanning');
  $: intakeBarLabel = `${Math.round(intakeBarPercent)}%`;
  $: recentFileRows = files.slice(0, 12);
  $: maxTimelineCount = Math.max(1, ...timeline.map((bin) => bin.event_count));
  $: selectedEventBookmark = selectedEvent
    ? bookmarks.find((bookmark) => bookmark.event_id === selectedEvent?.event_id) ?? null
    : null;
  $: selectedFindingReview = selectedFinding ? reviewForFinding(selectedFinding) : null;

  // --- Hexビューア (taotieネイティブ: get_evidence_range で object_ref のバイト範囲を表示) ---
  const HEX_PAGE = 1024;
  async function loadHexFiles() {
    const page = await getFilePage(caseRoot, 200, null);
    hexFiles = page.rows;
  }
  async function selectHexFile(file: FileRecord) {
    hexSelectedFile = file;
    hexOffset = 0;
    await loadHexRange();
  }
  async function loadHexRange() {
    if (!hexSelectedFile) return;
    hexLoading = true;
    hexError = null;
    try {
      hexRange = await getEvidenceRange(caseRoot, hexSelectedFile.object_ref, hexOffset, HEX_PAGE);
    } catch (e) {
      hexError = e instanceof Error ? e.message : String(e);
      hexRange = null;
    } finally {
      hexLoading = false;
    }
  }
  function hexCanNext(): boolean {
    if (!hexSelectedFile) return false;
    const total = hexRange?.total_size ?? hexSelectedFile.size;
    return hexOffset + HEX_PAGE < total;
  }
  async function hexPrev() {
    if (!hexSelectedFile || hexOffset === 0) return;
    hexOffset = Math.max(0, hexOffset - HEX_PAGE);
    await loadHexRange();
  }
  async function hexNext() {
    if (!hexCanNext()) return;
    hexOffset = hexOffset + HEX_PAGE;
    await loadHexRange();
  }

  function parseHexOffsetInput(raw: string): number | null {
    const text = raw.trim();
    if (!text) return null;
    const value = /^0x/i.test(text) ? parseInt(text.slice(2), 16) : Number(text);
    return Number.isFinite(value) && value >= 0 ? Math.floor(value) : null;
  }

  async function gotoHexOffset() {
    if (!hexSelectedFile) return;
    const target = parseHexOffsetInput(hexGotoInput);
    if (target === null) {
      hexError = $t('hex.err.offset');
      return;
    }
    const total = hexRange?.total_size ?? hexSelectedFile.size;
    hexOffset = Math.max(0, Math.min(target, Math.max(0, total - 1)));
    await loadHexRange();
  }

  async function searchHexNext(continueFromCurrent: boolean) {
    if (!hexSelectedFile || !hexSearchInput.trim()) return;
    hexSearchBusy = true;
    hexSearchStatus = $t('hex.searching');
    try {
      const from = continueFromCurrent ? hexOffset + 1 : 0;
      const result = await findEvidenceMatch(
        caseRoot,
        hexSelectedFile.object_ref,
        hexSearchInput,
        hexSearchHex,
        from
      );
      if (result.offset === null || result.offset === undefined) {
        hexSearchStatus = continueFromCurrent ? $t('hex.no_more_match') : $t('hex.no_match');
      } else {
        hexOffset = result.offset;
        await loadHexRange();
        hexSearchStatus =
          $locale === 'en'
            ? `Match at 0x${result.offset.toString(16)} (${result.offset.toLocaleString()})`
            : `0x${result.offset.toString(16)} (${result.offset.toLocaleString()}) で一致`;
      }
    } catch (error) {
      hexSearchStatus = error instanceof Error ? error.message : String(error);
    } finally {
      hexSearchBusy = false;
    }
  }

  async function run(action: () => Promise<void>) {
    busy = true;
    errorMessage = '';
    try {
      await action();
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : String(error);
    } finally {
      busy = false;
    }
  }

  function eventCacheKey(eventId: string) {
    return `${caseRoot}\u0000${eventId}`;
  }

  function eventContextCacheKey(eventId: string, windowMinutes: number, perGroupLimit: number, sameHostOnly: boolean) {
    return `${eventCacheKey(eventId)}\u0000${windowMinutes}\u0000${perGroupLimit}\u0000${sameHostOnly ? 'host' : 'all'}`;
  }

  function readLruCache<T>(cache: Map<string, T>, key: string): CacheRead<T> {
    if (!cache.has(key)) return { hit: false, value: undefined };
    const value = cache.get(key) as T;
    cache.delete(key);
    cache.set(key, value);
    return { hit: true, value };
  }

  function writeLruCache<T>(cache: Map<string, T>, key: string, value: T, limit: number) {
    if (cache.has(key)) cache.delete(key);
    cache.set(key, value);
    while (cache.size > limit) {
      const oldest = cache.keys().next().value;
      if (oldest === undefined) break;
      cache.delete(oldest);
    }
  }

  function isNearScrollBottom(node: HTMLElement, threshold = 220) {
    return node.scrollHeight - node.scrollTop - node.clientHeight <= threshold;
  }

  function pageLoaderFor(list: PagedList): (() => Promise<void>) | null {
    if (list === 'events') return nextEventCursor ? () => loadEvents(false) : null;
    if (list === 'user_events') return nextUserEventCursor ? () => loadUserEvents(false) : null;
    if (list === 'artifact_events') return nextArtifactEventCursor ? () => loadArtifactEvents(false) : null;
    if (list === 'indexed_search') return nextIndexedSearchCursor ? () => runIndexedSearch(false) : null;
    if (list === 'evidence_verification') {
      return nextEvidenceVerificationCursor ? () => runEvidenceVerification(false) : null;
    }
    if (list === 'finding_events') return nextFindingEventCursor ? () => loadFindingEvents(false) : null;
    if (list === 'ioc_events') return nextIocEventCursor ? () => loadIocEvents(false) : null;
    if (list === 'defender_events') return nextDefenderEventCursor ? () => loadDefenderEvents(false) : null;
    if (list === 'chain_events') return nextChainEventCursor ? () => loadCorrelationChainEvents(false) : null;
    if (list === 'bookmark_events') return nextBookmarkEventCursor ? () => loadBookmarkEvents(false) : null;
    if (list === 'timeline_events') return nextTimelineEventCursor ? () => loadTimelineEvents(false) : null;
    return null;
  }

  async function autoLoadNextPage(list: PagedList) {
    if (busy || autoPageLoading) return;
    const loader = pageLoaderFor(list);
    if (!loader) return;
    autoPageLoading = list;
    try {
      await run(loader);
    } finally {
      autoPageLoading = '';
    }
  }

  function handlePagedScroll(event: Event, list: PagedList) {
    const node = event.currentTarget;
    if (!(node instanceof HTMLElement) || !isNearScrollBottom(node)) return;
    void autoLoadNextPage(list);
  }

  function clearEventDetailCaches() {
    cancelScheduledDetailLoad();
    detailToken += 1;
    eventDetailCache = new Map();
    eventContextCache = new Map();
    eventStructureCache = new Map();
  }

  function cancelScheduledDetailLoad() {
    if (detailLoadTimer === null) return;
    window.clearTimeout(detailLoadTimer);
    detailLoadTimer = null;
  }

  function clearSelectedEventState() {
    cancelScheduledDetailLoad();
    detailToken += 1;
    selectedEvent = null;
    detail = null;
    eventContext = null;
    rawRecord = null;
    artifactObjects = [];
    evidenceOffsets = [];
    evidenceRange = null;
    evidenceOffset = 0;
    detailLoading = false;
    contextLoading = false;
    rawLoading = false;
    evidenceLoading = false;
    structureLoading = false;
    structureLoaded = false;
  }

  function setUploadStatus(message: string, autoClearMs = 0) {
    uploadStatus = message;
    const token = ++uploadStatusToken;
    if (autoClearMs <= 0) return;
    window.setTimeout(() => {
      if (uploadStatusToken === token) uploadStatus = '';
    }, autoClearMs);
  }

  function setExportStatus(message: string, autoClearMs = 10_000) {
    exportStatus = message;
    const token = ++exportStatusToken;
    if (autoClearMs <= 0) return;
    window.setTimeout(() => {
      if (exportStatusToken === token) exportStatus = '';
    }, autoClearMs);
  }

  async function createCurrentCase() {
    if (!caseRoot.trim()) {
      errorMessage = $t('case.err.root_required');
      activeTab = 'files';
      return;
    }
    if (!caseName.trim()) {
      errorMessage = $t('case.err.name_required');
      activeTab = 'files';
      return;
    }
    await run(async () => {
      viewHistory = [];
      clearEventDetailCaches();
      summary = await createCase(caseRoot.trim(), caseName.trim());
      syncCaseControlsFromSummary();
      await refreshCaseMetadata();
    });
  }

  async function openCurrentCase() {
    if (!caseRoot.trim()) {
      errorMessage = $t('case.err.root_required');
      activeTab = 'files';
      return;
    }
    await run(async () => {
      viewHistory = [];
      clearEventDetailCaches();
      summary = await openCase(caseRoot.trim());
      syncCaseControlsFromSummary();
      await refreshCaseMetadata();
    });
  }

  function tauriRuntimeAvailable() {
    return typeof window !== 'undefined' && Boolean((window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
  }

  function openCaseSetupFromSidebar() {
    if (tauriRuntimeAvailable()) {
      void createCaseFromDirectoryPicker();
      return;
    }
    activeTab = 'files';
    setUploadStatus($t('case.hint.enter_root'), 5_000);
  }

  function inferCaseNameFromPath(path: string) {
    const normalized = path.replace(/[\\/]+$/, '');
    return normalized.split(/[\\/]/).pop()?.trim() || 'case';
  }

  async function createCaseFromDirectoryPicker() {
    if (!tauriRuntimeAvailable()) {
      errorMessage = $t('case.err.picker_tauri_only');
      return;
    }
    await run(async () => {
      const selectedPath = await selectCaseDirectory();
      if (!selectedPath) {
        setUploadStatus($t('case.create_cancelled'), 3_000);
        return;
      }
      const selectedName = inferCaseNameFromPath(selectedPath);
      caseRoot = selectedPath;
      caseName = selectedName;
      viewHistory = [];
      clearEventDetailCaches();
      try {
        summary = await openCase(selectedPath);
        setUploadStatus(`${$t('case.opened_existing')}: ${selectedPath}`, 5_000);
      } catch {
        summary = await createCase(selectedPath, selectedName);
        setUploadStatus(`${$t('case.created')}: ${selectedPath}`, 5_000);
      }
      syncCaseControlsFromSummary();
      await refreshCaseMetadata();
    });
  }

  async function refreshCaseMetadata() {
    await loadCaseCustodyProfile();
    await loadCaseApprovals();
    await loadSavedSearches();
    await loadSearchIndexMetadata();
    await refreshActiveTab();
  }

  function syncCaseControlsFromSummary() {
    if (!summary) return;
    caseRoot = summary.root_path;
    caseName = summary.name;
    try {
      localStorage.setItem('taotie:lastCaseRoot', summary.root_path);
    } catch {
      // localStorage unavailable — non-fatal
    }
  }

  // 起動時に最後のケースを自動再オープン。stale パスは黙ってクリア。
  async function autoReopenLastCase() {
    if (!tauriRuntimeAvailable()) return;
    let saved = '';
    try {
      saved = localStorage.getItem('taotie:lastCaseRoot') ?? '';
    } catch {
      saved = '';
    }
    if (!saved) return;
    try {
      caseRoot = saved;
      summary = await openCase(saved);
      syncCaseControlsFromSummary();
      await refreshCaseMetadata();
    } catch {
      caseRoot = '';
      summary = null;
      try {
        localStorage.removeItem('taotie:lastCaseRoot');
      } catch {
        // ignore
      }
    }
  }

  onMount(() => {
    void autoReopenLastCase();
  });

  function resetCaseDataState() {
    clearEventDetailCaches();
    summary = null;
    viewHistory = [];
    custodyProfile = null;
    files = [];
    evidenceVerifications = [];
    nextEvidenceVerificationCursor = null;
    custodyManifestVerification = null;
    reportBundleVerification = null;
    caseApprovals = [];
    coverage = [];
    failedParsers = [];
    triageActions = [];
    caseDetectionEvaluation = null;
    timeline = [];
    correlations = [];
    correlationChains = [];
    correlationStatus = '';
    correlationChainsStatus = '';
    selectedChain = null;
    processNodes = [];
    processTreeStatus = '';
    processTreeFilter = '';
    processTreeExpanded = new Set();
    selectedProcessNode = null;
    chainEventRows = [];
    nextChainEventCursor = null;
    entities = [];
    subgraph = { nodes: [], edges: [] };
    findings = [];
    findingOverrides = [];
    findingReviews = [];
    findingReviewSummary = null;
    selectedFinding = null;
    selectedFindingReview = null;
    findingEventRows = [];
    nextFindingEventCursor = null;
    answerCandidates = [];
    selectedAnswerCandidate = null;
    answerQuestionFilter = '';
    iocHits = [];
    selectedIoc = null;
    iocEventRows = [];
    nextIocEventCursor = null;
    defenderSummaries = [];
    selectedDefenderCategory = null;
    hexFiles = [];
    hexSelectedFile = null;
    hexRange = null;
    hexOffset = 0;
    hexError = null;
    hexGotoInput = '';
    hexSearchInput = '';
    hexSearchHex = false;
    hexSearchStatus = '';
    hexSearchBusy = false;
    timelineGranularity = 'hour';
    timelineView = 'chart';
    timelineSelectedBin = null;
    timelineSelectedBinData = null;
    timelineSeverityBins = [];
    timelineHeatmapBins = [];
    timelineBinCache = new Map();
    timelineFindingMarks = [];
    timelineIocMarks = [];
    timelineBookmarkMarks = [];
    timelineSevFilter = '';
    timelineHostFilter = '';
    timelineUserFilter = '';
    timelineSearchText = '';
    timelineSearchRegex = false;
    timelineFindingOnly = false;
    timelineWindowStart = '';
    timelineWindowEnd = '';
    timelineEventRows = [];
    nextTimelineEventCursor = null;
    defenderEventRows = [];
    nextDefenderEventCursor = null;
    prefetchSummaries = [];
    selectedPrefetchSummary = null;
    risks = [];
    riskStatus = '';
    users = [];
    bookmarks = [];
    bookmarkEventRows = [];
    nextBookmarkEventCursor = null;
    auditLog = [];
    analyzerRuns = [];
    eventRows = [];
    nextEventCursor = null;
    eventFacets = [];
    overviewFacets = [];
    savedSearches = [];
    searchIndexMetadata = null;
    searchIndexStatus = null;
    indexedSearchHits = [];
    nextIndexedSearchCursor = null;
    indexedSearchNotice = '';
    artifactEventRows = [];
    nextArtifactEventCursor = null;
    autoPageLoading = '';
    userEventRows = [];
    nextUserEventCursor = null;
    jobs = [];
    clearSelectedEventState();
    investigationTrail = [];
    investigationIndex = -1;
    selectedEntity = null;
    selectedUser = null;
    eventScrollTop = 0;
    artifactScrollTop = 0;
  }

  async function reloadCurrentView() {
    if (!summary) {
      errorMessage = $t('err.open_case_first');
      return;
    }
    await run(async () => {
      await refreshActiveTab();
      const jobs = await startAnalysisReadModelJobs(caseRoot, 'manual_reload');
      await loadJobs();
      setUploadStatus(
        jobs.length > 0
          ? `${$t('reload.reloaded')}${$t('reload.jobs_started')}: ${jobs.length}`
          : `${$t('reload.reloaded')}${$t('reload.readmodel_fresh')}`,
        4_000
      );
    });
  }

  async function clearCurrentCaseWorkspace() {
    if (!summary) {
      errorMessage = $t('err.open_case_first');
      return;
    }
    const ok = window.confirm(
      `${$t('clear.confirm.head')}\n\n${$t('clear.confirm.target')}: ${caseRoot}\n\n${$t('clear.confirm.body')}`
    );
    if (!ok) return;
    await run(async () => {
      const cleared = await clearCaseWorkspace(caseRoot);
      resetCaseDataState();
      setUploadStatus(
        `${$t('clear.done')}: ${cleared.case_root}` +
          (cleared.root_removed ? $t('clear.root_removed') : ''),
        8_000
      );
    });
  }

  async function ingestSample() {
    await run(async () => {
      startIntakeProgress(1, artifactPath, artifactContent.length);
      await waitForIntakeOverlayPaint();
      try {
        summary = await ingestFakeArtifact(caseRoot, artifactPath, artifactContent);
        finishIntakeItem();
        await refreshAfterIntake();
      } finally {
        finishIntakeProgress();
      }
    });
  }

  async function ingestLocalPathRecursive(inputPath: string, statusPrefix: string) {
    if (!inputPath) {
      errorMessage = $t('ingest.err.path_required');
      return;
    }
    await run(async () => {
      const baselineFileCount = summary?.file_count ?? 0;
      startIntakeProgress(0, inputPath, 0, baselineFileCount);
      setUploadStatus(`${statusPrefix}${$t('ingest.scanning_target')}: ${inputPath}`);
      await waitForIntakeOverlayPaint();
      try {
        const scan = await scanLocalPath(inputPath, true);
        intakeTotal = scan.file_count;
        intakeCurrentSize = scan.total_bytes;
        intakeBaselineFileCount = baselineFileCount;
        setUploadStatus(
          `${statusPrefix}${$t('ingest.ingesting')}: ${inputPath} (${scan.file_count.toLocaleString()} files / ${formatBytes(scan.total_bytes)})`
        );
        await waitForIntakeOverlayPaint();
        const result = await ingestLocalPath(caseRoot, inputPath, true);
        summary = result.summary;
        intakeTotal = result.file_count + (result.skipped_count ?? 0);
        intakeCompleted = Math.max(0, result.file_count + (result.skipped_count ?? 0) - result.failed_count);
        intakeCurrentPath = '';
        if (result.file_count > 0 && result.summary.event_count === 0) {
          setUploadStatus(`${statusPrefix}${$t('ingest.rebuilding_index')}: ${inputPath}`);
          await waitForIntakeOverlayPaint();
          summary = await rebuildAnalysisReadModels(caseRoot);
        }
        setUploadStatus(
          `${statusPrefix}${$t('ingest.complete')}: added ${result.file_count}` +
            ` / skipped ${result.skipped_count ?? 0}` +
            (result.worker_count ? ` / workers ${result.worker_count}` : '') +
            (result.failed_count > 0 ? ` / failed ${result.failed_count}` : ''),
          8_000
        );
        if (result.errors.length > 0) {
          errorMessage = result.errors.slice(0, 5).join('\n');
        }
        await refreshAfterIntake();
      } finally {
        finishIntakeProgress();
      }
    });
  }

  async function ingestLocalPathInput() {
    await ingestLocalPathRecursive(localPathInput.trim(), $t('ingest.prefix.localpath'));
  }

  function openUploadPicker() {
    if (!summary) {
      errorMessage = $t('err.open_case_first');
      return;
    }
    fileInput?.click();
  }

  async function openFolderPicker() {
    if (!summary) {
      errorMessage = $t('err.open_case_first');
      return;
    }
    if (tauriRuntimeAvailable()) {
      let selectedFolder = '';
      await run(async () => {
        const selectedPath = await selectIngestDirectory();
        if (!selectedPath) {
          setUploadStatus($t('ingest.folder_cancelled'), 3_000);
          return;
        }
        selectedFolder = selectedPath;
        localPathInput = selectedPath;
      });
      if (selectedFolder) {
        await ingestLocalPathRecursive(selectedFolder, $t('ingest.prefix.folder'));
      }
      return;
    }
    folderInput?.click();
  }

  function directoryPicker(node: HTMLInputElement) {
    const input = node as HTMLInputElement & { webkitdirectory?: boolean };
    input.webkitdirectory = true;
    input.setAttribute('webkitdirectory', '');
    input.setAttribute('directory', '');
  }

  async function uploadSelectedArtifacts(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const selectedFiles = Array.from(input.files ?? []);
    if (selectedFiles.length === 0) return;
    const isFolderImport = input === folderInput;
    await run(async () => {
      startIntakeProgress(selectedFiles.length);
      setUploadStatus(
        $locale === 'en'
          ? `${isFolderImport ? 'From folder: ' : ''}Ingesting ${selectedFiles.length} file(s)`
          : `${isFolderImport ? 'フォルダから ' : ''}${selectedFiles.length} 件のファイルを取り込み中`
      );
      await waitForIntakeOverlayPaint();
      try {
        for (const [index, file] of selectedFiles.entries()) {
          const relativePath = file.webkitRelativePath || file.name;
          updateIntakeCurrent(index, selectedFiles.length, relativePath, file.size);
          setUploadStatus(
            $locale === 'en'
              ? `${isFolderImport ? 'Folder' : 'File'} ingest ${index + 1}/${selectedFiles.length}: ${relativePath} (${formatBytes(file.size)})`
              : `${isFolderImport ? 'フォルダ' : 'ファイル'}取り込み中 ${index + 1}/${selectedFiles.length}: ${relativePath} (${formatBytes(file.size)})`
          );
          await tick();
          summary = await ingestUploadedFile(caseRoot, relativePath, file);
          finishIntakeItem();
        }
        if (selectedFiles.length > 1) {
          setUploadStatus($t('ingest.rebuild_display'));
          await waitForIntakeOverlayPaint();
          summary = await rebuildAnalysisReadModels(caseRoot);
        }
        setUploadStatus(
          $locale === 'en'
            ? `${isFolderImport ? 'From folder: ' : ''}Ingested ${selectedFiles.length} file(s)`
            : `${isFolderImport ? 'フォルダから ' : ''}${selectedFiles.length} 件のファイルを取り込みました`,
          8_000
        );
        await refreshAfterIntake();
      } finally {
        finishIntakeProgress();
      }
    });
    input.value = '';
  }

  function startIntakeProgress(
    total: number,
    currentPath = '',
    currentSize = 0,
    baselineFileCount = summary?.file_count ?? 0
  ) {
    if (intakeHideTimer !== null) {
      window.clearTimeout(intakeHideTimer);
      intakeHideTimer = null;
    }
    intakeActive = true;
    intakeFinalizePending = false;
    intakeCompleteVisible = false;
    intakeTotal = total;
    intakeCompleted = 0;
    intakeBaselineFileCount = baselineFileCount;
    intakeCurrentPath = currentPath;
    intakeCurrentSize = currentSize;
    startIntakeJobPolling();
  }

  function updateIntakeCurrent(index: number, total: number, currentPath: string, currentSize: number) {
    intakeActive = true;
    intakeFinalizePending = false;
    intakeCompleteVisible = false;
    intakeTotal = total;
    intakeCompleted = index;
    intakeBaselineFileCount = summary?.file_count ?? intakeBaselineFileCount;
    intakeCurrentPath = currentPath;
    intakeCurrentSize = currentSize;
    startIntakeJobPolling();
  }

  function finishIntakeItem() {
    intakeCompleted = Math.min(Math.max(intakeTotal, 1), intakeCompleted + 1);
  }

  function finishIntakeProgress() {
    const completedTotal = Math.max(intakeTotal, intakeCompleted, 1);
    intakeTotal = completedTotal;
    intakeCompleted = completedTotal;
    intakeCurrentPath = '';
    intakeCurrentSize = 0;
    intakeFinalizePending = true;
    intakeCompleteVisible = true;
    intakeActive = false;
    startIntakeJobPolling();
    void refreshIntakeJobs().finally(() => {
      scheduleIntakeHideIfIdle();
    });
  }

  function isActiveIntakeJob(job: JobRecord) {
    return (
      ['queued', 'running'].includes(job.status) &&
      [
        'intake_file',
        'detect_artifact_type',
        'parse_artifact',
        'build_event_rows',
        'build_timeline_bins',
        'extract_entities',
        'build_edges'
      ].includes(job.kind)
    );
  }

  function scheduleIntakeHideIfIdle() {
    if (!intakeFinalizePending) return;
    if (intakeHideTimer !== null) {
      return;
    }
    intakeHideTimer = window.setTimeout(() => {
      intakeActive = false;
      intakeFinalizePending = false;
      intakeCompleteVisible = false;
      stopIntakeJobPolling();
      intakeHideTimer = null;
    }, 1_200);
  }

  function startIntakeJobPolling() {
    if (intakeJobPollTimer !== null) return;
    void refreshIntakeJobs();
    intakeJobPollTimer = window.setInterval(() => {
      void refreshIntakeJobs();
    }, 1_000);
  }

  function stopIntakeJobPolling() {
    if (intakeJobPollTimer === null) return;
    window.clearInterval(intakeJobPollTimer);
    intakeJobPollTimer = null;
  }

  async function refreshIntakeJobs() {
    if (!summary) return;
    try {
      const [recentJobs, latestSummary] = await Promise.all([getRecentJobs(caseRoot, 100), getCaseSummary(caseRoot)]);
      jobs = recentJobs;
      summary = latestSummary;
      if (intakeActive && intakeTotal > 0) {
        const observedCompleted = Math.max(0, latestSummary.file_count - intakeBaselineFileCount);
        intakeCompleted = Math.min(intakeTotal, Math.max(intakeCompleted, observedCompleted));
      }
      scheduleIntakeHideIfIdle();
    } catch {
      // The intake modal should not replace the primary operation error.
    }
  }

  async function waitForIntakeOverlayPaint() {
    await tick();
    await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
    await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
    await new Promise<void>((resolve) => window.setTimeout(resolve, 40));
  }

  function isIntakeStatus(status: string) {
    return /取り込み|読み込み|解析|インデックス|rebuild|ingest|parse|loading|scanning|parsing|index/i.test(status);
  }

	  function formatBytes(value: number) {
	    if (value < 1024) return `${value} B`;
	    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
	    if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
	    return `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`;
	  }

	  function buildIntakeStatusSummary(
	    currentSummary: CaseSummary | null,
	    coverageRows: CoverageSummary[],
	    fileRows: FileRecord[]
	  ): IntakeStatusSummary {
	    const coverageTotal = coverageRows.reduce((sum, row) => sum + row.total_files, 0);
	    const coverageParsed = coverageRows.reduce((sum, row) => sum + row.parsed_files, 0);
	    const coverageFailed = coverageRows.reduce((sum, row) => sum + row.failed_files, 0);
	    const coverageUnsupported = coverageRows.reduce((sum, row) => sum + row.unsupported_files, 0);
	    const coverageEvents = coverageRows.reduce((sum, row) => sum + row.event_count, 0);
	    const total = Math.max(currentSummary?.file_count ?? 0, coverageTotal, fileRows.length);
	    const parsed =
	      coverageTotal > 0 ? coverageParsed : fileRows.filter((file) => file.parser_status === 'parsed').length;
	    const failed =
	      coverageTotal > 0
	        ? coverageFailed
	        : (currentSummary?.failed_parse_count ?? fileRows.filter((file) => file.parser_status === 'failed').length);
	    const unsupported =
	      coverageTotal > 0
	        ? coverageUnsupported
	        : (currentSummary?.unsupported_file_count ??
	            fileRows.filter((file) => file.parser_status === 'unsupported').length);
	    const events = Math.max(
	      currentSummary?.event_count ?? 0,
	      coverageEvents,
	      fileRows.reduce((sum, file) => sum + file.event_count, 0)
	    );
	    const bytes = fileRows.reduce((sum, file) => sum + file.size, 0);
	    return {
	      total,
	      parsed,
	      failed,
	      unsupported,
	      pending: Math.max(0, total - parsed - failed - unsupported),
	      events,
	      bytes
	    };
	  }

	  function buildIntakeCoverageRows(coverageRows: CoverageSummary[]) {
	    return [...coverageRows]
	      .sort((left, right) => right.total_files - left.total_files || right.event_count - left.event_count)
	      .slice(0, 14);
	  }

	  function ratioPercent(part: number, total: number) {
	    if (total <= 0) return 0;
	    return Math.max(0, Math.min(100, (part / total) * 100));
	  }



	  function coverageParsedPercent(row: CoverageSummary) {
	    return ratioPercent(row.parsed_files, row.total_files);
	  }

	  function artifactTypeLabel(artifactType: string) {
	    return Object.values(artifactViews).find((view) => view.artifactType === artifactType)?.label ?? artifactType;
	  }

  async function refreshAfterIntake() {
    clearEventDetailCaches();
    // 再取込でデータが変わるためタイムライン結果キャッシュを無効化(古いビンを出さない)
    timelineBinCache = new Map();
    const refreshes: Promise<unknown>[] = [
      loadFiles(),
      loadCoverage(),
      loadTriageActions(),
      loadCaseDetectionEvaluation(),
      loadTimeline(),
      loadEvents(true),
      loadFindings(),
      loadAnswerCandidates(),
      loadRisk(),
      loadEntities(),
      loadUsers(),
      loadBookmarks(true),
      loadSavedSearches(),
      loadSearchIndexMetadata(),
      loadAuditLog(),
      loadAnalyzerRuns(),
      loadJobs()
    ];
    if (activeTab === 'correlation') refreshes.push(loadCorrelations());
    if (activeTab === 'chains') refreshes.push(loadCorrelationChains());
    if (activeTab === 'process_tree') refreshes.push(loadProcessTree());
    await Promise.all(refreshes);
    overviewFacets = await getEventFacets(
      caseRoot,
      { artifactType: null, userName: null, search: null, sortBy: 'event_time_utc', sortDir: 'asc' },
      10
    );
    if (activeTab === 'ioc') {
      await runIocMatch();
    }
    if (activeTab === 'defender') {
      await loadDefender();
    }
    if (activeArtifactView) {
      if (activeTab === 'artifact_prefetch') {
        await loadPrefetchSummary();
      }
      await loadArtifactEvents(true);
    }
  }

  async function refreshActiveTab() {
    if (!summary) {
      bookmarks = [];
      return;
    }
    bookmarks = await getEventBookmarks(caseRoot);
    if (activeTab === 'overview') {
      await loadCaseCustodyProfile();
      if (findings.length === 0) await loadFindings();
      if (risks.length === 0) await loadRisk();
      await loadOverviewData();
    }
    if (activeTab === 'evidence_ledger') await loadFiles();
    if (activeTab === 'files') await loadFiles();
    if (activeTab === 'hex') await loadHexFiles();
    if (activeTab === 'coverage') await loadCoverage();
    if (activeTab === 'triage') await loadTriageActions();
    if (activeTab === 'evaluation') await loadCaseDetectionEvaluation();
    if (activeTab === 'timeline') {
      await loadTimelineSeverity();
      await loadTimelineMarkers();
      // 初期表示は最古のビンを選択し、一番古いイベントを右ペインに出しておく
      // (既に選択済みなら尊重して上書きしない)。
      if (!timelineSelectedBin) {
        const bins =
          timelineGranularity === 'week' ? rebucketWeekBins(timelineSeverityBins) : timelineSeverityBins;
        if (bins.length > 0) await selectTimelineBin(bins[0]);
      }
    }
    if (activeTab === 'events') {
      if (eventSubtab === 'users') {
        await loadUsers();
      } else {
        await loadEvents(true);
      }
    }
    if (activeTab === 'saved_searches') await loadSavedSearches();
    if (activeTab === 'search_index') await loadSearchIndexMetadata();
    if (activeTab === 'findings') await loadFindings();
    if (activeTab === 'answers') await loadAnswerCandidates();
    if (activeTab === 'ioc') await runIocMatch();
    if (activeTab === 'defender') await loadDefender();
    if (activeTab === 'risk') await loadRisk();
    if (activeTab === 'correlation') await loadCorrelations();
    if (activeTab === 'chains') await loadCorrelationChains();
    if (activeTab === 'process_tree') await loadProcessTree();
    if (activeTab === 'graph') await loadEntities();
    if (activeTab === 'artifact_prefetch') await loadPrefetchSummary();
    if (activeArtifactView) await loadArtifactEvents(true);
    if (activeTab === 'bookmarks') await loadBookmarks(true);
    if (activeTab === 'approvals') await loadCaseApprovals();
    if (activeTab === 'audit') await loadAuditLog();
    if (activeTab === 'analyzers') await loadAnalyzerRuns();
    if (activeTab === 'jobs') await loadJobs();
  }

  async function setTab(tab: Tab) {
    exportMenuOpen = false;
    rememberViewBeforeChange(tab, eventSubtab);
    activeTab = tab;
    await run(refreshActiveTab);
  }

  async function setEventSubtab(tab: EventSubtab) {
    exportMenuOpen = false;
    rememberViewBeforeChange('events', tab);
    activeTab = 'events';
    eventSubtab = tab;
    if (!summary) return;
    await run(async () => {
      if (tab === 'users') {
        await loadUsers();
      } else {
        await loadEvents(true);
      }
    });
  }

  async function setEventArtifactSubtab(tab: ArtifactTab) {
    exportMenuOpen = false;
    const changingArtifactTab = activeTab !== tab;
    rememberViewBeforeChange(tab, 'all');
    activeTab = tab;
    eventSubtab = 'all';
    if (changingArtifactTab) {
      resetEventListSearchForArtifactView();
      resetArtifactScopedFilters();
    }
    if (!artifactQuickFiltersFor(artifactViews[tab].artifactType).some((filter) => filter.id === artifactQuickFilter)) {
      artifactQuickFilter = '';
    }
    await run(refreshActiveTab);
  }

  function sameViewState(left: ViewState, right: ViewState) {
    return left.tab === right.tab && left.eventSubtab === right.eventSubtab;
  }

  function rememberViewBeforeChange(nextTab: Tab, nextEventSubtab: EventSubtab = eventSubtab) {
    const current = { tab: activeTab, eventSubtab };
    const next = { tab: nextTab, eventSubtab: nextEventSubtab };
    if (sameViewState(current, next)) return;
    const last = viewHistory[viewHistory.length - 1];
    if (last && sameViewState(last, current)) return;
    viewHistory = [...viewHistory, current].slice(-50);
  }

  async function goBackView() {
    const previous = viewHistory[viewHistory.length - 1];
    if (!previous) return;
    viewHistory = viewHistory.slice(0, -1);
    exportMenuOpen = false;
    activeTab = previous.tab;
    eventSubtab = previous.eventSubtab;
    await run(refreshActiveTab);
  }

  function viewTitleFor(tab: Tab, subtab: EventSubtab, artifactView: ArtifactView | null) {
    if (artifactView) return artifactView.label;
    if (tab === 'events') return subtab === 'users' ? $t('events.title.by_user') : $t('events.title.all');
    return tabs.find((item) => item.id === tab)?.label ?? tab;
  }

  function viewFilterSummaryFor(
    tab: Tab,
    subtab: EventSubtab,
    search: string,
    artifactType: string,
    user: string,
    eventIds: string,
    quickFilter: string
  ) {
    const parts = [];
    if (search) parts.push(`${$t('filter.search')}: "${search}"`);
    if (artifactType && tab === 'events') parts.push(`${$t('common.type')}: ${artifactType}`);
    if (user || subtab === 'users') parts.push(`${$t('common.user')}: ${user || $t('common.list_all')}`);
    if (eventIds) parts.push(`Event ID: ${eventIds}`);
    if (artifactViewFor(tab) && quickFilter) parts.push(`${$t('filter.quick')}: ${quickFilter}`);
    return parts.length > 0 ? parts.slice(0, 3).join(' / ') : '';
  }

  async function loadFiles() {
    const page = await getFilePage(caseRoot, 100, null);
    files = page.rows;
  }

  async function loadCaseCustodyProfile() {
    custodyProfile = await getCaseCustodyProfile(caseRoot);
    syncCustodyControls();
  }

  async function loadCaseApprovals() {
    caseApprovals = await getCaseApprovals(caseRoot, 100);
  }

  async function loadSavedSearches() {
    savedSearches = await getSavedSearches(caseRoot, 100, savedSearchViewer.trim() || null);
  }

  async function loadSearchIndexMetadata() {
    searchIndexStatus = await getSearchIndexStatus(caseRoot);
    searchIndexMetadata = searchIndexStatus.metadata ?? null;
  }

  async function startSearchIndexRebuild() {
    await startSearchIndexBuild(caseRoot);
    await loadSearchIndexMetadata();
    await loadAnalyzerRuns();
    await loadJobs();
    await loadAuditLog();
  }

  async function startAnswerCandidateRebuild() {
    await startAnswerCandidateBuild(caseRoot);
    await loadAnswerCandidates();
    await loadAnalyzerRuns();
    await loadJobs();
    await loadAuditLog();
  }

  function syncCustodyControls() {
    custodyInvestigator = custodyProfile?.investigator ?? '';
    custodyCustodian = custodyProfile?.custodian ?? '';
    custodyOrganization = custodyProfile?.organization ?? '';
    custodyEvidenceSource = custodyProfile?.evidence_source ?? '';
    custodyAcquisitionMethod = custodyProfile?.acquisition_method ?? '';
    custodyAcquiredAt = datetimeLocalFromIso(custodyProfile?.acquired_at);
    custodyLegalAuthority = custodyProfile?.legal_authority ?? '';
    custodyChainNote = custodyProfile?.chain_of_custody_note ?? '';
  }

  function datetimeLocalFromIso(value: string | null | undefined) {
    if (!value) return '';
    const timestamp = Date.parse(value);
    if (!Number.isFinite(timestamp)) return '';
    return new Date(timestamp).toISOString().slice(0, 16);
  }

  function datetimeLocalToUtcIso(value: string) {
    const trimmed = value.trim();
    if (!trimmed) return null;
    return `${trimmed.length === 16 ? trimmed : trimmed.slice(0, 16)}:00Z`;
  }

  async function saveCaseCustodyProfile() {
    custodyProfile = await setCaseCustodyProfile(caseRoot, {
      investigator: custodyInvestigator.trim() || null,
      custodian: custodyCustodian.trim() || null,
      organization: custodyOrganization.trim() || null,
      evidence_source: custodyEvidenceSource.trim() || null,
      acquisition_method: custodyAcquisitionMethod.trim() || null,
      acquired_at: datetimeLocalToUtcIso(custodyAcquiredAt),
      legal_authority: custodyLegalAuthority.trim() || null,
      chain_of_custody_note: custodyChainNote.trim() || null
    });
    syncCustodyControls();
    await loadAuditLog();
  }

  async function runEvidenceVerification(reset = true) {
    const cursor = reset ? null : nextEvidenceVerificationCursor;
    const page = await verifyEvidencePage(caseRoot, 25, cursor);
    evidenceVerifications = reset ? page.rows : [...evidenceVerifications, ...page.rows];
    nextEvidenceVerificationCursor = page.next_cursor;
    await loadAuditLog();
  }

  async function exportCustodyManifest() {
    const outputPath = await generateCustodyManifest(caseRoot);
    custodyManifestPath = outputPath;
    custodyManifestVerification = null;
    setApprovalTarget('custody_manifest', outputPath);
    setExportStatus(
      $locale === 'en'
        ? `Exported custody manifest to ${outputPath}`
        : `保全マニフェストを ${outputPath} に出力しました`
    );
    await loadAuditLog();
  }

  async function exportReportBundle() {
    const outputPath = await generateReportBundle(caseRoot);
    reportBundlePath = outputPath;
    reportBundleVerification = null;
    setApprovalTarget('report_bundle', outputPath);
    setExportStatus(
      $locale === 'en'
        ? `Exported report bundle to ${outputPath}`
        : `レポートバンドルを ${outputPath} に出力しました`
    );
    await loadAuditLog();
  }

  async function verifyCurrentReportBundle() {
    const bundlePath = reportBundlePath.trim();
    if (!bundlePath) {
      errorMessage = $t('verify.err.bundle_path');
      return;
    }
    reportBundleVerification = await verifyReportBundle(caseRoot, bundlePath);
    setApprovalTarget('report_bundle', bundlePath);
    await loadAuditLog();
  }

  async function verifyCurrentCustodyManifest() {
    const manifestPath = custodyManifestPath.trim();
    if (!manifestPath) {
      errorMessage = $t('verify.err.manifest_path');
      return;
    }
    custodyManifestVerification = await verifyCustodyManifest(caseRoot, manifestPath, 500);
    setApprovalTarget('custody_manifest', manifestPath);
    await loadAuditLog();
  }

  function setApprovalTarget(kind: string, path: string, id = '') {
    approvalTargetKind = kind;
    approvalTargetPath = path;
    approvalTargetId = id;
  }

  function currentApprovalSha256() {
    if (approvalTargetKind === 'report_bundle') {
      return reportBundleVerification?.bundle_sha256 ?? reportBundleVerification?.computed_bundle_sha256 ?? null;
    }
    if (approvalTargetKind === 'custody_manifest') {
      return custodyManifestVerification?.manifest_sha256 ?? custodyManifestVerification?.computed_manifest_sha256 ?? null;
    }
    return null;
  }

  async function saveCaseApproval() {
    const targetPath = approvalTargetPath.trim();
    const targetId = approvalTargetId.trim();
    if (!targetPath && !targetId) {
      errorMessage = $t('approval.err.target');
      return;
    }
    caseApprovals = await setCaseApproval(
      caseRoot,
      approvalTargetKind.trim() || 'artifact',
      approvalStatus,
      approvalApprover.trim() || null,
      approvalRole.trim() || null,
      approvalComment.trim() || null,
      targetPath || null,
      targetId || null,
      currentApprovalSha256()
    );
    await loadAuditLog();
  }

  function verificationForFile(fileId: string) {
    return evidenceVerifications.find((row) => row.file_id === fileId) ?? null;
  }

  async function loadAuditLog() {
    auditLog = await getAuditLog(caseRoot, 200);
  }

  async function loadCoverage() {
    [coverage, failedParsers] = await Promise.all([
      getCoverageSummary(caseRoot),
      getFailedParserSummary(caseRoot)
    ]);
  }

  async function loadTriageActions() {
    triageActions = await getTriageActions(caseRoot, 150);
  }

  async function loadCaseDetectionEvaluation() {
    caseDetectionEvaluation = await getCaseDetectionEvaluation(caseRoot);
  }

  async function loadTimeline() {
    timeline = await getTimelineBins(caseRoot);
    await loadTimelineSeverity();
  }

  async function loadCorrelations() {
    correlationStatus = '';
    correlations = await getCorrelationSummary(caseRoot, 100);
    if (correlations.length === 0 && (summary?.event_count ?? 0) > 200_000) {
      correlationStatus =
        $t('corr.large_case_notice');
    }
  }

  async function loadCorrelationChains() {
    correlationChainsStatus = '';
    correlationChains = await getCorrelationChains(caseRoot, 100);
    if (correlationChains.length === 0 && (summary?.event_count ?? 0) > 200_000) {
      correlationChainsStatus =
        $t('corr.large_case_notice');
    }
    if (!selectedChain && correlationChains[0]) {
      await selectCorrelationChain(correlationChains[0]);
    } else if (
      selectedChain &&
      !correlationChains.some(
        (chain) => chain.key_kind === selectedChain?.key_kind && chain.key_value === selectedChain?.key_value
      )
    ) {
      selectedChain = null;
      chainEventRows = [];
      nextChainEventCursor = null;
    } else if (selectedChain) {
      await loadCorrelationChainEvents(true);
    }
  }

  async function loadProcessTree() {
    processTreeStatus = '';
    processNodes = await getProcessTreeInstances(caseRoot);
    if (processNodes.length === 0) {
      processTreeStatus =
        (summary?.event_count ?? 0) > 0 ? $t('ptree.no_process_events') : '';
    }
    // 初期表示は全展開にしてツリー構造(接続線)がすぐ見えるようにする。
    processTreeExpanded = new Set(processNodes.map((node) => node.key));
    selectedProcessNode = null;
  }

  // key/parent_key のフラットなノード列から森(roots + children map)を組む。
  function buildProcessForest(nodes: ProcessNode[]) {
    const byKey = new Map<string, ProcessNode>();
    for (const node of nodes) byKey.set(node.key, node);
    const children = new Map<string, ProcessNode[]>();
    const roots: ProcessNode[] = [];
    for (const node of nodes) {
      const pk = node.parent_key;
      if (pk && byKey.has(pk) && pk !== node.key) {
        const list = children.get(pk) ?? [];
        list.push(node);
        children.set(pk, list);
      } else {
        roots.push(node);
      }
    }
    return { byKey, children, roots };
  }

  // 重大度ランク(検知重大度): critical>high>medium>low>info。medium 以上を「注目」とする。
  function processSeverityRank(severity: string | null): number {
    switch ((severity ?? '').toLowerCase()) {
      case 'critical':
        return 5;
      case 'high':
        return 4;
      case 'medium':
        return 3;
      case 'low':
        return 2;
      case 'info':
        return 1;
      default:
        return 0;
    }
  }
  // 注目ノード: high 以上の検知が紐づくプロセス(広域インベントリの medium/info を除外)。
  function isNotableProcess(node: ProcessNode): boolean {
    return node.has_finding && processSeverityRank(node.severity) >= 4;
  }

  $: processForest = buildProcessForest(processNodes);
  // 注目(high/critical)ノードとその祖先だけを残す集合(危険な系譜のみ表示用)。
  $: processDangerKeep = computeProcessDangerKeep(processNodes, processForest);
  // 展開状態とフィルタから、描画する行(node + 深さ + 子有無)を平坦化。
  $: processTreeRows = flattenProcessForest(
    processForest,
    processTreeExpanded,
    processTreeFilter,
    processDangerOnly ? processDangerKeep : null
  );
  $: processFindingCount = processNodes.filter((node) => isNotableProcess(node)).length;

  function computeProcessDangerKeep(
    nodes: ProcessNode[],
    forest: ReturnType<typeof buildProcessForest>
  ): Set<string> {
    const keep = new Set<string>();
    for (const node of nodes) {
      if (!isNotableProcess(node)) continue;
      keep.add(node.key);
      let cursor: ProcessNode | undefined = node;
      let guard = 0;
      while (cursor?.parent_key && forest.byKey.has(cursor.parent_key) && guard < 128) {
        keep.add(cursor.parent_key);
        cursor = forest.byKey.get(cursor.parent_key);
        guard += 1;
      }
    }
    return keep;
  }

  function flattenProcessForest(
    forest: ReturnType<typeof buildProcessForest>,
    expanded: Set<string>,
    filter: string,
    restrict: Set<string> | null
  ): Array<{ node: ProcessNode; depth: number; hasChildren: boolean; guides: boolean[] }> {
    const needle = filter.trim().toLowerCase();
    // 危険な系譜のみ: restrict に含まれるノードだけを常に展開して表示。
    if (restrict) {
      const rows: Array<{
        node: ProcessNode;
        depth: number;
        hasChildren: boolean;
        guides: boolean[];
      }> = [];
      const visit = (node: ProcessNode, depth: number, guides: boolean[]) => {
        const kids = (forest.children.get(node.key) ?? []).filter((k) => restrict.has(k.key));
        rows.push({ node, depth, hasChildren: kids.length > 0, guides });
        kids.forEach((kid, i) => visit(kid, depth + 1, [...guides, i < kids.length - 1]));
      };
      for (const root of forest.roots.filter((r) => restrict.has(r.key))) visit(root, 0, []);
      return rows;
    }
    // フィルタ時は展開状態を無視し、名前/コマンドラインが一致する行を平坦表示。
    if (needle) {
      return forest.roots
        .flatMap(function collect(node): ProcessNode[] {
          const kids = forest.children.get(node.key) ?? [];
          return [node, ...kids.flatMap(collect)];
        })
        .filter(
          (node) =>
            node.name.toLowerCase().includes(needle) ||
            (node.command_line ?? '').toLowerCase().includes(needle)
        )
        .map((node) => ({
          node,
          depth: 0,
          hasChildren: (forest.children.get(node.key) ?? []).length > 0,
          guides: [] as boolean[]
        }));
    }
    // guides[i] = そのレベル i の祖先に「次の兄弟」がいるか(縦線を引くか)。
    // 末尾要素は自ノードの兄弟有無(├ か └ か)を表す。
    const rows: Array<{ node: ProcessNode; depth: number; hasChildren: boolean; guides: boolean[] }> =
      [];
    const visit = (node: ProcessNode, depth: number, guides: boolean[]) => {
      const kids = forest.children.get(node.key) ?? [];
      rows.push({ node, depth, hasChildren: kids.length > 0, guides });
      if (expanded.has(node.key)) {
        kids.forEach((kid, i) => visit(kid, depth + 1, [...guides, i < kids.length - 1]));
      }
    };
    for (const root of forest.roots) visit(root, 0, []);
    return rows;
  }

  function toggleProcessNode(key: string) {
    const next = new Set(processTreeExpanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    processTreeExpanded = next;
  }

  function expandAllProcessNodes() {
    processTreeExpanded = new Set(processNodes.map((node) => node.key));
  }

  function collapseAllProcessNodes() {
    processTreeExpanded = new Set();
  }

  // ノード本体クリック: 子があれば開閉し、詳細ドロワーを開く。
  function activateProcessNode(node: ProcessNode, hasChildren: boolean) {
    if (hasChildren) toggleProcessNode(node.key);
    selectedProcessNode = node;
  }

  function closeProcessDetail() {
    selectedProcessNode = null;
  }

  async function drillDownProcessNode(node: ProcessNode) {
    await drillDownToEvents({ search: `process:"${node.name}"` });
  }

  // 同名 or 同ハッシュの他インスタンス(自分以外)。
  function processOtherInstances(node: ProcessNode): ProcessNode[] {
    return processNodes.filter(
      (p) => p.key !== node.key && (p.name === node.name || (!!node.hash && p.hash === node.hash))
    );
  }

  // プロセス生成時刻の前後 ±15分の窓(イベント一覧のタイムライン文脈用)。
  function processTimeWindow(node: ProcessNode): { startUtc?: string; endUtc?: string } {
    const t = node.first_seen_utc;
    if (!t) return {};
    const ms = Date.parse(t);
    if (Number.isNaN(ms)) return {};
    const iso = (v: number) => new Date(v).toISOString().slice(0, 16);
    return { startUtc: iso(ms - 15 * 60000), endUtc: iso(ms + 15 * 60000) };
  }

  async function drillProcessTimeline(node: ProcessNode) {
    const win = processTimeWindow(node);
    if (!win.startUtc) return;
    await drillDownToEvents({ startUtc: win.startUtc, endUtc: win.endUtc });
  }

  // 選択プロセス(同一 ProcessGuid)に紐づく非生成イベント(ネット/ファイル/レジストリ等)を読み込む。
  async function loadProcessRelated(node: ProcessNode | null) {
    processRelated = [];
    if (!node?.guid) {
      processRelatedLoading = false;
      return;
    }
    const token = ++processRelatedToken;
    processRelatedLoading = true;
    const rows = await getProcessRelatedEvents(caseRoot, node.guid).catch(
      () => [] as ProcessRelatedEvent[]
    );
    if (token === processRelatedToken) {
      processRelated = rows;
      processRelatedLoading = false;
    }
  }
  $: void loadProcessRelated(selectedProcessNode);

  // 関連イベントの大分類(ネット/ファイル/レジストリ/その他)。スレッド/インジェクション/
  // イメージロード/名前付きパイプ等はファイル/ネットに誤分類しないよう先に other へ。
  function relatedCategory(e: ProcessRelatedEvent): string {
    const a = `${e.event_action} ${e.artifact_type}`.toLowerCase();
    if (/thread|inject|image_load|process_access|process_terminat|pipe/.test(a)) return 'other';
    if (/network|connect|dns|socket|http|tcp|udp|beacon/.test(a)) return 'network';
    if (/registry|regvalue|regkey|reg_/.test(a)) return 'registry';
    if (/file|usn|mft|create|delete|rename|write|lnk|prefetch|amcache/.test(a)) return 'file';
    return 'other';
  }
  $: processRelatedCounts = processRelated.reduce(
    (acc, e) => {
      const c = relatedCategory(e);
      acc[c] = (acc[c] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  // 選択プロセスの祖先チェーン(ルート→自分)をテキスト化(コピー/報告書用)。
  function processAncestryText(node: ProcessNode): string {
    const chain: ProcessNode[] = [];
    let cursor: ProcessNode | undefined = node;
    let guard = 0;
    while (cursor && guard < 128) {
      chain.unshift(cursor);
      cursor = cursor.parent_key ? processForest.byKey.get(cursor.parent_key) : undefined;
      guard += 1;
    }
    return chain
      .map((n, i) => {
        const head = `${'  '.repeat(i)}${i > 0 ? '└ ' : ''}${n.name}${n.pid ? ` [${n.pid}]` : ''}`;
        return n.command_line ? `${head}  ${n.command_line}` : head;
      })
      .join('\n');
  }

  // Sysmon の Hashes は "MD5=..,SHA256=..,IMPHASH=.." 形式。SHA256 だけ取り出す。
  function processSha256(node: ProcessNode): string {
    const h = node.hash;
    if (!h) return '—';
    const m = h.match(/SHA256=([0-9a-fA-F]{64})/i);
    return m ? m[1] : h;
  }

  // 右詳細ペインの幅(ドラッグで変更可能)。
  let processDetailWidth = 620;
  let ptreeDragStartX = 0;
  let ptreeDragStartW = 0;
  function onPtreeResize(e: MouseEvent) {
    const delta = ptreeDragStartX - e.clientX;
    processDetailWidth = Math.max(360, Math.min(1100, ptreeDragStartW + delta));
  }
  function stopPtreeResize() {
    window.removeEventListener('mousemove', onPtreeResize);
    window.removeEventListener('mouseup', stopPtreeResize);
    document.body.style.userSelect = '';
    document.body.style.cursor = '';
  }
  function startPtreeResize(e: MouseEvent) {
    ptreeDragStartX = e.clientX;
    ptreeDragStartW = processDetailWidth;
    window.addEventListener('mousemove', onPtreeResize);
    window.addEventListener('mouseup', stopPtreeResize);
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'col-resize';
    e.preventDefault();
  }

  let processCopiedKey: string | null = null;
  async function copyProcessValue(text: string, tagKey: string) {
    try {
      await navigator.clipboard.writeText(text);
      processCopiedKey = tagKey;
      setTimeout(() => {
        if (processCopiedKey === tagKey) processCopiedKey = null;
      }, 1200);
    } catch {
      // clipboard unavailable; ignore
    }
  }

  async function loadFindings() {
    [findings, findingOverrides, findingReviews, findingReviewSummary] = await Promise.all([
      getFindingSummary(caseRoot, 100),
      getFindingOverrides(caseRoot),
      getFindingReviews(caseRoot),
      getFindingReviewSummary(caseRoot)
    ]);
    if (!selectedFinding && findings[0]) {
      await selectFinding(findings[0]);
    } else if (selectedFinding && !findings.some((finding) => sameFinding(finding, selectedFinding))) {
      selectedFinding = null;
      findingEventRows = [];
      nextFindingEventCursor = null;
    } else if (selectedFinding) {
      syncFindingReviewControls(selectedFinding);
      await loadFindingEvents(true);
    }
  }

  async function loadAnswerCandidates() {
    answerCandidates = await getAnswerCandidates(caseRoot, answerQuestionFilter || null, 250);
    if (
      selectedAnswerCandidate &&
      !answerCandidates.some((row) => row.candidate_id === selectedAnswerCandidate?.candidate_id)
    ) {
      selectedAnswerCandidate = null;
    }
    if (!selectedAnswerCandidate && answerCandidates[0]) {
      selectedAnswerCandidate = answerCandidates[0];
    }
  }

  async function applyAnswerQuestionFilter() {
    selectedAnswerCandidate = null;
    await loadAnswerCandidates();
  }

  async function clearAnswerQuestionFilter() {
    answerQuestionFilter = '';
    await applyAnswerQuestionFilter();
  }

  function parsedIocs() {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const value of iocInput.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean)) {
      const key = value.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(value);
      if (out.length >= 500) break;
    }
    return out;
  }

  async function runIocMatch() {
    const indicators = parsedIocs();
    if (indicators.length === 0) {
      iocHits = [];
      selectedIoc = null;
      iocEventRows = [];
      nextIocEventCursor = null;
      return;
    }
    iocHits = await getIocMatches(caseRoot, indicators, 100);
    if (!selectedIoc && iocHits[0]) {
      await selectIoc(iocHits[0]);
    } else if (selectedIoc && !iocHits.some((hit) => hit.ioc === selectedIoc?.ioc)) {
      selectedIoc = null;
      iocEventRows = [];
      nextIocEventCursor = null;
    } else if (selectedIoc) {
      await loadIocEvents(true);
    } else {
      iocEventRows = [];
      nextIocEventCursor = null;
    }
  }

  async function publishIocFindings() {
    const indicators = parsedIocs();
    if (indicators.length === 0) return;
    findings = await runIocFindings(caseRoot, indicators, 500);
    await Promise.all([
      loadRisk(),
      loadEvents(true),
      loadAnalyzerRuns(),
      loadAuditLog(),
      runIocMatch()
    ]);
  }

  async function selectIoc(hit: IocHit) {
    selectedIoc = hit;
    await loadIocEvents(true);
  }

  async function loadIocEvents(reset: boolean) {
    if (!selectedIoc) return;
    const cursor = reset ? null : nextIocEventCursor;
    const page = await getIocEventPage(
      caseRoot,
      selectedIoc.ioc,
      100,
      cursor,
      eventSortBy,
      eventSortDir,
      currentEventSearch()
    );
    iocEventRows = reset ? page.rows : [...iocEventRows, ...page.rows];
    nextIocEventCursor = page.next_cursor;
  }


  async function loadDefender() {
    defenderSummaries = await getDefenderSummary(caseRoot, 100);
    if (!selectedDefenderCategory && defenderSummaries[0]) {
      await selectDefenderCategory(defenderSummaries[0]);
    } else if (
      selectedDefenderCategory &&
      !defenderSummaries.some((row) => row.category === selectedDefenderCategory?.category)
    ) {
      selectedDefenderCategory = null;
      defenderEventRows = [];
      nextDefenderEventCursor = null;
    } else if (selectedDefenderCategory) {
      await loadDefenderEvents(true);
    }
  }

  async function selectDefenderCategory(row: DefenderSummary) {
    selectedDefenderCategory = row;
    await loadDefenderEvents(true);
    // マスター選択時点で先頭イベントを下部の調査ペインへ自動表示する
    if (defenderEventRows.length > 0) selectEvent(defenderEventRows[0], false);
  }

  async function loadDefenderEvents(reset: boolean) {
    const cursor = reset ? null : nextDefenderEventCursor;
    const page = await getDefenderEventPage(
      caseRoot,
      selectedDefenderCategory?.category ?? null,
      100,
      cursor,
      eventSortBy,
      eventSortDir,
      currentEventSearch()
    );
    defenderEventRows = reset ? page.rows : [...defenderEventRows, ...page.rows];
    nextDefenderEventCursor = page.next_cursor;
  }

  async function loadPrefetchSummary() {
    prefetchSummaries = await getPrefetchSummary(caseRoot, 100);
    if (
      selectedPrefetchSummary &&
      !prefetchSummaries.some((row) => row.process_name === selectedPrefetchSummary?.process_name)
    ) {
      selectedPrefetchSummary = null;
    }
  }

  async function selectPrefetchSummary(row: PrefetchSummary) {
    selectedPrefetchSummary = row;
    eventSearchText = row.process_name;
    appliedEventSearch = row.process_name;
    await loadArtifactEvents(true);
  }

  async function loadRisk() {
    riskStatus = '';
    risks = await getRiskSummary(caseRoot, 100);
    if (risks.length === 0 && (summary?.event_count ?? 0) > 0) {
      riskStatus = activeDetectionReadModelJob
        ? `${$t('risk.readmodel_generating')}: ${Math.round(activeDetectionReadModelJob.progress * 100)}%`
        : $t('risk.no_findings_yet');
    }
  }

  async function loadAnalyzerRuns() {
    analyzerRuns = await getAnalyzerRuns(caseRoot, 100);
  }

  async function loadEntities() {
    entities = await getEntitySummary(caseRoot, 100);
    if (!selectedEntity && entities[0]) {
      await selectEntity(entities[0]);
    } else if (selectedEntity && !entities.some((entity) => entity.entity_id === selectedEntity?.entity_id)) {
      selectedEntity = null;
      subgraph = { nodes: [], edges: [] };
    }
  }

  async function loadUsers() {
    users = await getUserActivitySummary(caseRoot, 100);
    if (!selectedUser && users[0]) {
      await selectUser(users[0]);
    } else if (selectedUser && !users.some((user) => user.user_name === selectedUser?.user_name)) {
      selectedUser = null;
      userEventRows = [];
      nextUserEventCursor = null;
    }
  }

  async function loadBookmarks(reset: boolean) {
    bookmarks = await getEventBookmarks(caseRoot);
    await loadBookmarkEvents(reset);
  }

  async function loadBookmarkEvents(reset: boolean) {
    const cursor = reset ? null : nextBookmarkEventCursor;
    const page = await getBookmarkEventPage(
      caseRoot,
      100,
      cursor,
      eventSortBy,
      eventSortDir,
      currentEventSearch()
    );
    bookmarkEventRows = reset ? page.rows : [...bookmarkEventRows, ...page.rows];
    nextBookmarkEventCursor = page.next_cursor;
  }

  function currentEventFilters() {
    return {
      artifactType: eventArtifactFilter.trim() || null,
      userName: null,
      search: currentEventSearch(),
      sortBy: eventSortBy,
      sortDir: eventSortDir
    };
  }

  async function loadEventFacets() {
    eventFacets = await getEventFacets(caseRoot, currentEventFilters(), 8);
  }

  async function loadOverviewData() {
    [timeline, overviewFacets, overviewSeverityBins] = await Promise.all([
      getTimelineBins(caseRoot),
      getEventFacets(
        caseRoot,
        {
          artifactType: null,
          userName: null,
          search: null,
          sortBy: 'event_time_utc',
          sortDir: 'asc'
        },
        10
      ),
      getEventTimeline(caseRoot, {}, 'day')
    ]);
    // 高度チャート。1つ失敗しても概要全体は壊さない(各々 catch)。
    [timestompPoints, processTreeEdges, fileOpBins, beaconBins] = await Promise.all([
      getTimestompScatter(caseRoot).catch(() => [] as TimestompPoint[]),
      getProcessTree(caseRoot).catch(() => [] as ProcessTreeEdge[]),
      getFileOpTimeline(caseRoot).catch(() => [] as FileOpBin[]),
      getBeaconIntervals(caseRoot).catch(() => [] as BeaconIntervalBin[])
    ]);
  }

  async function runIndexedSearch(reset: boolean) {
    const cursor = reset ? null : nextIndexedSearchCursor;
    try {
      const page = await searchIndexedEvents(caseRoot, indexedSearchText.trim(), 50, cursor);
      indexedSearchHits = reset ? page.rows : [...indexedSearchHits, ...page.rows];
      nextIndexedSearchCursor = page.next_cursor;
      indexedSearchNotice = '';
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // 未構築なら生エラーを出さず、バックグラウンド構築を開始して案内する。
      if (/not built|未構築|not ready|no index|index/i.test(msg)) {
        indexedSearchHits = [];
        nextIndexedSearchCursor = null;
        if (activeSearchIndexJob) {
          indexedSearchNotice = $t('search.index.building');
        } else {
          await startSearchIndexBuild(caseRoot);
          await loadSearchIndexMetadata();
          indexedSearchNotice = $t('search.index.started');
        }
      } else {
        throw e;
      }
    }
  }

  async function loadEvents(reset: boolean) {
    if (reset) {
      resetEventScroll();
    }
    const cursor = reset ? null : nextEventCursor;
    const page = await getEventPage(caseRoot, 100, cursor, {
      ...currentEventFilters()
    });
    eventRows = reset ? page.rows : [...eventRows, ...page.rows];
    nextEventCursor = page.next_cursor;
    if (reset) {
      await loadEventFacets();
    }
    if (reset) {
      resetEventScroll();
    }
    if (!selectedEvent && eventRows[0]) {
      selectEvent(eventRows[0], false);
    }
  }

  async function loadArtifactEvents(reset: boolean) {
    const artifactView = artifactViewFor(activeTab);
    if (!artifactView) return;
    if (reset) {
      resetArtifactScroll();
    }
    const cursor = reset ? null : nextArtifactEventCursor;
    const page = await getEventPage(caseRoot, artifactEventPageSize, cursor, {
      artifactType: artifactView.artifactType,
      search: currentEventSearch(),
      sortBy: eventSortBy,
      sortDir: eventSortDir
    });
    artifactEventRows = reset ? page.rows : [...artifactEventRows, ...page.rows];
    nextArtifactEventCursor = page.next_cursor;
    if (!selectedEvent && artifactEventRows[0]) {
      selectEvent(artifactEventRows[0], false);
    }
  }

  function resetEventScroll() {
    eventScrollTop = 0;
    if (!eventScroller) return;
    eventScroller.scrollTop = 0;
    requestAnimationFrame(() => {
      if (eventScroller) {
        eventScroller.scrollTop = 0;
      }
    });
  }

  function resetArtifactScroll() {
    artifactScrollTop = 0;
    if (!artifactScroller) return;
    artifactScroller.scrollTop = 0;
    requestAnimationFrame(() => {
      if (artifactScroller) {
        artifactScroller.scrollTop = 0;
      }
    });
  }

  async function selectUser(user: UserActivitySummary) {
    selectedUser = user;
    await loadUserEvents(true);
  }

  async function selectEntity(entity: EntityRecord) {
    selectedEntity = entity;
    subgraph = await getSubgraph(caseRoot, entity.entity_id, 1, 200);
  }

  async function selectFinding(finding: FindingSummary) {
    selectedFinding = finding;
    syncFindingReviewControls(finding);
    await loadFindingEvents(true);
    // 他タブと同様に、マスター選択時点で先頭の検知イベントを下部の調査ペインへ自動表示する
    if (findingEventRows.length > 0) selectEvent(findingEventRows[0], false);
  }

  function syncFindingReviewControls(finding: FindingSummary) {
    const review = reviewForFinding(finding);
    reviewStatus = reviewStatusValue(review?.status);
    reviewReviewer = review?.reviewer ?? 'analyst';
    reviewAssignee = review?.assignee ?? '';
    reviewTags = reviewTagsText(review?.tags_json);
    reviewDueAt = dueAtInputValue(review?.due_at);
    reviewComment = review?.comment ?? '';
  }

  function sameFinding(left: FindingSummary, right: FindingSummary | null) {
    return Boolean(
      right &&
        left.title === right.title &&
        left.engine === right.engine &&
        (left.rule_id ?? null) === (right.rule_id ?? null)
    );
  }

  function reviewForFinding(finding: FindingSummary) {
    return (
      findingReviews.find(
        (review) =>
          review.engine === finding.engine &&
          (review.rule_id ?? null) === (finding.rule_id ?? null) &&
          review.title === finding.title
      ) ?? null
    );
  }

  function reviewStatusValue(value: string | null | undefined): FindingReviewStatus {
    if (
      value === 'new' ||
      value === 'in_review' ||
      value === 'confirmed' ||
      value === 'false_positive' ||
      value === 'benign' ||
      value === 'needs_context'
    ) {
      return value;
    }
    return 'in_review';
  }

  function reviewTagsText(tagsJson: string | null | undefined) {
    if (!tagsJson) return '';
    try {
      const parsed = JSON.parse(tagsJson);
      if (!Array.isArray(parsed)) return '';
      return parsed.map((tag) => String(tag).trim()).filter(Boolean).join(', ');
    } catch {
      return '';
    }
  }

  function parseReviewTags(value: string) {
    const seen = new Set<string>();
    const tags: string[] = [];
    for (const tag of value.split(/[,;\n]/).map((part) => part.trim()).filter(Boolean)) {
      const key = tag.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      tags.push(tag);
      if (tags.length >= 20) break;
    }
    return tags;
  }

  function dueAtInputValue(value: string | null | undefined) {
    if (!value) return '';
    const timestamp = Date.parse(value);
    if (!Number.isFinite(timestamp)) return '';
    return new Date(timestamp).toISOString().slice(0, 10);
  }

  function dueAtIsoValue(value: string) {
    const trimmed = value.trim();
    if (!trimmed) return null;
    return `${trimmed}T00:00:00Z`;
  }

  async function saveSelectedFindingReview() {
    if (!selectedFinding) return;
    findingReviews = await setFindingReview(
      caseRoot,
      selectedFinding,
      reviewStatus,
      reviewReviewer.trim() || null,
      reviewAssignee.trim() || null,
      parseReviewTags(reviewTags),
      dueAtIsoValue(reviewDueAt),
      reviewComment.trim() || null
    );
    findingReviewSummary = await getFindingReviewSummary(caseRoot);
    await loadTriageActions();
    await loadAuditLog();
  }

  async function suppressSelectedFinding() {
    if (!selectedFinding) return;
    findingOverrides = await addFindingOverride(caseRoot, selectedFinding, 'suppress', null, 'suppressed in triage');
    selectedFinding = null;
    findingEventRows = [];
    nextFindingEventCursor = null;
    await refreshFindingDerivedViews();
  }

  async function overrideSelectedFindingSeverity() {
    if (!selectedFinding) return;
    findingOverrides = await addFindingOverride(
      caseRoot,
      selectedFinding,
      'severity_override',
      overrideSeverity,
      'severity override in triage'
    );
    await refreshFindingDerivedViews();
  }

  async function removeOverride(overrideId: string) {
    findingOverrides = await removeFindingOverride(caseRoot, overrideId);
    await refreshFindingDerivedViews();
  }

  async function refreshFindingDerivedViews() {
    await Promise.all([
      loadFindings(),
      loadAnswerCandidates(),
      loadRisk(),
      loadTriageActions(),
      loadEvents(true),
      loadAnalyzerRuns(),
      loadAuditLog()
    ]);
  }

  async function bookmarkSelectedEvent() {
    if (!selectedEvent) return;
    bookmarks = await addEventBookmark(
      caseRoot,
      selectedEvent.event_id,
      selectedEvent.process_name ?? selectedEvent.file_path ?? selectedEvent.ip ?? selectedEvent.user_name ?? null,
      selectedEvent.message_short
    );
    await loadBookmarkEvents(true);
    await loadAuditLog();
  }

  async function removeSelectedEventBookmark() {
    if (!selectedEventBookmark) return;
    bookmarks = await removeEventBookmark(caseRoot, selectedEventBookmark.bookmark_id);
    await loadBookmarkEvents(true);
    await loadAuditLog();
  }

  async function removeBookmarkById(bookmarkId: string) {
    bookmarks = await removeEventBookmark(caseRoot, bookmarkId);
    await loadBookmarkEvents(true);
    await loadAuditLog();
  }

  async function selectCorrelationChain(chain: CorrelationChainSummary) {
    selectedChain = chain;
    await loadCorrelationChainEvents(true);
    // マスター選択時点で先頭イベントを下部の調査ペインへ自動表示する
    if (chainEventRows.length > 0) selectEvent(chainEventRows[0], false);
  }

  async function openTriageAction(action: TriageAction) {
    if (action.source_kind === 'finding') {
      rememberViewBeforeChange('findings');
      activeTab = 'findings';
      await loadFindings();
      const finding = findings.find((row) => findingSourceKey(row) === action.source_key);
      if (finding) await selectFinding(finding);
      return;
    }
    if (action.source_kind === 'correlation_chain') {
      rememberViewBeforeChange('chains');
      activeTab = 'chains';
      await loadCorrelationChains();
      const [keyKind, ...valueParts] = action.source_key.split('=');
      const keyValue = valueParts.join('=');
      const chain = correlationChains.find((row) => row.key_kind === keyKind && row.key_value === keyValue);
      if (chain) await selectCorrelationChain(chain);
      return;
    }
    if (action.source_kind === 'parser_failure') {
      rememberViewBeforeChange('coverage');
      activeTab = 'coverage';
      await loadCoverage();
      return;
    }
    if (action.source_kind === 'case_quality_gate') {
      rememberViewBeforeChange('evaluation');
      activeTab = 'evaluation';
      await loadCaseDetectionEvaluation();
      return;
    }
    if (action.source_kind === 'finding_review') {
      rememberViewBeforeChange('findings');
      activeTab = 'findings';
      await loadFindings();
    }
  }

  function findingSourceKey(finding: Pick<FindingSummary, 'engine' | 'rule_id' | 'title'>) {
    return `${finding.engine}:${finding.rule_id ?? '-'}:${finding.title}`;
  }

  async function loadFindingEvents(reset: boolean) {
    if (!selectedFinding) return;
    const cursor = reset ? null : nextFindingEventCursor;
    const page = await getFindingEventPage(
      caseRoot,
      selectedFinding,
      100,
      cursor,
      eventSortBy,
      eventSortDir,
      currentEventSearch()
    );
    findingEventRows = reset ? page.rows : [...findingEventRows, ...page.rows];
    nextFindingEventCursor = page.next_cursor;
  }

  async function loadCorrelationChainEvents(reset: boolean) {
    if (!selectedChain) return;
    const cursor = reset ? null : nextChainEventCursor;
    const page = await getCorrelationChainEventPage(
      caseRoot,
      selectedChain,
      100,
      cursor,
      eventSortBy,
      eventSortDir,
      currentEventSearch()
    );
    chainEventRows = reset ? page.rows : [...chainEventRows, ...page.rows];
    nextChainEventCursor = page.next_cursor;
  }

  async function setEventSort(sortBy: EventSortBy) {
    if (eventSortBy === sortBy) {
      eventSortDir = eventSortDir === 'asc' ? 'desc' : 'asc';
    } else {
      eventSortBy = sortBy;
      eventSortDir = sortBy === 'event_time_utc' ? 'asc' : 'desc';
    }
    eventScrollTop = 0;
    artifactScrollTop = 0;
    await reloadCurrentEventSlice();
  }

  async function loadUserEvents(reset: boolean) {
    if (!selectedUser) return;
    const cursor = reset ? null : nextUserEventCursor;
    const page = await getEventPage(caseRoot, 100, cursor, {
      userName: selectedUser.user_name,
      search: currentEventSearch(),
      sortBy: eventSortBy,
      sortDir: eventSortDir
    });
    userEventRows = reset ? page.rows : [...userEventRows, ...page.rows];
    nextUserEventCursor = page.next_cursor;
  }

  async function loadJobs() {
    jobs = await getRecentJobs(caseRoot, 100);
  }

  function selectEvent(row: EventRow, addToTrail = true) {
    performance.mark('taotie-event-select-start');
    selectedEvent = row;
    if (addToTrail) {
      addInvestigationTrail(row);
    } else if (investigationTrail.length === 0) {
      investigationIndex = -1;
    }
    detail = null;
    eventContext = null;
    rawRecord = null;
    artifactObjects = [];
    evidenceOffsets = [];
    evidenceRange = null;
    evidenceOffset = 0;
    contextLoading = false;
    rawLoading = false;
    evidenceLoading = false;
    structureLoading = false;
    structureLoaded = false;
    detailTab = 'summary';
    const token = ++detailToken;
    cancelScheduledDetailLoad();
    restoreSelectedEventStructureFromCache(row.event_id);
    if (!restoreSelectedEventDetailFromCache(row.event_id)) {
      void loadSelectedEventDetail(row.event_id, token);
    }
  }

  async function loadSelectedEventDetail(eventId: string, token: number) {
    detailLoading = true;
    try {
      const value = await fetchEventDetailCached(eventId);
      if (token === detailToken) {
        detail = value;
      }
    } catch (error) {
      if (token === detailToken) {
        errorMessage = error instanceof Error ? error.message : String(error);
      }
    } finally {
      if (token === detailToken) {
        detailLoading = false;
        performance.mark('taotie-event-detail-loaded');
      }
    }
  }

  function restoreSelectedEventDetailFromCache(eventId: string) {
    const cached = readLruCache(eventDetailCache, eventCacheKey(eventId));
    if (!cached.hit) return false;
    detail = cached.value ?? null;
    detailLoading = false;
    performance.mark('taotie-event-detail-loaded');
    return true;
  }

  function scheduleSelectedEventDetailLoad(eventId: string, token: number) {
    detailLoading = false;
    detailLoadTimer = window.setTimeout(() => {
      detailLoadTimer = null;
      if (token !== detailToken) return;
      void loadSelectedEventDetail(eventId, token);
    }, 150);
  }

  async function loadSelectedEventDetailNow() {
    if (!selectedEvent || detailLoading) return;
    const eventId = selectedEvent.event_id;
    const token = detailToken;
    await loadSelectedEventDetail(eventId, token);
  }

  async function fetchEventDetailCached(eventId: string) {
    const key = eventCacheKey(eventId);
    const cached = readLruCache(eventDetailCache, key);
    if (cached.hit) return cached.value ?? null;
    const value = await getEventDetailLight(caseRoot, eventId);
    writeLruCache(eventDetailCache, key, value, eventDetailCacheLimit);
    return value;
  }

  function restoreSelectedEventStructureFromCache(eventId: string) {
    const cached = readLruCache(eventStructureCache, eventCacheKey(eventId));
    if (!cached.hit || !cached.value) return;
    artifactObjects = cached.value.artifactObjects;
    evidenceOffsets = cached.value.evidenceOffsets;
    structureLoaded = true;
  }

  async function loadSelectedEventStructure() {
    if (!selectedEvent || structureLoading) return;
    const eventId = selectedEvent.event_id;
    const key = eventCacheKey(eventId);
    const cached = readLruCache(eventStructureCache, key);
    if (cached.hit && cached.value) {
      artifactObjects = cached.value.artifactObjects;
      evidenceOffsets = cached.value.evidenceOffsets;
      structureLoaded = true;
      return;
    }
    structureLoading = true;
    const token = detailToken;
    try {
      const [objects, offsets] = await Promise.all([
        getEventArtifactObjects(caseRoot, eventId),
        getEventEvidenceOffsets(caseRoot, eventId)
      ]);
      writeLruCache(eventStructureCache, key, { artifactObjects: objects, evidenceOffsets: offsets }, eventStructureCacheLimit);
      if (token === detailToken) {
        artifactObjects = objects;
        evidenceOffsets = offsets;
        structureLoaded = true;
      }
    } catch (error) {
      if (token === detailToken) {
        errorMessage = error instanceof Error ? error.message : String(error);
      }
    } finally {
      if (token === detailToken) {
        structureLoading = false;
      }
    }
  }

  function addInvestigationTrail(row: EventRow) {
    const existingIndex = investigationTrail.findIndex((item) => item.event_id === row.event_id);
    if (existingIndex >= 0) {
      investigationIndex = existingIndex;
      return;
    }
    const kept = investigationIndex >= 0 ? investigationTrail.slice(0, investigationIndex + 1) : investigationTrail;
    investigationTrail = [...kept, row].slice(-12);
    investigationIndex = investigationTrail.findIndex((item) => item.event_id === row.event_id);
  }

  function openInvestigationTrail(index: number) {
    const row = investigationTrail[index];
    if (!row) return;
    investigationIndex = index;
    selectEvent(row, false);
    detailTab = 'context';
    eventContext = null;
    void loadEventContext(true);
  }

  function clearInvestigationTrail() {
    investigationTrail = [];
    investigationIndex = -1;
  }

  function startEventColumnResize(index: number, event: PointerEvent) {
    event.preventDefault();
    event.stopPropagation();
    eventColumnResize = {
      index,
      startX: event.clientX,
      startWidth: eventColumnWidths[index] ?? eventColumnMinWidths[index] ?? 80
    };
    window.addEventListener('pointermove', resizeEventColumn);
    window.addEventListener('pointerup', stopEventColumnResize, { once: true });
    window.addEventListener('pointercancel', stopEventColumnResize, { once: true });
  }

  function resizeEventColumn(event: PointerEvent) {
    if (!eventColumnResize) return;
    const { index, startX, startWidth } = eventColumnResize;
    const minWidth = eventColumnMinWidths[index] ?? 80;
    const nextWidth = Math.min(1800, Math.max(minWidth, Math.round(startWidth + event.clientX - startX)));
    const nextWidths = eventColumnWidths.map((width, currentIndex) => (currentIndex === index ? nextWidth : width));
    eventColumnWidths = nextWidths;
    keepEventColumnVisible(index, nextWidths);
  }

  function stopEventColumnResize() {
    eventColumnResize = null;
    window.removeEventListener('pointermove', resizeEventColumn);
    window.removeEventListener('pointerup', stopEventColumnResize);
    window.removeEventListener('pointercancel', stopEventColumnResize);
  }

  function eventColumnOffset(index: number, widths = eventColumnWidths) {
    const gap = 10;
    const rowPadding = 12;
    return rowPadding + widths.slice(0, index).reduce((total, width) => total + width, 0) + index * gap;
  }

  function keepEventColumnVisible(index: number, widths = eventColumnWidths) {
    if (!eventScroller) return;
    const left = eventColumnOffset(index, widths);
    const right = left + (widths[index] ?? 0);
    const visibleLeft = eventScroller.scrollLeft;
    const visibleRight = visibleLeft + eventScroller.clientWidth;
    if (right > visibleRight) {
      eventScroller.scrollLeft = Math.max(0, right - eventScroller.clientWidth + 24);
      eventHorizontalScroll = eventScroller.scrollLeft;
    } else if (left < visibleLeft) {
      eventScroller.scrollLeft = Math.max(0, left - 12);
      eventHorizontalScroll = eventScroller.scrollLeft;
    }
  }

  function resolvedArtifactColumnWidths(artifactType: string, columns: ArtifactEventColumn[]) {
    const stored = artifactColumnWidths[artifactType] ?? [];
    return columns.map((column, index) => stored[index] ?? column.width ?? artifactDefaultColumnWidth(column, index));
  }

  function artifactDefaultColumnWidth(column: ArtifactEventColumn, index: number) {
    if (column.sortBy === 'event_time_utc') return 250;
    if (column.kind === 'severity') return 96;
    if (column.sortBy === 'event_action') return 170;
    if (column.sortBy === 'process_name') return 240;
    if (column.sortBy === 'file_path') return 560;
    if (column.sortBy === 'hash') return 260;
    if (column.sortBy === 'host') return 240;
    if (column.sortBy === 'message_short') return 760;
    return index === 0 ? 240 : 220;
  }

  function artifactColumnWidth(index: number, column: ArtifactEventColumn) {
    return activeArtifactColumnWidths[index] ?? column.width ?? artifactDefaultColumnWidth(column, index);
  }

  function artifactColumnMinWidth(column: ArtifactEventColumn) {
    if (column.sortBy === 'event_time_utc') return 230;
    if (column.kind === 'severity') return 86;
    return column.minWidth ?? 110;
  }

  function startArtifactColumnResize(index: number, column: ArtifactEventColumn, event: PointerEvent) {
    if (!activeArtifactView) return;
    event.preventDefault();
    event.stopPropagation();
    artifactColumnResize = {
      artifactType: activeArtifactView.artifactType,
      index,
      startX: event.clientX,
      startWidth: artifactColumnWidth(index, column)
    };
    window.addEventListener('pointermove', resizeArtifactColumn);
    window.addEventListener('pointerup', stopArtifactColumnResize, { once: true });
    window.addEventListener('pointercancel', stopArtifactColumnResize, { once: true });
  }

  function resizeArtifactColumn(event: PointerEvent) {
    if (!artifactColumnResize) return;
    const { artifactType, index, startX, startWidth } = artifactColumnResize;
    const columns = artifactViewFor(activeTab)?.artifactType === artifactType ? activeArtifactColumns : artifactEventColumns(artifactType);
    const column = columns[index];
    if (!column) return;
    const nextWidth = Math.min(2400, Math.max(artifactColumnMinWidth(column), Math.round(startWidth + event.clientX - startX)));
    const current = resolvedArtifactColumnWidths(artifactType, columns);
    const next = current.map((width, currentIndex) => (currentIndex === index ? nextWidth : width));
    artifactColumnWidths = { ...artifactColumnWidths, [artifactType]: next };
  }

  function stopArtifactColumnResize() {
    artifactColumnResize = null;
    window.removeEventListener('pointermove', resizeArtifactColumn);
    window.removeEventListener('pointerup', stopArtifactColumnResize);
    window.removeEventListener('pointercancel', stopArtifactColumnResize);
  }

  function investigationColor(eventId: string | null | undefined) {
    if (!eventId) return '';
    const index = investigationTrail.findIndex((row) => row.event_id === eventId);
    return index >= 0 ? investigationColors[index % investigationColors.length] : '';
  }

  function investigationRowStyle(eventId: string | null | undefined) {
    const color = investigationColor(eventId);
    return color ? `--trail-color: ${color};` : '';
  }

  function sortMark(sortBy: EventSortBy) {
    if (eventSortBy !== sortBy) return '';
    return eventSortDir === 'asc' ? ' ↑' : ' ↓';
  }

  async function applyEventSearch() {
    appliedEventSearch = buildEventSearchQuery();
    eventScrollTop = 0;
    artifactScrollTop = 0;
    await reloadCurrentEventSlice();
  }

  async function clearEventSearch() {
    eventSearchText = '';
    eventSearchRegex = false;
    appliedEventSearch = '';
    eventScrollTop = 0;
    artifactScrollTop = 0;
    await reloadCurrentEventSlice();
  }

  function resetEventListSearchForArtifactView() {
    eventSearchText = '';
    appliedEventSearch = '';
    eventIdFilter = '';
    eventIpFilter = '';
    eventHostFilter = '';
    eventStartUtc = '';
    eventEndUtc = '';
    eventSearchRegex = false;
    eventArtifactFilter = '';
    eventUserFilter = '';
    eventFacetField = '';
    eventFacetValue = '';
    eventScrollTop = 0;
    artifactScrollTop = 0;
  }

  function resetArtifactScopedFilters() {
    artifactSeverityFilter = '';
    artifactFindingOnly = false;
    artifactHighOnly = false;
    artifactQuickFilter = '';
  }

  async function clearEventFilters() {
    eventSearchText = '';
    appliedEventSearch = '';
    eventIdFilter = '';
    eventIpFilter = '';
    eventHostFilter = '';
    eventStartUtc = '';
    eventEndUtc = '';
    eventSearchRegex = false;
    eventArtifactFilter = '';
    eventUserFilter = '';
    eventFacetField = '';
    eventFacetValue = '';
    eventScrollTop = 0;
    artifactScrollTop = 0;
    await reloadCurrentEventSlice();
  }

  async function applyFacet(facet: EventFacetValue) {
    const value = facet.value === '-' ? '' : facet.value;
    if (facet.field === 'artifact_type') {
      eventArtifactFilter = value;
    } else if (facet.field === 'user_name') {
      eventUserFilter = value;
    } else if (facet.field === 'host') {
      eventHostFilter = value;
    } else if (facet.field === 'event_code') {
      eventIdFilter = value;
    } else if (facet.field === 'channel') {
      eventSearchText = value ? `channel:${value}` : '';
    } else if (facet.field === 'level') {
      eventSearchText = value ? `level:${value}` : '';
    } else {
      eventSearchText = value;
    }
    appliedEventSearch = buildEventSearchQuery();
    eventScrollTop = 0;
    await loadEvents(true);
  }

  async function saveCurrentSearch() {
    const name = savedSearchName.trim();
    if (!name) {
      errorMessage = $t('saved.err.name_required');
      return;
    }
    savedSearches = await saveSavedSearch(
      caseRoot,
      name,
      currentEventFilters(),
      savedSearchDescription.trim() || null,
      savedSearchOwner.trim() || null,
      savedSearchVisibility,
      parseSavedSearchSharedWith(savedSearchSharedWith)
    );
    savedSearchName = '';
    savedSearchDescription = '';
    await loadAuditLog();
  }

  async function applySavedSearch(row: SavedSearch) {
    eventIdFilter = '';
    eventIpFilter = '';
    eventHostFilter = '';
    eventStartUtc = '';
    eventEndUtc = '';
    eventSearchRegex = false;
    eventArtifactFilter = row.query.artifact_type ?? '';
    eventUserFilter = row.query.user_name ?? '';
    eventSearchText = row.query.search ?? '';
    appliedEventSearch = eventSearchText;
    if (isEventSortBy(row.query.sort_by)) {
      eventSortBy = row.query.sort_by;
    }
    if (row.query.sort_dir === 'asc' || row.query.sort_dir === 'desc') {
      eventSortDir = row.query.sort_dir;
    }
    rememberViewBeforeChange('events', 'all');
    eventSubtab = 'all';
    activeTab = 'events';
    await loadEvents(true);
  }

  async function openSearchHit(row: EventSearchHit) {
    eventIdFilter = '';
    eventIpFilter = '';
    eventHostFilter = '';
    eventStartUtc = '';
    eventEndUtc = '';
    eventSearchRegex = false;
    eventSearchText = `id:${row.event_id}`;
    appliedEventSearch = eventSearchText;
    eventArtifactFilter = '';
    eventUserFilter = '';
    rememberViewBeforeChange('events', 'all');
    eventSubtab = 'all';
    activeTab = 'events';
    await loadEvents(true);
  }

  async function removeSavedSearch(row: SavedSearch) {
    savedSearches = await deleteSavedSearch(caseRoot, row.search_id, savedSearchViewer.trim() || null);
    await loadAuditLog();
  }

  async function reloadCurrentEventSlice() {
    clearSelectedEventState();
    if (activeTab === 'events') {
      if (eventSubtab === 'users' && selectedUser) {
        await loadUserEvents(true);
        return;
      }
      await loadEvents(true);
      return;
    }
    if (artifactViewFor(activeTab)) {
      await loadArtifactEvents(true);
      return;
    }
    if (activeTab === 'findings' && selectedFinding) {
      await loadFindingEvents(true);
      return;
    }
    if (activeTab === 'chains' && selectedChain) {
      await loadCorrelationChainEvents(true);
      return;
    }
    if (activeTab === 'ioc' && selectedIoc) {
      await loadIocEvents(true);
      return;
    }
    if (activeTab === 'defender') {
      await loadDefenderEvents(true);
      return;
    }
    if (activeTab === 'bookmarks') {
      await loadBookmarkEvents(true);
    }
  }

  function currentEventSearch() {
    const base = appliedEventSearch.length > 0 ? appliedEventSearch : '';
    if (!artifactViewFor(activeTab)) return base || null;
    return combineEventSearchParts([base, buildArtifactSearchQuery()]) || null;
  }

  function buildEventSearchQuery() {
    const parts: string[] = [];
    const eventIds = eventIdFilter
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)
      .slice(0, 50);
    if (eventIds.length === 1) {
      parts.push(`eid:${quoteEventSearchValue(eventIds[0])}`);
    } else if (eventIds.length > 1) {
      parts.push(`(${eventIds.map((id) => `eid:${quoteEventSearchValue(id)}`).join(' OR ')})`);
    }
    if (eventUserFilter.trim()) parts.push(`user:${quoteEventSearchValue(eventUserFilter.trim())}`);
    if (eventIpFilter.trim()) parts.push(`ip:${quoteEventSearchValue(eventIpFilter.trim())}`);
    if (eventHostFilter.trim()) parts.push(`host:${quoteEventSearchValue(eventHostFilter.trim())}`);
    const start = normalizeUtcSearchTime(eventStartUtc, false);
    const end = normalizeUtcSearchTime(eventEndUtc, true);
    if (start) parts.push(`after:${quoteEventSearchValue(start)}`);
    if (end) parts.push(`before:${quoteEventSearchValue(end)}`);
    const text = eventSearchText.trim();
    if (text) {
      if (eventSearchRegex) {
        parts.push(`re:/${escapeRegexSearchLiteral(text)}/`);
      } else {
        parts.push(looksLikeEventSearchDsl(text) ? text : quoteEventSearchValue(text));
      }
    }
    return parts.join(' ');
  }

  function buildArtifactSearchQuery() {
    if (!artifactViewFor(activeTab)) return '';
    const parts: string[] = [];
    if (artifactSeverityFilter) {
      parts.push(`severity:${quoteEventSearchValue(artifactSeverityFilter)}`);
    }
    if (artifactFindingOnly) {
      parts.push('finding:true');
    }
    if (artifactHighOnly) {
      parts.push('(severity:high OR severity:critical)');
    }
    const quick = selectedArtifactQuickFilter();
    if (quick) {
      parts.push(quick.query);
    }
    return combineEventSearchParts(parts);
  }

  function combineEventSearchParts(parts: Array<string | null | undefined>) {
    return parts
      .map((part) => part?.trim() ?? '')
      .filter(Boolean)
      .map((part) => (needsSearchGrouping(part) ? `(${part})` : part))
      .join(' ');
  }

  function needsSearchGrouping(value: string) {
    const trimmed = value.trim();
    return Boolean(trimmed && (/\bOR\b/.test(trimmed) || /\bAND\b/.test(trimmed)) && !isWrappedSearchExpr(trimmed));
  }

  function isWrappedSearchExpr(value: string) {
    return value.startsWith('(') && value.endsWith(')');
  }

  function selectedArtifactQuickFilter() {
    return activeArtifactQuickFilters.find((filter) => filter.id === artifactQuickFilter) ?? null;
  }

  function hasArtifactFilters() {
    return Boolean(
      appliedEventSearch ||
        eventSearchText ||
        eventUserFilter ||
        eventHostFilter ||
        eventStartUtc ||
        eventEndUtc ||
        eventSearchRegex ||
        artifactSeverityFilter ||
        artifactFindingOnly ||
        artifactHighOnly ||
        artifactQuickFilter
    );
  }

  async function clearArtifactFilters() {
    resetEventListSearchForArtifactView();
    resetArtifactScopedFilters();
    await reloadCurrentEventSlice();
  }

  $: activeArtifactEmptyMessage = () => {
    const label = activeArtifactView?.label ?? $t('common.artifact');
    if (hasArtifactFilters()) {
      return $locale === 'en'
        ? `${label} does not match the current filters. Reset to show everything again.`
        : `${label} は現在のフィルタ条件に一致しません。リセットすると全件を再表示します。`;
    }
    if (!activeArtifactCoverage || activeArtifactCoverage.event_count === 0) {
      return $locale === 'en'
        ? `${label} has no events in this case yet. The matching files may not have been ingested, or are out of parser scope.`
        : `${label} のイベントはこのケースにまだありません。該当ファイルが取り込まれていないか、パーサ対象外です。`;
    }
    return $locale === 'en'
      ? `${label} has ${activeArtifactCoverage.event_count.toLocaleString()} indexed events. If nothing shows, reload.`
      : `${label} は ${activeArtifactCoverage.event_count.toLocaleString()} 件インデックス済みです。表示されない場合は再読み込みしてください。`;
  };

  async function applySelectedEventFacet() {
    const facet = selectedEventFacetValues.find((row) => row.value === eventFacetValue);
    if (!facet) return;
    await applyFacet(facet);
  }

  function changeEventFacetField() {
    eventFacetValue = '';
  }

  function quoteEventSearchValue(value: string) {
    const trimmed = value.trim();
    if (isQuotedSearchValue(trimmed)) return trimmed;
    if (/^[A-Za-z0-9_.:@\\/\-]+$/.test(trimmed)) return trimmed;
    // 引用符で囲む。バックエンドのトークナイザは引用符内でバックスラッシュを
    // リテラル保持し(復元は \" のみ)、JSON.stringify の \\ 二重化は逆に LIKE を
    // 壊す(例 "C:\Program Files (x86)\..." が 0 件化)。よって \ は二重化せず、
    // " のみエスケープ。末尾 \ は閉じ引用符をエスケープしてしまうため除去する。
    const safe = trimmed.replace(/\\+$/, '').replace(/"/g, '\\"');
    return `"${safe}"`;
  }

  function isQuotedSearchValue(value: string) {
    if (value.length < 2) return false;
    const first = value[0];
    const last = value[value.length - 1];
    return (first === '"' && last === '"') || (first === "'" && last === "'");
  }

  function escapeRegexSearchLiteral(value: string) {
    return value.replace(/\\/g, '\\\\').replace(/\//g, '\\/');
  }

  function normalizeUtcSearchTime(value: string, isEnd: boolean) {
    const trimmed = value.trim();
    if (!trimmed) return '';
    let normalized = trimmed.replace(/\//g, '-').replace(' ', 'T');
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(normalized)) {
      normalized = `${normalized}:${isEnd ? '59' : '00'}`;
    }
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(normalized)) {
      normalized = `${normalized}Z`;
    }
    return normalized;
  }

  function looksLikeEventSearchDsl(value: string) {
    return /(^|\s|\()(!|-)?[A-Za-z_][A-Za-z0-9_]*:/.test(value) || /\b(AND|OR|NOT)\b/.test(value);
  }

  function hasEventFilters() {
    return Boolean(
      appliedEventSearch ||
        eventArtifactFilter ||
        eventIdFilter ||
        eventUserFilter ||
        eventIpFilter ||
        eventHostFilter ||
        eventStartUtc ||
        eventEndUtc
    );
  }

  function isEventSortBy(value: unknown): value is EventSortBy {
    return typeof value === 'string' && eventSortByValues.has(value as EventSortBy);
  }

  function groupEventFacets(rows: EventFacetValue[]): FacetGroup[] {
    const order = [
      'artifact_type',
      'severity',
      'channel',
      'level',
      'event_code',
      'host',
      'user_name',
      'event_action',
      'parser_name'
    ];
    return order
      .map((field) => ({
        field,
        label: facetFieldLabel(field),
        values: rows.filter((row) => row.field === field)
      }))
      .filter((group) => group.values.length > 0);
  }

  function facetFieldLabel(field: string) {
    const labels: Record<string, string> =
      $locale === 'en'
        ? {
            artifact_type: 'Type',
            severity: 'Severity',
            channel: 'Channel',
            level: 'Level',
            event_code: 'Event ID',
            host: 'Host',
            user_name: 'User',
            event_action: 'Action',
            parser_name: 'Parser'
          }
        : {
            artifact_type: '種別',
            severity: '重要度',
            channel: 'チャンネル',
            level: 'レベル',
            event_code: 'Event ID',
            host: 'ホスト',
            user_name: 'ユーザー',
            event_action: 'アクション',
            parser_name: 'パーサ'
          };
    return labels[field] ?? field;
  }

  function facetValues(rows: EventFacetValue[], field: string) {
    return rows.filter((row) => row.field === field && row.value !== '-');
  }

  function buildEventArtifactOptions(
    coverageRows: CoverageSummary[],
    facetRows: EventFacetValue[],
    rows: EventRow[]
  ): EventArtifactOption[] {
    const counts = new Map<string, number>();
    const add = (artifactType: string | null | undefined, count: number) => {
      const normalized = artifactType?.trim();
      if (!normalized || normalized === '-') return;
      counts.set(normalized, Math.max(counts.get(normalized) ?? 0, count));
    };
    for (const row of coverageRows) {
      add(row.artifact_type, row.event_count || row.total_files);
    }
    for (const facet of facetRows) {
      if (facet.field === 'artifact_type') add(facet.value, facet.count);
    }
    for (const row of rows) {
      add(row.artifact_type, (counts.get(row.artifact_type) ?? 0) + 1);
    }
    for (const view of Object.values(artifactViews)) {
      add(view.artifactType, counts.get(view.artifactType) ?? 0);
    }
    return Array.from(counts.entries())
      .map(([artifactType, count]) => ({ artifactType, count }))
      .sort((left, right) => {
        if (left.count !== right.count) return right.count - left.count;
        return artifactTypeLabel(left.artifactType).localeCompare(artifactTypeLabel(right.artifactType));
      });
  }

  function buildOverviewChartGroups(rows: EventFacetValue[]): OverviewChartGroup[] {
    return ['channel', 'level', 'event_code', 'artifact_type']
      .map((field) => ({
        field,
        label: facetFieldLabel(field),
        values: facetValues(rows, field).slice(0, field === 'event_code' ? 10 : 8)
      }))
      .filter((group) => group.values.length > 0);
  }

  // トリアージファネル: 収集(全イベント) → 検知(ヒット) → トリアージ(不審種別) → インシデント(High/Crit)。
  type TriageFunnelStage = { key: string; label: string; sub: string; count: number; color: string };
  function buildTriageFunnel(caseSummary: CaseSummary | null, findingRows: FindingSummary[]): TriageFunnelStage[] {
    const collected = caseSummary?.event_count ?? 0;
    const detected = findingRows.reduce((sum, f) => sum + (f.finding_count ?? 0), 0);
    const triaged = findingRows.length;
    const incident = findingRows.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
    return [
      { key: 'collection', label: $t('funnel.collection'), sub: $t('funnel.collection.sub'), count: collected, color: '#4e9e8d' },
      { key: 'detection', label: $t('funnel.detection'), sub: $t('funnel.detection.sub'), count: detected, color: '#46c78f' },
      { key: 'triage', label: $t('funnel.triage'), sub: $t('funnel.triage.sub'), count: triaged, color: '#f5a524' },
      { key: 'incident', label: $t('funnel.incident'), sub: 'High / Critical', count: incident, color: '#ff5c5c' }
    ];
  }
  // イベント数はステージ間で桁が大きく違うため、幅は sqrt スケールで小ステージも視認可能にする。
  function funnelWidth(count: number, base: number): number {
    if (base <= 0) return 0;
    return Math.max(4, Math.round(Math.sqrt(count / base) * 100));
  }
  function funnelRate(count: number, prev: number): string {
    if (prev <= 0) return '0%';
    const ratio = count / prev;
    return `${(ratio * 100).toFixed(ratio < 0.01 ? 2 : 1)}%`;
  }

  // --- グラフタブ 高度チャート ---

  // ① タイムスタンプ矛盾スキャッター: $SI作成(x) vs $FN作成(y)。正方プロットで
  // 対角線(si==fn)を基準に、外れた点(mismatch)を timestomping 疑いとして赤表示。
  const TIMESTOMP_SIZE = 340;
  const TIMESTOMP_PAD = 34;
  function buildTimestompView(points: TimestompPoint[]) {
    const parsed = points
      .map((p) => ({
        point: p,
        x: Date.parse(p.si_created_utc),
        y: Date.parse(p.fn_created_utc)
      }))
      .filter((p) => Number.isFinite(p.x) && Number.isFinite(p.y));
    if (parsed.length === 0) return null;
    const values = parsed.flatMap((p) => [p.x, p.y]);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = Math.max(1, max - min);
    const plot = TIMESTOMP_SIZE - 2 * TIMESTOMP_PAD;
    const sx = (v: number) => TIMESTOMP_PAD + ((v - min) / span) * plot;
    const sy = (v: number) => TIMESTOMP_SIZE - TIMESTOMP_PAD - ((v - min) / span) * plot;
    const mapped = parsed.map((p) => ({
      ...p.point,
      cx: sx(p.x),
      cy: sy(p.y)
    }));
    return {
      size: TIMESTOMP_SIZE,
      mapped,
      mismatchCount: parsed.filter((p) => p.point.mismatch).length,
      total: parsed.length,
      diag: {
        x1: TIMESTOMP_PAD,
        y1: TIMESTOMP_SIZE - TIMESTOMP_PAD,
        x2: TIMESTOMP_SIZE - TIMESTOMP_PAD,
        y2: TIMESTOMP_PAD
      }
    };
  }

  // ② ATT&CK ヒートマップ: finding の tactic(行) × first_seen の時刻(0-23時, 列)。
  // 各セルの重み = finding_count。バックエンド不要(findings から算出)。
  $: ATTACK_TACTIC_LABEL = ($locale === 'en'
    ? {
        reconnaissance: 'Reconnaissance',
        resource_development: 'Resource Development',
        initial_access: 'Initial Access',
        execution: 'Execution',
        persistence: 'Persistence',
        privilege_escalation: 'Privilege Escalation',
        defense_evasion: 'Defense Evasion',
        credential_access: 'Credential Access',
        discovery: 'Discovery',
        lateral_movement: 'Lateral Movement',
        collection: 'Collection',
        command_and_control: 'Command & Control (C2)',
        exfiltration: 'Exfiltration',
        impact: 'Impact'
      }
    : {
        reconnaissance: '偵察',
        resource_development: 'リソース開発',
        initial_access: '初期アクセス',
        execution: '実行',
        persistence: '永続化',
        privilege_escalation: '権限昇格',
        defense_evasion: '防御回避',
        credential_access: '資格情報アクセス',
        discovery: '探索',
        lateral_movement: '横展開',
        collection: '収集',
        command_and_control: 'C2 (コマンド&コントロール)',
        exfiltration: '持ち出し',
        impact: '影響'
      }) as Record<string, string>;
  // enrichment の tactic はスペース区切り小文字(例 "credential access")で届く。
  // ラベルマップはアンダースコアkeyなので正規化してから引く。
  $: attackTacticLabel = (tactic: string): string =>
    ATTACK_TACTIC_LABEL[tactic.replace(/ /g, '_')] ?? tactic;
  // 赤の透明度ランプ(sqrt で低頻度も視認)。検知の熱=脅威なので赤で表現。
  function heatColor(v: number, max: number): string {
    if (v <= 0) return 'transparent';
    const t = Math.min(1, Math.sqrt(v / max));
    return `rgba(255, 92, 92, ${(0.1 + t * 0.85).toFixed(3)})`;
  }
  function buildAttackHeatmap(rows: FindingSummary[]) {
    const map = new Map<string, { hours: number[]; wins: ({ min: string; max: string } | null)[] }>();
    for (const f of rows) {
      const time = f.first_seen_utc;
      if (!time) continue;
      const hour = new Date(time).getUTCHours();
      if (!Number.isFinite(hour)) continue;
      const enr = parseEnrichment(f);
      const tactics = (enr?.tactics ?? []).filter((t) => t && t !== 'mitre');
      const list = tactics.length > 0 ? tactics : [$t('tactic.none')];
      const weight = f.finding_count ?? 1;
      for (const tac of list) {
        if (!map.has(tac)) {
          map.set(tac, { hours: new Array(24).fill(0), wins: new Array(24).fill(null) });
        }
        const cell = map.get(tac)!;
        cell.hours[hour] += weight;
        // クリック時のドリルダウン用に、セルに寄与した finding の時間範囲を保持。
        const win = cell.wins[hour];
        if (!win) cell.wins[hour] = { min: time, max: f.last_seen_utc ?? time };
        else {
          if (time < win.min) win.min = time;
          const end = f.last_seen_utc ?? time;
          if (end > win.max) win.max = end;
        }
      }
    }
    const heatRows = Array.from(map.entries())
      .map(([tactic, cell]) => ({
        tactic,
        hours: cell.hours,
        wins: cell.wins,
        total: cell.hours.reduce((a, b) => a + b, 0)
      }))
      .sort((a, b) => b.total - a.total);
    const max = Math.max(1, ...heatRows.flatMap((r) => r.hours));
    return { rows: heatRows, max };
  }
  // ヒートマップセルのクリック: 寄与 finding の時間範囲(時単位に丸め)で
  // 検知フラグ付きイベントに絞ってイベント一覧へ。
  function drillDownHeatmapCell(win: { min: string; max: string } | null) {
    if (!win) return;
    // after:/before: は try_cast(TIMESTAMPTZ) 比較のため、時プレフィックスのままでは
    // キャスト不能で0件になる。分まで含む形式(正規化で :00Z/:59:59Z になる)を渡す。
    drillDownToEvents({
      search: 'finding:true',
      startUtc: `${win.min.slice(0, 13)}:00`,
      endUtc: `${win.max.slice(0, 13)}:59`
    });
  }

  // ③ プロセスツリー(アイシクル): parent -> child エッジを親でまとめた2階層。
  function buildProcessTree(edges: ProcessTreeEdge[]) {
    if (edges.length === 0) return null;
    const parents = new Map<
      string,
      { name: string; total: number; children: { name: string; count: number }[] }
    >();
    for (const e of edges) {
      if (!parents.has(e.parent)) parents.set(e.parent, { name: e.parent, total: 0, children: [] });
      const p = parents.get(e.parent)!;
      p.total += e.count;
      p.children.push({ name: e.child, count: e.count });
    }
    const rows = Array.from(parents.values())
      .sort((a, b) => b.total - a.total)
      .slice(0, 8);
    rows.forEach((r) => r.children.sort((a, b) => b.count - a.count));
    const max = Math.max(1, ...rows.map((r) => r.total));
    return { rows, max };
  }

  // ④ ファイル操作ダイバージング: USN の作成(上)/削除(下)を時系列で。
  function buildFileOpView(bins: FileOpBin[]) {
    if (bins.length === 0) return null;
    const max = Math.max(1, ...bins.flatMap((b) => [b.created, b.deleted]));
    return {
      bins,
      max,
      totalCreated: bins.reduce((a, b) => a + b.created, 0),
      totalDeleted: bins.reduce((a, b) => a + b.deleted, 0)
    };
  }

  function buildLoginOutcomeRows(rows: EventFacetValue[]): LoginOutcomeRow[] {
    const eventCodes = facetValues(rows, 'event_code');
    const countFor = (eventCode: string) =>
      eventCodes.find((row) => row.value === eventCode)?.count ?? 0;
    return [
      { label: $t('logon.success'), eventCode: '4624', count: countFor('4624'), tone: 'success' },
      { label: $t('logon.failure'), eventCode: '4625', count: countFor('4625'), tone: 'failure' }
    ];
  }

  function buildOverviewTimelineRows(rows: TimelineBin[]): OverviewTimelineRow[] {
    const grouped = new Map<string, OverviewTimelineRow>();
    for (const row of rows) {
      const existing = grouped.get(row.bin_start_utc);
      if (existing) {
        existing.eventCount += row.event_count;
        if (!existing.artifactTypes.includes(row.artifact_type)) {
          existing.artifactTypes.push(row.artifact_type);
        }
        existing.severityMax = maxSeverityValue(existing.severityMax, row.severity_max ?? null);
      } else {
        grouped.set(row.bin_start_utc, {
          binStartUtc: row.bin_start_utc,
          eventCount: row.event_count,
          artifactTypes: [row.artifact_type],
          severityMax: row.severity_max ?? null
        });
      }
    }
    return Array.from(grouped.values()).sort((left, right) =>
      left.binStartUtc.localeCompare(right.binStartUtc)
    );
  }

  // --- 強化タイムライン: read-time severity集計チャート + フィルタDSL + ヒートマップ ---
  const TIMELINE_STACK_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const;

  function backendGranularity(): 'minute' | 'hour' | 'day' {
    return timelineGranularity === 'week' ? 'day' : timelineGranularity;
  }

  function timelineBinWidthMs(): number {
    switch (timelineGranularity) {
      case 'minute':
        return 60_000;
      case 'day':
        return 86_400_000;
      case 'week':
        return 7 * 86_400_000;
      default:
        return 3_600_000;
    }
  }

  function buildTimelineFilters(): { search?: string } {
    const parts: string[] = [];
    if (timelineSevFilter) parts.push(`severity:${quoteEventSearchValue(timelineSevFilter)}`);
    if (timelineFindingOnly) parts.push('finding:true');
    if (timelineHostFilter.trim()) parts.push(`host:${quoteEventSearchValue(timelineHostFilter.trim())}`);
    if (timelineUserFilter.trim()) parts.push(`user:${quoteEventSearchValue(timelineUserFilter.trim())}`);
    const text = timelineSearchText.trim();
    if (text) {
      if (timelineSearchRegex) parts.push(`re:/${escapeRegexSearchLiteral(text)}/`);
      else parts.push(looksLikeEventSearchDsl(text) ? text : quoteEventSearchValue(text));
    }
    const search = combineEventSearchParts(parts);
    return search ? { search } : {};
  }

  function hasTimelineFilters(): boolean {
    return Boolean(
      timelineSevFilter ||
        timelineFindingOnly ||
        timelineHostFilter ||
        timelineUserFilter ||
        timelineSearchText
    );
  }

  // (フィルタ×粒度)キーで結果をキャッシュし、タブ再入や粒度往復での再スキャンを避ける。
  // 再取込/ケース切替時にクリアするので古いデータは出さない。
  let timelineBinCache = new Map<string, EventTimelineBin[]>();

  async function loadTimelineSeverity() {
    const gran = backendGranularity();
    const key = `${gran}|${buildTimelineFilters().search ?? ''}`;
    const cached = timelineBinCache.get(key);
    if (cached) {
      timelineSeverityBins = cached;
    } else {
      timelineSeverityBins = await getEventTimeline(caseRoot, buildTimelineFilters(), gran);
      timelineBinCache.set(key, timelineSeverityBins);
    }
    if (timelineView === 'heatmap') await loadTimelineHeatmap();
  }

  async function loadTimelineHeatmap() {
    // ヒートマップは粒度切替と独立に常に hour 解像度で集計する
    const key = `heatmap|hour|${buildTimelineFilters().search ?? ''}`;
    const cached = timelineBinCache.get(key);
    if (cached) {
      timelineHeatmapBins = cached;
    } else {
      timelineHeatmapBins = await getEventTimeline(caseRoot, buildTimelineFilters(), 'hour');
      timelineBinCache.set(key, timelineHeatmapBins);
    }
  }

  // finding(検知)/IOC/bookmark の時刻マーカーを収集。finding/IOC は既にロード済みの
  // グローバルを再利用(first_seen_utc)、bookmark は該当イベントの時刻ページを軽く取得。
  async function loadTimelineMarkers() {
    if (!caseRoot) return;
    const findingSrc = findings.length > 0 ? findings : await getFindingSummary(caseRoot, 200).catch(() => []);
    timelineFindingMarks = findingSrc
      .filter((f) => f.first_seen_utc)
      .map((f) => ({ t: f.first_seen_utc as string, label: displayText(f.title, f.engine) }));
    timelineIocMarks = iocHits
      .filter((h) => h.first_seen_utc)
      .map((h) => ({ t: h.first_seen_utc as string, label: h.ioc }));
    const page = await getBookmarkEventPage(caseRoot, 300).catch(() => ({ rows: [], next_cursor: null }));
    timelineBookmarkMarks = page.rows.map((r) => ({ t: r.event_time_utc, label: eventSubject(r) }));
  }

  function rebucketWeekBins(bins: EventTimelineBin[]): EventTimelineBin[] {
    const grouped = new Map<string, EventTimelineBin>();
    for (const b of bins) {
      const t = new Date(b.bin_start_utc).getTime();
      if (Number.isNaN(t)) continue;
      const weekMs = 7 * 86_400_000;
      const monOffset = 4 * 86_400_000; // Unixエポックは木曜。週境界を月曜起点(UTC)に補正
      const key = new Date(Math.floor((t - monOffset) / weekMs) * weekMs + monOffset).toISOString().slice(0, 19) + 'Z';
      const e = grouped.get(key);
      if (e) {
        e.total += b.total;
        e.critical += b.critical;
        e.high += b.high;
        e.medium += b.medium;
        e.low += b.low;
        e.info += b.info;
      } else {
        grouped.set(key, { ...b, bin_start_utc: key });
      }
    }
    return Array.from(grouped.values()).sort((a, b) => a.bin_start_utc.localeCompare(b.bin_start_utc));
  }

  const TIMELINE_BIN_CAP = 20000;
  const TIMELINE_MAX_COLUMNS = 200;
  $: timelineBins = timelineGranularity === 'week' ? rebucketWeekBins(timelineSeverityBins) : timelineSeverityBins;
  $: timelineRenderColumns = aggregateTimelineColumns(timelineBins, TIMELINE_MAX_COLUMNS);
  $: maxRenderColumn = Math.max(1, ...timelineRenderColumns.map((c) => c.total));
  $: timelineBinsTruncated = timelineSeverityBins.length >= TIMELINE_BIN_CAP;
  $: timelineAggregated = timelineBins.length > TIMELINE_MAX_COLUMNS;

  type TimelineColumn = EventTimelineBin & { endMs: number; binCount: number };
  // 数千ビンをそのままSVG描画するとsmear+重い。プロット幅に収まる列数へ集約し、
  // 描画を軽く・読みやすくする。1列クリックでその列がカバーする時間範囲を窓にする。
  function aggregateTimelineColumns(bins: EventTimelineBin[], maxCols: number): TimelineColumn[] {
    const width = timelineBinWidthMs();
    if (bins.length === 0) return [];
    if (bins.length <= maxCols) {
      return bins.map((b) => ({
        ...b,
        endMs: new Date(b.bin_start_utc).getTime() + width,
        binCount: 1
      }));
    }
    const perCol = Math.ceil(bins.length / maxCols);
    const cols: TimelineColumn[] = [];
    for (let i = 0; i < bins.length; i += perCol) {
      const group = bins.slice(i, i + perCol);
      const last = group[group.length - 1];
      const col: TimelineColumn = {
        bin_start_utc: group[0].bin_start_utc,
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        endMs: new Date(last.bin_start_utc).getTime() + width,
        binCount: group.length
      };
      for (const b of group) {
        col.total += b.total;
        col.critical += b.critical;
        col.high += b.high;
        col.medium += b.medium;
        col.low += b.low;
        col.info += b.info;
      }
      cols.push(col);
    }
    return cols;
  }

  // マーカー時刻 → その時刻を含む描画列の中心x。含む列が無ければ null。
  function timelineMarkerX(timeUtc: string, cols: TimelineColumn[]): number | null {
    const t = new Date(timeUtc).getTime();
    if (Number.isNaN(t) || cols.length === 0) return null;
    const len = cols.length;
    for (let i = 0; i < len; i += 1) {
      const s = new Date(cols[i].bin_start_utc).getTime();
      if (t >= s && t < cols[i].endMs) {
        return overviewColumnX(i, len) + 912 / len / 2;
      }
    }
    return null;
  }

  function markerGlyphs(marks: Array<{ t: string; label: string }>, cols: TimelineColumn[]) {
    const byCol = new Map<number, { x: number; count: number; label: string }>();
    for (const m of marks) {
      const x = timelineMarkerX(m.t, cols);
      if (x == null) continue;
      const key = Math.round(x);
      const existing = byCol.get(key);
      if (existing) existing.count += 1;
      else byCol.set(key, { x, count: 1, label: m.label });
    }
    return Array.from(byCol.values());
  }

  $: timelineFindingGlyphs = timelineMarkersOn ? markerGlyphs(timelineFindingMarks, timelineRenderColumns) : [];
  $: timelineIocGlyphs = timelineMarkersOn ? markerGlyphs(timelineIocMarks, timelineRenderColumns) : [];
  $: timelineBookmarkGlyphs = timelineMarkersOn ? markerGlyphs(timelineBookmarkMarks, timelineRenderColumns) : [];

  function timelineStackSegments(bin: EventTimelineBin, maxCount: number) {
    const baseline = 188;
    const plotHeight = 170;
    const segs: Array<{ sev: string; y: number; height: number }> = [];
    // 合計に sqrt スケール(巨大スパイクで小バーが潰れないように)、
    // 各 severity セグメントは合計内で比例配分してスタックする。
    const total = TIMELINE_STACK_ORDER.reduce((a, s) => a + Math.max(0, bin[s]), 0);
    if (total <= 0) return segs;
    const scaledTotal = (plotHeight * Math.sqrt(total)) / Math.sqrt(Math.max(1, maxCount));
    let accHeight = 0;
    for (const sev of TIMELINE_STACK_ORDER) {
      const count = bin[sev];
      if (count <= 0) continue;
      const height = scaledTotal * (count / total);
      segs.push({ sev, y: baseline - (accHeight + height), height: Math.max(0.5, height) });
      accHeight += height;
    }
    return segs;
  }

  function setTimelineGranularity(g: 'minute' | 'hour' | 'day' | 'week') {
    if (timelineGranularity === g) return;
    timelineGranularity = g;
    timelineSelectedBin = null;
    timelineSelectedBinData = null;
    timelineEventRows = [];
    nextTimelineEventCursor = null;
    timelineWindowStart = '';
    timelineWindowEnd = '';
    clearSelectedEventState();
    run(loadTimelineSeverity);
  }

  function setTimelineView(v: 'chart' | 'heatmap') {
    timelineView = v;
    if (v === 'heatmap' && timelineHeatmapBins.length === 0) run(loadTimelineHeatmap);
  }

  async function applyTimelineFilters() {
    timelineSelectedBin = null;
    timelineSelectedBinData = null;
    timelineEventRows = [];
    nextTimelineEventCursor = null;
    timelineWindowStart = '';
    timelineWindowEnd = '';
    timelineHeatmapBins = [];
    clearSelectedEventState();
    await loadTimelineSeverity();
  }

  async function clearTimelineFilters() {
    timelineSevFilter = '';
    timelineFindingOnly = false;
    timelineHostFilter = '';
    timelineUserFilter = '';
    timelineSearchText = '';
    timelineSearchRegex = false;
    await applyTimelineFilters();
  }

  async function selectTimelineBin(bin: EventTimelineBin & { endMs?: number }) {
    const startMs = new Date(bin.bin_start_utc).getTime();
    if (Number.isNaN(startMs)) return;
    const endMs = bin.endMs ?? startMs + timelineBinWidthMs();
    timelineWindowStart = new Date(startMs).toISOString().slice(0, 19) + 'Z';
    timelineWindowEnd = new Date(endMs).toISOString().slice(0, 19) + 'Z';
    timelineSelectedBin = {
      startUtc: bin.bin_start_utc,
      label: `${formatTimestamp(timelineWindowStart)} 〜 ${formatTimestamp(timelineWindowEnd)}`
    };
    timelineSelectedBinData = bin;
    await loadTimelineEvents(true);
    // 他タブと同様に先頭イベントを共有調査ペインへ自動表示する
    if (timelineEventRows.length > 0) selectEvent(timelineEventRows[0], false);
  }

  function timelineWindowSearch(): string {
    // before_exclusive(<) にして、ビン境界(次ビン先頭)ちょうどのイベントが
    // 隣接2ビンに二重計上されるのを防ぐ(チャート集計は substr で排他)。
    const windowSearch = `after:${quoteEventSearchValue(timelineWindowStart)} before_exclusive:${quoteEventSearchValue(timelineWindowEnd)}`;
    return combineEventSearchParts([windowSearch, buildTimelineFilters().search]);
  }

  async function loadTimelineEvents(reset: boolean) {
    if (!timelineWindowStart) return;
    const cursor = reset ? null : nextTimelineEventCursor;
    const page = await getEventPage(caseRoot, 100, cursor, {
      search: timelineWindowSearch(),
      sortBy: 'event_time_utc',
      sortDir: 'asc'
    });
    timelineEventRows = reset ? page.rows : [...timelineEventRows, ...page.rows];
    nextTimelineEventCursor = page.next_cursor;
  }

  async function exportTimelineWindow(format: 'csv' | 'jsonl') {
    if (!timelineWindowStart) return;
    await exportEvents(caseRoot, { search: timelineWindowSearch() }, format);
  }

  async function pivotTimelineToEvents() {
    if (!timelineWindowStart) return;
    eventSubtab = 'all';
    eventStartUtc = timelineWindowStart;
    eventEndUtc = timelineWindowEnd;
    eventUserFilter = '';
    eventHostFilter = '';
    eventIpFilter = '';
    eventIdFilter = '';
    eventSearchText = buildTimelineFilters().search ?? '';
    eventSearchRegex = false;
    rememberViewBeforeChange('events', 'all');
    activeTab = 'events';
    await applyEventSearch();
  }

  // ヒートマップ: 曜日(0=日)×時間帯(0-23, UTC) の件数グリッド
  $: timelineHeatmapGrid = buildTimelineHeatmapGrid(timelineHeatmapBins);
  $: timelineHeatmapMax = Math.max(1, ...timelineHeatmapGrid.flat());

  function heatmapCellColor(count: number, max: number): string {
    if (count <= 0) return '#131c28';
    const t = Math.min(1, count / Math.max(1, max));
    const alpha = 0.14 + 0.86 * t;
    return `rgba(78, 158, 141, ${alpha.toFixed(3)})`;
  }

  function buildTimelineHeatmapGrid(bins: EventTimelineBin[]): number[][] {
    const grid: number[][] = Array.from({ length: 7 }, () => new Array(24).fill(0));
    for (const b of bins) {
      const d = new Date(b.bin_start_utc);
      if (Number.isNaN(d.getTime())) continue;
      grid[d.getUTCDay()][d.getUTCHours()] += b.total;
    }
    return grid;
  }

  function maxSeverityValue(left: string | null, right: string | null) {
    const rank: Record<string, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };
    if (!left) return right;
    if (!right) return left;
    return (rank[right] ?? 0) > (rank[left] ?? 0) ? right : left;
  }

  function overviewBarWidth(count: number, maxCount: number) {
    return `width: ${Math.max(2, Math.round((count / Math.max(1, maxCount)) * 100))}%`;
  }

  function overviewChartPoints(rows: OverviewTimelineRow[], maxCount: number): OverviewChartPoint[] {
    const height = 220;
    const padTop = 18;
    const padBottom = 32;
    const plotHeight = height - padTop - padBottom;
    // x は column バンドの中心に合わせる(bar/hitbar と一致させる)。
    // y は sqrt スケール: 巨大スパイクに小バーが潰れて平坦化するのを防ぐ。
    const total = rows.length;
    const denom = Math.sqrt(Math.max(1, maxCount));
    return rows.map((row, index) => ({
      x: overviewColumnX(index, total) + overviewColumnWidth(total) / 2,
      y: padTop + plotHeight - (plotHeight * Math.sqrt(Math.max(0, row.eventCount))) / denom
    }));
  }

  function overviewLinePoints(rows: OverviewTimelineRow[], maxCount: number) {
    return overviewChartPoints(rows, maxCount)
      .map((point) => `${point.x.toFixed(1)},${point.y.toFixed(1)}`)
      .join(' ');
  }

  function overviewAreaPath(rows: OverviewTimelineRow[], maxCount: number) {
    const points = overviewChartPoints(rows, maxCount);
    if (points.length === 0) return '';
    const baseline = 188;
    const line = points.map((point) => `L ${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(' ');
    return `M ${points[0].x.toFixed(1)} ${baseline} ${line} L ${points[points.length - 1].x.toFixed(1)} ${baseline} Z`;
  }

  function overviewColumnX(index: number, total: number) {
    const width = 912;
    const padX = 24;
    return padX + (width * index) / Math.max(1, total);
  }

  function overviewColumnWidth(total: number) {
    return Math.max(5, Math.min(18, 912 / Math.max(1, total) - 3));
  }

  function overviewColumnY(count: number, maxCount: number) {
    const baseline = 188;
    const plotHeight = 170;
    // sqrt スケール(overviewChartPoints と一致)。
    return baseline - (plotHeight * Math.sqrt(Math.max(0, count))) / Math.sqrt(Math.max(1, maxCount));
  }

  function overviewColumnHeight(count: number, maxCount: number) {
    return Math.max(2, 188 - overviewColumnY(count, maxCount));
  }

  async function drillDownOverviewTimeline(row: OverviewTimelineRow) {
    eventSubtab = 'all';
    eventStartUtc = row.binStartUtc;
    eventEndUtc = '';
    rememberViewBeforeChange('events', 'all');
    activeTab = 'events';
    await applyEventSearch();
  }

  async function drillDownOverviewBin(bin: EventTimelineBin) {
    eventSubtab = 'all';
    eventStartUtc = bin.bin_start_utc;
    eventEndUtc = '';
    rememberViewBeforeChange('events', 'all');
    activeTab = 'events';
    await applyEventSearch();
  }

  async function drillDownOverviewFacet(facet: EventFacetValue) {
    eventSubtab = 'all';
    eventSearchText = '';
    appliedEventSearch = '';
    eventArtifactFilter = '';
    eventUserFilter = '';
    eventIdFilter = '';
    eventIpFilter = '';
    eventHostFilter = '';
    eventStartUtc = '';
    eventEndUtc = '';
    eventSearchRegex = false;
    if (facet.field === 'artifact_type') {
      eventArtifactFilter = facet.value;
    } else if (facet.field === 'channel') {
      eventSearchText = `channel:${facet.value}`;
    } else if (facet.field === 'level') {
      eventSearchText = `level:${facet.value}`;
    } else if (facet.field === 'event_code') {
      eventIdFilter = facet.value;
    } else {
      eventSearchText = `${facet.field}:${facet.value}`;
    }
    appliedEventSearch = buildEventSearchQuery();
    rememberViewBeforeChange('events', 'all');
    activeTab = 'events';
    await loadEvents(true);
  }

  // グラフ→イベント一覧への汎用ドリルダウン。フィルタUI(検索/種別/IP/期間)に値を
  // 入れて遷移するので、着地後もどう絞られたかが見える＋手で緩められる。
  async function drillDownToEvents(opts: {
    artifact?: string;
    search?: string;
    ip?: string;
    startUtc?: string;
    endUtc?: string;
  }) {
    eventSubtab = 'all';
    eventSearchText = opts.search ?? '';
    appliedEventSearch = '';
    eventArtifactFilter = opts.artifact ?? '';
    eventUserFilter = '';
    eventIdFilter = '';
    eventIpFilter = opts.ip ?? '';
    eventHostFilter = '';
    eventStartUtc = opts.startUtc ?? '';
    eventEndUtc = opts.endUtc ?? '';
    eventSearchRegex = false;
    appliedEventSearch = buildEventSearchQuery();
    rememberViewBeforeChange('events', 'all');
    activeTab = 'events';
    await loadEvents(true);
  }

  function formatSavedSearchQuery(query: EventPageQuery) {
    const parts = [
      query.search ? `search=${query.search}` : '',
      query.artifact_type ? `type=${query.artifact_type}` : '',
      query.user_name ? `user=${query.user_name}` : '',
      `sort=${query.sort_by ?? 'event_time_utc'} ${query.sort_dir ?? 'asc'}`
    ].filter(Boolean);
    return parts.join(' / ');
  }

  function parseSavedSearchSharedWith(value: string) {
    return [
      ...new Set(
        value
          .split(',')
          .map((item) => item.trim().toLowerCase())
          .filter(Boolean)
      )
    ].slice(0, 50);
  }

  function formatSavedSearchSharedWith(row: SavedSearch) {
    return row.shared_with?.length ? row.shared_with.join(', ') : '-';
  }

  function canManageSavedSearch(row: SavedSearch) {
    const viewer = savedSearchViewer.trim().toLowerCase();
    const owner = (row.created_by ?? '').trim().toLowerCase();
    return !viewer || !owner || viewer === owner;
  }

  function artifactViewFor(tab: Tab): ArtifactView | null {
    return tab in artifactViews ? artifactViews[tab as ArtifactTab] : null;
  }

  function artifactTabForType(artifactType: string | null | undefined): ArtifactTab | null {
    const entry = Object.entries(artifactViews).find(([, view]) => view.artifactType === artifactType);
    return entry ? (entry[0] as ArtifactTab) : null;
  }

  function isEventArtifactSubtab(tab: Tab) {
    return eventArtifactSubtabs.some((item) => item.id === tab);
  }

  function isEventNavigationActive(tab: Tab) {
    return tab === 'events' || isEventArtifactSubtab(tab);
  }

  function bookmarkForEvent(eventId: string) {
    return bookmarks.find((bookmark) => bookmark.event_id === eventId) ?? null;
  }

  async function pivotToEventField(field: PivotField, value: string) {
    const cleaned = displayText(value, '').trim();
    if (!cleaned) return;
    rememberViewBeforeChange('events', 'all');
    eventSubtab = 'all';
    activeTab = 'events';
    eventIdFilter = '';
    eventIpFilter = '';
    eventHostFilter = '';
    eventStartUtc = '';
    eventEndUtc = '';
    eventArtifactFilter = '';
    eventUserFilter = '';
    eventSearchRegex = false;
    eventSearchText = `${field}:${quoteEventSearchValue(cleaned)}`;
    appliedEventSearch = eventSearchText;
    eventScrollTop = 0;
    await loadEvents(true);
  }

  async function openSelectedRaw() {
    await openDetailTab('raw');
  }

  async function openSelectedEvidence() {
    await openDetailTab('evidence');
  }

  async function openEvidenceOffset(offset: EvidenceOffset) {
    evidenceOffset = Math.max(0, offset.offset);
    evidenceLength = Math.min(65536, Math.max(1024, offset.length || 4096));
    detailTab = 'evidence';
    await loadEvidenceRange(evidenceOffset, offset.object_ref);
  }

  async function openSelectedArtifactTab() {
    const tab = artifactTabForType(selectedEvent?.artifact_type);
    if (!tab) return;
    await setEventArtifactSubtab(tab);
  }

  async function loadEventContext(force = false) {
    if (!selectedEvent || (!force && eventContext) || contextLoading) return;
    const eventId = selectedEvent.event_id;
    const perGroupLimit = 100;
    const cacheKey = eventContextCacheKey(eventId, contextWindowMinutes, perGroupLimit, contextSameHostOnly);
    if (!force) {
      const cached = readLruCache(eventContextCache, cacheKey);
      if (cached.hit) {
        eventContext = cached.value ?? null;
        return;
      }
    }
    contextLoading = true;
    const token = detailToken;
    try {
      const context = await getEventContext(
        caseRoot,
        eventId,
        contextWindowMinutes,
        perGroupLimit,
        contextSameHostOnly
      );
      writeLruCache(eventContextCache, cacheKey, context, eventContextCacheLimit);
      if (token === detailToken) {
        eventContext = context;
      }
    } catch (error) {
      if (token === detailToken) {
        errorMessage = error instanceof Error ? error.message : String(error);
      }
    } finally {
      if (token === detailToken) {
        contextLoading = false;
      }
    }
  }

  async function openDetailTab(tab: DetailTab) {
    detailTab = tab;
    if (tab === 'summary') {
      return;
    }
    if (tab === 'context') {
      if (!detail && selectedEvent) {
        await loadSelectedEventDetailNow();
      }
      await loadEventContext();
      return;
    }
    if (tab === 'evidence') {
      if (!detail && selectedEvent) {
        await loadSelectedEventDetailNow();
      }
      await loadEvidenceRange(evidenceOffset);
      return;
    }
    if (tab !== 'raw' || !selectedEvent || rawRecord || rawLoading) return;
    rawLoading = true;
    try {
      rawRecord = await getEventRawRecord(caseRoot, selectedEvent.event_id);
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : String(error);
    } finally {
      rawLoading = false;
    }
  }

  async function loadEvidenceRange(offset: number, objectRefOverride: string | undefined = undefined) {
    if (!selectedEvent || evidenceLoading) return;
    evidenceLoading = true;
    const token = detailToken;
    try {
      let currentDetail = detail;
      if (!currentDetail) {
        currentDetail = await fetchEventDetailCached(selectedEvent.event_id);
        if (token === detailToken) {
          detail = currentDetail;
        }
      }
      const objectRef = objectRefOverride || currentDetail?.evidence_ref;
      if (!objectRef) {
        evidenceRange = null;
        return;
      }
      const safeOffset = Math.max(0, offset);
      const range = await getEvidenceRange(caseRoot, objectRef, safeOffset, evidenceLength);
      if (token === detailToken) {
        evidenceOffset = safeOffset;
        evidenceRange = range;
      }
    } catch (error) {
      if (token === detailToken) {
        errorMessage = error instanceof Error ? error.message : String(error);
      }
    } finally {
      if (token === detailToken) {
        evidenceLoading = false;
      }
    }
  }

  async function shiftEvidenceRange(delta: number) {
    await loadEvidenceRange(Math.max(0, evidenceOffset + delta));
  }

  async function reloadEventContext() {
    eventContext = null;
    await loadEventContext(true);
  }

  async function exportCurrentEvents(format: EventExportResult['format']) {
    if (!summary) {
      errorMessage = $t('err.open_case_first');
      return;
    }
    const artifactView = artifactViewFor(activeTab);
    const result = await exportEvents(
      caseRoot,
      activeTab === 'events'
        ? currentEventFilters()
        : {
            artifactType: artifactView?.artifactType ?? null,
            userName: null,
            search: currentEventSearch(),
            sortBy: eventSortBy,
            sortDir: eventSortDir
          },
      format === 'jsonl' ? 'jsonl' : 'csv',
      100_000
    );
    setExportStatus(
      $locale === 'en'
        ? `Exported ${result.row_count.toLocaleString()} rows to ${result.output_path}${result.truncated ? ' (truncated at limit)' : ''}`
        : `${result.row_count.toLocaleString()} 件を ${result.output_path} に出力しました${result.truncated ? '（上限で打ち切り）' : ''}`
    );
  }

  async function chooseExportFormat(format: EventExportResult['format']) {
    exportMenuOpen = false;
    await exportCurrentEvents(format);
  }

  function statusClass(status: string) {
    return `status status-${status}`;
  }

  // --- severity 色 + ドーナツ(円グラフ)ヘルパー ---
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  const OVERVIEW_SEV_LABEL: Record<string, string> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
  };
  // Windows イベントの Level フィールド(数値コード)→ ラベル。
  $: WINDOWS_LEVEL_LABEL = ($locale === 'en'
    ? {
        '0': 'Information (default)',
        '1': 'Critical',
        '2': 'Error',
        '3': 'Warning',
        '4': 'Information',
        '5': 'Verbose'
      }
    : {
        '0': '情報(既定)',
        '1': '重大',
        '2': 'エラー',
        '3': '警告',
        '4': '情報',
        '5': '詳細'
      }) as Record<string, string>;
  $: levelLabel = (value: string): string =>
    WINDOWS_LEVEL_LABEL[value] ? `${WINDOWS_LEVEL_LABEL[value]} (${value})` : value;
  // Level コード → 深刻度に応じたラベル色(重大=赤 / エラー=橙 / 警告=琥珀 / 情報=中間 / 詳細=灰)。
  const WINDOWS_LEVEL_COLOR: Record<string, string> = {
    '0': '#9fb0bf',
    '1': '#ff5c5c',
    '2': '#ff8c42',
    '3': '#f5a524',
    '4': '#9fb0bf',
    '5': '#6b7c8d',
  };
  function levelColor(value: string): string {
    return WINDOWS_LEVEL_COLOR[value] ?? '#cad6e1';
  }
  // 重大度の正準パレット。CSS の --sev-* トークンと必ず同値に保つこと
  // (JS からは CSS 変数を直接読めないため hex をミラー)。全チャート共通。
  const SEVERITY_COLOR: Record<string, string> = {
    critical: '#e5686a',
    high: '#e88b4a',
    medium: '#d8b24a',
    low: '#7d92a8',
    info: '#5fae86',
  };
  // 旧名は互換のため正準マップのエイリアス(色は統一済み)。
  const OVERVIEW_SEV_FILL = SEVERITY_COLOR;
  const SEV_COLOR = SEVERITY_COLOR;
  function severityColor(s: string | null | undefined): string {
    return SEV_COLOR[s ?? 'info'] ?? SEV_COLOR.info;
  }
  function buildDonut(items: { label: string; count: number; color: string }[]) {
    const R = 42;
    const C = 2 * Math.PI * R;
    const total = items.reduce((a, b) => a + b.count, 0);
    let acc = 0;
    const segs = items
      .filter((i) => i.count > 0)
      .map((i) => {
        const frac = total > 0 ? i.count / total : 0;
        const seg = {
          ...i,
          dash: `${(frac * C).toFixed(2)} ${(C - frac * C).toFixed(2)}`,
          offset: (-acc * C).toFixed(2),
          pct: Math.round(frac * 100),
        };
        acc += frac;
        return seg;
      });
    return { segs, total, R, C };
  }
  $: riskSeverityBuckets = SEV_ORDER.map((s) => ({
    label: s,
    count: risks.filter((r) => (r.severity_max ?? 'info') === s).length,
    color: SEV_COLOR[s],
  })).filter((b) => b.count > 0);
  $: riskDonut = buildDonut(riskSeverityBuckets);
  $: riskCriticalHigh = risks.filter((r) => ['critical', 'high'].includes(r.severity_max ?? '')).length;

  // --- 不審イベント/サジェスト カード (taotieネイティブ, engine語彙に合わせて分類) ---
  const FINDING_SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  function findingTechniques(f: FindingSummary): string[] {
    return jsonStringArray(f.attack_json);
  }
  type FindingEnrichment = {
    description?: string | null;
    references?: string[];
    falsepositives?: string[];
    rule_level?: string | null;
    tactics?: string[];
    matched?: { channel?: string | null; event_ids?: string[] };
  };
  function parseEnrichment(f: FindingSummary | null): FindingEnrichment | null {
    if (!f?.enrichment_json) return null;
    try {
      const o = JSON.parse(f.enrichment_json);
      return o && typeof o === 'object' ? (o as FindingEnrichment) : null;
    } catch {
      return null;
    }
  }
  $: selectedEnrichment = parseEnrichment(selectedFinding);
  $: selectedFindingTechniques = selectedFinding ? findingTechniques(selectedFinding) : [];
  function groupAffected(entities: string[] | undefined) {
    const hosts: string[] = [];
    const users: string[] = [];
    const procs: string[] = [];
    for (const e of entities ?? []) {
      if (e.startsWith('host:')) hosts.push(e.slice(5));
      else if (e.startsWith('user:')) users.push(e.slice(5));
      else if (e.startsWith('process:')) procs.push(e.slice(8));
    }
    return { hosts, users, procs };
  }
  function relatedFindingKey(g: FindingSummary): string {
    return `${g.title}|${g.engine}|${g.rule_id ?? ''}`;
  }
  function relatedFindings(f: FindingSummary, all: FindingSummary[]): FindingSummary[] {
    const techs = new Set(findingTechniques(f));
    const hosts = new Set((f.affected_entities ?? []).filter((e) => e.startsWith('host:')));
    const out: FindingSummary[] = [];
    // {#each} の key と同じ複合キーで重複排除(同一キーだと Svelte の each_key_duplicate で描画が壊れる)。
    const seen = new Set<string>();
    for (const g of all) {
      if (sameFinding(g, f)) continue;
      const key = relatedFindingKey(g);
      if (seen.has(key)) continue;
      const sharesTech = findingTechniques(g).some((t) => techs.has(t));
      const sharesHost = (g.affected_entities ?? []).some(
        (e) => e.startsWith('host:') && hosts.has(e),
      );
      if (sharesTech || sharesHost) {
        out.push(g);
        seen.add(key);
        if (out.length >= 6) break;
      }
    }
    return out;
  }
  function nextActionFor(enr: FindingEnrichment | null): string {
    const tactics = enr?.tactics ?? [];
    if (tactics.includes('credential access')) return $t('nextaction.credential_access');
    if (tactics.includes('defense evasion')) return $t('nextaction.defense_evasion');
    if (tactics.includes('persistence')) return $t('nextaction.persistence');
    if (tactics.includes('execution')) return $t('nextaction.execution');
    return $t('nextaction.default');
  }
  function scoreBreakdown(f: FindingSummary) {
    const rank = FINDING_SEV_RANK[f.severity] ?? 0;
    const tech = findingTechniques(f).length;
    const rarity = Math.max(0, Math.round(70 - Math.log2((f.finding_count ?? 0) + 1) * 8));
    return { sev: rank * 1000, tech: tech * 40, base: 20, rarity, total: rank * 1000 + tech * 40 + 20 + rarity };
  }
  function findingConfidence(f: FindingSummary, enr: FindingEnrichment | null): string {
    let s = 0;
    if (['sigma', 'ioc', 'hayabusa'].includes(f.engine)) s += 2;
    else if (f.engine === 'correlation') s += 1;
    if (enr?.description) s += 1;
    if ((f.affected_entities?.length ?? 0) > 0) s += 1;
    if ((f.event_count ?? 0) >= 5) s += 1;
    return s >= 4 ? $t('level.high') : s >= 2 ? $t('level.medium') : $t('level.low');
  }
  $: selectedAffected = groupAffected(selectedFinding?.affected_entities);
  $: selectedRelated = selectedFinding ? relatedFindings(selectedFinding, findings) : [];
  $: selectedNextAction = selectedFinding ? (void $locale, nextActionFor(selectedEnrichment)) : '';
  $: selectedScore = selectedFinding ? scoreBreakdown(selectedFinding) : null;
  $: selectedConfidence = selectedFinding ? (void $locale, findingConfidence(selectedFinding, selectedEnrichment)) : '';
  $: hasFindingExplain = !!(
    selectedFinding &&
    (selectedEnrichment?.description ||
      selectedFindingTechniques.length ||
      selectedEnrichment?.matched?.channel ||
      selectedEnrichment?.matched?.event_ids?.length ||
      selectedEnrichment?.falsepositives?.length ||
      selectedEnrichment?.references?.length ||
      selectedFinding.affected_entities?.length ||
      selectedRelated.length)
  );
  function findingScore(f: FindingSummary): number {
    const rank = FINDING_SEV_RANK[f.severity] ?? 0;
    const rarity = Math.max(0, Math.round(70 - Math.log2((f.finding_count ?? 0) + 1) * 8));
    return rank * 1000 + findingTechniques(f).length * 40 + 20 + rarity;
  }
  function findingScoreBand(n: number): string {
    if (n >= 4000) return 'crit';
    if (n >= 3000) return 'high';
    if (n >= 2000) return 'med';
    return 'low';
  }
  function findingBucket(f: FindingSummary): 'rule' | 'suggest' {
    const e = (f.engine ?? '').toLowerCase();
    return e === 'sigma' || e === 'ioc' || e === 'yara' ? 'rule' : 'suggest';
  }
  function findingsBySeverity(list: FindingSummary[]): [string, FindingSummary[]][] {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const groups: Record<string, FindingSummary[]> = {};
    for (const f of list) {
      const s = order.includes(f.severity) ? f.severity : 'info';
      (groups[s] ??= []).push(f);
    }
    return order.filter((s) => groups[s]?.length).map((s) => [s, groups[s]]);
  }
  $: ruleFindings = findings
    .filter((f) => findingBucket(f) === 'rule')
    .slice()
    .sort((a, b) => findingScore(b) - findingScore(a));
  $: suggestFindings = findings
    .filter((f) => findingBucket(f) === 'suggest')
    .slice()
    .sort((a, b) => findingScore(b) - findingScore(a));

  function severityClass(severity: string) {
    return `severity severity-${severity}`;
  }

  function reviewClass(status: string) {
    return `status review-${status}`;
  }

  function jsonList(value: string) {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.join(', ') : value;
    } catch {
      return value;
    }
  }

  function jsonStringArray(value: string | null | undefined) {
    if (!value) return [];
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.map((item) => String(item)).filter(Boolean) : [];
    } catch {
      return [];
    }
  }

  function jsonObjectEntries(value: string | null | undefined) {
    if (!value) return [];
    try {
      const parsed = JSON.parse(value);
      if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') return [];
      return Object.entries(parsed as Record<string, unknown>).map(([key, item]) => [key, String(item)] as const);
    } catch {
      return [];
    }
  }

  function answerQuestionOptions() {
    const seen = new Map<string, string>();
    for (const row of answerCandidates) {
      if (!seen.has(row.question_key)) seen.set(row.question_key, row.question_label);
    }
    return Array.from(seen.entries()).sort((left, right) => left[1].localeCompare(right[1]));
  }

  function answerStatusClass(status: string) {
    return `status status-${status.replace(/[^a-z0-9_-]/gi, '_').toLowerCase()}`;
  }

  function answerConfidence(value: number) {
    return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
  }

  function chainSteps(value: string) {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.slice(0, 6) : [];
    } catch {
      return [];
    }
  }

  function subgraphNodeLabel(entityId: string) {
    return subgraph.nodes.find((node) => node.entity_id === entityId)?.display_name ?? entityId;
  }

  function eventSubject(row: EventRow) {
    return displayText(row.process_name ?? row.file_path ?? row.ip ?? row.hash ?? row.user_name ?? row.host, '-');
  }
  // コマンドラインは attributes_json 由来で JSON エスケープ(\\ / \")が残るため表示時に復元。
  function commandDisplay(value: string | null | undefined): string {
    const v = (value ?? '').trim();
    if (!v) return '-';
    return v.replace(/\\\\/g, '\\').replace(/\\"/g, '"');
  }

  function artifactQuickFiltersFor(artifactType: string): ArtifactQuickFilter[] {
    const term = (value: string) => quoteEventSearchValue(value);
    const field = (name: string, value: string) => `${name}:${term(value)}`;
    const any = (values: string[]) => `(${values.map(term).join(' OR ')})`;
    const anyField = (name: string, values: string[]) => `(${values.map((value) => field(name, value)).join(' OR ')})`;
    const writablePaths = anyField('file', ['\\Users\\', '\\AppData\\', '\\Temp\\', '\\ProgramData\\', '\\Downloads\\']);
    const scriptAndExecutable = any(['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf', '.lnk']);
    const lolbins = anyField('process', [
      'powershell',
      'pwsh',
      'cmd',
      'rundll32',
      'regsvr32',
      'mshta',
      'wscript',
      'cscript',
      'wmic',
      'certutil',
      'bitsadmin',
      'installutil',
      'msbuild',
      'regasm',
      'regsvcs'
    ]);

    if (artifactType === 'mft') {
      return [
        { id: 'mft-writable-exec', label: $t('preset.mft.writable_exec'), query: `${writablePaths} ${scriptAndExecutable}` },
        { id: 'mft-delete-rename', label: $t('preset.delete_rename'), query: any(['delete', 'deleted', 'removed', 'rename', 'renamed']) },
        { id: 'mft-timestomp', label: $t('preset.timestomp'), query: any(['timestomp', 'SI/FN', 'timestamp mismatch', 'time mismatch']) },
        { id: 'mft-startup-persistence', label: $t('preset.startup_persistence'), query: any(['\\Startup\\', 'RunOnce', '\\Start Menu\\Programs\\Startup\\']) }
      ];
    }
    if (artifactType === 'prefetch') {
      return [
        { id: 'pf-lolbin', label: $t('preset.lolbin_exec'), query: lolbins },
        { id: 'pf-user-writable', label: $t('preset.user_writable_exec'), query: writablePaths },
        { id: 'pf-script-launch', label: $t('preset.script_exec'), query: any(['.ps1', '.vbs', '.js', '.jse', '.wsf', '.bat', '.cmd']) },
        { id: 'pf-finding', label: $t('preset.with_finding'), query: 'finding:true' }
      ];
    }
    if (artifactType === 'usn_jrnl') {
      return [
        { id: 'usn-destructive', label: $t('preset.destructive'), query: any(['delete', 'deleted', 'truncate', 'overwrite', 'data overwrite']) },
        { id: 'usn-rename', label: $t('preset.rename_chain'), query: any(['rename', 'renamed', 'old name', 'new name']) },
        { id: 'usn-writable-exec', label: $t('preset.exec_file_change'), query: `${writablePaths} ${scriptAndExecutable}` },
        { id: 'usn-temp', label: $t('preset.temp_appdata'), query: anyField('file', ['\\Temp\\', '\\AppData\\', '\\Downloads\\']) }
      ];
    }
    if (artifactType === 'amcache') {
      return [
        { id: 'amcache-user-program', label: $t('preset.user_program'), query: writablePaths },
        { id: 'amcache-lolbin', label: $t('preset.admin_lolbin'), query: lolbins },
        { id: 'amcache-hash-present', label: $t('preset.hash_present'), query: 're:/\\b[a-f0-9]{32,64}\\b/' },
        { id: 'amcache-installer-updater', label: 'Installer/Updater', query: any(['installer', 'setup', 'updater', 'update', 'download']) }
      ];
    }
    if (artifactType === 'srum') {
      return [
        { id: 'srum-network', label: $t('preset.network_dest'), query: 're:/\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|https?:\\/\\//' },
        { id: 'srum-browser', label: $t('preset.browser_fetch'), query: anyField('process', ['chrome', 'msedge', 'firefox', 'iexplore', 'curl', 'wget']) },
        { id: 'srum-script-network', label: $t('preset.script_network'), query: anyField('process', ['powershell', 'pwsh', 'wscript', 'cscript', 'mshta']) },
        { id: 'srum-admin-tools', label: $t('preset.admin_network'), query: anyField('process', ['psexec', 'wmic', 'winrm', 'rundll32', 'regsvr32']) }
      ];
    }
    if (artifactType === 'text_observation') {
      return [
        { id: 'text-errors', label: $t('preset.errors'), query: any(['error', 'fail', 'failed', 'warning', 'denied']) },
        { id: 'text-network', label: $t('preset.url_ip'), query: 're:/https?:\\/\\/|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b/' },
        { id: 'text-exec', label: $t('preset.exec_script'), query: `${lolbins} ${any(['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js'])}` },
        { id: 'text-transfer', label: $t('preset.transfer_sync'), query: any(['download', 'upload', 'sync', 'exfil', 'ftp', 'http']) }
      ];
    }
    return [
      { id: 'artifact-finding', label: $t('preset.with_finding'), query: 'finding:true' },
      { id: 'artifact-high', label: $t('preset.high_plus'), query: '(severity:high OR severity:critical)' },
      { id: 'artifact-writable', label: $t('preset.user_writable_area'), query: writablePaths }
    ];
  }

  function artifactEventColumns(artifactType: string): ArtifactEventColumn[] {
    const timeColumn: ArtifactEventColumn = {
      label: 'Time',
      sortBy: 'event_time_utc',
      className: 'mono time-cell',
      width: 250,
      minWidth: 230,
      value: (row) => formatTimestamp(row.event_time_utc)
    };
    const severityColumn: ArtifactEventColumn = {
      label: 'Severity',
      sortBy: 'severity',
      kind: 'severity',
      value: (row) => row.severity
    };
    const messageColumn: ArtifactEventColumn = {
      label: 'Message',
      sortBy: 'message_short',
      value: (row) => row.message_short
    };
    const hostUserColumn: ArtifactEventColumn = {
      label: 'Host / User',
      sortBy: 'host',
      value: (row) => compactJoin([row.host, row.user_name], ' / ')
    };

    if (artifactType === 'mft') {
      return [
        timeColumn,
        severityColumn,
        { label: 'Action', sortBy: 'event_action', value: (row) => row.event_action },
        { label: 'File Path', sortBy: 'file_path', value: (row) => row.file_path ?? eventSubject(row) },
        { label: 'Hash / EID', sortBy: 'hash', className: 'mono', value: (row) => row.hash ?? row.event_code },
        messageColumn
      ];
    }
    if (artifactType === 'prefetch') {
      return [
        timeColumn,
        severityColumn,
        { label: 'Process', sortBy: 'process_name', value: (row) => row.process_name ?? eventSubject(row) },
        { label: 'Prefetch / Path', sortBy: 'file_path', value: (row) => row.file_path ?? row.message_short },
        hostUserColumn,
        messageColumn
      ];
    }
    if (artifactType === 'usn_jrnl') {
      return [
        timeColumn,
        severityColumn,
        { label: 'USN Action', sortBy: 'event_action', value: (row) => row.event_action },
        { label: 'Path', sortBy: 'file_path', value: (row) => row.file_path ?? eventSubject(row) },
        hostUserColumn,
        messageColumn
      ];
    }
    if (artifactType === 'amcache') {
      return [
        timeColumn,
        severityColumn,
        { label: 'Program', sortBy: 'process_name', value: (row) => row.process_name ?? eventSubject(row) },
        { label: 'Path', sortBy: 'file_path', value: (row) => row.file_path ?? row.message_short },
        { label: 'Hash', sortBy: 'hash', className: 'mono', value: (row) => row.hash },
        messageColumn
      ];
    }
    if (artifactType === 'srum') {
      return [
        timeColumn,
        severityColumn,
        { label: 'Resource', sortBy: 'process_name', value: (row) => row.process_name ?? row.url ?? row.ip ?? eventSubject(row) },
        { label: 'Network', sortBy: 'ip', value: (row) => compactJoin([row.ip, row.url], ' / ') },
        hostUserColumn,
        messageColumn
      ];
    }
    if (artifactType === 'text_observation') {
      return [
        timeColumn,
        severityColumn,
        { label: 'Source / Path', sortBy: 'file_path', value: (row) => row.file_path ?? eventSubject(row) },
        { label: 'Process / Network', sortBy: 'process_name', value: (row) => compactJoin([row.process_name, row.ip, row.url], ' / ') },
        { label: 'Action', sortBy: 'event_action', value: (row) => row.event_action },
        messageColumn
      ];
    }
    return [
      timeColumn,
      severityColumn,
      { label: 'Action', sortBy: 'event_action', value: (row) => row.event_action },
      { label: 'Subject', sortBy: 'process_name', value: (row) => eventSubject(row) },
      hostUserColumn,
      messageColumn
    ];
  }

  function artifactEventStats(rows: EventRow[]): ArtifactEventStats {
    const hosts = new Set<string>();
    const users = new Set<string>();
    let findings = 0;
    let highPriority = 0;
    for (const row of rows) {
      if (row.host) hosts.add(row.host);
      if (row.user_name) users.add(row.user_name);
      if (row.has_finding) findings += 1;
      if (row.severity === 'high' || row.severity === 'critical') highPriority += 1;
    }
    return {
      loaded: rows.length,
      findings,
      highPriority,
      hosts: hosts.size,
      users: users.size
    };
  }

  function parseDetailAttributes(attributesJson: string | null | undefined): Record<string, unknown> | null {
    if (!attributesJson) return null;
    try {
      const parsed = JSON.parse(attributesJson) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return null;
    }
    return null;
  }

  function artifactDetailFields(
    row: EventRow | null,
    rowDetail: EventDetailLight | null,
    attributes: Record<string, unknown> | null
  ): DetailField[] {
    if (!row) return [];
    const fields: DetailField[] = [];
    const seen = new Set<string>();
    const add = (
      label: string,
      value: unknown,
      className: string | undefined = undefined,
      pivot: PivotField | undefined = undefined
    ) => {
      const text = detailValueText(value);
      if (!text) return;
      const key = `${label}\0${text}`;
      if (seen.has(key)) return;
      seen.add(key);
      fields.push({ label, value: text, className, pivot });
    };
    const attr = (key: string) => attributes?.[key];
    const addAttr = (
      key: string,
      label = detailFieldLabel(key),
      className: string | undefined = undefined,
      pivot: PivotField | undefined = undefined
    ) =>
      add(label, attr(key), className, pivot);

    add('Artifact', row.artifact_type);
    add('Action', row.event_action);
    add('Time kind', rowDetail?.time_kind);
    add('Time confidence', rowDetail ? confidenceText(rowDetail.time_confidence) : null);
    add('Source confidence', rowDetail ? confidenceText(rowDetail.source_confidence) : null);

    if (row.artifact_type === 'mft') {
      for (const [key, label] of [
        ['parser_mode', 'Parser mode'],
        ['record_number', 'Record number'],
        ['record_offset', 'Record offset'],
        ['record_size', 'Record size'],
        ['entry_number', 'Entry number'],
        ['sequence_number', 'Sequence'],
        ['flags', 'Flags'],
        ['in_use', 'In use'],
        ['deleted', 'Deleted'],
        ['is_directory', 'Directory'],
        ['parent_record_number', 'Parent record'],
        ['file_namespace', 'Namespace'],
        ['file_attributes', 'File attrs'],
        ['allocated_size', 'Allocated size'],
        ['file_size', 'File size'],
        ['time_source', 'Time source'],
        ['time_column', 'Time column'],
        ['attribute_count', 'Attribute count']
      ] as const) {
        addAttr(key, label, key.includes('size') || key.includes('offset') ? 'mono' : undefined);
      }
    } else if (row.artifact_type === 'prefetch') {
      for (const [key, label, pivot] of [
        ['parser_mode', 'Parser mode', undefined],
        ['time_column', 'Time column', undefined],
        ['file_size_header', 'Header file size', undefined],
        ['executable_name_header', 'Header executable', 'file'],
        ['section_count', 'Section count', undefined],
        ['run_count', 'Run count', undefined],
        ['prefetch_file_name', 'PF file', 'file'],
        ['prefetch_hash', 'PF hash', 'hash'],
        ['referenced_file_count', 'Referenced files', undefined],
        ['suspicion', 'Suspicion', undefined],
        ['source_filename', 'Source filename', 'file'],
        ['time_inferred', 'Time inferred', undefined]
      ] as const) {
        addAttr(key, label, pivot ? 'mono' : undefined, pivot);
      }
    } else if (row.artifact_type === 'usn_jrnl') {
      for (const [key, label] of [
        ['parser_mode', 'Parser mode'],
        ['record_index', 'Record index'],
        ['record_offset', 'Record offset'],
        ['record_length', 'Record length'],
        ['usn', 'USN'],
        ['reason', 'Reason'],
        ['reason_raw', 'Reason raw'],
        ['file_reference', 'File reference'],
        ['parent_file_reference', 'Parent file ref'],
        ['source_info', 'Source info'],
        ['security_id', 'Security ID'],
        ['file_attributes', 'File attrs'],
        ['time_inferred', 'Time inferred']
      ] as const) {
        addAttr(
          key,
          label,
          key.includes('reference') || key.includes('offset') || key === 'record_length' || key === 'usn'
            ? 'mono'
            : undefined
        );
      }
    } else if (row.artifact_type === 'amcache') {
      for (const [key, label, pivot] of [
        ['parser_mode', 'Parser mode', undefined],
        ['product_name', 'Product', undefined],
        ['publisher', 'Publisher', undefined],
        ['source_path', 'Source path', 'file'],
        ['string', 'Recovered string', undefined],
        ['time_inferred', 'Time inferred', undefined]
      ] as const) {
        addAttr(key, label, pivot ? 'mono' : undefined, pivot);
      }
    } else if (row.artifact_type === 'srum') {
      for (const [key, label, pivot] of [
        ['parser_mode', 'Parser mode', undefined],
        ['source_path', 'Source path', 'file'],
        ['string', 'Recovered resource', undefined],
        ['time_inferred', 'Time inferred', undefined]
      ] as const) {
        addAttr(key, label, pivot ? 'mono' : undefined, pivot);
      }
    } else {
      for (const key of ['parser_mode', 'provider', 'record_id', 'command_line', 'logon_id', 'logon_type', 'source_path']) {
        addAttr(key);
      }
    }

    add('Host', rowDetail?.host ?? row.host, undefined, 'host');
    add('User', rowDetail?.user_name ?? row.user_name, undefined, 'user');
    add('Process', rowDetail?.process_name ?? row.process_name, undefined, 'process');
    add('File path', rowDetail?.file_path ?? row.file_path, 'mono', 'file');
    add('IP', rowDetail?.ip ?? row.ip, 'mono', 'ip');
    add('URL', rowDetail?.url ?? row.url, 'mono', 'url');
    add('Hash', rowDetail?.hash ?? row.hash, 'mono', 'hash');

    return fields.slice(0, 36);
  }

  function pivotActionsFor(row: EventRow | null, rowDetail: EventDetailLight | null): PivotAction[] {
    if (!row) return [];
    const actions: PivotAction[] = [];
    const add = (label: string, field: PivotField, value: string | null | undefined) => {
      const text = displayText(value, '').trim();
      if (!text || actions.some((action) => action.field === field && action.value === text)) return;
      actions.push({ label, field, value: text });
    };
    add($t('pivot.same_file'), 'file', rowDetail?.file_path ?? row.file_path);
    add($t('pivot.same_process'), 'process', rowDetail?.process_name ?? row.process_name);
    add($t('pivot.same_hash'), 'hash', rowDetail?.hash ?? row.hash);
    add($t('pivot.same_ip'), 'ip', rowDetail?.ip ?? row.ip);
    add($t('pivot.same_url'), 'url', rowDetail?.url ?? row.url);
    add($t('pivot.same_user'), 'user', rowDetail?.user_name ?? row.user_name);
    add($t('pivot.same_host'), 'host', rowDetail?.host ?? row.host);
    return actions;
  }

  function detailFieldLabel(key: string) {
    return key
      .split('_')
      .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
      .join(' ');
  }

  function detailValueText(value: unknown): string {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string') return displayText(value, '');
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (Array.isArray(value)) return value.map(detailValueText).filter(Boolean).join(', ');
    try {
      return displayText(JSON.stringify(value), '');
    } catch {
      return String(value);
    }
  }

  function confidenceText(value: number | null | undefined) {
    if (value === null || value === undefined || Number.isNaN(value)) return '';
    return `${Math.round(value * 100)}%`;
  }

  function compactJoin(values: Array<string | null | undefined>, separator = ' ') {
    return values
      .map((value) => displayText(value, ''))
      .filter(Boolean)
      .join(separator);
  }

  function displayText(value: string | null | undefined, fallback = '-') {
    if (!value) return fallback;
    const cleaned = value
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\ufffd]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    if (!cleaned) return fallback;
    if (looksCorruptDisplay(cleaned)) return '[binary/text decode artifact]';
    return cleaned;
  }

  function formatTimestamp(value: string | null | undefined, fallback = '-') {
    const text = displayText(value, '');
    if (!text) return fallback;
    const match = text.match(
      /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}(?::?\d{2})?)?$/
    );
    if (!match) return text.replace('T', ' ');
    const milliseconds = (match[3] ?? '000').slice(0, 3).padEnd(3, '0');
    // Data is stored in UTC; the zone is shown once in the TIME column header,
    // not appended to every value, so cells stay compact (no trailing UTC/+00:00).
    return `${match[1]} ${match[2]}.${milliseconds}`;
  }

  function formatTimeRange(start: string | null | undefined, end: string | null | undefined) {
    return `${formatTimestamp(start)} / ${formatTimestamp(end)}`;
  }

  // Same UTC instant as formatTimestamp, reordered to DD/MM/YYYY HH:MM:SS (no zone conversion).
  function formatTimestampDmy(value: string | null | undefined, fallback = '-') {
    const text = displayText(value, '');
    if (!text) return fallback;
    const match = text.match(
      /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)?$/
    );
    if (!match) return fallback;
    return `${match[3]}/${match[2]}/${match[1]} ${match[4]}`;
  }

  function shortHash(value: string | null | undefined) {
    if (!value) return '-';
    return value.length > 18 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value;
  }

  function looksCorruptDisplay(value: string) {
    const chars = Array.from(value);
    if (chars.length < 12) return false;
    let signal = 0;
    let symbolish = 0;
    for (const ch of chars) {
      const code = ch.codePointAt(0) ?? 0;
      if (
        /[A-Za-z0-9]/.test(ch) ||
        (code >= 0x3040 && code <= 0x30ff) ||
        (code >= 0x3400 && code <= 0x9fff) ||
        (code >= 0xff66 && code <= 0xff9f)
      ) {
        signal += 1;
      } else if (!/\s/.test(ch) && !['.', ',', ':', ';', '-', '_', '/', '\\', '[', ']', '(', ')'].includes(ch)) {
        symbolish += 1;
      }
    }
    return (signal * 100) / chars.length < 20 && (symbolish * 100) / chars.length > 35;
  }

  function detailEventCode() {
    if (detail?.attributes_json) {
      try {
        const parsed = JSON.parse(detail.attributes_json);
        if (typeof parsed.event_id === 'string' && parsed.event_id) return parsed.event_id;
      } catch {
        // Keep detail rendering resilient to malformed adapter attributes.
      }
    }
    return selectedEvent?.event_code ?? '-';
  }

  // --- Ctrl+F page-wide find (find-on-page over the rendered DOM) ---
  let findOpen = false;
  let findQuery = '';
  let findCount = 0;
  let findIndex = 0;
  let findInputEl: HTMLInputElement | null = null;
  let findTimer: number | null = null;
  let findRanges: Range[] = [];
  const FIND_SUPPORTED = typeof CSS !== 'undefined' && 'highlights' in (CSS as any);

  function handleGlobalKeydown(event: KeyboardEvent) {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'f') {
      event.preventDefault();
      void openFind();
    } else if (event.key === 'Escape' && findOpen) {
      closeFind();
    }
  }

  async function openFind() {
    findOpen = true;
    await tick();
    findInputEl?.focus();
    findInputEl?.select();
    if (findQuery) runFind();
  }

  function closeFind() {
    findOpen = false;
    clearFindHighlights();
  }

  function clearFindHighlights() {
    findRanges = [];
    findCount = 0;
    findIndex = 0;
    if (FIND_SUPPORTED) {
      (CSS as any).highlights.delete('taotie-find');
      (CSS as any).highlights.delete('taotie-find-current');
    }
  }

  function onFindInput() {
    if (findTimer) clearTimeout(findTimer);
    findTimer = window.setTimeout(runFind, 120);
  }

  function runFind() {
    clearFindHighlights();
    const needle = findQuery.trim().toLowerCase();
    if (!needle) return;
    const root = document.querySelector('main.app-shell');
    if (!root) return;
    const ranges: Range[] = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node: Node) {
        const v = node.nodeValue;
        if (!v || !v.trim()) return NodeFilter.FILTER_REJECT;
        const p = (node as Text).parentElement;
        if (!p) return NodeFilter.FILTER_REJECT;
        if (p.closest('.find-bar')) return NodeFilter.FILTER_REJECT;
        const tag = p.tagName;
        if (tag === 'SCRIPT' || tag === 'STYLE') return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    let node: Node | null;
    while ((node = walker.nextNode()) && ranges.length < 5000) {
      const hay = node.nodeValue!.toLowerCase();
      let idx = hay.indexOf(needle);
      while (idx !== -1) {
        const r = document.createRange();
        r.setStart(node, idx);
        r.setEnd(node, idx + needle.length);
        ranges.push(r);
        idx = hay.indexOf(needle, idx + needle.length);
      }
    }
    findRanges = ranges;
    findCount = ranges.length;
    findIndex = 0;
    applyFindHighlights();
    if (ranges.length) scrollToCurrent();
  }

  function applyFindHighlights() {
    if (!FIND_SUPPORTED) return;
    const HighlightCtor = (window as any).Highlight;
    if (!HighlightCtor) return;
    if (findRanges.length) {
      (CSS as any).highlights.set('taotie-find', new HighlightCtor(...findRanges));
      (CSS as any).highlights.set('taotie-find-current', new HighlightCtor(findRanges[findIndex]));
    } else {
      (CSS as any).highlights.delete('taotie-find');
      (CSS as any).highlights.delete('taotie-find-current');
    }
  }

  function scrollToCurrent() {
    const r = findRanges[findIndex];
    const el = r ? (r.startContainer as Text).parentElement : null;
    el?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  function findNext() {
    if (!findCount) return;
    findIndex = (findIndex + 1) % findCount;
    applyFindHighlights();
    scrollToCurrent();
  }

  function findPrev() {
    if (!findCount) return;
    findIndex = (findIndex - 1 + findCount) % findCount;
    applyFindHighlights();
    scrollToCurrent();
  }

  function onFindKeydown(event: KeyboardEvent) {
    if (event.key === 'Enter') {
      event.preventDefault();
      if (event.shiftKey) findPrev();
      else findNext();
    } else if (event.key === 'Escape') {
      event.preventDefault();
      closeFind();
    }
  }
</script>

<svelte:window on:keydown={handleGlobalKeydown} />

{#if findOpen}
  <div class="find-bar" role="search">
    <input
      class="find-input"
      type="text"
      placeholder={$t('find.placeholder')}
      bind:value={findQuery}
      bind:this={findInputEl}
      on:input={onFindInput}
      on:keydown={onFindKeydown}
    />
    <span class="find-count">{findCount ? `${findIndex + 1} / ${findCount}` : findQuery ? '0 / 0' : ''}</span>
    <button class="find-btn" title={$t('find.prev')} on:click={findPrev} disabled={!findCount}>‹</button>
    <button class="find-btn" title={$t('find.next')} on:click={findNext} disabled={!findCount}>›</button>
    <button class="find-btn find-close" title={$t('find.close')} on:click={closeFind}>✕</button>
  </div>
{/if}

<main class="app-shell">
  <aside class="sidebar">
    <div class="brand" aria-label="饕餮 Taotie Digital Forensics & Incident Response">
      <div class="brand-kanji" aria-hidden="true"><span class="bk-fill">饕</span><span class="bk-outline">餮</span></div>
      <div class="brand-divider" aria-hidden="true"></div>
      <div class="brand-copy">
        <div class="brand-latin">Taotie</div>
        <div class="brand-subtitle">Digital Forensics &amp;<br />Incident Response</div>
      </div>
    </div>

    <nav class="tabs" aria-label="Views">
      {#each navGroups as group}
        <div class="nav-group-label">{group.label}</div>
        {#each group.items as tab}
        <button
          class:active={tab.id === 'events' ? isEventNavigationActive(activeTab) : activeTab === tab.id}
          title={tab.label}
          on:click={() => setTab(tab.id)}
        >
          <span class="tab-icon"><NavIcon name={tab.icon} /></span>
          <span>{tab.label}</span>
        </button>
        {#if tab.id === 'events' && isEventNavigationActive(activeTab)}
          <div class="sidebar-subnav" aria-label="Event list views">
            <button
              type="button"
              class:active={activeTab === 'events' && eventSubtab === 'all'}
              on:click={() => setEventSubtab('all')}
            >
              <span class="tab-icon"><NavIcon name="list" /></span>
              {$t('subnav.all_events')}
            </button>
            <button
              type="button"
              class:active={activeTab === 'events' && eventSubtab === 'users'}
              on:click={() => setEventSubtab('users')}
            >
              <span class="tab-icon"><NavIcon name="user" /></span>
              {$t('subnav.by_user')}
            </button>
            {#each eventArtifactSubtabs as item}
              <button
                type="button"
                class:active={activeTab === item.id}
                on:click={() => setEventArtifactSubtab(item.id)}
              >
                <span class="tab-icon"><NavIcon name={item.icon} /></span>
                {item.label}
              </button>
            {/each}
          </div>
        {/if}
        {/each}
      {/each}
    </nav>

    <div class="sidebar-foot">
      <button class="case-create-button" disabled={busy} on:click={openCaseSetupFromSidebar}>
        {tauriRuntimeAvailable() ? $t('sidebar.create_case') : $t('sidebar.enter_case_root')}
      </button>
      <input
        class="hidden-file"
        bind:this={fileInput}
        type="file"
        multiple
        on:change={uploadSelectedArtifacts}
      />
      <input
        class="hidden-file"
        bind:this={folderInput}
        use:directoryPicker
        type="file"
        multiple
        on:change={uploadSelectedArtifacts}
      />
      <button class="primary-ingest" disabled={busy || !summary} on:click={openUploadPicker}>
        {$t('sidebar.ingest_files')}
      </button>
      <button class="secondary-ingest" disabled={busy || !summary} on:click={openFolderPicker}>
        {$t('sidebar.ingest_folder')}
      </button>
      <button class="sidebar-refresh-button" disabled={busy || !summary} on:click={reloadCurrentView}>
        {$t('common.reload')}
      </button>
    </div>
  </aside>

  <section class="content-pane">
    <div class="content-topbar">
      <button class="view-back-button" disabled={busy || viewHistory.length === 0} on:click={goBackView}>
        {$t('nav.back')}
      </button>
      <div class="view-title" title={currentViewFilterSummary}>
        <strong>{currentViewTitle}</strong>
        {#if currentViewFilterSummary}
          <span>{currentViewFilterSummary}</span>
        {/if}
      </div>
      {#if !summary}
        <div class="case-empty-hint">{$t('hint.start_create_case')}</div>
      {/if}
    </div>

    {#if errorMessage}
      <div class="error-line">{errorMessage}</div>
    {/if}
    {#if uploadStatus}
      <div class="status-line">{uploadStatus}</div>
    {/if}
    {#if exportStatus}
      <div class="status-line">{exportStatus}</div>
    {/if}

    <section class="workspace" style={`--workspace-reserve: ${showDetailPane ? detailPaneHeight + 7 : 0}px`}>
    {#if activeTab === 'overview'}
      <div class="metrics">
        <div class="metric">
          <span>{$t('ov.metric.files')}</span>
          <strong>{summary?.file_count ?? 0}</strong>
        </div>
        <div class="metric">
          <span>{$t('ov.metric.events')}</span>
          <strong>{summary?.event_count ?? 0}</strong>
        </div>
        <div class="metric">
          <span>{$t('ov.metric.failed')}</span>
          <strong>{summary?.failed_parse_count ?? 0}</strong>
        </div>
        <div class="metric">
          <span>{$t('ov.metric.unsupported')}</span>
          <strong>{summary?.unsupported_file_count ?? 0}</strong>
        </div>
      </div>
      <div class="overview-graph-grid">
        <div class="panel overview-wide">
          <div class="panel-heading">
            <h2>{$t('chart.event_timeline')}</h2>
            <span class="subtle">{overviewTimelineRows.length} bins</span>
          </div>
          {#if overviewSeverityColumns.length > 0}
            <div class="overview-timeline-chart">
              <svg viewBox="0 0 960 220" preserveAspectRatio="none" role="img" aria-label={$t('chart.event_timeline.aria')}>
                <g class="overview-grid-lines">
                  <line x1="24" y1="18" x2="936" y2="18"></line>
                  <line x1="24" y1="75" x2="936" y2="75"></line>
                  <line x1="24" y1="132" x2="936" y2="132"></line>
                  <line x1="24" y1="188" x2="936" y2="188"></line>
                </g>
                {#each overviewSeverityColumns as bin, index}
                  {#each timelineStackSegments(bin, overviewSeverityMax) as seg}
                    <rect
                      class={`overview-column severity-fill-${seg.sev}`}
                      x={overviewColumnX(index, overviewSeverityColumns.length)}
                      y={seg.y}
                      width={overviewColumnWidth(overviewSeverityColumns.length)}
                      height={seg.height}
                    ></rect>
                  {/each}
                  <rect
                    class="overview-hitbar"
                    x={overviewColumnX(index, overviewSeverityColumns.length)}
                    y="18"
                    width={912 / Math.max(1, overviewSeverityColumns.length)}
                    height="170"
                    tabindex="0"
                    role="button"
                    aria-label={`${bin.bin_start_utc} ${bin.total} events`}
                    on:click={() => run(() => drillDownOverviewBin(bin))}
                    on:keydown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') run(() => drillDownOverviewBin(bin));
                    }}
                  >
                    <title>{bin.bin_start_utc} / {$t('chart.total')} {bin.total} (Crit {bin.critical} / High {bin.high} / Med {bin.medium} / Low {bin.low} / Info {bin.info})</title>
                  </rect>
                {/each}
              </svg>
              <div class="overview-chart-axis">
                <span>{overviewSeverityColumns[0]?.bin_start_utc ?? '-'}</span>
                <strong>{overviewSeverityMax.toLocaleString()} max</strong>
                <span>{overviewSeverityColumns[overviewSeverityColumns.length - 1]?.bin_start_utc ?? '-'}</span>
              </div>
              <div class="overview-legend">
                <span class="ov-leg-label">{$t('chart.legend')}:</span>
                {#each overviewSeverityLegend as item}
                  <span class="ov-leg">
                    <span class="ov-leg-dot" style={`background:${OVERVIEW_SEV_FILL[item.sev]}`}></span>
                    {item.label}
                    <strong class="mono">{item.total.toLocaleString()}</strong>
                  </span>
                {/each}
              </div>
            </div>
          {:else}
            <div class="empty-state">{$t('empty.timeline')}</div>
          {/if}
        </div>
        <div class="panel overview-wide">
          <div class="panel-heading">
            <h2>{$t('chart.triage_funnel')}</h2>
            <span class="subtle">{$t('funnel.collection_to_incident')}</span>
          </div>
          {#if triageFunnel[0].count > 0}
            <div class="funnel">
              {#each triageFunnel as stage, i}
                <button
                  type="button"
                  class="funnel-stage"
                  title={stage.key === 'collection'
                    ? $t('funnel.tip.show_all')
                    : stage.key === 'detection'
                      ? $t('funnel.tip.show_finding')
                      : $t('funnel.tip.to_suspicious')}
                  on:click={() => {
                    if (stage.key === 'collection') drillDownToEvents({});
                    else if (stage.key === 'detection') drillDownToEvents({ search: 'finding:true' });
                    else run(() => setTab('findings'));
                  }}
                >
                  <div class="funnel-meta">
                    <span class="funnel-label">{stage.label}</span>
                    <span class="funnel-sub">{stage.sub}</span>
                  </div>
                  <div class="funnel-bar-wrap">
                    <div
                      class="funnel-bar"
                      style={`width:${funnelWidth(stage.count, triageFunnel[0].count)}%; background:${stage.color}`}
                    >
                      <span class="funnel-count mono">{stage.count.toLocaleString()}</span>
                    </div>
                  </div>
                  <span class="funnel-rate mono" title={$t('funnel.tip.retention')}>
                    {i === 0 ? '100%' : funnelRate(stage.count, triageFunnel[i - 1].count)}
                  </span>
                </button>
              {/each}
            </div>
          {:else}
            <div class="empty-state">{$t('empty.funnel')}</div>
          {/if}
        </div>
        <div class="panel overview-wide">
          <div class="panel-heading">
            <h2>{$t('chart.timestomp_scatter')}</h2>
            <span class="subtle">{$t('chart.timestomp_scatter.sub')}</span>
          </div>
          {#if timestompView}
            <div class="scatter-wrap">
              <svg
                class="scatter"
                viewBox={`0 0 ${timestompView.size} ${timestompView.size}`}
                role="group"
                aria-label={$t('scatter.aria')}
              >
                <line
                  class="scatter-diag"
                  x1={timestompView.diag.x1}
                  y1={timestompView.diag.y1}
                  x2={timestompView.diag.x2}
                  y2={timestompView.diag.y2}
                ></line>
                {#each timestompView.mapped as p}
                  <circle
                    class={p.mismatch ? 'scatter-dot suspect' : 'scatter-dot'}
                    cx={p.cx}
                    cy={p.cy}
                    r={p.mismatch ? 4 : 2.4}
                    tabindex="0"
                    role="button"
                    aria-label={$locale === 'en' ? `Show events for ${p.file_path}` : `${p.file_path} のイベントを表示`}
                    on:click={() =>
                      drillDownToEvents({ artifact: 'mft', search: `path:${quoteEventSearchValue(p.file_path)}` })}
                    on:keydown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        drillDownToEvents({ artifact: 'mft', search: `path:${quoteEventSearchValue(p.file_path)}` });
                      }
                    }}
                  ><title>{`${p.file_path} | SI ${p.si_created_utc} | FN ${p.fn_created_utc} | Δ${p.delta_seconds}s | ${$t('chart.click_to_events')}`}</title></circle>
                {/each}
                <text
                  class="scatter-axis"
                  x="10"
                  y={timestompView.size / 2}
                  transform={`rotate(-90 10 ${timestompView.size / 2})`}
                >{$t('scatter.axis_fn')}</text>
                <text class="scatter-axis" x={timestompView.size / 2} y={timestompView.size - 6}
                  >{$t('scatter.axis_si')}</text>
              </svg>
              <div class="scatter-side">
                <span class="scatter-key"
                  ><span class="scatter-swatch suspect"></span>{$t('scatter.suspect')} {timestompView.mismatchCount} {$t('common.count_suffix')}</span
                >
                <span class="scatter-key"
                  ><span class="scatter-swatch"></span>{$t('scatter.consistent')} {timestompView.total -
                    timestompView.mismatchCount} {$t('common.count_suffix')}</span
                >
                <span class="subtle"
                  >{$t('scatter.explain')}</span
                >
              </div>
            </div>
          {:else}
            <div class="empty-state">{$t('empty.mft_scatter')}</div>
          {/if}
        </div>
        <div class="panel overview-wide">
          <div class="panel-heading">
            <h2>{$t('chart.attack_heatmap')}</h2>
            <span class="subtle">{$t('chart.attack_heatmap.sub')}</span>
          </div>
          {#if attackHeatmap.rows.length > 0}
            <div class="heatmap">
              <div class="heatmap-row heatmap-head">
                <span class="heatmap-rowlabel"></span>
                <div class="heatmap-cells">
                  {#each Array(24) as _unused, h}
                    <span class="heatmap-hour">{h % 3 === 0 ? h : ''}</span>
                  {/each}
                </div>
              </div>
              {#each attackHeatmap.rows as row}
                <div class="heatmap-row">
                  <span class="heatmap-rowlabel" title={row.tactic}>{attackTacticLabel(row.tactic)}</span>
                  <div class="heatmap-cells">
                    {#each row.hours as v, h}
                      {#if v > 0}
                        <button
                          type="button"
                          class="heatmap-cell heatmap-cell-hot"
                          style={`background:${heatColor(v, attackHeatmap.max)}`}
                          title={`${attackTacticLabel(row.tactic)} ${h}${$t('chart.hour_suffix')}: ${v} · ${$t('chart.click_to_events')}`}
                          on:click={() => drillDownHeatmapCell(row.wins[h])}
                        ></button>
                      {:else}
                        <span class="heatmap-cell" title={`${attackTacticLabel(row.tactic)} ${h}${$t('chart.hour_suffix')}: 0`}></span>
                      {/if}
                    {/each}
                  </div>
                </div>
              {/each}
            </div>
          {:else}
            <div class="empty-state">{$t('empty.attack_heatmap')}</div>
          {/if}
        </div>
        <div class="panel overview-wide">
          <div class="panel-heading">
            <h2>{$t('chart.process_tree')}</h2>
            <span class="subtle">{$t('chart.process_tree.sub')}</span>
          </div>
          {#if processTree}
            <div class="ptree">
              {#each processTree.rows as p}
                <div class="ptree-row">
                  <span class="ptree-parent" title={p.name}>{p.name}<em class="mono">{p.total}</em></span>
                  <div class="ptree-bar" style={`width:${Math.max(6, (p.total / processTree.max) * 100)}%`}>
                    {#each p.children.slice(0, 12) as c, i}
                      <button
                        type="button"
                        class="ptree-seg"
                        style={`flex:${c.count}; background:${investigationColors[i % investigationColors.length]}`}
                        title={`${p.name} → ${c.name}: ${c.count} · ${$t('chart.click_to_events')}`}
                        on:click={() =>
                          drillDownToEvents({
                            search: `action:process_created process:${quoteEventSearchValue(c.name)}`
                          })}
                      ><span class="ptree-seg-label">{c.name}</span></button>
                    {/each}
                  </div>
                </div>
              {/each}
            </div>
          {:else}
            <div class="empty-state">{$t('empty.process_tree')}</div>
          {/if}
        </div>
        <div class="panel overview-wide">
          <div class="panel-heading">
            <h2>{$t('chart.fileop')}</h2>
            <span class="subtle"
              >USN: {$t('chart.fileop.legend')} ({fileOpView?.totalCreated ?? 0} {$t('chart.op.created')} · {fileOpView?.totalDeleted ??
                0} {$t('chart.op.deleted')})</span
            >
          </div>
          {#if fileOpView}
            <div class="fileop">
              {#each fileOpView.bins as b}
                <div
                  class="fileop-col"
                  title={`${b.bin_start_utc} · ${$t('chart.op.created')} ${b.created} / ${$t('chart.op.deleted')} ${b.deleted} / ${$t('chart.op.renamed')} ${b.renamed} / ${$t('chart.op.modified')} ${b.modified}`}
                >
                  <button
                    type="button"
                    class="fileop-top"
                    title={`${b.bin_start_utc} ${$t('chart.op.created')} ${b.created} · ${$t('chart.click_to_events')}`}
                    on:click={() =>
                      drillDownToEvents({
                        artifact: 'usn_jrnl',
                        search: 'action:usn_created',
                        startUtc: `${b.bin_start_utc}:00`,
                        endUtc: `${b.bin_start_utc}:59`
                      })}
                    ><span class="fileop-up" style={`height:${Math.round((b.created / fileOpView.max) * 100)}%`}></span></button
                  >
                  <span class="fileop-mid"></span>
                  <button
                    type="button"
                    class="fileop-bot"
                    title={`${b.bin_start_utc} ${$t('chart.op.deleted')} ${b.deleted} · ${$t('chart.click_to_events')}`}
                    on:click={() =>
                      drillDownToEvents({
                        artifact: 'usn_jrnl',
                        search: 'action:usn_deleted',
                        startUtc: `${b.bin_start_utc}:00`,
                        endUtc: `${b.bin_start_utc}:59`
                      })}
                    ><span class="fileop-down" style={`height:${Math.round((b.deleted / fileOpView.max) * 100)}%`}></span></button
                  >
                </div>
              {/each}
            </div>
            <div class="fileop-axis">
              <span>{fileOpView.bins[0]?.bin_start_utc}</span>
              <span>{fileOpView.bins[fileOpView.bins.length - 1]?.bin_start_utc}</span>
            </div>
          {:else}
            <div class="empty-state">{$t('empty.usn')}</div>
          {/if}
        </div>
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('chart.logon')}</h2>
            <span class="subtle">Security 4624 / 4625</span>
          </div>
          <div class="overview-bars">
            {#each loginOutcomeRows as row}
              <button
                type="button"
                class={`overview-bar-row outcome-${row.tone}`}
                on:click={() => drillDownOverviewFacet({ field: 'event_code', value: row.eventCode, count: row.count })}
              >
                <span>{row.label}</span>
                <span class="bar-track">
                  <span class="bar" style={overviewBarWidth(row.count, maxLoginOutcomeCount)}></span>
                </span>
                <strong>{row.count}</strong>
              </button>
            {/each}
          </div>
        </div>
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('chart.beacon')}</h2>
            <span class="subtle"
              >{$t('chart.beacon.sub_prefix')} · {beaconTotal} {$t('chart.beacon.intervals')}{#if beaconPeak && beaconTotal > 0} · {$t('chart.beacon.peak')} {beaconPeak.label}{/if}</span
            >
          </div>
          {#if beaconTotal > 0}
            <div class="beacon">
              {#each beaconBins as b}
                <div class="beacon-col">
                  <span class="beacon-count mono">{b.count}</span>
                  <button
                    type="button"
                    class="beacon-track"
                    disabled={b.count === 0}
                    title={b.count > 0
                      ? `${b.label}: ${b.count} ${$t('chart.beacon.intervals')}${b.top_ip ? ` · ${$t('chart.beacon.top_dest')} ${b.top_ip}` : ''} · ${$t('chart.click_to_events')}`
                      : `${b.label}: 0`}
                    on:click={() =>
                      drillDownToEvents({
                        ip: b.top_ip ?? '',
                        search: '(action:network_connection OR action:firewall_connection_allowed)'
                      })}
                    ><span
                      class={beaconPeak && b.label === beaconPeak.label ? 'beacon-bar peak' : 'beacon-bar'}
                      style={`height:${Math.round((b.count / beaconMax) * 100)}%`}
                    ></span></button
                  >
                  <span class="beacon-label">{b.label}</span>
                </div>
              {/each}
            </div>
            <p class="chart-note">{$t('chart.beacon.note')}</p>
          {:else}
            <div class="empty-state">{$t('empty.beacon')}</div>
          {/if}
        </div>
        {#each overviewChartGroups as group}
          {@const maxCount = Math.max(1, ...group.values.map((row) => row.count))}
          <div class="panel">
            <div class="panel-heading">
              <h2>{group.label} {$t('chart.breakdown')}</h2>
              <span class="subtle">top {group.values.length}</span>
            </div>
            {#if group.field === 'artifact_type'}
              {@const typeDonut = buildDonut(group.values.map((facet, i) => ({ label: facet.value, count: facet.count, color: investigationColors[i % investigationColors.length] })))}
              <div class="donut-wrap">
                <svg class="donut" viewBox="0 0 120 120" role="img" aria-label={$t('chart.type_breakdown')}>
                  <circle cx="60" cy="60" r={typeDonut.R} fill="none" stroke="#0b1017" stroke-width="16"></circle>
                  {#each typeDonut.segs as seg}
                    <circle
                      cx="60" cy="60" r={typeDonut.R} fill="none" stroke={seg.color} stroke-width="16"
                      stroke-dasharray={seg.dash} stroke-dashoffset={seg.offset}
                      transform="rotate(-90 60 60)"
                    ><title>{artifactTypeLabel(seg.label)} {seg.count} ({seg.pct}%)</title></circle>
                  {/each}
                  <text x="60" y="57" class="donut-total" text-anchor="middle">{typeDonut.total.toLocaleString()}</text>
                  <text x="60" y="73" class="donut-sub" text-anchor="middle">{$t('common.count_suffix')}</text>
                </svg>
                <div class="donut-legend">
                  {#each typeDonut.segs as seg}
                    <button
                      type="button"
                      class="donut-legend-row donut-legend-btn"
                      title={`${$t('common.type')}: ${seg.label}`}
                      on:click={() => drillDownOverviewFacet({ field: 'artifact_type', value: seg.label, count: seg.count })}
                    >
                      <span class="donut-swatch" style={`background:${seg.color}`}></span>
                      <span class="donut-legend-label">{artifactTypeLabel(seg.label)}</span>
                      <strong class="mono">{seg.count.toLocaleString()}</strong>
                    </button>
                  {/each}
                </div>
              </div>
            {:else}
              <div class="overview-bars">
                {#each group.values as facet}
                  <button
                    type="button"
                    class="overview-bar-row"
                    title={`${group.label}: ${facet.value}`}
                    on:click={() => drillDownOverviewFacet(facet)}
                  >
                    <span style={group.field === 'level' ? `color:${levelColor(facet.value)}; font-weight:600` : ''}
                      >{group.field === 'level' ? levelLabel(facet.value) : facet.value}</span
                    >
                    <span class="bar-track">
                      <span class="bar" style={overviewBarWidth(facet.count, maxCount)}></span>
                    </span>
                    <strong>{facet.count}</strong>
                  </button>
                {/each}
              </div>
            {/if}
          </div>
        {/each}
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('chart.risk_breakdown')}</h2>
            <span class="subtle">{riskDonut.total} {$t('common.techniques_suffix')}</span>
          </div>
          {#if riskDonut.total > 0}
            <button type="button" class="donut-wrap" on:click={() => run(() => setTab('risk'))} title={$t('risk.to_list')}>
              <svg class="donut" viewBox="0 0 120 120" role="img" aria-label={$t('chart.risk_sev_breakdown')}>
                <circle cx="60" cy="60" r={riskDonut.R} fill="none" stroke="#0b1017" stroke-width="16"></circle>
                {#each riskDonut.segs as seg}
                  <circle
                    cx="60" cy="60" r={riskDonut.R} fill="none" stroke={seg.color} stroke-width="16"
                    stroke-dasharray={seg.dash} stroke-dashoffset={seg.offset}
                    transform="rotate(-90 60 60)"
                  ><title>{seg.label} {seg.count} ({seg.pct}%)</title></circle>
                {/each}
                <text x="60" y="57" class="donut-total" text-anchor="middle">{riskDonut.total}</text>
                <text x="60" y="73" class="donut-sub" text-anchor="middle">{$t('common.techniques_suffix')}</text>
              </svg>
              <div class="donut-legend">
                {#each riskDonut.segs as seg}
                  <div class="donut-legend-row">
                    <span class="donut-swatch" style={`background:${seg.color}`}></span>
                    <span class="donut-legend-label">{seg.label}</span>
                    <strong class="mono">{seg.count}</strong>
                  </div>
                {/each}
              </div>
            </button>
          {:else}
            <div class="empty-state">{$t('empty.risk')}</div>
          {/if}
        </div>
      </div>
    {:else if activeTab === 'triage'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.triage')}</h2>
        </div>
        <table>
          <thead>
            <tr>
              <th>Priority</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Title</th>
              <th>Events</th>
              <th>Last</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {#each triageActions as action}
              <tr class="clickable" on:click={() => run(() => openTriageAction(action))}>
                <td>{action.priority}</td>
                <td>{action.category}</td>
                <td><span class={severityClass(action.severity)}>{action.severity}</span></td>
                <td><span class={statusClass(action.status)}>{action.status}</span></td>
                <td>
                  {action.title}<br />
                  <span class="subtle">{action.source_kind} / {action.source_key}</span>
                </td>
                <td>{action.event_count}</td>
                <td>{formatTimestamp(action.last_seen_utc)}</td>
                <td>{displayText(action.reason, '')}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if triageActions.length === 0}
          <div class="empty-state">No triage actions</div>
        {/if}
      </div>
    {:else if activeTab === 'evaluation'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.evaluation')}</h2>
        </div>
        {#if caseDetectionEvaluation}
          <div class="review-summary-strip">
            <span>Overall <strong>{caseDetectionEvaluation.overall_score.toFixed(1)}</strong></span>
            <span>Coverage <strong>{caseDetectionEvaluation.detection_coverage_rate.toFixed(1)}%</strong></span>
            <span>Investigation <strong>{caseDetectionEvaluation.investigation_readiness_score.toFixed(1)}</strong></span>
            <span>Report <strong>{caseDetectionEvaluation.report_quality_score.toFixed(1)}</strong></span>
            <span>Open <strong>{caseDetectionEvaluation.open_findings}</strong></span>
            <span>{$t('eval.high_unreviewed')} <strong>{caseDetectionEvaluation.unreviewed_high_findings}</strong></span>
            <span>Parser gap <strong>{caseDetectionEvaluation.parser_gap_count}</strong></span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Objective</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Findings</th>
                <th>Events</th>
                <th>Artifacts</th>
                <th>ATT&CK</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {#each caseDetectionEvaluation.objectives as objective}
                <tr>
                  <td>{objective.objective_name}</td>
                  <td><span class={statusClass(objective.status)}>{objective.status}</span></td>
                  <td><span class={severityClass(objective.severity_max ?? 'info')}>{objective.severity_max ?? 'info'}</span></td>
                  <td>{objective.finding_count}</td>
                  <td>{objective.event_count}</td>
                  <td>{displayText(objective.artifact_types, '-')}</td>
                  <td>{displayText(objective.attack_techniques, '-')}</td>
                  <td>{displayText(objective.evidence_note, '-')}</td>
                </tr>
              {/each}
            </tbody>
          </table>
          <div class="panel-heading section-heading">
            <h2>{$t('eval.quality_gate')}</h2>
          </div>
          <table>
            <thead>
              <tr>
                <th>Gate</th>
                <th>Category</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Metric</th>
                <th>Detail</th>
                <th>Next Action</th>
              </tr>
            </thead>
            <tbody>
              {#each caseDetectionEvaluation.quality_gates as gate}
                <tr>
                  <td>{gate.title}</td>
                  <td>{gate.category}</td>
                  <td><span class={statusClass(gate.status)}>{gate.status}</span></td>
                  <td><span class={severityClass(gate.severity)}>{gate.severity}</span></td>
                  <td>{gate.metric}</td>
                  <td>{displayText(gate.detail, '-')}</td>
                  <td>{displayText(gate.recommended_action, '-')}</td>
                </tr>
              {/each}
            </tbody>
          </table>
          <div class="subtle table-note">
            {$t('eval.evaluated_at')}: {caseDetectionEvaluation.evaluated_at} / {$t('eval.objectives')} {caseDetectionEvaluation.covered_objective_count}+{caseDetectionEvaluation.partial_objective_count}/{caseDetectionEvaluation.applicable_objective_count}
          </div>
        {:else}
          <div class="empty-state">No case evaluation</div>
        {/if}
      </div>
    {:else if activeTab === 'answers'}
      <div class="answer-layout">
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('tab.answers')}</h2>
            <div class="toolbar compact-toolbar">
              <select aria-label="Investigation lead filter" bind:value={answerQuestionFilter}>
                <option value="">{$t('common.all')}</option>
                {#each answerQuestionOptions() as [key, label]}
                  <option value={key}>{label}</option>
                {/each}
              </select>
              <button class="search-apply-button" disabled={busy} on:click={() => run(applyAnswerQuestionFilter)}>{$t('common.apply')}</button>
              <button disabled={busy || !answerQuestionFilter} on:click={() => run(clearAnswerQuestionFilter)}>{$t('common.reset')}</button>
              <button
                disabled={busy || !summary || !!activeAnswerCandidateJob}
                on:click={() => run(startAnswerCandidateRebuild)}
              >
                {$t('answers.extract')}
              </button>
            </div>
          </div>
          {#if activeAnswerCandidateJob}
            <div class="status-inline">
              {$t('answers.gen_job')}:
              <strong>{activeAnswerCandidateJob.status} {(activeAnswerCandidateJob.progress * 100).toFixed(0)}%</strong>
            </div>
          {/if}
          <div class="review-summary-strip">
            <span>{$t('answers.candidates')} <strong>{answerCandidates.length}</strong></span>
            <span>{$t('answers.conf80')} <strong>{answerCandidates.filter((row) => row.confidence >= 0.8).length}</strong></span>
            <span>{$t('answers.awaiting_recovery')} <strong>{answerCandidates.filter((row) => row.status.includes('recovery') || row.status.includes('needs')).length}</strong></span>
          </div>
          <table class="answer-table">
            <thead>
              <tr>
                <th>{$t('answers.th.perspective')}</th>
                <th>{$t('answers.th.candidate')}</th>
                <th>{$t('common.confidence')}</th>
                <th>{$t('common.status')}</th>
                <th>{$t('common.severity')}</th>
                <th>{$t('answers.th.category')}</th>
                <th>{$t('common.reason')}</th>
              </tr>
            </thead>
            <tbody>
              {#each answerCandidates as row (row.candidate_id)}
                <tr
                  class="clickable"
                  class:selected-row={selectedAnswerCandidate?.candidate_id === row.candidate_id}
                  on:click={() => (selectedAnswerCandidate = row)}
                >
                  <td>
                    {row.question_label}
                  </td>
                  <td class="mono">{row.candidate_value}</td>
                  <td>{answerConfidence(row.confidence)}</td>
                  <td><span class={answerStatusClass(row.status)}>{row.status}</span></td>
                  <td><span class={severityClass(row.severity)}>{row.severity}</span></td>
                  <td>{row.category}</td>
                  <td>{displayText(row.reason, '')}</td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if answerCandidates.length === 0}
            <div class="empty-state">{$t('empty.answers')}</div>
          {/if}
        </div>
        <div class="panel">
          <div class="panel-heading">
            <h2>{selectedAnswerCandidate ? selectedAnswerCandidate.question_label : $t('answers.detail')}</h2>
          </div>
          {#if selectedAnswerCandidate}
            <dl class="meta-grid compact-meta">
              <dt>{$t('answers.th.candidate')}</dt>
              <dd class="mono">{selectedAnswerCandidate.candidate_value}</dd>
              <dt>{$t('common.confidence')}</dt>
              <dd>{answerConfidence(selectedAnswerCandidate.confidence)}</dd>
              <dt>{$t('common.status')}</dt>
              <dd><span class={answerStatusClass(selectedAnswerCandidate.status)}>{selectedAnswerCandidate.status}</span></dd>
              <dt>{$t('common.window')}</dt>
              <dd>{formatTimeRange(selectedAnswerCandidate.first_seen_utc, selectedAnswerCandidate.last_seen_utc)}</dd>
              <dt>{$t('common.reason')}</dt>
              <dd>{selectedAnswerCandidate.reason}</dd>
              <dt>{$t('answers.next_check')}</dt>
              <dd>{selectedAnswerCandidate.next_action ?? '-'}</dd>
            </dl>
            <div class="answer-detail-grid">
              <section>
                <h3>{$t('answers.evidence_events')}</h3>
                {#if jsonStringArray(selectedAnswerCandidate.evidence_event_ids_json).length > 0}
                  <div class="token-list">
                    {#each jsonStringArray(selectedAnswerCandidate.evidence_event_ids_json) as eventId}
                      <span class="mono">{eventId}</span>
                    {/each}
                  </div>
                {:else}
                  <div class="subtle">{$t('answers.no_basis_events')}</div>
                {/if}
              </section>
              <section>
                <h3>{$t('answers.evidence_ref')}</h3>
                {#if jsonStringArray(selectedAnswerCandidate.evidence_refs_json).length > 0}
                  <div class="token-list">
                    {#each jsonStringArray(selectedAnswerCandidate.evidence_refs_json) as ref}
                      <span class="mono">{ref}</span>
                    {/each}
                  </div>
                {:else}
                  <div class="subtle">{$t('answers.no_evidence_ref')}</div>
                {/if}
              </section>
              <section>
                <h3>{$t('answers.missing_steps')}</h3>
                {#if jsonStringArray(selectedAnswerCandidate.missing_steps_json).length > 0}
                  <ol class="answer-steps">
                    {#each jsonStringArray(selectedAnswerCandidate.missing_steps_json) as step}
                      <li>{step}</li>
                    {/each}
                  </ol>
                {:else}
                  <div class="subtle">{$t('answers.no_extra_steps')}</div>
                {/if}
              </section>
              <section>
                <h3>{$t('answers.attributes')}</h3>
                {#if jsonObjectEntries(selectedAnswerCandidate.attributes_json).length > 0}
                  <dl class="meta-grid compact-meta">
                    {#each jsonObjectEntries(selectedAnswerCandidate.attributes_json) as [key, value]}
                      <dt>{key}</dt>
                      <dd class="mono">{value}</dd>
                    {/each}
                  </dl>
                {:else}
                  <div class="subtle">No attributes</div>
                {/if}
              </section>
            </div>
          {:else}
            <div class="empty-state">{$t('answers.select_candidate')}</div>
          {/if}
        </div>
      </div>
    {:else if activeTab === 'evidence_ledger'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.evidence_ledger')}</h2>
          <div class="toolbar compact-toolbar">
            <button disabled={busy || files.length === 0} on:click={() => run(() => runEvidenceVerification(true))}>
              {$t('ledger.verify')}
            </button>
            <button disabled={busy || files.length === 0} on:click={() => run(exportCustodyManifest)}>
              {$t('ledger.custody_manifest')}
            </button>
            <input
              class="manifest-path-input"
              aria-label="Custody manifest path"
              placeholder="/path/to/custody-manifest.json"
              bind:value={custodyManifestPath}
            />
            <button disabled={busy || !custodyManifestPath.trim()} on:click={() => run(verifyCurrentCustodyManifest)}>
              {$t('ledger.verify_manifest')}
            </button>
            <button disabled={busy || files.length === 0} on:click={() => run(exportReportBundle)}>
              {$t('ledger.report_bundle')}
            </button>
            <input
              class="manifest-path-input"
              aria-label="Report bundle path"
              placeholder="/path/to/report-bundle.json"
              bind:value={reportBundlePath}
            />
            <button disabled={busy || !reportBundlePath.trim()} on:click={() => run(verifyCurrentReportBundle)}>
              {$t('ledger.verify_bundle')}
            </button>
          </div>
        </div>
        {#if custodyManifestVerification}
          <div class="review-strip">
            <span class={statusClass(custodyManifestVerification.manifest_hash_ok ? 'verified' : 'failed')}>
              manifest {custodyManifestVerification.manifest_hash_ok ? 'ok' : 'failed'}
            </span>
            <span class={statusClass(custodyManifestVerification.case_id_matches ? 'verified' : 'failed')}>
              case {custodyManifestVerification.case_id_matches ? 'ok' : 'failed'}
            </span>
            <span class={statusClass(custodyManifestVerification.evidence_hash_mismatch_count === 0 ? 'verified' : 'failed')}>
              evidence mismatch {custodyManifestVerification.evidence_hash_mismatch_count}
            </span>
            <span>{custodyManifestVerification.evidence_hash_checked_count}/{custodyManifestVerification.evidence_file_count}</span>
            <span>{custodyManifestVerification.checked_at}</span>
          </div>
        {/if}
        {#if reportBundleVerification}
          <div class="review-strip">
            <span class={statusClass(reportBundleVerification.bundle_hash_ok ? 'verified' : 'failed')}>
              bundle {reportBundleVerification.bundle_hash_ok ? 'ok' : 'failed'}
            </span>
            <span class={statusClass(reportBundleVerification.report_hash_ok ? 'verified' : 'failed')}>
              report {reportBundleVerification.report_hash_ok ? 'ok' : 'failed'}
            </span>
            <span class={statusClass(reportBundleVerification.custody_manifest_hash_ok ? 'verified' : 'failed')}>
              custody {reportBundleVerification.custody_manifest_hash_ok ? 'ok' : 'failed'}
            </span>
            <span class={statusClass(reportBundleVerification.custody_manifest_internal_hash_ok ? 'verified' : 'failed')}>
              manifest internal {reportBundleVerification.custody_manifest_internal_hash_ok ? 'ok' : 'failed'}
            </span>
            <span class={statusClass(reportBundleVerification.case_custody_profile_hash_ok ? 'verified' : 'failed')}>
              custody profile {reportBundleVerification.case_custody_profile_hash_ok ? 'ok' : 'changed'}
            </span>
            <span class={statusClass(reportBundleVerification.signature_valid ? 'verified' : 'failed')}>
              signature {reportBundleVerification.signature_valid ? 'ok' : 'failed'}
            </span>
            <span class={statusClass(reportBundleVerification.signature_payload_hash_ok ? 'verified' : 'failed')}>
              signed hash {reportBundleVerification.signature_payload_hash_ok ? 'ok' : 'failed'}
            </span>
            <span class={statusClass(reportBundleVerification.signature_key_matches_case_key ? 'verified' : 'failed')}>
              key {reportBundleVerification.signature_key_matches_case_key ? 'case' : 'external'}
            </span>
            <span class={statusClass(reportBundleVerification.audit_log_unchanged ? 'verified' : 'failed')}>
              audit {reportBundleVerification.audit_log_unchanged ? 'unchanged' : 'changed'}
            </span>
            {#if reportBundleVerification.signature_key_id}
              <span>{reportBundleVerification.signature_algorithm ?? 'signature'} {reportBundleVerification.signature_key_id}</span>
            {/if}
            <span>{reportBundleVerification.checked_at}</span>
          </div>
        {/if}
        <section class="approval-panel">
          <h3>{$t('tab.approvals')}</h3>
          <div class="approval-form">
            <select bind:value={approvalTargetKind} disabled={busy}>
              <option value="report_bundle">report_bundle</option>
              <option value="custody_manifest">custody_manifest</option>
              <option value="case_report">case_report</option>
              <option value="evidence">evidence</option>
            </select>
            <select bind:value={approvalStatus} disabled={busy}>
              <option value="approved">approved</option>
              <option value="pending">pending</option>
              <option value="rejected">rejected</option>
              <option value="revoked">revoked</option>
            </select>
            <input placeholder="/path/to/artifact" bind:value={approvalTargetPath} disabled={busy} />
            <input placeholder="target id" bind:value={approvalTargetId} disabled={busy} />
            <input placeholder="approver" bind:value={approvalApprover} disabled={busy} />
            <input placeholder="role" bind:value={approvalRole} disabled={busy} />
            <input class="wide-field" placeholder="comment" bind:value={approvalComment} disabled={busy} />
            <button disabled={busy || (!approvalTargetPath.trim() && !approvalTargetId.trim())} on:click={() => run(saveCaseApproval)}>
              {$t('approval.record')}
            </button>
          </div>
        </section>
        <div class="paged-table-scroll" on:scroll={(event) => handlePagedScroll(event, 'evidence_verification')}>
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Artifact</th>
                <th>Status</th>
                <th>Integrity</th>
                <th>Size</th>
                <th>Events</th>
                <th>SHA256</th>
                <th>Object Ref</th>
              </tr>
            </thead>
            <tbody>
              {#each files as file}
                {@const verification = verificationForFile(file.file_id)}
                <tr>
                  <td>{file.normalized_path}</td>
                  <td>{file.artifact_type}</td>
                  <td><span class={statusClass(file.parser_status)}>{file.parser_status}</span></td>
                  <td>
                    {#if verification}
                      <span class={statusClass(verification.verified ? 'verified' : 'failed')}>
                        {verification.verified ? 'ok' : 'failed'}
                      </span>
                      {#if verification.error_message}
                        <br /><span class="subtle">{verification.error_message}</span>
                      {/if}
                    {:else}
                      <span class="subtle">{$t('ledger.unverified')}</span>
                    {/if}
                  </td>
                  <td>{formatBytes(file.size)}</td>
                  <td>{file.event_count}</td>
                  <td class="mono">{file.sha256}</td>
                  <td class="mono">{file.object_ref}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    {:else if activeTab === 'files'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.files')}</h2>
        </div>
        <section class="case-admin-panel">
          <div class="case-admin-grid">
            <label>
              <span>{$t('files.case_root')}</span>
              <input aria-label="Case root" bind:value={caseRoot} />
            </label>
            <label>
              <span>{$t('files.case_name')}</span>
              <input aria-label="Case name" bind:value={caseName} />
            </label>
            <button disabled={busy || !caseRoot.trim() || !caseName.trim()} on:click={createCurrentCase}>{$t('common.create')}</button>
            <button disabled={busy || !caseRoot.trim()} on:click={openCurrentCase}>{$t('common.open')}</button>
            <button class="danger-button" disabled={busy || !summary} on:click={clearCurrentCaseWorkspace}>
              {$t('common.clear')}
            </button>
          </div>
	        </section>
	        <section class="case-admin-panel">
	          <div class="panel-heading">
	            <h2>{$t('files.case_info')}</h2>
	            <button disabled={busy || !summary} on:click={() => run(saveCaseCustodyProfile)}>{$t('common.save')}</button>
	          </div>
	          <dl class="meta-grid">
	            <dt>ID</dt><dd>{summary?.case_id ?? '-'}</dd>
	            <dt>Root</dt><dd class="mono">{summary?.root_path ?? caseRoot}</dd>
	            <dt>Schema</dt><dd>{summary?.schema_version ?? '-'}</dd>
	            <dt>Created</dt><dd>{formatTimestamp(summary?.created_at)}</dd>
	          </dl>
	          <div class="custody-form">
	            <label><span>Investigator</span><input bind:value={custodyInvestigator} placeholder="analyst name" disabled={busy || !summary} /></label>
	            <label><span>Custodian</span><input bind:value={custodyCustodian} placeholder="custodian" disabled={busy || !summary} /></label>
	            <label><span>Organization</span><input bind:value={custodyOrganization} placeholder="organization" disabled={busy || !summary} /></label>
	            <label><span>Evidence Source</span><input bind:value={custodyEvidenceSource} placeholder="host / image / source" disabled={busy || !summary} /></label>
	            <label><span>Acquisition Method</span><input bind:value={custodyAcquisitionMethod} placeholder="KAPE / triage zip" disabled={busy || !summary} /></label>
	            <label><span>Acquired UTC</span><input type="datetime-local" bind:value={custodyAcquiredAt} disabled={busy || !summary} /></label>
	            <label><span>Legal Authority</span><input bind:value={custodyLegalAuthority} placeholder="ticket / warrant" disabled={busy || !summary} /></label>
	            <label class="wide-field"><span>Chain Note</span><textarea bind:value={custodyChainNote} placeholder="handoff, storage, validation notes" disabled={busy || !summary}></textarea></label>
	          </div>
	          {#if custodyProfile}
	            <div class="review-strip">
	              <span>updated {formatTimestamp(custodyProfile.updated_at)}</span>
	              <span>{custodyProfile.investigator ?? 'no investigator'}</span>
	              <span>{custodyProfile.custodian ?? 'no custodian'}</span>
	            </div>
	          {/if}
	        </section>
	        <section class="file-intake-panel">
	          <button class="link-button" type="button" on:click={() => (advancedIntakeOpen = !advancedIntakeOpen)}>
	            {advancedIntakeOpen ? $t('files.advanced_hide') : $t('files.advanced_show')}
          </button>
          {#if advancedIntakeOpen}
            <div class="file-intake-grid">
              <label>
                <span>{$t('files.virtual_path')}</span>
                <input aria-label="Artifact path" bind:value={artifactPath} />
              </label>
              <label class="wide-field">
                <span>{$t('files.virtual_text')}</span>
                <textarea aria-label="Artifact content" bind:value={artifactContent}></textarea>
              </label>
              <button disabled={busy || !summary} on:click={ingestSample}>{$t('files.demo_ingest')}</button>
              <label class="wide-field">
                <span>{$t('files.manual_localpath')}</span>
                <input aria-label="Local path ingest" placeholder="/path/to/triage-or-file" bind:value={localPathInput} />
              </label>
              <button disabled={busy || !summary || !localPathInput.trim()} on:click={ingestLocalPathInput}>
                {$t('files.path_ingest')}
              </button>
	            </div>
	          {/if}
	        </section>
	        <section class="intake-status-panel" aria-label={$t('intake.status')}>
	          <div class="intake-status-header">
	            <h3>{$t('intake.status')}</h3>
	            <span>
	              {intakeActive
	                ? `${intakeCompleted.toLocaleString()} / ${Math.max(intakeTotal, 0).toLocaleString()}`
	                : `${$t('intake.final_total')}: ${intakeStatusSummary.total.toLocaleString()} files / ${intakeStatusSummary.events.toLocaleString()} events`}
	            </span>
	          </div>
	          <div class="intake-meter" aria-label="Intake progress">
	            <span style={`width: ${intakeBarFilePercent}%`}></span>
	          </div>
	          {#if intakeActive && intakeCurrentPath}
	            <div class="intake-current">
	              <span>{$t('intake.processing')}</span>
	              <strong title={intakeCurrentPath}>{intakeCurrentPath}</strong>
	              <em>{formatBytes(intakeCurrentSize)}</em>
	            </div>
	          {/if}
	          <div class="intake-status-strip">
	            <span><em>Files</em><strong>{intakeStatusSummary.total.toLocaleString()}</strong></span>
	            <span><em>Parsed</em><strong>{intakeStatusSummary.parsed.toLocaleString()}</strong></span>
	            <span><em>Pending</em><strong>{intakeStatusSummary.pending.toLocaleString()}</strong></span>
	            <span><em>Failed</em><strong>{intakeStatusSummary.failed.toLocaleString()}</strong></span>
	            <span><em>Unsupported</em><strong>{intakeStatusSummary.unsupported.toLocaleString()}</strong></span>
	            <span><em>Events</em><strong>{intakeStatusSummary.events.toLocaleString()}</strong></span>
	            <span><em>Loaded bytes</em><strong>{formatBytes(intakeStatusSummary.bytes)}</strong></span>
	          </div>
	          <div class="intake-status-grid">
	            <div class="intake-status-section">
	              <div class="intake-section-heading">
	                <strong>{$t('intake.coverage_by_artifact')}</strong>
	                <span>{coverage.length.toLocaleString()} types</span>
	              </div>
	              <div class="intake-coverage-list">
	                {#if intakeCoverageRows.length === 0}
	                  <div class="empty-state compact">{$t('intake.no_coverage')}</div>
	                {:else}
	                  {#each intakeCoverageRows as row}
	                    <div class="intake-coverage-row">
	                      <span title={row.artifact_type}>{artifactTypeLabel(row.artifact_type)}</span>
	                      <div class="intake-row-meter">
	                        <span style={`width: ${coverageParsedPercent(row)}%`}></span>
	                      </div>
	                      <em>{row.parsed_files.toLocaleString()} / {row.total_files.toLocaleString()}</em>
	                      <strong>{row.event_count.toLocaleString()}</strong>
	                    </div>
	                  {/each}
	                {/if}
	              </div>
	            </div>
	            <div class="intake-status-section">
	              <div class="intake-section-heading">
	                <strong>{$t('intake.running_jobs')}</strong>
	                <span>{activeIntakeJobs.length.toLocaleString()} active</span>
	              </div>
	              <div class="intake-job-list">
	                {#if activeIntakeJobs.length === 0}
	                  <div class="empty-state compact">{$t('intake.no_running_jobs')}</div>
	                {:else}
	                  {#each activeIntakeJobs as job}
	                    <div class="intake-job-row">
	                      <span>{job.kind}</span>
	                      <strong class={statusClass(job.status)}>{job.status}</strong>
	                      <em>{Math.round(job.progress * 100)}%</em>
	                    </div>
	                  {/each}
	                {/if}
	              </div>
	            </div>
	            <div class="intake-status-section recent-files">
	              <div class="intake-section-heading">
	                <strong>{$t('intake.recent_files')}</strong>
	                <span>{recentFileRows.length.toLocaleString()} shown</span>
	              </div>
	              <div class="intake-file-list">
	                {#if recentFileRows.length === 0}
	                  <div class="empty-state compact">{$t('intake.no_files')}</div>
	                {:else}
	                  {#each recentFileRows as file}
	                    <div class="intake-file-row">
	                      <span title={file.normalized_path}>{file.normalized_path}</span>
	                      <em>{file.artifact_type}</em>
	                      <strong class={statusClass(file.parser_status)}>{file.parser_status}</strong>
	                      <b>{file.event_count.toLocaleString()}</b>
	                    </div>
	                  {/each}
	                {/if}
	              </div>
	            </div>
	          </div>
	        </section>
	        <table>
	          <thead>
	            <tr>
              <th>Path</th>
              <th>Type</th>
              <th>Status</th>
              <th>Events</th>
              <th>SHA256</th>
            </tr>
          </thead>
          <tbody>
            {#each files as file}
              <tr>
                <td>{file.normalized_path}</td>
                <td>{file.artifact_type}</td>
                <td><span class={statusClass(file.parser_status)}>{file.parser_status}</span></td>
                <td>{file.event_count}</td>
                <td class="mono">{file.sha256}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if activeTab === 'coverage'}
      <div class="split">
        <div class="panel">
          <h2>Coverage</h2>
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Total</th>
                <th>Parsed</th>
                <th>Failed</th>
                <th>Unsupported</th>
                <th>Events</th>
              </tr>
            </thead>
            <tbody>
              {#each coverage as row}
                <tr>
                  <td>{row.artifact_type}</td>
                  <td>{row.total_files}</td>
                  <td>{row.parsed_files}</td>
                  <td>{row.failed_files}</td>
                  <td>{row.unsupported_files}</td>
                  <td>{row.event_count}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="panel">
          <h2>Parser Failures</h2>
          <table>
            <thead>
              <tr>
                <th>Parser</th>
                <th>Type</th>
                <th>Count</th>
                <th>Last Error</th>
              </tr>
            </thead>
            <tbody>
              {#each failedParsers as row}
                <tr>
                  <td>{row.parser_name}</td>
                  <td>{row.artifact_type}</td>
                  <td>{row.failure_count}</td>
                  <td>{row.last_error}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    {:else if activeTab === 'timeline'}
      <div class="panel timeline-panel">
        <div class="panel-heading">
          <h2>{$t('tab.timeline')}</h2>
          <div class="toolbar compact-toolbar timeline-bucket-toolbar">
            <button class:active={timelineView === 'chart'} on:click={() => setTimelineView('chart')}>{$t('timeline.chart')}</button>
            <button class:active={timelineView === 'heatmap'} on:click={() => setTimelineView('heatmap')}>{$t('timeline.heatmap')}</button>
            <span class="tl-sep"></span>
            <button class:active={timelineGranularity === 'minute'} on:click={() => setTimelineGranularity('minute')}>{$t('timeline.minute')}</button>
            <button class:active={timelineGranularity === 'hour'} on:click={() => setTimelineGranularity('hour')}>{$t('timeline.hour')}</button>
            <button class:active={timelineGranularity === 'day'} on:click={() => setTimelineGranularity('day')}>{$t('timeline.day')}</button>
            <button class:active={timelineGranularity === 'week'} on:click={() => setTimelineGranularity('week')}>{$t('timeline.week')}</button>
            <span class="tl-sep"></span>
            <button class:active={timelineMarkersOn} title={$t('timeline.markers.tip')} on:click={() => (timelineMarkersOn = !timelineMarkersOn)}>{$t('timeline.markers')}</button>
          </div>
        </div>
        <div class="timeline-filter-bar">
          <label>
            <span>Severity</span>
            <select bind:value={timelineSevFilter} on:change={() => run(applyTimelineFilters)}>
              <option value="">{$t('common.all')}</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
          </label>
          <label>
            <span>{$t('common.host')}</span>
            <input placeholder={$t('common.partial')} bind:value={timelineHostFilter} on:keydown={(event) => { if (event.key === 'Enter') run(applyTimelineFilters); }} />
          </label>
          <label>
            <span>{$t('common.user')}</span>
            <input placeholder={$t('common.partial')} bind:value={timelineUserFilter} on:keydown={(event) => { if (event.key === 'Enter') run(applyTimelineFilters); }} />
          </label>
          <label class="tl-filter-wide">
            <span>{$t('common.fulltext')}</span>
            <input placeholder={$t('timeline.search.placeholder')} bind:value={timelineSearchText} on:keydown={(event) => { if (event.key === 'Enter') run(applyTimelineFilters); }} />
          </label>
          <label class="regex-toggle artifact-regex-toggle" title={$t('filter.regex_fulltext')}>
            <input type="checkbox" bind:checked={timelineSearchRegex} />
            <span>.*</span>
          </label>
          <button class="search-apply-button" disabled={busy} on:click={() => run(applyTimelineFilters)}>{$t('common.apply')}</button>
          <button disabled={busy || !hasTimelineFilters()} on:click={() => run(clearTimelineFilters)}>{$t('common.reset')}</button>
        </div>

        {#if timelineView === 'chart' && (timelineBinsTruncated || timelineAggregated)}
          <div class="timeline-hint">
            {#if timelineBinsTruncated}{$t('timeline.hint.cap_pre')} {TIMELINE_BIN_CAP.toLocaleString()} {$t('timeline.hint.cap_post')}{/if}{#if timelineAggregated}{timelineBins.length.toLocaleString()} {$t('timeline.hint.agg_a')} {timelineRenderColumns.length} {$t('timeline.hint.agg_b')}{Math.ceil(timelineBins.length / timelineRenderColumns.length)}{$t('timeline.hint.agg_c')}{/if}
          </div>
        {/if}

        {#if timelineView === 'heatmap'}
          {#if timelineHeatmapBins.length > 0}
            <div class="timeline-heatmap">
              <div class="thm-grid">
                <div class="thm-corner"></div>
                {#each Array.from({ length: 24 }) as _, h}
                  <div class="thm-hlabel">{h % 3 === 0 ? h : ''}</div>
                {/each}
                {#each timelineDowLabels as dname, d}
                  <div class="thm-dlabel">{dname}</div>
                  {#each timelineHeatmapGrid[d] as count, h}
                    <div class="thm-cell" style={`background:${heatmapCellColor(count, timelineHeatmapMax)}`} title={`${dname}${$t('timeline.dow_suffix')} ${h}:00 (UTC) / ${count.toLocaleString()} events`}></div>
                  {/each}
                {/each}
              </div>
              <div class="thm-legend subtle">{$t('timeline.heatmap.legend_a')} {timelineHeatmapMax.toLocaleString()}{$t('timeline.heatmap.legend_b')}</div>
            </div>
          {:else}
            <div class="empty-state">{hasTimelineFilters() ? $t('empty.no_match_events') : $t('empty.timeline_heatmap')}</div>
          {/if}
        {:else if timelineBins.length > 0}
          <div class="overview-timeline-chart timeline-chart">
            <svg viewBox="0 0 960 220" preserveAspectRatio="none" role="img" aria-label={$t('tab.timeline')}>
              <g class="overview-grid-lines">
                <line x1="24" y1="18" x2="936" y2="18"></line>
                <line x1="24" y1="75" x2="936" y2="75"></line>
                <line x1="24" y1="132" x2="936" y2="132"></line>
                <line x1="24" y1="188" x2="936" y2="188"></line>
              </g>
              {#each timelineRenderColumns as bin, index}
                {#each timelineStackSegments(bin, maxRenderColumn) as seg}
                  <rect
                    class={`overview-column severity-fill-${seg.sev}`}
                    class:selected={timelineSelectedBin?.startUtc === bin.bin_start_utc}
                    x={overviewColumnX(index, timelineRenderColumns.length)}
                    y={seg.y}
                    width={overviewColumnWidth(timelineRenderColumns.length)}
                    height={seg.height}
                  ></rect>
                {/each}
                <rect
                  class="overview-hitbar"
                  x={overviewColumnX(index, timelineRenderColumns.length)}
                  y="18"
                  width={912 / Math.max(1, timelineRenderColumns.length)}
                  height="170"
                  tabindex="0"
                  role="button"
                  aria-label={`${bin.bin_start_utc} ${bin.total} events`}
                  on:click={() => run(() => selectTimelineBin(bin))}
                  on:keydown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') run(() => selectTimelineBin(bin));
                  }}
                >
                  <title>{formatTimestamp(bin.bin_start_utc)}{bin.binCount > 1 ? ` 〜 (${bin.binCount}${$t('timeline.bins_suffix')})` : ''} / {$t('chart.total')} {bin.total.toLocaleString()}{bin.critical > 0 ? ` / critical ${bin.critical}` : ''}{bin.high > 0 ? ` / high ${bin.high}` : ''}{bin.medium > 0 ? ` / medium ${bin.medium}` : ''}</title>
                </rect>
              {/each}
              {#if timelineMarkersOn}
                {#each timelineFindingGlyphs as g}
                  <path class="tl-mark-finding" d={`M ${g.x - 3} 7 L ${g.x + 3} 7 L ${g.x} 3 Z`}><title>{$t('mark.detection')}{g.count > 1 ? ` ×${g.count}` : ''}: {g.label}</title></path>
                {/each}
                {#each timelineIocGlyphs as g}
                  <path class="tl-mark-ioc" d={`M ${g.x} 8 L ${g.x + 2.5} 10 L ${g.x} 12 L ${g.x - 2.5} 10 Z`}><title>IOC{g.count > 1 ? ` ×${g.count}` : ''}: {g.label}</title></path>
                {/each}
                {#each timelineBookmarkGlyphs as g}
                  <circle class="tl-mark-bookmark" cx={g.x} cy="15" r="1.8"><title>Bookmark{g.count > 1 ? ` ×${g.count}` : ''}: {g.label}</title></circle>
                {/each}
              {/if}
            </svg>
            <div class="overview-chart-axis">
              <span>{formatTimestamp(timelineRenderColumns[0]?.bin_start_utc ?? '')}</span>
              <strong>{maxRenderColumn.toLocaleString()} max</strong>
              <span>{formatTimestamp(timelineRenderColumns[timelineRenderColumns.length - 1]?.bin_start_utc ?? '')}</span>
            </div>
            {#if timelineMarkersOn && (timelineFindingMarks.length || timelineIocMarks.length || timelineBookmarkMarks.length)}
              <div class="tl-marker-legend">
                <span class="tl-lg-finding">▲ {$t('mark.detection')} {timelineFindingMarks.length.toLocaleString()}</span>
                <span class="tl-lg-ioc">◆ IOC {timelineIocMarks.length.toLocaleString()}</span>
                <span class="tl-lg-bookmark">● Bookmark {timelineBookmarkMarks.length.toLocaleString()}</span>
              </div>
            {/if}
          </div>
          <div class="timeline-events-head">
            {#if timelineSelectedBin}
              <strong>{timelineSelectedBin.label}</strong>
              {#if timelineSelectedBinData}
                <span class="tl-sev-chips">
                  {#each [...TIMELINE_STACK_ORDER].reverse() as sev}
                    {#if timelineSelectedBinData[sev] > 0}
                      <span class={`tl-sev-chip ${severityClass(sev)}`}>{sev} {timelineSelectedBinData[sev].toLocaleString()}</span>
                    {/if}
                  {/each}
                </span>
              {/if}
              <span class="tl-head-actions">
                <button class="tl-mini-btn" disabled={busy} on:click={() => run(() => exportTimelineWindow('csv'))}>⇩ CSV</button>
                <button class="tl-mini-btn" disabled={busy} on:click={() => run(() => exportTimelineWindow('jsonl'))}>⇩ JSONL</button>
                <button class="tl-mini-btn" disabled={busy} on:click={() => run(pivotTimelineToEvents)}>{$t('timeline.open_all_events')}</button>
              </span>
            {:else}
              <span class="subtle">{$t('timeline.bar_hint')}</span>
            {/if}
          </div>
          {#if timelineSelectedBin}
            <div class="paged-table-scroll timeline-events-scroll" on:scroll={(event) => handlePagedScroll(event, 'timeline_events')}>
              <table>
                <thead>
                  <tr>
                    <th>Time (UTC)</th>
                    <th>Severity</th>
                    <th>EventID</th>
                    <th>Type</th>
                    <th>Host</th>
                    <th>User</th>
                    <th>Subject</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {#each timelineEventRows as row (row.event_id)}
                    <tr
                      class="clickable"
                      class:selected-row={selectedEvent?.event_id === row.event_id}
                      on:click={() => selectEvent(row)}
                    >
                      <td>{formatTimestamp(row.event_time_utc)}</td>
                      <td><span class={severityClass(row.severity)}>{row.severity}</span></td>
                      <td class="mono">{row.event_code ?? '-'}</td>
                      <td>{row.artifact_type}</td>
                      <td>{displayText(row.host, '-')}</td>
                      <td>{displayText(row.user_name, '-')}</td>
                      <td>{eventSubject(row)}</td>
                      <td>{displayText(row.message_short, '')}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
              {#if timelineEventRows.length === 0}
                <div class="empty-state">{$t('empty.no_events_window')}</div>
              {/if}
            </div>
          {/if}
        {:else}
          <div class="empty-state">{hasTimelineFilters() ? $t('empty.no_match_events') : $t('empty.timeline')}</div>
        {/if}
      </div>
    {:else if activeTab === 'events'}
        <div class="panel event-panel">
          <div class="panel-heading">
            <h2>Events</h2>
            <div class="toolbar compact-toolbar">
              {#if eventSubtab === 'all'}
                <div class="export-menu-wrap">
                  <button
                    class="export-button"
                    title={$t('events.export.tip')}
                    aria-label={$t('events.export')}
                    disabled={busy || !summary}
                    on:click={() => (exportMenuOpen = !exportMenuOpen)}
                  >
                    ⇩ {$t('events.download')}
                  </button>
                  {#if exportMenuOpen}
                    <div class="export-menu" role="menu">
                      <button role="menuitem" on:click={() => run(() => chooseExportFormat('csv'))}>CSV</button>
                      <button role="menuitem" on:click={() => run(() => chooseExportFormat('jsonl'))}>JSONL</button>
                    </div>
                  {/if}
                </div>
              {/if}
            </div>
          </div>
          {#if eventSubtab === 'all'}
          <div class="event-tools taotie-search">
            <label class="event-id-filter">
              <span>{$t('events.eventid_comma')}</span>
              <input
                aria-label="Event ID filter"
                placeholder="4624,4688"
                bind:value={eventIdFilter}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="compact-search-filter">
              <span>{$t('common.user')}</span>
              <input
                aria-label="User filter"
                placeholder={$t('common.partial')}
                bind:value={eventUserFilter}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="compact-search-filter">
              <span>IP</span>
              <input
                aria-label="IP filter"
                placeholder={$t('common.partial')}
                bind:value={eventIpFilter}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="compact-search-filter">
              <span>{$t('events.computer')}</span>
              <input
                aria-label="Computer filter"
                placeholder={$t('common.partial')}
                bind:value={eventHostFilter}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="time-search-filter">
              <span>{$t('common.start_utc')}</span>
              <input
                aria-label="Start UTC filter"
                placeholder="YYYY/MM/DD HH:mm:ss"
                bind:value={eventStartUtc}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="time-search-filter">
              <span>{$t('common.end_utc')}</span>
              <input
                aria-label="End UTC filter"
                placeholder="YYYY/MM/DD HH:mm:ss"
                bind:value={eventEndUtc}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="fulltext-filter">
              <span>{$t('common.fulltext')}</span>
              <input
                aria-label="Full text event search"
                placeholder='powershell -enc / ext:asp / word:asp / "move.aspx" / hash:...'
                bind:value={eventSearchText}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="regex-toggle" title={$t('filter.regex_fulltext')}>
              <input type="checkbox" bind:checked={eventSearchRegex} />
              <span>.*</span>
            </label>
	            <label class="artifact-search-filter">
	              <span>{$t('events.artifact')}</span>
	              <select aria-label="Artifact filter" bind:value={eventArtifactFilter}>
	                <option value="">{$t('common.all')}</option>
	                {#each eventArtifactOptions as row}
	                  <option value={row.artifactType}>{artifactTypeLabel(row.artifactType)}</option>
	                {/each}
	              </select>
	            </label>
	            <label class="facet-kind-filter">
	              <span>{$t('events.facet_field')}</span>
	              <select
	                aria-label="Facet field"
	                bind:value={eventFacetField}
	                on:change={changeEventFacetField}
	              >
	                <option value="">{$t('events.select_candidate')}</option>
	                {#each eventFacetGroups as group}
	                  <option value={group.field}>{group.label}</option>
	                {/each}
	              </select>
	            </label>
	            <label class="facet-value-filter">
	              <span>{$t('events.facet_value')}</span>
	              <select
	                aria-label="Facet value"
	                bind:value={eventFacetValue}
	                disabled={!eventFacetField || selectedEventFacetValues.length === 0}
	                on:change={() => run(applySelectedEventFacet)}
	              >
	                <option value="">{$t('events.select_value')}</option>
	                {#each selectedEventFacetValues as facet}
	                  <option value={facet.value}>{facet.value} ({facet.count})</option>
	                {/each}
	              </select>
	            </label>
	            <button class="search-apply-button" disabled={busy} on:click={() => run(applyEventSearch)}>{$t('common.apply')}</button>
	            <button class="search-reset-button" disabled={busy || !hasEventFilters()} on:click={() => run(clearEventFilters)}>{$t('common.reset')}</button>
	          </div>
          {#if hasEventFilters()}
            <div class="active-filter-strip">
              {#if eventIdFilter}<span>eid={eventIdFilter}</span>{/if}
              {#if eventUserFilter}<span>user={eventUserFilter}</span>{/if}
              {#if eventIpFilter}<span>ip={eventIpFilter}</span>{/if}
              {#if eventHostFilter}<span>host={eventHostFilter}</span>{/if}
              {#if eventStartUtc}<span>start={eventStartUtc}</span>{/if}
              {#if eventEndUtc}<span>end={eventEndUtc}</span>{/if}
              {#if appliedEventSearch}<span>search={appliedEventSearch}</span>{/if}
              {#if eventArtifactFilter}<span>type={eventArtifactFilter}</span>{/if}
            </div>
          {/if}
          <div class="event-header-viewport">
            <div class="event-header" style={eventHeaderGridStyle}>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('event_time_utc'))}>
                  Time (UTC){sortMark('event_time_utc')}
                </button>
                <button
                  class="column-resizer"
                  type="button"
                  aria-label="Time column width"
                  on:pointerdown={(event) => startEventColumnResize(0, event)}
                ></button>
              </div>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('event_code'))}>
                  EventID{sortMark('event_code')}
                </button>
                <button
                  class="column-resizer"
                  type="button"
                  aria-label="EventID column width"
                  on:pointerdown={(event) => startEventColumnResize(1, event)}
                ></button>
              </div>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('severity'))}>
                  Severity{sortMark('severity')}
                </button>
                <button
                  class="column-resizer"
                  type="button"
                  aria-label="Severity column width"
                  on:pointerdown={(event) => startEventColumnResize(2, event)}
                ></button>
              </div>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('artifact_type'))}>
                  Type{sortMark('artifact_type')}
                </button>
                <button
                  class="column-resizer"
                  type="button"
                  aria-label="Type column width"
                  on:pointerdown={(event) => startEventColumnResize(3, event)}
                ></button>
              </div>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('host'))}>
                  Host{sortMark('host')}
                </button>
                <button
                  class="column-resizer"
                  type="button"
                  aria-label="Host column width"
                  on:pointerdown={(event) => startEventColumnResize(4, event)}
                ></button>
              </div>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('user_name'))}>
                  User{sortMark('user_name')}
                </button>
                <button
                  class="column-resizer"
                  type="button"
                  aria-label="User column width"
                  on:pointerdown={(event) => startEventColumnResize(5, event)}
                ></button>
              </div>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('process_name'))}>
                  Process{sortMark('process_name')}
                </button>
                <button
                  class="column-resizer"
                  type="button"
                  aria-label="Process column width"
                  on:pointerdown={(event) => startEventColumnResize(6, event)}
                ></button>
              </div>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('command_line'))}>
                  Command{sortMark('command_line')}
                </button>
                <button
                  class="column-resizer"
                  type="button"
                  aria-label="Command column width"
                  on:pointerdown={(event) => startEventColumnResize(7, event)}
                ></button>
              </div>
              <div class="event-header-cell">
                <button class="event-sort-button" on:click={() => run(() => setEventSort('message_short'))}>
                  Message{sortMark('message_short')}
                </button>
              </div>
            </div>
          </div>
          <div
            class="virtual-table"
            bind:this={eventScroller}
            bind:clientHeight={eventViewportPx}
            on:scroll={(event) => {
              eventScrollTop = event.currentTarget.scrollTop;
              eventHorizontalScroll = event.currentTarget.scrollLeft;
              handlePagedScroll(event, 'events');
            }}
          >
            <div class="event-table-canvas" style={eventTableCanvasStyle}>
              <div style={`height: ${topPad}px`}></div>
              {#each visibleEventRows as row, index (row.event_id)}
                <button
                  type="button"
                  class="event-row"
                  class:row-even={(visibleStart + index) % 2 === 0}
                  class:row-odd={(visibleStart + index) % 2 === 1}
                  class:selected={selectedEvent?.event_id === row.event_id}
                  class:in-trail={Boolean(investigationColor(row.event_id))}
                  style={`${eventGridColumnsStyle} ${investigationRowStyle(row.event_id)}`}
                  on:click={() => selectEvent(row)}
                >
                  <span class="event-time-cell time-cell" title={formatTimestamp(row.event_time_utc)}>{formatTimestamp(row.event_time_utc)}</span>
                  <span class="event-id-cell mono" title={displayText(row.event_code, '-')}>{displayText(row.event_code, '-')}</span>
                  <span class={`event-severity-cell ${severityClass(row.severity)}`} title={displayText(row.severity, '-')}>{displayText(row.severity, '-')}</span>
                  <span class="event-type-cell" title={displayText(row.artifact_type, '-')}>{displayText(row.artifact_type, '-')}</span>
                  <span class="event-host-cell" title={displayText(row.host, '-')}>{displayText(row.host, '-')}</span>
                  <span class="event-user-cell" title={displayText(row.user_name, '-')}>{displayText(row.user_name, '-')}</span>
                  <span class="event-subject-cell" title={eventSubject(row)}>{eventSubject(row)}</span>
                  <span class="event-command-cell mono" title={commandDisplay(row.command_line)}>{commandDisplay(row.command_line)}</span>
                  <span class="event-message-cell" title={displayText(row.message_short, '')}>{displayText(row.message_short, '')}</span>
                </button>
              {/each}
              <div style={`height: ${bottomPad}px`}></div>
            </div>
          </div>
          {:else}
            <div class="event-user-layout">
              <section class="subpanel">
                <div class="panel-heading">
                  <h3>{$t('users.list')}</h3>
                </div>
                <div class="paged-table-scroll user-list-scroll">
                <table class="user-list-table">
                  <thead>
                    <tr>
                      <th><button class="table-sort" on:click={() => setUserSort('user_name')}>User{userSortMark('user_name')}</button></th>
                      <th><button class="table-sort" on:click={() => setUserSort('event_count')}>Events{userSortMark('event_count')}</button></th>
                      <th><button class="table-sort" on:click={() => setUserSort('host_count')}>Hosts{userSortMark('host_count')}</button></th>
                      <th><button class="table-sort" on:click={() => setUserSort('severity_max')}>{$t('users.max_risk')}{userSortMark('severity_max')}</button></th>
                      <th><button class="table-sort" on:click={() => setUserSort('first_seen_utc')}>{$t('users.first_utc')}{userSortMark('first_seen_utc')}</button></th>
                      <th><button class="table-sort" on:click={() => setUserSort('last_seen_utc')}>{$t('users.last_utc')}{userSortMark('last_seen_utc')}</button></th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each userView as user (user.user_name)}
                      <tr
                        class="clickable sev-row-{user.severity_max ?? 'info'}"
                        class:selected-row={selectedUser?.user_name === user.user_name}
                        on:click={() => run(() => selectUser(user))}
                      >
                        <td class="mono" title={user.user_name}>{user.user_name}</td>
                        <td class="num">
                          <span class="ucount">
                            <span class="utrack"><span class="ufill" style={`width:${(user.event_count / maxUserEvents) * 100}%`}></span></span>
                            <span class="un">{user.event_count.toLocaleString()}</span>
                          </span>
                        </td>
                        <td class="num">{user.host_count}</td>
                        <td><span class={severityClass(user.severity_max ?? 'info')}>{user.severity_max ?? 'info'}</span></td>
                        <td class="mono nowrap">{formatTimestamp(user.first_seen_utc)}</td>
                        <td class="mono nowrap">{formatTimestamp(user.last_seen_utc)}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
                </div>
              </section>
              <section class="subpanel">
                <div class="panel-heading">
                  <h3>{selectedUser ? ($locale === 'en' ? `${selectedUser.user_name}'s events` : `${selectedUser.user_name} のイベント`) : $t('users.user_events')}</h3>
                </div>
                <div class="paged-table-scroll" on:scroll={(event) => handlePagedScroll(event, 'user_events')}>
                  <table>
                    <thead>
                      <tr>
                        <th><button class="table-sort" on:click={() => run(() => setEventSort('event_time_utc'))}>Time (UTC){sortMark('event_time_utc')}</button></th>
                        <th><button class="table-sort" on:click={() => run(() => setEventSort('severity'))}>Severity{sortMark('severity')}</button></th>
                        <th><button class="table-sort" on:click={() => run(() => setEventSort('artifact_type'))}>Type{sortMark('artifact_type')}</button></th>
                        <th><button class="table-sort" on:click={() => run(() => setEventSort('host'))}>Host{sortMark('host')}</button></th>
                        <th><button class="table-sort" on:click={() => run(() => setEventSort('message_short'))}>Message{sortMark('message_short')}</button></th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each userEventRows as row}
                        <tr
                          class="clickable sev-row-{row.severity}"
                          class:selected-row={selectedEvent?.event_id === row.event_id}
                          on:click={() => selectEvent(row)}
                        >
                          <td>{formatTimestamp(row.event_time_utc)}</td>
                          <td><span class={severityClass(row.severity)}>{row.severity}</span></td>
                          <td>{row.artifact_type}</td>
                          <td>{row.host ?? '-'}</td>
                          <td>{displayText(row.message_short, '')}</td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
                {#if users.length === 0}
                  <div class="empty-state">{$t('empty.user_events')}</div>
                {/if}
              </section>
            </div>
          {/if}
        </div>
    {:else if activeTab === 'saved_searches'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.saved_searches')}</h2>
          <div class="toolbar compact-toolbar">
            <input aria-label="Saved search viewer" placeholder={$t('saved.viewer')} bind:value={savedSearchViewer} />
            <button disabled={busy} on:click={() => setTab('events')}>{$t('saved.to_events')}</button>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Query</th>
              <th>Owner</th>
              <th>Visibility</th>
              <th>Shared</th>
              <th>Updated</th>
              <th>Description</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {#each savedSearches as row}
              <tr>
                <td>{row.name}</td>
                <td class="mono">{formatSavedSearchQuery(row.query)}</td>
                <td>{row.created_by ?? '-'}</td>
                <td>{row.visibility}</td>
                <td>{formatSavedSearchSharedWith(row)}</td>
                <td>{formatTimestamp(row.updated_at)}</td>
                <td>{row.description ?? ''}</td>
                <td>
                  <div class="toolbar compact-toolbar">
                    <button class="search-apply-button" disabled={busy} on:click={() => run(() => applySavedSearch(row))}>{$t('common.apply')}</button>
                    <button disabled={busy || !canManageSavedSearch(row)} on:click={() => run(() => removeSavedSearch(row))}>
                      {$t('common.delete')}
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if savedSearches.length === 0}
          <div class="empty-state">{$t('empty.saved_searches')}</div>
        {/if}
      </div>
    {:else if activeTab === 'search_index'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.search')}</h2>
          <div class="toolbar compact-toolbar">
            <button disabled={busy || !summary || !!activeSearchIndexJob} on:click={() => run(startSearchIndexRebuild)}>
              {$t('search.start_build_job')}
            </button>
          </div>
        </div>
        <div class="review-summary-strip">
          {#if searchIndexMetadata}
            <span>Version <strong>{searchIndexMetadata.index_version}</strong></span>
            <span>Events <strong>{searchIndexMetadata.indexed_event_count.toLocaleString()}</strong></span>
            <span>Updated <strong>{formatTimestamp(searchIndexMetadata.updated_at)}</strong></span>
            {#if searchIndexMetadata.build_mode}
              <span>Mode <strong>{searchIndexMetadata.build_mode}</strong></span>
            {/if}
            {#if searchIndexMetadata.appended_event_count != null}
              <span>Delta <strong>+{searchIndexMetadata.appended_event_count.toLocaleString()}</strong></span>
            {/if}
            {#if searchIndexMetadata.updated_event_count != null}
              <span>Changed <strong>{searchIndexMetadata.updated_event_count.toLocaleString()}</strong></span>
            {/if}
            {#if searchIndexMetadata.deleted_event_count != null}
              <span>Deleted <strong>{searchIndexMetadata.deleted_event_count.toLocaleString()}</strong></span>
            {/if}
          {:else}
            <span>Index <strong>{$t('search.not_built')}</strong></span>
          {/if}
          {#if searchIndexStatus}
            <span>Current <strong>{searchIndexStatus.current_event_count.toLocaleString()}</strong></span>
            <span>Status <strong>{searchIndexStatus.is_stale ? 'stale' : 'fresh'}</strong></span>
          {/if}
          {#if activeSearchIndexJob}
            <span>
              Job
              <strong>{activeSearchIndexJob.status} {(activeSearchIndexJob.progress * 100).toFixed(0)}%</strong>
            </span>
          {/if}
        </div>
        <div class="indexed-search-strip">
          <input
            aria-label="Indexed full text search"
            placeholder="powershell OR merlin / process_name:powershell / message:&quot;EncodedCommand&quot;"
            bind:value={indexedSearchText}
            on:keydown={(event) => {
              if (event.key === 'Enter') run(() => runIndexedSearch(true));
            }}
          />
          <button class="search-apply-button" disabled={busy} on:click={() => run(() => runIndexedSearch(true))}>
            {$t('common.search')}
          </button>
        </div>
        {#if indexedSearchNotice}
          <div class="indexed-search-notice">
            <span>{indexedSearchNotice}</span>
            {#if !activeSearchIndexJob}
              <button
                on:click={() =>
                  run(async () => {
                    await startSearchIndexBuild(caseRoot);
                    await loadSearchIndexMetadata();
                  })}
              >{$t('search.build_index')}</button>
            {/if}
          </div>
        {/if}
        <div class="paged-table-scroll" on:scroll={(event) => handlePagedScroll(event, 'indexed_search')}>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Score</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Subject</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {#each indexedSearchHits as hit}
                <tr class="clickable" on:click={() => run(() => openSearchHit(hit))}>
                  <td>{formatTimestamp(hit.event_time_utc)}</td>
                  <td class="mono">{hit.score_basis}</td>
                  <td>{hit.artifact_type}</td>
                  <td><span class={severityClass(hit.severity)}>{hit.severity}</span></td>
                  <td>{hit.process_name ?? hit.file_path ?? hit.user_name ?? hit.host ?? '-'}</td>
                  <td>{hit.message_short}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if indexedSearchHits.length === 0}
          <div class="empty-state">{$t('empty.search_results')}</div>
        {/if}
      </div>
    {:else if activeArtifactView}
      <div class="artifact-layout">
        {#if activeTab === 'artifact_prefetch'}
          <div class="panel">
            <div class="panel-heading">
              <h2>{$t('prefetch.analysis')}</h2>
            </div>
            <table class="prefetch-summary-table">
              <thead>
                <tr>
                  <th>Process</th>
                  <th>Severity</th>
                  <th>Run</th>
                  <th>Refs</th>
                  <th>PF Hash</th>
                  <th>Events</th>
                  <th>Last</th>
                  <th>Suspicion</th>
                </tr>
              </thead>
              <tbody>
                {#each prefetchSummaries as row}
                  <tr
                    class="clickable"
                    class:selected-row={selectedPrefetchSummary?.process_name === row.process_name}
                    on:click={() => run(() => selectPrefetchSummary(row))}
                  >
                    <td>
                      <span class="mono">{displayText(row.process_name, '-')}</span><br />
                      <span class="subtle">{displayText(row.prefetch_file_name ?? row.file_path, '')}</span>
                    </td>
                    <td><span class={severityClass(row.severity_max ?? 'info')}>{row.severity_max ?? 'info'}</span></td>
                    <td>{row.run_count_max ?? '-'}</td>
                    <td>{row.referenced_file_count_max ?? '-'}</td>
                    <td class="mono">{row.prefetch_hash ?? '-'}</td>
                    <td>{row.event_count}</td>
                    <td>{formatTimestamp(row.last_seen_utc)}</td>
                    <td>{displayText(row.suspicion ?? row.sample_message, '-')}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
            {#if prefetchSummaries.length === 0}
              <div class="empty-state">No Prefetch summary</div>
            {/if}
          </div>
        {/if}
        <div class="panel">
          <div class="panel-heading">
            <h2>{activeArtifactView.label}</h2>
            <div class="toolbar compact-toolbar">
              <div class="export-menu-wrap">
                <button
                  class="icon-button"
                  title="Export"
                  aria-label="Export"
                  disabled={busy || !summary}
                  on:click={() => (exportMenuOpen = !exportMenuOpen)}
                >
                  ⇩
                </button>
                {#if exportMenuOpen}
                  <div class="export-menu" role="menu">
                    <button role="menuitem" on:click={() => run(() => chooseExportFormat('csv'))}>CSV</button>
                    <button role="menuitem" on:click={() => run(() => chooseExportFormat('jsonl'))}>JSONL</button>
                  </div>
                {/if}
              </div>
            </div>
          </div>
          <div class="artifact-filter-bar">
            <label>
              <span>{$t('common.start_utc')}</span>
              <input
                aria-label="Artifact start UTC filter"
                placeholder="YYYY/MM/DD HH:mm:ss"
                bind:value={eventStartUtc}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label>
              <span>{$t('common.end_utc')}</span>
              <input
                aria-label="Artifact end UTC filter"
                placeholder="YYYY/MM/DD HH:mm:ss"
                bind:value={eventEndUtc}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label>
              <span>{$t('common.host')}</span>
              <input
                aria-label="Artifact host filter"
                placeholder={$t('common.partial')}
                bind:value={eventHostFilter}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label>
              <span>{$t('common.user')}</span>
              <input
                aria-label="Artifact user filter"
                placeholder={$t('common.partial')}
                bind:value={eventUserFilter}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="artifact-filter-wide">
              <span>{$t('common.fulltext')}</span>
              <input
                aria-label="Artifact free text search"
                placeholder='path/hash/ip/url/action/command: ext:asp, word:asp, "move.aspx", hash:..., ip:...'
                bind:value={eventSearchText}
                on:keydown={(event) => {
                  if (event.key === 'Enter') run(applyEventSearch);
                }}
              />
            </label>
            <label class="regex-toggle artifact-regex-toggle" title={$t('filter.regex_fulltext')}>
              <input type="checkbox" bind:checked={eventSearchRegex} />
              <span>.*</span>
            </label>
            <label>
              <span>{$t('common.severity')}</span>
              <select aria-label="Artifact severity filter" bind:value={artifactSeverityFilter}>
                <option value="">{$t('common.all')}</option>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
                <option value="info">info</option>
              </select>
            </label>
            <label class="artifact-filter-wide">
              <span>{$t('artifact.preset')}</span>
              <select aria-label="Artifact quick filter" bind:value={artifactQuickFilter}>
                <option value="">{$t('common.none')}</option>
                {#each activeArtifactQuickFilters as filter}
                  <option value={filter.id}>{filter.label}</option>
                {/each}
              </select>
            </label>
            <label class="artifact-check">
              <input type="checkbox" bind:checked={artifactFindingOnly} />
              <span>{$t('artifact.finding_only')}</span>
            </label>
            <label class="artifact-check">
              <input type="checkbox" bind:checked={artifactHighOnly} />
              <span>{$t('artifact.high_plus')}</span>
            </label>
            <button class="search-apply-button" disabled={busy} on:click={() => run(applyEventSearch)}>{$t('common.apply')}</button>
            <button disabled={busy || !hasArtifactFilters()} on:click={() => run(clearArtifactFilters)}>{$t('common.reset')}</button>
          </div>
          {#if hasArtifactFilters()}
            <div class="active-filter-strip artifact-active-filters">
              {#if eventStartUtc}<span>start={eventStartUtc}</span>{/if}
              {#if eventEndUtc}<span>end={eventEndUtc}</span>{/if}
              {#if eventHostFilter}<span>host={eventHostFilter}</span>{/if}
              {#if eventUserFilter}<span>user={eventUserFilter}</span>{/if}
              {#if appliedEventSearch}<span>search={appliedEventSearch}</span>{/if}
              {#if artifactSeverityFilter}<span>severity={artifactSeverityFilter}</span>{/if}
              {#if artifactFindingOnly}<span>finding=true</span>{/if}
              {#if artifactHighOnly}<span>severity=high+</span>{/if}
              {#if selectedArtifactQuickFilter()}<span>preset={selectedArtifactQuickFilter()?.label}</span>{/if}
            </div>
          {/if}
          <div class="artifact-summary-strip">
            <span>{$t('artifact.loaded')} <strong>{activeArtifactStats.loaded}</strong></span>
            <span>Finding <strong>{activeArtifactStats.findings}</strong></span>
            <span>High+ <strong>{activeArtifactStats.highPriority}</strong></span>
            <span>Host <strong>{activeArtifactStats.hosts}</strong></span>
            <span>User <strong>{activeArtifactStats.users}</strong></span>
            {#if nextArtifactEventCursor}
              <span>{$t('artifact.more_hidden')}</span>
            {/if}
          </div>
          <div
            class="artifact-table-scroll"
            bind:this={artifactScroller}
            on:scroll={(event) => {
              artifactScrollTop = event.currentTarget.scrollTop;
              handlePagedScroll(event, 'artifact_events');
            }}
          >
            <table class="artifact-table" style={`--artifact-table-width: ${activeArtifactTableWidth}px;`}>
              <colgroup>
                {#each activeArtifactColumns as column, index}
                  <col style={`width: ${artifactColumnWidth(index, column)}px`} />
                {/each}
              </colgroup>
              <thead>
                <tr>
                  {#each activeArtifactColumns as column, index}
                    <th class={column.className ?? ''}>
                      {#if column.sortBy}
                        <button class="table-sort" on:click={() => run(() => setEventSort(column.sortBy as EventSortBy))}>
                          {column.label}{sortMark(column.sortBy)}
                        </button>
                      {:else}
                        {column.label}
                      {/if}
                      <button
                        class="column-resizer table-column-resizer"
                        type="button"
                        aria-label={`${column.label} column width`}
                        on:pointerdown={(event) => startArtifactColumnResize(index, column, event)}
                      ></button>
                    </th>
                  {/each}
                </tr>
              </thead>
              <tbody>
                {#if artifactTopPad > 0}
                  <tr class="virtual-spacer" style={`height: ${artifactTopPad}px`}>
                    <td colspan={activeArtifactColumns.length}></td>
                  </tr>
                {/if}
                {#each visibleArtifactRows as row (row.event_id)}
                  <tr class="clickable" class:selected-row={selectedEvent?.event_id === row.event_id} on:click={() => selectEvent(row)}>
                    {#each activeArtifactColumns as column}
                      <td class={column.className ?? ''}>
                        {#if column.kind === 'severity'}
                          <span class={severityClass(column.value(row) ?? 'info')}>{displayText(column.value(row), '-')}</span>
                        {:else}
                          {displayText(column.value(row), '-')}
                        {/if}
                      </td>
                    {/each}
                  </tr>
                {/each}
                {#if artifactBottomPad > 0}
                  <tr class="virtual-spacer" style={`height: ${artifactBottomPad}px`}>
                    <td colspan={activeArtifactColumns.length}></td>
                  </tr>
                {/if}
              </tbody>
            </table>
          </div>
          {#if artifactEventRows.length === 0}
            <div class="empty-state">{activeArtifactEmptyMessage()}</div>
          {/if}
        </div>
      </div>
    {:else if activeTab === 'findings'}
      <div class="finding-layout">
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('tab.findings')}</h2>
          </div>
          {#if findingReviewSummary}
            <div class="review-summary-strip">
              <span>Open <strong>{findingReviewSummary.open_count}</strong></span>
              <span>Confirmed <strong>{findingReviewSummary.confirmed_count}</strong></span>
              <span>FP <strong>{findingReviewSummary.false_positive_count}</strong></span>
              <span>Overdue <strong>{findingReviewSummary.overdue_count}</strong></span>
              <span>Unassigned <strong>{findingReviewSummary.unassigned_count}</strong></span>
              <span>Tagged <strong>{findingReviewSummary.tagged_count}</strong></span>
            </div>
          {/if}
          <div class="finding-buckets">
            <div class="bucket-head bk-rule">
              <span class="bk-label">{$t('tab.findings')}</span>
              <span class="subtle">{$t('findings.rule_detect')} · {ruleFindings.length} {$t('common.groups_suffix')}</span>
            </div>
            {#each findingsBySeverity(ruleFindings) as [sev, group] (sev)}
              <div class="sev-section-head"><span class={severityClass(sev)}>{sev}</span> <span class="subtle">{group.length}</span></div>
              {#each group as f (`${f.severity}|${f.title}|${f.engine}|${f.rule_id ?? ''}`)}
                <button
                  type="button"
                  class="finding-card sev-card-{f.severity}"
                  class:selected-row={sameFinding(f, selectedFinding)}
                  on:click={() => run(() => selectFinding(f))}
                >
                  <div class="fc-row1">
                    <span class="fc-score score-{findingScoreBand(findingScore(f))}">{findingScore(f)}</span>
                    <span class={`fc-sev ${severityClass(f.severity)}`}>{f.severity}</span>
                    <span class="fc-engine">{f.engine}</span>
                    {#each findingTechniques(f) as t}<span class="fc-atk">{t}</span>{/each}
                    {#if f.finding_count > 1}<span class="fc-count">×{f.finding_count}</span>{/if}
                  </div>
                  <div class="fc-title">{f.title}</div>
                  <div class="fc-meta mono subtle">{formatTimestamp(f.last_seen_utc)} · {$t('findings.events_label')} {f.event_count}</div>
                  {#if f.sample_message}<div class="fc-sample subtle">{f.sample_message}</div>{/if}
                </button>
              {/each}
            {/each}
            {#if ruleFindings.length === 0}<div class="empty-state subtle">{$t('empty.rule_detect')}</div>{/if}

            <div class="bucket-head bk-suggest">
              <span class="bk-label">{$t('findings.suggest')}</span>
              <span class="subtle">{$t('findings.suggest_sub')} · {suggestFindings.length} {$t('common.groups_suffix')}</span>
            </div>
            {#each suggestFindings as f (`${f.severity}|${f.title}|${f.engine}|${f.rule_id ?? ''}`)}
              <button
                type="button"
                class="finding-card sev-card-{f.severity}"
                class:selected-row={sameFinding(f, selectedFinding)}
                on:click={() => run(() => selectFinding(f))}
              >
                <div class="fc-row1">
                  <span class="fc-score score-{findingScoreBand(findingScore(f))}">{findingScore(f)}</span>
                  <span class={`fc-sev ${severityClass(f.severity)}`}>{f.severity}</span>
                  <span class="fc-engine">{f.engine}</span>
                  {#each findingTechniques(f) as t}<span class="fc-atk">{t}</span>{/each}
                  {#if f.finding_count > 1}<span class="fc-count">×{f.finding_count}</span>{/if}
                </div>
                <div class="fc-title">{f.title}</div>
                <div class="fc-meta mono subtle">{formatTimestamp(f.last_seen_utc)} · {$t('findings.events_label')} {f.event_count}</div>
                {#if f.sample_message}<div class="fc-sample subtle">{f.sample_message}</div>{/if}
              </button>
            {/each}
            {#if suggestFindings.length === 0}<div class="empty-state subtle">{$t('empty.suggest')}</div>{/if}
          </div>
        </div>
        <div class="panel">
          <div class="panel-heading">
            <h2>{selectedFinding ? ($locale === 'en' ? `Events for ${selectedFinding.title}` : `${selectedFinding.title} のイベント`) : $t('findings.detect_events')}</h2>
            <div class="toolbar compact-toolbar">
              <select bind:value={reviewStatus} disabled={!selectedFinding || busy}>
                <option value="in_review">in_review</option>
                <option value="confirmed">confirmed</option>
                <option value="false_positive">false_positive</option>
                <option value="benign">benign</option>
                <option value="needs_context">needs_context</option>
                <option value="new">new</option>
              </select>
              <input
                class="compact-input"
                aria-label="Reviewer"
                placeholder="reviewer"
                bind:value={reviewReviewer}
                disabled={!selectedFinding || busy}
              />
              <input
                class="compact-input"
                aria-label="Assignee"
                placeholder="assignee"
                bind:value={reviewAssignee}
                disabled={!selectedFinding || busy}
              />
              <input
                class="compact-input"
                aria-label="Due date"
                type="date"
                bind:value={reviewDueAt}
                disabled={!selectedFinding || busy}
              />
              <input
                class="review-tags-input"
                aria-label="Review tags"
                placeholder="tags"
                bind:value={reviewTags}
                disabled={!selectedFinding || busy}
              />
              <input
                class="review-comment-input"
                aria-label="Review comment"
                placeholder="comment"
                bind:value={reviewComment}
                disabled={!selectedFinding || busy}
              />
              <button disabled={!selectedFinding || busy} on:click={() => run(saveSelectedFindingReview)}>
                {$t('findings.save_review')}
              </button>
              <select bind:value={overrideSeverity} disabled={!selectedFinding || busy}>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
                <option value="info">info</option>
              </select>
              <button disabled={!selectedFinding || busy} on:click={() => run(overrideSelectedFindingSeverity)}>
                {$t('findings.override_sev')}
              </button>
              <button disabled={!selectedFinding || busy} on:click={() => run(suppressSelectedFinding)}>
                {$t('findings.suppress')}
              </button>
            </div>
          </div>
          {#if selectedFindingReview}
            <div class="review-strip">
              <span class={reviewClass(selectedFindingReview.status)}>{selectedFindingReview.status}</span>
              <span>{selectedFindingReview.reviewer ?? '-'}</span>
              <span>{selectedFindingReview.assignee ?? 'unassigned'}</span>
              <span>{selectedFindingReview.due_at ? `due ${formatTimestamp(selectedFindingReview.due_at)}` : 'no due'}</span>
              <span>{reviewTagsText(selectedFindingReview.tags_json) || 'no tags'}</span>
              <span>{formatTimestamp(selectedFindingReview.updated_at)}</span>
              <span>{selectedFindingReview.comment ?? ''}</span>
            </div>
          {/if}
          {#if selectedFinding && hasFindingExplain}
            <div class="finding-explain">
              {#if selectedEnrichment?.description}
                <p class="fe-desc">{selectedEnrichment.description}</p>
              {/if}
              {#if selectedFindingTechniques.length}
                <div class="fe-row">
                  <span class="fe-k">ATT&amp;CK</span>
                  <span class="fe-v">
                    {#each selectedFindingTechniques as t}
                      <span class="fe-atk">{t} {attackName(t)}</span>
                    {/each}
                    {#if selectedEnrichment?.tactics?.length}
                      <span class="fe-tactics">{selectedEnrichment.tactics.join(' / ')}</span>
                    {/if}
                  </span>
                </div>
              {/if}
              {#if selectedEnrichment?.matched?.channel || selectedEnrichment?.matched?.event_ids?.length}
                <div class="fe-row">
                  <span class="fe-k">{$t('finding.detection_logic')}</span>
                  <span class="fe-v mono">
                    {#if selectedEnrichment?.matched?.channel}channel={selectedEnrichment.matched.channel}{/if}
                    {#if selectedEnrichment?.matched?.event_ids?.length} · EventID={selectedEnrichment.matched.event_ids.join(',')}{/if}
                  </span>
                </div>
              {/if}
              {#if selectedEnrichment?.falsepositives?.length}
                <div class="fe-row">
                  <span class="fe-k">{$t('finding.fp_notes')}</span>
                  <span class="fe-v">{selectedEnrichment.falsepositives.join(' / ')}</span>
                </div>
              {/if}
              {#if selectedEnrichment?.references?.length}
                <div class="fe-row">
                  <span class="fe-k">{$t('finding.reference')}</span>
                  <span class="fe-v">
                    {#each selectedEnrichment.references as r}
                      <span class="fe-ref mono">{r}</span>
                    {/each}
                  </span>
                </div>
              {/if}
              {#if selectedAffected.hosts.length || selectedAffected.users.length || selectedAffected.procs.length}
                <div class="fe-row">
                  <span class="fe-k">{$t('finding.affected')}</span>
                  <span class="fe-v">
                    {#each selectedAffected.hosts as h}<span class="fe-ent fe-ent-host mono">host: {h}</span>{/each}
                    {#each selectedAffected.users as u}<span class="fe-ent fe-ent-user mono">user: {u}</span>{/each}
                    {#each selectedAffected.procs as p}<span class="fe-ent fe-ent-proc mono">proc: {p}</span>{/each}
                  </span>
                </div>
              {/if}
              {#if selectedFinding?.first_seen_utc}
                <div class="fe-row">
                  <span class="fe-k">{$t('common.window')}</span>
                  <span class="fe-v mono">
                    {formatTimestamp(selectedFinding.first_seen_utc)}
                    {#if selectedFinding.last_seen_utc && selectedFinding.last_seen_utc !== selectedFinding.first_seen_utc}
                      → {formatTimestamp(selectedFinding.last_seen_utc)}
                    {/if}
                    · {$locale === 'en' ? `${selectedFinding.event_count} total` : `全${selectedFinding.event_count}件`}
                  </span>
                </div>
              {/if}
              {#if selectedNextAction}
                <div class="fe-row">
                  <span class="fe-k">{$t('finding.next_action')}</span>
                  <span class="fe-v">{selectedNextAction}</span>
                </div>
              {/if}
              {#if selectedRelated.length}
                <div class="fe-row">
                  <span class="fe-k">{$t('finding.related')}</span>
                  <span class="fe-v">
                    {#each selectedRelated as g (relatedFindingKey(g))}
                      <button type="button" class="fe-related" on:click={() => run(() => selectFinding(g))}>
                        <span class={`fe-related-sev ${severityClass(g.severity)}`}>{g.severity}</span>
                        {g.title}
                      </button>
                    {/each}
                  </span>
                </div>
              {/if}
              {#if selectedScore}
                <div class="fe-row">
                  <span class="fe-k">{$t('finding.score')}</span>
                  <span class="fe-v mono">
                    {selectedScore.total}
                    <span class="fe-score-detail">(severity {selectedScore.sev} + {$t('finding.score.technique')} {selectedScore.tech} + {$t('finding.score.rarity')} {selectedScore.rarity} + {$t('finding.score.base')} {selectedScore.base})</span>
                    · {$t('common.confidence')} {selectedConfidence}
                  </span>
                </div>
              {/if}
            </div>
          {/if}
          <div class="paged-table-scroll" on:scroll={(event) => handlePagedScroll(event, 'finding_events')}>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>EventID</th>
                  <th>Severity</th>
                  <th>Subject</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {#each findingEventRows as row}
                  <tr class="clickable" class:selected-row={selectedEvent?.event_id === row.event_id} on:click={() => selectEvent(row)}>
                    <td>{formatTimestamp(row.event_time_utc)}</td>
                    <td class="mono">{row.event_code ?? '-'}</td>
                    <td><span class={severityClass(row.severity)}>{row.severity}</span></td>
                    <td>{eventSubject(row)}</td>
                    <td>{displayText(row.message_short, '')}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if findingOverrides.length > 0}
            <div class="subpanel">
              <div class="panel-heading">
                <h3>{$t('finding.suppress_override')}</h3>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Severity</th>
                    <th>Created</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {#each findingOverrides as row}
                    <tr>
                      <td>{row.action}</td>
                      <td>
                        <span class="mono">{row.engine ?? '*'}</span>
                        {row.rule_id ? ` / ${row.rule_id}` : ''}<br />
                        <span class="subtle">{row.title ?? '*'}</span>
                      </td>
                      <td>{row.severity ?? '-'}</td>
                      <td>{formatTimestamp(row.created_at)}</td>
                      <td>
                        <button disabled={busy} on:click={() => run(() => removeOverride(row.override_id))}>
                          {$t('common.remove_mark')}
                        </button>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>
      </div>
    {:else if activeTab === 'ioc'}
      <div class="ioc-layout">
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('tab.ioc')}</h2>
            <button disabled={busy || !summary} on:click={() => run(runIocMatch)}>{$t('ioc.match')}</button>
            <button disabled={busy || !summary || parsedIocs().length === 0} on:click={() => run(publishIocFindings)}>
              {$t('ioc.to_finding')}
            </button>
          </div>
          <div class="ioc-input-wrap">
            <textarea
              class="ioc-input"
              aria-label="IOC list"
              bind:value={iocInput}
              spellcheck="false"
            ></textarea>
            <div class="subtle">{parsedIocs().length} indicators / {iocHits.length} hits</div>
          </div>
          <table>
            <thead>
              <tr>
                <th>IOC</th>
                <th>Kind</th>
                <th>Hits</th>
                <th>Artifacts</th>
                <th>Last</th>
              </tr>
            </thead>
            <tbody>
              {#each iocHits as hit}
                <tr
                  class="clickable"
                  class:selected-row={selectedIoc?.ioc === hit.ioc}
                  on:click={() => run(() => selectIoc(hit))}
                >
                  <td class="mono">{hit.ioc}</td>
                  <td>{hit.match_kind}</td>
                  <td>{hit.hit_count}</td>
                  <td>{hit.artifact_types}</td>
                  <td>{formatTimestamp(hit.last_seen_utc)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="panel">
          <div class="panel-heading">
            <h2>{selectedIoc ? ($locale === 'en' ? `Events for ${selectedIoc.ioc}` : `${selectedIoc.ioc} のイベント`) : $t('ioc.events')}</h2>
          </div>
          {#if selectedIoc}
            <dl class="meta-grid compact-meta">
              <dt>Kind</dt>
              <dd>{selectedIoc.match_kind}</dd>
              <dt>Artifacts</dt>
              <dd>{selectedIoc.artifact_types}</dd>
              <dt>Window</dt>
              <dd>{formatTimeRange(selectedIoc.first_seen_utc, selectedIoc.last_seen_utc)}</dd>
            </dl>
          {/if}
          <div class="paged-table-scroll" on:scroll={(event) => handlePagedScroll(event, 'ioc_events')}>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Artifact</th>
                  <th>EventID</th>
                  <th>Subject</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {#each iocEventRows as row (row.event_id)}
                  <tr
                    class="clickable"
                    class:selected-row={selectedEvent?.event_id === row.event_id}
                    on:click={() => selectEvent(row)}
                  >
                    <td>{formatTimestamp(row.event_time_utc)}</td>
                    <td>{row.artifact_type}</td>
                    <td class="mono">{row.event_code ?? '-'}</td>
                    <td>{eventSubject(row)}</td>
                    <td>{displayText(row.message_short, '')}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    {:else if activeTab === 'defender'}
      <div class="defender-layout">
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('defender.aggregate')}</h2>
          </div>
          <div class="defender-cat-list">
            {#each defenderSummaries as row (row.category)}
              <button
                type="button"
                class="defender-cat {defenderAccent(row.category)}"
                class:selected-row={selectedDefenderCategory?.category === row.category}
                on:click={() => run(() => selectDefenderCategory(row))}
              >
                <div class="dc-top">
                  <span class="dc-name" title={row.category}>{defenderCategoryLabel(row.category)}</span>
                  <span class={`dc-sev ${severityClass(row.severity_max ?? 'info')}`}>{row.severity_max ?? 'info'}</span>
                  <span class="dc-count mono">{row.event_count.toLocaleString()}</span>
                </div>
                <div class="dc-bar"><span style={`width:${(row.event_count / defenderCatMax) * 100}%`}></span></div>
                {#if row.sample_message}<div class="dc-sample subtle" title={row.sample_message}>{row.sample_message}</div>{/if}
              </button>
            {/each}
          </div>
        </div>
        <div class="panel">
          <div class="panel-heading">
            <h2>{selectedDefenderCategory ? ($locale === 'en' ? `Events for ${selectedDefenderCategory.category}` : `${selectedDefenderCategory.category} のイベント`) : $t('defender.events')}</h2>
          </div>
          {#if defenderSources.length}
            <div class="def-src-line">
              <span class="subtle">{$t('defender.source')}:</span>
              {#each defenderSources as s}<span class="def-src-pill">{artifactTypeLabel(s)}</span>{/each}
            </div>
          {/if}
          <div class="paged-table-scroll" on:scroll={(event) => handlePagedScroll(event, 'defender_events')}>
            <table>
              <thead>
                <tr>
                  <th>Time (UTC)</th>
                  <th>Severity</th>
                  <th>EventID</th>
                  <th>{$t('common.type')}</th>
                  <th>Subject</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {#each defenderEventRows as row (row.event_id)}
                  <tr
                    class="clickable"
                    class:selected-row={selectedEvent?.event_id === row.event_id}
                    on:click={() => selectEvent(row)}
                  >
                    <td>{formatTimestamp(row.event_time_utc)}</td>
                    <td><span class={severityClass(row.severity)}>{row.severity}</span></td>
                    <td class="mono">{row.event_code ?? '-'}</td>
                    <td class="nowrap">{defenderEventName(row)}</td>
                    <td>{eventSubject(row)}</td>
                    <td>{displayText(row.message_short, '')}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    {:else if activeTab === 'hex'}
      <div class="hex-layout">
        <div class="panel hex-files">
          <div class="panel-heading"><h2>{$t('hex.files')}</h2></div>
          <div class="paged-table-scroll">
            <table>
              <thead>
                <tr><th>{$t('hex.file')}</th><th>{$t('hex.size')}</th><th>{$t('common.type')}</th></tr>
              </thead>
              <tbody>
                {#each hexFiles as file (file.file_id)}
                  <tr
                    class="clickable"
                    class:selected-row={hexSelectedFile?.file_id === file.file_id}
                    on:click={() => run(() => selectHexFile(file))}
                  >
                    <td class="mono hex-fname" title={file.original_path}>{file.filename}</td>
                    <td class="num mono">{file.size.toLocaleString()}</td>
                    <td>{artifactTypeLabel(file.artifact_type)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
            {#if hexFiles.length === 0}
              <div class="empty-state">{$t('hex.no_files')}</div>
            {/if}
          </div>
        </div>
        <div class="panel hex-view">
          <div class="panel-heading">
            <h2>{hexSelectedFile ? hexSelectedFile.filename : $t('tab.hex')}</h2>
            {#if hexSelectedFile}
              <div class="toolbar compact-toolbar">
                <button disabled={busy || hexOffset === 0} on:click={() => run(hexPrev)}>‹ {$t('hex.prev')}{HEX_PAGE}B</button>
                <span class="mono subtle">offset {hexOffset.toLocaleString()} / {(hexRange?.total_size ?? hexSelectedFile.size).toLocaleString()} bytes</span>
                <button disabled={busy || !hexCanNext()} on:click={() => run(hexNext)}>{$t('hex.next')}{HEX_PAGE}B ›</button>
              </div>
              <div class="toolbar compact-toolbar hex-tools">
                <input
                  class="hex-goto-input"
                  placeholder={$t('hex.goto_placeholder')}
                  bind:value={hexGotoInput}
                  on:keydown={(event) => {
                    if (event.key === 'Enter') run(gotoHexOffset);
                  }}
                />
                <button disabled={busy} on:click={() => run(gotoHexOffset)}>{$t('hex.goto')}</button>
                <input
                  class="hex-search-input"
                  placeholder={$t('hex.search_placeholder')}
                  bind:value={hexSearchInput}
                  on:keydown={(event) => {
                    if (event.key === 'Enter') run(() => searchHexNext(false));
                  }}
                />
                <label class="hex-search-hex" title={$t('hex.search_as_hex')}>
                  <input type="checkbox" bind:checked={hexSearchHex} /> HEX
                </label>
                <button
                  disabled={busy || hexSearchBusy || !hexSearchInput.trim()}
                  on:click={() => run(() => searchHexNext(false))}
                >
                  {$t('common.search')}
                </button>
                <button
                  disabled={busy || hexSearchBusy || !hexSearchInput.trim()}
                  on:click={() => run(() => searchHexNext(true))}
                >
                  {$t('hex.next_match')} ›
                </button>
                {#if hexSearchStatus}<span class="subtle hex-search-status">{hexSearchStatus}</span>{/if}
              </div>
            {/if}
          </div>
          {#if hexError}
            <div class="empty-state">{$t('common.error')}: {hexError}</div>
          {:else if !hexSelectedFile}
            <div class="empty-state">{$t('hex.select_hint')}</div>
          {:else if hexLoading}
            <div class="empty-state">{$t('hex.loading')}</div>
          {:else if hexRange}
            <div class="hex-meta mono subtle">sha256 {hexRange.sha256}{hexRange.truncated ? ` · ${$t('hex.more')}` : ''}</div>
            <pre class="hex-dump">{hexRange.hex_dump}</pre>
          {/if}
        </div>
      </div>
    {:else if activeTab === 'correlation'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.correlation')}</h2>
        </div>
        {#if correlationStatus}
          <div class="table-note">{correlationStatus}</div>
        {/if}
        <table>
          <thead>
            <tr>
              <th>Key</th>
              <th>Artifacts</th>
              <th>Events</th>
              <th>First</th>
              <th>Last</th>
              <th>Severity</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {#each correlations as row}
              <tr>
                <td>
                  <span class="subtle">{row.key_kind}</span><br />
                  <span class="mono">{row.key_value}</span>
                </td>
                <td>{row.artifact_types}</td>
                <td>{row.event_count}</td>
                <td>{formatTimestamp(row.first_seen_utc)}</td>
                <td>{formatTimestamp(row.last_seen_utc)}</td>
                <td><span class={severityClass(row.severity_max ?? 'info')}>{row.severity_max ?? 'info'}</span></td>
                <td>{row.explanation}</td>
              </tr>
              {/each}
            </tbody>
          </table>
          {#if correlations.length === 0 && !correlationStatus}
            <div class="empty-state">{$t('empty.correlation')}</div>
          {/if}
      </div>
    {:else if activeTab === 'chains'}
      <div class="chain-layout">
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('tab.chains')}</h2>
          </div>
          {#if correlationChainsStatus}
            <div class="table-note">{correlationChainsStatus}</div>
          {/if}
          <table>
            <thead>
              <tr>
                <th>Score</th>
                <th>Chain</th>
                <th>Artifacts</th>
                <th>Events</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {#each correlationChains as chain}
                <tr
                  class="clickable"
                  class:selected-row={selectedChain?.key_kind === chain.key_kind && selectedChain?.key_value === chain.key_value}
                  on:click={() => run(() => selectCorrelationChain(chain))}
                >
                  <td>{chain.score}</td>
                  <td>
                    {chain.title}<br />
                    <span class="subtle">{chain.key_kind}</span><br />
                    <span class="mono">{chain.key_value}</span>
                  </td>
                  <td>{chain.artifact_types}</td>
                  <td>{chain.event_count}</td>
                  <td><span class={severityClass(chain.severity)}>{chain.severity}</span></td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if correlationChains.length === 0 && !correlationChainsStatus}
            <div class="empty-state">{$t('empty.chains')}</div>
          {/if}
        </div>
        <div class="panel">
          <div class="panel-heading">
            <h2>{selectedChain ? ($locale === 'en' ? `Evidence events for ${selectedChain.key_value}` : `${selectedChain.key_value} の根拠イベント`) : $t('chains.evidence_events')}</h2>
          </div>
          {#if selectedChain}
            <dl class="meta-grid compact-meta">
              <dt>Title</dt>
              <dd>{selectedChain.title}</dd>
              <dt>Severity</dt>
              <dd>
                <span class={severityClass(selectedChain.severity)}>{selectedChain.severity}</span>
                <span class="subtle">event max: {selectedChain.severity_max ?? 'info'}</span>
              </dd>
              <dt>Reason</dt>
              <dd>{selectedChain.explanation}</dd>
              <dt>Window</dt>
              <dd>{formatTimeRange(selectedChain.first_seen_utc, selectedChain.last_seen_utc)}</dd>
            </dl>
          {/if}
          <div class="paged-table-scroll" on:scroll={(event) => handlePagedScroll(event, 'chain_events')}>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Artifact</th>
                  <th>EventID</th>
                  <th>Subject</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {#each chainEventRows as row}
                  <tr class="clickable" class:selected-row={selectedEvent?.event_id === row.event_id} on:click={() => selectEvent(row)}>
                    <td>{formatTimestamp(row.event_time_utc)}</td>
                    <td>{row.artifact_type}</td>
                    <td class="mono">{row.event_code ?? '-'}</td>
                    <td>{eventSubject(row)}</td>
                    <td>{displayText(row.message_short, '')}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if selectedChain}
            <div class="chain-steps">
              {#each chainSteps(selectedChain.steps_json) as step}
                <div class="chain-step">
                  <span class="mono">{formatTimestamp(step.ts)}</span>
                  <span>{step.artifact ?? '-'}</span>
                  <span>{step.action ?? '-'}</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      </div>
    {:else if activeTab === 'process_tree'}
      <div class="panel process-tree-panel">
        <div class="panel-heading ptree-heading">
          <div>
            <h2>{$t('tab.process_tree')}</h2>
            <span class="subtle">{$t('ptree.sub')}</span>
          </div>
          <div class="ptree-controls">
            <input
              class="ptree-filter"
              type="text"
              placeholder={$t('ptree.filter')}
              bind:value={processTreeFilter}
            />
            <button class="ghost-button" on:click={expandAllProcessNodes}
              >{$t('ptree.expand_all')}</button
            >
            <button class="ghost-button" on:click={collapseAllProcessNodes}
              >{$t('ptree.collapse_all')}</button
            >
            <button
              class="ghost-button"
              class:active={processDangerOnly}
              on:click={() => (processDangerOnly = !processDangerOnly)}
              >{$t('ptree.danger_only')}</button
            >
          </div>
        </div>
        <div class="ptree-summary subtle">
          {processNodes.length}{' '}{$t('ptree.processes')} · {processForest.roots
            .length}{' '}{$t('ptree.roots')} · {processFindingCount}{' '}{$t(
            'ptree.with_finding'
          )}{#if processNodes.length >= 2000} · {$t('ptree.truncated')}{/if}
        </div>
        {#if processNodes.length > 0 && processForest.roots.length === processNodes.length}
          <div class="ptree-banner">{$t('ptree.reingest_hint')}</div>
        {/if}
        {#if processTreeStatus}
          <div class="empty-state">{processTreeStatus}</div>
        {:else if processTreeRows.length === 0}
          <div class="empty-state">{$t('empty.process_tree')}</div>
        {:else}
          <div class="ptree-body-rel">
            <div class="ptree-graph">
              {#each processTreeRows as row (row.node.key)}
                <div class="ptree-row-flex">
                  {#each row.guides as g, i}
                    <span
                      class="pg-cell {i === row.depth - 1
                        ? g
                          ? 'pg-tee'
                          : 'pg-ell'
                        : g
                          ? 'pg-vert'
                          : 'pg-blank'}"
                    ></span>
                  {/each}
                  <div
                    class="ptree-node"
                    class:has-finding={isNotableProcess(row.node)}
                    class:selected={selectedProcessNode?.key === row.node.key}
                    role="button"
                    tabindex="0"
                    on:click={() => activateProcessNode(row.node, row.hasChildren)}
                    on:keydown={(e) =>
                      e.key === 'Enter' && activateProcessNode(row.node, row.hasChildren)}
                  >
                    {#if row.hasChildren}
                      <span class="ptree-toggle"
                        >{processTreeExpanded.has(row.node.key) ? '−' : '+'}</span
                      >
                    {:else}
                      <span class="ptree-toggle ptree-toggle-empty"></span>
                    {/if}
                    {#if isNotableProcess(row.node)}
                      <span
                        class="ptree-dot"
                        style={`background:${severityColor(row.node.severity)}`}
                        title={row.node.severity ?? ''}
                      ></span>
                    {/if}
                    {#if row.node.pid}<span class="ptree-pid">[{row.node.pid}]</span>{/if}
                    <span class="ptree-name">{row.node.name}</span>
                    {#if row.hasChildren}
                      {@const childCount =
                        processForest.children.get(row.node.key)?.length ?? 0}
                      <span class="ptree-count" title={$t('ptree.children')}>{childCount}</span>
                    {/if}
                    {#if row.node.command_line}<span
                        class="ptree-cmd"
                        title={row.node.command_line}>{row.node.command_line}</span
                      >{/if}
                  </div>
                </div>
              {/each}
            </div>
            {#if selectedProcessNode}
              {@const n = selectedProcessNode}
              <aside class="ptree-drawer" style={`width:${processDetailWidth}px`}>
                <button
                  class="ptree-splitter"
                  type="button"
                  aria-label="resize detail pane"
                  on:mousedown={startPtreeResize}
                  on:keydown={(e) => {
                    if (e.key === 'ArrowLeft')
                      processDetailWidth = Math.min(1100, processDetailWidth + 20);
                    else if (e.key === 'ArrowRight')
                      processDetailWidth = Math.max(360, processDetailWidth - 20);
                  }}
                ></button>
                <div class="ptree-drawer-body">
                  <div class="ptree-drawer-head">
                    {#if isNotableProcess(n)}
                      <span
                        class="ptree-dot"
                        style={`background:${severityColor(n.severity)}`}
                      ></span>
                    {/if}
                    <span class="ptree-detail-name">{n.name}</span>
                    {#if n.has_finding && n.severity}
                      <span class="ptree-sev" style={`color:${severityColor(n.severity)}`}
                        >{n.severity}</span
                      >
                    {/if}
                    <button
                      class="ptree-close"
                      aria-label="close"
                      on:click={closeProcessDetail}>✕</button
                    >
                  </div>
                  <div class="ptree-card-grid">
                    <span class="ptree-card-k">{$t('ptree.detail.pid')}</span>
                    <span class="ptree-card-v">{n.pid ?? '—'}</span>
                    <span class="ptree-card-k">{$t('ptree.detail.time')}</span>
                    <span class="ptree-card-v">{n.first_seen_utc ?? '—'}</span>
                    <span class="ptree-card-k">{$t('ptree.detail.cmdline')}</span>
                    <span class="ptree-card-v">
                      {#if n.command_line}
                        <span class="ptree-cmdbox">
                          <pre class="ptree-mono">{n.command_line}</pre>
                          <button
                            class="ptree-copy"
                            title={$t('ptree.copy')}
                            on:click={() => copyProcessValue(n.command_line ?? '', `cmd:${n.key}`)}
                            >{processCopiedKey === `cmd:${n.key}`
                              ? $t('ptree.copied')
                              : '⧉'}</button
                          >
                        </span>
                      {:else}—{/if}
                    </span>
                    <span class="ptree-card-k">{$t('ptree.detail.image')}</span>
                    <span class="ptree-card-v ptree-mono ptree-imgpath">{n.image ?? '—'}</span>
                    <span class="ptree-card-k">GUID</span>
                    <span class="ptree-card-v ptree-mono">{n.guid ?? '—'}</span>
                    <span class="ptree-card-k">SHA256</span>
                    <span class="ptree-card-v ptree-mono ptree-hashval">
                      {processSha256(n)}
                      {#if n.hash}
                        <button
                          class="ptree-copy"
                          title={$t('ptree.copy')}
                          on:click={() => copyProcessValue(processSha256(n), `sha:${n.key}`)}
                          >{processCopiedKey === `sha:${n.key}`
                            ? $t('ptree.copied')
                            : '⧉'}</button
                        >
                      {/if}
                    </span>
                    <span class="ptree-card-k">{$t('ptree.detail.user')}</span>
                    <span class="ptree-card-v">{n.user_name ?? '—'}</span>
                    <span class="ptree-card-k">{$t('ptree.detail.detection')}</span>
                    <span class="ptree-card-v">
                      {#if n.has_finding && n.severity}
                        <span class="ptree-sev" style={`color:${severityColor(n.severity)}`}
                          >{n.severity}</span
                        >
                      {:else}—{/if}
                    </span>
                    {#if n.attack.length}
                      <span class="ptree-card-k">ATT&CK</span>
                      <span class="ptree-card-v">
                        <span class="ptree-attack">
                          {#each n.attack as a}<span class="ptree-atk-chip">{a}</span>{/each}
                        </span>
                      </span>
                    {/if}
                    {#if n.finding_titles.length}
                      <span class="ptree-card-k">{$t('ptree.detail.rules')}</span>
                      <span class="ptree-card-v">
                        <ul class="ptree-rules">
                          {#each n.finding_titles as title}<li>{title}</li>{/each}
                        </ul>
                      </span>
                    {/if}
                    {#if n.parent_key && processForest.byKey.get(n.parent_key)}
                      {@const parent = processForest.byKey.get(n.parent_key)}
                      <span class="ptree-card-k">{$t('ptree.detail.parent')}</span>
                      <span class="ptree-card-v">
                        <button
                          class="ptree-link"
                          on:click={() => parent && (selectedProcessNode = parent)}
                          >{parent?.name}{parent?.pid ? ` [${parent.pid}]` : ''}</button
                        >
                      </span>
                    {/if}
                  </div>
                  {#if processOtherInstances(n).length}
                    {@const others = processOtherInstances(n)}
                    <div class="ptree-others">
                      <div class="ptree-others-head">
                        {$t('ptree.other_instances')} ({others.length})
                      </div>
                      <ul class="ptree-others-list">
                        {#each others.slice(0, 20) as o (o.key)}
                          <li>
                            <button class="ptree-link" on:click={() => (selectedProcessNode = o)}
                              >[{o.pid ?? '?'}]</button
                            >
                            <span class="subtle">{o.first_seen_utc ?? ''}</span>
                          </li>
                        {/each}
                        {#if others.length > 20}
                          <li class="subtle">… +{others.length - 20}</li>
                        {/if}
                      </ul>
                    </div>
                  {/if}
                  {#if n.guid}
                    <div class="ptree-related">
                      <div class="ptree-others-head">
                        {$t('ptree.related_activity')} ({processRelated.length})
                      </div>
                      {#if processRelatedLoading}
                        <span class="subtle">{$t('ptree.related_loading')}</span>
                      {:else if processRelated.length}
                        <div class="ptree-related-counts">
                          {#each ['network', 'file', 'registry', 'other'] as cat}
                            {#if processRelatedCounts[cat]}
                              <span class="ptree-rel-cat cat-{cat}"
                                >{cat} {processRelatedCounts[cat]}</span
                              >
                            {/if}
                          {/each}
                        </div>
                        <ul class="ptree-related-list">
                          {#each processRelated.slice(0, 40) as e (e.event_id)}
                            <li>
                              <span class="ptree-rel-dot cat-{relatedCategory(e)}"></span>
                              <span class="subtle ptree-rel-time">{e.event_time_utc ?? ''}</span>
                              <span class="ptree-rel-action">{e.event_action}</span>
                              {#if e.message}<span class="ptree-rel-msg" title={e.message}
                                  >{e.message}</span
                                >{/if}
                            </li>
                          {/each}
                          {#if processRelated.length > 40}
                            <li class="subtle">… +{processRelated.length - 40}</li>
                          {/if}
                        </ul>
                      {:else}
                        <span class="subtle">{$t('ptree.related_none')}</span>
                      {/if}
                    </div>
                  {/if}
                  <div class="ptree-drawer-actions">
                    <button
                      class="search-apply-button ptree-view-events"
                      on:click={() => drillDownProcessNode(n)}>{$t('ptree.view_events')}</button
                    >
                    {#if n.first_seen_utc}
                      <button class="ghost-button" on:click={() => drillProcessTimeline(n)}
                        >{$t('ptree.timeline_context')}</button
                      >
                    {/if}
                    <button
                      class="ghost-button"
                      on:click={() => copyProcessValue(processAncestryText(n), `chain:${n.key}`)}
                      >{processCopiedKey === `chain:${n.key}`
                        ? $t('ptree.copied')
                        : $t('ptree.copy_chain')}</button
                    >
                  </div>
                </div>
              </aside>
            {/if}
          </div>
        {/if}
      </div>
    {:else if activeTab === 'graph'}
      <div class="graph-layout">
        <div class="panel">
          <div class="panel-heading">
            <h2>Entities</h2>
          </div>
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Entity</th>
                <th>Events</th>
                <th>Last</th>
              </tr>
            </thead>
            <tbody>
              {#each entities as entity}
                <tr
                  class="clickable"
                  class:selected-row={selectedEntity?.entity_id === entity.entity_id}
                  on:click={() => run(() => selectEntity(entity))}
                >
                  <td>{entity.entity_type}</td>
                  <td>
                    {entity.display_name}<br />
                    <span class="subtle mono">{entity.entity_id}</span>
                  </td>
                  <td>{entity.event_count}</td>
                  <td>{formatTimestamp(entity.last_seen_utc)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="panel">
          <div class="panel-heading">
            <h2>{selectedEntity ? ($locale === 'en' ? `Neighborhood of ${selectedEntity.display_name}` : `${selectedEntity.display_name} の近傍`) : 'Subgraph'}</h2>
            <span class="subtle">{subgraph.nodes.length} nodes / {subgraph.edges.length} edges</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Relation</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Evidence</th>
                <th>Last</th>
              </tr>
            </thead>
            <tbody>
              {#each subgraph.edges as edge}
                <tr>
                  <td>{edge.edge_type}</td>
                  <td>{subgraphNodeLabel(edge.src_entity_id)}</td>
                  <td>{subgraphNodeLabel(edge.dst_entity_id)}</td>
                  <td class="mono">{jsonList(edge.evidence_event_ids_json)}</td>
                  <td>{formatTimestamp(edge.last_seen_utc)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    {:else if activeTab === 'risk'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('risk.title')}</h2>
          <span class="subtle">{risks.length} {$t('common.techniques_suffix')} · Critical/High {riskCriticalHigh}</span>
        </div>
        <p class="risk-intro subtle">
          {$t('risk.intro')}
        </p>
        {#if riskStatus}
          <div class="table-note">{riskStatus}</div>
        {/if}
        {#if risks.length > 0}
          <div class="risk-overview">
            <div class="donut-wrap">
              <svg class="donut" viewBox="0 0 120 120" role="img" aria-label={$t('chart.risk_sev_breakdown')}>
                <circle cx="60" cy="60" r={riskDonut.R} fill="none" stroke="#0b1017" stroke-width="16"></circle>
                {#each riskDonut.segs as seg}
                  <circle
                    cx="60" cy="60" r={riskDonut.R} fill="none" stroke={seg.color} stroke-width="16"
                    stroke-dasharray={seg.dash} stroke-dashoffset={seg.offset}
                    transform="rotate(-90 60 60)"
                  ><title>{seg.label} {seg.count} ({seg.pct}%)</title></circle>
                {/each}
                <text x="60" y="57" class="donut-total" text-anchor="middle">{riskDonut.total}</text>
                <text x="60" y="73" class="donut-sub" text-anchor="middle">{$t('common.techniques_suffix')}</text>
              </svg>
              <div class="donut-legend">
                {#each riskDonut.segs as seg}
                  <div class="donut-legend-row">
                    <span class="donut-swatch" style={`background:${seg.color}`}></span>
                    <span class="donut-legend-label">{seg.label}</span>
                    <strong class="mono">{seg.count}</strong>
                  </div>
                {/each}
              </div>
            </div>
          </div>
        {/if}
        <table>
          <thead>
            <tr>
              <th>Technique</th>
              <th>Severity</th>
              <th>Findings</th>
              <th>Events</th>
              <th>First</th>
              <th>Last</th>
            </tr>
          </thead>
          <tbody>
            {#each risks as row}
              <tr class="clickable" title={$t('risk.to_suspicious')} on:click={() => run(() => setTab('findings'))}>
                <td class="mono">{row.technique} <span class="risk-tname">{attackName(row.technique)}</span></td>
                <td><span class={severityClass(row.severity_max ?? 'info')}>{row.severity_max ?? 'info'}</span></td>
                <td>{row.finding_count}</td>
                <td>{row.event_count}</td>
                <td>{formatTimestamp(row.first_seen_utc)}</td>
                <td>{formatTimestamp(row.last_seen_utc)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if risks.length === 0 && !riskStatus}
          <div class="empty-state">{$t('empty.risk')}</div>
        {/if}
      </div>
    {:else if activeTab === 'bookmarks'}
        <div class="panel">
          <div class="panel-heading">
            <h2>{$t('tab.bookmarks')}</h2>
            <div class="toolbar compact-toolbar">
            </div>
          </div>
        <div class="paged-table-scroll bookmarks-scroll" on:scroll={(event) => handlePagedScroll(event, 'bookmark_events')}>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Subject</th>
                <th>Label</th>
                <th>Created</th>
                <th>Message</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each bookmarkEventRows as row}
                {@const bookmark = bookmarkForEvent(row.event_id)}
                <tr class="clickable" on:click={() => selectEvent(row)}>
                  <td>{formatTimestamp(row.event_time_utc)}</td>
                  <td><span class={severityClass(row.severity)}>{row.severity}</span></td>
                  <td>{eventSubject(row)}</td>
                  <td>{bookmark?.label ?? '-'}</td>
                  <td>{formatTimestamp(bookmark?.created_at)}</td>
                  <td>{displayText(row.message_short, '')}</td>
                  <td>
                    {#if bookmark}
                      <button disabled={busy} on:click|stopPropagation={() => run(() => removeBookmarkById(bookmark.bookmark_id))}>
                        {$t('common.remove_mark')}
                      </button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    {:else if activeTab === 'approvals'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.approvals')}</h2>
        </div>
        <div class="approval-form">
          <select bind:value={approvalTargetKind} disabled={busy}>
            <option value="report_bundle">report_bundle</option>
            <option value="custody_manifest">custody_manifest</option>
            <option value="case_report">case_report</option>
            <option value="evidence">evidence</option>
          </select>
          <select bind:value={approvalStatus} disabled={busy}>
            <option value="approved">approved</option>
            <option value="pending">pending</option>
            <option value="rejected">rejected</option>
            <option value="revoked">revoked</option>
          </select>
          <input placeholder="/path/to/artifact" bind:value={approvalTargetPath} disabled={busy} />
          <input placeholder="target id" bind:value={approvalTargetId} disabled={busy} />
          <input placeholder="approver" bind:value={approvalApprover} disabled={busy} />
          <input placeholder="role" bind:value={approvalRole} disabled={busy} />
          <input class="wide-field" placeholder="comment" bind:value={approvalComment} disabled={busy} />
          <button disabled={busy || (!approvalTargetPath.trim() && !approvalTargetId.trim())} on:click={() => run(saveCaseApproval)}>
            {$t('approval.record')}
          </button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Target</th>
              <th>Path/ID</th>
              <th>SHA256</th>
              <th>Approver</th>
              <th>Updated</th>
              <th>Comment</th>
            </tr>
          </thead>
          <tbody>
            {#each caseApprovals as row}
              <tr>
                <td><span class={reviewClass(row.status)}>{row.status}</span></td>
                <td>{row.target_kind}</td>
                <td class="mono">{row.target_path ?? row.target_id ?? '-'}</td>
                <td class="mono">{shortHash(row.target_sha256)}</td>
                <td>{row.approver ?? '-'}{row.role ? ` / ${row.role}` : ''}</td>
                <td>{formatTimestamp(row.updated_at)}</td>
                <td>{row.comment ?? '-'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if caseApprovals.length === 0}
          <div class="empty-state">No approvals</div>
        {/if}
      </div>
    {:else if activeTab === 'audit'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.audit')}</h2>
        </div>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {#each auditLog as row}
              <tr>
                <td>{formatTimestamp(row.occurred_at)}</td>
                <td>{row.actor}</td>
                <td>{row.action}</td>
                <td>
                  <span class="mono">{row.target_kind}</span><br />
                  <span class="subtle mono">{row.target_id ?? '-'}</span>
                </td>
                <td>{row.summary}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if auditLog.length === 0}
          <div class="empty-state">No audit log</div>
        {/if}
      </div>
    {:else if activeTab === 'analyzers'}
      <div class="panel">
        <div class="panel-heading">
          <h2>{$t('tab.analyzers')}</h2>
        </div>
        <table>
          <thead>
            <tr>
              <th>Analyzer</th>
              <th>Status</th>
              <th>Input</th>
              <th>Output</th>
              <th>Started</th>
              <th>Finished</th>
              <th>Version</th>
            </tr>
          </thead>
          <tbody>
            {#each analyzerRuns as row}
              <tr>
                <td>{row.name}<br /><span class="subtle mono">{row.analyzer_id}</span></td>
                <td><span class={statusClass(row.status)}>{row.status}</span></td>
                <td>{row.input_count}</td>
                <td>{row.output_count}</td>
                <td>{formatTimestamp(row.started_at)}</td>
                <td>{formatTimestamp(row.finished_at)}</td>
                <td>{row.version}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if activeTab === 'jobs'}
      <div class="panel">
        <h2>Jobs</h2>
        <table>
          <thead>
            <tr>
              <th>Kind</th>
              <th>Status</th>
              <th>Progress</th>
              <th>Attempts</th>
              <th>Updated</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {#each jobs as job}
              <tr>
                <td>{job.kind}</td>
                <td><span class={statusClass(job.status)}>{job.status}</span></td>
                <td>{Math.round(job.progress * 100)}%</td>
                <td>{job.attempts}/{job.max_attempts}</td>
                <td>{formatTimestamp(job.updated_at)}</td>
                <td>{job.error_message ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if activeTab === 'settings'}
      <div class="panel settings-panel">
        <div class="panel-heading">
          <h2>{$t('settings.title')}</h2>
        </div>
        <div class="settings-grid">
          <div class="settings-row">
            <label class="settings-label" for="settings-language">{$t('settings.language')}</label>
            <select id="settings-language" class="settings-select" bind:value={$locale}>
              {#each LOCALES as loc}
                <option value={loc.code}>{loc.label}</option>
              {/each}
            </select>
            <p class="settings-hint subtle">{$t('settings.language.hint')}</p>
          </div>
          <div class="settings-row">
            <span class="settings-label">{$t('settings.fontsize')}</span>
            <div class="settings-segmented">
              {#each FONT_SCALES as size}
                <button type="button" class:active={$fontScale === size} on:click={() => ($fontScale = size)}>
                  {$t(`settings.size.${size}`)}
                </button>
              {/each}
            </div>
            <p class="settings-hint subtle">{$t('settings.fontsize.hint')}</p>
          </div>
        </div>
        <p class="settings-note subtle">{$t('settings.note')}</p>
      </div>
    {/if}
  </section>
    {#if showDetailPane}
        <div
          class="detail-pane-resize"
          class:resizing={detailPaneResizing}
          role="separator"
          aria-orientation="horizontal"
          aria-label={$t('detail.resize_aria')}
          on:pointerdown={startDetailPaneResize}
        ></div>

        <aside class="panel detail-pane" style={`height: ${detailPaneHeight}px`}>
          <div class="panel-heading">
            <h2>{$t('detail.pane')}</h2>
            <div class="toolbar compact-toolbar">
              {#if detailLoading}<span class="subtle">Loading</span>{/if}
              <button disabled={investigationTrail.length === 0} on:click={clearInvestigationTrail}>Trail Clear</button>
              {#if selectedEventBookmark}
                <button disabled={busy} on:click={() => run(removeSelectedEventBookmark)}>{$t('detail.bookmark_remove')}</button>
              {:else}
                <button disabled={!selectedEvent || busy} on:click={() => run(bookmarkSelectedEvent)}>Bookmark</button>
              {/if}
            </div>
          </div>
          <div class="detail-pane-scroll">
            <div class="detail-pane-body">
          {#if investigationTrail.length > 0}
            <nav class="investigation-trail" aria-label="Investigation breadcrumb">
              {#each investigationTrail as row, index}
                <button
                  class:active={index === investigationIndex}
                  style={investigationRowStyle(row.event_id)}
                  title={displayText(row.message_short, '')}
                  on:click={() => openInvestigationTrail(index)}
                >
                  <span class="trail-step">{index + 1}</span>
                  <strong>{displayText(row.event_code, row.artifact_type)}</strong>
                  <em>{displayText(row.process_name ?? row.file_path ?? row.user_name ?? row.host, formatTimestamp(row.event_time_utc))}</em>
                </button>
              {/each}
            </nav>
          {/if}
          {#if selectedEvent}
            <div class="detail-tabs">
              <button class:active={detailTab === 'summary'} on:click={() => openDetailTab('summary')}>
                Summary
              </button>
              <button class:active={detailTab === 'context'} on:click={() => openDetailTab('context')}>
                Context
              </button>
              <button class:active={detailTab === 'raw'} on:click={() => openDetailTab('raw')}>
                Raw
              </button>
              <button class:active={detailTab === 'evidence'} on:click={() => openDetailTab('evidence')}>
                Evidence
              </button>
            </div>
            {#if detailTab === 'summary'}
              <dl class="meta-grid event-summary-grid">
                <dt>Event</dt>
                <dd class="mono wrap-value">{selectedEvent.event_id}</dd>
                <dt>Time</dt>
                <dd class="wrap-value">
                  {formatTimestamp(selectedEvent.event_time_utc)}
                  <span class="alt-time">{formatTimestampDmy(selectedEvent.event_time_utc)}</span>
                </dd>
                <dt>EventID</dt>
                <dd class="mono wrap-value">{detailEventCode()}</dd>
                <dt>Parser</dt>
                <dd class="wrap-value">{detail?.parser_name ?? selectedEvent.parser_name}</dd>
                <dt>Process</dt>
                <dd class="wrap-value">{displayText(detail?.process_name ?? selectedEvent.process_name, '-')}</dd>
                <dt>File/IP</dt>
                <dd class="wrap-value">{displayText(detail?.file_path ?? detail?.ip ?? selectedEvent.file_path ?? selectedEvent.ip, '-')}</dd>
                <dt>Evidence</dt>
                <dd class="wrap-value">{displayText(detail?.evidence_ref, '-')}</dd>
                <dt>Source File</dt>
                <dd class="mono wrap-value">{detail?.source_file_id ?? selectedEvent.source_file_id}</dd>
                <dt>Message</dt>
                <dd class="wrap-value message-value">{displayText(detail?.message_full ?? selectedEvent?.message_short, '-')}</dd>
              </dl>
              <div class="detail-action-strip">
                <button disabled={!artifactTabForType(selectedEvent.artifact_type) || busy} on:click={() => run(openSelectedArtifactTab)}>
                  Artifact View
                </button>
                <button disabled={detailLoading || busy} on:click={() => run(loadSelectedEventDetailNow)}>
                  {detail ? $t('detail.reload_detail') : $t('detail.load_detail')}
                </button>
                <button disabled={rawLoading || busy} on:click={() => run(openSelectedRaw)}>Raw</button>
                <button disabled={detailLoading || evidenceLoading || busy || (detail !== null && !detail.evidence_ref)} on:click={() => run(openSelectedEvidence)}>
                  Evidence
                </button>
                <button disabled={contextLoading || busy} on:click={() => run(() => openDetailTab('context'))}>
                  Context
                </button>
              </div>
              <div class="detail-action-strip secondary-actions">
                <button disabled={structureLoading} on:click={() => loadSelectedEventStructure()}>
                  {structureLoaded ? $t('detail.reload_structure') : $t('detail.load_structure')}
                </button>
                {#if structureLoading}
                  <span class="subtle">{$t('detail.loading_structure')}</span>
                {:else if detailLoading}
                  <span class="subtle">{$t('detail.loading_detail')}</span>
                {:else if !structureLoaded}
                  <span class="subtle">{$t('detail.lazy_hint')}</span>
                {/if}
              </div>
              {#if activePivotActions.length > 0}
                <div class="pivot-strip">
                  <span>{$t('detail.cross_pivot')}</span>
                  {#each activePivotActions as action}
                    <button
                      title={`${action.field}:${action.value}`}
                      on:click={() => run(() => pivotToEventField(action.field, action.value))}
                    >
                      {action.label}
                    </button>
                  {/each}
                </div>
              {/if}
              {#if activeArtifactDetailFields.length > 0}
                <section class="artifact-detail-fields">
                  <h3>{$t('detail.structure_fields')}</h3>
                  <dl class="meta-grid compact-meta">
                    {#each activeArtifactDetailFields as field}
                      <dt>{field.label}</dt>
                      <dd class={field.className ?? ''}>
                        {#if field.pivot}
                          <button
                            class="inline-pivot"
                            title={`${field.pivot}:${field.value}`}
                            on:click={() => run(() => pivotToEventField(field.pivot as PivotField, field.value))}
                          >
                            {displayText(field.value, '-')}
                          </button>
                        {:else}
                          {displayText(field.value, '-')}
                        {/if}
                      </dd>
                    {/each}
                  </dl>
                </section>
              {/if}
              {#if artifactObjects.length > 0}
                <section class="artifact-detail-fields">
                  <h3>{$t('detail.structure_objects')}</h3>
                  <div class="structure-list">
                    {#each artifactObjects as object}
                      <div class="structure-row">
                        <span>{object.object_kind}</span>
                        <strong title={object.object_key}>{object.display_name}</strong>
                        <em>{Math.round(object.confidence * 100)}%</em>
                      </div>
                    {/each}
                  </div>
                </section>
              {/if}
              {#if evidenceOffsets.length > 0}
                <section class="artifact-detail-fields">
                  <h3>{$t('detail.evidence_offsets')}</h3>
                  <div class="structure-list">
                    {#each evidenceOffsets as offset}
                      <button
                        type="button"
                        class="structure-row structure-action"
                        title={`${offset.object_ref} @ ${offset.offset}`}
                        on:click={() => run(() => openEvidenceOffset(offset))}
                      >
                        <span>{offset.structure_kind}</span>
                        <strong>{offset.label}</strong>
                        <em>{offset.offset} + {offset.length}</em>
                      </button>
                    {/each}
                  </div>
                </section>
              {/if}
            {:else if detailTab === 'context'}
              <div class="context-toolbar">
                <span>{$t('detail.surrounding')}</span>
                <select bind:value={contextWindowMinutes} on:change={() => run(reloadEventContext)}>
                  <option value={5}>±5{$t('detail.min_suffix')}</option>
                  <option value={15}>±15{$t('detail.min_suffix')}</option>
                  <option value={30}>±30{$t('detail.min_suffix')}</option>
                  <option value={60}>±60{$t('detail.min_suffix')}</option>
                </select>
                <label>
                  <input type="checkbox" bind:checked={contextSameHostOnly} on:change={() => run(reloadEventContext)} />
                  {$t('detail.same_host_only')}
                </label>
                <button disabled={contextLoading} on:click={() => run(reloadEventContext)}>{$t('common.reload_short')}</button>
              </div>
              {#if contextLoading}
                <div class="subtle">Loading context</div>
              {:else if eventContext && eventContext.groups.length > 0}
                <div class="context-groups">
                  {#each eventContext.groups as group}
                    <section class="context-group">
                      <div class="context-heading">
                        <strong>{group.label}</strong>
                        <span class="mono">{group.value}</span>
                        <span>{group.rows.length} {$t('common.count_suffix')}</span>
                      </div>
                      <div class="context-list">
                        {#each group.rows as row}
                          <button
                            class="context-row"
                            class:anchor={row.event_id === selectedEvent.event_id}
                            class:in-trail={Boolean(investigationColor(row.event_id))}
                            style={investigationRowStyle(row.event_id)}
                            on:click={() => selectEvent(row)}
                          >
                            <span>{formatTimestamp(row.event_time_utc)}</span>
                            <span class={severityClass(row.severity)}>{row.severity}</span>
                            <span>{displayText(row.artifact_type, '-')}</span>
                            <span>{eventSubject(row)}</span>
                            <span>{displayText(row.message_short, '')}</span>
                          </button>
                        {/each}
                      </div>
                    </section>
                  {/each}
                </div>
              {:else}
                <div class="subtle">No correlated context</div>
              {/if}
            {:else if detailTab === 'evidence'}
              <div class="evidence-toolbar">
                <button disabled={evidenceLoading || evidenceOffset <= 0} on:click={() => run(() => shiftEvidenceRange(-evidenceLength))}>
                  Prev
                </button>
                <input
                  aria-label="Evidence offset"
                  type="number"
                  min="0"
                  bind:value={evidenceOffset}
                />
                <select bind:value={evidenceLength} disabled={evidenceLoading}>
                  <option value={1024}>1 KB</option>
                  <option value={4096}>4 KB</option>
                  <option value={16384}>16 KB</option>
                  <option value={65536}>64 KB</option>
                </select>
                <button disabled={evidenceLoading} on:click={() => run(() => loadEvidenceRange(evidenceOffset))}>
                  Read
                </button>
                <button
                  disabled={evidenceLoading || !evidenceRange?.truncated}
                  on:click={() => run(() => shiftEvidenceRange(evidenceLength))}
                >
                  Next
                </button>
              </div>
              {#if evidenceLoading}
                <div class="subtle">Loading evidence range</div>
              {:else if evidenceRange}
                <dl class="meta-grid compact-meta">
                  <dt>Object</dt>
                  <dd class="mono">{evidenceRange.object_ref}</dd>
                  <dt>Range</dt>
                  <dd>{evidenceRange.offset} + {evidenceRange.length} / {formatBytes(evidenceRange.total_size)}</dd>
                  <dt>SHA256</dt>
                  <dd class="mono">{evidenceRange.sha256}</dd>
                </dl>
                <pre class="hex-dump">{evidenceRange.hex_dump}</pre>
              {:else}
                <div class="subtle">No evidence range</div>
              {/if}
            {:else}
              {#if rawLoading}
                <div class="subtle">Loading raw record</div>
              {:else if rawRecord}
                <pre>{rawRecord.raw_record_json}</pre>
              {:else}
                <div class="subtle">No raw record</div>
              {/if}
            {/if}
          {:else}
            <div class="subtle">No event selected</div>
          {/if}
            </div>
          </div>
        </aside>
    {/if}
  </section>
</main>

{#if intakeOverlayVisible}
  <div
    class="intake-topbar"
    class:complete={intakeCompleteVisible || intakeFinalizePending}
    role="status"
    aria-live="polite"
    aria-busy={intakeCompleteVisible || intakeFinalizePending ? 'false' : 'true'}
  >
    <div
      class="intake-topbar-meter"
      class:indeterminate={intakeBarIndeterminate}
      aria-label="Intake progress"
    >
      <span style={`width: ${intakeBarPercent}%`}></span>
    </div>
    <div class="intake-topbar-label">
      <strong class="intake-topbar-title">{intakeBarTitle}</strong>
      <span class="intake-topbar-status">{intakeBarStatus}</span>
      {#if intakeCurrentPath}
        <span class="intake-topbar-current" title={intakeCurrentPath}>{intakeCurrentPath}</span>
      {/if}
      <strong class="intake-topbar-pct">{intakeBarLabel}</strong>
    </div>
  </div>
{/if}
