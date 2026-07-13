mod parquet_tables;
mod query;

use std::{
    fs,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use taotie_schema::{
    AnalyzerRunSummary, AnswerCandidate, ArtifactObject, CaseManifest, CorrelationChainSummary,
    CoverageSummary, EdgeRecord, EntityRecord, EventFull, EventRow, EvidenceOffset,
    FailedParserSummary, FileRecord, FindingRecord, ParseRun, ParserErrorRecord,
    ParserVersionRecord, RawRecord, SchemaVersionRecord, TimelineBin, UnsupportedFileRecord,
};
use thiserror::Error;
use uuid::Uuid;

pub use query::DuckDbQueryLayer;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
    #[error("arrow error: {0}")]
    Arrow(#[from] arrow_schema::ArrowError),
    #[error("duckdb error: {0}")]
    DuckDb(#[from] duckdb::Error),
    #[error("case manifest not found at {0}")]
    MissingCaseManifest(String),
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),
    #[error("invalid object ref: {0}")]
    InvalidObjectRef(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredObject {
    pub object_ref: String,
    pub sha256: String,
    pub size: i64,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CaseWorkspace {
    root: PathBuf,
    manifest: CaseManifest,
}

impl CaseWorkspace {
    pub fn create(root: impl AsRef<Path>, name: impl Into<String>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let manifest = CaseManifest::new(name);
        let workspace = Self { root, manifest };
        workspace.init_layout()?;
        workspace.write_manifest()?;
        Ok(workspace)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let manifest_path = root.join("meta").join("case.json");
        if !manifest_path.exists() {
            return Err(StorageError::MissingCaseManifest(
                manifest_path.display().to_string(),
            ));
        }
        let manifest = serde_json::from_slice(&fs::read(manifest_path)?)?;
        let workspace = Self { root, manifest };
        workspace.init_layout()?;
        Ok(workspace)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &CaseManifest {
        &self.manifest
    }

    pub fn query_layer(&self) -> DuckDbQueryLayer {
        DuckDbQueryLayer::new(self.root.clone(), self.manifest.clone())
    }

    pub fn raw_object_store(&self) -> RawObjectStore {
        RawObjectStore {
            objects_dir: self.root.join("raw").join("objects"),
        }
    }

    pub fn init_layout(&self) -> Result<()> {
        for dir in [
            self.root.join("raw").join("objects"),
            self.table_dir(TableKind::Files),
            self.table_dir(TableKind::ParseRuns),
            self.table_dir(TableKind::ParserVersions),
            self.table_dir(TableKind::SchemaVersions),
            self.table_dir(TableKind::EventsFull),
            self.table_dir(TableKind::RawRecords),
            self.table_dir(TableKind::ArtifactObjects),
            self.table_dir(TableKind::EvidenceOffsets),
            self.table_dir(TableKind::Entities),
            self.table_dir(TableKind::Edges),
            self.table_dir(TableKind::Findings),
            self.table_dir(TableKind::AnalyzerRuns),
            self.table_dir(TableKind::EventRows),
            self.table_dir(TableKind::TimelineBins),
            self.table_dir(TableKind::CorrelationChains),
            self.table_dir(TableKind::AnswerCandidates),
            self.table_dir(TableKind::CoverageSummary),
            self.table_dir(TableKind::FailedParserSummary),
            self.table_dir(TableKind::ParserErrors),
            self.table_dir(TableKind::UnsupportedFiles),
            self.root.join("indexes").join("tantivy"),
            self.root.join("meta"),
        ] {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    fn write_manifest(&self) -> Result<()> {
        let path = self.root.join("meta").join("case.json");
        fs::write(path, serde_json::to_vec_pretty(&self.manifest)?)?;
        Ok(())
    }

    pub fn jobs_db_path(&self) -> PathBuf {
        self.root.join("meta").join("jobs.sqlite")
    }

    pub fn table_dir(&self, kind: TableKind) -> PathBuf {
        match kind {
            TableKind::Files => self.root.join("inventory").join("files"),
            TableKind::ParseRuns => self.root.join("inventory").join("parse_runs"),
            TableKind::ParserVersions => self.root.join("inventory").join("parser_versions"),
            TableKind::SchemaVersions => self.root.join("inventory").join("schema_versions"),
            TableKind::EventsFull => self.root.join("lake").join("events_full"),
            TableKind::RawRecords => self.root.join("lake").join("raw_records"),
            TableKind::ArtifactObjects => self.root.join("lake").join("artifact_objects"),
            TableKind::EvidenceOffsets => self.root.join("lake").join("evidence_offsets"),
            TableKind::Entities => self.root.join("lake").join("entities"),
            TableKind::Edges => self.root.join("lake").join("edges"),
            TableKind::Findings => self.root.join("lake").join("findings"),
            TableKind::AnalyzerRuns => self.root.join("lake").join("analyzer_runs"),
            TableKind::ParserErrors => self.root.join("lake").join("parser_errors"),
            TableKind::UnsupportedFiles => self.root.join("lake").join("unsupported_files"),
            TableKind::EventRows => self.root.join("read_models").join("event_rows"),
            TableKind::TimelineBins => self.root.join("read_models").join("timeline_bins"),
            TableKind::CorrelationChains => {
                self.root.join("read_models").join("correlation_chains")
            }
            TableKind::AnswerCandidates => self.root.join("read_models").join("answer_candidates"),
            TableKind::CoverageSummary => self.root.join("read_models").join("coverage_summary"),
            TableKind::FailedParserSummary => {
                self.root.join("read_models").join("failed_parser_summary")
            }
        }
    }

    pub fn table_fingerprint(&self, kind: TableKind) -> Result<Option<String>> {
        parquet_dir_fingerprint(&self.table_dir(kind))
    }

    pub fn table_latest_modified_nanos(&self, kind: TableKind) -> Result<Option<u128>> {
        parquet_dir_latest_modified_nanos(&self.table_dir(kind))
    }

    pub fn append_files(&self, rows: &[FileRecord]) -> Result<Option<PathBuf>> {
        parquet_tables::write_files(&self.table_dir(TableKind::Files), rows)
    }

    pub fn append_parse_runs(&self, rows: &[ParseRun]) -> Result<Option<PathBuf>> {
        parquet_tables::write_parse_runs(&self.table_dir(TableKind::ParseRuns), rows)
    }

    pub fn append_parser_versions(&self, rows: &[ParserVersionRecord]) -> Result<Option<PathBuf>> {
        parquet_tables::write_parser_versions(&self.table_dir(TableKind::ParserVersions), rows)
    }

    pub fn append_schema_versions(&self, rows: &[SchemaVersionRecord]) -> Result<Option<PathBuf>> {
        parquet_tables::write_schema_versions(&self.table_dir(TableKind::SchemaVersions), rows)
    }

    pub fn append_events_full(&self, rows: &[EventFull]) -> Result<Option<PathBuf>> {
        parquet_tables::write_events_full(&self.table_dir(TableKind::EventsFull), rows)
    }

    pub fn append_raw_records(&self, rows: &[RawRecord]) -> Result<Option<PathBuf>> {
        parquet_tables::write_raw_records(&self.table_dir(TableKind::RawRecords), rows)
    }

    pub fn append_artifact_objects(&self, rows: &[ArtifactObject]) -> Result<Option<PathBuf>> {
        parquet_tables::write_artifact_objects(&self.table_dir(TableKind::ArtifactObjects), rows)
    }

    pub fn replace_artifact_objects(&self, rows: &[ArtifactObject]) -> Result<Option<PathBuf>> {
        let dir = self.table_dir(TableKind::ArtifactObjects);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        parquet_tables::write_artifact_objects(&dir, rows)
    }

    pub fn append_evidence_offsets(&self, rows: &[EvidenceOffset]) -> Result<Option<PathBuf>> {
        parquet_tables::write_evidence_offsets(&self.table_dir(TableKind::EvidenceOffsets), rows)
    }

    pub fn replace_evidence_offsets(&self, rows: &[EvidenceOffset]) -> Result<Option<PathBuf>> {
        let dir = self.table_dir(TableKind::EvidenceOffsets);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        parquet_tables::write_evidence_offsets(&dir, rows)
    }

    pub fn append_entities(&self, rows: &[EntityRecord]) -> Result<Option<PathBuf>> {
        parquet_tables::write_entities(&self.table_dir(TableKind::Entities), rows)
    }

    pub fn append_edges(&self, rows: &[EdgeRecord]) -> Result<Option<PathBuf>> {
        parquet_tables::write_edges(&self.table_dir(TableKind::Edges), rows)
    }

    pub fn append_findings(&self, rows: &[FindingRecord]) -> Result<Option<PathBuf>> {
        parquet_tables::write_findings(&self.table_dir(TableKind::Findings), rows)
    }

    pub fn replace_findings(&self, rows: &[FindingRecord]) -> Result<Option<PathBuf>> {
        let dir = self.table_dir(TableKind::Findings);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        parquet_tables::write_findings(&dir, rows)
    }

    pub fn append_analyzer_runs(&self, rows: &[AnalyzerRunSummary]) -> Result<Option<PathBuf>> {
        parquet_tables::write_analyzer_runs(&self.table_dir(TableKind::AnalyzerRuns), rows)
    }

    pub fn append_event_rows(&self, rows: &[EventRow]) -> Result<Option<PathBuf>> {
        parquet_tables::write_event_rows(&self.table_dir(TableKind::EventRows), rows)
    }

    pub fn replace_event_rows(&self, rows: &[EventRow]) -> Result<Option<PathBuf>> {
        let dir = self.table_dir(TableKind::EventRows);
        let old_parts = parquet_part_paths(&dir)?;
        fs::create_dir_all(&dir)?;
        let written = parquet_tables::write_event_rows(&dir, rows)?;
        for old_part in old_parts {
            if written.as_ref().is_some_and(|path| path == &old_part) {
                continue;
            }
            if old_part.exists() {
                fs::remove_file(old_part)?;
            }
        }
        Ok(written)
    }

    pub fn append_timeline_bins(&self, rows: &[TimelineBin]) -> Result<Option<PathBuf>> {
        parquet_tables::write_timeline_bins(&self.table_dir(TableKind::TimelineBins), rows)
    }

    pub fn replace_correlation_chains(
        &self,
        rows: &[CorrelationChainSummary],
    ) -> Result<Option<PathBuf>> {
        let dir = self.table_dir(TableKind::CorrelationChains);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        parquet_tables::write_correlation_chains(&dir, rows)
    }

    pub fn replace_answer_candidates(&self, rows: &[AnswerCandidate]) -> Result<Option<PathBuf>> {
        let dir = self.table_dir(TableKind::AnswerCandidates);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        parquet_tables::write_answer_candidates(&dir, rows)
    }

    pub fn append_coverage_summary(&self, rows: &[CoverageSummary]) -> Result<Option<PathBuf>> {
        parquet_tables::write_coverage_summary(&self.table_dir(TableKind::CoverageSummary), rows)
    }

    pub fn append_failed_parser_summary(
        &self,
        rows: &[FailedParserSummary],
    ) -> Result<Option<PathBuf>> {
        parquet_tables::write_failed_parser_summary(
            &self.table_dir(TableKind::FailedParserSummary),
            rows,
        )
    }

    pub fn append_parser_errors(&self, rows: &[ParserErrorRecord]) -> Result<Option<PathBuf>> {
        parquet_tables::write_parser_errors(&self.table_dir(TableKind::ParserErrors), rows)
    }

    pub fn append_unsupported_files(
        &self,
        rows: &[UnsupportedFileRecord],
    ) -> Result<Option<PathBuf>> {
        parquet_tables::write_unsupported_files(&self.table_dir(TableKind::UnsupportedFiles), rows)
    }
}

fn parquet_dir_fingerprint(dir: &Path) -> Result<Option<String>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut parts = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("parquet") {
            continue;
        }
        let metadata = entry.metadata()?;
        let modified = metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = entry.file_name().to_string_lossy().to_string();
        parts.push((name, metadata.len(), modified));
    }
    if parts.is_empty() {
        return Ok(None);
    }
    parts.sort();
    let mut digest = Sha256::new();
    for (name, size, modified) in &parts {
        digest.update(name.as_bytes());
        digest.update(b"\0");
        digest.update(size.to_le_bytes());
        digest.update(modified.to_le_bytes());
        digest.update(b"\0");
    }
    Ok(Some(format!(
        "parquet:{}:{}",
        parts.len(),
        hex::encode(digest.finalize())
    )))
}

fn parquet_dir_latest_modified_nanos(dir: &Path) -> Result<Option<u128>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut latest: Option<u128> = None;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("parquet") {
            continue;
        }
        let modified = entry
            .metadata()?
            .modified()?
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        latest = Some(latest.map_or(modified, |current| current.max(modified)));
    }
    Ok(latest)
}

fn parquet_part_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("parquet") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
pub enum TableKind {
    Files,
    ParseRuns,
    ParserVersions,
    SchemaVersions,
    EventsFull,
    RawRecords,
    ArtifactObjects,
    EvidenceOffsets,
    Entities,
    Edges,
    Findings,
    AnalyzerRuns,
    ParserErrors,
    UnsupportedFiles,
    EventRows,
    TimelineBins,
    CorrelationChains,
    AnswerCandidates,
    CoverageSummary,
    FailedParserSummary,
}

#[derive(Debug, Clone)]
pub struct RawObjectStore {
    objects_dir: PathBuf,
}

impl RawObjectStore {
    pub fn store_bytes(&self, bytes: &[u8]) -> Result<StoredObject> {
        fs::create_dir_all(&self.objects_dir)?;
        let sha256 = hex::encode(Sha256::digest(bytes));
        let shard = &sha256[..2];
        let shard_dir = self.objects_dir.join(shard);
        fs::create_dir_all(&shard_dir)?;
        let path = shard_dir.join(format!("{sha256}.bin"));
        if !path.exists() {
            fs::write(&path, bytes)?;
        }
        Ok(StoredObject {
            object_ref: format!("raw://sha256/{sha256}"),
            sha256,
            size: bytes.len() as i64,
            path,
        })
    }

    pub fn store_file(&self, source_path: impl AsRef<Path>) -> Result<StoredObject> {
        fs::create_dir_all(&self.objects_dir)?;
        let source_path = source_path.as_ref();
        let mut source = File::open(source_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 1024 * 1024];
        let mut size = 0i64;
        let spool_path = self
            .objects_dir
            .join(format!("spool-{}.bin", Uuid::new_v4().simple()));
        let mut spool = File::create(&spool_path)?;
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            spool.write_all(&buffer[..read])?;
            size += read as i64;
        }
        spool.flush()?;

        let sha256 = hex::encode(hasher.finalize());
        let shard = &sha256[..2];
        let shard_dir = self.objects_dir.join(shard);
        fs::create_dir_all(&shard_dir)?;
        let path = shard_dir.join(format!("{sha256}.bin"));
        if path.exists() {
            fs::remove_file(&spool_path)?;
        } else {
            fs::rename(&spool_path, &path)?;
        }
        Ok(StoredObject {
            object_ref: format!("raw://sha256/{sha256}"),
            sha256,
            size,
            path,
        })
    }

    pub fn read_range(
        &self,
        object_ref: &str,
        offset: u64,
        length: usize,
    ) -> Result<(StoredObject, Vec<u8>)> {
        let sha256 = object_ref
            .strip_prefix("raw://sha256/")
            .filter(|value| value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit()))
            .ok_or_else(|| StorageError::InvalidObjectRef(object_ref.to_string()))?;
        let path = self
            .objects_dir
            .join(&sha256[..2])
            .join(format!("{sha256}.bin"));
        let mut file = File::open(&path)?;
        let total_size = file.metadata()?.len();
        let safe_offset = offset.min(total_size);
        file.seek(SeekFrom::Start(safe_offset))?;
        let mut limited = file.take(length as u64);
        let mut bytes = Vec::new();
        limited.read_to_end(&mut bytes)?;
        Ok((
            StoredObject {
                object_ref: object_ref.to_string(),
                sha256: sha256.to_string(),
                size: total_size as i64,
                path,
            },
            bytes,
        ))
    }
}

pub fn part_path(dir: &Path) -> PathBuf {
    dir.join(format!("part-{}.parquet", Uuid::new_v4().simple()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use taotie_schema::{CorrelationChainEventPageQuery, EventPageQuery, FindingEventPageQuery};

    #[test]
    fn creates_case_layout_and_raw_object() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = CaseWorkspace::create(temp.path().join("case"), "demo").unwrap();
        assert!(workspace.root().join("meta/case.json").exists());
        assert!(workspace.table_dir(TableKind::EventRows).exists());

        let object = workspace
            .raw_object_store()
            .store_bytes(b"evidence")
            .unwrap();
        assert_eq!(object.size, 8);
        assert!(object.path.exists());
        assert!(object.object_ref.starts_with("raw://sha256/"));
    }

    #[test]
    fn artifact_object_correlation_chains_are_queryable() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = CaseWorkspace::create(temp.path().join("case"), "demo").unwrap();
        let case_id = workspace.manifest().case_id.clone();
        let key = "lnk_property:system.appusermodel.id:taotie.test.app";

        workspace
            .replace_event_rows(&[
                EventRow {
                    event_id: "event_lnk_1".to_string(),
                    case_id: case_id.clone(),
                    event_time_utc: "2026-01-01T00:00:00Z".to_string(),
                    artifact_type: "lnk".to_string(),
                    host: Some("host1".to_string()),
                    user_name: Some("alice".to_string()),
                    process_name: Some("evil.exe".to_string()),
                    file_path: Some("C:\\Temp\\evil.lnk".to_string()),
                    ip: None,
                    url: None,
                    hash: None,
                    event_code: None,
                    channel: None,
                    level: None,
                    event_action: "lnk_file_import_observed".to_string(),
                    severity: "medium".to_string(),
                    message_short: "lnk".to_string(),
                    source_file_id: "file_lnk_1".to_string(),
                    parser_name: "taotie_core_lnk".to_string(),
                    has_finding: false,
                    command_line: None,
                },
                EventRow {
                    event_id: "event_lnk_2".to_string(),
                    case_id: case_id.clone(),
                    event_time_utc: "2026-01-01T00:01:00Z".to_string(),
                    artifact_type: "lnk".to_string(),
                    host: Some("host1".to_string()),
                    user_name: Some("alice".to_string()),
                    process_name: Some("evil.exe".to_string()),
                    file_path: Some("C:\\Users\\alice\\Recent\\evil.lnk".to_string()),
                    ip: None,
                    url: None,
                    hash: None,
                    event_code: None,
                    channel: None,
                    level: None,
                    event_action: "lnk_file_import_observed".to_string(),
                    severity: "medium".to_string(),
                    message_short: "lnk".to_string(),
                    source_file_id: "file_lnk_2".to_string(),
                    parser_name: "taotie_core_lnk".to_string(),
                    has_finding: false,
                    command_line: None,
                },
            ])
            .unwrap();
        workspace
            .append_artifact_objects(&[
                ArtifactObject {
                    object_id: "obj_1".to_string(),
                    case_id: case_id.clone(),
                    event_id: "event_lnk_1".to_string(),
                    source_file_id: "file_lnk_1".to_string(),
                    parse_run_id: "parse_1".to_string(),
                    artifact_type: "lnk".to_string(),
                    object_kind: "lnk_property_value".to_string(),
                    object_key: key.to_string(),
                    display_name: "LNK property System.AppUserModel.ID=Taotie.Test.App".to_string(),
                    event_time_utc: Some("2026-01-01T00:00:00Z".to_string()),
                    evidence_ref: "raw://sha256/a".to_string(),
                    evidence_offset: Some(320),
                    evidence_length: Some(30),
                    confidence: 0.78,
                    attributes_json: "{}".to_string(),
                },
                ArtifactObject {
                    object_id: "obj_2".to_string(),
                    case_id: case_id.clone(),
                    event_id: "event_lnk_2".to_string(),
                    source_file_id: "file_lnk_2".to_string(),
                    parse_run_id: "parse_2".to_string(),
                    artifact_type: "lnk".to_string(),
                    object_kind: "lnk_property_value".to_string(),
                    object_key: key.to_string(),
                    display_name: "LNK property System.AppUserModel.ID=Taotie.Test.App".to_string(),
                    event_time_utc: Some("2026-01-01T00:01:00Z".to_string()),
                    evidence_ref: "raw://sha256/b".to_string(),
                    evidence_offset: Some(400),
                    evidence_length: Some(30),
                    confidence: 0.78,
                    attributes_json: "{}".to_string(),
                },
            ])
            .unwrap();

        let chains = workspace
            .query_layer()
            .rebuild_correlation_chains(Some(10))
            .unwrap();
        let chain = chains
            .iter()
            .find(|row| row.key_kind == "artifact_object:lnk_property_value")
            .expect("lnk property structure chain");
        assert_eq!(chain.key_value, key);
        assert_eq!(chain.title, "LNK PropertyStore の横断一致");

        let page = workspace
            .query_layer()
            .correlation_chain_event_page(CorrelationChainEventPageQuery {
                key_kind: chain.key_kind.clone(),
                key_value: chain.key_value.clone(),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".to_string()),
                    sort_dir: Some("asc".to_string()),
                },
            })
            .unwrap();
        assert_eq!(page.rows.len(), 2);
    }

    #[test]
    fn finding_summary_falls_back_to_suspicious_event_rows() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = CaseWorkspace::create(temp.path().join("case"), "demo").unwrap();
        let case_id = workspace.manifest().case_id.clone();
        workspace
            .replace_event_rows(&[
                EventRow {
                    event_id: "event_high_powershell".to_string(),
                    case_id: case_id.clone(),
                    event_time_utc: "2026-01-01T00:00:00Z".to_string(),
                    artifact_type: "evtx".to_string(),
                    host: Some("host1".to_string()),
                    user_name: Some("alice".to_string()),
                    process_name: Some("powershell.exe".to_string()),
                    file_path: None,
                    ip: None,
                    url: None,
                    hash: None,
                    event_code: Some("1".to_string()),
                    channel: Some("Sysmon".to_string()),
                    level: None,
                    event_action: "powershell_encoded_command".to_string(),
                    severity: "high".to_string(),
                    message_short: "PowerShell encoded command observed".to_string(),
                    source_file_id: "file_evtx_1".to_string(),
                    parser_name: "taotie_core_evtx".to_string(),
                    has_finding: false,
                    command_line: None,
                },
                EventRow {
                    event_id: "event_info_noise".to_string(),
                    case_id: case_id.clone(),
                    event_time_utc: "2026-01-01T00:01:00Z".to_string(),
                    artifact_type: "prefetch".to_string(),
                    host: Some("host1".to_string()),
                    user_name: None,
                    process_name: Some("notepad.exe".to_string()),
                    file_path: None,
                    ip: None,
                    url: None,
                    hash: None,
                    event_code: None,
                    channel: None,
                    level: None,
                    event_action: "prefetch_execution_observed".to_string(),
                    severity: "info".to_string(),
                    message_short: "Prefetch execution observed".to_string(),
                    source_file_id: "file_pf_1".to_string(),
                    parser_name: "taotie_core_prefetch".to_string(),
                    has_finding: false,
                    command_line: None,
                },
            ])
            .unwrap();

        let findings = workspace.query_layer().finding_summary(Some(10)).unwrap();
        let finding = findings
            .iter()
            .find(|row| row.title == "powershell_encoded_command (evtx)")
            .expect("high severity event row should be exposed as fallback finding");
        assert_eq!(finding.engine, "event_rows");
        assert_eq!(finding.event_count, 1);

        let page = workspace
            .query_layer()
            .finding_event_page(FindingEventPageQuery {
                title: finding.title.clone(),
                engine: Some(finding.engine.clone()),
                rule_id: finding.rule_id.clone(),
                page: EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: None,
                    sort_by: Some("event_time_utc".to_string()),
                    sort_dir: Some("asc".to_string()),
                },
            })
            .unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].event_id, "event_high_powershell");
    }

    #[test]
    fn event_search_uses_high_value_search_text_from_attributes() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = CaseWorkspace::create(temp.path().join("case"), "demo").unwrap();
        let case_id = workspace.manifest().case_id.clone();
        let event = EventFull {
            event_id: "event_hidden_values".to_string(),
            case_id: case_id.clone(),
            event_time_utc: "2026-01-01T00:00:00Z".to_string(),
            event_time_original: "2026-01-01T00:00:00Z".to_string(),
            time_kind: "event_created".to_string(),
            time_confidence: 0.9,
            source_confidence: 0.9,
            artifact_type: "mft".to_string(),
            source_file_id: "file_mft".to_string(),
            parse_run_id: "parse_mft".to_string(),
            parser_name: "taotie_core_mft".to_string(),
            parser_version: "0.1.0".to_string(),
            schema_version: "test".to_string(),
            evidence_ref: "raw://sha256/test".to_string(),
            host: Some("HOST1".to_string()),
            user_name: None,
            process_name: None,
            file_path: Some("Users/alice/Downloads/Stage.zip:Zone.Identifier".to_string()),
            ip: None,
            url: None,
            hash: None,
            event_action: "mft_ads_resident_content_observed".to_string(),
            severity: "medium".to_string(),
            message_short: "ADS resident content observed".to_string(),
            message_full: "short display text without answer terms".to_string(),
            raw_record_ref: "raw_event_hidden_values".to_string(),
            attributes_json: serde_json::json!({
                "ZoneIdContents": "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://download.example/Stage.zip",
                "c2": "203.0.113.10",
                "secret": "S3cr3t-test-value",
                "archive_note": "CVE-2023-38831"
            })
            .to_string(),
        };
        workspace.append_events_full(&[event.clone()]).unwrap();
        workspace
            .replace_event_rows(&[event.to_event_row()])
            .unwrap();
        assert_eq!(
            workspace
                .query_layer()
                .rebuild_event_rows_from_lake()
                .unwrap(),
            1
        );

        for term in [
            "HostUrl",
            "203.0.113.10",
            "S3cr3t-test-value",
            "CVE-2023-38831",
        ] {
            let page = workspace
                .query_layer()
                .event_page(EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: Some(term.to_string()),
                    sort_by: Some("event_time_utc".to_string()),
                    sort_dir: Some("asc".to_string()),
                })
                .unwrap();
            assert_eq!(page.rows.len(), 1, "term {term} should hit search_text");
            assert_eq!(page.rows[0].event_id, "event_hidden_values");
        }
    }

    #[test]
    fn event_search_supports_extension_and_word_exact_terms() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = CaseWorkspace::create(temp.path().join("case"), "demo").unwrap();
        let case_id = workspace.manifest().case_id.clone();
        let asp = EventFull {
            event_id: "event_mft_asp".to_string(),
            case_id: case_id.clone(),
            event_time_utc: "2026-01-01T00:00:00Z".to_string(),
            event_time_original: "2026-01-01T00:00:00Z".to_string(),
            time_kind: "event_created".to_string(),
            time_confidence: 0.9,
            source_confidence: 0.9,
            artifact_type: "mft".to_string(),
            source_file_id: "file_mft".to_string(),
            parse_run_id: "parse_mft".to_string(),
            parser_name: "taotie_core_mft".to_string(),
            parser_version: "0.1.0".to_string(),
            schema_version: "test".to_string(),
            evidence_ref: "raw://sha256/test".to_string(),
            host: Some("HOST1".to_string()),
            user_name: None,
            process_name: None,
            file_path: Some("C:/inetpub/wwwroot/move.asp".to_string()),
            ip: None,
            url: None,
            hash: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            event_action: "mft_filename_created".to_string(),
            severity: "medium".to_string(),
            message_short: "MFT file observed: move.asp".to_string(),
            message_full: "MFT file observed: move.asp".to_string(),
            raw_record_ref: "raw_event_mft_asp".to_string(),
            attributes_json: "{}".to_string(),
        };
        let mut aspx = asp.clone();
        aspx.event_id = "event_mft_aspx".to_string();
        aspx.event_time_utc = "2026-01-01T00:00:01Z".to_string();
        aspx.event_time_original = "2026-01-01T00:00:01Z".to_string();
        aspx.file_path = Some("C:/inetpub/wwwroot/move.aspx".to_string());
        aspx.hash = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string());
        aspx.message_short = "MFT file observed: move.aspx".to_string();
        aspx.message_full = "MFT file observed: move.aspx".to_string();
        aspx.raw_record_ref = "raw_event_mft_aspx".to_string();

        workspace
            .append_events_full(&[asp.clone(), aspx.clone()])
            .unwrap();
        assert_eq!(
            workspace
                .query_layer()
                .rebuild_event_rows_from_lake()
                .unwrap(),
            2
        );

        let search_ids = |search: &str| {
            workspace
                .query_layer()
                .event_page(EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: Some("mft".to_string()),
                    user_name: None,
                    search: Some(search.to_string()),
                    sort_by: Some("event_time_utc".to_string()),
                    sort_dir: Some("asc".to_string()),
                })
                .unwrap()
                .rows
                .into_iter()
                .map(|row| row.event_id)
                .collect::<Vec<_>>()
        };

        assert_eq!(search_ids("asp").len(), 2);
        assert_eq!(search_ids("ext:asp"), vec!["event_mft_asp".to_string()]);
        assert_eq!(search_ids("word:asp"), vec!["event_mft_asp".to_string()]);
        assert_eq!(search_ids("\"asp\""), vec!["event_mft_asp".to_string()]);
        assert_eq!(search_ids("ext:aspx"), vec!["event_mft_aspx".to_string()]);
    }

    #[test]
    fn event_search_handles_incremental_rows_without_search_text() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = CaseWorkspace::create(temp.path().join("case"), "demo").unwrap();
        let case_id = workspace.manifest().case_id.clone();
        let initial = EventFull {
            event_id: "event_initial".to_string(),
            case_id: case_id.clone(),
            event_time_utc: "2026-01-01T00:00:00Z".to_string(),
            event_time_original: "2026-01-01T00:00:00Z".to_string(),
            time_kind: "event_created".to_string(),
            time_confidence: 0.9,
            source_confidence: 0.9,
            artifact_type: "evtx".to_string(),
            source_file_id: "file_evtx".to_string(),
            parse_run_id: "parse_evtx".to_string(),
            parser_name: "test".to_string(),
            parser_version: "0.1.0".to_string(),
            schema_version: "test".to_string(),
            evidence_ref: "raw://sha256/test".to_string(),
            host: Some("HOST1".to_string()),
            user_name: None,
            process_name: Some("services.exe".to_string()),
            file_path: None,
            ip: None,
            url: None,
            hash: None,
            event_action: "service_started".to_string(),
            severity: "info".to_string(),
            message_short: "baseline event".to_string(),
            message_full: "baseline event".to_string(),
            raw_record_ref: "raw_event_initial".to_string(),
            attributes_json: "{}".to_string(),
        };
        let mut incremental = initial.clone();
        incremental.event_id = "event_incremental".to_string();
        incremental.event_time_utc = "2026-01-01T00:00:01Z".to_string();
        incremental.artifact_type = "mft".to_string();
        incremental.source_file_id = "file_mft".to_string();
        incremental.parse_run_id = "parse_mft".to_string();
        incremental.process_name = None;
        incremental.file_path = Some("C:/Users/alice/needle-visible.txt".to_string());
        incremental.event_action = "mft_filename_created".to_string();
        incremental.message_short = "incremental needle-visible event".to_string();
        incremental.message_full = "incremental needle-visible event".to_string();
        incremental.raw_record_ref = "raw_event_incremental".to_string();

        workspace.append_events_full(&[initial.clone()]).unwrap();
        assert_eq!(
            workspace
                .query_layer()
                .rebuild_event_rows_from_lake()
                .unwrap(),
            1
        );
        workspace
            .append_events_full(&[incremental.clone()])
            .unwrap();
        workspace
            .append_event_rows(&[incremental.to_event_row()])
            .unwrap();

        let page = workspace
            .query_layer()
            .event_page(EventPageQuery {
                limit: Some(10),
                cursor: None,
                artifact_type: None,
                user_name: None,
                search: Some("needle-visible".to_string()),
                sort_by: Some("event_time_utc".to_string()),
                sort_dir: Some("asc".to_string()),
            })
            .unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].event_id, "event_incremental");

        assert_eq!(
            workspace
                .query_layer()
                .rebuild_event_rows_from_lake()
                .unwrap(),
            2
        );
    }
}
