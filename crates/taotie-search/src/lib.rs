use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tantivy::{
    collector::TopDocs,
    doc,
    query::{AllQuery, QueryParser},
    schema::{
        Field, Schema, TantivyDocument, TextFieldIndexing, TextOptions, Value, FAST, STORED,
        STRING, TEXT,
    },
    Index, TantivyError, Term,
};
use taotie_schema::{now_utc, Page};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("search index is not built yet")]
    NotIndexed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tantivy error: {0}")]
    Tantivy(#[from] TantivyError),
    #[error("invalid query: {0}")]
    InvalidQuery(String),
}

pub type Result<T> = std::result::Result<T, SearchError>;

const INDEX_VERSION: &str = "taotie-tantivy-events-v1";
const WRITER_MEMORY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchHit {
    pub event_id: String,
    pub event_time_utc: String,
    pub artifact_type: String,
    pub severity: String,
    pub event_action: String,
    pub host: Option<String>,
    pub user_name: Option<String>,
    pub process_name: Option<String>,
    pub file_path: Option<String>,
    pub message_short: String,
    pub score_basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchQuery {
    pub text: String,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexMetadata {
    pub case_id: String,
    pub index_version: String,
    pub indexed_event_count: i64,
    pub updated_at: Option<String>,
    pub build_mode: Option<String>,
    pub appended_event_count: Option<i64>,
    pub updated_event_count: Option<i64>,
    pub deleted_event_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexEvent {
    pub event_id: String,
    pub event_time_utc: String,
    pub artifact_type: String,
    pub severity: String,
    pub event_action: String,
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
    pub parser_name: String,
    pub source_file_id: String,
    pub message_short: String,
    pub message_full: String,
}

pub trait EventSearchIndex: Send + Sync {
    fn metadata(&self) -> Result<Option<IndexMetadata>>;
    fn search_first_page(&self, query: SearchQuery) -> Result<Page<SearchHit>>;
}

#[derive(Debug, Clone)]
pub struct TantivyEventIndex {
    index_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct EventIndexFields {
    event_id: Field,
    event_time_utc: Field,
    artifact_type: Field,
    severity: Field,
    event_action: Field,
    host: Field,
    user_name: Field,
    process_name: Field,
    file_path: Field,
    ip: Field,
    url: Field,
    hash: Field,
    event_code: Field,
    channel: Field,
    level: Field,
    parser_name: Field,
    source_file_id: Field,
    message_short: Field,
    message_full: Field,
    body: Field,
}

impl TantivyEventIndex {
    pub fn new(index_dir: impl AsRef<Path>) -> Self {
        Self {
            index_dir: index_dir.as_ref().to_path_buf(),
        }
    }

    pub fn build_from_events<I>(&self, case_id: &str, events: I) -> Result<IndexMetadata>
    where
        I: IntoIterator<Item = IndexEvent>,
    {
        if self.index_dir.exists() {
            fs::remove_dir_all(&self.index_dir)?;
        }
        fs::create_dir_all(&self.index_dir)?;
        let schema = event_schema();
        let fields = event_fields(&schema)?;
        let index = Index::create_in_dir(&self.index_dir, schema)?;
        let mut writer = index.writer(WRITER_MEMORY_BYTES)?;
        let mut indexed_event_count = 0i64;
        let mut fingerprints = BTreeMap::new();
        for event in events {
            fingerprints.insert(event.event_id.clone(), event_fingerprint(&event)?);
            writer.add_document(event_document(&fields, &event))?;
            indexed_event_count += 1;
        }
        writer.commit()?;
        let metadata = IndexMetadata {
            case_id: case_id.to_string(),
            index_version: INDEX_VERSION.to_string(),
            indexed_event_count,
            updated_at: Some(now_utc()),
            build_mode: Some("full_rebuild".to_string()),
            appended_event_count: Some(indexed_event_count),
            updated_event_count: Some(0),
            deleted_event_count: Some(0),
        };
        self.write_event_fingerprints(&fingerprints)?;
        fs::write(self.metadata_path(), serde_json::to_vec_pretty(&metadata)?)?;
        Ok(metadata)
    }

    pub fn sync_from_events<I>(&self, case_id: &str, events: I) -> Result<IndexMetadata>
    where
        I: IntoIterator<Item = IndexEvent>,
    {
        let events = events.into_iter().collect::<Vec<_>>();
        let Some(metadata) = self.metadata()? else {
            return self.build_from_events(case_id, events);
        };
        if metadata.case_id != case_id || metadata.index_version != INDEX_VERSION {
            return self.build_from_events(case_id, events);
        }
        let Ok(indexed_fingerprints) = self.read_event_fingerprints() else {
            return self.build_from_events(case_id, events);
        };
        if indexed_fingerprints.len() as i64 != metadata.indexed_event_count {
            return self.build_from_events(case_id, events);
        }
        let mut current_fingerprints = BTreeMap::new();
        let mut events_by_id = BTreeMap::new();
        for event in events {
            current_fingerprints.insert(event.event_id.clone(), event_fingerprint(&event)?);
            events_by_id.insert(event.event_id.clone(), event);
        }
        let deleted_event_ids = indexed_fingerprints
            .keys()
            .filter(|event_id| !current_fingerprints.contains_key(*event_id))
            .cloned()
            .collect::<Vec<_>>();
        let changed_or_new_event_ids = current_fingerprints
            .iter()
            .filter_map(
                |(event_id, fingerprint)| match indexed_fingerprints.get(event_id) {
                    Some(indexed) if indexed == fingerprint => None,
                    _ => Some(event_id.clone()),
                },
            )
            .collect::<Vec<_>>();
        if deleted_event_ids.is_empty() && changed_or_new_event_ids.is_empty() {
            let metadata = IndexMetadata {
                case_id: case_id.to_string(),
                index_version: INDEX_VERSION.to_string(),
                indexed_event_count: current_fingerprints.len() as i64,
                updated_at: Some(now_utc()),
                build_mode: Some("noop".to_string()),
                appended_event_count: Some(0),
                updated_event_count: Some(0),
                deleted_event_count: Some(0),
            };
            fs::write(self.metadata_path(), serde_json::to_vec_pretty(&metadata)?)?;
            return Ok(metadata);
        }

        let index = Index::open_in_dir(&self.index_dir)?;
        let schema = index.schema();
        let fields = event_fields(&schema)?;
        let mut writer = index.writer(WRITER_MEMORY_BYTES)?;
        for event_id in &deleted_event_ids {
            writer.delete_term(Term::from_field_text(fields.event_id, event_id));
        }
        let mut appended_event_count = 0i64;
        let mut updated_event_count = 0i64;
        for event_id in changed_or_new_event_ids {
            let Some(event) = events_by_id.get(&event_id) else {
                continue;
            };
            if indexed_fingerprints.contains_key(&event_id) {
                writer.delete_term(Term::from_field_text(fields.event_id, &event_id));
                updated_event_count += 1;
            } else {
                appended_event_count += 1;
            }
            writer.add_document(event_document(&fields, event))?;
        }
        writer.commit()?;
        let deleted_event_count = deleted_event_ids.len() as i64;
        let build_mode = if deleted_event_count > 0 || updated_event_count > 0 {
            "incremental_sync"
        } else {
            "incremental_append"
        };
        let metadata = IndexMetadata {
            case_id: case_id.to_string(),
            index_version: INDEX_VERSION.to_string(),
            indexed_event_count: current_fingerprints.len() as i64,
            updated_at: Some(now_utc()),
            build_mode: Some(build_mode.to_string()),
            appended_event_count: Some(appended_event_count),
            updated_event_count: Some(updated_event_count),
            deleted_event_count: Some(deleted_event_count),
        };
        self.write_event_fingerprints(&current_fingerprints)?;
        fs::write(self.metadata_path(), serde_json::to_vec_pretty(&metadata)?)?;
        Ok(metadata)
    }

    fn metadata_path(&self) -> PathBuf {
        self.index_dir.join("taotie_index_manifest.json")
    }

    fn event_fingerprints_path(&self) -> PathBuf {
        self.index_dir.join("taotie_index_event_fingerprints.json")
    }

    fn read_event_fingerprints(&self) -> Result<BTreeMap<String, String>> {
        Ok(serde_json::from_slice(&fs::read(
            self.event_fingerprints_path(),
        )?)?)
    }

    fn write_event_fingerprints(&self, fingerprints: &BTreeMap<String, String>) -> Result<()> {
        fs::write(
            self.event_fingerprints_path(),
            serde_json::to_vec_pretty(fingerprints)?,
        )?;
        Ok(())
    }

    fn open_index(&self) -> Result<Index> {
        if !self.metadata_path().exists() {
            return Err(SearchError::NotIndexed);
        }
        Index::open_in_dir(&self.index_dir).map_err(SearchError::from)
    }
}

impl EventSearchIndex for TantivyEventIndex {
    fn metadata(&self) -> Result<Option<IndexMetadata>> {
        let path = self.metadata_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice::<IndexMetadata>(&fs::read(
            path,
        )?)?))
    }

    fn search_first_page(&self, query: SearchQuery) -> Result<Page<SearchHit>> {
        let index = self.open_index()?;
        let schema = index.schema();
        let fields = event_fields(&schema)?;
        let reader = index.reader()?;
        let searcher = reader.searcher();
        let limit = query.limit.unwrap_or(50).clamp(1, 200);
        let offset = query
            .cursor
            .as_deref()
            .and_then(|cursor| cursor.parse::<usize>().ok())
            .unwrap_or(0);
        let text = query.text.trim();
        let query_box = if text.is_empty() {
            Box::new(AllQuery) as Box<dyn tantivy::query::Query>
        } else {
            let parser = QueryParser::for_index(
                &index,
                vec![
                    fields.body,
                    fields.message_short,
                    fields.message_full,
                    fields.process_name,
                    fields.file_path,
                    fields.user_name,
                    fields.host,
                    fields.ip,
                    fields.url,
                    fields.hash,
                    fields.artifact_type,
                    fields.event_code,
                    fields.event_action,
                    fields.parser_name,
                ],
            );
            parser
                .parse_query(text)
                .map_err(|error| SearchError::InvalidQuery(error.to_string()))?
        };
        let top_docs = searcher.search(
            &query_box,
            &TopDocs::with_limit(limit + 1)
                .and_offset(offset)
                .order_by_score(),
        )?;
        let mut rows = Vec::new();
        for (score, address) in top_docs.into_iter().take(limit + 1) {
            let document: TantivyDocument = searcher.doc(address)?;
            rows.push(hit_from_document(&document, &fields, score));
        }
        let next_cursor = if rows.len() > limit {
            rows.truncate(limit);
            Some((offset + limit).to_string())
        } else {
            None
        };
        Ok(Page { rows, next_cursor })
    }
}

fn event_document(fields: &EventIndexFields, event: &IndexEvent) -> TantivyDocument {
    let body = event_body(event);
    doc!(
        fields.event_id => event.event_id.clone(),
        fields.event_time_utc => event.event_time_utc.clone(),
        fields.artifact_type => event.artifact_type.clone(),
        fields.severity => event.severity.clone(),
        fields.event_action => event.event_action.clone(),
        fields.host => event.host.clone().unwrap_or_default(),
        fields.user_name => event.user_name.clone().unwrap_or_default(),
        fields.process_name => event.process_name.clone().unwrap_or_default(),
        fields.file_path => event.file_path.clone().unwrap_or_default(),
        fields.ip => event.ip.clone().unwrap_or_default(),
        fields.url => event.url.clone().unwrap_or_default(),
        fields.hash => event.hash.clone().unwrap_or_default(),
        fields.event_code => event.event_code.clone().unwrap_or_default(),
        fields.channel => event.channel.clone().unwrap_or_default(),
        fields.level => event.level.clone().unwrap_or_default(),
        fields.parser_name => event.parser_name.clone(),
        fields.source_file_id => event.source_file_id.clone(),
        fields.message_short => event.message_short.clone(),
        fields.message_full => event.message_full.clone(),
        fields.body => body,
    )
}

fn event_fingerprint(event: &IndexEvent) -> Result<String> {
    let bytes = serde_json::to_vec(event)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn event_schema() -> Schema {
    let mut builder = Schema::builder();
    let text_stored = TEXT | STORED;
    let string_stored = STRING | STORED;
    let exact_indexed = TextOptions::default()
        .set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer("raw")
                .set_index_option(tantivy::schema::IndexRecordOption::Basic),
        )
        .set_stored();
    builder.add_text_field("event_id", string_stored.clone() | FAST);
    builder.add_text_field("event_time_utc", string_stored.clone() | FAST);
    builder.add_text_field("artifact_type", exact_indexed.clone());
    builder.add_text_field("severity", exact_indexed.clone());
    builder.add_text_field("event_action", exact_indexed.clone());
    builder.add_text_field("host", text_stored.clone());
    builder.add_text_field("user_name", text_stored.clone());
    builder.add_text_field("process_name", text_stored.clone());
    builder.add_text_field("file_path", text_stored.clone());
    builder.add_text_field("ip", text_stored.clone());
    builder.add_text_field("url", text_stored.clone());
    builder.add_text_field("hash", exact_indexed);
    builder.add_text_field("event_code", string_stored.clone());
    builder.add_text_field("channel", text_stored.clone());
    builder.add_text_field("level", text_stored.clone());
    builder.add_text_field("parser_name", string_stored.clone());
    builder.add_text_field("source_file_id", string_stored);
    builder.add_text_field("message_short", text_stored.clone());
    builder.add_text_field("message_full", text_stored);
    builder.add_text_field("body", TEXT);
    builder.build()
}

fn event_fields(schema: &Schema) -> Result<EventIndexFields> {
    let field = |name: &str| {
        schema
            .get_field(name)
            .map_err(|_| SearchError::InvalidQuery(format!("index schema missing field: {name}")))
    };
    Ok(EventIndexFields {
        event_id: field("event_id")?,
        event_time_utc: field("event_time_utc")?,
        artifact_type: field("artifact_type")?,
        severity: field("severity")?,
        event_action: field("event_action")?,
        host: field("host")?,
        user_name: field("user_name")?,
        process_name: field("process_name")?,
        file_path: field("file_path")?,
        ip: field("ip")?,
        url: field("url")?,
        hash: field("hash")?,
        event_code: field("event_code")?,
        channel: field("channel")?,
        level: field("level")?,
        parser_name: field("parser_name")?,
        source_file_id: field("source_file_id")?,
        message_short: field("message_short")?,
        message_full: field("message_full")?,
        body: field("body")?,
    })
}

fn hit_from_document(
    document: &TantivyDocument,
    fields: &EventIndexFields,
    score: f32,
) -> SearchHit {
    SearchHit {
        event_id: doc_string(document, fields.event_id),
        event_time_utc: doc_string(document, fields.event_time_utc),
        artifact_type: doc_string(document, fields.artifact_type),
        severity: doc_string(document, fields.severity),
        event_action: doc_string(document, fields.event_action),
        host: doc_optional_string(document, fields.host),
        user_name: doc_optional_string(document, fields.user_name),
        process_name: doc_optional_string(document, fields.process_name),
        file_path: doc_optional_string(document, fields.file_path),
        message_short: doc_string(document, fields.message_short),
        score_basis: format!("{score:.3}"),
    }
}

fn doc_string(document: &TantivyDocument, field: Field) -> String {
    doc_optional_string(document, field).unwrap_or_default()
}

fn doc_optional_string(document: &TantivyDocument, field: Field) -> Option<String> {
    document
        .get_first(field)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

fn event_body(event: &IndexEvent) -> String {
    [
        Some(event.event_id.as_str()),
        Some(event.event_time_utc.as_str()),
        Some(event.artifact_type.as_str()),
        Some(event.severity.as_str()),
        Some(event.event_action.as_str()),
        event.host.as_deref(),
        event.user_name.as_deref(),
        event.process_name.as_deref(),
        event.file_path.as_deref(),
        event.ip.as_deref(),
        event.url.as_deref(),
        event.hash.as_deref(),
        event.event_code.as_deref(),
        event.channel.as_deref(),
        event.level.as_deref(),
        Some(event.parser_name.as_str()),
        Some(event.source_file_id.as_str()),
        Some(event.message_short.as_str()),
        Some(event.message_full.as_str()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
}

#[derive(Debug, Default)]
pub struct TantivyStubIndex;

impl EventSearchIndex for TantivyStubIndex {
    fn metadata(&self) -> Result<Option<IndexMetadata>> {
        Ok(None)
    }

    fn search_first_page(&self, _query: SearchQuery) -> Result<Page<SearchHit>> {
        Err(SearchError::NotIndexed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_metadata_and_searches_event_fields() {
        let temp = tempfile::tempdir().unwrap();
        let index = TantivyEventIndex::new(temp.path().join("tantivy"));
        let metadata = index
            .build_from_events(
                "case_demo",
                vec![
                    IndexEvent {
                        event_id: "event_1".into(),
                        event_time_utc: "2026-06-25T00:00:00Z".into(),
                        artifact_type: "evtx".into(),
                        severity: "high".into(),
                        event_action: "process_start".into(),
                        host: Some("host-a".into()),
                        user_name: Some("alice".into()),
                        process_name: Some("powershell.exe".into()),
                        file_path: Some(
                            "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe".into(),
                        ),
                        ip: Some("10.0.0.5".into()),
                        url: None,
                        hash: Some("0123456789abcdef".into()),
                        event_code: Some("4688".into()),
                        channel: Some("Security".into()),
                        level: Some("Information".into()),
                        parser_name: "test_parser".into(),
                        source_file_id: "file_1".into(),
                        message_short: "PowerShell EncodedCommand execution".into(),
                        message_full: "powershell.exe -EncodedCommand AAAA".into(),
                    },
                    IndexEvent {
                        event_id: "event_2".into(),
                        event_time_utc: "2026-06-25T00:01:00Z".into(),
                        artifact_type: "text_log".into(),
                        severity: "info".into(),
                        event_action: "service_status".into(),
                        host: Some("host-a".into()),
                        user_name: None,
                        process_name: Some("svchost.exe".into()),
                        file_path: None,
                        ip: None,
                        url: None,
                        hash: None,
                        event_code: None,
                        channel: None,
                        level: None,
                        parser_name: "test_parser".into(),
                        source_file_id: "file_2".into(),
                        message_short: "service stopped".into(),
                        message_full: "INFO service stopped".into(),
                    },
                ],
            )
            .unwrap();
        assert_eq!(metadata.case_id, "case_demo");
        assert_eq!(metadata.indexed_event_count, 2);
        assert_eq!(index.metadata().unwrap().unwrap().indexed_event_count, 2);

        let hits = index
            .search_first_page(SearchQuery {
                text: "process_name:powershell encodedcommand".into(),
                limit: Some(10),
                cursor: None,
            })
            .unwrap();
        assert_eq!(hits.rows.len(), 1);
        assert_eq!(hits.rows[0].event_id, "event_1");
        assert_eq!(hits.rows[0].user_name.as_deref(), Some("alice"));

        let first_page = index
            .search_first_page(SearchQuery {
                text: "host-a".into(),
                limit: Some(1),
                cursor: None,
            })
            .unwrap();
        assert_eq!(first_page.rows.len(), 1);
        assert!(first_page.next_cursor.is_some());
        let second_page = index
            .search_first_page(SearchQuery {
                text: "host-a".into(),
                limit: Some(1),
                cursor: first_page.next_cursor,
            })
            .unwrap();
        assert_eq!(second_page.rows.len(), 1);
    }

    #[test]
    fn sync_appends_only_new_events() {
        let temp = tempfile::tempdir().unwrap();
        let index = TantivyEventIndex::new(temp.path().join("tantivy"));
        let event_1 = test_event("event_1", "PowerShell EncodedCommand", "powershell.exe");
        let event_2 = test_event("event_2", "service stopped", "svchost.exe");
        let event_3 = test_event("event_3", "Merlin agent beacon", "merlin.exe");
        let full = index
            .build_from_events("case_demo", vec![event_1.clone(), event_2.clone()])
            .unwrap();
        assert_eq!(full.build_mode.as_deref(), Some("full_rebuild"));
        assert_eq!(full.appended_event_count, Some(2));

        let incremental = index
            .sync_from_events("case_demo", vec![event_1, event_2, event_3])
            .unwrap();
        assert_eq!(incremental.indexed_event_count, 3);
        assert_eq!(
            incremental.build_mode.as_deref(),
            Some("incremental_append")
        );
        assert_eq!(incremental.appended_event_count, Some(1));
        assert_eq!(index.metadata().unwrap().unwrap().indexed_event_count, 3);
        let hits = index
            .search_first_page(SearchQuery {
                text: "merlin".into(),
                limit: Some(10),
                cursor: None,
            })
            .unwrap();
        assert_eq!(hits.rows.len(), 1);
        assert_eq!(hits.rows[0].event_id, "event_3");

        let noop = index
            .sync_from_events(
                "case_demo",
                vec![
                    test_event("event_1", "PowerShell EncodedCommand", "powershell.exe"),
                    test_event("event_2", "service stopped", "svchost.exe"),
                    test_event("event_3", "Merlin agent beacon", "merlin.exe"),
                ],
            )
            .unwrap();
        assert_eq!(noop.build_mode.as_deref(), Some("noop"));
        assert_eq!(noop.appended_event_count, Some(0));
    }

    #[test]
    fn sync_updates_and_deletes_changed_events() {
        let temp = tempfile::tempdir().unwrap();
        let index = TantivyEventIndex::new(temp.path().join("tantivy"));
        let event_1 = test_event("event_1", "PowerShell EncodedCommand", "powershell.exe");
        let event_2 = test_event("event_2", "service stopped", "svchost.exe");
        index
            .build_from_events("case_demo", vec![event_1, event_2])
            .unwrap();

        let metadata = index
            .sync_from_events(
                "case_demo",
                vec![
                    test_event("event_1", "PowerShell renamed payload", "powershell.exe"),
                    test_event("event_3", "Merlin agent beacon", "merlin.exe"),
                ],
            )
            .unwrap();
        assert_eq!(metadata.indexed_event_count, 2);
        assert_eq!(metadata.build_mode.as_deref(), Some("incremental_sync"));
        assert_eq!(metadata.appended_event_count, Some(1));
        assert_eq!(metadata.updated_event_count, Some(1));
        assert_eq!(metadata.deleted_event_count, Some(1));

        let removed = index
            .search_first_page(SearchQuery {
                text: "\"service stopped\"".into(),
                limit: Some(10),
                cursor: None,
            })
            .unwrap();
        assert_eq!(removed.rows.len(), 0);
        let updated = index
            .search_first_page(SearchQuery {
                text: "renamed".into(),
                limit: Some(10),
                cursor: None,
            })
            .unwrap();
        assert_eq!(updated.rows.len(), 1);
        assert_eq!(updated.rows[0].event_id, "event_1");
        let added = index
            .search_first_page(SearchQuery {
                text: "merlin".into(),
                limit: Some(10),
                cursor: None,
            })
            .unwrap();
        assert_eq!(added.rows.len(), 1);
        assert_eq!(added.rows[0].event_id, "event_3");
    }

    fn test_event(event_id: &str, message: &str, process_name: &str) -> IndexEvent {
        IndexEvent {
            event_id: event_id.to_string(),
            event_time_utc: "2026-06-25T00:00:00Z".into(),
            artifact_type: "evtx".into(),
            severity: "info".into(),
            event_action: "process_start".into(),
            host: Some("host-a".into()),
            user_name: Some("alice".into()),
            process_name: Some(process_name.to_string()),
            file_path: Some(format!("C:/Windows/System32/{process_name}")),
            ip: None,
            url: None,
            hash: None,
            event_code: Some("4688".into()),
            channel: Some("Security".into()),
            level: Some("Information".into()),
            parser_name: "test_parser".into(),
            source_file_id: "file_1".into(),
            message_short: message.to_string(),
            message_full: message.to_string(),
        }
    }
}
