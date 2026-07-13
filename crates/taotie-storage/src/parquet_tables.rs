use std::{fs, fs::File, path::Path, path::PathBuf, sync::Arc};

use arrow_array::{ArrayRef, BooleanArray, Float64Array, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use parquet::{arrow::ArrowWriter, basic::Compression, file::properties::WriterProperties};
use taotie_schema::{
    AnalyzerRunSummary, AnswerCandidate, ArtifactObject, CorrelationChainSummary, CoverageSummary,
    EdgeRecord, EntityRecord, EventFull, EventRow, EvidenceOffset, FailedParserSummary, FileRecord,
    FindingRecord, ParseRun, ParserErrorRecord, ParserVersionRecord, RawRecord,
    SchemaVersionRecord, TimelineBin, UnsupportedFileRecord,
};

use crate::{part_path, Result};

fn write_part(dir: &Path, schema: SchemaRef, columns: Vec<ArrayRef>) -> Result<Option<PathBuf>> {
    if columns.is_empty() {
        return Ok(None);
    }
    let batch = RecordBatch::try_new(schema.clone(), columns)?;
    if batch.num_rows() == 0 {
        return Ok(None);
    }
    fs::create_dir_all(dir)?;
    let path = part_path(dir);
    let tmp_path = path.with_extension("parquet.tmp");
    let file = File::create(&tmp_path)?;
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(Default::default()))
        .build();
    let mut writer = ArrowWriter::try_new(file, schema, Some(props))?;
    writer.write(&batch)?;
    writer.close()?;
    fs::rename(&tmp_path, &path)?;
    Ok(Some(path))
}

fn schema(fields: Vec<Field>) -> SchemaRef {
    Arc::new(Schema::new(fields))
}

fn field(name: &str, data_type: DataType, nullable: bool) -> Field {
    Field::new(name, data_type, nullable)
}

fn str_required<'a>(values: impl Iterator<Item = &'a str>) -> ArrayRef {
    Arc::new(StringArray::from_iter_values(values))
}

fn str_optional<'a>(values: impl Iterator<Item = Option<&'a str>>) -> ArrayRef {
    Arc::new(StringArray::from_iter(values))
}

fn i64_required(values: impl Iterator<Item = i64>) -> ArrayRef {
    Arc::new(Int64Array::from_iter_values(values))
}

fn i64_optional(values: impl Iterator<Item = Option<i64>>) -> ArrayRef {
    Arc::new(Int64Array::from_iter(values))
}

fn f64_required(values: impl Iterator<Item = f64>) -> ArrayRef {
    Arc::new(Float64Array::from_iter_values(values))
}

fn bool_required(values: impl Iterator<Item = bool>) -> ArrayRef {
    Arc::new(BooleanArray::from_iter(values.map(Some)))
}

pub fn write_files(dir: &Path, rows: &[FileRecord]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("file_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("parent_file_id", DataType::Utf8, true),
            field("original_path", DataType::Utf8, false),
            field("normalized_path", DataType::Utf8, false),
            field("filename", DataType::Utf8, false),
            field("extension", DataType::Utf8, false),
            field("size", DataType::Int64, false),
            field("sha256", DataType::Utf8, false),
            field("artifact_type", DataType::Utf8, false),
            field("parser_status", DataType::Utf8, false),
            field("event_count", DataType::Int64, false),
            field("object_ref", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.file_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_optional(rows.iter().map(|r| r.parent_file_id.as_deref())),
            str_required(rows.iter().map(|r| r.original_path.as_str())),
            str_required(rows.iter().map(|r| r.normalized_path.as_str())),
            str_required(rows.iter().map(|r| r.filename.as_str())),
            str_required(rows.iter().map(|r| r.extension.as_str())),
            i64_required(rows.iter().map(|r| r.size)),
            str_required(rows.iter().map(|r| r.sha256.as_str())),
            str_required(rows.iter().map(|r| r.artifact_type.as_str())),
            str_required(rows.iter().map(|r| r.parser_status.as_str())),
            i64_required(rows.iter().map(|r| r.event_count)),
            str_required(rows.iter().map(|r| r.object_ref.as_str())),
        ],
    )
}

pub fn write_parse_runs(dir: &Path, rows: &[ParseRun]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("parse_run_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("file_id", DataType::Utf8, false),
            field("parser_name", DataType::Utf8, false),
            field("parser_version", DataType::Utf8, false),
            field("parser_config_hash", DataType::Utf8, false),
            field("schema_version", DataType::Utf8, false),
            field("status", DataType::Utf8, false),
            field("started_at", DataType::Utf8, false),
            field("finished_at", DataType::Utf8, true),
            field("duration_ms", DataType::Int64, false),
            field("event_count", DataType::Int64, false),
            field("error_message", DataType::Utf8, true),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.parse_run_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.file_id.as_str())),
            str_required(rows.iter().map(|r| r.parser_name.as_str())),
            str_required(rows.iter().map(|r| r.parser_version.as_str())),
            str_required(rows.iter().map(|r| r.parser_config_hash.as_str())),
            str_required(rows.iter().map(|r| r.schema_version.as_str())),
            str_required(rows.iter().map(|r| r.status.as_str())),
            str_required(rows.iter().map(|r| r.started_at.as_str())),
            str_optional(rows.iter().map(|r| r.finished_at.as_deref())),
            i64_required(rows.iter().map(|r| r.duration_ms)),
            i64_required(rows.iter().map(|r| r.event_count)),
            str_optional(rows.iter().map(|r| r.error_message.as_deref())),
        ],
    )
}

pub fn write_parser_versions(dir: &Path, rows: &[ParserVersionRecord]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("case_id", DataType::Utf8, false),
            field("parser_name", DataType::Utf8, false),
            field("parser_version", DataType::Utf8, false),
            field("recorded_at", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.parser_name.as_str())),
            str_required(rows.iter().map(|r| r.parser_version.as_str())),
            str_required(rows.iter().map(|r| r.recorded_at.as_str())),
        ],
    )
}

pub fn write_schema_versions(dir: &Path, rows: &[SchemaVersionRecord]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("case_id", DataType::Utf8, false),
            field("schema_name", DataType::Utf8, false),
            field("schema_version", DataType::Utf8, false),
            field("recorded_at", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.schema_name.as_str())),
            str_required(rows.iter().map(|r| r.schema_version.as_str())),
            str_required(rows.iter().map(|r| r.recorded_at.as_str())),
        ],
    )
}

pub fn write_events_full(dir: &Path, rows: &[EventFull]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("event_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("event_time_utc", DataType::Utf8, false),
            field("event_time_original", DataType::Utf8, false),
            field("time_kind", DataType::Utf8, false),
            field("time_confidence", DataType::Float64, false),
            field("source_confidence", DataType::Float64, false),
            field("artifact_type", DataType::Utf8, false),
            field("source_file_id", DataType::Utf8, false),
            field("parse_run_id", DataType::Utf8, false),
            field("parser_name", DataType::Utf8, false),
            field("parser_version", DataType::Utf8, false),
            field("schema_version", DataType::Utf8, false),
            field("evidence_ref", DataType::Utf8, false),
            field("host", DataType::Utf8, true),
            field("user_name", DataType::Utf8, true),
            field("process_name", DataType::Utf8, true),
            field("file_path", DataType::Utf8, true),
            field("ip", DataType::Utf8, true),
            field("url", DataType::Utf8, true),
            field("hash", DataType::Utf8, true),
            field("event_action", DataType::Utf8, false),
            field("severity", DataType::Utf8, false),
            field("message_short", DataType::Utf8, false),
            field("message_full", DataType::Utf8, false),
            field("raw_record_ref", DataType::Utf8, false),
            field("attributes_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.event_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.event_time_utc.as_str())),
            str_required(rows.iter().map(|r| r.event_time_original.as_str())),
            str_required(rows.iter().map(|r| r.time_kind.as_str())),
            f64_required(rows.iter().map(|r| r.time_confidence)),
            f64_required(rows.iter().map(|r| r.source_confidence)),
            str_required(rows.iter().map(|r| r.artifact_type.as_str())),
            str_required(rows.iter().map(|r| r.source_file_id.as_str())),
            str_required(rows.iter().map(|r| r.parse_run_id.as_str())),
            str_required(rows.iter().map(|r| r.parser_name.as_str())),
            str_required(rows.iter().map(|r| r.parser_version.as_str())),
            str_required(rows.iter().map(|r| r.schema_version.as_str())),
            str_required(rows.iter().map(|r| r.evidence_ref.as_str())),
            str_optional(rows.iter().map(|r| r.host.as_deref())),
            str_optional(rows.iter().map(|r| r.user_name.as_deref())),
            str_optional(rows.iter().map(|r| r.process_name.as_deref())),
            str_optional(rows.iter().map(|r| r.file_path.as_deref())),
            str_optional(rows.iter().map(|r| r.ip.as_deref())),
            str_optional(rows.iter().map(|r| r.url.as_deref())),
            str_optional(rows.iter().map(|r| r.hash.as_deref())),
            str_required(rows.iter().map(|r| r.event_action.as_str())),
            str_required(rows.iter().map(|r| r.severity.as_str())),
            str_required(rows.iter().map(|r| r.message_short.as_str())),
            str_required(rows.iter().map(|r| r.message_full.as_str())),
            str_required(rows.iter().map(|r| r.raw_record_ref.as_str())),
            str_required(rows.iter().map(|r| r.attributes_json.as_str())),
        ],
    )
}

pub fn write_raw_records(dir: &Path, rows: &[RawRecord]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("raw_record_ref", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("event_id", DataType::Utf8, false),
            field("parse_run_id", DataType::Utf8, false),
            field("source_file_id", DataType::Utf8, false),
            field("evidence_ref", DataType::Utf8, false),
            field("raw_record_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.raw_record_ref.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.event_id.as_str())),
            str_required(rows.iter().map(|r| r.parse_run_id.as_str())),
            str_required(rows.iter().map(|r| r.source_file_id.as_str())),
            str_required(rows.iter().map(|r| r.evidence_ref.as_str())),
            str_required(rows.iter().map(|r| r.raw_record_json.as_str())),
        ],
    )
}

pub fn write_artifact_objects(dir: &Path, rows: &[ArtifactObject]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("object_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("event_id", DataType::Utf8, false),
            field("source_file_id", DataType::Utf8, false),
            field("parse_run_id", DataType::Utf8, false),
            field("artifact_type", DataType::Utf8, false),
            field("object_kind", DataType::Utf8, false),
            field("object_key", DataType::Utf8, false),
            field("display_name", DataType::Utf8, false),
            field("event_time_utc", DataType::Utf8, true),
            field("evidence_ref", DataType::Utf8, false),
            field("evidence_offset", DataType::Int64, true),
            field("evidence_length", DataType::Int64, true),
            field("confidence", DataType::Float64, false),
            field("attributes_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.object_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.event_id.as_str())),
            str_required(rows.iter().map(|r| r.source_file_id.as_str())),
            str_required(rows.iter().map(|r| r.parse_run_id.as_str())),
            str_required(rows.iter().map(|r| r.artifact_type.as_str())),
            str_required(rows.iter().map(|r| r.object_kind.as_str())),
            str_required(rows.iter().map(|r| r.object_key.as_str())),
            str_required(rows.iter().map(|r| r.display_name.as_str())),
            str_optional(rows.iter().map(|r| r.event_time_utc.as_deref())),
            str_required(rows.iter().map(|r| r.evidence_ref.as_str())),
            i64_optional(rows.iter().map(|r| r.evidence_offset)),
            i64_optional(rows.iter().map(|r| r.evidence_length)),
            f64_required(rows.iter().map(|r| r.confidence)),
            str_required(rows.iter().map(|r| r.attributes_json.as_str())),
        ],
    )
}

pub fn write_evidence_offsets(dir: &Path, rows: &[EvidenceOffset]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("offset_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("event_id", DataType::Utf8, false),
            field("source_file_id", DataType::Utf8, false),
            field("parse_run_id", DataType::Utf8, false),
            field("object_ref", DataType::Utf8, false),
            field("label", DataType::Utf8, false),
            field("structure_kind", DataType::Utf8, false),
            field("offset", DataType::Int64, false),
            field("length", DataType::Int64, false),
            field("parser_name", DataType::Utf8, false),
            field("confidence", DataType::Float64, false),
            field("attributes_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.offset_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.event_id.as_str())),
            str_required(rows.iter().map(|r| r.source_file_id.as_str())),
            str_required(rows.iter().map(|r| r.parse_run_id.as_str())),
            str_required(rows.iter().map(|r| r.object_ref.as_str())),
            str_required(rows.iter().map(|r| r.label.as_str())),
            str_required(rows.iter().map(|r| r.structure_kind.as_str())),
            i64_required(rows.iter().map(|r| r.offset)),
            i64_required(rows.iter().map(|r| r.length)),
            str_required(rows.iter().map(|r| r.parser_name.as_str())),
            f64_required(rows.iter().map(|r| r.confidence)),
            str_required(rows.iter().map(|r| r.attributes_json.as_str())),
        ],
    )
}

pub fn write_entities(dir: &Path, rows: &[EntityRecord]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("entity_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("entity_type", DataType::Utf8, false),
            field("canonical_value", DataType::Utf8, false),
            field("display_name", DataType::Utf8, false),
            field("host", DataType::Utf8, true),
            field("first_seen_utc", DataType::Utf8, true),
            field("last_seen_utc", DataType::Utf8, true),
            field("event_count", DataType::Int64, false),
            field("attributes_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.entity_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.entity_type.as_str())),
            str_required(rows.iter().map(|r| r.canonical_value.as_str())),
            str_required(rows.iter().map(|r| r.display_name.as_str())),
            str_optional(rows.iter().map(|r| r.host.as_deref())),
            str_optional(rows.iter().map(|r| r.first_seen_utc.as_deref())),
            str_optional(rows.iter().map(|r| r.last_seen_utc.as_deref())),
            i64_required(rows.iter().map(|r| r.event_count)),
            str_required(rows.iter().map(|r| r.attributes_json.as_str())),
        ],
    )
}

pub fn write_edges(dir: &Path, rows: &[EdgeRecord]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("edge_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("src_entity_id", DataType::Utf8, false),
            field("dst_entity_id", DataType::Utf8, false),
            field("edge_type", DataType::Utf8, false),
            field("first_seen_utc", DataType::Utf8, true),
            field("last_seen_utc", DataType::Utf8, true),
            field("confidence", DataType::Float64, false),
            field("evidence_event_ids_json", DataType::Utf8, false),
            field("attributes_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.edge_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.src_entity_id.as_str())),
            str_required(rows.iter().map(|r| r.dst_entity_id.as_str())),
            str_required(rows.iter().map(|r| r.edge_type.as_str())),
            str_optional(rows.iter().map(|r| r.first_seen_utc.as_deref())),
            str_optional(rows.iter().map(|r| r.last_seen_utc.as_deref())),
            f64_required(rows.iter().map(|r| r.confidence)),
            str_required(rows.iter().map(|r| r.evidence_event_ids_json.as_str())),
            str_required(rows.iter().map(|r| r.attributes_json.as_str())),
        ],
    )
}

pub fn write_findings(dir: &Path, rows: &[FindingRecord]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("detection_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("engine", DataType::Utf8, false),
            field("rule_id", DataType::Utf8, true),
            field("title", DataType::Utf8, false),
            field("severity", DataType::Utf8, false),
            field("attack_json", DataType::Utf8, false),
            field("event_ids_json", DataType::Utf8, false),
            field("entity_ids_json", DataType::Utf8, false),
            field("first_seen_utc", DataType::Utf8, true),
            field("message", DataType::Utf8, true),
            field("enrichment_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.detection_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.engine.as_str())),
            str_optional(rows.iter().map(|r| r.rule_id.as_deref())),
            str_required(rows.iter().map(|r| r.title.as_str())),
            str_required(rows.iter().map(|r| r.severity.as_str())),
            str_required(rows.iter().map(|r| r.attack_json.as_str())),
            str_required(rows.iter().map(|r| r.event_ids_json.as_str())),
            str_required(rows.iter().map(|r| r.entity_ids_json.as_str())),
            str_optional(rows.iter().map(|r| r.first_seen_utc.as_deref())),
            str_optional(rows.iter().map(|r| r.message.as_deref())),
            str_required(rows.iter().map(|r| r.enrichment_json.as_str())),
        ],
    )
}

pub fn write_answer_candidates(dir: &Path, rows: &[AnswerCandidate]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("candidate_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("question_key", DataType::Utf8, false),
            field("question_label", DataType::Utf8, false),
            field("candidate_value", DataType::Utf8, false),
            field("confidence", DataType::Float64, false),
            field("status", DataType::Utf8, false),
            field("severity", DataType::Utf8, false),
            field("category", DataType::Utf8, false),
            field("reason", DataType::Utf8, false),
            field("evidence_event_ids_json", DataType::Utf8, false),
            field("evidence_refs_json", DataType::Utf8, false),
            field("missing_steps_json", DataType::Utf8, false),
            field("next_action", DataType::Utf8, true),
            field("first_seen_utc", DataType::Utf8, true),
            field("last_seen_utc", DataType::Utf8, true),
            field("attributes_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.candidate_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.question_key.as_str())),
            str_required(rows.iter().map(|r| r.question_label.as_str())),
            str_required(rows.iter().map(|r| r.candidate_value.as_str())),
            f64_required(rows.iter().map(|r| r.confidence)),
            str_required(rows.iter().map(|r| r.status.as_str())),
            str_required(rows.iter().map(|r| r.severity.as_str())),
            str_required(rows.iter().map(|r| r.category.as_str())),
            str_required(rows.iter().map(|r| r.reason.as_str())),
            str_required(rows.iter().map(|r| r.evidence_event_ids_json.as_str())),
            str_required(rows.iter().map(|r| r.evidence_refs_json.as_str())),
            str_required(rows.iter().map(|r| r.missing_steps_json.as_str())),
            str_optional(rows.iter().map(|r| r.next_action.as_deref())),
            str_optional(rows.iter().map(|r| r.first_seen_utc.as_deref())),
            str_optional(rows.iter().map(|r| r.last_seen_utc.as_deref())),
            str_required(rows.iter().map(|r| r.attributes_json.as_str())),
        ],
    )
}

pub fn write_analyzer_runs(dir: &Path, rows: &[AnalyzerRunSummary]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("run_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("analyzer_id", DataType::Utf8, false),
            field("name", DataType::Utf8, false),
            field("version", DataType::Utf8, false),
            field("status", DataType::Utf8, false),
            field("started_at", DataType::Utf8, false),
            field("finished_at", DataType::Utf8, true),
            field("input_count", DataType::Int64, false),
            field("output_count", DataType::Int64, false),
            field("error_message", DataType::Utf8, true),
            field("metadata_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.run_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.analyzer_id.as_str())),
            str_required(rows.iter().map(|r| r.name.as_str())),
            str_required(rows.iter().map(|r| r.version.as_str())),
            str_required(rows.iter().map(|r| r.status.as_str())),
            str_required(rows.iter().map(|r| r.started_at.as_str())),
            str_optional(rows.iter().map(|r| r.finished_at.as_deref())),
            i64_required(rows.iter().map(|r| r.input_count)),
            i64_required(rows.iter().map(|r| r.output_count)),
            str_optional(rows.iter().map(|r| r.error_message.as_deref())),
            str_required(rows.iter().map(|r| r.metadata_json.as_str())),
        ],
    )
}

pub fn write_event_rows(dir: &Path, rows: &[EventRow]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("event_id", DataType::Utf8, false),
            field("case_id", DataType::Utf8, false),
            field("event_time_utc", DataType::Utf8, false),
            field("artifact_type", DataType::Utf8, false),
            field("host", DataType::Utf8, true),
            field("user_name", DataType::Utf8, true),
            field("process_name", DataType::Utf8, true),
            field("file_path", DataType::Utf8, true),
            field("ip", DataType::Utf8, true),
            field("url", DataType::Utf8, true),
            field("hash", DataType::Utf8, true),
            field("event_code", DataType::Utf8, true),
            field("channel", DataType::Utf8, true),
            field("level", DataType::Utf8, true),
            field("event_action", DataType::Utf8, false),
            field("severity", DataType::Utf8, false),
            field("message_short", DataType::Utf8, false),
            field("source_file_id", DataType::Utf8, false),
            field("parser_name", DataType::Utf8, false),
            field("has_finding", DataType::Boolean, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.event_id.as_str())),
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.event_time_utc.as_str())),
            str_required(rows.iter().map(|r| r.artifact_type.as_str())),
            str_optional(rows.iter().map(|r| r.host.as_deref())),
            str_optional(rows.iter().map(|r| r.user_name.as_deref())),
            str_optional(rows.iter().map(|r| r.process_name.as_deref())),
            str_optional(rows.iter().map(|r| r.file_path.as_deref())),
            str_optional(rows.iter().map(|r| r.ip.as_deref())),
            str_optional(rows.iter().map(|r| r.url.as_deref())),
            str_optional(rows.iter().map(|r| r.hash.as_deref())),
            str_optional(rows.iter().map(|r| r.event_code.as_deref())),
            str_optional(rows.iter().map(|r| r.channel.as_deref())),
            str_optional(rows.iter().map(|r| r.level.as_deref())),
            str_required(rows.iter().map(|r| r.event_action.as_str())),
            str_required(rows.iter().map(|r| r.severity.as_str())),
            str_required(rows.iter().map(|r| r.message_short.as_str())),
            str_required(rows.iter().map(|r| r.source_file_id.as_str())),
            str_required(rows.iter().map(|r| r.parser_name.as_str())),
            bool_required(rows.iter().map(|r| r.has_finding)),
        ],
    )
}

pub fn write_timeline_bins(dir: &Path, rows: &[TimelineBin]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("case_id", DataType::Utf8, false),
            field("granularity", DataType::Utf8, false),
            field("bin_start_utc", DataType::Utf8, false),
            field("artifact_type", DataType::Utf8, false),
            field("event_count", DataType::Int64, false),
            field("severity_max", DataType::Utf8, true),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.granularity.as_str())),
            str_required(rows.iter().map(|r| r.bin_start_utc.as_str())),
            str_required(rows.iter().map(|r| r.artifact_type.as_str())),
            i64_required(rows.iter().map(|r| r.event_count)),
            str_optional(rows.iter().map(|r| r.severity_max.as_deref())),
        ],
    )
}

pub fn write_correlation_chains(
    dir: &Path,
    rows: &[CorrelationChainSummary],
) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("case_id", DataType::Utf8, false),
            field("key_kind", DataType::Utf8, false),
            field("key_value", DataType::Utf8, false),
            field("title", DataType::Utf8, false),
            field("severity", DataType::Utf8, false),
            field("artifact_types", DataType::Utf8, false),
            field("event_count", DataType::Int64, false),
            field("step_count", DataType::Int64, false),
            field("first_seen_utc", DataType::Utf8, false),
            field("last_seen_utc", DataType::Utf8, false),
            field("severity_max", DataType::Utf8, true),
            field("score", DataType::Int64, false),
            field("explanation", DataType::Utf8, false),
            field("steps_json", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.key_kind.as_str())),
            str_required(rows.iter().map(|r| r.key_value.as_str())),
            str_required(rows.iter().map(|r| r.title.as_str())),
            str_required(rows.iter().map(|r| r.severity.as_str())),
            str_required(rows.iter().map(|r| r.artifact_types.as_str())),
            i64_required(rows.iter().map(|r| r.event_count)),
            i64_required(rows.iter().map(|r| r.step_count)),
            str_required(rows.iter().map(|r| r.first_seen_utc.as_str())),
            str_required(rows.iter().map(|r| r.last_seen_utc.as_str())),
            str_optional(rows.iter().map(|r| r.severity_max.as_deref())),
            i64_required(rows.iter().map(|r| r.score)),
            str_required(rows.iter().map(|r| r.explanation.as_str())),
            str_required(rows.iter().map(|r| r.steps_json.as_str())),
        ],
    )
}

pub fn write_coverage_summary(dir: &Path, rows: &[CoverageSummary]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("case_id", DataType::Utf8, false),
            field("artifact_type", DataType::Utf8, false),
            field("total_files", DataType::Int64, false),
            field("parsed_files", DataType::Int64, false),
            field("failed_files", DataType::Int64, false),
            field("unsupported_files", DataType::Int64, false),
            field("event_count", DataType::Int64, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.artifact_type.as_str())),
            i64_required(rows.iter().map(|r| r.total_files)),
            i64_required(rows.iter().map(|r| r.parsed_files)),
            i64_required(rows.iter().map(|r| r.failed_files)),
            i64_required(rows.iter().map(|r| r.unsupported_files)),
            i64_required(rows.iter().map(|r| r.event_count)),
        ],
    )
}

pub fn write_failed_parser_summary(
    dir: &Path,
    rows: &[FailedParserSummary],
) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("case_id", DataType::Utf8, false),
            field("parser_name", DataType::Utf8, false),
            field("artifact_type", DataType::Utf8, false),
            field("failure_count", DataType::Int64, false),
            field("last_error", DataType::Utf8, false),
            field("last_seen_at", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.parser_name.as_str())),
            str_required(rows.iter().map(|r| r.artifact_type.as_str())),
            i64_required(rows.iter().map(|r| r.failure_count)),
            str_required(rows.iter().map(|r| r.last_error.as_str())),
            str_required(rows.iter().map(|r| r.last_seen_at.as_str())),
        ],
    )
}

pub fn write_parser_errors(dir: &Path, rows: &[ParserErrorRecord]) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("case_id", DataType::Utf8, false),
            field("parse_run_id", DataType::Utf8, false),
            field("file_id", DataType::Utf8, false),
            field("parser_name", DataType::Utf8, false),
            field("error_message", DataType::Utf8, false),
            field("recorded_at", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.parse_run_id.as_str())),
            str_required(rows.iter().map(|r| r.file_id.as_str())),
            str_required(rows.iter().map(|r| r.parser_name.as_str())),
            str_required(rows.iter().map(|r| r.error_message.as_str())),
            str_required(rows.iter().map(|r| r.recorded_at.as_str())),
        ],
    )
}

pub fn write_unsupported_files(
    dir: &Path,
    rows: &[UnsupportedFileRecord],
) -> Result<Option<PathBuf>> {
    if rows.is_empty() {
        return Ok(None);
    }
    write_part(
        dir,
        schema(vec![
            field("case_id", DataType::Utf8, false),
            field("file_id", DataType::Utf8, false),
            field("artifact_type", DataType::Utf8, false),
            field("reason", DataType::Utf8, false),
            field("recorded_at", DataType::Utf8, false),
        ]),
        vec![
            str_required(rows.iter().map(|r| r.case_id.as_str())),
            str_required(rows.iter().map(|r| r.file_id.as_str())),
            str_required(rows.iter().map(|r| r.artifact_type.as_str())),
            str_required(rows.iter().map(|r| r.reason.as_str())),
            str_required(rows.iter().map(|r| r.recorded_at.as_str())),
        ],
    )
}
