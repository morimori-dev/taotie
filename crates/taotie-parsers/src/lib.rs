#![recursion_limit = "256"]

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::fs;
use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

use chrono::{DateTime, Datelike, Duration, NaiveDateTime, TimeZone, Utc};
use encoding_rs::SHIFT_JIS;
use evtx::{EvtxParser, SerializedEvtxRecord};
use flate2::read::GzDecoder;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use taotie_schema::{new_id, EventFull, RawRecord, CURRENT_SCHEMA_VERSION};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error("artifact is unsupported: {0}")]
    Unsupported(String),
    #[error("parse failed: {0}")]
    Failed(String),
}

pub type Result<T> = std::result::Result<T, ParserError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserMetadata {
    pub parser_name: String,
    pub parser_version: String,
    pub parser_config_hash: String,
    pub schema_version: String,
}

#[derive(Debug, Clone)]
pub struct ParserInput {
    pub case_id: String,
    pub source_file_id: String,
    pub object_ref: String,
    pub original_path: String,
    pub artifact_type: String,
    pub parse_run_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedArtifact {
    pub events: Vec<EventFull>,
    pub raw_records: Vec<RawRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParserOutcome {
    Parsed(ParsedArtifact),
    Unsupported { reason: String },
}

pub trait ParserAdapter: Send + Sync {
    fn metadata(&self) -> ParserMetadata;
    fn supports(&self, input: &ParserInput) -> bool;
    fn parse(&self, input: ParserInput) -> Result<ParserOutcome>;
}

#[derive(Debug, Default)]
pub struct FakeParser;

impl FakeParser {
    fn severity_for(line: &str) -> &'static str {
        let upper = line.to_ascii_uppercase();
        if upper.contains("ERROR") || upper.contains("FAIL") {
            "high"
        } else if upper.contains("WARN") {
            "medium"
        } else {
            "info"
        }
    }
}

impl ParserAdapter for FakeParser {
    fn metadata(&self) -> ParserMetadata {
        ParserMetadata {
            parser_name: "fake_text_parser".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            parser_config_hash: "default".to_string(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
        }
    }

    fn supports(&self, input: &ParserInput) -> bool {
        let lower = input.original_path.to_ascii_lowercase();
        lower.ends_with(".txt") || lower.ends_with(".log") || lower.ends_with(".fake")
    }

    fn parse(&self, input: ParserInput) -> Result<ParserOutcome> {
        if !self.supports(&input) {
            return Ok(ParserOutcome::Unsupported {
                reason: "fake parser supports only .txt, .log, and .fake files".to_string(),
            });
        }
        let text = std::str::from_utf8(&input.bytes)
            .map_err(|error| ParserError::Failed(format!("input is not utf-8: {error}")))?;
        let metadata = self.metadata();
        let mut events = Vec::new();
        let mut raw_records = Vec::new();
        let base_time = Utc::now();

        for (idx, line) in text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .enumerate()
        {
            let event_id = new_id("event");
            let raw_record_ref = new_id("rawrec");
            let event_time = base_time + Duration::seconds(idx as i64);
            let severity = Self::severity_for(line).to_string();
            let message_short = line.chars().take(120).collect::<String>();
            let raw_record_json = json!({
                "line_number": idx + 1,
                "line": line,
                "parser": metadata.parser_name,
                "object_ref": input.object_ref,
            })
            .to_string();

            events.push(EventFull {
                event_id: event_id.clone(),
                case_id: input.case_id.clone(),
                event_time_utc: event_time.to_rfc3339(),
                event_time_original: event_time.to_rfc3339(),
                time_kind: "textlog_line_timestamp".to_string(),
                time_confidence: 0.5,
                source_confidence: 0.7,
                artifact_type: input.artifact_type.clone(),
                source_file_id: input.source_file_id.clone(),
                parse_run_id: input.parse_run_id.clone(),
                parser_name: metadata.parser_name.clone(),
                parser_version: metadata.parser_version.clone(),
                schema_version: metadata.schema_version.clone(),
                evidence_ref: input.object_ref.clone(),
                host: Some("local".to_string()),
                user_name: None,
                process_name: None,
                file_path: Some(input.original_path.clone()),
                ip: None,
                url: None,
                hash: None,
                event_action: "observed".to_string(),
                severity,
                message_short,
                message_full: line.to_string(),
                raw_record_ref: raw_record_ref.clone(),
                attributes_json: json!({
                    "line_number": idx + 1,
                    "parser_mode": "fake"
                })
                .to_string(),
            });

            raw_records.push(RawRecord {
                raw_record_ref,
                case_id: input.case_id.clone(),
                event_id,
                parse_run_id: input.parse_run_id.clone(),
                source_file_id: input.source_file_id.clone(),
                evidence_ref: input.object_ref.clone(),
                raw_record_json,
            });
        }

        if events.is_empty() {
            return Err(ParserError::Failed(
                "fake parser found no non-empty lines".to_string(),
            ));
        }

        Ok(ParserOutcome::Parsed(ParsedArtifact {
            events,
            raw_records,
        }))
    }
}

#[derive(Debug, Default)]
pub struct StructuredArtifactParser;

impl ParserAdapter for StructuredArtifactParser {
    fn metadata(&self) -> ParserMetadata {
        ParserMetadata {
            parser_name: "structured_artifact_parser".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            parser_config_hash: "lite-safe-import".to_string(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
        }
    }

    fn supports(&self, input: &ParserInput) -> bool {
        !input.original_path.trim().is_empty()
    }

    fn parse(&self, input: ParserInput) -> Result<ParserOutcome> {
        if !self.supports(&input) {
            return Ok(ParserOutcome::Unsupported {
                reason: "structured parser requires an original evidence path".to_string(),
            });
        }
        let metadata = self.metadata();
        let path_artifact_type = input.artifact_type.clone();
        let lower = input.original_path.to_ascii_lowercase();

        if looks_like_gzip(&input) {
            return match decompress_gzip(&input.bytes) {
                Ok(bytes) => {
                    let parsed = if input.artifact_type == "onedrive_log"
                        || lower.contains("onedrive")
                    {
                        parse_onedrive_artifact(&input, &metadata, &bytes, decode_text(&bytes).ok())
                    } else if let Ok(text) = decode_text(&bytes) {
                        parse_text_lines_as(&input, &metadata, &text, "text_log", "observed")?
                    } else {
                        parse_database_artifact_strings_from_bytes(
                            &input,
                            &metadata,
                            &path_artifact_type,
                            &bytes,
                            "compressed_binary_string_signals",
                        )
                    };
                    Ok(ParserOutcome::Parsed(parsed))
                }
                Err(error) => Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                    &input,
                    &metadata,
                    &path_artifact_type,
                    "compressed_artifact_observed",
                    Some(format!("gzip decode failed: {error}")),
                ))),
            };
        }

        if looks_like_evtx_binary(&input.bytes) {
            return match parse_evtx_binary(&input, &metadata) {
                Ok(parsed) if !parsed.events.is_empty() => Ok(ParserOutcome::Parsed(parsed)),
                Ok(_) => Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                    &input,
                    &metadata,
                    "evtx",
                    "evtx_file_observed",
                    Some("native EVTX parser produced no records".to_string()),
                ))),
                Err(error) => Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                    &input,
                    &metadata,
                    "evtx",
                    "evtx_file_observed",
                    Some(format!("native EVTX parser failed: {error}")),
                ))),
            };
        }

        if looks_like_mft_binary(&input) {
            return match parse_mft_binary(&input, &metadata) {
                Ok(parsed) if !parsed.events.is_empty() => Ok(ParserOutcome::Parsed(parsed)),
                Ok(_) => Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                    &input,
                    &metadata,
                    "mft",
                    "mft_file_observed",
                    Some("native $MFT parser produced no records".to_string()),
                ))),
                Err(error) => Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                    &input,
                    &metadata,
                    "mft",
                    "mft_file_observed",
                    Some(format!("native $MFT parser failed: {error}")),
                ))),
            };
        }

        if path_artifact_type == "usn_jrnl" && looks_like_usn_journal_binary(&input) {
            return match parse_usn_jrnl_binary(&input, &metadata) {
                Ok(parsed) if !parsed.events.is_empty() => Ok(ParserOutcome::Parsed(parsed)),
                Ok(_) => Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                    &input,
                    &metadata,
                    "usn_jrnl",
                    "usn_journal_observed",
                    Some("native USN parser produced no records".to_string()),
                ))),
                Err(error) => Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                    &input,
                    &metadata,
                    "usn_jrnl",
                    "usn_journal_observed",
                    Some(format!("native USN parser failed: {error}")),
                ))),
            };
        }

        if (path_artifact_type == "prefetch"
            || input.artifact_type == "prefetch"
            || lower.ends_with(".pf")
            || lower.contains("/prefetch/")
            || lower.contains("\\prefetch\\"))
            && looks_like_prefetch_binary(&input.bytes)
        {
            return Ok(ParserOutcome::Parsed(parse_prefetch_binary(
                &input, &metadata,
            )));
        }

        if (path_artifact_type == "amcache" || lower.contains("amcache"))
            && input.bytes.starts_with(b"regf")
        {
            return Ok(ParserOutcome::Parsed(parse_registry_hive_strings(
                &input, &metadata, "amcache",
            )));
        }

        if path_artifact_type == "registry_hive" && input.bytes.starts_with(b"regf") {
            return Ok(ParserOutcome::Parsed(parse_registry_hive_strings(
                &input,
                &metadata,
                "registry_hive",
            )));
        }

        if path_artifact_type == "filezilla" && input.bytes.starts_with(b"SQLite format 3\0") {
            return Ok(ParserOutcome::Parsed(parse_filezilla_queue_metadata(
                &input, &metadata,
            )));
        }

        if path_artifact_type == "onedrive_log" {
            return Ok(ParserOutcome::Parsed(parse_onedrive_artifact(
                &input,
                &metadata,
                &input.bytes,
                decode_text_lossless(&input.bytes),
            )));
        }

        if path_artifact_type == "windows_search_log" || is_windows_search_log_path(&lower) {
            return Ok(ParserOutcome::Parsed(
                if let Some(text) = decode_text_lossless(&input.bytes) {
                    parse_windows_search_log(&input, &metadata, &text)
                } else {
                    parse_binary_text_log_signals(
                        &input,
                        &metadata,
                        "windows_search_log",
                        "windows_search_binary_string_signal",
                        20_000,
                    )
                },
            ));
        }

        if path_artifact_type == "network_capture" {
            return Ok(ParserOutcome::Parsed(parse_network_capture_signals(
                &input, &metadata,
            )));
        }

        if matches!(
            path_artifact_type.as_str(),
            "credential_store" | "document" | "archive"
        ) {
            return Ok(ParserOutcome::Parsed(parse_recovery_artifact_metadata(
                &input,
                &metadata,
                &path_artifact_type,
            )));
        }

        if path_artifact_type == "browser"
            && (input.bytes.starts_with(b"SQLite format 3\0")
                || decode_text_lossless(&input.bytes).is_none())
        {
            return Ok(ParserOutcome::Parsed(parse_database_artifact_strings(
                &input,
                &metadata,
                &path_artifact_type,
            )));
        }

        if matches!(
            path_artifact_type.as_str(),
            "web_cache" | "webcache" | "srum" | "ese" | "sqlite"
        ) {
            return Ok(ParserOutcome::Parsed(parse_database_artifact_strings(
                &input,
                &metadata,
                &path_artifact_type,
            )));
        }

        if path_artifact_type == "lnk" || lower.ends_with(".lnk") {
            return Ok(ParserOutcome::Parsed(parse_lnk_binary(&input, &metadata)));
        }

        if path_artifact_type == "jump_list" {
            return Ok(ParserOutcome::Parsed(parse_jump_list_strings(
                &input, &metadata,
            )));
        }

        if is_binary_metadata_artifact(&path_artifact_type) {
            return Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                &input,
                &metadata,
                &path_artifact_type,
                "binary_artifact_observed",
                Some("binary artifact kept as metadata to avoid lossy text decoding".to_string()),
            )));
        }

        if matches!(
            path_artifact_type.as_str(),
            "defender" | "defender_mplog" | "defender_operational"
        ) && decode_text_lossless(&input.bytes).is_none()
        {
            return Ok(ParserOutcome::Parsed(parse_binary_text_log_signals(
                &input,
                &metadata,
                "defender",
                "defender_binary_string_signal",
                20_000,
            )));
        }

        if let Some(text) = decode_text_lossless(&input.bytes) {
            let artifact_type = detect_structured_artifact(&input, &text);
            let parsed = match artifact_type.as_str() {
                "mft" => parse_mft_csv(&input, &metadata, &text)?,
                "evtx" => parse_evtx_text(&input, &metadata, &text)?,
                "prefetch" => parse_prefetch_export(&input, &metadata, &text)?,
                "amcache" => parse_amcache_export(&input, &metadata, &text)?,
                "usn_jrnl" | "usn" => parse_usn_export(&input, &metadata, &text)?,
                "browser" => parse_browser_export(&input, &metadata, &text)?,
                "filezilla" => parse_filezilla_artifact(&input, &metadata, &text),
                "network_capture" => parse_network_capture_signals(&input, &metadata),
                "credential_store" | "document" | "archive" => {
                    parse_recovery_artifact_metadata(&input, &metadata, &artifact_type)
                }
                "defender" | "defender_mplog" | "defender_operational" => {
                    parse_defender_export(&input, &metadata, &text)?
                }
                "scheduled_task" => parse_scheduled_task_xml(&input, &metadata, &text),
                "windows_search_log" => parse_windows_search_log(&input, &metadata, &text),
                "hayabusa" => parse_hayabusa_export(&input, &metadata, &text)?,
                "json" | "jsonl" => parse_json_events(&input, &metadata, &text, "json")?,
                "csv" => parse_evtx_csv(&input, &metadata, &text, "csv")?,
                "text_log" => parse_text_lines(&input, &metadata, &text)?,
                "onedrive_log" => {
                    parse_onedrive_artifact(&input, &metadata, &input.bytes, Some(text.clone()))
                }
                "config" | "script" | "stylesheet" | "html" | "xml" | "generic_text" => {
                    parse_text_document(&input, &metadata, &text, &artifact_type)
                }
                _ if is_text_artifact(&artifact_type) => {
                    parse_text_document(&input, &metadata, &text, &artifact_type)
                }
                _ => parse_file_metadata_event(
                    &input,
                    &metadata,
                    &artifact_type,
                    "artifact_file_observed",
                    None,
                ),
            };

            if !parsed.events.is_empty() {
                return Ok(ParserOutcome::Parsed(parsed));
            }

            return Ok(ParserOutcome::Parsed(parse_file_metadata_event(
                &input,
                &metadata,
                &artifact_type,
                "artifact_file_observed",
                Some("parser produced no records; metadata event emitted".to_string()),
            )));
        }

        Ok(ParserOutcome::Parsed(parse_file_metadata_event(
            &input,
            &metadata,
            &path_artifact_type,
            "artifact_file_observed",
            None,
        )))
    }
}

fn looks_like_evtx_binary(bytes: &[u8]) -> bool {
    bytes.starts_with(b"ElfFile")
}

fn looks_like_prefetch_binary(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MAM\x04") || bytes.get(4..8) == Some(b"SCCA") || bytes.starts_with(b"SCCA")
}

fn looks_like_mft_binary(input: &ParserInput) -> bool {
    let lower = input.original_path.to_ascii_lowercase();
    (lower.contains("$mft") || lower.contains("mft") || input.artifact_type == "mft")
        && input.bytes.starts_with(b"FILE")
}

fn looks_like_usn_journal(input: &ParserInput) -> bool {
    let lower = input.original_path.to_ascii_lowercase();
    input.artifact_type == "usn_jrnl" || lower.contains("$j") || lower.contains("usnjrnl")
}

fn looks_like_usn_journal_binary(input: &ParserInput) -> bool {
    if !looks_like_usn_journal(input) {
        return false;
    }
    let scan_limit = input.bytes.len().min(64 * 1024);
    let mut offset = 0usize;
    while offset + 60 <= scan_limit {
        if parse_usn_record_at(&input.bytes, offset, 1).is_some() {
            return true;
        }
        offset += 8;
    }
    false
}

fn looks_like_gzip(input: &ParserInput) -> bool {
    let lower = input.original_path.to_ascii_lowercase();
    input.bytes.starts_with(&[0x1f, 0x8b])
        || lower.ends_with(".gz")
        || lower.ends_with(".odlgz")
        || lower.ends_with(".loggz")
}

fn decompress_gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| ParserError::Failed(format!("gzip decode failed: {error}")))?;
    Ok(out)
}

fn decode_text(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&[0xff, 0xfe]) {
        return decode_utf16(
            bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])),
        );
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return decode_utf16(
            bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])),
        );
    }
    let zero_count = bytes.iter().take(256).filter(|byte| **byte == 0).count();
    if zero_count > 16 && bytes.len() % 2 == 0 {
        return decode_utf16(
            bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])),
        );
    }
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .or_else(|utf8_error| {
            let (decoded, _, had_errors) = SHIFT_JIS.decode(bytes);
            if had_errors {
                Err(ParserError::Failed(format!(
                    "input is not supported text: {utf8_error}"
                )))
            } else {
                Ok(decoded.into_owned())
            }
        })
}

fn decode_text_lossless(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        return decode_text(bytes).ok();
    }
    decode_text(bytes).ok().filter(|text| {
        let mut total = 0usize;
        let mut non_control = 0usize;
        let mut replacement = 0usize;
        let mut suspicious = 0usize;
        let mut signal = 0usize;
        for ch in text.chars() {
            total += 1;
            if !ch.is_control() || matches!(ch, '\n' | '\r' | '\t') {
                non_control += 1;
            }
            if ch == '\u{fffd}' {
                replacement += 1;
            }
            if ch == '\u{fffd}' || matches!(ch, '\u{0000}'..='\u{0008}' | '\u{000b}' | '\u{000c}' | '\u{000e}'..='\u{001f}' | '\u{007f}'..='\u{009f}') {
                suspicious += 1;
            }
            if ch.is_ascii_alphanumeric() || is_cjk_or_kana(ch) {
                signal += 1;
            }
        }
        let total = total.max(1);
        non_control * 100 / total >= 90
            && replacement * 100 / total <= 1
            && suspicious * 100 / total <= 5
            && (total < 80 || signal * 100 / total >= 10)
    })
}

fn decode_utf16(units: impl Iterator<Item = u16>) -> Result<String> {
    String::from_utf16(&units.collect::<Vec<_>>())
        .map_err(|error| ParserError::Failed(format!("input is not supported utf-16: {error}")))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u8(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_i64_le(bytes: &[u8], offset: usize) -> Option<i64> {
    Some(i64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

fn read_filetime_rfc3339(bytes: &[u8], offset: usize) -> Option<String> {
    let filetime = read_u64_le(bytes, offset)?;
    filetime_u64_rfc3339(filetime)
}

fn filetime_i64_rfc3339(filetime: i64) -> Option<String> {
    if filetime < 0 {
        return None;
    }
    filetime_u64_rfc3339(filetime as u64)
}

fn filetime_u64_rfc3339(filetime: u64) -> Option<String> {
    if filetime == 0 {
        return None;
    }
    let unix_100ns = filetime as i128 - 116_444_736_000_000_000i128;
    if unix_100ns < 0 {
        return None;
    }
    let seconds = (unix_100ns / 10_000_000) as i64;
    let nanos = ((unix_100ns % 10_000_000) as u32) * 100;
    Utc.timestamp_opt(seconds, nanos)
        .single()
        .map(|datetime| datetime.to_rfc3339())
}

fn is_cjk_or_kana(ch: char) -> bool {
    matches!(
        ch as u32,
        0x3040..=0x30ff | 0x3400..=0x9fff | 0xf900..=0xfaff | 0xff66..=0xff9f
    )
}

fn is_binary_metadata_artifact(artifact_type: &str) -> bool {
    matches!(
        artifact_type,
        "registry_hive"
            | "registry_log"
            | "srum"
            | "web_cache"
            | "webcache"
            | "jump_list"
            | "thumbcache"
            | "ese"
            | "sqlite"
            | "etl"
            | "ntfs_logfile"
            | "ntfs_boot"
            | "ntfs_secure"
            | "font"
            | "image"
            | "binary"
    )
}

fn is_text_artifact(artifact_type: &str) -> bool {
    matches!(
        artifact_type,
        "text_log"
            | "generic_text"
            | "config"
            | "script"
            | "stylesheet"
            | "html"
            | "xml"
            | "onedrive_log"
            | "windows_search_log"
            | "kape_log"
            | "cookie_text"
    )
}

fn is_windows_search_log_path(lower_path: &str) -> bool {
    let extension = extension_from_path(lower_path);
    if matches!(extension.as_deref(), Some("gthr" | "crwl")) {
        return true;
    }
    let in_search_tree = lower_path.contains("/programdata/microsoft/search/")
        || lower_path.contains("\\programdata\\microsoft\\search\\")
        || lower_path.contains("/microsoft/search/data/applications/windows/")
        || lower_path.contains("\\microsoft\\search\\data\\applications\\windows\\");
    in_search_tree
        && (lower_path.contains("/gatherlogs/")
            || lower_path.contains("\\gatherlogs\\")
            || matches!(
                extension.as_deref(),
                Some("jtx" | "jcp" | "jfm" | "log" | "txt")
            ))
}

fn detect_structured_artifact(input: &ParserInput, text: &str) -> String {
    let lower = input.original_path.to_ascii_lowercase();
    let header = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let header_norm = normalize_header(header);
    let sample = text
        .chars()
        .take(8192)
        .collect::<String>()
        .to_ascii_lowercase();
    let sample_norm = normalize_header(&sample);
    if input.artifact_type == "onedrive_log"
        || lower.contains("/onedrive/logs/")
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
    if input.artifact_type == "windows_search_log" || is_windows_search_log_path(&lower) {
        return "windows_search_log".to_string();
    }
    if input.artifact_type == "filezilla"
        || lower.contains("/filezilla/")
        || lower.contains("\\filezilla\\")
        || lower.ends_with("recentservers.xml")
        || lower.ends_with("filezilla.xml")
        || lower.ends_with("sitemanager.xml")
        || sample.contains("<filezilla3")
        || sample.contains("<recentservers>")
    {
        return "filezilla".to_string();
    }
    if input.artifact_type == "credential_store"
        || lower.ends_with("/login data")
        || lower.ends_with("\\login data")
        || lower.ends_with(".kdbx")
        || lower.contains("/microsoft/protect/")
        || lower.contains("\\microsoft\\protect\\")
    {
        return "credential_store".to_string();
    }
    if input.artifact_type == "document"
        || matches!(
            extension_from_path(&lower).as_deref(),
            Some("pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "rtf")
        )
    {
        return "document".to_string();
    }
    if input.artifact_type == "network_capture"
        || lower.ends_with(".pcap")
        || lower.ends_with(".pcapng")
    {
        return "network_capture".to_string();
    }
    if input.artifact_type == "archive"
        || matches!(
            extension_from_path(&lower).as_deref(),
            Some("zip" | "rar" | "7z" | "iso")
        )
    {
        return "archive".to_string();
    }
    if input.artifact_type == "lnk" || lower.ends_with(".lnk") {
        return "lnk".to_string();
    }
    if input.artifact_type == "jump_list"
        || lower.ends_with(".automaticdestinations-ms")
        || lower.ends_with(".customdestinations-ms")
    {
        return "jump_list".to_string();
    }
    if input.artifact_type == "scheduled_task"
        || lower.contains("/windows/system32/tasks/")
        || lower.contains("\\windows\\system32\\tasks\\")
        || ((sample.contains("<task") || sample.contains("taskversion"))
            && (sample.contains("<actions") || sample.contains("<exec"))
            && (sample.contains("<command") || sample.contains("<uri")))
    {
        return "scheduled_task".to_string();
    }
    if input.artifact_type == "amcache" || lower.contains("amcache") {
        return "amcache".to_string();
    }
    if input.artifact_type == "registry_hive"
        || lower.ends_with("ntuser.dat")
        || lower.ends_with("usrclass.dat")
        || lower.ends_with(".hve")
        || lower.ends_with("/sam")
        || lower.ends_with("/system")
        || lower.ends_with("/software")
        || lower.ends_with("/security")
    {
        return "registry_hive".to_string();
    }
    if input.artifact_type == "registry_log"
        || lower.ends_with(".dat.log1")
        || lower.ends_with(".dat.log2")
        || lower.ends_with(".log1")
        || lower.ends_with(".log2")
    {
        return "registry_log".to_string();
    }
    if input.artifact_type == "srum"
        || lower.contains("/sru/")
        || lower.contains("\\sru\\")
        || lower.contains("srudb.dat")
        || (lower.starts_with("sru") && lower.ends_with(".log"))
    {
        return "srum".to_string();
    }
    if matches!(input.artifact_type.as_str(), "web_cache" | "webcache")
        || lower.contains("/windows/webcache/")
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
    if input.artifact_type == "thumbcache" || lower.contains("thumbcache") {
        return "thumbcache".to_string();
    }
    if input.artifact_type == "ese"
        || lower.ends_with(".edb")
        || lower.ends_with(".jrs")
        || lower.ends_with(".chk")
    {
        return "ese".to_string();
    }
    if input.artifact_type == "etl" || lower.ends_with(".etl") {
        return "etl".to_string();
    }
    if input.artifact_type == "sqlite"
        || lower.ends_with(".sqlite")
        || lower.ends_with(".sqlite-wal")
        || lower.ends_with(".sqlite-shm")
        || lower.ends_with(".db")
        || lower.ends_with(".db-wal")
        || lower.ends_with(".db-shm")
        || lower.ends_with(".otc")
        || lower.ends_with(".otc-wal")
        || lower.ends_with(".otc-shm")
    {
        if lower.contains("firefox")
            || lower.contains("places.sqlite")
            || lower.contains("cookies.sqlite")
        {
            return "browser".to_string();
        }
        return "sqlite".to_string();
    }
    if input.artifact_type == "image"
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".png")
        || lower.ends_with(".gif")
        || lower.ends_with(".ico")
    {
        return "image".to_string();
    }
    if input.artifact_type == "font" || lower.ends_with(".woff") {
        return "font".to_string();
    }
    if lower.ends_with(".htm") || lower.ends_with(".html") {
        return "html".to_string();
    }
    if lower.ends_with(".js") || lower.ends_with(".map") {
        return "script".to_string();
    }
    if lower.ends_with(".css") {
        return "stylesheet".to_string();
    }
    if lower.ends_with(".ini") || lower.ends_with(".cfg") || lower.ends_with(".config") {
        return "config".to_string();
    }
    if input.artifact_type == "ntfs_metadata"
        || lower.contains("/$boot")
        || lower.contains("\\$boot")
        || lower.contains("/$logfile")
        || lower.contains("\\$logfile")
        || lower.contains("/$secure")
        || lower.contains("\\$secure")
    {
        return input.artifact_type.clone();
    }
    if input.artifact_type == "defender"
        || input.artifact_type == "defender_mplog"
        || input.artifact_type == "defender_operational"
        || lower.contains("mplog")
        || lower.contains("mpwpptracing")
        || lower.contains("mpoperational")
        || lower.contains("windows defender")
        || lower.contains("defender")
        || sample.contains("microsoft-windows-windows defender")
        || sample.contains("windows defender antivirus")
        || sample.contains("microsoft defender antivirus")
        || sample_norm.contains("threatname")
        || sample_norm.contains("mpoperationalevents")
    {
        if lower.contains("mplog")
            || lower.contains("mpwpptracing")
            || sample.contains("mpcmdrun")
            || sample.contains("msmpeng")
        {
            return "defender_mplog".to_string();
        }
        return "defender_operational".to_string();
    }
    if input.artifact_type == "hayabusa"
        || lower.contains("hayabusa")
        || sample.contains("\"ruletitle\"")
        || sample.contains("\"ruleauthor\"")
        || sample.contains("\"mitretactics\"")
        || (header_norm.contains("ruletitle")
            && header_norm.contains("level")
            && header_norm.contains("timestamp"))
        || (header_norm.contains("ruleauthor")
            && header_norm.contains("eventid")
            && header_norm.contains("timestamp"))
    {
        return "hayabusa".to_string();
    }
    if input.artifact_type == "prefetch"
        || lower.ends_with(".pf")
        || lower.contains("prefetch")
        || lower.contains("pecmd")
        || ((header_norm.contains("executable") || header_norm.contains("sourcefilename"))
            && (header_norm.contains("runcount")
                || header_norm.contains("lastrun")
                || header_norm.contains("previousrun")))
    {
        return "prefetch".to_string();
    }
    if input.artifact_type == "amcache"
        || ((header_norm.contains("sha1") || header_norm.contains("sha256"))
            && (header_norm.contains("programname")
                || header_norm.contains("filepath")
                || header_norm.contains("fullpath")
                || header_norm.contains("path")))
    {
        return "amcache".to_string();
    }
    if input.artifact_type == "usn"
        || input.artifact_type == "usn_jrnl"
        || lower.contains("usnjrnl")
        || lower.contains("$j")
        || (lower.contains("usn") && lower.ends_with(".csv"))
        || (header_norm.contains("usn")
            && header_norm.contains("reason")
            && (header_norm.contains("filename") || header_norm.contains("filereference")))
    {
        return "usn_jrnl".to_string();
    }
    if input.artifact_type == "browser"
        || lower.contains("browser")
        || lower.contains("places.sqlite")
        || (lower.contains("history") && lower.ends_with(".csv"))
        || (header_norm.contains("url")
            && (header_norm.contains("visit")
                || header_norm.contains("lastvisit")
                || header_norm.contains("title")))
    {
        return "browser".to_string();
    }
    if input.artifact_type == "mft"
        || lower.ends_with(".mft")
        || lower.contains("$mft")
        || lower.contains("mft")
        || (header_norm.contains("entrynumber") && header_norm.contains("sequence"))
        || (header_norm.contains("fullpath") && header_norm.contains("created0x10"))
    {
        return "mft".to_string();
    }
    if input.artifact_type == "evtx"
        || lower.ends_with(".evtx")
        || text.contains("<EventID")
        || text.contains("<Event ")
        || text.contains("<Event>")
        || header_norm.contains("eventid")
        || header_norm.contains("timecreated")
    {
        return "evtx".to_string();
    }
    if lower.ends_with(".jsonl") {
        return "jsonl".to_string();
    }
    if lower.ends_with(".json") {
        return "json".to_string();
    }
    if lower.ends_with(".csv") {
        return "csv".to_string();
    }
    if lower.ends_with(".txt") || lower.ends_with(".log") || lower.ends_with(".fake") {
        return "text_log".to_string();
    }
    if !text.trim().is_empty() {
        return "generic_text".to_string();
    }
    input.artifact_type.clone()
}

fn parse_evtx_text(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return parse_json_events(input, metadata, text, "evtx");
    }
    if text.contains("<Event") {
        return Ok(parse_evtx_xml(input, metadata, text));
    }
    parse_evtx_csv(input, metadata, text, "evtx")
}

pub fn parse_evtx_path(
    input: &ParserInput,
    metadata: &ParserMetadata,
    path: &Path,
) -> Result<ParsedArtifact> {
    let mut parser = match EvtxParser::from_path(path) {
        Ok(parser) => parser,
        Err(error) => {
            return Ok(parse_file_metadata_event(
                input,
                metadata,
                "evtx",
                "evtx_file_observed",
                Some(format!(
                    "native EVTX open failed for {}: {error}",
                    path.display()
                )),
            ));
        }
    };
    match parse_evtx_records(input, metadata, parser.records()) {
        Ok(parsed) if !parsed.events.is_empty() => Ok(parsed),
        Ok(_) => Ok(parse_file_metadata_event(
            input,
            metadata,
            "evtx",
            "evtx_file_observed",
            Some("native EVTX parser produced no records".to_string()),
        )),
        Err(error) => Ok(parse_file_metadata_event(
            input,
            metadata,
            "evtx",
            "evtx_file_observed",
            Some(format!(
                "native EVTX parser failed for {}: {error}",
                path.display()
            )),
        )),
    }
}

fn parse_evtx_binary(input: &ParserInput, metadata: &ParserMetadata) -> Result<ParsedArtifact> {
    let mut parser = EvtxParser::from_buffer(input.bytes.clone())
        .map_err(|error| ParserError::Failed(format!("native EVTX open failed: {error}")))?;
    parse_evtx_records(input, metadata, parser.records())
}

fn parse_evtx_records<I, E>(
    input: &ParserInput,
    metadata: &ParserMetadata,
    records: I,
) -> Result<ParsedArtifact>
where
    I: IntoIterator<Item = std::result::Result<SerializedEvtxRecord<String>, E>>,
    E: Display,
{
    let base_time = Utc::now();
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let mut parsed_count = 0usize;
    let mut failed_count = 0usize;
    let mut sample_errors = Vec::new();

    for record in records {
        match record {
            Ok(record) => {
                let (event, raw) = build_evtx_xml_event(
                    input,
                    metadata,
                    &record.data,
                    parsed_count,
                    &base_time,
                    "evtx_native",
                    Some(record.event_record_id),
                );
                events.push(event);
                raw_records.push(raw);
                if let Some((context_event, context_raw)) = build_evtx_context_event(
                    input,
                    metadata,
                    &record.data,
                    parsed_count,
                    &base_time,
                    "evtx_native",
                    Some(record.event_record_id),
                ) {
                    events.push(context_event);
                    raw_records.push(context_raw);
                }
                parsed_count += 1;
            }
            Err(error) => {
                failed_count += 1;
                if sample_errors.len() < 5 {
                    sample_errors.push(error.to_string());
                }
            }
        }
    }

    if parsed_count == 0 {
        return Err(ParserError::Failed(format!(
            "native EVTX parser produced no records; failed_records={failed_count}; errors={}",
            sample_errors.join(" | ")
        )));
    }

    if failed_count > 0 {
        for event in &mut events {
            let mut attrs =
                serde_json::from_str::<Value>(&event.attributes_json).unwrap_or_else(|_| json!({}));
            if let Some(map) = attrs.as_object_mut() {
                map.insert(
                    "evtx_native_failed_records".to_string(),
                    json!(failed_count),
                );
                map.insert(
                    "evtx_native_sample_errors".to_string(),
                    json!(sample_errors.clone()),
                );
            }
            event.attributes_json = attrs.to_string();
        }
    }

    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

pub fn parse_mft_path(
    input: &ParserInput,
    metadata: &ParserMetadata,
    path: &Path,
) -> Result<ParsedArtifact> {
    let mut file = File::open(path).map_err(|error| {
        ParserError::Failed(format!(
            "native $MFT open failed for {}: {error}",
            path.display()
        ))
    })?;
    let mut sample = vec![0u8; 1024 * 1024];
    let read = file
        .read(&mut sample)
        .map_err(|error| ParserError::Failed(format!("native $MFT sample read failed: {error}")))?;
    sample.truncate(read);
    let record_size = detect_mft_record_size(&sample).ok_or_else(|| {
        ParserError::Failed("native $MFT parser could not detect record size".to_string())
    })?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| ParserError::Failed(format!("native $MFT seek failed: {error}")))?;

    let mut records = Vec::new();
    let mut record_number = 0u64;
    loop {
        let mut buffer = vec![0u8; record_size];
        match file.read_exact(&mut buffer) {
            Ok(()) => {
                if let Some(record) = parse_mft_record(&buffer, record_number, record_size) {
                    records.push(record);
                }
                record_number += 1;
            }
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
            Err(error) => {
                return Err(ParserError::Failed(format!(
                    "native $MFT record read failed at record {record_number}: {error}"
                )));
            }
        }
    }
    Ok(mft_records_to_artifact(input, metadata, records))
}

fn parse_mft_binary(input: &ParserInput, metadata: &ParserMetadata) -> Result<ParsedArtifact> {
    let record_size = detect_mft_record_size(&input.bytes).ok_or_else(|| {
        ParserError::Failed("native $MFT parser could not detect record size".to_string())
    })?;
    let records = input
        .bytes
        .chunks_exact(record_size)
        .enumerate()
        .filter_map(|(idx, record)| parse_mft_record(record, idx as u64, record_size))
        .collect::<Vec<_>>();
    Ok(mft_records_to_artifact(input, metadata, records))
}

#[derive(Debug, Clone)]
struct MftNativeRecord {
    record_number: u64,
    record_offset: u64,
    record_size: usize,
    sequence_number: u16,
    in_use: bool,
    is_directory: bool,
    parent_record_number: Option<u64>,
    parent_sequence_number: Option<u16>,
    file_name: Option<String>,
    file_namespace: Option<u8>,
    file_attributes: Option<u32>,
    allocated_size: Option<u64>,
    file_size: Option<u64>,
    si_created: Option<String>,
    si_modified: Option<String>,
    si_record_changed: Option<String>,
    si_accessed: Option<String>,
    fn_created: Option<String>,
    fn_modified: Option<String>,
    fn_record_changed: Option<String>,
    fn_accessed: Option<String>,
    attribute_count: usize,
    attributes: Vec<MftAttributeSummary>,
    resident_contents: Vec<MftResidentContentSummary>,
    data_runs: Vec<MftDataRunSummary>,
}

#[derive(Debug, Clone)]
struct MftFileNameAttribute {
    parent_record_number: u64,
    parent_sequence_number: u16,
    file_name: String,
    namespace: u8,
    file_attributes: u32,
    allocated_size: u64,
    file_size: u64,
    created: Option<String>,
    modified: Option<String>,
    record_changed: Option<String>,
    accessed: Option<String>,
}

#[derive(Debug, Clone)]
struct MftAttributeSummary {
    type_name: &'static str,
    non_resident: bool,
}

#[derive(Debug, Clone)]
struct MftResidentContentSummary {
    attribute_id: Option<u16>,
    type_name: &'static str,
    name: Option<String>,
    value_offset: usize,
    value_length: usize,
    sha256: String,
    text_preview: Option<String>,
    host_url: Option<String>,
    zone_id: Option<String>,
    referrer_url: Option<String>,
    stream_kind: &'static str,
}

#[derive(Debug, Clone)]
struct MftDataRunSummary {
    vcn_start: u64,
    cluster_count: u64,
    lcn: Option<i64>,
    sparse: bool,
}

fn detect_mft_record_size(bytes: &[u8]) -> Option<usize> {
    let scored = [1024usize, 4096usize]
        .into_iter()
        .filter_map(|candidate| {
            if bytes.len() < candidate {
                return None;
            }
            let sampled = bytes.chunks_exact(candidate).take(256).collect::<Vec<_>>();
            if sampled.is_empty() {
                return None;
            }
            let file_count = sampled
                .iter()
                .filter(|chunk| chunk.starts_with(b"FILE"))
                .count();
            if file_count == 0 {
                return None;
            }
            let score = file_count.saturating_mul(10_000) / sampled.len();
            Some((score, std::cmp::Reverse(candidate), candidate))
        })
        .collect::<Vec<_>>();
    if scored
        .iter()
        .any(|(score, _, candidate)| *candidate == 1024 && *score >= 7_500)
    {
        return Some(1024);
    }
    scored
        .into_iter()
        .max_by_key(|(score, reverse_candidate, _)| (*score, *reverse_candidate))
        .map(|(_, _, candidate)| candidate)
}

fn parse_mft_record(
    record: &[u8],
    record_number: u64,
    record_size: usize,
) -> Option<MftNativeRecord> {
    if record.len() < 48 || !record.starts_with(b"FILE") {
        return None;
    }
    let fixed = apply_mft_fixup(record).unwrap_or_else(|| record.to_vec());
    let first_attr_offset = read_u16_le(&fixed, 0x14)? as usize;
    let flags = read_u16_le(&fixed, 0x16)?;
    let bytes_used = read_u32_le(&fixed, 0x18).unwrap_or(fixed.len() as u32) as usize;
    let sequence_number = read_u16_le(&fixed, 0x10).unwrap_or_default();
    let mut out = MftNativeRecord {
        record_number,
        record_offset: record_number.saturating_mul(record_size as u64),
        record_size,
        sequence_number,
        in_use: flags & 0x0001 != 0,
        is_directory: flags & 0x0002 != 0,
        parent_record_number: None,
        parent_sequence_number: None,
        file_name: None,
        file_namespace: None,
        file_attributes: None,
        allocated_size: None,
        file_size: None,
        si_created: None,
        si_modified: None,
        si_record_changed: None,
        si_accessed: None,
        fn_created: None,
        fn_modified: None,
        fn_record_changed: None,
        fn_accessed: None,
        attribute_count: 0,
        attributes: Vec::new(),
        resident_contents: Vec::new(),
        data_runs: Vec::new(),
    };
    let mut file_names = Vec::new();
    let mut data_size: Option<u64> = None;
    let mut data_allocated: Option<u64> = None;
    let mut offset = first_attr_offset;
    let attr_limit = bytes_used.min(fixed.len());
    while offset + 16 <= attr_limit {
        let attr_type = read_u32_le(&fixed, offset)?;
        if attr_type == 0xffff_ffff {
            break;
        }
        let attr_len = read_u32_le(&fixed, offset + 4)? as usize;
        if attr_len < 16 || offset + attr_len > fixed.len() {
            break;
        }
        out.attribute_count += 1;
        let non_resident = fixed.get(offset + 8).copied().unwrap_or(1) != 0;
        let name_len = fixed.get(offset + 9).copied().unwrap_or_default() as usize;
        let name_offset = read_u16_le(&fixed, offset + 10).unwrap_or_default() as usize;
        let attribute_id = read_u16_le(&fixed, offset + 14);
        let attr_name = read_mft_attribute_name(&fixed, offset, attr_len, name_len, name_offset);
        let attr_summary = MftAttributeSummary {
            type_name: mft_attribute_type_name(attr_type),
            non_resident,
        };
        if !non_resident && offset + 24 <= fixed.len() {
            let value_len = read_u32_le(&fixed, offset + 16).unwrap_or_default() as usize;
            let value_offset = read_u16_le(&fixed, offset + 20).unwrap_or_default() as usize;
            let value_start = offset + value_offset;
            let value_end = value_start.saturating_add(value_len);
            if value_start <= fixed.len() && value_end <= fixed.len() {
                let value = &fixed[value_start..value_end];
                if let Some(content) = summarize_mft_resident_content(
                    attr_type,
                    attribute_id,
                    attr_summary.type_name,
                    attr_name.clone(),
                    value_start,
                    value,
                ) {
                    out.resident_contents.push(content);
                }
                match attr_type {
                    0x10 => parse_mft_standard_information(value, &mut out),
                    0x30 => {
                        if let Some(file_name) = parse_mft_file_name_attribute(value) {
                            file_names.push(file_name);
                        }
                    }
                    _ => {}
                }
                if attr_type == 0x80 && name_len == 0 && data_size.is_none() {
                    // Resident unnamed $DATA: the file size is the resident value length.
                    data_size = Some(value_len as u64);
                }
            }
        } else if non_resident && offset + 64 <= fixed.len() {
            let run_offset = read_u16_le(&fixed, offset + 32).map(|value| value as usize);
            if attr_type == 0x80 {
                if name_len == 0 {
                    // Non-resident unnamed $DATA: real size (header offset 0x30) is the
                    // authoritative current file size; the $FILE_NAME copy is updated lazily
                    // by Windows and is frequently stale or 0.
                    if data_size.is_none() {
                        data_size = read_u64_le(&fixed, offset + 48);
                    }
                    if data_allocated.is_none() {
                        data_allocated = read_u64_le(&fixed, offset + 40);
                    }
                }
                if let Some(run_offset) = run_offset {
                    let runlist_start = offset.saturating_add(run_offset);
                    if runlist_start < offset + attr_len && runlist_start < fixed.len() {
                        out.data_runs.extend(parse_mft_data_runs(
                            &fixed[runlist_start..(offset + attr_len).min(fixed.len())],
                        ));
                    }
                }
            }
        }
        out.attributes.push(attr_summary);
        offset += attr_len;
    }
    if let Some(file_name) = select_mft_file_name(&file_names) {
        out.parent_record_number = Some(file_name.parent_record_number);
        out.parent_sequence_number = Some(file_name.parent_sequence_number);
        out.file_name = Some(file_name.file_name.clone());
        out.file_namespace = Some(file_name.namespace);
        out.file_attributes = Some(file_name.file_attributes);
        out.allocated_size = Some(file_name.allocated_size);
        out.file_size = Some(file_name.file_size);
        out.fn_created = file_name.created.clone();
        out.fn_modified = file_name.modified.clone();
        out.fn_record_changed = file_name.record_changed.clone();
        out.fn_accessed = file_name.accessed.clone();
    }
    // The unnamed $DATA attribute carries the authoritative current size; prefer it over the
    // $FILE_NAME size, which Windows updates lazily (often 0 / stale, e.g. small dropped webshells).
    if let Some(actual) = data_size {
        out.file_size = Some(actual);
    }
    if let Some(alloc) = data_allocated {
        out.allocated_size = Some(alloc);
    }
    Some(out)
}

fn apply_mft_fixup(record: &[u8]) -> Option<Vec<u8>> {
    let usa_offset = read_u16_le(record, 0x04)? as usize;
    let usa_count = read_u16_le(record, 0x06)? as usize;
    if usa_count < 2 || usa_offset + usa_count * 2 > record.len() {
        return None;
    }
    let mut fixed = record.to_vec();
    for sector_idx in 1..usa_count {
        let sector_end = sector_idx * 512;
        if sector_end < 2 || sector_end > fixed.len() {
            return None;
        }
        let replacement_start = usa_offset + sector_idx * 2;
        fixed[sector_end - 2] = record[replacement_start];
        fixed[sector_end - 1] = record[replacement_start + 1];
    }
    Some(fixed)
}

fn parse_mft_standard_information(value: &[u8], out: &mut MftNativeRecord) {
    if value.len() < 32 {
        return;
    }
    out.si_created = read_filetime_rfc3339(value, 0);
    out.si_modified = read_filetime_rfc3339(value, 8);
    out.si_record_changed = read_filetime_rfc3339(value, 16);
    out.si_accessed = read_filetime_rfc3339(value, 24);
    if value.len() >= 36 {
        out.file_attributes = read_u32_le(value, 32).or(out.file_attributes);
    }
}

fn parse_mft_file_name_attribute(value: &[u8]) -> Option<MftFileNameAttribute> {
    if value.len() < 66 {
        return None;
    }
    let parent_reference = read_u64_le(value, 0)?;
    let name_len = *value.get(64)? as usize;
    let namespace = *value.get(65)?;
    let name_start = 66usize;
    let name_end = name_start.checked_add(name_len.checked_mul(2)?)?;
    if name_end > value.len() {
        return None;
    }
    let name = decode_utf16le_lossy(&value[name_start..name_end]);
    if name.is_empty() {
        return None;
    }
    Some(MftFileNameAttribute {
        parent_record_number: file_reference_record_number(parent_reference),
        parent_sequence_number: file_reference_sequence_number(parent_reference),
        file_name: name,
        namespace,
        file_attributes: read_u32_le(value, 56).unwrap_or_default(),
        allocated_size: read_u64_le(value, 40).unwrap_or_default(),
        file_size: read_u64_le(value, 48).unwrap_or_default(),
        created: read_filetime_rfc3339(value, 8),
        modified: read_filetime_rfc3339(value, 16),
        record_changed: read_filetime_rfc3339(value, 24),
        accessed: read_filetime_rfc3339(value, 32),
    })
}

fn read_mft_attribute_name(
    record: &[u8],
    attr_offset: usize,
    attr_len: usize,
    name_len: usize,
    name_offset: usize,
) -> Option<String> {
    if name_len == 0 {
        return None;
    }
    let start = attr_offset.checked_add(name_offset)?;
    let byte_len = name_len.checked_mul(2)?;
    let end = start.checked_add(byte_len)?;
    if name_offset >= attr_len || end > attr_offset.saturating_add(attr_len) || end > record.len() {
        return None;
    }
    clean_opt(Some(decode_utf16le_lossy(&record[start..end])))
}

fn summarize_mft_resident_content(
    attr_type: u32,
    attribute_id: Option<u16>,
    type_name: &'static str,
    name: Option<String>,
    value_offset: usize,
    value: &[u8],
) -> Option<MftResidentContentSummary> {
    if attr_type != 0x80 || value.is_empty() || value.len() > 64 * 1024 {
        return None;
    }
    let text_preview = resident_text_preview(value);
    let named_stream = name.as_deref().is_some_and(|value| !value.is_empty());
    if !named_stream && text_preview.is_none() {
        return None;
    }
    let text_for_keys = text_preview.as_deref().unwrap_or_default();
    let host_url =
        ini_value(text_for_keys, "HostUrl").or_else(|| ini_value(text_for_keys, "HostURL"));
    let referrer_url =
        ini_value(text_for_keys, "ReferrerUrl").or_else(|| ini_value(text_for_keys, "ReferrerURL"));
    let zone_id = ini_value(text_for_keys, "ZoneId");
    let stream_kind = if named_stream { "ads" } else { "resident_data" };
    Some(MftResidentContentSummary {
        attribute_id,
        type_name,
        name,
        value_offset,
        value_length: value.len(),
        sha256: sha256_hex(value),
        text_preview,
        host_url,
        zone_id,
        referrer_url,
        stream_kind,
    })
}

fn resident_text_preview(value: &[u8]) -> Option<String> {
    if value.len() >= 4 && value.iter().step_by(2).filter(|byte| **byte != 0).count() > 2 {
        let odd_zero = value
            .iter()
            .skip(1)
            .step_by(2)
            .filter(|byte| **byte == 0)
            .count();
        if odd_zero.saturating_mul(2) >= value.len() / 2 {
            let text = decode_utf16le_lossy(value);
            return clean_resident_preview(&text);
        }
    }
    let printable = value
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if printable.saturating_mul(100) < value.len().saturating_mul(70) {
        return None;
    }
    let text = String::from_utf8_lossy(value);
    clean_resident_preview(&text)
}

fn clean_resident_preview(text: &str) -> Option<String> {
    let cleaned = text
        .chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.chars().take(4096).collect())
    }
}

fn ini_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let Some((left, right)) = line.split_once('=') else {
            continue;
        };
        if left.trim().eq_ignore_ascii_case(key) {
            return clean_opt(Some(right.trim().to_string()));
        }
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn select_mft_file_name(file_names: &[MftFileNameAttribute]) -> Option<&MftFileNameAttribute> {
    file_names
        .iter()
        .min_by_key(|file_name| match file_name.namespace {
            1 => 0,
            3 => 1,
            0 => 2,
            2 => 3,
            _ => 4,
        })
}

fn file_reference_record_number(reference: u64) -> u64 {
    reference & 0x0000_ffff_ffff_ffff
}

fn file_reference_sequence_number(reference: u64) -> u16 {
    (reference >> 48) as u16
}

fn mft_attribute_type_name(attr_type: u32) -> &'static str {
    match attr_type {
        0x10 => "STANDARD_INFORMATION",
        0x20 => "ATTRIBUTE_LIST",
        0x30 => "FILE_NAME",
        0x40 => "OBJECT_ID",
        0x50 => "SECURITY_DESCRIPTOR",
        0x60 => "VOLUME_NAME",
        0x70 => "VOLUME_INFORMATION",
        0x80 => "DATA",
        0x90 => "INDEX_ROOT",
        0xa0 => "INDEX_ALLOCATION",
        0xb0 => "BITMAP",
        0xc0 => "REPARSE_POINT",
        0xd0 => "EA_INFORMATION",
        0xe0 => "EA",
        0x100 => "LOGGED_UTILITY_STREAM",
        _ => "UNKNOWN",
    }
}

fn parse_mft_data_runs(bytes: &[u8]) -> Vec<MftDataRunSummary> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut current_lcn = 0i64;
    let mut current_vcn = 0u64;
    while cursor < bytes.len() && out.len() < 16 {
        let header = bytes[cursor];
        cursor += 1;
        if header == 0 {
            break;
        }
        let length_size = (header & 0x0f) as usize;
        let offset_size = (header >> 4) as usize;
        if length_size == 0 || length_size > 8 || offset_size > 8 {
            break;
        }
        if cursor + length_size + offset_size > bytes.len() {
            break;
        }
        let cluster_count = read_le_uint(&bytes[cursor..cursor + length_size]);
        cursor += length_size;
        let lcn_delta = if offset_size == 0 {
            None
        } else {
            Some(read_le_int(&bytes[cursor..cursor + offset_size]))
        };
        cursor += offset_size;
        let (lcn, sparse) = match lcn_delta {
            Some(delta) => {
                current_lcn = current_lcn.saturating_add(delta);
                (Some(current_lcn), false)
            }
            None => (None, true),
        };
        out.push(MftDataRunSummary {
            vcn_start: current_vcn,
            cluster_count,
            lcn,
            sparse,
        });
        current_vcn = current_vcn.saturating_add(cluster_count);
    }
    out
}

fn read_le_uint(bytes: &[u8]) -> u64 {
    let mut out = 0u64;
    for (idx, byte) in bytes.iter().copied().enumerate().take(8) {
        out |= (byte as u64) << (idx * 8);
    }
    out
}

fn read_le_int(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let unsigned = read_le_uint(bytes);
    let sign_bit = 1u64 << (bytes.len() * 8 - 1);
    if unsigned & sign_bit == 0 {
        unsigned as i64
    } else {
        let mask = if bytes.len() >= 8 {
            0
        } else {
            (!0u64) << (bytes.len() * 8)
        };
        (unsigned | mask) as i64
    }
}

fn mft_attribute_types(attributes: &[MftAttributeSummary]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for attribute in attributes {
        if !out.contains(&attribute.type_name) {
            out.push(attribute.type_name);
        }
    }
    out
}

fn mft_si_fn_timestamp_mismatch(record: &MftNativeRecord) -> bool {
    [
        (&record.si_created, &record.fn_created),
        (&record.si_modified, &record.fn_modified),
        (&record.si_record_changed, &record.fn_record_changed),
        (&record.si_accessed, &record.fn_accessed),
    ]
    .into_iter()
    .any(|(si, filename)| matches!((si, filename), (Some(si), Some(filename)) if si != filename))
}

const MFT_NATIVE_FULL_EVENT_RECORD_THRESHOLD: usize = 50_000;
const MFT_NATIVE_SELECTED_EVENT_RECORD_LIMIT: usize = 10_000;
const MFT_NATIVE_CORE_RECORD_SAMPLE_LIMIT: usize = 1_024;

fn mft_records_to_artifact(
    input: &ParserInput,
    metadata: &ParserMetadata,
    records: Vec<MftNativeRecord>,
) -> ParsedArtifact {
    let total_record_count = records.len();
    let selected_indices = select_mft_record_indices_for_events(&records);
    let selected_record_count = selected_indices.len();
    let path_map = mft_path_map(&records);
    let mut path_cache = HashMap::new();
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    if selected_record_count < total_record_count {
        push_mft_selection_summary_event(
            input,
            metadata,
            total_record_count,
            selected_record_count,
            &mut events,
            &mut raw_records,
        );
    }
    for record_index in selected_indices {
        let Some(record) = records.get(record_index) else {
            continue;
        };
        let path = mft_path_for_record(record.record_number, &path_map, &mut path_cache)
            .or_else(|| record.file_name.clone())
            .unwrap_or_else(|| format!("$MFT_RECORD_{}", record.record_number));
        let record_user = user_from_path(&path);
        let record_host = host_from_path(&input.original_path);
        let attribute_types = mft_attribute_types(&record.attributes);
        let data_run_count = record.data_runs.len();
        let non_resident_attribute_count = record
            .attributes
            .iter()
            .filter(|attribute| attribute.non_resident)
            .count();
        let first_data_run = record.data_runs.first();
        let first_data_run_lcn = first_data_run.and_then(|run| run.lcn);
        let first_data_run_cluster_count = first_data_run.map(|run| run.cluster_count);
        let first_data_run_vcn_start = first_data_run.map(|run| run.vcn_start);
        let sparse_data_run_count = record.data_runs.iter().filter(|run| run.sparse).count();
        let data_run_total_clusters = record
            .data_runs
            .iter()
            .map(|run| run.cluster_count)
            .sum::<u64>();
        let structure_available = !record.attributes.is_empty() || !record.data_runs.is_empty();
        let time_fields = [
            (
                record.si_created.clone(),
                "mft_created",
                "standard_information",
            ),
            (
                record.si_modified.clone(),
                "mft_modified",
                "standard_information",
            ),
            (
                record.si_record_changed.clone(),
                "mft_record_changed",
                "standard_information",
            ),
            (
                record.si_accessed.clone(),
                "mft_accessed",
                "standard_information",
            ),
            (
                record.fn_created.clone(),
                "mft_filename_created",
                "file_name",
            ),
            (
                record.fn_modified.clone(),
                "mft_filename_modified",
                "file_name",
            ),
            (
                record.fn_record_changed.clone(),
                "mft_filename_record_changed",
                "file_name",
            ),
            (
                record.fn_accessed.clone(),
                "mft_filename_accessed",
                "file_name",
            ),
        ];
        for (time, action, time_source) in time_fields {
            let Some(event_time) = time else {
                continue;
            };
            let deleted = !record.in_use;
            let si_fn_timestamp_mismatch = mft_si_fn_timestamp_mismatch(&record);
            let severity = if deleted { "medium" } else { "info" };
            let message_full = if deleted {
                format!("MFT {action}: record={} deleted=true", record.record_number)
            } else {
                format!("MFT {action}: record={}", record.record_number)
            };
            let attributes_json = json!({
                "parser_mode": "mft_native",
                "record_number": record.record_number,
                "record_offset": record.record_offset,
                "record_size": record.record_size,
                "sequence_number": record.sequence_number,
                "in_use": record.in_use,
                "deleted": deleted,
                "is_directory": record.is_directory,
                "parent_record_number": record.parent_record_number,
                "parent_sequence_number": record.parent_sequence_number,
                "file_attributes": record.file_attributes,
                "allocated_size": record.allocated_size,
                "file_size": record.file_size,
                "time_source": time_source,
                "attribute_count": record.attribute_count,
                "attribute_types": &attribute_types,
                "non_resident_attribute_count": non_resident_attribute_count,
                "data_run_count": data_run_count,
                "sparse_data_run_count": sparse_data_run_count,
                "data_run_total_clusters": data_run_total_clusters,
                "first_data_run_lcn": first_data_run_lcn,
                "first_data_run_cluster_count": first_data_run_cluster_count,
                "first_data_run_vcn_start": first_data_run_vcn_start,
                "structure_available": structure_available,
                "structure_inline": false,
                "structure_load_hint": "open event detail/evidence offsets for record-level structure",
                "si_fn_timestamp_mismatch": si_fn_timestamp_mismatch,
            })
            .to_string();
            let raw_json = json!({
                "parser_mode": "mft_native",
                "record_number": record.record_number,
                "record_offset": record.record_offset,
                "record_size": record.record_size,
                "sequence_number": record.sequence_number,
                "parent_record_number": record.parent_record_number,
                "parent_sequence_number": record.parent_sequence_number,
                "in_use": record.in_use,
                "is_directory": record.is_directory,
                "attribute_types": &attribute_types,
                "attribute_count": record.attribute_count,
                "non_resident_attribute_count": non_resident_attribute_count,
                "data_run_count": data_run_count,
                "sparse_data_run_count": sparse_data_run_count,
                "data_run_total_clusters": data_run_total_clusters,
                "first_data_run_lcn": first_data_run_lcn,
                "first_data_run_cluster_count": first_data_run_cluster_count,
                "first_data_run_vcn_start": first_data_run_vcn_start,
                "structure_available": structure_available,
                "structure_inline": false,
                "structure_load_hint": "record structure is summarized on the event row; raw record detail is intentionally compact",
                "time_source": time_source,
                "event_action": action,
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "mft",
                event_time.clone(),
                event_time,
                action,
                0.9,
                record_host.clone(),
                record_user.clone(),
                None,
                Some(path.clone()),
                None,
                None,
                None,
                action.to_string(),
                severity.to_string(),
                message_full,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
        }

        for content in record.resident_contents.iter().take(4) {
            let event_time = mft_resident_event_time(&record);
            let action = if content.stream_kind == "ads" {
                "mft_ads_resident_content_observed"
            } else {
                "mft_resident_data_observed"
            };
            let stream_path = content
                .name
                .as_deref()
                .map(|name| format!("{path}:{name}"))
                .unwrap_or_else(|| path.clone());
            let severity = if content.host_url.is_some() || content.stream_kind == "ads" {
                "medium"
            } else {
                "info"
            };
            let message_full = match (
                content.name.as_deref(),
                content.host_url.as_deref(),
                content.zone_id.as_deref(),
            ) {
                (Some(name), Some(host_url), zone_id) => format!(
                    "MFT ADS resident content observed: record={} stream={} HostUrl={} ZoneId={}",
                    record.record_number,
                    name,
                    host_url,
                    zone_id.unwrap_or("-")
                ),
                (Some(name), None, _) => format!(
                    "MFT ADS resident content observed: record={} stream={} length={}",
                    record.record_number, name, content.value_length
                ),
                (None, _, _) => format!(
                    "MFT resident DATA content observed: record={} length={}",
                    record.record_number, content.value_length
                ),
            };
            let attributes_json = json!({
                "parser_mode": "mft_native",
                "record_number": record.record_number,
                "record_offset": record.record_offset,
                "record_size": record.record_size,
                "sequence_number": record.sequence_number,
                "in_use": record.in_use,
                "deleted": !record.in_use,
                "is_directory": record.is_directory,
                "parent_record_number": record.parent_record_number,
                "parent_sequence_number": record.parent_sequence_number,
                "attribute_id": content.attribute_id,
                "attribute_type": content.type_name,
                "stream_name": content.name,
                "stream_kind": content.stream_kind,
                "resident_value_offset": content.value_offset,
                "resident_value_length": content.value_length,
                "resident_sha256": content.sha256,
                "text_preview": content.text_preview,
                "HostUrl": content.host_url,
                "ReferrerUrl": content.referrer_url,
                "ZoneId": content.zone_id,
                "structure_available": true,
                "structure_inline": true,
            })
            .to_string();
            let raw_json = json!({
                "parser_mode": "mft_native",
                "event_action": action,
                "record_number": record.record_number,
                "record_offset": record.record_offset,
                "record_size": record.record_size,
                "sequence_number": record.sequence_number,
                "attribute_id": content.attribute_id,
                "attribute_type": content.type_name,
                "stream_name": content.name,
                "stream_kind": content.stream_kind,
                "resident_value_offset": content.value_offset,
                "resident_value_length": content.value_length,
                "resident_sha256": content.sha256,
                "text_preview": content.text_preview,
                "HostUrl": content.host_url,
                "ReferrerUrl": content.referrer_url,
                "ZoneId": content.zone_id,
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "mft",
                event_time.clone(),
                event_time,
                action,
                0.75,
                record_host.clone(),
                record_user.clone(),
                None,
                Some(stream_path),
                None,
                content
                    .host_url
                    .clone()
                    .or_else(|| content.referrer_url.clone()),
                Some(content.sha256.clone()),
                action.to_string(),
                severity.to_string(),
                message_full,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
        }
    }
    ParsedArtifact {
        events,
        raw_records,
    }
}

fn select_mft_record_indices_for_events(records: &[MftNativeRecord]) -> Vec<usize> {
    if records.len() <= MFT_NATIVE_FULL_EVENT_RECORD_THRESHOLD {
        return (0..records.len()).collect();
    }

    let mut ranked = records
        .iter()
        .enumerate()
        .filter_map(|(idx, record)| {
            mft_record_event_priority(record, idx).map(|priority| (priority, idx))
        })
        .collect::<Vec<_>>();
    ranked.sort_unstable_by_key(|(priority, idx)| (*priority, *idx));
    ranked.truncate(MFT_NATIVE_SELECTED_EVENT_RECORD_LIMIT);
    let mut indices = ranked.into_iter().map(|(_, idx)| idx).collect::<Vec<_>>();
    indices.sort_unstable();
    indices
}

fn mft_record_event_priority(record: &MftNativeRecord, record_index: usize) -> Option<u8> {
    let filename = record.file_name.as_deref().unwrap_or_default();
    let lower = filename.to_ascii_lowercase();
    if record
        .resident_contents
        .iter()
        .any(|content| content.stream_kind == "ads" || content.host_url.is_some())
    {
        return Some(0);
    }
    if mft_filename_has_critical_name(&lower) {
        return Some(1);
    }
    if mft_filename_has_web_or_script_extension(&lower) {
        return Some(2);
    }
    if mft_filename_has_execution_or_archive_extension(&lower) {
        return Some(3);
    }
    if mft_filename_has_platform_binary_extension(&lower) {
        return Some(8);
    }
    if mft_si_fn_timestamp_mismatch(record) {
        return Some(10);
    }
    if !record.in_use && mft_filename_has_interesting_extension(&lower) {
        return Some(20);
    }
    if !record.in_use {
        return Some(30);
    }
    if record_index < MFT_NATIVE_CORE_RECORD_SAMPLE_LIMIT {
        return Some(80);
    }
    None
}

fn mft_filename_has_critical_name(lower: &str) -> bool {
    if lower.is_empty() {
        return false;
    }
    [
        "moveit",
        "move.aspx",
        "moveit.asp",
        "webshell",
        "shell",
        "payload",
        "beacon",
        "mimikatz",
        "rubeus",
        "sharphound",
        "bloodhound",
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "psexec",
        "procdump",
        "lsass",
        "ntds.dit",
        "sam",
        "system",
        "security",
        "consolehost_history",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn mft_filename_has_web_or_script_extension(lower: &str) -> bool {
    [
        ".aspx", ".asp", ".ashx", ".asmx", ".php", ".jsp", ".ps1", ".psm1", ".bat", ".cmd", ".vbs",
        ".vbe", ".js", ".jse", ".hta",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn mft_filename_has_execution_or_archive_extension(lower: &str) -> bool {
    [
        ".exe", ".msi", ".scr", ".lnk", ".pf", ".kdbx", ".zip", ".rar", ".7z", ".tar", ".gz",
        ".cab", ".evtx", ".dmp", ".kirbi", ".dit", ".config", ".history",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn mft_filename_has_platform_binary_extension(lower: &str) -> bool {
    [".dll", ".sys"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn mft_filename_has_interesting_extension(lower: &str) -> bool {
    mft_filename_has_web_or_script_extension(lower)
        || mft_filename_has_execution_or_archive_extension(lower)
        || mft_filename_has_platform_binary_extension(lower)
}

fn push_mft_selection_summary_event(
    input: &ParserInput,
    metadata: &ParserMetadata,
    total_record_count: usize,
    selected_record_count: usize,
    events: &mut Vec<EventFull>,
    raw_records: &mut Vec<RawRecord>,
) {
    let event_time = Utc::now().to_rfc3339();
    let omitted_record_count = total_record_count.saturating_sub(selected_record_count);
    let attributes_json = json!({
        "parser_mode": "mft_native",
        "record_selection": "priority_bounded",
        "total_record_count": total_record_count,
        "selected_record_count": selected_record_count,
        "omitted_record_count": omitted_record_count,
        "full_event_record_threshold": MFT_NATIVE_FULL_EVENT_RECORD_THRESHOLD,
        "selected_event_record_limit": MFT_NATIVE_SELECTED_EVENT_RECORD_LIMIT,
        "selection_policy": [
            "ADS/resident content",
            "high-value filenames and extensions",
            "SI/FN timestamp mismatch",
            "deleted records",
            "core metadata record sample"
        ],
    })
    .to_string();
    let raw_record_json = json!({
        "parser_mode": "mft_native",
        "event_action": "mft_native_selection_summary",
        "total_record_count": total_record_count,
        "selected_record_count": selected_record_count,
        "omitted_record_count": omitted_record_count,
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        "mft",
        event_time.clone(),
        event_time,
        "artifact_import_time",
        0.5,
        host_from_path(&input.original_path),
        None,
        None,
        Some(input.original_path.clone()),
        None,
        None,
        None,
        "mft_native_selection_summary".to_string(),
        "medium".to_string(),
        format!(
            "MFT native parser prioritized {selected_record_count}/{total_record_count} records for UI events; omitted={omitted_record_count}"
        ),
        attributes_json,
        raw_record_json,
    );
    events.push(event);
    raw_records.push(raw);
}

fn mft_resident_event_time(record: &MftNativeRecord) -> String {
    record
        .si_modified
        .clone()
        .or_else(|| record.fn_modified.clone())
        .or_else(|| record.si_created.clone())
        .or_else(|| record.fn_created.clone())
        .unwrap_or_else(|| "1970-01-01T00:00:00+00:00".to_string())
}

#[derive(Debug, Clone)]
struct MftPathEntry {
    sequence_number: u16,
    parent_record_number: Option<u64>,
    parent_sequence_number: Option<u16>,
    file_name: Option<String>,
}

fn mft_path_map(records: &[MftNativeRecord]) -> HashMap<u64, MftPathEntry> {
    records
        .iter()
        .map(|record| {
            (
                record.record_number,
                MftPathEntry {
                    sequence_number: record.sequence_number,
                    parent_record_number: record.parent_record_number,
                    parent_sequence_number: record.parent_sequence_number,
                    file_name: record.file_name.clone(),
                },
            )
        })
        .collect()
}

fn mft_path_for_record(
    record_number: u64,
    map: &HashMap<u64, MftPathEntry>,
    cache: &mut HashMap<u64, String>,
) -> Option<String> {
    let mut visiting = HashSet::new();
    mft_path_for_record_inner(record_number, map, cache, &mut visiting, 0)
}

fn mft_path_for_record_inner(
    record_number: u64,
    map: &HashMap<u64, MftPathEntry>,
    cache: &mut HashMap<u64, String>,
    visiting: &mut HashSet<u64>,
    depth: usize,
) -> Option<String> {
    if depth > 64 {
        return None;
    }
    if let Some(value) = cache.get(&record_number) {
        return Some(value.clone());
    }
    if !visiting.insert(record_number) {
        return None;
    }
    let result = (|| {
        let entry = map.get(&record_number)?;
        let name = entry.file_name.clone()?;
        if name == "." || entry.parent_record_number == Some(record_number) {
            return Some(String::new());
        }
        let parent_record = entry.parent_record_number.filter(|parent_record| {
            let Some(parent_entry) = map.get(parent_record) else {
                return false;
            };
            match entry.parent_sequence_number {
                Some(parent_sequence) => parent_sequence == parent_entry.sequence_number,
                None => false,
            }
        });
        let path = if let Some(parent_record) = parent_record {
            let parent_path =
                mft_path_for_record_inner(parent_record, map, cache, visiting, depth + 1);
            match parent_path {
                Some(parent_path) if parent_path.is_empty() => name.clone(),
                Some(parent_path) => format!("{parent_path}\\{name}"),
                None => name.clone(),
            }
        } else {
            name.clone()
        };
        Some(path)
    })();
    if let Some(path) = &result {
        cache.insert(record_number, path.clone());
    }
    visiting.remove(&record_number);
    result
}

pub fn parse_usn_jrnl_path(
    input: &ParserInput,
    metadata: &ParserMetadata,
    path: &Path,
) -> Result<ParsedArtifact> {
    let bytes = fs::read(path).map_err(|error| {
        ParserError::Failed(format!(
            "native USN journal read failed for {}: {error}",
            path.display()
        ))
    })?;
    parse_usn_jrnl_bytes(input, metadata, &bytes)
}

fn parse_usn_jrnl_binary(input: &ParserInput, metadata: &ParserMetadata) -> Result<ParsedArtifact> {
    parse_usn_jrnl_bytes(input, metadata, &input.bytes)
}

#[derive(Debug, Clone)]
struct UsnNativeRecord {
    record_index: usize,
    record_offset: usize,
    record_length: usize,
    major_version: u16,
    file_reference: u64,
    parent_file_reference: u64,
    usn: i64,
    timestamp: Option<String>,
    reason: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    file_name: String,
}

fn parse_usn_jrnl_bytes(
    input: &ParserInput,
    metadata: &ParserMetadata,
    bytes: &[u8],
) -> Result<ParsedArtifact> {
    let mut offset = 0usize;
    let mut records = Vec::new();
    while offset + 60 <= bytes.len() {
        if let Some((record, length)) = parse_usn_record_at(bytes, offset, records.len() + 1) {
            records.push(record);
            offset += length.max(8);
        } else {
            offset += 8;
        }
    }
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();
    for record in records {
        let event_time = record.timestamp.clone().unwrap_or_else(|| {
            (base_time + Duration::seconds(record.record_index as i64)).to_rfc3339()
        });
        let event_time_original = record.timestamp.clone().unwrap_or_default();
        let time_inferred = record.timestamp.is_none();
        let reason_text = usn_reason_flags(record.reason);
        let action = usn_action(Some(&reason_text));
        let severity = if matches!(action.as_str(), "usn_deleted" | "usn_renamed") {
            "medium"
        } else {
            "info"
        };
        let file_name = record.file_name.clone();
        let message_full = format!(
            "USN {action}: {} reason={} usn={}",
            file_name, reason_text, record.usn
        );
        let attributes_json = json!({
            "parser_mode": "usn_native",
            "record_index": record.record_index,
            "record_offset": record.record_offset,
            "record_length": record.record_length,
            "major_version": record.major_version,
            "file_reference": record.file_reference,
            "parent_file_reference": record.parent_file_reference,
            "usn": record.usn,
            "reason": reason_text,
            "reason_raw": record.reason,
            "source_info": record.source_info,
            "security_id": record.security_id,
            "file_attributes": record.file_attributes,
            "time_inferred": time_inferred,
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "usn_native",
            "record_index": record.record_index,
            "record_offset": record.record_offset,
            "record_length": record.record_length,
            "major_version": record.major_version,
            "file_reference": record.file_reference,
            "parent_file_reference": record.parent_file_reference,
            "file_name": file_name.clone(),
            "reason_raw": record.reason,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "usn_jrnl",
            event_time.clone(),
            event_time_original.clone(),
            "usn_timestamp",
            0.85,
            host_from_path(&input.original_path),
            user_from_path(&file_name),
            None,
            Some(file_name.clone()),
            None,
            None,
            None,
            action,
            severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);

        if record.parent_file_reference != 0 {
            let parent_message = format!(
                "USN parent link: parent_frn={} child_frn={} name={} usn={}",
                record.parent_file_reference, record.file_reference, file_name, record.usn
            );
            let parent_attributes_json = json!({
                "parser_mode": "usn_native_parent_reference",
                "record_index": record.record_index,
                "record_offset": record.record_offset,
                "record_length": record.record_length,
                "major_version": record.major_version,
                "file_reference": record.file_reference,
                "parent_file_reference": record.parent_file_reference,
                "usn": record.usn,
                "reason": reason_text,
                "reason_raw": record.reason,
                "source_info": record.source_info,
                "security_id": record.security_id,
                "file_attributes": record.file_attributes,
                "relationship": "parent_child",
                "time_inferred": time_inferred,
            })
            .to_string();
            let parent_raw_json = json!({
                "parser_mode": "usn_native_parent_reference",
                "record_index": record.record_index,
                "record_offset": record.record_offset,
                "record_length": record.record_length,
                "file_reference": record.file_reference,
                "parent_file_reference": record.parent_file_reference,
                "file_name": file_name.clone(),
                "reason_raw": record.reason,
            })
            .to_string();
            let (parent_event, parent_raw) = build_event(
                input,
                metadata,
                "usn_jrnl",
                event_time.clone(),
                event_time_original.clone(),
                "usn_parent_reference",
                0.8,
                host_from_path(&input.original_path),
                user_from_path(&file_name),
                None,
                Some(file_name.clone()),
                None,
                None,
                None,
                "usn_parent_reference_observed".to_string(),
                "info".to_string(),
                parent_message,
                parent_attributes_json,
                parent_raw_json,
            );
            events.push(parent_event);
            raw_records.push(parent_raw);
        }
    }
    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

fn parse_usn_record_at(
    bytes: &[u8],
    offset: usize,
    record_index: usize,
) -> Option<(UsnNativeRecord, usize)> {
    let length = read_u32_le(bytes, offset)? as usize;
    if !(60..=65536).contains(&length) || offset + length > bytes.len() {
        return None;
    }
    let major = read_u16_le(bytes, offset + 4)?;
    let minor = read_u16_le(bytes, offset + 6)?;
    if minor > 4 {
        return None;
    }
    let (
        file_reference,
        parent_file_reference,
        usn,
        timestamp_offset,
        reason_offset,
        source_offset,
        security_offset,
        attributes_offset,
        name_len_offset,
        name_offset_offset,
    ) = match major {
        2 => (
            read_u64_le(bytes, offset + 8)?,
            read_u64_le(bytes, offset + 16)?,
            read_i64_le(bytes, offset + 24)?,
            offset + 32,
            offset + 40,
            offset + 44,
            offset + 48,
            offset + 52,
            offset + 56,
            offset + 58,
        ),
        3 | 4 => (
            read_u64_le(bytes, offset + 8)?,
            read_u64_le(bytes, offset + 24)?,
            read_i64_le(bytes, offset + 40)?,
            offset + 48,
            offset + 56,
            offset + 60,
            offset + 64,
            offset + 68,
            offset + 72,
            offset + 74,
        ),
        _ => return None,
    };
    let name_len = read_u16_le(bytes, name_len_offset)? as usize;
    let name_offset = read_u16_le(bytes, name_offset_offset)? as usize;
    if name_len == 0 || name_len % 2 != 0 || name_offset + name_len > length {
        return None;
    }
    let name_start = offset + name_offset;
    let name_end = name_start + name_len;
    let file_name = decode_utf16le_lossy(&bytes[name_start..name_end]);
    if file_name.is_empty() {
        return None;
    }
    Some((
        UsnNativeRecord {
            record_index,
            record_offset: offset,
            record_length: length,
            major_version: major,
            file_reference: file_reference_record_number(file_reference),
            parent_file_reference: file_reference_record_number(parent_file_reference),
            usn,
            timestamp: read_filetime_rfc3339(bytes, timestamp_offset),
            reason: read_u32_le(bytes, reason_offset).unwrap_or_default(),
            source_info: read_u32_le(bytes, source_offset).unwrap_or_default(),
            security_id: read_u32_le(bytes, security_offset).unwrap_or_default(),
            file_attributes: read_u32_le(bytes, attributes_offset).unwrap_or_default(),
            file_name,
        },
        length,
    ))
}

fn usn_reason_flags(reason: u32) -> String {
    let mut out = Vec::new();
    for (flag, name) in [
        (0x0000_0001, "DATA_OVERWRITE"),
        (0x0000_0002, "DATA_EXTEND"),
        (0x0000_0004, "DATA_TRUNCATION"),
        (0x0000_0010, "NAMED_DATA_OVERWRITE"),
        (0x0000_0020, "NAMED_DATA_EXTEND"),
        (0x0000_0040, "NAMED_DATA_TRUNCATION"),
        (0x0000_0100, "FILE_CREATE"),
        (0x0000_0200, "FILE_DELETE"),
        (0x0000_0400, "EA_CHANGE"),
        (0x0000_0800, "SECURITY_CHANGE"),
        (0x0000_1000, "RENAME_OLD_NAME"),
        (0x0000_2000, "RENAME_NEW_NAME"),
        (0x0000_4000, "INDEXABLE_CHANGE"),
        (0x0000_8000, "BASIC_INFO_CHANGE"),
        (0x0001_0000, "HARD_LINK_CHANGE"),
        (0x0002_0000, "COMPRESSION_CHANGE"),
        (0x0004_0000, "ENCRYPTION_CHANGE"),
        (0x0008_0000, "OBJECT_ID_CHANGE"),
        (0x0010_0000, "REPARSE_POINT_CHANGE"),
        (0x0020_0000, "STREAM_CHANGE"),
        (0x8000_0000, "CLOSE"),
    ] {
        if reason & flag != 0 {
            out.push(name);
        }
    }
    if out.is_empty() {
        format!("0x{reason:08x}")
    } else {
        out.join("|")
    }
}

fn parse_evtx_xml(input: &ParserInput, metadata: &ParserMetadata, text: &str) -> ParsedArtifact {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for (idx, chunk) in xml_event_chunks(text).into_iter().enumerate() {
        let (event, raw) =
            build_evtx_xml_event(input, metadata, &chunk, idx, &base_time, "evtx_xml", None);
        events.push(event);
        raw_records.push(raw);
        if let Some((context_event, context_raw)) =
            build_evtx_context_event(input, metadata, &chunk, idx, &base_time, "evtx_xml", None)
        {
            events.push(context_event);
            raw_records.push(context_raw);
        }
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn build_evtx_xml_event(
    input: &ParserInput,
    metadata: &ParserMetadata,
    chunk: &str,
    idx: usize,
    base_time: &DateTime<Utc>,
    parser_mode: &str,
    native_record_id: Option<u64>,
) -> (EventFull, RawRecord) {
    let data = extract_named_data(chunk);
    let event_code = clean_opt(extract_xml_tag(chunk, "EventID"))
        .or_else(|| first_named(&data, &["EventID", "Id"]));
    let time_original = clean_opt(extract_xml_attr_in_tag(chunk, "TimeCreated", "SystemTime"))
        .or_else(|| first_named(&data, &["TimeCreated", "SystemTime", "UtcTime"]));
    let event_time = time_original
        .as_deref()
        .and_then(normalize_datetime)
        .unwrap_or_else(|| (base_time.clone() + Duration::seconds(idx as i64)).to_rfc3339());
    let host = clean_opt(extract_xml_tag(chunk, "Computer"))
        .or_else(|| first_named(&data, &["Computer", "MachineName", "Host"]));
    let provider = extract_xml_attr_in_tag(chunk, "Provider", "Name");
    let channel = extract_xml_tag(chunk, "Channel");
    let user_name = evtx_user_name(&data);
    let process_name = evtx_process_name(&data);
    let file_path = evtx_file_path(&data).or_else(|| process_name.clone());
    let ip = first_named(
        &data,
        &[
            "IpAddress",
            "SourceNetworkAddress",
            "ClientAddress",
            "SourceIp",
        ],
    );
    let url = first_named(
        &data,
        &["Url", "URL", "QueryName", "DestinationUrl", "SourceUrl"],
    );
    let hash = first_named(&data, &["Hash", "Hashes", "SHA256", "SHA1", "MD5"]);
    let action = windows_event_action_provider(event_code.as_deref(), provider.as_deref(), &data);
    let semantics = evtx_semantics(
        event_code.as_deref(),
        provider.as_deref(),
        channel.as_deref(),
        &data,
        &event_time,
        time_original.as_deref(),
    );
    let severity = evtx_semantic_severity(
        windows_event_severity(event_code.as_deref(), None),
        &semantics,
    )
    .to_string();
    let message_full = enrich_message_with_semantics(
        format_event_message(event_code.as_deref(), &action, &data),
        &semantics,
    );
    let record_id = extract_xml_tag(chunk, "EventRecordID")
        .or_else(|| native_record_id.map(|id| id.to_string()));
    let (process_id, process_guid, parent_process_id, parent_process_guid) =
        process_identity(&data);
    let attributes_json = json!({
        "event_id": event_code.clone(),
        "provider": provider.clone(),
        "record_id": record_id.clone(),
        "native_record_id": native_record_id,
        "channel": channel.clone(),
        "parent_process": first_named(&data, &["ParentImage", "ParentProcessName", "ParentCommandLine"]),
        "process_id": process_id,
        "process_guid": process_guid,
        "parent_process_id": parent_process_id,
        "parent_process_guid": parent_process_guid,
        "command_line": first_named(&data, &["CommandLine", "ProcessCommandLine"]),
        "logon_id": first_named(&data, &["LogonId", "TargetLogonId", "SubjectLogonId"]),
        "logon_type": first_named(&data, &["LogonType"]),
        "service_name": first_named(&data, &["ServiceName"]),
        "task_name": first_named(&data, &["TaskName", "TaskContent", "TaskName"]),
        "threat_name": first_named(&data, &["Threat Name", "ThreatName"]),
        "target_user": first_named(&data, &["TargetUserName", "TargetUserSid"]),
        "subject_user": first_named(&data, &["SubjectUserName", "SubjectUserSid"]),
        "semantics": semantics,
        "data": data,
        "parser_mode": parser_mode,
    })
    .to_string();
    let raw_json = json!({
        "record_index": idx + 1,
        "parser_mode": parser_mode,
        "native_record_id": native_record_id,
        "xml": chunk,
    })
    .to_string();
    build_event(
        input,
        metadata,
        "evtx",
        event_time,
        time_original.unwrap_or_default(),
        "evtx_time_created",
        0.95,
        host,
        user_name,
        process_name,
        file_path,
        ip,
        url,
        hash,
        action,
        severity,
        message_full,
        attributes_json,
        raw_json,
    )
}

fn build_evtx_context_event(
    input: &ParserInput,
    metadata: &ParserMetadata,
    chunk: &str,
    idx: usize,
    base_time: &DateTime<Utc>,
    parser_mode: &str,
    native_record_id: Option<u64>,
) -> Option<(EventFull, RawRecord)> {
    let data = extract_named_data(chunk);
    let event_code = clean_opt(extract_xml_tag(chunk, "EventID"))
        .or_else(|| first_named(&data, &["EventID", "Id"]));
    let provider = extract_xml_attr_in_tag(chunk, "Provider", "Name");
    let channel = extract_xml_tag(chunk, "Channel");
    let record_id = extract_xml_tag(chunk, "EventRecordID")
        .or_else(|| native_record_id.map(|id| id.to_string()));
    if event_code.is_none() && provider.is_none() && channel.is_none() && record_id.is_none() {
        return None;
    }
    let time_original = clean_opt(extract_xml_attr_in_tag(chunk, "TimeCreated", "SystemTime"))
        .or_else(|| first_named(&data, &["TimeCreated", "SystemTime", "UtcTime"]));
    let event_time = time_original
        .as_deref()
        .and_then(normalize_datetime)
        .unwrap_or_else(|| (base_time.clone() + Duration::seconds(idx as i64)).to_rfc3339());
    let host = clean_opt(extract_xml_tag(chunk, "Computer"))
        .or_else(|| first_named(&data, &["Computer", "MachineName", "Host"]));
    let user_name = evtx_user_name(&data);
    let process_name = evtx_process_name(&data);
    let file_path = evtx_file_path(&data).or_else(|| process_name.clone());
    let ip = first_named(
        &data,
        &[
            "IpAddress",
            "SourceNetworkAddress",
            "ClientAddress",
            "SourceIp",
        ],
    );
    let url = first_named(
        &data,
        &["Url", "URL", "QueryName", "DestinationUrl", "SourceUrl"],
    );
    let hash = first_named(&data, &["Hash", "Hashes", "SHA256", "SHA1", "MD5"]);
    let logon_id = first_named(&data, &["LogonId", "TargetLogonId", "SubjectLogonId"]);
    let service_name = first_named(&data, &["ServiceName"]);
    let task_name = first_named(&data, &["TaskName", "TaskContent"]);
    let threat_name = first_named(&data, &["Threat Name", "ThreatName"]);
    let mut data_keys = data.keys().cloned().collect::<Vec<_>>();
    data_keys.sort();
    let provider_label = provider.as_deref().unwrap_or("(unknown-provider)");
    let channel_label = channel.as_deref().unwrap_or("(unknown-channel)");
    let event_label = event_code.as_deref().unwrap_or("-");
    let record_label = record_id.as_deref().unwrap_or("-");
    let message_full = format!(
        "EVTX context indexed: provider={provider_label} channel={channel_label} eid={event_label} record_id={record_label}"
    );
    let attributes_json = json!({
        "parser_mode": format!("{parser_mode}_context"),
        "source_parser_mode": parser_mode,
        "event_id": event_code,
        "provider": provider,
        "record_id": record_id,
        "native_record_id": native_record_id,
        "channel": channel,
        "level": extract_xml_tag(chunk, "Level"),
        "task": extract_xml_tag(chunk, "Task"),
        "opcode": extract_xml_tag(chunk, "Opcode"),
        "keywords": extract_xml_tag(chunk, "Keywords"),
        "data_keys": data_keys.clone(),
        "entity_refs": {
            "user": user_name.clone(),
            "process": process_name.clone(),
            "file": file_path.clone(),
            "ip": ip.clone(),
            "url": url.clone(),
            "hash": hash.clone(),
            "logon_id": logon_id.clone(),
            "service_name": service_name.clone(),
            "task_name": task_name.clone(),
            "threat_name": threat_name.clone(),
        },
        "semantics": evtx_semantics(
            event_code.as_deref(),
            provider.as_deref(),
            channel.as_deref(),
            &data,
            &event_time,
            time_original.as_deref(),
        ),
        "time_inferred": time_original.is_none(),
    })
    .to_string();
    let raw_json = json!({
        "record_index": idx + 1,
        "parser_mode": format!("{parser_mode}_context"),
        "native_record_id": native_record_id,
        "event_id": event_code.clone(),
        "provider": provider.clone(),
        "record_id": record_id.clone(),
        "channel": channel.clone(),
        "data_keys": data_keys.clone(),
    })
    .to_string();
    Some(build_event(
        input,
        metadata,
        "evtx",
        event_time.clone(),
        time_original.unwrap_or_else(|| event_time.clone()),
        "evtx_record_context",
        0.9,
        host,
        user_name,
        process_name,
        file_path,
        ip,
        url,
        hash,
        "evtx_record_context_indexed".to_string(),
        "info".to_string(),
        message_full,
        attributes_json,
        raw_json,
    ))
}

fn parse_json_events(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
    artifact_type: &str,
) -> Result<ParsedArtifact> {
    let values = parse_json_values(text)?;
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for (idx, value) in values.iter().enumerate() {
        let mut flat = HashMap::new();
        flatten_json(value, &mut flat);
        let event_code = first_flat(&flat, &["eventid", "id", "eventcode"]);
        let time_original = first_flat(
            &flat,
            &[
                "timecreated",
                "systemtime",
                "utctime",
                "timestamp",
                "datetime",
                "eventtimeutc",
            ],
        );
        let event_time = time_original
            .as_deref()
            .and_then(normalize_datetime)
            .unwrap_or_else(|| (base_time + Duration::seconds(idx as i64)).to_rfc3339());
        let host = first_flat(&flat, &["computer", "machinename", "host", "hostname"]);
        let user_name = first_flat(
            &flat,
            &[
                "targetusername",
                "subjectusername",
                "accountname",
                "username",
                "user",
                "userid",
            ],
        );
        let process_name = first_flat(
            &flat,
            &[
                "newprocessname",
                "processname",
                "image",
                "application",
                "process",
                "sourceimage",
                "parentimage",
            ],
        )
        .and_then(|value| file_name_from_path(&value).or(Some(value)));
        let file_path = first_flat(
            &flat,
            &[
                "newprocessname",
                "processname",
                "image",
                "objectname",
                "targetfilename",
                "imageloaded",
                "path",
                "fullpath",
                "filepath",
                "sourceimage",
                "targetimage",
            ],
        )
        .or_else(|| process_name.clone());
        let ip = first_flat(
            &flat,
            &[
                "ipaddress",
                "sourcenetworkaddress",
                "clientaddress",
                "sourceip",
                "ip",
            ],
        );
        let level = first_flat(&flat, &["level", "leveldisplayname", "severity"]);
        let provider = first_flat(&flat, &["provider", "providername", "source"]);
        let action =
            windows_event_action_provider(event_code.as_deref(), provider.as_deref(), &flat);
        let channel = first_flat(&flat, &["channel", "logname"]);
        let semantics = evtx_semantics(
            event_code.as_deref(),
            provider.as_deref(),
            channel.as_deref(),
            &flat,
            &event_time,
            time_original.as_deref(),
        );
        let message_full = enrich_message_with_semantics(
            first_flat(&flat, &["message", "rendereddescription"])
                .unwrap_or_else(|| format_event_message(event_code.as_deref(), &action, &flat)),
            &semantics,
        );
        let severity = evtx_semantic_severity(
            windows_event_severity(event_code.as_deref(), level.as_deref()),
            &semantics,
        )
        .to_string();
        let url = first_flat(&flat, &["url", "queryname", "destinationurl", "sourceurl"]);
        let hash = first_flat(&flat, &["hash", "hashes", "sha256", "sha1", "md5"]);
        let (process_id, process_guid, parent_process_id, parent_process_guid) =
            process_identity(&flat);
        let attributes_json = json!({
            "event_id": event_code,
            "provider": provider,
            "record_id": first_flat(&flat, &["eventrecordid", "recordid"]),
            "channel": channel,
            "parent_process": first_flat(&flat, &["parentimage", "parentprocessname", "parentcommandline"]),
            "process_id": process_id,
            "process_guid": process_guid,
            "parent_process_id": parent_process_id,
            "parent_process_guid": parent_process_guid,
            "command_line": first_flat(&flat, &["commandline", "processcommandline"]),
            "logon_id": first_flat(&flat, &["logonid", "targetlogonid", "subjectlogonid"]),
            "logon_type": first_flat(&flat, &["logontype"]),
            "service_name": first_flat(&flat, &["servicename"]),
            "task_name": first_flat(&flat, &["taskname", "taskcontent"]),
            "threat_name": first_flat(&flat, &["threatname"]),
            "semantics": semantics,
            "parser_mode": "json",
        })
        .to_string();
        let raw_json = json!({
            "record_index": idx + 1,
            "parser_mode": "json",
            "record": value,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            artifact_type,
            event_time,
            time_original.unwrap_or_default(),
            "structured_json_timestamp",
            0.85,
            host,
            user_name,
            process_name,
            file_path,
            ip,
            url,
            hash,
            action,
            severity,
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

fn parse_evtx_csv(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
    artifact_type: &str,
) -> Result<ParsedArtifact> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let Some(header_line) = lines.next() else {
        return Ok(ParsedArtifact {
            events: Vec::new(),
            raw_records: Vec::new(),
        });
    };
    let headers = split_csv_line(header_line)
        .into_iter()
        .map(|header| normalize_header(&header))
        .collect::<Vec<_>>();
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for (idx, line) in lines.enumerate() {
        let cells = split_csv_line(line);
        let row = row_map(&headers, &cells);
        let event_code = cell(&row, &["eventid", "id", "eventcode"]);
        let time_original = cell(
            &row,
            &[
                "timecreated",
                "systemtime",
                "utctime",
                "timestamp",
                "datetime",
                "eventtimeutc",
            ],
        );
        let event_time = time_original
            .as_deref()
            .and_then(normalize_datetime)
            .unwrap_or_else(|| (base_time + Duration::seconds(idx as i64)).to_rfc3339());
        let host = cell(&row, &["computer", "machinename", "host", "hostname"]);
        let user_name = first_event_field(
            &row,
            &[
                "targetusername",
                "subjectusername",
                "accountname",
                "username",
                "user",
                "userid",
            ],
        );
        let process_name = first_event_field(
            &row,
            &[
                "newprocessname",
                "processname",
                "image",
                "application",
                "process",
                "sourceimage",
                "parentimage",
            ],
        )
        .and_then(|value| file_name_from_path(&value).or(Some(value)));
        let file_path = first_event_field(
            &row,
            &[
                "newprocessname",
                "processname",
                "image",
                "objectname",
                "targetfilename",
                "imageloaded",
                "path",
                "fullpath",
                "filepath",
                "sourceimage",
                "targetimage",
            ],
        )
        .or_else(|| process_name.clone());
        let ip = first_event_field(
            &row,
            &[
                "ipaddress",
                "sourcenetworkaddress",
                "clientaddress",
                "sourceip",
                "ip",
            ],
        );
        let level = cell(&row, &["level", "leveldisplayname", "severity"]);
        let provider = cell(&row, &["provider", "providername", "source"]);
        let action =
            windows_event_action_provider(event_code.as_deref(), provider.as_deref(), &row);
        let channel = cell(&row, &["channel", "logname"]);
        let semantics = evtx_semantics(
            event_code.as_deref(),
            provider.as_deref(),
            channel.as_deref(),
            &row,
            &event_time,
            time_original.as_deref(),
        );
        let severity = evtx_semantic_severity(
            windows_event_severity(event_code.as_deref(), level.as_deref()),
            &semantics,
        )
        .to_string();
        let message_full = joined_event_fields(
            &row,
            &[
                "message",
                "rendereddescription",
                "details",
                "extrafieldinfo",
            ],
        )
        .unwrap_or_else(|| format_event_message(event_code.as_deref(), &action, &row));
        let message_full = enrich_message_with_semantics(message_full, &semantics);
        let url = first_event_field(&row, &["url", "queryname", "destinationurl", "sourceurl"]);
        let hash = first_event_field(&row, &["hash", "hashes", "sha256", "sha1", "md5"])
            .or_else(|| extract_hash_like(&message_full));
        let (process_id, process_guid, parent_process_id, parent_process_guid) =
            process_identity(&row);
        let attributes_json = json!({
            "event_id": event_code,
            "provider": provider,
            "record_id": cell(&row, &["eventrecordid", "recordid"]),
            "channel": channel,
            "parent_process": cell(&row, &["parentimage", "parentprocessname", "parentcommandline"]),
            "process_id": process_id,
            "process_guid": process_guid,
            "parent_process_id": parent_process_id,
            "parent_process_guid": parent_process_guid,
            "command_line": cell(&row, &["commandline", "processcommandline"]),
            "logon_id": cell(&row, &["logonid", "targetlogonid", "subjectlogonid"]),
            "logon_type": cell(&row, &["logontype"]),
            "service_name": cell(&row, &["servicename"]),
            "task_name": cell(&row, &["taskname", "taskcontent"]),
            "threat_name": first_event_field(&row, &["ThreatName", "Threat Name", "Threat"]),
            "semantics": semantics,
            "data": row.clone(),
            "parser_mode": "csv",
        })
        .to_string();
        let raw_json = json!({
            "record_index": idx + 1,
            "parser_mode": "csv",
            "row": row,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            artifact_type,
            event_time,
            time_original.unwrap_or_default(),
            "structured_csv_timestamp",
            0.8,
            host,
            user_name,
            process_name,
            file_path,
            ip,
            url,
            hash,
            action,
            severity,
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

fn parse_hayabusa_export(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let values = parse_json_values(text)?;
        return Ok(parse_hayabusa_json_values(input, metadata, &values));
    }
    Ok(parse_hayabusa_csv(input, metadata, text))
}

fn parse_hayabusa_json_values(
    input: &ParserInput,
    metadata: &ParserMetadata,
    values: &[Value],
) -> ParsedArtifact {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();
    for (idx, value) in values.iter().enumerate() {
        let mut row = HashMap::new();
        flatten_json(value, &mut row);
        if let Some((event, raw)) = hayabusa_row_event(
            input,
            metadata,
            idx,
            &row,
            Some(value.clone()),
            base_time + Duration::seconds(idx as i64),
        ) {
            events.push(event);
            raw_records.push(raw);
        }
    }
    ParsedArtifact {
        events,
        raw_records,
    }
}

fn parse_hayabusa_csv(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> ParsedArtifact {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let Some(header_line) = lines.next() else {
        return ParsedArtifact {
            events: Vec::new(),
            raw_records: Vec::new(),
        };
    };
    let headers = split_csv_line(header_line)
        .into_iter()
        .map(|header| normalize_header(&header))
        .collect::<Vec<_>>();
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();
    for (idx, line) in lines.enumerate() {
        let cells = split_csv_line(line);
        let row = row_map(&headers, &cells);
        if let Some((event, raw)) = hayabusa_row_event(
            input,
            metadata,
            idx,
            &row,
            None,
            base_time + Duration::seconds(idx as i64),
        ) {
            events.push(event);
            raw_records.push(raw);
        }
    }
    ParsedArtifact {
        events,
        raw_records,
    }
}

fn hayabusa_row_event(
    input: &ParserInput,
    metadata: &ParserMetadata,
    idx: usize,
    row: &HashMap<String, String>,
    raw_value: Option<Value>,
    fallback_time: DateTime<Utc>,
) -> Option<(EventFull, RawRecord)> {
    let title = cell(row, &["RuleTitle", "Rule", "Title"])
        .or_else(|| cell(row, &["Detection", "RuleName"]))
        .unwrap_or_else(|| "Hayabusa Detection".to_string());
    let details = joined_event_fields(
        row,
        &[
            "Details",
            "Message",
            "ExtraFieldInfo",
            "RenderedDescription",
        ],
    )
    .unwrap_or_default();
    let timestamp = cell(
        row,
        &["Timestamp", "TimeCreated", "Datetime", "EventTimeUtc"],
    );
    let event_time = timestamp
        .as_deref()
        .and_then(normalize_datetime)
        .unwrap_or_else(|| fallback_time.to_rfc3339());
    let level = cell(row, &["Level", "Severity"]).unwrap_or_else(|| "informational".to_string());
    let event_code = cell(row, &["EventID", "EventId", "EventCode"]);
    let channel = cell(row, &["Channel"]);
    let host = cell(row, &["Computer", "Hostname", "Host"]);
    let user_name = first_event_field(
        row,
        &[
            "TargetUserName",
            "SubjectUserName",
            "AccountName",
            "UserName",
            "User",
        ],
    );
    let process_name = first_event_field(
        row,
        &[
            "ProcessName",
            "Image",
            "NewProcessName",
            "CommandLine",
            "Process",
        ],
    );
    let file_path = first_event_field(
        row,
        &[
            "TargetFilename",
            "ObjectName",
            "ImageLoaded",
            "FilePath",
            "Path",
        ],
    )
    .or_else(|| process_name.clone());
    let ip = first_event_field(
        row,
        &[
            "IpAddress",
            "SourceIp",
            "SourceNetworkAddress",
            "ClientAddress",
        ],
    );
    let url = first_event_field(
        row,
        &["Url", "URL", "QueryName", "DestinationUrl", "SourceUrl"],
    );
    let hash = first_event_field(row, &["Hash", "Hashes", "SHA256", "SHA1", "MD5"])
        .or_else(|| extract_hash_like(&details));
    let rule_id = cell(
        row,
        &[
            "RuleID",
            "RuleId",
            "RuleFile",
            "RulePath",
            "SigmaRuleID",
            "RuleAuthor",
        ],
    );
    let mitre_tactics = cell(row, &["MitreTactics", "MITRETactics", "Tactics"]);
    let mitre_tags = cell(row, &["MitreTags", "MITRE", "Tags", "Attack"]);
    let record_id = cell(row, &["RecordID", "EventRecordID"]);
    let message_full = if details.is_empty() {
        format!("Hayabusa: {title}")
    } else {
        format!("Hayabusa: {title} | {details}")
    };
    let semantics = evtx_semantics(
        event_code.as_deref(),
        None,
        channel.as_deref(),
        row,
        &event_time,
        timestamp.as_deref(),
    );
    let message_full = enrich_message_with_semantics(message_full, &semantics);
    let attributes_json = json!({
        "event_id": event_code,
        "channel": channel,
        "record_id": record_id,
        "parser_mode": "hayabusa",
        "rule_title": title,
        "rule_id": rule_id,
        "level": level,
        "mitre_tactics": mitre_tactics,
        "mitre_tags": mitre_tags,
        "threat_name": first_event_field(row, &["ThreatName", "Threat Name", "Threat"]),
        "hash": hash.clone(),
        "semantics": semantics,
        "data": row,
    })
    .to_string();
    let raw_json = json!({
        "record_index": idx + 1,
        "parser_mode": "hayabusa",
        "row": row,
        "record": raw_value,
    })
    .to_string();
    Some(build_event(
        input,
        metadata,
        "hayabusa",
        event_time,
        timestamp.unwrap_or_default(),
        "hayabusa_timestamp",
        0.9,
        host,
        user_name,
        process_name,
        file_path,
        ip,
        url,
        hash,
        "hayabusa_detection".to_string(),
        hayabusa_level_severity(&level).to_string(),
        message_full,
        attributes_json,
        raw_json,
    ))
}

fn hayabusa_level_severity(level: &str) -> &'static str {
    let level = level.to_ascii_lowercase();
    if level.starts_with("crit") {
        "critical"
    } else if level.starts_with("high") {
        "high"
    } else if level.starts_with("med") || level.contains("warn") {
        "medium"
    } else if level.starts_with("low") {
        "low"
    } else {
        "info"
    }
}

fn parse_mft_csv(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let Some(header_line) = lines.next() else {
        return Ok(ParsedArtifact {
            events: Vec::new(),
            raw_records: Vec::new(),
        });
    };
    let headers = split_csv_line(header_line)
        .into_iter()
        .map(|header| normalize_header(&header))
        .collect::<Vec<_>>();
    let time_columns = [
        ("created0x10", "mft_created"),
        ("lastmodified0x10", "mft_modified"),
        ("lastrecordchange0x10", "mft_record_changed"),
        ("lastaccess0x10", "mft_accessed"),
        ("created0x30", "mft_filename_created"),
        ("lastmodified0x30", "mft_filename_modified"),
        ("lastrecordchange0x30", "mft_filename_record_changed"),
        ("lastaccess0x30", "mft_filename_accessed"),
        ("sicreated", "mft_created"),
        ("silastmodified", "mft_modified"),
        ("silastrecordchange", "mft_record_changed"),
        ("silastaccess", "mft_accessed"),
        ("fncreated", "mft_filename_created"),
        ("fnlastmodified", "mft_filename_modified"),
        ("fnlastrecordchange", "mft_filename_record_changed"),
        ("fnlastaccess", "mft_filename_accessed"),
        ("created", "mft_created"),
        ("lastmodified", "mft_modified"),
        ("lastrecordchange", "mft_record_changed"),
        ("lastaccess", "mft_accessed"),
    ];
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for (idx, line) in lines.enumerate() {
        let cells = split_csv_line(line);
        let row = row_map(&headers, &cells);
        let file_path = cell(&row, &["fullpath", "path", "filepath", "filename", "name"])
            .unwrap_or_else(|| input.original_path.clone());
        let entry_number = cell(&row, &["entrynumber", "entry", "recordnumber"]);
        let sequence_number = cell(&row, &["sequencenumber", "sequence"]);

        for (column, action) in time_columns {
            let Some(time_original) = cell(&row, &[column]) else {
                continue;
            };
            let Some(event_time) = normalize_datetime(&time_original) else {
                continue;
            };
            let message_full = format!("{}: {}", action, file_path);
            let attributes_json = json!({
                "parser_mode": "mft_csv",
                "time_column": column,
                "entry_number": entry_number.clone(),
                "sequence_number": sequence_number.clone(),
            })
            .to_string();
            let raw_json = json!({
                "record_index": idx + 1,
                "parser_mode": "mft_csv",
                "time_column": column,
                "row": row.clone(),
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "mft",
                event_time,
                time_original,
                action,
                0.9,
                None,
                None,
                None,
                Some(file_path.clone()),
                None,
                None,
                None,
                action.to_string(),
                "info".to_string(),
                message_full,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
        }

        if events.is_empty() && idx == 0 {
            let event_time = base_time.to_rfc3339();
            let message_full = format!("MFT row observed: {}", file_path);
            let attributes_json = json!({
                "parser_mode": "mft_csv",
                "time_inferred": true,
            })
            .to_string();
            let raw_json = json!({
                "record_index": idx + 1,
                "parser_mode": "mft_csv",
                "row": row,
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "mft",
                event_time,
                String::new(),
                "mft_row_observed",
                0.3,
                None,
                None,
                None,
                Some(file_path.clone()),
                None,
                None,
                None,
                "mft_row_observed".to_string(),
                "info".to_string(),
                message_full,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
        }
    }

    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

#[derive(Debug, Clone)]
struct FlatExportRecord {
    record_index: usize,
    row: HashMap<String, String>,
    raw: Value,
    parser_mode: String,
}

fn parse_flat_export_records(text: &str, artifact_type: &str) -> Result<Vec<FlatExportRecord>> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return parse_json_values(text).map(|values| {
            values
                .into_iter()
                .enumerate()
                .map(|(idx, value)| {
                    let mut row = HashMap::new();
                    flatten_json(&value, &mut row);
                    FlatExportRecord {
                        record_index: idx + 1,
                        row,
                        raw: value,
                        parser_mode: format!("{artifact_type}_json"),
                    }
                })
                .collect()
        });
    }

    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let Some(header_line) = lines.next() else {
        return Ok(Vec::new());
    };
    let headers = split_csv_line(header_line)
        .into_iter()
        .map(|header| normalize_header(&header))
        .collect::<Vec<_>>();

    Ok(lines
        .enumerate()
        .map(|(idx, line)| {
            let cells = split_csv_line(line);
            let row = row_map(&headers, &cells);
            FlatExportRecord {
                record_index: idx + 1,
                raw: json!({ "row": row.clone() }),
                row,
                parser_mode: format!("{artifact_type}_csv"),
            }
        })
        .collect())
}

fn event_time_from_record(
    row: &HashMap<String, String>,
    keys: &[&str],
    base_time: DateTime<Utc>,
    record_index: usize,
) -> (String, String, f64) {
    let time_original = cell(row, keys).unwrap_or_default();
    if let Some(event_time) = normalize_datetime(&time_original) {
        return (event_time, time_original, 0.9);
    }
    (
        (base_time + Duration::seconds(record_index.saturating_sub(1) as i64)).to_rfc3339(),
        time_original,
        0.3,
    )
}

fn parse_prefetch_export(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let records = parse_flat_export_records(text, "prefetch")?;
    let time_columns = [
        ("lastrun", "prefetch_last_run"),
        ("lastruntime", "prefetch_last_run"),
        ("lastrun0", "prefetch_last_run"),
        ("previousrun0", "prefetch_previous_run"),
        ("previousrun1", "prefetch_previous_run"),
        ("previousrun2", "prefetch_previous_run"),
        ("previousrun3", "prefetch_previous_run"),
        ("previousrun4", "prefetch_previous_run"),
        ("previousrun5", "prefetch_previous_run"),
        ("previousrun6", "prefetch_previous_run"),
        ("previousrun7", "prefetch_previous_run"),
    ];
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for record in records {
        let executable = cell(
            &record.row,
            &[
                "executable",
                "executablename",
                "application",
                "processname",
                "filename",
                "sourcefilename",
                "path",
                "fullpath",
                "filepath",
            ],
        )
        .unwrap_or_else(|| input.original_path.clone());
        let file_path = cell(
            &record.row,
            &[
                "fullpath",
                "filepath",
                "path",
                "executable",
                "executablename",
                "filename",
                "sourcefilename",
            ],
        )
        .or_else(|| Some(executable.clone()));
        let process_name = cell(
            &record.row,
            &["executablename", "executable", "processname", "application"],
        )
        .or_else(|| file_name_from_path(&executable));
        let host = cell(
            &record.row,
            &["computername", "computer", "host", "hostname"],
        );
        let user_name = cell(&record.row, &["username", "user", "profile"]);
        let hash = cell(&record.row, &["hash", "sha1", "sha256", "md5"]);
        let run_count = cell(&record.row, &["runcount", "run_count"]);
        let run_count_value = run_count
            .as_deref()
            .and_then(|value| value.parse::<u32>().ok());
        let prefetch_file_name = cell(&record.row, &["sourcefilename"])
            .as_deref()
            .and_then(file_name_from_path)
            .or_else(|| file_name_from_path(&executable));
        let prefetch_hash = prefetch_file_name
            .as_deref()
            .or(Some(executable.as_str()))
            .and_then(prefetch_hash_from_filename);
        let referenced_files = prefetch_referenced_files_from_export_row(
            &record.row,
            file_path.as_deref(),
            &executable,
        );
        let referenced_file_count = referenced_files.len();
        let suspicion = prefetch_suspicion(
            process_name.as_deref().unwrap_or(executable.as_str()),
            &referenced_files,
        );
        let severity = prefetch_severity(suspicion.as_deref()).to_string();
        let mut emitted = false;

        for (column, time_kind) in time_columns {
            let Some(time_original) = cell(&record.row, &[column]) else {
                continue;
            };
            let Some(event_time) = normalize_datetime(&time_original) else {
                continue;
            };
            let target = process_name
                .as_deref()
                .or(file_path.as_deref())
                .unwrap_or(&executable);
            let message_full = if let Some(run_count) = &run_count {
                format!("Prefetch execution: {target} run_count={run_count}")
            } else {
                format!("Prefetch execution: {target}")
            };
            let attributes_json = json!({
                "parser_mode": record.parser_mode.clone(),
                "time_column": column,
                "run_count": run_count.clone(),
                "prefetch_file_name": prefetch_file_name.clone(),
                "prefetch_hash": prefetch_hash.clone(),
                "referenced_file_count": referenced_file_count,
                "referenced_files": referenced_files.clone(),
                "suspicion": suspicion.clone(),
                "source_filename": cell(&record.row, &["sourcefilename"]),
            })
            .to_string();
            let raw_json = json!({
                "record_index": record.record_index,
                "parser_mode": record.parser_mode.clone(),
                "record": record.raw.clone(),
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "prefetch",
                event_time,
                time_original,
                time_kind,
                0.95,
                host.clone(),
                user_name.clone(),
                process_name.clone(),
                file_path.clone(),
                None,
                None,
                hash.clone(),
                "process_executed".to_string(),
                severity.clone(),
                message_full,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
            emitted = true;
        }

        if !emitted {
            let (event_time, time_original, confidence) = event_time_from_record(
                &record.row,
                &[
                    "timestamp",
                    "datetime",
                    "time",
                    "sourcecreated",
                    "sourcemodified",
                ],
                base_time,
                record.record_index,
            );
            let target = process_name
                .as_deref()
                .or(file_path.as_deref())
                .unwrap_or(&executable);
            let message_full = format!("Prefetch execution observed: {target}");
            let attributes_json = json!({
                "parser_mode": record.parser_mode.clone(),
                "time_inferred": confidence < 0.9,
                "run_count": run_count.clone(),
                "prefetch_file_name": prefetch_file_name.clone(),
                "prefetch_hash": prefetch_hash.clone(),
                "referenced_file_count": referenced_file_count,
                "referenced_files": referenced_files.clone(),
                "suspicion": suspicion.clone(),
                "source_filename": cell(&record.row, &["sourcefilename"]),
            })
            .to_string();
            let raw_json = json!({
                "record_index": record.record_index,
                "parser_mode": record.parser_mode.clone(),
                "record": record.raw.clone(),
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "prefetch",
                event_time,
                time_original,
                "prefetch_observed",
                confidence,
                host.clone(),
                user_name.clone(),
                process_name.clone(),
                file_path.clone(),
                None,
                None,
                hash.clone(),
                "process_executed".to_string(),
                severity.clone(),
                message_full,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
        }
        if !referenced_files.is_empty() {
            let reference_time = events
                .last()
                .map(|event| event.event_time_utc.clone())
                .unwrap_or_else(|| Utc::now().to_rfc3339());
            append_prefetch_reference_events(
                input,
                metadata,
                &mut events,
                &mut raw_records,
                process_name.as_deref().unwrap_or(&executable),
                &referenced_files,
                &reference_time,
                prefetch_file_name.as_deref(),
                prefetch_hash.as_deref(),
                run_count_value,
                None,
            );
        }
    }

    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

fn parse_amcache_export(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let records = parse_flat_export_records(text, "amcache")?;
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for record in records {
        let file_path = cell(
            &record.row,
            &[
                "fullpath",
                "filepath",
                "path",
                "filename",
                "name",
                "programname",
                "value",
            ],
        )
        .unwrap_or_else(|| input.original_path.clone());
        let process_name = cell(
            &record.row,
            &[
                "programname",
                "executablename",
                "name",
                "filename",
                "productname",
            ],
        )
        .or_else(|| file_name_from_path(&file_path));
        let host = cell(
            &record.row,
            &["computername", "computer", "host", "hostname"],
        );
        let user_name = cell(&record.row, &["username", "user", "profile"]);
        let hash = cell(&record.row, &["sha1", "sha256", "md5", "hash"]);
        let (event_time, time_original, confidence) = event_time_from_record(
            &record.row,
            &[
                "lastwritetimestamp",
                "lastwrite",
                "lastmodified",
                "lastmodifiedtime",
                "timestamp",
                "datetime",
                "created",
                "firstseen",
            ],
            base_time,
            record.record_index,
        );
        let target = process_name.as_deref().unwrap_or(&file_path);
        let message_full = format!("Amcache program observed: {target}");
        let attributes_json = json!({
            "parser_mode": record.parser_mode.clone(),
            "time_inferred": confidence < 0.9,
            "product_name": cell(&record.row, &["productname"]),
            "publisher": cell(&record.row, &["publisher", "companyname"]),
        })
        .to_string();
        let raw_json = json!({
            "record_index": record.record_index,
            "parser_mode": record.parser_mode.clone(),
            "record": record.raw.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "amcache",
            event_time,
            time_original,
            "amcache_program_timestamp",
            confidence,
            host,
            user_name,
            process_name,
            Some(file_path),
            None,
            None,
            hash,
            "amcache_program_seen".to_string(),
            "info".to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

#[derive(Debug, Clone)]
struct RegistrySignal {
    action: &'static str,
    severity: &'static str,
    key_hint: String,
    value_hint: String,
    process_name: Option<String>,
    file_path: Option<String>,
    url: Option<String>,
    hash: Option<String>,
}

fn parse_registry_hive_strings(
    input: &ParserInput,
    metadata: &ParserMetadata,
    artifact_type: &str,
) -> ParsedArtifact {
    let strings = extract_forensic_strings(&input.bytes, 30_000);
    let signals = registry_signals_from_strings(&strings, artifact_type);
    if signals.is_empty() {
        return parse_file_metadata_event(
            input,
            metadata,
            artifact_type,
            "registry_hive_observed",
            Some("no high-value registry strings were classified".to_string()),
        );
    }

    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();
    for (idx, signal) in signals.into_iter().take(600).enumerate() {
        let event_time = (base_time + Duration::milliseconds(idx as i64)).to_rfc3339();
        let target = signal
            .file_path
            .as_deref()
            .or(signal.process_name.as_deref())
            .or(signal.url.as_deref())
            .unwrap_or(&signal.value_hint);
        let message_full = format!(
            "Registry signal: action={} target={} key_hint={}",
            signal.action, target, signal.key_hint
        );
        let attributes_json = json!({
            "parser_mode": "registry_hive_string_signals",
            "key_hint": signal.key_hint,
            "value_hint": signal.value_hint,
            "source_path": input.original_path,
            "time_inferred": true,
        })
        .to_string();
        let raw_json = json!({
            "record_index": idx + 1,
            "parser_mode": "registry_hive_string_signals",
            "key_hint": signal.key_hint,
            "value_hint": signal.value_hint,
            "object_ref": input.object_ref,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            artifact_type,
            event_time.clone(),
            event_time,
            "registry_hive_import_time",
            0.35,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            signal.process_name,
            signal
                .file_path
                .or_else(|| Some(input.original_path.clone())),
            None,
            signal.url,
            signal.hash,
            signal.action.to_string(),
            signal.severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn registry_signals_from_strings(strings: &[String], artifact_type: &str) -> Vec<RegistrySignal> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (idx, value) in strings.iter().enumerate() {
        let start = idx.saturating_sub(3);
        let end = (idx + 4).min(strings.len());
        let context = strings[start..end].join(" ");
        let hay = context.to_ascii_lowercase();
        let classes = classify_registry_context(&hay, artifact_type);
        if classes.is_empty() {
            continue;
        }
        for (action, severity) in classes {
            let file_path = match action {
                "registry_service_image" => {
                    extract_path_near_label(&context, &["ImagePath", "ServiceDll"])
                        .or_else(|| extract_path_like_candidates(&context).into_iter().last())
                }
                "amcache_program_seen" => extract_path_like_candidates(&context)
                    .into_iter()
                    .last()
                    .or_else(|| extract_path_like(&context)),
                "registry_recentdocs_document" => extract_recent_document_candidate(&context)
                    .or_else(|| extract_path_like_candidates(&context).into_iter().next()),
                "registry_shellbag_folder" => extract_shellbag_folder_candidate(&context)
                    .or_else(|| extract_path_like(&context)),
                _ => extract_path_like_candidates(&context)
                    .into_iter()
                    .next()
                    .or_else(|| extract_path_like(&context)),
            };
            let url = extract_url_like(&context);
            let hash = extract_hash_like(&context);
            let process_name = if matches!(
                action,
                "registry_recentdocs_document" | "registry_shellbag_folder"
            ) {
                None
            } else {
                file_path
                    .as_deref()
                    .and_then(file_name_from_path)
                    .or_else(|| extract_process_name_like(&context))
            };
            let key_hint = registry_key_hint(&context).unwrap_or_else(|| truncate(value, 180));
            let value_hint = truncate(&context, 300);
            let dedup_key = format!(
                "{}|{}|{}|{}",
                action,
                key_hint.to_ascii_lowercase(),
                file_path
                    .as_deref()
                    .or(process_name.as_deref())
                    .unwrap_or("")
                    .to_ascii_lowercase(),
                hash.as_deref().unwrap_or("")
            );
            if !seen.insert(dedup_key) {
                continue;
            }
            out.push(RegistrySignal {
                action,
                severity,
                key_hint,
                value_hint,
                process_name,
                file_path,
                url,
                hash,
            });
        }
    }
    out
}

fn classify_registry_context(hay: &str, artifact_type: &str) -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    if artifact_type == "amcache" || hay.contains("amcache") || hay.contains("\\programs\\") {
        if contains_any_text(hay, &[".exe", ".dll", ".sys", "sha1", "sha256"]) {
            out.push(("amcache_program_seen", "info"));
        }
    }
    if contains_any_text(
        hay,
        &["currentversion\\run", "currentversion\\\\run", "\\runonce"],
    ) {
        out.push(("registry_run_key_persistence", "high"));
    }
    if hay.contains("\\services\\") && contains_any_text(hay, &["imagepath", ".exe", ".dll"]) {
        out.push(("registry_service_image", "high"));
    }
    if hay.contains("winlogon") && contains_any_text(hay, &["shell", "userinit", ".exe"]) {
        out.push(("registry_winlogon_config", "high"));
    }
    if hay.contains("wdigest") || hay.contains("uselogoncredential") {
        out.push(("registry_wdigest_config", "critical"));
    }
    if hay.contains("userassist") && contains_any_text(hay, &[".exe", ".lnk"]) {
        out.push(("registry_userassist_execution", "medium"));
    }
    if contains_any_text(hay, &["shimcache", "appcompatcache"])
        && contains_any_text(hay, &[".exe", ".dll"])
    {
        out.push(("registry_shimcache_execution", "medium"));
    }
    if hay.contains("recentdocs")
        && contains_any_text(
            hay,
            &[
                ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".csv",
                ".zip", ".lnk",
            ],
        )
    {
        out.push(("registry_recentdocs_document", "info"));
    }
    if contains_any_text(hay, &["shellbags", "bagmru", "bags\\", "bags\\\\"])
        && (contains_any_text(
            hay,
            &["c:\\", "d:\\", "\\users\\", "\\desktop", "\\downloads"],
        ) || contains_any_text(hay, &["::{20d04fe0", "shell folder", "knownfolder"]))
    {
        out.push(("registry_shellbag_folder", "info"));
    }
    if contains_any_text(hay, &["typedurls", "typedpaths", "recentdocs", "mru"]) {
        out.push(("registry_user_activity", "info"));
    }
    if out.is_empty()
        && contains_any_text(
            hay,
            &[
                "powershell",
                "cmd.exe",
                "rundll32",
                "regsvr32",
                "mshta",
                "wscript",
                "cscript",
                "schtasks",
                "\\temp\\",
                "\\appdata\\",
                "\\programdata\\",
            ],
        )
    {
        out.push(("registry_suspicious_value", "high"));
    }
    out
}

fn parse_database_artifact_strings(
    input: &ParserInput,
    metadata: &ParserMetadata,
    artifact_type: &str,
) -> ParsedArtifact {
    parse_database_artifact_strings_from_bytes(
        input,
        metadata,
        artifact_type,
        &input.bytes,
        "database_string_signals",
    )
}

fn parse_onedrive_artifact(
    input: &ParserInput,
    metadata: &ParserMetadata,
    bytes: &[u8],
    text: Option<String>,
) -> ParsedArtifact {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let base_time = Utc::now();

    if let Some(text) = text.as_deref() {
        for (idx, clean_line) in text
            .lines()
            .map(sanitize_display_text)
            .filter(|line| !line.trim().is_empty())
            .enumerate()
        {
            let line = clean_line.as_str();
            let lower = line.to_ascii_lowercase();
            if !onedrive_line_interesting(&lower) && idx > 2_000 {
                continue;
            }
            let key = format!("line|{}", truncate(line, 240)).to_ascii_lowercase();
            if !seen.insert(key) {
                continue;
            }
            if events.len() >= 12_000 {
                break;
            }
            let (time_original, message) = split_leading_timestamp(line);
            let event_time = time_original
                .as_deref()
                .and_then(normalize_datetime)
                .unwrap_or_else(|| (base_time + Duration::milliseconds(idx as i64)).to_rfc3339());
            let url = extract_url_like(line);
            let file_path = extract_path_like(line).or_else(|| Some(input.original_path.clone()));
            let process_name = extract_process_name_like(line);
            let hash = extract_hash_like(line);
            let action = onedrive_action(&lower, url.as_deref(), file_path.as_deref());
            let severity = onedrive_severity(&lower, &action);
            let attributes_json = json!({
                "line_number": idx + 1,
                "parser_mode": "onedrive_text_line",
                "time_inferred": time_original.is_none(),
                "account_hint": onedrive_account_hint(line),
                "sync_scope": onedrive_scope_from_path(&input.original_path),
                "source_path": input.original_path,
            })
            .to_string();
            let raw_json = json!({
                "line_number": idx + 1,
                "parser_mode": "onedrive_text_line",
                "line": clean_line,
                "object_ref": input.object_ref.clone(),
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "onedrive_log",
                event_time.clone(),
                time_original.unwrap_or_else(|| event_time.clone()),
                "onedrive_log_timestamp",
                if line_timestamp_confident(line) {
                    0.7
                } else {
                    0.35
                },
                host_from_path(&input.original_path),
                user_from_path(&input.original_path),
                process_name,
                file_path,
                None,
                url,
                hash,
                action,
                severity.to_string(),
                message,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
        }
    }

    for (idx, value) in extract_forensic_strings(bytes, 80_000)
        .into_iter()
        .enumerate()
    {
        let clean = sanitize_display_text(&value);
        let lower = clean.to_ascii_lowercase();
        if !onedrive_line_interesting(&lower) {
            continue;
        }
        let key = format!("string|{}", truncate(&clean, 240)).to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        if events.len() >= 12_000 {
            break;
        }
        let url = extract_url_like(&clean);
        let file_path = extract_path_like(&clean).or_else(|| {
            if lower.contains("onedrive") || lower.contains("sync") {
                Some(input.original_path.clone())
            } else {
                None
            }
        });
        let process_name = extract_process_name_like(&clean);
        let hash = extract_hash_like(&clean);
        let action = onedrive_action(&lower, url.as_deref(), file_path.as_deref());
        let severity = onedrive_severity(&lower, &action);
        let event_time =
            (base_time + Duration::milliseconds((events.len() + idx) as i64)).to_rfc3339();
        let message_full = format!("OneDrive signal: {}", truncate(&clean, 300));
        let attributes_json = json!({
            "parser_mode": "onedrive_string_signal",
            "record_index": idx + 1,
            "time_inferred": true,
            "string": truncate(&clean, 1000),
            "account_hint": onedrive_account_hint(&clean),
            "sync_scope": onedrive_scope_from_path(&input.original_path),
            "source_path": input.original_path,
            "file_signature": artifact_signature(bytes),
        })
        .to_string();
        let raw_json = json!({
            "record_index": idx + 1,
            "parser_mode": "onedrive_string_signal",
            "string": truncate(&clean, 2000),
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "onedrive_log",
            event_time.clone(),
            event_time,
            "artifact_import_time",
            0.25,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            process_name,
            file_path,
            None,
            url,
            hash,
            action,
            severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if events.is_empty() {
        return parse_file_metadata_event(
            input,
            metadata,
            "onedrive_log",
            "onedrive_artifact_observed",
            Some("no high-value OneDrive strings were classified".to_string()),
        );
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn parse_database_artifact_strings_from_bytes(
    input: &ParserInput,
    metadata: &ParserMetadata,
    artifact_type: &str,
    bytes: &[u8],
    parser_mode: &str,
) -> ParsedArtifact {
    let normalized_artifact = match artifact_type {
        "webcache" => "web_cache",
        other => other,
    };
    let ese_structure = parse_ese_structure(bytes);
    let event_limit = database_event_limit(normalized_artifact);
    let strings = extract_forensic_strings(bytes, event_limit.saturating_mul(12).max(20_000));
    let mut seen = std::collections::HashSet::new();
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for value in strings {
        let lower = value.to_ascii_lowercase();
        let url = extract_url_like(&value);
        let domain = extract_domain_like(&value);
        let file_path = extract_path_like(&value);
        let process_name = file_path
            .as_deref()
            .and_then(file_name_from_path)
            .filter(|name| is_executable_name(name))
            .or_else(|| extract_process_name_like(&value));
        let hash = extract_hash_like(&value);
        let extra_string_signal =
            database_extra_string_interesting(normalized_artifact, &value, &lower);
        let interesting = url.is_some()
            || domain.is_some()
            || file_path.is_some()
            || process_name.is_some()
            || hash.is_some()
            || extra_string_signal
            || contains_any_text(
                &lower,
                &[
                    "download",
                    "visited",
                    "visit",
                    "connect",
                    "network",
                    "appresource",
                    "urlhistory",
                    "container_",
                    "cookie",
                    "cache",
                    "history",
                    "typed",
                    "sharepoint",
                    "onedrive",
                    "github",
                    "bing",
                    "msn",
                ],
            );
        if !interesting {
            continue;
        }
        let action = database_string_action(
            normalized_artifact,
            &lower,
            url.as_deref(),
            process_name.as_deref(),
        );
        let dedup_key = format!(
            "{}|{}|{}|{}",
            normalized_artifact,
            action,
            url.as_deref()
                .or(file_path.as_deref())
                .or(domain.as_deref())
                .or(process_name.as_deref())
                .or(hash.as_deref())
                .unwrap_or(""),
            truncate(&value, 80)
        )
        .to_ascii_lowercase();
        if !seen.insert(dedup_key) {
            continue;
        }
        let idx = events.len();
        if idx >= event_limit {
            break;
        }
        let event_time = (base_time + Duration::milliseconds(idx as i64)).to_rfc3339();
        let target = url
            .as_deref()
            .or(file_path.as_deref())
            .or(domain.as_deref())
            .or(process_name.as_deref())
            .or(hash.as_deref())
            .unwrap_or(&value);
        let message_full = format!("{normalized_artifact} signal: {target}");
        let attributes_json = json!({
            "parser_mode": parser_mode,
            "source_path": input.original_path,
            "string": truncate(&value, 500),
            "string_class": database_string_class(normalized_artifact, &value, &lower),
            "domain": domain,
            "ese_page_size": ese_structure.page_size,
            "ese_page_count": ese_structure.page_count,
            "ese_header": ese_structure.header_json(),
            "ese_pages": ese_structure.pages_json(),
            "time_inferred": true,
        })
        .to_string();
        let raw_json = json!({
            "record_index": idx + 1,
            "parser_mode": parser_mode,
            "string": truncate(&value, 1000),
            "ese_page_size": ese_structure.page_size,
            "ese_page_count": ese_structure.page_count,
            "ese_pages": ese_structure.pages_json(),
            "object_ref": input.object_ref,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            normalized_artifact,
            event_time.clone(),
            event_time,
            "artifact_import_time",
            0.25,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            process_name,
            file_path.or_else(|| Some(input.original_path.clone())),
            None,
            url,
            hash,
            action.to_string(),
            database_signal_severity(normalized_artifact, &lower).to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if events.is_empty() {
        return parse_file_metadata_event(
            input,
            metadata,
            normalized_artifact,
            "binary_artifact_observed",
            Some("no high-value database strings were classified".to_string()),
        );
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn database_event_limit(artifact_type: &str) -> usize {
    match artifact_type {
        "web_cache" | "browser" => 8_000,
        "srum" => 12_000,
        "ese" => 5_000,
        "sqlite" => 4_000,
        _ => 1_000,
    }
}

fn database_extra_string_interesting(artifact_type: &str, value: &str, lower: &str) -> bool {
    match artifact_type {
        "srum" => srum_string_signal_interesting(value, lower),
        "web_cache" | "browser" => {
            lower.contains("container_")
                || lower.contains("urlhistory")
                || lower.contains("iedownload")
                || lower.contains("msedge")
                || lower.contains("chrome")
                || lower.contains("visited:")
                || web_cache_string_surface_signal(value, lower)
        }
        "sqlite" => {
            lower.contains("sqlite_master")
                || lower.contains("downloads")
                || lower.contains("urls")
                || lower.contains("visits")
                || lower.contains("logins")
                || lower.contains("cookies")
        }
        _ => false,
    }
}

fn srum_string_signal_interesting(value: &str, lower: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 4 || matches!(lower, "en-us" | "msysobjects" | "msysobjectsshadow") {
        return false;
    }
    looks_like_path(trimmed)
        || looks_like_url(trimmed)
        || extract_process_name_like(trimmed).is_some()
        || lower.contains(".exe")
        || lower.contains("appresource")
        || lower.contains("network")
        || lower.contains("connect")
        || lower.contains("energy")
        || lower.contains("interface")
        || lower.contains("resource")
        || lower.contains("application")
        || lower.contains("package")
        || lower.contains("appx")
        || lower.contains("sid")
        || lower.contains("user")
        || lower.contains("sru")
        || lower.contains("srum")
        || lower.contains("autoinc")
        || lower.contains("recordoffset")
        || lower.contains("timestamp")
        || trimmed.contains('{')
        || trimmed.contains('}')
        || srum_database_identifier_signal(trimmed, lower)
}

fn srum_database_identifier_signal(value: &str, lower: &str) -> bool {
    if value.len() < 4 || value.len() > 240 {
        return false;
    }
    if matches!(
        lower,
        "en-us" | "locale" | "version" | "name" | "type" | "flags" | "pages" | "rootflag"
    ) {
        return false;
    }
    let mut has_letter = false;
    for ch in value.chars() {
        if ch.is_ascii_alphabetic() {
            has_letter = true;
        }
        if ch.is_control() {
            return false;
        }
    }
    has_letter
}

fn web_cache_string_surface_signal(value: &str, lower: &str) -> bool {
    if value.len() < 4 || value.len() > 300 {
        return false;
    }
    if matches!(
        lower,
        "en-us" | "locale" | "version" | "name" | "type" | "flags" | "pages" | "rootflag"
    ) {
        return false;
    }
    let has_letter = value.chars().any(|ch| ch.is_ascii_alphabetic());
    has_letter
        && value.chars().all(|ch| !ch.is_control())
        && (contains_any_text(
            lower,
            &[
                "http",
                "url",
                "cache",
                "cookie",
                "history",
                "visited",
                "download",
                "container",
                "iedownload",
                "msedge",
                "chrome",
                "internet explorer",
                "content",
                "response",
                "request",
                "filename",
                "filepath",
                "recordoffset",
                "autoinc",
            ],
        ) || looks_like_domain_label(value)
            || value.contains('\\')
            || value.contains('/'))
}

fn looks_like_domain_label(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let labels = lower.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
        && labels
            .last()
            .is_some_and(|tld| (2..=24).contains(&tld.len()))
}

fn database_string_class(artifact_type: &str, value: &str, lower: &str) -> &'static str {
    if extract_url_like(value).is_some() {
        "url"
    } else if extract_process_name_like(value).is_some() {
        "process"
    } else if extract_path_like(value).is_some() {
        "path"
    } else if extract_hash_like(value).is_some() {
        "hash"
    } else if artifact_type == "srum"
        && contains_any_text(
            lower,
            &["appresource", "network", "energy", "interface", "resource"],
        )
    {
        "srum_resource_schema"
    } else if contains_any_text(lower, &["sqlite_master", "msys", "recordoffset", "autoinc"]) {
        "database_schema"
    } else {
        "string_signal"
    }
}

fn onedrive_line_interesting(lower: &str) -> bool {
    contains_any_text(
        lower,
        &[
            "onedrive",
            "sync",
            "download",
            "upload",
            "delete",
            "rename",
            "move",
            "sharepoint",
            "tenant",
            "cid=",
            "usercid",
            "error",
            "fail",
            "warn",
            "conflict",
            "hydration",
            "dehydration",
            "placeholder",
            "localroot",
            "mountpoint",
            "business",
            "personal",
            "account",
            "http://",
            "https://",
            "c:\\",
            "\\users\\",
            "/users/",
        ],
    )
}

fn onedrive_action(lower: &str, url: Option<&str>, file_path: Option<&str>) -> String {
    if lower.contains("download") || lower.contains("hydration") {
        "onedrive_download_observed"
    } else if lower.contains("upload") || lower.contains("dehydration") {
        "onedrive_upload_observed"
    } else if lower.contains("delete") || lower.contains("recycle") {
        "onedrive_delete_observed"
    } else if lower.contains("rename") || lower.contains("move") {
        "onedrive_rename_or_move_observed"
    } else if lower.contains("error") || lower.contains("fail") || lower.contains("exception") {
        "onedrive_error_observed"
    } else if lower.contains("account") || lower.contains("tenant") || lower.contains("usercid") {
        "onedrive_account_observed"
    } else if url.is_some() {
        "onedrive_url_observed"
    } else if file_path.is_some() {
        "onedrive_path_observed"
    } else if lower.contains("sync") {
        "onedrive_sync_observed"
    } else {
        "onedrive_signal_observed"
    }
    .to_string()
}

fn onedrive_severity(lower: &str, action: &str) -> &'static str {
    if lower.contains("error") || lower.contains("fail") || lower.contains("exception") {
        "medium"
    } else if action.contains("upload") || action.contains("delete") {
        "medium"
    } else {
        "info"
    }
}

fn onedrive_scope_from_path(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("/business") || lower.contains("\\business") {
        Some("business".to_string())
    } else if lower.contains("/personal") || lower.contains("\\personal") {
        Some("personal".to_string())
    } else if lower.contains("/common") || lower.contains("\\common") {
        Some("common".to_string())
    } else {
        None
    }
}

fn onedrive_account_hint(value: &str) -> Option<String> {
    extract_label_value(
        value,
        &["UserCid", "cid", "Tenant", "Account", "User", "email"],
    )
    .or_else(|| {
        value
            .split_whitespace()
            .find(|part| part.contains('@') && part.contains('.'))
            .map(|part| {
                part.trim_matches(|ch: char| {
                    matches!(
                        ch,
                        '"' | '\'' | ',' | ';' | '<' | '>' | '(' | ')' | '[' | ']'
                    )
                })
                .to_string()
            })
    })
    .and_then(|value| clean_opt(Some(value)))
}

#[derive(Debug, Clone)]
struct EseStructure {
    page_size: Option<usize>,
    page_count: Option<usize>,
    signature_offset: Option<usize>,
    pages: Vec<EsePageSummary>,
}

#[derive(Debug, Clone)]
struct EsePageSummary {
    page_number: usize,
    offset: usize,
    length: usize,
    checksum_hint: Option<u32>,
    page_number_hint: Option<u32>,
    dbtime_hint: Option<u64>,
    flags_hint: Option<u32>,
    tag_count_hint: Option<u16>,
    nonzero_bytes: usize,
    tags: Vec<EseTagSummary>,
    table_name_hints: Vec<String>,
}

#[derive(Debug, Clone)]
struct EseTagSummary {
    tag_index: usize,
    offset: usize,
    absolute_offset: usize,
    length: usize,
    flags_hint: u16,
    value_preview: Option<String>,
    confidence: f64,
}

impl EseStructure {
    fn header_json(&self) -> Value {
        json!({
            "signature_offset": self.signature_offset,
            "page_size": self.page_size,
            "page_count": self.page_count,
            "offset": 0,
            "length": self.page_size.unwrap_or(4096).min(64 * 1024),
            "confidence": if self.signature_offset.is_some() { 0.8 } else { 0.45 },
        })
    }

    fn pages_json(&self) -> Vec<Value> {
        self.pages
            .iter()
            .map(|page| {
                json!({
                    "page_number": page.page_number,
                    "offset": page.offset,
                    "length": page.length,
                    "checksum_hint": page.checksum_hint,
                    "page_number_hint": page.page_number_hint,
                    "dbtime_hint": page.dbtime_hint,
                    "flags_hint": page.flags_hint,
                    "tag_count_hint": page.tag_count_hint,
                    "nonzero_bytes": page.nonzero_bytes,
                    "tags": ese_tag_json(&page.tags),
                    "table_name_hints": page.table_name_hints,
                    "confidence": 0.55,
                })
            })
            .collect()
    }
}

fn parse_ese_structure(bytes: &[u8]) -> EseStructure {
    let signature_offset = find_ese_signature(bytes);
    let page_size = read_u32_le(bytes, 0xec)
        .map(|value| value as usize)
        .filter(|value| matches!(*value, 2048 | 4096 | 8192 | 16384 | 32768))
        .or_else(|| infer_ese_page_size(bytes));
    let page_count = page_size
        .map(|size| bytes.len() / size)
        .filter(|count| *count > 0);
    let mut pages = Vec::new();
    if let Some(page_size) = page_size {
        for page_number in 0..page_count.unwrap_or_default().min(8) {
            let offset = page_number.saturating_mul(page_size);
            if offset + page_size > bytes.len() {
                break;
            }
            let page = &bytes[offset..offset + page_size];
            pages.push(EsePageSummary {
                page_number,
                offset,
                length: page_size,
                checksum_hint: read_u32_le(page, 0),
                page_number_hint: read_u32_le(page, 4),
                dbtime_hint: read_u64_le(page, 8),
                flags_hint: read_u32_le(page, 20),
                tag_count_hint: read_u16_le(page, 22),
                nonzero_bytes: page.iter().filter(|byte| **byte != 0).count(),
                tags: parse_ese_page_tags(page, offset),
                table_name_hints: ese_page_table_name_hints(page),
            });
        }
    }
    EseStructure {
        page_size,
        page_count,
        signature_offset,
        pages,
    }
}

fn ese_tag_json(tags: &[EseTagSummary]) -> Vec<Value> {
    tags.iter()
        .take(64)
        .map(|tag| {
            json!({
                "tag_index": tag.tag_index,
                "offset": tag.offset,
                "absolute_offset": tag.absolute_offset,
                "length": tag.length,
                "flags_hint": tag.flags_hint,
                "value_preview": tag.value_preview,
                "confidence": tag.confidence,
            })
        })
        .collect()
}

fn parse_ese_page_tags(page: &[u8], page_offset: usize) -> Vec<EseTagSummary> {
    let Some(tag_count) = read_u16_le(page, 22).map(|value| value as usize) else {
        return Vec::new();
    };
    if tag_count == 0 || tag_count > 256 || tag_count.saturating_mul(4) > page.len() {
        return Vec::new();
    }
    let tag_area_start = page.len().saturating_sub(tag_count * 4);
    let mut out = Vec::new();
    for tag_index in 0..tag_count {
        let entry_offset = tag_area_start + tag_index * 4;
        let Some(raw_offset) = read_u16_le(page, entry_offset) else {
            continue;
        };
        let Some(raw_length) = read_u16_le(page, entry_offset + 2) else {
            continue;
        };
        let offset = (raw_offset & 0x1fff) as usize;
        let flags_hint = raw_offset >> 13;
        let length = raw_length as usize;
        if length == 0 || offset >= page.len() || offset.saturating_add(length) > page.len() {
            continue;
        }
        let value_preview = ese_tag_value_preview(&page[offset..offset + length]);
        out.push(EseTagSummary {
            tag_index,
            offset,
            absolute_offset: page_offset + offset,
            length,
            flags_hint,
            value_preview,
            confidence: if length >= 8 { 0.65 } else { 0.45 },
        });
    }
    out
}

fn ese_tag_value_preview(bytes: &[u8]) -> Option<String> {
    extract_ascii_strings(bytes)
        .into_iter()
        .chain(extract_utf16le_strings(bytes))
        .find(|value| value.len() >= 4)
        .map(|value| truncate(&value, 160))
}

fn ese_page_table_name_hints(page: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for value in extract_ascii_strings(page)
        .into_iter()
        .chain(extract_utf16le_strings(page))
    {
        let lower = value.to_ascii_lowercase();
        let looks_like_table = lower.contains("table")
            || lower.contains("container_")
            || lower.contains("msys")
            || lower.contains("sru")
            || lower.contains("webcache")
            || lower.contains("history")
            || lower.contains("url");
        if !looks_like_table || out.iter().any(|existing| existing == &value) {
            continue;
        }
        out.push(truncate(&value, 180));
        if out.len() >= 12 {
            break;
        }
    }
    out
}

fn find_ese_signature(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .take(512)
        .position(|window| window == [0xef, 0xcd, 0xab, 0x89] || window == [0x89, 0xab, 0xcd, 0xef])
}

fn infer_ese_page_size(bytes: &[u8]) -> Option<usize> {
    [32768usize, 16384, 8192, 4096, 2048]
        .into_iter()
        .find(|size| bytes.len() >= *size && bytes.len() % *size == 0)
}

fn parse_usn_export(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let records = parse_flat_export_records(text, "usn_jrnl")?;
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for record in records {
        let file_path = cell(
            &record.row,
            &["fullpath", "filepath", "path", "filename", "name"],
        )
        .unwrap_or_else(|| input.original_path.clone());
        let reason = cell(&record.row, &["reason", "reasons"]);
        let action = usn_action(reason.as_deref());
        let severity = if action == "usn_deleted" || action == "usn_renamed" {
            "medium"
        } else {
            "info"
        };
        let host = cell(
            &record.row,
            &["computername", "computer", "host", "hostname"],
        );
        let user_name = cell(&record.row, &["username", "user"]);
        let (event_time, time_original, confidence) = event_time_from_record(
            &record.row,
            &[
                "timestamp",
                "datetime",
                "time",
                "date",
                "eventtime",
                "usntime",
                "changedtime",
            ],
            base_time,
            record.record_index,
        );
        let message_full = if let Some(reason) = &reason {
            format!("USN {action}: {file_path} reason={reason}")
        } else {
            format!("USN {action}: {file_path}")
        };
        let attributes_json = json!({
            "parser_mode": record.parser_mode.clone(),
            "time_inferred": confidence < 0.9,
            "reason": reason.clone(),
            "file_reference": cell(&record.row, &["filereference", "filereferencenumber", "frn"]),
            "parent_file_reference": cell(&record.row, &["parentfilereference", "parentfilereferencenumber", "parentfrn"]),
        })
        .to_string();
        let raw_json = json!({
            "record_index": record.record_index,
            "parser_mode": record.parser_mode.clone(),
            "record": record.raw.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "usn_jrnl",
            event_time,
            time_original,
            "usn_timestamp",
            confidence,
            host,
            user_name,
            None,
            Some(file_path),
            None,
            None,
            None,
            action,
            severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

fn parse_browser_export(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let records = parse_flat_export_records(text, "browser")?;
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for record in records {
        if record.parser_mode == "browser_json" && browser_profile_json_path(&input.original_path) {
            append_browser_json_signal_events(
                input,
                metadata,
                &record.raw,
                record.record_index,
                base_time,
                &mut events,
                &mut raw_records,
            );
            continue;
        }

        let url = cell(
            &record.row,
            &[
                "url",
                "typedurl",
                "destinationurl",
                "sourceurl",
                "downloadurl",
            ],
        );
        let title = cell(&record.row, &["title", "pagetitle", "name"]);
        let file_path = cell(
            &record.row,
            &[
                "targetfilename",
                "downloadpath",
                "downloadfilepath",
                "fullpath",
                "filepath",
                "path",
                "filename",
            ],
        )
        .or_else(|| url.as_deref().and_then(file_name_from_url));
        let host = cell(
            &record.row,
            &["computername", "computer", "host", "hostname"],
        );
        let user_name = cell(&record.row, &["username", "user", "profile"]);
        let hash = cell(&record.row, &["sha1", "sha256", "md5", "hash"]);
        let (event_time, time_original, confidence) = event_time_from_record(
            &record.row,
            &[
                "visittime",
                "lastvisittime",
                "lastvisit",
                "lastvisited",
                "timestamp",
                "datetime",
                "time",
                "visitdate",
                "lastaccessed",
            ],
            base_time,
            record.record_index,
        );
        let message_full = match (&url, &title) {
            (Some(url), Some(title)) => format!("Browser visit: {url} title={title}"),
            (Some(url), None) => format!("Browser visit: {url}"),
            (None, Some(title)) => format!("Browser visit: {title}"),
            (None, None) => format!("Browser record observed: {}", input.original_path),
        };
        let attributes_json = json!({
            "parser_mode": record.parser_mode.clone(),
            "time_inferred": confidence < 0.9,
            "title": title.clone(),
        })
        .to_string();
        let raw_json = json!({
            "record_index": record.record_index,
            "parser_mode": record.parser_mode.clone(),
            "record": record.raw.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "browser",
            event_time,
            time_original,
            "browser_visit_time",
            confidence,
            host,
            user_name,
            None,
            file_path,
            None,
            url,
            hash,
            "browser_visit".to_string(),
            "info".to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

fn browser_profile_json_path(original_path: &str) -> bool {
    let lower = original_path.to_ascii_lowercase();
    lower.ends_with("/preferences")
        || lower.ends_with("\\preferences")
        || lower.ends_with("/secure preferences")
        || lower.ends_with("\\secure preferences")
        || lower.ends_with("/local state")
        || lower.ends_with("\\local state")
        || lower.ends_with("/bookmarks")
        || lower.ends_with("\\bookmarks")
        || lower.ends_with("/downloadmetadata")
        || lower.ends_with("\\downloadmetadata")
}

fn append_browser_json_signal_events(
    input: &ParserInput,
    metadata: &ParserMetadata,
    value: &Value,
    record_index: usize,
    base_time: DateTime<Utc>,
    events: &mut Vec<EventFull>,
    raw_records: &mut Vec<RawRecord>,
) {
    let mut scalars = Vec::new();
    collect_json_scalar_values(value, "", &mut scalars);
    let mut seen = std::collections::HashSet::new();

    for (key_path, scalar) in scalars {
        let clean = sanitize_display_text(&scalar);
        if !browser_json_signal_interesting(&key_path, &clean) {
            continue;
        }
        let dedup = format!("{key_path}|{}", truncate(&clean, 180)).to_ascii_lowercase();
        if !seen.insert(dedup) {
            continue;
        }
        if events.len() >= 8_000 {
            break;
        }

        let lower = format!("{} {}", key_path, clean).to_ascii_lowercase();
        let url = extract_url_like(&clean);
        let domain = extract_domain_like(&clean);
        let file_path = extract_path_like(&clean).or_else(|| Some(input.original_path.clone()));
        let process_name = extract_process_name_like(&clean);
        let hash = extract_hash_like(&clean);
        let action = browser_json_signal_action(&key_path, &clean, url.as_deref());
        let severity = browser_json_signal_severity(&lower, &action);
        let idx = events.len();
        let event_time = (base_time + Duration::milliseconds(idx as i64)).to_rfc3339();
        let target = url
            .as_deref()
            .or(domain.as_deref())
            .or(process_name.as_deref())
            .or(hash.as_deref())
            .unwrap_or(&clean);
        let message_full = format!(
            "Browser profile signal: {}={}",
            truncate(&key_path, 160),
            truncate(target, 240)
        );
        let attributes_json = json!({
            "parser_mode": "browser_profile_json",
            "source_path": input.original_path,
            "record_index": record_index,
            "key_path": key_path.clone(),
            "value": truncate(&clean, 700),
            "domain": domain,
            "time_inferred": true,
        })
        .to_string();
        let raw_json = json!({
            "record_index": record_index,
            "parser_mode": "browser_profile_json",
            "key_path": key_path,
            "value": truncate(&clean, 1200),
            "object_ref": input.object_ref,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "browser",
            event_time.clone(),
            event_time,
            "artifact_import_time",
            0.3,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            process_name,
            file_path,
            None,
            url,
            hash,
            action,
            severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }
}

fn collect_json_scalar_values(value: &Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_json_scalar_values(value, &path, out);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_json_scalar_values(value, prefix, out);
            }
        }
        Value::Null => {}
        Value::String(text) => out.push((prefix.to_string(), text.clone())),
        other => out.push((prefix.to_string(), other.to_string())),
    }
}

fn browser_json_signal_interesting(key_path: &str, value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 2 || trimmed.len() > 1_500 {
        return false;
    }
    let key_lower = key_path.to_ascii_lowercase();
    let lower = trimmed.to_ascii_lowercase();
    if matches!(lower.as_str(), "null" | "none" | "{}" | "[]") {
        return false;
    }
    if matches!(lower.as_str(), "true" | "false" | "0" | "1")
        && !contains_any_text(
            &key_lower,
            &[
                "safebrowsing",
                "safe_browsing",
                "proxy",
                "dns",
                "sync",
                "password",
                "credential",
                "extension",
                "cookie",
            ],
        )
    {
        return false;
    }

    extract_url_like(trimmed).is_some()
        || extract_domain_like(trimmed).is_some()
        || extract_path_like(trimmed).is_some()
        || extract_process_name_like(trimmed).is_some()
        || extract_hash_like(trimmed).is_some()
        || contains_any_text(
            &key_lower,
            &[
                "url",
                "homepage",
                "startup",
                "download",
                "default_directory",
                "defaultdirectory",
                "extension",
                "installed",
                "path",
                "account",
                "signin",
                "sync",
                "safebrowsing",
                "safe_browsing",
                "dns",
                "proxy",
                "search",
                "session",
                "tab",
                "cookie",
                "password",
                "credential",
            ],
        )
        || contains_any_text(
            &lower,
            &[
                "powershell",
                "cmd.exe",
                "rundll32",
                "regsvr32",
                "mshta",
                "download",
                "cookie",
                "chrome-extension://",
                "edge-extension://",
            ],
        )
}

fn browser_json_signal_action(key_path: &str, value: &str, url: Option<&str>) -> String {
    let key_lower = key_path.to_ascii_lowercase();
    let lower = value.to_ascii_lowercase();
    if contains_any_text(&key_lower, &["extension", "extensions"]) {
        "browser_extension_observed".to_string()
    } else if contains_any_text(&key_lower, &["download", "default_directory"]) {
        "browser_download_setting_observed".to_string()
    } else if contains_any_text(&key_lower, &["session", "tab"]) {
        "browser_session_signal".to_string()
    } else if contains_any_text(&key_lower, &["password", "credential", "login"]) {
        "browser_credential_config_observed".to_string()
    } else if contains_any_text(&key_lower, &["cookie"]) {
        "browser_cookie_config_observed".to_string()
    } else if contains_any_text(&key_lower, &["safebrowsing", "safe_browsing"])
        && contains_any_text(&lower, &["false", "disabled", "0"])
    {
        "browser_security_setting_weak".to_string()
    } else if url.is_some() {
        "browser_url_observed".to_string()
    } else {
        "browser_setting_observed".to_string()
    }
}

fn browser_json_signal_severity(lower: &str, action: &str) -> &'static str {
    if contains_any_text(
        lower,
        &[
            "powershell",
            "cmd.exe",
            "rundll32",
            "regsvr32",
            "mshta",
            "mimikatz",
            "lsass",
        ],
    ) || action == "browser_security_setting_weak"
    {
        "high"
    } else if matches!(
        action,
        "browser_extension_observed"
            | "browser_download_setting_observed"
            | "browser_credential_config_observed"
    ) {
        "medium"
    } else {
        "info"
    }
}

fn parse_network_capture_signals(input: &ParserInput, metadata: &ParserMetadata) -> ParsedArtifact {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let base_time = Utc::now();
    let mut current = Vec::new();
    let mut current_start = 0usize;
    const LIMIT: usize = 12_000;

    for (offset, byte) in input.bytes.iter().copied().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            if current.is_empty() {
                current_start = offset;
            }
            current.push(byte);
            if current.len() > 1500 {
                append_network_capture_signal(
                    input,
                    metadata,
                    current_start,
                    &current,
                    base_time,
                    &mut seen,
                    &mut events,
                    &mut raw_records,
                    LIMIT,
                );
                current.clear();
            }
        } else {
            append_network_capture_signal(
                input,
                metadata,
                current_start,
                &current,
                base_time,
                &mut seen,
                &mut events,
                &mut raw_records,
                LIMIT,
            );
            current.clear();
        }
        if events.len() >= LIMIT {
            break;
        }
    }
    append_network_capture_signal(
        input,
        metadata,
        current_start,
        &current,
        base_time,
        &mut seen,
        &mut events,
        &mut raw_records,
        LIMIT,
    );

    if events.is_empty() {
        return parse_recovery_artifact_metadata(input, metadata, "network_capture");
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

#[allow(clippy::too_many_arguments)]
fn append_network_capture_signal(
    input: &ParserInput,
    metadata: &ParserMetadata,
    offset: usize,
    bytes: &[u8],
    base_time: DateTime<Utc>,
    seen: &mut std::collections::HashSet<String>,
    events: &mut Vec<EventFull>,
    raw_records: &mut Vec<RawRecord>,
    limit: usize,
) {
    if bytes.len() < 4 || events.len() >= limit {
        return;
    }
    let value = sanitize_display_text(&String::from_utf8_lossy(bytes));
    let Some(signal) = network_capture_signal(&value) else {
        return;
    };
    let dedup = format!(
        "{}|{}|{}",
        signal.action,
        signal
            .url
            .as_deref()
            .or(signal.domain.as_deref())
            .or(signal.ip.as_deref())
            .or(signal.file_path.as_deref())
            .or(signal.process_name.as_deref())
            .unwrap_or(&signal.target),
        truncate(&value, 120)
    )
    .to_ascii_lowercase();
    if !seen.insert(dedup) {
        return;
    }

    let idx = events.len();
    let event_time = (base_time + Duration::milliseconds(idx as i64)).to_rfc3339();
    let message_full = format!("Network capture signal: {}", truncate(&signal.target, 300));
    let attributes_json = json!({
        "parser_mode": "network_capture_string_signal",
        "source_path": input.original_path,
        "byte_offset": offset,
        "string": truncate(&value, 700),
        "domain": signal.domain,
        "time_inferred": true,
        "sidecar_recommended": "zeek_tshark_pcap_analysis",
    })
    .to_string();
    let raw_json = json!({
        "record_index": idx + 1,
        "parser_mode": "network_capture_string_signal",
        "byte_offset": offset,
        "string": truncate(&value, 1200),
        "object_ref": input.object_ref,
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        "network_capture",
        event_time.clone(),
        event_time,
        "artifact_import_time",
        0.25,
        host_from_path(&input.original_path),
        user_from_path(&input.original_path),
        signal.process_name,
        signal.file_path,
        signal.ip,
        signal.url,
        signal.hash,
        signal.action,
        signal.severity,
        message_full,
        attributes_json,
        raw_json,
    );
    events.push(event);
    raw_records.push(raw);
}

#[derive(Debug)]
struct NetworkCaptureSignal {
    action: String,
    severity: String,
    target: String,
    url: Option<String>,
    domain: Option<String>,
    ip: Option<String>,
    file_path: Option<String>,
    process_name: Option<String>,
    hash: Option<String>,
}

fn network_capture_signal(value: &str) -> Option<NetworkCaptureSignal> {
    let trimmed = value.trim();
    if trimmed.len() < 4 || trimmed.len() > 1500 {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let url = extract_url_like(trimmed);
    let domain = extract_http_host(trimmed)
        .or_else(|| extract_domain_like(trimmed))
        .filter(|domain| network_capture_domain_is_signal(domain, &lower));
    let ip = extract_ipv4_like(trimmed);
    let file_path_candidate = extract_path_like(trimmed);
    let file_path_is_signal = file_path_candidate
        .as_deref()
        .is_some_and(|path| network_capture_path_is_signal(path, &lower));
    let file_path = if file_path_is_signal {
        file_path_candidate.clone()
    } else {
        None
    };
    let process_name = file_path_candidate
        .as_deref()
        .and_then(file_name_from_path)
        .filter(|name| is_executable_name(name))
        .or_else(|| extract_process_name_like(trimmed));
    let hash = extract_hash_like(trimmed);
    let http_path = extract_http_request_path(trimmed);
    let interesting = url.is_some()
        || domain.is_some()
        || ip.is_some()
        || file_path_is_signal
        || process_name.is_some()
        || hash.is_some()
        || http_path.is_some()
        || contains_any_text(
            &lower,
            &[
                "host:",
                "user-agent:",
                "cookie:",
                "authorization:",
                "content-disposition:",
                "filename=",
                "download",
                ".exe",
                ".dll",
                ".ps1",
                ".zip",
                ".rar",
                ".7z",
                "powershell",
                "cmd.exe",
                "mimikatz",
                "lsass",
                "ftp://",
                "smtp",
                "imap",
                "dns",
            ],
        );
    if !interesting {
        return None;
    }

    let action = if contains_any_text(&lower, &["cookie:", "authorization:"]) {
        "network_credential_header_observed"
    } else if contains_any_text(&lower, &["user-agent:"]) {
        "network_user_agent_observed"
    } else if contains_any_text(&lower, &["content-disposition:", "filename="])
        || (url.is_some() && contains_any_text(&lower, &["download", ".exe", ".ps1", ".zip"]))
    {
        "network_download_observed"
    } else if http_path.is_some() || lower.starts_with("http/") {
        "network_http_observed"
    } else if domain.is_some() {
        "network_domain_observed"
    } else if ip.is_some() {
        "network_ip_observed"
    } else {
        "network_string_signal"
    };
    let severity = if contains_any_text(
        &lower,
        &[
            "powershell",
            "cmd.exe",
            "rundll32",
            "regsvr32",
            "mshta",
            "mimikatz",
            "lsass",
            "authorization:",
        ],
    ) {
        "high"
    } else if matches!(
        action,
        "network_download_observed" | "network_credential_header_observed"
    ) {
        "medium"
    } else {
        "info"
    };
    let target = url
        .as_deref()
        .or(http_path.as_deref())
        .or(domain.as_deref())
        .or(ip.as_deref())
        .or(file_path.as_deref())
        .or(process_name.as_deref())
        .or(hash.as_deref())
        .unwrap_or(trimmed)
        .to_string();

    Some(NetworkCaptureSignal {
        action: action.to_string(),
        severity: severity.to_string(),
        target,
        url,
        domain,
        ip,
        file_path,
        process_name,
        hash,
    })
}

fn extract_http_host(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    if !lower.starts_with("host:") {
        return None;
    }
    value
        .split_once(':')
        .map(|(_, host)| host.trim().trim_matches('/').to_string())
        .filter(|host| looks_like_domain(host))
}

fn extract_http_request_path(value: &str) -> Option<String> {
    let mut parts = value.split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT"
    ) {
        return None;
    }
    let path = parts.next()?.trim();
    if path.len() > 1 && path.len() < 700 {
        Some(path.to_string())
    } else {
        None
    }
}

fn network_capture_path_is_signal(path: &str, lower: &str) -> bool {
    if lower.contains("\\device\\npf_") || lower.contains("/device/npf_") {
        return false;
    }
    path.starts_with("\\\\")
        || contains_any_text(
            lower,
            &[
                ".exe",
                ".dll",
                ".ps1",
                ".zip",
                ".rar",
                ".7z",
                "\\users\\",
                "/users/",
                "\\downloads\\",
                "/downloads/",
                "\\temp\\",
                "/temp/",
                "\\appdata\\",
                "/appdata/",
                "\\programdata\\",
                "/programdata/",
            ],
        )
}

fn network_capture_domain_is_signal(domain: &str, lower: &str) -> bool {
    if is_common_network_noise(domain) {
        return false;
    }
    if lower.starts_with("host:")
        || lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ftp://")
    {
        return true;
    }
    if domain.len() < 7 {
        return false;
    }
    let domain_lower = domain.to_ascii_lowercase();
    let Some((_, tld)) = domain_lower.rsplit_once('.') else {
        return false;
    };
    matches!(
        tld,
        "com"
            | "net"
            | "org"
            | "io"
            | "co"
            | "biz"
            | "info"
            | "dev"
            | "app"
            | "cloud"
            | "site"
            | "xyz"
            | "top"
            | "online"
            | "store"
            | "ru"
            | "cn"
            | "uk"
            | "de"
            | "jp"
            | "us"
            | "test"
            | "local"
    )
}

fn is_common_network_noise(domain: &str) -> bool {
    matches!(
        domain.to_ascii_lowercase().as_str(),
        "w3.org" | "example.com" | "example.net" | "example.org"
    )
}

fn parse_text_lines(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    parse_text_lines_as(input, metadata, text, "text_log", "observed")
}

fn parse_text_lines_as(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
    artifact_type: &str,
    default_action: &str,
) -> Result<ParsedArtifact> {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    append_text_observation_events(
        input,
        metadata,
        text,
        artifact_type,
        "text_line_observation",
        &mut events,
        &mut raw_records,
    );
    let base_time = Utc::now();
    for (idx, clean_line) in text
        .lines()
        .map(sanitize_display_text)
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let line = clean_line.as_str();
        let (time_original, message) = split_leading_timestamp(line);
        let lower = line.to_ascii_lowercase();
        let event_time = time_original
            .as_deref()
            .and_then(normalize_datetime)
            .unwrap_or_else(|| (base_time + Duration::seconds(idx as i64)).to_rfc3339());
        let url = extract_url_like(line);
        let domain = extract_domain_like(line);
        let ip = extract_ipv4_like(line);
        let process_name = extract_process_name_like(line);
        let file_path = extract_path_like(line).or_else(|| Some(input.original_path.clone()));
        let hash = extract_hash_like(line);
        let classification = classify_text_log(
            &input.original_path,
            line,
            &lower,
            url.as_deref(),
            process_name.as_deref(),
            ip.as_deref(),
        );
        let base_action = text_line_action(
            artifact_type,
            default_action,
            &lower,
            url.as_deref(),
            process_name.as_deref(),
            ip.as_deref(),
        );
        let action = classified_text_action(
            artifact_type,
            default_action,
            base_action,
            classification.as_ref(),
        );
        let severity = classification
            .as_ref()
            .map(|value| value.severity)
            .unwrap_or_else(|| FakeParser::severity_for(line))
            .to_string();
        let attributes_json = json!({
            "line_number": idx + 1,
            "parser_mode": "text_line",
            "time_inferred": time_original.is_none(),
            "domain": domain,
            "source_path": input.original_path,
            "log_family": classification.as_ref().map(|value| value.log_family),
            "classification": classification.as_ref().map(|value| value.classification),
            "http_method": classification.as_ref().and_then(|value| value.http_method.clone()),
            "http_status": classification.as_ref().and_then(|value| value.http_status),
            "username": classification.as_ref().and_then(|value| value.username.clone()),
            "command_hint": classification.as_ref().and_then(|value| value.command_hint.clone()),
        })
        .to_string();
        let raw_json = json!({
            "line_number": idx + 1,
            "line": clean_line,
            "parser": metadata.parser_name,
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            artifact_type,
            event_time.clone(),
            time_original.unwrap_or_else(|| event_time.clone()),
            "textlog_line_timestamp",
            if line_timestamp_confident(line) {
                0.7
            } else {
                0.35
            },
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            process_name,
            file_path,
            ip,
            url,
            hash,
            action,
            severity,
            message,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }
    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

const TEXT_OBSERVATION_MAX_LINES_PER_FILE: usize = 50_000;

fn append_text_observation_events(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
    source_artifact_type: &str,
    parser_mode: &str,
    events: &mut Vec<EventFull>,
    raw_records: &mut Vec<RawRecord>,
) -> usize {
    let base_time = Utc::now();
    let mut emitted = 0usize;
    for (idx, clean_line) in text
        .lines()
        .map(sanitize_display_text)
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        if emitted >= TEXT_OBSERVATION_MAX_LINES_PER_FILE {
            break;
        }
        let line = clean_line.as_str();
        let (time_original, message) = split_leading_timestamp(line);
        let lower = line.to_ascii_lowercase();
        let event_time = time_original
            .as_deref()
            .and_then(normalize_datetime)
            .unwrap_or_else(|| (base_time + Duration::milliseconds(idx as i64)).to_rfc3339());
        let url = extract_url_like(line);
        let domain = extract_domain_like(line);
        let ip = extract_ipv4_like(line);
        let process_name = extract_process_name_like(line);
        let file_path = extract_path_like(line).or_else(|| Some(input.original_path.clone()));
        let hash = extract_hash_like(line);
        let classification = classify_text_log(
            &input.original_path,
            line,
            &lower,
            url.as_deref(),
            process_name.as_deref(),
            ip.as_deref(),
        );
        let signal = text_document_line_interesting(line) || classification.is_some();
        let base_action = text_line_action(
            "text_observation",
            "text_observation_line_observed",
            &lower,
            url.as_deref(),
            process_name.as_deref(),
            ip.as_deref(),
        );
        let action = classified_text_action(
            "text_observation",
            "text_observation_line_observed",
            base_action,
            classification.as_ref(),
        );
        let severity = if let Some(classification) = classification.as_ref() {
            classification.severity
        } else if signal {
            text_document_signal_severity(&lower)
        } else {
            FakeParser::severity_for(line)
        };
        let attributes_json = json!({
            "line_number": idx + 1,
            "parser_mode": parser_mode,
            "source_artifact_type": source_artifact_type,
            "source_path": input.original_path,
            "domain": domain,
            "line_length": line.chars().count(),
            "time_inferred": time_original.is_none(),
            "semantic_signal": signal,
            "line_truncated": message.chars().count() > 1000,
            "observation_cap_per_file": TEXT_OBSERVATION_MAX_LINES_PER_FILE,
            "log_family": classification.as_ref().map(|value| value.log_family),
            "classification": classification.as_ref().map(|value| value.classification),
            "http_method": classification.as_ref().and_then(|value| value.http_method.clone()),
            "http_status": classification.as_ref().and_then(|value| value.http_status),
            "username": classification.as_ref().and_then(|value| value.username.clone()),
            "command_hint": classification.as_ref().and_then(|value| value.command_hint.clone()),
        })
        .to_string();
        let raw_json = json!({
            "line_number": idx + 1,
            "parser_mode": parser_mode,
            "source_artifact_type": source_artifact_type,
            "line": truncate(&clean_line, 4096),
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "text_observation",
            event_time.clone(),
            time_original.unwrap_or_else(|| event_time.clone()),
            "text_observation_order",
            if line_timestamp_confident(line) {
                0.55
            } else {
                0.2
            },
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            process_name,
            file_path,
            ip,
            url,
            hash,
            action,
            severity.to_string(),
            format!(
                "{} line {}: {}",
                source_artifact_type,
                idx + 1,
                truncate(&message, 1000)
            ),
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
        emitted += 1;
    }
    emitted
}

fn parse_windows_search_log(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> ParsedArtifact {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let base_time = Utc::now();

    for (idx, clean_line) in text
        .lines()
        .map(sanitize_display_text)
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let line = clean_line.trim_matches('\u{feff}').trim();
        if line.is_empty() {
            continue;
        }
        let fields = line
            .split('\t')
            .map(|value| value.trim_matches('\u{feff}').trim())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let uri = windows_search_uri_candidate(&fields, line);
        let file_path = uri
            .as_deref()
            .and_then(windows_search_file_path_from_uri)
            .or_else(|| extract_path_like(line));
        let url = uri
            .as_deref()
            .and_then(windows_search_url_from_uri)
            .or_else(|| extract_url_like(line));
        let status_hint = windows_search_status_hint(&fields);
        let lower = line.to_ascii_lowercase();

        if uri.is_none()
            && file_path.is_none()
            && url.is_none()
            && !windows_search_line_interesting(&lower, status_hint.as_deref())
        {
            continue;
        }

        let key = uri
            .as_deref()
            .or(file_path.as_deref())
            .or(url.as_deref())
            .unwrap_or(line);
        let key = format!("{}:{key}", idx / 10);
        if !seen.insert(truncate(&key, 400).to_ascii_lowercase()) {
            continue;
        }

        let action = windows_search_action(&lower, file_path.as_deref(), url.as_deref());
        let severity = windows_search_severity(&lower, file_path.as_deref(), url.as_deref());
        let process_name = file_path.as_deref().and_then(|path| {
            if is_executable_name(path) {
                file_name_from_path(path)
            } else {
                None
            }
        });
        let target = uri
            .as_deref()
            .or(file_path.as_deref())
            .or(url.as_deref())
            .unwrap_or(line);
        let target_message = truncate(target, 300);
        let event_time = (base_time + Duration::milliseconds(idx as i64)).to_rfc3339();
        let attributes_json = json!({
            "parser_mode": "windows_search_gather_log",
            "line_number": idx + 1,
            "source_path": input.original_path,
            "uri": uri,
            "field_count": fields.len(),
            "status_hint": status_hint,
            "time_inferred": true,
            "line": truncate(line, 1000),
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "windows_search_gather_log",
            "line_number": idx + 1,
            "fields": fields,
            "line": line,
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "windows_search_log",
            event_time.clone(),
            event_time,
            "windows_search_import_order",
            0.25,
            host_from_path(&input.original_path),
            file_path
                .as_deref()
                .and_then(user_from_path)
                .or_else(|| user_from_path(&input.original_path)),
            process_name,
            file_path,
            extract_ipv4_like(line),
            url,
            extract_hash_like(line),
            action.to_string(),
            severity.to_string(),
            format!("Windows Search indexed/crawled: {target_message}"),
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if events.is_empty() {
        return parse_file_metadata_event(
            input,
            metadata,
            "windows_search_log",
            "windows_search_log_observed",
            Some("Windows Search artifact parsed without high-value row signals".to_string()),
        );
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn windows_search_uri_candidate(fields: &[&str], line: &str) -> Option<String> {
    fields
        .iter()
        .find_map(|field| {
            let value = field.trim_matches('"').trim();
            if windows_search_uri_like(value) {
                Some(value.to_string())
            } else {
                None
            }
        })
        .or_else(|| {
            line.split_whitespace()
                .find(|value| windows_search_uri_like(value.trim_matches('"')))
                .map(|value| value.trim_matches('"').to_string())
        })
}

fn windows_search_uri_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("file:")
        || lower.starts_with("mapi:")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
}

fn windows_search_file_path_from_uri(uri: &str) -> Option<String> {
    let lower = uri.to_ascii_lowercase();
    if !lower.starts_with("file:") {
        return None;
    }
    let mut value = uri[5..].trim();
    value = value.trim_start_matches("///");
    value = value.trim_start_matches("//?/");
    value = value.trim_start_matches("//");
    if value.is_empty() {
        None
    } else {
        Some(value.replace('/', "\\"))
    }
}

fn windows_search_url_from_uri(uri: &str) -> Option<String> {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some(uri.to_string())
    } else {
        None
    }
}

fn windows_search_status_hint(fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .rev()
        .find(|field| {
            let value = field.trim();
            value.len() >= 4
                && value.len() <= 16
                && value.chars().all(|ch| ch.is_ascii_hexdigit())
                && value.chars().any(|ch| ch.is_ascii_alphabetic())
        })
        .map(|value| value.to_string())
}

fn windows_search_line_interesting(lower_line: &str, status_hint: Option<&str>) -> bool {
    status_hint.is_some()
        || contains_any_text(
            lower_line,
            &[
                "file:",
                "mapi:",
                "systemindex",
                "gather",
                "crawl",
                "indexed",
                "access denied",
                "error",
                "failed",
            ],
        )
}

fn windows_search_action(
    lower_line: &str,
    file_path: Option<&str>,
    url: Option<&str>,
) -> &'static str {
    if contains_any_text(lower_line, &["error", "failed", "access denied"]) {
        return "windows_search_crawl_warning";
    }
    if let Some(path) = file_path {
        let lower_path = path.to_ascii_lowercase();
        if is_executable_name(path)
            || contains_any_text(
                &lower_path,
                &[".ps1", ".vbs", ".js", ".bat", ".cmd", ".dll", ".scr"],
            )
        {
            return "windows_search_indexed_executable";
        }
        if contains_any_text(
            &lower_path,
            &[
                ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".zip", ".rar", ".7z",
            ],
        ) {
            return "windows_search_indexed_document";
        }
        return "windows_search_indexed_path";
    }
    if url.is_some() {
        "windows_search_indexed_url"
    } else {
        "windows_search_gather_record"
    }
}

fn windows_search_severity(
    lower_line: &str,
    file_path: Option<&str>,
    url: Option<&str>,
) -> &'static str {
    if contains_any_text(
        lower_line,
        &[
            "access denied",
            "error",
            "failed",
            "mimikatz",
            "lsass",
            "credential",
        ],
    ) {
        return "medium";
    }
    if let Some(path) = file_path {
        let lower_path = path.to_ascii_lowercase();
        if suspicious_path(path)
            || contains_any_text(
                &lower_path,
                &[
                    "\\downloads\\",
                    "\\appdata\\",
                    "\\temp\\",
                    "\\startup\\",
                    ".ps1",
                    ".vbs",
                    ".js",
                    ".bat",
                    ".cmd",
                    ".scr",
                ],
            )
        {
            return "medium";
        }
    }
    if url.is_some() {
        "low"
    } else {
        "info"
    }
}

fn parse_binary_text_log_signals(
    input: &ParserInput,
    metadata: &ParserMetadata,
    artifact_type: &str,
    parser_mode: &str,
    limit: usize,
) -> ParsedArtifact {
    let mut strings = extract_ascii_strings_with_offsets(&input.bytes)
        .into_iter()
        .map(|(offset, value)| (offset, "ascii", value))
        .chain(
            extract_utf16le_strings_with_offsets(&input.bytes)
                .into_iter()
                .map(|(offset, value)| (offset, "utf16le", value)),
        )
        .collect::<Vec<_>>();
    strings.sort_by_key(|(offset, _, _)| *offset);

    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let base_time = Utc::now();

    for (offset, encoding, value) in strings {
        if events.len() >= limit {
            break;
        }
        let clean = sanitize_display_text(&value);
        if clean.len() < 4 || !binary_log_string_interesting(&clean, artifact_type) {
            continue;
        }
        let key = truncate(&clean, 260).to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        let (time_original, message) = split_leading_timestamp(&clean);
        let lower = message.to_ascii_lowercase();
        let event_time = time_original
            .as_deref()
            .and_then(normalize_datetime)
            .unwrap_or_else(|| {
                (base_time + Duration::milliseconds(events.len() as i64)).to_rfc3339()
            });
        let url = extract_url_like(&message);
        let domain = extract_domain_like(&message);
        let ip = extract_ipv4_like(&message);
        let process_name =
            defender_process_hint(&message).or_else(|| extract_process_name_like(&message));
        let file_path = extract_path_like(&message).or_else(|| Some(input.original_path.clone()));
        let hash = extract_hash_like(&message);
        let action = if artifact_type == "defender" {
            defender_text_action(&message)
        } else {
            text_line_action(
                artifact_type,
                "binary_text_signal_observed",
                &lower,
                url.as_deref(),
                process_name.as_deref(),
                ip.as_deref(),
            )
        };
        let severity = if artifact_type == "defender" {
            defender_text_severity(&message)
        } else {
            text_document_signal_severity(&lower)
        };
        let attributes_json = json!({
            "parser_mode": parser_mode,
            "string_offset": offset,
            "string_encoding": encoding,
            "time_inferred": time_original.is_none(),
            "domain": domain,
            "source_path": input.original_path,
            "line": truncate(&clean, 1000),
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": parser_mode,
            "string_offset": offset,
            "string_encoding": encoding,
            "line": clean,
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            artifact_type,
            event_time.clone(),
            time_original.unwrap_or_else(|| event_time.clone()),
            "binary_string_observed",
            if line_timestamp_confident(&clean) {
                0.55
            } else {
                0.25
            },
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            process_name,
            file_path,
            ip,
            url,
            hash,
            action,
            severity.to_string(),
            message,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if events.is_empty() {
        return parse_file_metadata_event(
            input,
            metadata,
            artifact_type,
            "binary_text_artifact_observed",
            Some("no high-value strings were classified".to_string()),
        );
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn binary_log_string_interesting(value: &str, artifact_type: &str) -> bool {
    if text_document_line_interesting(value) {
        return true;
    }
    if artifact_type == "defender" {
        let lower = value.to_ascii_lowercase();
        return contains_any_text(
            &lower,
            &[
                "defender",
                "mpcmdrun",
                "msmpeng",
                "windefend",
                "signature",
                "threat",
                "scan",
                "quarantine",
                "remediation",
                "tamper",
                "malware",
                "trojan",
                "engine",
                "platform",
                "security intelligence",
                "real-time",
            ],
        );
    }
    false
}

fn parse_text_document(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
    artifact_type: &str,
) -> ParsedArtifact {
    let line_count = text.lines().count();
    let byte_count = input.bytes.len();
    let url = extract_url_like(text);
    let hash = extract_hash_like(text);
    let message_full = format!(
        "{} text artifact observed: {} lines={} bytes={}",
        artifact_type, input.original_path, line_count, byte_count
    );
    let attributes_json = json!({
        "parser_mode": "text_document",
        "line_count": line_count,
        "byte_count": byte_count,
        "extension": extension_from_path(&input.original_path),
        "sample": truncate(text, 2048),
    })
    .to_string();
    let raw_json = json!({
        "parser_mode": "text_document",
        "path": input.original_path.clone(),
        "line_count": line_count,
        "sample": truncate(text, 4096),
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        artifact_type,
        Utc::now().to_rfc3339(),
        String::new(),
        "file_import_observed",
        0.2,
        host_from_path(&input.original_path),
        user_from_path(&input.original_path),
        None,
        Some(input.original_path.clone()),
        None,
        url,
        hash,
        format!("{artifact_type}_file_observed"),
        "info".to_string(),
        message_full,
        attributes_json,
        raw_json,
    );
    let mut events = vec![event];
    let mut raw_records = vec![raw];
    append_text_observation_events(
        input,
        metadata,
        text,
        artifact_type,
        "text_document_observation",
        &mut events,
        &mut raw_records,
    );
    let base_time = Utc::now();
    let mut seen = std::collections::HashSet::new();
    let mut signal_count = 0usize;
    for (idx, clean_line) in text
        .lines()
        .map(sanitize_display_text)
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        if signal_count >= 1_000 {
            break;
        }
        let line = clean_line.as_str();
        if !text_document_line_interesting(line) {
            continue;
        }
        let key = truncate(line, 240).to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let url = extract_url_like(line);
        let domain = extract_domain_like(line);
        let file_path = extract_path_like(line).or_else(|| {
            if is_text_artifact(artifact_type) {
                Some(input.original_path.clone())
            } else {
                None
            }
        });
        let process_name = extract_process_name_like(line);
        let hash = extract_hash_like(line);
        let action = text_document_action(artifact_type, &lower, url.as_deref());
        let severity = text_document_signal_severity(&lower);
        let event_time = (base_time + Duration::milliseconds(idx as i64)).to_rfc3339();
        let attributes_json = json!({
            "parser_mode": "text_document_signal",
            "line_number": idx + 1,
            "source_path": input.original_path,
            "domain": domain.clone(),
            "time_inferred": true,
            "line": truncate(line, 1000),
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "text_document_signal",
            "line_number": idx + 1,
            "line": clean_line,
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let target = url
            .as_deref()
            .or(file_path.as_deref())
            .or(domain.as_deref())
            .or(process_name.as_deref())
            .or(hash.as_deref())
            .unwrap_or(line)
            .to_string();
        let message_full = format!("{artifact_type} signal: {}", truncate(&target, 300));
        let (event, raw) = build_event(
            input,
            metadata,
            artifact_type,
            event_time.clone(),
            event_time,
            "artifact_import_time",
            0.25,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            process_name,
            file_path,
            None,
            url,
            hash,
            action,
            severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
        signal_count += 1;
    }
    ParsedArtifact {
        events,
        raw_records,
    }
}

fn text_document_line_interesting(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    extract_url_like(line).is_some()
        || extract_domain_like(line).is_some()
        || extract_path_like(line).is_some()
        || extract_hash_like(line).is_some()
        || extract_process_name_like(line).is_some()
        || contains_any_text(
            &lower,
            &[
                "download",
                "upload",
                "visited",
                "cookie",
                "cache",
                "history",
                "sync",
                "onedrive",
                "sharepoint",
                "file:",
                "mapi:",
                "systemindex",
                "gather",
                "crawl",
                "indexed",
                "powershell",
                "cmd.exe",
                "rundll32",
                "regsvr32",
                "mshta",
                "mimikatz",
                "lsass",
                "error",
                "fail",
                "warning",
            ],
        )
}

fn text_document_action(artifact_type: &str, lower: &str, url: Option<&str>) -> String {
    if lower.contains("download") {
        format!("{artifact_type}_download_signal")
    } else if lower.contains("upload") {
        format!("{artifact_type}_upload_signal")
    } else if lower.contains("cookie") {
        format!("{artifact_type}_cookie_signal")
    } else if lower.contains("cache") || lower.contains("history") || lower.contains("visited") {
        format!("{artifact_type}_web_activity_signal")
    } else if lower.contains("onedrive") || lower.contains("sync") {
        format!("{artifact_type}_sync_signal")
    } else if url.is_some() {
        format!("{artifact_type}_url_signal")
    } else {
        format!("{artifact_type}_content_signal")
    }
}

fn text_line_action(
    artifact_type: &str,
    default_action: &str,
    lower: &str,
    url: Option<&str>,
    process_name: Option<&str>,
    ip: Option<&str>,
) -> String {
    if lower.contains("download") {
        format!("{artifact_type}_download_observed")
    } else if lower.contains("upload") || lower.contains("exfil") {
        format!("{artifact_type}_upload_observed")
    } else if process_name.is_some()
        || lower.contains("process created")
        || lower.contains("process start")
    {
        format!("{artifact_type}_process_observed")
    } else if url.is_some() {
        format!("{artifact_type}_url_observed")
    } else if ip.is_some()
        || lower.contains("connect")
        || lower.contains("network")
        || lower.contains("socket")
    {
        format!("{artifact_type}_network_observed")
    } else if lower.contains("delete") || lower.contains("removed") {
        format!("{artifact_type}_delete_observed")
    } else if lower.contains("error") || lower.contains("fail") || lower.contains("warning") {
        format!("{artifact_type}_warning_observed")
    } else {
        default_action.to_string()
    }
}

#[derive(Debug, Clone)]
struct TextLogClassification {
    log_family: &'static str,
    classification: &'static str,
    action_suffix: &'static str,
    severity: &'static str,
    http_method: Option<String>,
    http_status: Option<i64>,
    username: Option<String>,
    command_hint: Option<String>,
}

fn classified_text_action(
    artifact_type: &str,
    default_action: &str,
    base_action: String,
    classification: Option<&TextLogClassification>,
) -> String {
    let Some(classification) = classification else {
        return base_action;
    };
    let preserves_specific_transfer = matches!(
        classification.action_suffix,
        "powershell_activity_observed" | "file_transfer_observed"
    ) && (base_action.ends_with("_download_observed")
        || base_action.ends_with("_upload_observed"));
    if preserves_specific_transfer {
        return base_action;
    }
    if base_action == default_action
        || base_action.ends_with("_warning_observed")
        || base_action.ends_with("_process_observed")
        || matches!(
            classification.action_suffix,
            "auth_failure_observed"
                | "auth_success_observed"
                | "privilege_use_observed"
                | "http_request_observed"
                | "tamper_or_deletion_observed"
        )
    {
        format!("{artifact_type}_{}", classification.action_suffix)
    } else {
        base_action
    }
}

fn classify_text_log(
    source_path: &str,
    line: &str,
    lower: &str,
    url: Option<&str>,
    process_name: Option<&str>,
    ip: Option<&str>,
) -> Option<TextLogClassification> {
    let source_lower = source_path.to_ascii_lowercase();
    let (http_method, http_status) = extract_http_log_fields(line);
    let looks_iis = http_method.is_some()
        || contains_any_text(
            &source_lower,
            &["w3svc", "u_ex", "inetpub", "iis", "httperr", "access.log"],
        );
    if looks_iis && (http_method.is_some() || url.is_some() || ip.is_some()) {
        let suspicious = http_status.is_some_and(|status| status >= 400)
            || contains_any_text(
                lower,
                &[
                    "cmd=",
                    "exec",
                    "webshell",
                    "powershell",
                    "mimikatz",
                    "/upload",
                    "/download",
                    ".aspx",
                    ".ashx",
                    ".php",
                    "../",
                    "%2e%2e",
                ],
            );
        return Some(TextLogClassification {
            log_family: "web_access",
            classification: if suspicious {
                "suspicious_http_request"
            } else {
                "http_request"
            },
            action_suffix: "http_request_observed",
            severity: if suspicious { "medium" } else { "info" },
            http_method,
            http_status,
            username: extract_username_hint(line),
            command_hint: extract_command_hint(line),
        });
    }

    if contains_any_text(
        lower,
        &[
            "failed password",
            "failure audit",
            "invalid user",
            "logon failed",
            "4625",
            "authentication failure",
        ],
    ) {
        return Some(TextLogClassification {
            log_family: "authentication",
            classification: "auth_failure",
            action_suffix: "auth_failure_observed",
            severity: "medium",
            http_method: None,
            http_status: None,
            username: extract_username_hint(line),
            command_hint: None,
        });
    }
    if contains_any_text(
        lower,
        &[
            "accepted password",
            "successful logon",
            "logon success",
            "4624",
            "session opened",
        ],
    ) {
        return Some(TextLogClassification {
            log_family: "authentication",
            classification: "auth_success",
            action_suffix: "auth_success_observed",
            severity: "info",
            http_method: None,
            http_status: None,
            username: extract_username_hint(line),
            command_hint: None,
        });
    }
    if contains_any_text(
        lower,
        &[" sudo:", "sudo ", " su:", "runas", "privilege escalation"],
    ) {
        return Some(TextLogClassification {
            log_family: "authentication",
            classification: "privilege_use",
            action_suffix: "privilege_use_observed",
            severity: "medium",
            http_method: None,
            http_status: None,
            username: extract_username_hint(line),
            command_hint: extract_command_hint(line),
        });
    }

    if contains_any_text(
        lower,
        &[
            "powershell",
            "encodedcommand",
            " -enc ",
            "frombase64string",
            "iex ",
            "invoke-webrequest",
            "downloadstring",
            "start-bitstransfer",
        ],
    ) || process_name.is_some_and(|name| {
        name.eq_ignore_ascii_case("powershell.exe") || name.eq_ignore_ascii_case("pwsh.exe")
    }) {
        return Some(TextLogClassification {
            log_family: "powershell",
            classification: if contains_any_text(
                lower,
                &[
                    "encodedcommand",
                    " -enc ",
                    "frombase64string",
                    "downloadstring",
                    "iex ",
                ],
            ) {
                "suspicious_powershell"
            } else {
                "powershell_activity"
            },
            action_suffix: "powershell_activity_observed",
            severity: if contains_any_text(
                lower,
                &[
                    "encodedcommand",
                    " -enc ",
                    "frombase64string",
                    "downloadstring",
                    "iex ",
                ],
            ) {
                "high"
            } else {
                "medium"
            },
            http_method: None,
            http_status: None,
            username: extract_username_hint(line),
            command_hint: extract_command_hint(line),
        });
    }

    if contains_any_text(
        lower,
        &[
            "curl ",
            "wget ",
            "bitsadmin",
            "certutil",
            "download",
            "upload",
            "put ",
            "get ",
            "file transfer",
        ],
    ) && (url.is_some() || ip.is_some() || lower.contains(".exe") || lower.contains(".ps1"))
    {
        return Some(TextLogClassification {
            log_family: "file_transfer",
            classification: "file_transfer",
            action_suffix: "file_transfer_observed",
            severity: if contains_any_text(lower, &[".exe", ".dll", ".ps1", ".bat", ".cmd"]) {
                "high"
            } else {
                "medium"
            },
            http_method: None,
            http_status: None,
            username: extract_username_hint(line),
            command_hint: extract_command_hint(line),
        });
    }

    if contains_any_text(
        lower,
        &[
            "wevtutil cl",
            "event log cleared",
            "cleared the security log",
            "delete",
            "deleted",
            "removed",
            "rmdir",
            "rm -rf",
        ],
    ) {
        return Some(TextLogClassification {
            log_family: "tamper_or_deletion",
            classification: if contains_any_text(
                lower,
                &["wevtutil", "event log cleared", "cleared the security log"],
            ) {
                "log_clearing"
            } else {
                "file_deletion"
            },
            action_suffix: "tamper_or_deletion_observed",
            severity: if contains_any_text(
                lower,
                &["wevtutil", "event log cleared", "cleared the security log"],
            ) {
                "high"
            } else {
                "medium"
            },
            http_method: None,
            http_status: None,
            username: extract_username_hint(line),
            command_hint: extract_command_hint(line),
        });
    }

    None
}

fn extract_http_log_fields(line: &str) -> (Option<String>, Option<i64>) {
    let mut method_index = None;
    let parts = line.split_whitespace().collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        if is_http_method(part) {
            method_index = Some(index);
            break;
        }
    }
    let method = method_index.map(|index| parts[index].to_ascii_uppercase());
    let status = method_index.and_then(|index| {
        parts
            .iter()
            .skip(index + 1)
            .filter_map(|part| part.parse::<i64>().ok())
            .filter(|value| (100..=599).contains(value))
            .rev()
            .find(|value| !matches!(value, 80 | 443))
    });
    (method, status)
}

fn is_http_method(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE"
    )
}

fn extract_username_hint(line: &str) -> Option<String> {
    extract_label_value(
        line,
        &[
            "UserName",
            "Username",
            "User",
            "Account Name",
            "TargetUserName",
            "SubjectUserName",
            "user",
        ],
    )
    .or_else(|| {
        let lower = line.to_ascii_lowercase();
        for marker in [" for ", " user ", " account "] {
            if let Some(pos) = lower.find(marker) {
                let candidate = line[pos + marker.len()..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches(|ch: char| {
                        !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' && ch != '.'
                    });
                if candidate.len() >= 2 {
                    return Some(candidate.to_string());
                }
            }
        }
        None
    })
}

fn extract_command_hint(line: &str) -> Option<String> {
    extract_label_value(line, &["CommandLine", "Command", "cmd", "command"]).or_else(|| {
        let lower = line.to_ascii_lowercase();
        for marker in [
            "powershell",
            "cmd.exe",
            "curl ",
            "wget ",
            "certutil",
            "bitsadmin",
        ] {
            if let Some(pos) = lower.find(marker) {
                return Some(truncate(&line[pos..], 240));
            }
        }
        None
    })
}

fn text_document_signal_severity(lower: &str) -> &'static str {
    if contains_any_text(
        lower,
        &[
            "powershell",
            "cmd.exe",
            "rundll32",
            "regsvr32",
            "mshta",
            "mimikatz",
            "lsass",
        ],
    ) {
        "high"
    } else if contains_any_text(lower, &["download", "upload", "error", "fail", "warning"]) {
        "medium"
    } else {
        "info"
    }
}

fn parse_filezilla_artifact(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> ParsedArtifact {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();
    let blocks = extract_xml_blocks(text, "Server");
    let records = if blocks.is_empty() {
        vec![text.to_string()]
    } else {
        blocks
    };

    for (idx, record) in records.iter().enumerate() {
        let remote_host = extract_xml_tag(record, "Host");
        let port = extract_xml_tag(record, "Port");
        let user_name =
            extract_xml_tag(record, "User").or_else(|| user_from_path(&input.original_path));
        let password_raw = extract_xml_tag(record, "Pass");
        let password_encoding = extract_xml_attr_in_tag(record, "Pass", "encoding");
        let password_decoded = password_raw.as_deref().and_then(|value| {
            if password_encoding
                .as_deref()
                .is_some_and(|encoding| encoding.eq_ignore_ascii_case("base64"))
            {
                decode_base64_utf8(value)
            } else {
                clean_opt(Some(value.to_string()))
            }
        });
        let remote_path_raw = extract_xml_tag(record, "RemotePath");
        let remote_path_normalized = remote_path_raw
            .as_deref()
            .and_then(normalize_filezilla_remote_path);
        let local_path = extract_xml_tag(record, "LocalPath");
        let file_path = remote_path_normalized
            .clone()
            .or_else(|| local_path.clone())
            .or_else(|| Some(input.original_path.clone()));
        let server_url = remote_host
            .as_deref()
            .map(|host| filezilla_server_url(host, port.as_deref()));
        let remote_ip = remote_host
            .as_deref()
            .filter(|host| looks_like_ipv4(host))
            .map(str::to_string);
        let action = if password_decoded.is_some() {
            "filezilla_saved_password_recovered"
        } else if remote_path_normalized.is_some() {
            "filezilla_remote_path_recovered"
        } else {
            "filezilla_server_observed"
        };
        let severity = if password_decoded.is_some() {
            "high"
        } else if remote_host.is_some() && remote_path_normalized.is_some() {
            "medium"
        } else {
            "info"
        };
        let host_label = remote_host.as_deref().unwrap_or("(unknown)");
        let user_label = user_name.as_deref().unwrap_or("(unknown)");
        let message_full = match remote_path_normalized.as_deref() {
            Some(remote_path) => {
                format!(
                    "FileZilla server observed: host={host_label} user={user_label} remote_path={remote_path}"
                )
            }
            None => format!("FileZilla server observed: host={host_label} user={user_label}"),
        };
        let attributes_json = json!({
            "parser_mode": "filezilla_xml",
            "record_index": idx,
            "remote_host": remote_host,
            "remote_port": port,
            "remote_user": user_name,
            "password_encoding": password_encoding,
            "password_raw_present": password_raw.is_some(),
            "password_decoded": password_decoded,
            "remote_path_raw": remote_path_raw,
            "remote_path_normalized": remote_path_normalized,
            "local_path": local_path,
            "exfil_path_candidate": remote_path_raw.is_some(),
            "answer_recovery_candidate": true,
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "filezilla_xml",
            "record_index": idx,
            "xml": truncate(record, 4096),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "filezilla",
            (base_time + Duration::seconds(idx as i64)).to_rfc3339(),
            String::new(),
            "file_import_observed",
            0.25,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            None,
            file_path,
            remote_ip,
            server_url,
            None,
            action.to_string(),
            severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if events.is_empty() {
        return parse_text_document(input, metadata, text, "filezilla");
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn parse_filezilla_queue_metadata(
    input: &ParserInput,
    metadata: &ParserMetadata,
) -> ParsedArtifact {
    let message_full = format!(
        "FileZilla queue database observed: {} bytes={} (SQLite sidecar required)",
        input.original_path,
        input.bytes.len()
    );
    let attributes_json = json!({
        "parser_mode": "filezilla_queue_metadata",
        "byte_count": input.bytes.len(),
        "extension": extension_from_path(&input.original_path),
        "file_signature": artifact_signature(&input.bytes),
        "sidecar_recommended": "sqlite_queue_parser",
        "deep_structure_required": true,
        "answer_recovery_candidate": true,
    })
    .to_string();
    let raw_json = json!({
        "parser_mode": "filezilla_queue_metadata",
        "path": input.original_path.clone(),
        "byte_count": input.bytes.len(),
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        "filezilla",
        Utc::now().to_rfc3339(),
        String::new(),
        "file_import_observed",
        0.2,
        host_from_path(&input.original_path),
        user_from_path(&input.original_path),
        None,
        Some(input.original_path.clone()),
        None,
        None,
        None,
        "filezilla_queue_database_observed".to_string(),
        "medium".to_string(),
        message_full,
        attributes_json,
        raw_json,
    );
    ParsedArtifact {
        events: vec![event],
        raw_records: vec![raw],
    }
}

fn parse_recovery_artifact_metadata(
    input: &ParserInput,
    metadata: &ParserMetadata,
    artifact_type: &str,
) -> ParsedArtifact {
    let lower = input.original_path.to_ascii_lowercase();
    let extension = extension_from_path(&lower);
    let signature = artifact_signature(&input.bytes);
    let (normalized_type, action, severity, sidecar, recovery_target, cve_hints): (
        &str,
        &str,
        &str,
        &str,
        &str,
        Vec<&str>,
    ) = match artifact_type {
        "credential_store" => {
            if lower.ends_with("/login data") || lower.ends_with("\\login data") {
                (
                    "credential_store",
                    "browser_login_data_observed",
                    "high",
                    "chromium_dpapi_credential_recovery",
                    "Chrome/Edge Login Data",
                    Vec::new(),
                )
            } else if lower.ends_with(".kdbx") {
                (
                    "credential_store",
                    "keepass_database_observed",
                    "medium",
                    "keepass_recovery_workflow",
                    "KeePass database",
                    Vec::new(),
                )
            } else if lower.contains("/microsoft/protect/")
                || lower.contains("\\microsoft\\protect\\")
            {
                (
                    "credential_store",
                    "dpapi_masterkey_observed",
                    "medium",
                    "dpapi_masterkey_recovery",
                    "DPAPI masterkey",
                    Vec::new(),
                )
            } else {
                (
                    "credential_store",
                    "credential_store_observed",
                    "medium",
                    "credential_recovery_workflow",
                    "credential store",
                    Vec::new(),
                )
            }
        }
        "network_capture" => (
            "network_capture",
            "network_capture_observed",
            "medium",
            "zeek_tshark_pcap_analysis",
            "network traffic",
            Vec::new(),
        ),
        "archive" => {
            let cve_hints = if extension.as_deref() == Some("rar") {
                vec!["CVE-2023-38831"]
            } else {
                Vec::new()
            };
            (
                "archive",
                "archive_recovery_candidate",
                if cve_hints.is_empty() {
                    "medium"
                } else {
                    "high"
                },
                "archive_listing_and_carving",
                "archive contents",
                cve_hints,
            )
        }
        _ => (
            "document",
            "document_recovery_candidate",
            "medium",
            "tika_oletools_document_recovery",
            "document text/metadata",
            Vec::new(),
        ),
    };
    let sidecar_tools = sidecar_tool_candidates(sidecar, &lower, extension.as_deref());
    let sidecar_steps = sidecar_workflow_steps(sidecar);
    let sidecar_outputs = sidecar_expected_outputs(sidecar);
    let message_full = format!(
        "{recovery_target} recovery candidate: {} bytes={} sidecar={sidecar}",
        input.original_path,
        input.bytes.len()
    );
    let attributes_json = json!({
        "parser_mode": "recovery_artifact_metadata",
        "byte_count": input.bytes.len(),
        "extension": extension,
        "file_signature": signature,
        "recovery_target": recovery_target,
        "recovery_status": "pending_sidecar",
        "sidecar_recommended": sidecar,
        "sidecar_tool_candidates": sidecar_tools,
        "sidecar_workflow_steps": sidecar_steps,
        "sidecar_expected_outputs": sidecar_outputs,
        "sidecar_execution_policy": "manual_or_background_job_only",
        "deep_structure_required": true,
        "answer_recovery_candidate": true,
        "cve_hints": cve_hints,
    })
    .to_string();
    let raw_json = json!({
        "parser_mode": "recovery_artifact_metadata",
        "path": input.original_path.clone(),
        "byte_count": input.bytes.len(),
        "file_signature": artifact_signature(&input.bytes),
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        normalized_type,
        Utc::now().to_rfc3339(),
        String::new(),
        "file_import_observed",
        0.2,
        host_from_path(&input.original_path),
        user_from_path(&input.original_path),
        None,
        Some(input.original_path.clone()),
        None,
        extract_url_like(&ascii_preview_for_metadata(&input.bytes)),
        extract_hash_like(&ascii_preview_for_metadata(&input.bytes)),
        action.to_string(),
        severity.to_string(),
        message_full,
        attributes_json,
        raw_json,
    );
    ParsedArtifact {
        events: vec![event],
        raw_records: vec![raw],
    }
}

fn sidecar_tool_candidates(
    sidecar: &str,
    lower_path: &str,
    extension: Option<&str>,
) -> Vec<&'static str> {
    match sidecar {
        "chromium_dpapi_credential_recovery" => vec![
            "sqlite3",
            "pypykatz dpapi",
            "dpapick-rs",
            "browser local state key extractor",
        ],
        "keepass_recovery_workflow" => vec!["keepassxc-cli", "keepass2john", "john"],
        "dpapi_masterkey_recovery" => vec!["pypykatz dpapi", "dpapick-rs"],
        "credential_recovery_workflow" => {
            if lower_path.ends_with(".kdbx") {
                vec!["keepassxc-cli", "keepass2john"]
            } else {
                vec!["pypykatz dpapi", "dpapick-rs", "sqlite3"]
            }
        }
        "tika_oletools_document_recovery" => match extension {
            Some("pdf") => vec!["pdftotext", "exiftool", "apache-tika"],
            Some("doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "rtf") => {
                vec!["apache-tika", "oletools", "exiftool"]
            }
            _ => vec!["apache-tika", "exiftool"],
        },
        "zeek_tshark_pcap_analysis" => vec!["tshark", "zeek"],
        "archive_listing_and_carving" => vec!["7z", "unrar", "bsdtar"],
        "sqlite_queue_parser" => vec!["sqlite3"],
        _ => Vec::new(),
    }
}

fn sidecar_workflow_steps(sidecar: &str) -> Vec<&'static str> {
    match sidecar {
        "chromium_dpapi_credential_recovery" => vec![
            "collect Login Data and Local State/Protect masterkeys",
            "extract encrypted login blobs without modifying source evidence",
            "decrypt only in a derived workspace when keys are available",
            "import recovered URL/user/password metadata as derived evidence",
        ],
        "keepass_recovery_workflow" => vec![
            "inventory KDBX metadata and candidate key files",
            "run password/keyfile validation only against copied evidence",
            "import opened entry metadata or hash-cracking requirement as derived evidence",
        ],
        "dpapi_masterkey_recovery" => vec![
            "inventory masterkey/SID/protect folder relationship",
            "link browser and credential blobs to matching masterkeys",
            "import decryptability status and recovered secret metadata",
        ],
        "tika_oletools_document_recovery" => vec![
            "extract text and embedded metadata with Tika or format-specific tools",
            "scan extracted text for credentials, PII, URLs, and internal project names",
            "import extracted text summary and hashes as derived evidence",
        ],
        "zeek_tshark_pcap_analysis" => vec![
            "extract conversations, DNS, HTTP, TLS, FTP, and transferred files",
            "hash carved payloads and link them to timeline events",
            "import Zeek logs or tshark JSON as derived network events",
        ],
        "archive_listing_and_carving" => vec![
            "list archive entries without executing content",
            "identify exploit-prone paths and staged payloads",
            "hash extracted copies in a derived workspace",
        ],
        "sqlite_queue_parser" => vec![
            "open copied SQLite queue database read-only",
            "extract queued transfer host/user/local/remote paths",
            "import transfer rows as derived FileZilla events",
        ],
        _ => Vec::new(),
    }
}

fn sidecar_expected_outputs(sidecar: &str) -> Vec<&'static str> {
    match sidecar {
        "chromium_dpapi_credential_recovery" => vec![
            "derived_credentials.jsonl",
            "browser_login_recovery_report.json",
        ],
        "keepass_recovery_workflow" => {
            vec!["keepass_inventory.json", "keepass_recovery_status.json"]
        }
        "dpapi_masterkey_recovery" => vec!["dpapi_masterkey_inventory.json"],
        "tika_oletools_document_recovery" => vec![
            "document_text.txt",
            "document_metadata.json",
            "document_iocs.jsonl",
        ],
        "zeek_tshark_pcap_analysis" => {
            vec![
                "conn.log",
                "dns.log",
                "http.log",
                "files.log",
                "tshark.json",
            ]
        }
        "archive_listing_and_carving" => vec!["archive_listing.json", "carved_file_hashes.jsonl"],
        "sqlite_queue_parser" => vec!["filezilla_queue_transfers.jsonl"],
        _ => Vec::new(),
    }
}

fn parse_scheduled_task_xml(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> ParsedArtifact {
    let uri = extract_xml_tag(text, "URI").or_else(|| file_name_from_path(&input.original_path));
    let author = extract_xml_tag(text, "Author");
    let description = extract_xml_tag(text, "Description");
    let user_id = extract_xml_tag(text, "UserId").or_else(|| user_from_path(&input.original_path));
    let logon_type = extract_xml_tag(text, "LogonType");
    let run_level = extract_xml_tag(text, "RunLevel");
    let enabled = extract_xml_tag(text, "Enabled");
    let hidden = extract_xml_tag(text, "Hidden");
    let start_boundary = extract_xml_tag(text, "StartBoundary");
    let command = extract_xml_tag(text, "Command");
    let arguments = extract_xml_tag(text, "Arguments");
    let working_directory = extract_xml_tag(text, "WorkingDirectory");
    let command_line = [command.as_deref(), arguments.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let event_time = start_boundary.as_deref().and_then(normalize_datetime);
    let time_inferred = event_time.is_none();
    let event_time = event_time.unwrap_or_else(|| Utc::now().to_rfc3339());
    let process_name = command
        .as_deref()
        .and_then(file_name_from_path)
        .or_else(|| command.clone());
    let file_path = command
        .clone()
        .or_else(|| Some(input.original_path.clone()));
    let url = extract_url_like(&command_line);
    let hash = extract_hash_like(&command_line);
    let severity = scheduled_task_severity(&command_line);
    let event_action = if severity == "high" {
        "scheduled_task_suspicious_exec"
    } else {
        "scheduled_task_observed"
    };
    let task_name = uri.clone().unwrap_or_else(|| input.original_path.clone());
    let message_full = if command_line.trim().is_empty() {
        format!("Scheduled task observed: {task_name}")
    } else {
        format!("Scheduled task observed: {task_name} command={command_line}")
    };
    let attributes_json = json!({
        "parser_mode": "scheduled_task_xml",
        "uri": uri.clone(),
        "author": author.clone(),
        "description": description.clone(),
        "user_id": user_id.clone(),
        "logon_type": logon_type.clone(),
        "run_level": run_level.clone(),
        "enabled": enabled.clone(),
        "hidden": hidden.clone(),
        "start_boundary": start_boundary.clone(),
        "command": command.clone(),
        "arguments": arguments.clone(),
        "working_directory": working_directory.clone(),
        "time_inferred": time_inferred,
    })
    .to_string();
    let raw_json = json!({
        "parser_mode": "scheduled_task_xml",
        "path": input.original_path.clone(),
        "object_ref": input.object_ref.clone(),
        "task_name": task_name.clone(),
        "command_line": command_line.clone(),
        "sample": truncate(text, 4096),
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        "scheduled_task",
        event_time.clone(),
        start_boundary.clone().unwrap_or_else(|| event_time.clone()),
        "scheduled_task_trigger_or_import",
        if time_inferred { 0.2 } else { 0.65 },
        host_from_path(&input.original_path),
        user_id.clone(),
        process_name.clone(),
        file_path.clone(),
        None,
        url.clone(),
        hash.clone(),
        event_action.to_string(),
        severity.to_string(),
        message_full,
        attributes_json,
        raw_json,
    );
    let mut events = vec![event];
    let mut raw_records = vec![raw];

    if !command_line.trim().is_empty() {
        let attributes_json = json!({
            "parser_mode": "scheduled_task_exec_action",
            "uri": uri.clone(),
            "command": command.clone(),
            "arguments": arguments.clone(),
            "working_directory": working_directory.clone(),
            "enabled": enabled.clone(),
            "hidden": hidden.clone(),
            "run_level": run_level.clone(),
            "source_path": input.original_path,
            "time_inferred": time_inferred,
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "scheduled_task_exec_action",
            "task_name": task_name.clone(),
            "command_line": command_line.clone(),
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "scheduled_task",
            event_time.clone(),
            start_boundary.clone().unwrap_or_else(|| event_time.clone()),
            "scheduled_task_exec_action_observed",
            if time_inferred { 0.25 } else { 0.6 },
            host_from_path(&input.original_path),
            user_id.clone(),
            process_name,
            file_path,
            None,
            url,
            hash,
            "scheduled_task_exec_action".to_string(),
            severity.to_string(),
            format!("Scheduled task exec action: {task_name} command={command_line}"),
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if let Some(start_boundary) = start_boundary.as_deref() {
        let attributes_json = json!({
            "parser_mode": "scheduled_task_trigger",
            "uri": uri,
            "trigger_start_boundary": start_boundary,
            "enabled": enabled,
            "hidden": hidden,
            "source_path": input.original_path,
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "scheduled_task_trigger",
            "task_name": task_name,
            "trigger_start_boundary": start_boundary,
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "scheduled_task",
            event_time.clone(),
            start_boundary.to_string(),
            "scheduled_task_trigger_boundary",
            0.7,
            host_from_path(&input.original_path),
            user_id,
            None,
            Some(input.original_path.clone()),
            None,
            None,
            None,
            "scheduled_task_trigger_observed".to_string(),
            "info".to_string(),
            format!("Scheduled task trigger observed: {start_boundary}"),
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn scheduled_task_severity(command_line: &str) -> &'static str {
    let lower = command_line.to_ascii_lowercase();
    if lower.is_empty() {
        return "info";
    }
    if lower.contains("powershell")
        || lower.contains("pwsh")
        || lower.contains("cmd.exe")
        || lower.contains("wscript")
        || lower.contains("cscript")
        || lower.contains("mshta")
        || lower.contains("rundll32")
        || lower.contains("regsvr32")
        || lower.contains("bitsadmin")
        || lower.contains("certutil")
        || lower.contains("-enc")
        || lower.contains("-encodedcommand")
        || lower.contains("downloadstring")
        || lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("\\temp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\programdata\\")
        || lower.contains("\\public\\")
    {
        "high"
    } else {
        "medium"
    }
}

fn parse_prefetch_binary(input: &ParserInput, metadata: &ParserMetadata) -> ParsedArtifact {
    if let Ok(info) = prefetch_core::parse(&input.bytes) {
        return parse_prefetch_core_binary(input, metadata, info);
    }

    let decoded = prefetch_core::decompress(&input.bytes).ok();
    let structure_bytes = decoded.as_deref().unwrap_or(&input.bytes);
    let process_name = prefetch_executable_from_path(&input.original_path)
        .or_else(|| extract_prefetch_executable_from_strings(&input.bytes))
        .unwrap_or_else(|| input.original_path.clone());
    let strings = extract_interesting_strings(structure_bytes, 64);
    let referenced_files = prefetch_referenced_files(&strings);
    let version = prefetch_version(structure_bytes);
    let structure = parse_prefetch_structure(structure_bytes, version);
    let run_count = structure.run_count;
    let run_times = structure
        .run_time_entries
        .iter()
        .map(|entry| entry.timestamp.clone())
        .collect::<Vec<_>>();
    let prefetch_file_name = file_name_from_path(&input.original_path);
    let prefetch_hash = prefetch_file_name
        .as_deref()
        .or(Some(input.original_path.as_str()))
        .and_then(prefetch_hash_from_filename);
    let referenced_file_count = referenced_files.len();
    let suspicion = prefetch_suspicion(&process_name, &referenced_files);
    let severity = prefetch_severity(suspicion.as_deref()).to_string();
    if !run_times.is_empty() {
        let mut events = Vec::new();
        let mut raw_records = Vec::new();
        for (idx, event_time) in run_times.into_iter().enumerate() {
            let message_full = match run_count {
                Some(run_count) => {
                    format!("Prefetch execution: {process_name} run_count={run_count}")
                }
                None => format!("Prefetch execution: {process_name}"),
            };
            let attributes_json = json!({
                "parser_mode": "prefetch_binary_v2",
                "container": prefetch_container_kind(&input.bytes),
                "offset_basis": if decoded.is_some() { "scca_decompressed" } else { "raw_object" },
                "decompressed_size": decoded.as_ref().map(|bytes| bytes.len()),
                "version": version,
                "prefetch_version_family": structure.version_family,
                "file_size_header": structure.file_size_header,
                "executable_name_header": structure.executable_name_header.clone(),
                "sections": prefetch_section_json(&structure.sections),
                "section_count": structure.sections.len(),
                "volume_strings": structure.volume_strings.clone(),
                "file_metric_count": structure.file_metrics_count,
                "file_metrics": prefetch_file_metric_json(&structure.file_metrics),
                "trace_chain_count": structure.trace_chain_count,
                "trace_chains": prefetch_trace_chain_json(&structure.trace_chains),
                "run_count": run_count,
                "run_count_offset": structure.run_count_offset,
                "run_time_entries": prefetch_run_time_json(&structure.run_time_entries),
                "prefetch_file_name": prefetch_file_name.clone(),
                "prefetch_hash": prefetch_hash.clone(),
                "execution_index": idx,
                "referenced_file_count": referenced_file_count,
                "referenced_files": referenced_files.clone(),
                "suspicion": suspicion.clone(),
                "strings_sample": strings.iter().take(16).collect::<Vec<_>>(),
            })
            .to_string();
            let raw_json = json!({
                "parser_mode": "prefetch_binary_v2",
                "container": prefetch_container_kind(&input.bytes),
                "offset_basis": if decoded.is_some() { "scca_decompressed" } else { "raw_object" },
                "path": input.original_path.clone(),
                "object_ref": input.object_ref.clone(),
                "size": input.bytes.len(),
                "decompressed_size": decoded.as_ref().map(|bytes| bytes.len()),
                "file_size_header": structure.file_size_header,
                "sections": prefetch_section_json(&structure.sections),
                "file_metrics": prefetch_file_metric_json(&structure.file_metrics),
                "trace_chains": prefetch_trace_chain_json(&structure.trace_chains),
                "run_count_offset": structure.run_count_offset,
                "run_time_entries": prefetch_run_time_json(&structure.run_time_entries),
                "event_time": event_time,
                "execution_index": idx,
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "prefetch",
                event_time.clone(),
                event_time,
                if idx == 0 {
                    "prefetch_last_run"
                } else {
                    "prefetch_previous_run"
                },
                0.8,
                host_from_path(&input.original_path),
                user_from_path(&input.original_path),
                Some(process_name.clone()),
                Some(process_name.clone()),
                None,
                None,
                None,
                "process_executed".to_string(),
                severity.clone(),
                message_full,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
        }
        let reference_time = events
            .first()
            .map(|event| event.event_time_utc.clone())
            .unwrap_or_else(|| Utc::now().to_rfc3339());
        append_prefetch_reference_events(
            input,
            metadata,
            &mut events,
            &mut raw_records,
            &process_name,
            &referenced_files,
            &reference_time,
            prefetch_file_name.as_deref(),
            prefetch_hash.as_deref(),
            run_count,
            version,
        );
        append_prefetch_structure_summary_event(
            input,
            metadata,
            &mut events,
            &mut raw_records,
            &process_name,
            &reference_time,
            "prefetch_binary_structure",
            prefetch_file_name.clone(),
            prefetch_hash.clone(),
            version,
            run_count,
            referenced_file_count,
            None,
            prefetch_container_kind(&input.bytes),
            if decoded.is_some() {
                "scca_decompressed"
            } else {
                "raw_object"
            },
            prefetch_section_json(&structure.sections),
            prefetch_file_metric_json(&structure.file_metrics),
            prefetch_trace_chain_json(&structure.trace_chains),
            structure.volume_strings.clone(),
            suspicion.clone(),
        );
        return ParsedArtifact {
            events,
            raw_records,
        };
    }

    let message_full = format!("Prefetch file observed: {process_name}");
    let attributes_json = json!({
        "parser_mode": "prefetch_binary_metadata",
        "container": prefetch_container_kind(&input.bytes),
        "offset_basis": if decoded.is_some() { "scca_decompressed" } else { "raw_object" },
        "decompressed_size": decoded.as_ref().map(|bytes| bytes.len()),
        "version": version,
        "prefetch_version_family": structure.version_family,
        "file_size_header": structure.file_size_header,
        "executable_name_header": structure.executable_name_header.clone(),
        "sections": prefetch_section_json(&structure.sections),
        "section_count": structure.sections.len(),
        "volume_strings": structure.volume_strings.clone(),
        "file_metric_count": structure.file_metrics_count,
        "file_metrics": prefetch_file_metric_json(&structure.file_metrics),
        "trace_chain_count": structure.trace_chain_count,
        "trace_chains": prefetch_trace_chain_json(&structure.trace_chains),
        "run_count": run_count,
        "run_count_offset": structure.run_count_offset,
        "run_time_entries": prefetch_run_time_json(&structure.run_time_entries),
        "prefetch_file_name": prefetch_file_name.clone(),
        "prefetch_hash": prefetch_hash.clone(),
        "referenced_file_count": referenced_file_count,
        "referenced_files": referenced_files.clone(),
        "suspicion": suspicion.clone(),
        "strings_sample": strings.clone(),
    })
    .to_string();
    let raw_json = json!({
        "parser_mode": "prefetch_binary_metadata",
        "container": prefetch_container_kind(&input.bytes),
        "offset_basis": if decoded.is_some() { "scca_decompressed" } else { "raw_object" },
        "path": input.original_path.clone(),
        "object_ref": input.object_ref.clone(),
        "size": input.bytes.len(),
        "decompressed_size": decoded.as_ref().map(|bytes| bytes.len()),
        "file_size_header": structure.file_size_header,
        "sections": prefetch_section_json(&structure.sections),
        "file_metrics": prefetch_file_metric_json(&structure.file_metrics),
        "trace_chains": prefetch_trace_chain_json(&structure.trace_chains),
        "run_count_offset": structure.run_count_offset,
        "run_time_entries": prefetch_run_time_json(&structure.run_time_entries),
    })
    .to_string();
    let event_time = Utc::now().to_rfc3339();
    let (event, raw) = build_event(
        input,
        metadata,
        "prefetch",
        event_time.clone(),
        String::new(),
        "prefetch_file_import_observed",
        0.25,
        host_from_path(&input.original_path),
        user_from_path(&input.original_path),
        Some(process_name.clone()),
        Some(process_name.clone()),
        None,
        None,
        None,
        "process_executed".to_string(),
        severity,
        message_full,
        attributes_json,
        raw_json,
    );
    let mut events = vec![event];
    let mut raw_records = vec![raw];
    append_prefetch_reference_events(
        input,
        metadata,
        &mut events,
        &mut raw_records,
        &process_name,
        &referenced_files,
        &event_time,
        prefetch_file_name.as_deref(),
        prefetch_hash.as_deref(),
        run_count,
        version,
    );
    append_prefetch_structure_summary_event(
        input,
        metadata,
        &mut events,
        &mut raw_records,
        &process_name,
        &event_time,
        "prefetch_binary_structure",
        prefetch_file_name.clone(),
        prefetch_hash.clone(),
        version,
        run_count,
        referenced_file_count,
        None,
        prefetch_container_kind(&input.bytes),
        if decoded.is_some() {
            "scca_decompressed"
        } else {
            "raw_object"
        },
        prefetch_section_json(&structure.sections),
        prefetch_file_metric_json(&structure.file_metrics),
        prefetch_trace_chain_json(&structure.trace_chains),
        structure.volume_strings.clone(),
        suspicion.clone(),
    );
    ParsedArtifact {
        events,
        raw_records,
    }
}

fn parse_prefetch_core_binary(
    input: &ParserInput,
    metadata: &ParserMetadata,
    info: prefetch_core::PrefetchInfo,
) -> ParsedArtifact {
    let process_name = if info.executable.trim().is_empty() {
        prefetch_executable_from_path(&input.original_path)
            .unwrap_or_else(|| input.original_path.clone())
    } else {
        info.executable.clone()
    };
    let prefetch_file_name = file_name_from_path(&input.original_path);
    let prefetch_hash = prefetch_file_name
        .as_deref()
        .or(Some(input.original_path.as_str()))
        .and_then(prefetch_hash_from_filename);
    let referenced_files = prefetch_referenced_files(&info.filenames);
    let referenced_file_count = referenced_files.len();
    let suspicion = prefetch_suspicion(&process_name, &referenced_files);
    let severity = prefetch_severity(suspicion.as_deref()).to_string();
    let container = prefetch_container_kind(&input.bytes);
    let decompressed_size = prefetch_mam_declared_size(&input.bytes);
    let decoded = prefetch_core::decompress(&input.bytes).ok();
    let deep_structure = decoded
        .as_deref()
        .map(|bytes| parse_prefetch_structure(bytes, Some(info.version)));
    let version = Some(info.version);
    let run_count = Some(info.run_count);
    let volume_strings = info
        .volumes
        .iter()
        .map(|volume| volume.device_path.clone())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let volume_serials = info
        .volumes
        .iter()
        .map(|volume| format!("{:08X}", volume.serial))
        .collect::<Vec<_>>();
    let volume_creation_times = info
        .volumes
        .iter()
        .filter_map(|volume| filetime_i64_rfc3339(volume.creation_time))
        .collect::<Vec<_>>();
    let run_times = info
        .last_run_times
        .iter()
        .filter_map(|value| filetime_i64_rfc3339(*value))
        .filter(|value| is_plausible_forensic_time(value))
        .collect::<Vec<_>>();
    let run_time_entries = deep_structure
        .as_ref()
        .filter(|structure| !structure.run_time_entries.is_empty())
        .map(|structure| prefetch_run_time_json(&structure.run_time_entries))
        .unwrap_or_else(|| {
            run_times
                .iter()
                .enumerate()
                .map(|(idx, timestamp)| {
                    json!({
                        "execution_index": idx,
                        "timestamp": timestamp,
                        "source": "prefetch_core_last_run_times",
                        "confidence": 0.95,
                    })
                })
                .collect::<Vec<_>>()
        });
    let sections_json = deep_structure
        .as_ref()
        .map(|structure| prefetch_section_json(&structure.sections))
        .unwrap_or_default();
    let file_metrics_json = deep_structure
        .as_ref()
        .map(|structure| prefetch_file_metric_json(&structure.file_metrics))
        .unwrap_or_default();
    let trace_chains_json = deep_structure
        .as_ref()
        .map(|structure| prefetch_trace_chain_json(&structure.trace_chains))
        .unwrap_or_default();
    let file_metric_count = deep_structure
        .as_ref()
        .map(|structure| structure.file_metrics_count)
        .unwrap_or(0);
    let trace_chain_count = deep_structure
        .as_ref()
        .map(|structure| structure.trace_chain_count)
        .unwrap_or(0);
    let run_count_offset = deep_structure
        .as_ref()
        .and_then(|structure| structure.run_count_offset);
    let mut events = Vec::new();
    let mut raw_records = Vec::new();

    if !run_times.is_empty() {
        for (idx, event_time) in run_times.iter().cloned().enumerate() {
            let message_full = format!(
                "Prefetch execution: {process_name} run_count={}",
                info.run_count
            );
            let attributes_json = json!({
                "parser_mode": "prefetch_core_v1",
                "container": container,
                "compression": if container == "mam_xpress_huffman" { Some("xpress_huffman") } else { None },
                "mam_declared_decompressed_size": decompressed_size,
                "decompressed_size": decoded.as_ref().map(|bytes| bytes.len()),
                "offset_basis": if container == "mam_xpress_huffman" { "scca_decompressed" } else { "raw_object" },
                "version": info.version,
                "prefetch_version_family": match info.version {
                    30 => "windows_10_v30",
                    31 => "windows_11_v31",
                    _ => "unknown_prefetch_layout",
                },
                "executable_name_header": info.executable.clone(),
                "sections": sections_json.clone(),
                "section_count": sections_json.len(),
                "run_count": info.run_count,
                "run_count_offset": run_count_offset,
                "run_time_entries": run_time_entries.clone(),
                "prefetch_file_name": prefetch_file_name.clone(),
                "prefetch_hash": prefetch_hash.clone(),
                "execution_index": idx,
                "referenced_file_count": referenced_file_count,
                "referenced_files": referenced_files.clone(),
                "loaded_file_count": info.filenames.len(),
                "loaded_files_sample": info.filenames.iter().take(64).collect::<Vec<_>>(),
                "file_metric_count": file_metric_count,
                "file_metrics": file_metrics_json.clone(),
                "trace_chain_count": trace_chain_count,
                "trace_chains": trace_chains_json.clone(),
                "volume_strings": volume_strings.clone(),
                "volume_serials": volume_serials.clone(),
                "volume_creation_times": volume_creation_times.clone(),
                "suspicion": suspicion.clone(),
            })
            .to_string();
            let raw_json = json!({
                "parser_mode": "prefetch_core_v1",
                "container": container,
                "path": input.original_path,
                "object_ref": input.object_ref,
                "size": input.bytes.len(),
                "mam_declared_decompressed_size": decompressed_size,
                "decompressed_size": decoded.as_ref().map(|bytes| bytes.len()),
                "offset_basis": if container == "mam_xpress_huffman" { "scca_decompressed" } else { "raw_object" },
                "version": info.version,
                "sections": sections_json.clone(),
                "file_metrics": file_metrics_json.clone(),
                "trace_chains": trace_chains_json.clone(),
                "run_count": info.run_count,
                "run_count_offset": run_count_offset,
                "last_run_filetimes": info.last_run_times.clone(),
                "event_time": event_time,
                "execution_index": idx,
            })
            .to_string();
            let (event, raw) = build_event(
                input,
                metadata,
                "prefetch",
                event_time.clone(),
                event_time,
                if idx == 0 {
                    "prefetch_last_run"
                } else {
                    "prefetch_previous_run"
                },
                0.95,
                host_from_path(&input.original_path),
                user_from_path(&input.original_path),
                Some(process_name.clone()),
                Some(process_name.clone()),
                None,
                None,
                None,
                "process_executed".to_string(),
                severity.clone(),
                message_full,
                attributes_json,
                raw_json,
            );
            events.push(event);
            raw_records.push(raw);
        }
    } else {
        let event_time = Utc::now().to_rfc3339();
        let message_full = format!(
            "Prefetch file decoded without run time: {process_name} run_count={}",
            info.run_count
        );
        let attributes_json = json!({
            "parser_mode": "prefetch_core_v1",
            "container": container,
            "compression": if container == "mam_xpress_huffman" { Some("xpress_huffman") } else { None },
            "mam_declared_decompressed_size": decompressed_size,
            "decompressed_size": decoded.as_ref().map(|bytes| bytes.len()),
            "offset_basis": if container == "mam_xpress_huffman" { "scca_decompressed" } else { "raw_object" },
            "version": info.version,
            "executable_name_header": info.executable.clone(),
            "sections": sections_json.clone(),
            "section_count": sections_json.len(),
            "run_count": info.run_count,
            "run_count_offset": run_count_offset,
            "prefetch_file_name": prefetch_file_name.clone(),
            "prefetch_hash": prefetch_hash.clone(),
            "referenced_file_count": referenced_file_count,
            "referenced_files": referenced_files.clone(),
            "loaded_file_count": info.filenames.len(),
            "loaded_files_sample": info.filenames.iter().take(64).collect::<Vec<_>>(),
            "file_metric_count": file_metric_count,
            "file_metrics": file_metrics_json.clone(),
            "trace_chain_count": trace_chain_count,
            "trace_chains": trace_chains_json.clone(),
            "volume_strings": volume_strings.clone(),
            "volume_serials": volume_serials.clone(),
            "volume_creation_times": volume_creation_times.clone(),
            "suspicion": suspicion.clone(),
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "prefetch_core_v1",
            "container": container,
            "path": input.original_path,
            "object_ref": input.object_ref,
            "size": input.bytes.len(),
            "mam_declared_decompressed_size": decompressed_size,
            "decompressed_size": decoded.as_ref().map(|bytes| bytes.len()),
            "offset_basis": if container == "mam_xpress_huffman" { "scca_decompressed" } else { "raw_object" },
            "version": info.version,
            "sections": sections_json.clone(),
            "file_metrics": file_metrics_json.clone(),
            "trace_chains": trace_chains_json.clone(),
            "run_count": info.run_count,
            "run_count_offset": run_count_offset,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "prefetch",
            event_time.clone(),
            String::new(),
            "prefetch_file_import_observed",
            0.75,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            Some(process_name.clone()),
            Some(process_name.clone()),
            None,
            None,
            None,
            "process_executed".to_string(),
            severity.clone(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    let reference_time = events
        .first()
        .map(|event| event.event_time_utc.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    append_prefetch_reference_events(
        input,
        metadata,
        &mut events,
        &mut raw_records,
        &process_name,
        &referenced_files,
        &reference_time,
        prefetch_file_name.as_deref(),
        prefetch_hash.as_deref(),
        run_count,
        version,
    );
    append_prefetch_structure_summary_event(
        input,
        metadata,
        &mut events,
        &mut raw_records,
        &process_name,
        &reference_time,
        "prefetch_core_structure",
        prefetch_file_name.clone(),
        prefetch_hash.clone(),
        version,
        run_count,
        referenced_file_count,
        Some(info.filenames.len()),
        container,
        if container == "mam_xpress_huffman" {
            "scca_decompressed"
        } else {
            "raw_object"
        },
        sections_json.clone(),
        file_metrics_json.clone(),
        trace_chains_json.clone(),
        volume_strings.clone(),
        suspicion.clone(),
    );
    ParsedArtifact {
        events,
        raw_records,
    }
}

fn prefetch_container_kind(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"MAM\x04") {
        "mam_xpress_huffman"
    } else if bytes.get(4..8) == Some(b"SCCA") {
        "scca_raw"
    } else if bytes.starts_with(b"SCCA") {
        "scca_legacy_header"
    } else {
        "unknown_prefetch_container"
    }
}

fn prefetch_mam_declared_size(bytes: &[u8]) -> Option<u32> {
    if !bytes.starts_with(b"MAM\x04") || bytes.len() < 8 {
        return None;
    }
    Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
}

#[allow(clippy::too_many_arguments)]
fn append_prefetch_structure_summary_event(
    input: &ParserInput,
    metadata: &ParserMetadata,
    events: &mut Vec<EventFull>,
    raw_records: &mut Vec<RawRecord>,
    process_name: &str,
    reference_time: &str,
    parser_mode: &str,
    prefetch_file_name: Option<String>,
    prefetch_hash: Option<String>,
    version: Option<u32>,
    run_count: Option<u32>,
    referenced_file_count: usize,
    loaded_file_count: Option<usize>,
    container: &str,
    offset_basis: &str,
    sections: Vec<Value>,
    file_metrics: Vec<Value>,
    trace_chains: Vec<Value>,
    volume_strings: Vec<String>,
    suspicion: Option<String>,
) {
    if sections.is_empty()
        && file_metrics.is_empty()
        && trace_chains.is_empty()
        && volume_strings.is_empty()
    {
        return;
    }
    let message_full = format!(
        "Prefetch structure decoded: {process_name} sections={} file_metrics={} trace_chains={}",
        sections.len(),
        file_metrics.len(),
        trace_chains.len()
    );
    let attributes_json = json!({
        "parser_mode": parser_mode,
        "container": container,
        "offset_basis": offset_basis,
        "version": version,
        "prefetch_file_name": prefetch_file_name.clone(),
        "prefetch_hash": prefetch_hash.clone(),
        "run_count": run_count,
        "referenced_file_count": referenced_file_count,
        "loaded_file_count": loaded_file_count,
        "section_count": sections.len(),
        "sections": sections,
        "file_metric_count": file_metrics.len(),
        "file_metrics": file_metrics,
        "trace_chain_count": trace_chains.len(),
        "trace_chains": trace_chains,
        "volume_strings": volume_strings,
        "suspicion": suspicion,
        "structure_inline": true,
    })
    .to_string();
    let raw_json = json!({
        "parser_mode": parser_mode,
        "path": input.original_path.clone(),
        "object_ref": input.object_ref.clone(),
        "container": container,
        "offset_basis": offset_basis,
        "version": version,
        "prefetch_file_name": prefetch_file_name,
        "prefetch_hash": prefetch_hash,
        "run_count": run_count,
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        "prefetch",
        reference_time.to_string(),
        reference_time.to_string(),
        "prefetch_structure_observed",
        0.75,
        host_from_path(&input.original_path),
        user_from_path(&input.original_path),
        Some(process_name.to_string()),
        Some(process_name.to_string()),
        None,
        None,
        None,
        "prefetch_structure_decoded".to_string(),
        "info".to_string(),
        message_full,
        attributes_json,
        raw_json,
    );
    events.push(event);
    raw_records.push(raw);
}

fn append_prefetch_reference_events(
    input: &ParserInput,
    metadata: &ParserMetadata,
    events: &mut Vec<EventFull>,
    raw_records: &mut Vec<RawRecord>,
    process_name: &str,
    referenced_files: &[String],
    reference_time: &str,
    prefetch_file_name: Option<&str>,
    prefetch_hash: Option<&str>,
    run_count: Option<u32>,
    version: Option<u32>,
) {
    for (idx, file_path) in prefetch_reference_event_candidates(referenced_files)
        .into_iter()
        .enumerate()
    {
        let action = prefetch_reference_action(&file_path);
        let severity = prefetch_reference_severity(&file_path);
        let message_full = format!("Prefetch referenced file: {process_name} -> {file_path}");
        let attributes_json = json!({
            "parser_mode": "prefetch_reference_signal",
            "reference_index": idx + 1,
            "source_path": input.original_path,
            "prefetch_file_name": prefetch_file_name,
            "prefetch_hash": prefetch_hash,
            "run_count": run_count,
            "version": version,
            "referenced_file": file_path.clone(),
            "referenced_file_count": referenced_files.len(),
            "reference_priority": prefetch_reference_priority(&file_path),
            "time_inferred_from_prefetch_execution": true,
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "prefetch_reference_signal",
            "reference_index": idx + 1,
            "path": input.original_path,
            "referenced_file": file_path.clone(),
            "object_ref": input.object_ref,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "prefetch",
            reference_time.to_string(),
            reference_time.to_string(),
            "prefetch_reference_observed",
            0.45,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            Some(process_name.to_string()),
            Some(file_path),
            None,
            None,
            None,
            action.to_string(),
            severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }
}

fn prefetch_reference_event_candidates(referenced_files: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for file_path in referenced_files {
        if prefetch_reference_priority(file_path) == 0 {
            continue;
        }
        if out.iter().any(|existing| existing == file_path) {
            continue;
        }
        out.push(file_path.clone());
        if out.len() >= 16 {
            break;
        }
    }
    out
}

fn prefetch_referenced_files_from_export_row(
    row: &HashMap<String, String>,
    primary_file_path: Option<&str>,
    executable: &str,
) -> Vec<String> {
    let mut candidates = Vec::new();
    for value in row.values() {
        for candidate in extract_path_like_candidates(value) {
            let lower = candidate.to_ascii_lowercase();
            if lower.ends_with(".pf")
                || lower.contains("\\prefetch\\")
                || lower.contains("/prefetch/")
                || primary_file_path.is_some_and(|path| path.eq_ignore_ascii_case(&candidate))
                || executable.eq_ignore_ascii_case(&candidate)
                || candidates
                    .iter()
                    .any(|existing: &String| existing.eq_ignore_ascii_case(&candidate))
            {
                continue;
            }
            candidates.push(candidate);
        }
    }
    prefetch_referenced_files(&candidates)
}

fn prefetch_reference_priority(file_path: &str) -> u8 {
    let lower = file_path.to_ascii_lowercase();
    if suspicious_path(file_path) {
        return 4;
    }
    if lower.contains("\\users\\") || lower.contains("/users/") {
        return 3;
    }
    if lower.ends_with(".exe")
        || lower.ends_with(".ps1")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".vbs")
        || lower.ends_with(".js")
        || lower.ends_with(".scr")
    {
        return 2;
    }
    if lower.contains("\\program files") || lower.contains("/program files") {
        return 1;
    }
    0
}

fn prefetch_reference_action(file_path: &str) -> &'static str {
    let lower = file_path.to_ascii_lowercase();
    if lower.ends_with(".dll") {
        "prefetch_referenced_module"
    } else if prefetch_reference_priority(file_path) >= 2 {
        "prefetch_referenced_executable"
    } else {
        "prefetch_referenced_file"
    }
}

fn prefetch_reference_severity(file_path: &str) -> &'static str {
    if prefetch_reference_priority(file_path) >= 3 {
        "medium"
    } else {
        "info"
    }
}

fn parse_lnk_binary(input: &ParserInput, metadata: &ParserMetadata) -> ParsedArtifact {
    let lnk = parse_lnk_metadata(&input.bytes);
    let strings = extract_interesting_strings(&input.bytes, 48);
    let target = lnk
        .target_path
        .clone()
        .or_else(|| strings.iter().find(|value| looks_like_path(value)).cloned())
        .or_else(|| lnk_target_from_name(&input.original_path));
    let network_share_path = lnk.network_share_path.clone();
    let tracker_machine_id = lnk.tracker_machine_id.clone();
    let tracker_droid = lnk.tracker_droid.clone();
    let process_name = target.as_deref().and_then(file_name_from_path);
    let event_time = lnk
        .modified_at
        .clone()
        .or_else(|| lnk.created_at.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    let action = if target.as_deref().is_some_and(is_executable_name) {
        "lnk_target_executable_observed"
    } else {
        "lnk_observed"
    };
    let severity = if target
        .as_deref()
        .is_some_and(|value| suspicious_path(value) || is_executable_name(value))
    {
        "medium"
    } else {
        "info"
    };
    let message_full = match &target {
        Some(target) => format!("LNK observed: {} -> {target}", input.original_path),
        None => format!("LNK observed: {}", input.original_path),
    };
    let attributes_json = json!({
        "parser_mode": "lnk_binary_metadata",
        "link_flags": lnk.link_flags,
        "file_size_hint": lnk.file_size,
        "created_at": lnk.created_at,
        "accessed_at": lnk.accessed_at,
        "modified_at": lnk.modified_at,
        "local_base_path": lnk.local_base_path,
        "common_path_suffix": lnk.common_path_suffix,
        "relative_path": lnk.relative_path,
        "working_dir": lnk.working_dir,
        "arguments": lnk.arguments,
        "drive_serial": lnk.drive_serial,
        "volume_label": lnk.volume_label,
        "network_share_path": lnk.network_share_path,
        "network_device_name": lnk.network_device_name,
        "network_provider_type": lnk.network_provider_type,
        "machine_id_hint": lnk.machine_id_hint,
        "tracker_machine_id": lnk.tracker_machine_id,
        "tracker_droid": lnk.tracker_droid,
        "tracker_droid_birth": lnk.tracker_droid_birth,
        "extra_data_blocks": lnk_extra_data_json(&lnk.extra_data_blocks),
        "extra_data_block_count": lnk.extra_data_blocks.len(),
        "target_hint": target.clone(),
        "strings_sample": strings,
    })
    .to_string();
    let raw_json = json!({
        "parser_mode": "lnk_binary_metadata",
        "path": input.original_path.clone(),
        "object_ref": input.object_ref.clone(),
        "size": input.bytes.len(),
        "extra_data_blocks": lnk_extra_data_json(&lnk.extra_data_blocks),
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        "lnk",
        event_time.clone(),
        String::new(),
        "lnk_file_import_observed",
        if lnk.header_valid { 0.7 } else { 0.25 },
        host_from_path(&input.original_path),
        user_from_path(&input.original_path),
        process_name,
        target.clone().or_else(|| Some(input.original_path.clone())),
        None,
        None,
        None,
        action.to_string(),
        severity.to_string(),
        message_full,
        attributes_json,
        raw_json,
    );
    let mut events = vec![event];
    let mut raw_records = vec![raw];

    if let Some(target_path) = target.as_deref() {
        let target_lower = target_path.to_ascii_lowercase();
        let severity = if suspicious_path(target_path) || is_executable_name(target_path) {
            "medium"
        } else {
            "low"
        };
        let attributes_json = json!({
            "parser_mode": "lnk_target_reference",
            "link_path": input.original_path,
            "target_path": target_path,
            "target_basename": file_name_from_path(target_path),
            "target_is_executable": is_executable_name(target_path),
            "target_under_user_writable_path": suspicious_path(target_path)
                || contains_any_text(&target_lower, &["\\appdata\\", "\\temp\\", "\\downloads\\"]),
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "lnk_target_reference",
            "link_path": input.original_path.clone(),
            "target_path": target_path,
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "lnk",
            event_time.clone(),
            String::new(),
            "lnk_target_reference",
            if lnk.header_valid { 0.65 } else { 0.35 },
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            file_name_from_path(target_path),
            Some(target_path.to_string()),
            None,
            extract_url_like(target_path),
            extract_hash_like(target_path),
            "lnk_target_reference".to_string(),
            severity.to_string(),
            format!(
                "LNK target reference: {} -> {target_path}",
                input.original_path
            ),
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if let Some(share_path) = network_share_path.as_deref() {
        let attributes_json = json!({
            "parser_mode": "lnk_network_share_reference",
            "link_path": input.original_path,
            "network_share_path": share_path,
            "target_path": target.clone(),
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "lnk_network_share_reference",
            "link_path": input.original_path.clone(),
            "network_share_path": share_path,
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "lnk",
            event_time.clone(),
            String::new(),
            "lnk_network_share_reference",
            if lnk.header_valid { 0.65 } else { 0.3 },
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            None,
            Some(share_path.to_string()),
            None,
            None,
            None,
            "lnk_network_share_reference".to_string(),
            "medium".to_string(),
            format!(
                "LNK network share reference: {} -> {share_path}",
                input.original_path
            ),
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if tracker_machine_id.is_some() || tracker_droid.is_some() {
        let attributes_json = json!({
            "parser_mode": "lnk_tracker_reference",
            "link_path": input.original_path,
            "tracker_machine_id": tracker_machine_id.clone(),
            "tracker_droid": tracker_droid.clone(),
        })
        .to_string();
        let raw_json = json!({
            "parser_mode": "lnk_tracker_reference",
            "link_path": input.original_path.clone(),
            "object_ref": input.object_ref.clone(),
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "lnk",
            event_time,
            String::new(),
            "lnk_tracker_reference",
            if lnk.header_valid { 0.6 } else { 0.25 },
            tracker_machine_id
                .clone()
                .or_else(|| host_from_path(&input.original_path)),
            user_from_path(&input.original_path),
            None,
            target.clone().or_else(|| Some(input.original_path.clone())),
            None,
            None,
            None,
            "lnk_tracker_reference".to_string(),
            "low".to_string(),
            format!("LNK tracker metadata observed: {}", input.original_path),
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

#[derive(Debug, Default)]
struct LnkMetadata {
    header_valid: bool,
    link_flags: Option<u32>,
    file_size: Option<u32>,
    created_at: Option<String>,
    accessed_at: Option<String>,
    modified_at: Option<String>,
    target_path: Option<String>,
    local_base_path: Option<String>,
    common_path_suffix: Option<String>,
    relative_path: Option<String>,
    working_dir: Option<String>,
    arguments: Option<String>,
    drive_serial: Option<String>,
    volume_label: Option<String>,
    network_share_path: Option<String>,
    network_device_name: Option<String>,
    network_provider_type: Option<u32>,
    machine_id_hint: Option<String>,
    tracker_machine_id: Option<String>,
    tracker_droid: Option<String>,
    tracker_droid_birth: Option<String>,
    extra_data_blocks: Vec<LnkExtraDataBlockSummary>,
}

#[derive(Debug, Clone)]
struct LnkExtraDataBlockSummary {
    signature: u32,
    signature_name: &'static str,
    offset: usize,
    length: usize,
    strings: Vec<String>,
    guid_candidates: Vec<String>,
    property_entries: Vec<LnkPropertyStoreEntry>,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct LnkPropertyStoreEntry {
    key: String,
    value_hint: Option<String>,
    format_id: Option<String>,
    property_id: Option<u32>,
    value_offset: Option<usize>,
    value_length: Option<usize>,
    confidence: f64,
}

fn parse_lnk_metadata(bytes: &[u8]) -> LnkMetadata {
    let mut out = LnkMetadata::default();
    if bytes.len() < 0x4c || read_u32_le(bytes, 0) != Some(0x4c) {
        return out;
    }
    out.header_valid = true;
    let flags = read_u32_le(bytes, 0x14).unwrap_or_default();
    out.link_flags = Some(flags);
    out.file_size = read_u32_le(bytes, 0x34).filter(|value| *value > 0);
    out.created_at =
        read_filetime_rfc3339(bytes, 0x1c).filter(|value| is_plausible_forensic_time(value));
    out.accessed_at =
        read_filetime_rfc3339(bytes, 0x24).filter(|value| is_plausible_forensic_time(value));
    out.modified_at =
        read_filetime_rfc3339(bytes, 0x2c).filter(|value| is_plausible_forensic_time(value));

    let mut offset = 0x4cusize;
    if flags & 0x1 != 0 {
        if let Some(id_list_size) = read_u16_le(bytes, offset) {
            offset = offset
                .saturating_add(2)
                .saturating_add(id_list_size as usize);
        }
    }
    if flags & 0x2 != 0 {
        if let Some(link_info_size) = parse_lnk_link_info(bytes, offset, &mut out) {
            offset = offset.saturating_add(link_info_size);
        }
    }
    offset = parse_lnk_string_data(bytes, offset, flags, &mut out);
    parse_lnk_extra_data(bytes, offset, &mut out);
    out.machine_id_hint = out
        .tracker_machine_id
        .clone()
        .or_else(|| lnk_machine_id_hint(bytes));
    if out.target_path.is_none() {
        out.target_path = lnk_join_target(
            out.local_base_path.as_deref(),
            out.common_path_suffix.as_deref(),
        )
        .or_else(|| {
            lnk_join_target(
                out.network_share_path.as_deref(),
                out.common_path_suffix.as_deref(),
            )
        })
        .or_else(|| out.relative_path.clone())
        .or_else(|| out.local_base_path.clone());
    }
    out
}

fn parse_lnk_link_info(bytes: &[u8], offset: usize, out: &mut LnkMetadata) -> Option<usize> {
    let size = read_u32_le(bytes, offset)? as usize;
    if size < 0x1c || offset.checked_add(size)? > bytes.len() {
        return None;
    }
    let end = offset + size;
    let header_size = read_u32_le(bytes, offset + 4).unwrap_or(0) as usize;
    let flags = read_u32_le(bytes, offset + 8).unwrap_or_default();
    let volume_offset = read_u32_le(bytes, offset + 0x0c).unwrap_or_default() as usize;
    let local_base_offset = read_u32_le(bytes, offset + 0x10).unwrap_or_default() as usize;
    let network_offset = read_u32_le(bytes, offset + 0x14).unwrap_or_default() as usize;
    let suffix_offset = read_u32_le(bytes, offset + 0x18).unwrap_or_default() as usize;
    if flags & 0x1 != 0 {
        if let Some(value) = read_lnk_ascii_at(bytes, offset, local_base_offset, end) {
            out.local_base_path = Some(value);
        }
        if volume_offset > 0 {
            parse_lnk_volume_id(bytes, offset + volume_offset, end, out);
        }
    }
    if let Some(value) = read_lnk_ascii_at(bytes, offset, suffix_offset, end) {
        out.common_path_suffix = Some(value);
    }
    if flags & 0x2 != 0 && network_offset > 0 {
        parse_lnk_common_network_relative_link(bytes, offset + network_offset, end, out);
    }
    if header_size >= 0x24 {
        let local_unicode = read_u32_le(bytes, offset + 0x1c).unwrap_or_default() as usize;
        let suffix_unicode = read_u32_le(bytes, offset + 0x20).unwrap_or_default() as usize;
        if let Some(value) = read_lnk_utf16_at(bytes, offset, local_unicode, end) {
            out.local_base_path = Some(value);
        }
        if let Some(value) = read_lnk_utf16_at(bytes, offset, suffix_unicode, end) {
            out.common_path_suffix = Some(value);
        }
    }
    Some(size)
}

fn parse_lnk_volume_id(bytes: &[u8], offset: usize, end: usize, out: &mut LnkMetadata) {
    if offset + 0x10 > end {
        return;
    }
    if let Some(serial) = read_u32_le(bytes, offset + 8) {
        if serial != 0 {
            out.drive_serial = Some(format!("{serial:08x}"));
        }
    }
    let label_offset = read_u32_le(bytes, offset + 0x0c).unwrap_or_default() as usize;
    if let Some(label) = read_lnk_ascii_at(bytes, offset, label_offset, end) {
        out.volume_label = Some(label);
    }
}

fn parse_lnk_common_network_relative_link(
    bytes: &[u8],
    offset: usize,
    end: usize,
    out: &mut LnkMetadata,
) {
    if offset + 0x14 > end {
        return;
    }
    let size = read_u32_le(bytes, offset).unwrap_or_default() as usize;
    if size < 0x14 || offset + size > end {
        return;
    }
    let block_end = offset + size;
    let net_name_offset = read_u32_le(bytes, offset + 0x08).unwrap_or_default() as usize;
    let device_name_offset = read_u32_le(bytes, offset + 0x0c).unwrap_or_default() as usize;
    out.network_provider_type = read_u32_le(bytes, offset + 0x10).filter(|value| *value != 0);
    if let Some(value) = read_lnk_ascii_at(bytes, offset, net_name_offset, block_end) {
        out.network_share_path = Some(value);
    }
    if let Some(value) = read_lnk_ascii_at(bytes, offset, device_name_offset, block_end) {
        out.network_device_name = Some(value);
    }
    if size >= 0x1c {
        let net_unicode = read_u32_le(bytes, offset + 0x14).unwrap_or_default() as usize;
        let device_unicode = read_u32_le(bytes, offset + 0x18).unwrap_or_default() as usize;
        if let Some(value) = read_lnk_utf16_at(bytes, offset, net_unicode, block_end) {
            out.network_share_path = Some(value);
        }
        if let Some(value) = read_lnk_utf16_at(bytes, offset, device_unicode, block_end) {
            out.network_device_name = Some(value);
        }
    }
}

fn parse_lnk_string_data(
    bytes: &[u8],
    mut offset: usize,
    flags: u32,
    out: &mut LnkMetadata,
) -> usize {
    let is_unicode = flags & 0x80 != 0;
    for (flag, slot) in [
        (0x4, None),
        (0x8, Some("relative_path")),
        (0x10, Some("working_dir")),
        (0x20, Some("arguments")),
        (0x40, None),
    ] {
        if flags & flag == 0 {
            continue;
        }
        let Some((value, next_offset)) = read_lnk_counted_string(bytes, offset, is_unicode) else {
            return offset;
        };
        offset = next_offset;
        match slot {
            Some("relative_path") => out.relative_path = Some(value),
            Some("working_dir") => out.working_dir = Some(value),
            Some("arguments") => out.arguments = Some(value),
            _ => {}
        }
    }
    offset
}

fn parse_lnk_extra_data(bytes: &[u8], mut offset: usize, out: &mut LnkMetadata) {
    while offset + 8 <= bytes.len() {
        let Some(block_size) = read_u32_le(bytes, offset).map(|value| value as usize) else {
            break;
        };
        if block_size == 0 {
            break;
        }
        if block_size < 8 || offset + block_size > bytes.len() {
            break;
        }
        let signature = read_u32_le(bytes, offset + 4).unwrap_or_default();
        out.extra_data_blocks
            .push(parse_lnk_extra_data_block_summary(
                bytes, offset, block_size, signature,
            ));
        if signature == 0xa0000003 {
            parse_lnk_tracker_data_block(bytes, offset, block_size, out);
        }
        offset += block_size;
    }
}

fn parse_lnk_extra_data_block_summary(
    bytes: &[u8],
    offset: usize,
    block_size: usize,
    signature: u32,
) -> LnkExtraDataBlockSummary {
    let block = &bytes[offset..offset + block_size];
    let strings = extract_interesting_strings(block, 12);
    let guid_candidates = if signature == 0xa0000009 {
        lnk_guid_candidates(block)
    } else {
        Vec::new()
    };
    let property_entries = if signature == 0xa0000009 {
        parse_lnk_property_store_entries(block, offset)
    } else {
        Vec::new()
    };
    LnkExtraDataBlockSummary {
        signature,
        signature_name: lnk_extra_data_signature_name(signature),
        offset,
        length: block_size,
        strings,
        guid_candidates,
        property_entries,
        confidence: if signature == 0xa0000009 { 0.85 } else { 0.75 },
    }
}

fn lnk_extra_data_signature_name(signature: u32) -> &'static str {
    match signature {
        0xa0000001 => "EnvironmentVariableDataBlock",
        0xa0000002 => "ConsoleDataBlock",
        0xa0000003 => "TrackerDataBlock",
        0xa0000004 => "ConsoleFEDataBlock",
        0xa0000005 => "SpecialFolderDataBlock",
        0xa0000006 => "DarwinDataBlock",
        0xa0000007 => "IconEnvironmentDataBlock",
        0xa0000008 => "ShimDataBlock",
        0xa0000009 => "PropertyStoreDataBlock",
        0xa000000b => "KnownFolderDataBlock",
        0xa000000c => "VistaAndAboveIDListDataBlock",
        _ => "UnknownExtraDataBlock",
    }
}

fn lnk_guid_candidates(block: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for (_, value) in lnk_guid_candidate_records(block) {
        if !out.iter().any(|existing| existing == &value) {
            out.push(value);
        }
        if out.len() >= 8 {
            break;
        }
    }
    out
}

fn lnk_guid_candidate_records(block: &[u8]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut offset = 8usize;
    while offset + 16 <= block.len() && out.len() < 16 {
        let guid = &block[offset..offset + 16];
        if guid.iter().any(|byte| *byte != 0) {
            let value = format_guid_le(guid);
            if !out.iter().any(|(_, existing)| existing == &value) {
                out.push((offset, value));
            }
        }
        offset += 4;
    }
    out
}

fn format_guid_le(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[derive(Debug, Clone)]
struct LnkTextCandidate {
    offset: usize,
    value: String,
    encoding: &'static str,
}

fn parse_lnk_property_store_entries(
    block: &[u8],
    absolute_block_offset: usize,
) -> Vec<LnkPropertyStoreEntry> {
    let mut entries = Vec::new();
    let guid = lnk_guid_candidate_records(block)
        .into_iter()
        .next()
        .map(|(_, value)| value);
    let mut candidates = lnk_property_text_candidates(block);
    candidates.sort_by_key(|candidate| candidate.offset);
    for (idx, candidate) in candidates.iter().enumerate() {
        let key = lnk_property_key(&candidate.value).or_else(|| {
            if looks_like_path(&candidate.value)
                || looks_like_url(&candidate.value)
                || is_executable_name(&candidate.value)
            {
                Some("lnk.property.value".to_string())
            } else {
                None
            }
        });
        let Some(key) = key else {
            continue;
        };
        let value_hint = lnk_property_value_hint(&candidates, idx);
        let property_id = lnk_property_id_near(block, candidate.offset);
        let confidence = if key.starts_with("System.") {
            0.78
        } else if value_hint.is_some() {
            0.62
        } else {
            0.45
        };
        entries.push(LnkPropertyStoreEntry {
            key,
            value_hint,
            format_id: guid.clone(),
            property_id,
            value_offset: Some(absolute_block_offset + candidate.offset),
            value_length: Some(
                candidate.value.len()
                    * if candidate.encoding == "utf16le" {
                        2
                    } else {
                        1
                    },
            ),
            confidence,
        });
        if entries.len() >= 24 {
            break;
        }
    }
    entries
}

fn lnk_property_text_candidates(block: &[u8]) -> Vec<LnkTextCandidate> {
    let mut out = Vec::new();
    out.extend(
        extract_ascii_strings_with_offsets(block)
            .into_iter()
            .map(|(offset, value)| LnkTextCandidate {
                offset,
                value,
                encoding: "ascii",
            }),
    );
    out.extend(
        extract_utf16le_strings_with_offsets(block)
            .into_iter()
            .map(|(offset, value)| LnkTextCandidate {
                offset,
                value,
                encoding: "utf16le",
            }),
    );
    out.retain(|candidate| {
        let value = candidate.value.trim();
        value.len() >= 4
            && (value.starts_with("System.")
                || value.contains("AppUserModel")
                || looks_like_path(value)
                || looks_like_url(value)
                || is_executable_name(value)
                || (value.len() <= 260 && value.chars().any(|ch| ch.is_ascii_alphanumeric())))
    });
    out
}

fn lnk_property_key(value: &str) -> Option<String> {
    let trimmed = value.trim_matches(char::from(0)).trim();
    if trimmed.starts_with("System.") && trimmed.len() <= 160 {
        return Some(trimmed.to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("appusermodel") {
        return Some("System.AppUserModel.ID".to_string());
    }
    if lower.contains("targetparsingpath") {
        return Some("System.Link.TargetParsingPath".to_string());
    }
    if lower.contains("itemnamedisplay") {
        return Some("System.ItemNameDisplay".to_string());
    }
    None
}

fn lnk_property_value_hint(candidates: &[LnkTextCandidate], idx: usize) -> Option<String> {
    candidates.iter().skip(idx + 1).find_map(|candidate| {
        let value = candidate.value.trim();
        if value.starts_with("System.") || value.contains("AppUserModel") {
            return None;
        }
        if value.len() >= 2 {
            Some(truncate(value, 220))
        } else {
            None
        }
    })
}

fn lnk_property_id_near(block: &[u8], offset: usize) -> Option<u32> {
    for candidate_offset in offset.saturating_sub(16)..=offset.saturating_sub(4) {
        let Some(value) = read_u32_le(block, candidate_offset) else {
            continue;
        };
        if (1..=100_000).contains(&value) {
            return Some(value);
        }
    }
    None
}

fn lnk_property_entries_json(entries: &[LnkPropertyStoreEntry]) -> Vec<Value> {
    entries
        .iter()
        .map(|entry| {
            json!({
                "key": entry.key,
                "value_hint": entry.value_hint,
                "format_id": entry.format_id,
                "property_id": entry.property_id,
                "value_offset": entry.value_offset,
                "value_length": entry.value_length,
                "confidence": entry.confidence,
            })
        })
        .collect()
}

fn lnk_extra_data_json(blocks: &[LnkExtraDataBlockSummary]) -> Vec<Value> {
    blocks
        .iter()
        .take(16)
        .map(|block| {
            json!({
                "signature": format!("{:08x}", block.signature),
                "signature_raw": block.signature,
                "signature_name": block.signature_name,
                "offset": block.offset,
                "length": block.length,
                "strings": block.strings,
                "guid_candidates": block.guid_candidates,
                "property_entries": lnk_property_entries_json(&block.property_entries),
                "confidence": block.confidence,
            })
        })
        .collect()
}

fn parse_lnk_tracker_data_block(
    bytes: &[u8],
    offset: usize,
    block_size: usize,
    out: &mut LnkMetadata,
) {
    if block_size < 0x60 || offset + 0x60 > bytes.len() {
        return;
    }
    let machine_start = offset + 0x10;
    let machine_end = machine_start + 16;
    let machine =
        sanitize_display_text(&String::from_utf8_lossy(&bytes[machine_start..machine_end]))
            .trim_matches(char::from(0))
            .trim()
            .to_string();
    if !machine.is_empty() {
        out.tracker_machine_id = Some(machine);
    }
    out.tracker_droid = Some(lnk_hex(&bytes[offset + 0x20..offset + 0x40]));
    out.tracker_droid_birth = Some(lnk_hex(&bytes[offset + 0x40..offset + 0x60]));
}

fn read_lnk_counted_string(
    bytes: &[u8],
    offset: usize,
    is_unicode: bool,
) -> Option<(String, usize)> {
    let chars = read_u16_le(bytes, offset)? as usize;
    let start = offset + 2;
    let byte_len = if is_unicode {
        chars.checked_mul(2)?
    } else {
        chars
    };
    let end = start.checked_add(byte_len)?;
    if end > bytes.len() {
        return None;
    }
    let value = if is_unicode {
        decode_utf16le_lossy(&bytes[start..end])
    } else {
        sanitize_display_text(&String::from_utf8_lossy(&bytes[start..end]))
    };
    Some((value, end))
}

fn read_lnk_ascii_at(bytes: &[u8], base: usize, relative: usize, end: usize) -> Option<String> {
    if relative == 0 {
        return None;
    }
    let start = base.checked_add(relative)?;
    if start >= end || start >= bytes.len() {
        return None;
    }
    let max = end.min(bytes.len());
    let nul = bytes[start..max]
        .iter()
        .position(|byte| *byte == 0)
        .map(|idx| start + idx)
        .unwrap_or(max);
    let value = sanitize_display_text(&String::from_utf8_lossy(&bytes[start..nul]));
    (!value.is_empty()).then_some(value)
}

fn read_lnk_utf16_at(bytes: &[u8], base: usize, relative: usize, end: usize) -> Option<String> {
    if relative == 0 {
        return None;
    }
    let start = base.checked_add(relative)?;
    if start + 2 > end || start + 2 > bytes.len() {
        return None;
    }
    let max = end.min(bytes.len());
    let mut cursor = start;
    while cursor + 1 < max {
        if bytes[cursor] == 0 && bytes[cursor + 1] == 0 {
            break;
        }
        cursor += 2;
    }
    let value = decode_utf16le_lossy(&bytes[start..cursor]);
    (!value.is_empty()).then_some(value)
}

fn lnk_join_target(base: Option<&str>, suffix: Option<&str>) -> Option<String> {
    let base = base?.trim();
    if base.is_empty() {
        return None;
    }
    let suffix = suffix
        .unwrap_or("")
        .trim_matches(|ch| ch == '\\' || ch == '/');
    if suffix.is_empty() || base.ends_with(suffix) {
        return Some(base.to_string());
    }
    Some(format!(
        "{}\\{}",
        base.trim_end_matches(|ch| ch == '\\' || ch == '/'),
        suffix
    ))
}

fn lnk_machine_id_hint(bytes: &[u8]) -> Option<String> {
    extract_ascii_strings(bytes)
        .into_iter()
        .chain(extract_utf16le_strings(bytes))
        .map(|value| value.trim().to_string())
        .find(|value| {
            let len = value.len();
            (3..=32).contains(&len)
                && value
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                && value.chars().any(|ch| ch.is_ascii_alphabetic())
        })
}

fn lnk_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn parse_jump_list_strings(input: &ParserInput, metadata: &ParserMetadata) -> ParsedArtifact {
    let strings = extract_forensic_strings(&input.bytes, 20_000);
    let app_id = jump_list_app_id(&input.original_path);
    let source_kind = if input
        .original_path
        .to_ascii_lowercase()
        .contains("automaticdestinations")
    {
        "automatic_destinations"
    } else {
        "custom_destinations"
    };
    let mut seen = std::collections::HashSet::new();
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();

    for (idx, value) in strings.iter().enumerate() {
        let start = idx.saturating_sub(2);
        let end = (idx + 3).min(strings.len());
        let context = strings[start..end].join(" ");
        let lower = context.to_ascii_lowercase();
        let target = extract_path_like_candidates(&context)
            .into_iter()
            .find(|path| !path.eq_ignore_ascii_case(&input.original_path))
            .or_else(|| extract_recent_document_candidate(&context));
        let Some(target) = target else {
            continue;
        };
        let target_lower = target.to_ascii_lowercase();
        if target_lower.len() < 4
            || target_lower.contains("automaticdestinations-ms")
            || target_lower.contains("customdestinations-ms")
        {
            continue;
        }
        let action = if lower.contains("destlist") || source_kind == "automatic_destinations" {
            "jumplist_destlist_entry_observed"
        } else {
            "jumplist_recent_item_observed"
        };
        let dedup_key = format!(
            "{}|{}|{}",
            action,
            app_id.as_deref().unwrap_or("-"),
            target_lower
        );
        if !seen.insert(dedup_key) {
            continue;
        }
        let record_index = events.len();
        if record_index >= 500 {
            break;
        }
        let event_time = (base_time + Duration::milliseconds(record_index as i64)).to_rfc3339();
        let process_name = file_name_from_path(&target).filter(|name| is_executable_name(name));
        let severity = if process_name
            .as_deref()
            .is_some_and(is_suspicious_execution_name)
            || suspicious_path(&target)
        {
            "medium"
        } else {
            "info"
        };
        let message_full = format!(
            "Jump List item recovered: app_id={} target={target}",
            app_id.as_deref().unwrap_or("unknown")
        );
        let attributes_json = json!({
            "parser_mode": "jump_list_string_recovery",
            "source_kind": source_kind,
            "app_id": app_id.clone(),
            "jump_list_file": input.original_path,
            "source_string": truncate(value, 500),
            "context": truncate(&context, 1000),
            "time_inferred": true,
        })
        .to_string();
        let raw_json = json!({
            "record_index": record_index + 1,
            "parser_mode": "jump_list_string_recovery",
            "source_kind": source_kind,
            "app_id": app_id.clone(),
            "target": target,
            "context": truncate(&context, 1500),
            "object_ref": input.object_ref,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "jump_list",
            event_time.clone(),
            event_time,
            "artifact_import_time",
            0.25,
            host_from_path(&input.original_path),
            user_from_path(&input.original_path),
            process_name,
            Some(target.clone()),
            None,
            None,
            None,
            action.to_string(),
            severity.to_string(),
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }

    if events.is_empty() {
        return parse_file_metadata_event(
            input,
            metadata,
            "jump_list",
            "jump_list_observed",
            Some("no DestList or recent item strings were recovered".to_string()),
        );
    }

    ParsedArtifact {
        events,
        raw_records,
    }
}

fn parse_file_metadata_event(
    input: &ParserInput,
    metadata: &ParserMetadata,
    artifact_type: &str,
    action: &str,
    note: Option<String>,
) -> ParsedArtifact {
    let strings = extract_interesting_strings(&input.bytes, 32);
    let hash = strings
        .iter()
        .find(|value| {
            matches!(value.len(), 32 | 40 | 64) && value.chars().all(|ch| ch.is_ascii_hexdigit())
        })
        .cloned();
    let url = strings.iter().find(|value| looks_like_url(value)).cloned();
    let process_name = prefetch_executable_from_path(&input.original_path).or_else(|| {
        file_name_from_path(&input.original_path).filter(|name| is_executable_name(name))
    });
    let message_full = match &note {
        Some(note) => format!(
            "{}: {} size={} note={}",
            action,
            input.original_path,
            input.bytes.len(),
            note
        ),
        None => format!(
            "{}: {} size={}",
            action,
            input.original_path,
            input.bytes.len()
        ),
    };
    let attributes_json = json!({
        "parser_mode": "file_metadata",
        "note": note,
        "extension": extension_from_path(&input.original_path),
        "size": input.bytes.len(),
        "magic": magic_hint(&input.bytes),
        "strings_sample": strings,
    })
    .to_string();
    let raw_json = json!({
        "parser_mode": "file_metadata",
        "path": input.original_path.clone(),
        "object_ref": input.object_ref.clone(),
        "size": input.bytes.len(),
        "artifact_type": artifact_type,
    })
    .to_string();
    let (event, raw) = build_event(
        input,
        metadata,
        artifact_type,
        Utc::now().to_rfc3339(),
        String::new(),
        "file_import_observed",
        0.15,
        host_from_path(&input.original_path),
        user_from_path(&input.original_path),
        process_name,
        Some(input.original_path.clone()),
        None,
        url,
        hash,
        action.to_string(),
        metadata_severity(artifact_type, action).to_string(),
        message_full,
        attributes_json,
        raw_json,
    );
    ParsedArtifact {
        events: vec![event],
        raw_records: vec![raw],
    }
}

fn parse_defender_export(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let trimmed = text.trim_start();
    if trimmed.contains("<Event") {
        return Ok(parse_defender_xml(input, metadata, text));
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return parse_defender_flat(input, metadata, text);
    }
    let first_line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    if first_line.contains(',') && normalize_header(first_line).contains("event") {
        return parse_defender_flat(input, metadata, text);
    }
    Ok(parse_defender_mplog_lines(input, metadata, text))
}

fn parse_defender_xml(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> ParsedArtifact {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();
    for (idx, chunk) in xml_event_chunks(text).into_iter().enumerate() {
        let data = extract_named_data(&chunk);
        let event_code = clean_opt(extract_xml_tag(&chunk, "EventID"))
            .or_else(|| first_named(&data, &["EventID", "Id"]));
        let time_original = clean_opt(extract_xml_attr_in_tag(&chunk, "TimeCreated", "SystemTime"))
            .or_else(|| first_named(&data, &["TimeCreated", "SystemTime", "UtcTime"]));
        let event_time = time_original
            .as_deref()
            .and_then(normalize_datetime)
            .unwrap_or_else(|| (base_time + Duration::seconds(idx as i64)).to_rfc3339());
        let host = clean_opt(extract_xml_tag(&chunk, "Computer"))
            .or_else(|| first_named(&data, &["Computer", "MachineName", "Host"]));
        let process_name = first_named(&data, &["Process Name", "ProcessName", "Path", "Image"]);
        let file_path = first_named(
            &data,
            &[
                "Path",
                "FileName",
                "Filename",
                "Resource",
                "Resources",
                "TargetFilename",
                "ObjectName",
            ],
        )
        .or_else(|| process_name.clone());
        let threat = first_named(&data, &["Threat Name", "ThreatName", "Name"]);
        let action = defender_event_action(event_code.as_deref(), Some(&data));
        let severity =
            defender_event_severity(event_code.as_deref(), None, Some(&data)).to_string();
        let message_full = defender_message(
            event_code.as_deref(),
            &action,
            threat.as_deref(),
            file_path.as_deref(),
            Some(&data),
        );
        let attributes_json = json!({
            "event_id": event_code,
            "provider": extract_xml_attr_in_tag(&chunk, "Provider", "Name"),
            "record_id": extract_xml_tag(&chunk, "EventRecordID"),
            "channel": extract_xml_tag(&chunk, "Channel").or_else(|| Some("Microsoft-Windows-Windows Defender/Operational".to_string())),
            "defender_threat": threat,
            "data": data,
        })
        .to_string();
        let raw_json = json!({
            "record_index": idx + 1,
            "parser_mode": "defender_xml",
            "xml": chunk,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "defender",
            event_time,
            time_original.unwrap_or_default(),
            "defender_operational_time",
            0.95,
            host,
            first_named(&data, &["User", "UserName", "AccountName"]),
            process_name,
            file_path,
            None,
            None,
            first_named(&data, &["SHA256", "SHA1", "MD5", "Hash"]),
            action,
            severity,
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }
    ParsedArtifact {
        events,
        raw_records,
    }
}

fn parse_defender_flat(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> Result<ParsedArtifact> {
    let records = parse_flat_export_records(text, "defender")?;
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();
    for record in records {
        let event_code = cell(&record.row, &["eventid", "eventcode", "id"]);
        let level = cell(&record.row, &["level", "severity", "leveldisplayname"]);
        let time_original = cell(
            &record.row,
            &[
                "timecreated",
                "systemtime",
                "utctime",
                "timestamp",
                "datetime",
                "eventtimeutc",
                "time",
            ],
        )
        .unwrap_or_default();
        let event_time = normalize_datetime(&time_original).unwrap_or_else(|| {
            (base_time + Duration::seconds(record.record_index as i64)).to_rfc3339()
        });
        let data = record.row.clone();
        let threat = first_event_field(
            &data,
            &["Threat Name", "ThreatName", "Threat", "ThreatDisplayName"],
        )
        .or_else(|| first_event_field(&data, &["Name"]));
        let file_path = first_event_field(
            &data,
            &[
                "Path",
                "FilePath",
                "File",
                "Filename",
                "Resource",
                "Resources",
                "TargetFilename",
            ],
        );
        let defender_user = first_event_field(&data, &["User", "UserName", "AccountName"]);
        let defender_process = first_event_field(
            &data,
            &["ProcessName", "Process", "Image", "Application", "Proc"],
        );
        let hash = first_event_field(&data, &["SHA256", "SHA1", "MD5", "Hash"])
            .or_else(|| data.values().find_map(|value| extract_hash_like(value)));
        let action = defender_event_action(event_code.as_deref(), Some(&data));
        let severity =
            defender_event_severity(event_code.as_deref(), level.as_deref(), Some(&data))
                .to_string();
        let detail_text = joined_event_fields(
            &data,
            &[
                "Details",
                "ExtraFieldInfo",
                "Message",
                "RenderedDescription",
            ],
        );
        let base_message = cell(
            &record.row,
            &["message", "rendereddescription", "description"],
        )
        .unwrap_or_else(|| {
            defender_message(
                event_code.as_deref(),
                &action,
                threat.as_deref(),
                file_path.as_deref(),
                Some(&data),
            )
        });
        let message_full = match detail_text.as_deref() {
            Some(details) if !base_message.contains(details) => {
                format!("{base_message} | {details}")
            }
            _ => base_message,
        };
        let attributes_json = json!({
            "event_id": event_code,
            "provider": cell(&record.row, &["provider", "providername", "source"]),
            "record_id": cell(&record.row, &["eventrecordid", "recordid"]),
            "channel": cell(&record.row, &["channel"]).or_else(|| Some("Microsoft-Windows-Windows Defender/Operational".to_string())),
            "defender_threat": threat.clone(),
            "defender_path": file_path.clone(),
            "defender_user": defender_user.clone(),
            "defender_process": defender_process.clone(),
            "hash": hash.clone(),
            "data": data.clone(),
            "parser_mode": record.parser_mode,
        })
        .to_string();
        let raw_json = json!({
            "record_index": record.record_index,
            "parser_mode": "defender_flat",
            "record": record.raw,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "defender",
            event_time,
            time_original,
            "defender_export_time",
            0.85,
            cell(
                &record.row,
                &["computer", "machinename", "host", "hostname"],
            ),
            defender_user,
            defender_process,
            file_path,
            None,
            None,
            hash,
            action,
            severity,
            message_full,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }
    Ok(ParsedArtifact {
        events,
        raw_records,
    })
}

fn parse_defender_mplog_lines(
    input: &ParserInput,
    metadata: &ParserMetadata,
    text: &str,
) -> ParsedArtifact {
    let mut events = Vec::new();
    let mut raw_records = Vec::new();
    let base_time = Utc::now();
    for (idx, line) in text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let (time_original, message) = split_leading_timestamp(line);
        let event_time = time_original
            .as_deref()
            .and_then(normalize_datetime)
            .unwrap_or_else(|| (base_time + Duration::seconds(idx as i64)).to_rfc3339());
        let action = defender_text_action(&message);
        let severity = defender_text_severity(&message).to_string();
        let file_path = extract_path_like(&message);
        let threat = extract_label_value(&message, &["Threat Name", "ThreatName", "Threat"]);
        let attributes_json = json!({
            "line_number": idx + 1,
            "parser_mode": "defender_mplog",
            "defender_threat": threat,
        })
        .to_string();
        let raw_json = json!({
            "line_number": idx + 1,
            "parser_mode": "defender_mplog",
            "line": line,
        })
        .to_string();
        let (event, raw) = build_event(
            input,
            metadata,
            "defender",
            event_time,
            time_original.unwrap_or_default(),
            "defender_mplog_line_time",
            0.55,
            None,
            None,
            defender_process_hint(&message),
            file_path,
            None,
            None,
            extract_hash_like(&message),
            action,
            severity,
            message,
            attributes_json,
            raw_json,
        );
        events.push(event);
        raw_records.push(raw);
    }
    ParsedArtifact {
        events,
        raw_records,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_event(
    input: &ParserInput,
    metadata: &ParserMetadata,
    artifact_type: &str,
    event_time_utc: String,
    event_time_original: String,
    time_kind: &str,
    time_confidence: f64,
    host: Option<String>,
    user_name: Option<String>,
    process_name: Option<String>,
    file_path: Option<String>,
    ip: Option<String>,
    url: Option<String>,
    hash: Option<String>,
    event_action: String,
    severity: String,
    message_full: String,
    attributes_json: String,
    raw_record_json: String,
) -> (EventFull, RawRecord) {
    let event_id = new_id("event");
    let raw_record_ref = new_id("rawrec");
    let message_full = sanitize_display_text(&message_full);
    let message_short = truncate(&message_full, 160);
    let event = EventFull {
        event_id: event_id.clone(),
        case_id: input.case_id.clone(),
        event_time_utc,
        event_time_original,
        time_kind: time_kind.to_string(),
        time_confidence,
        source_confidence: 0.85,
        artifact_type: artifact_type.to_string(),
        source_file_id: input.source_file_id.clone(),
        parse_run_id: input.parse_run_id.clone(),
        parser_name: metadata.parser_name.clone(),
        parser_version: metadata.parser_version.clone(),
        schema_version: metadata.schema_version.clone(),
        evidence_ref: input.object_ref.clone(),
        host: clean_opt(host),
        user_name: clean_opt(user_name),
        process_name: clean_opt(process_name),
        file_path: clean_opt(file_path),
        ip: clean_opt(ip),
        url: clean_opt(url),
        hash: clean_opt(hash),
        event_action,
        severity,
        message_short,
        message_full,
        raw_record_ref: raw_record_ref.clone(),
        attributes_json,
    };
    let raw = RawRecord {
        raw_record_ref,
        case_id: input.case_id.clone(),
        event_id,
        parse_run_id: input.parse_run_id.clone(),
        source_file_id: input.source_file_id.clone(),
        evidence_ref: input.object_ref.clone(),
        raw_record_json,
    };
    (event, raw)
}

fn parse_json_values(text: &str) -> Result<Vec<Value>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        let value = serde_json::from_str::<Value>(trimmed)?;
        return Ok(value.as_array().cloned().unwrap_or_default());
    }
    if trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            return Ok(vec![value]);
        }
    }
    let mut values = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        values.push(serde_json::from_str::<Value>(line.trim())?);
    }
    Ok(values)
}

impl From<serde_json::Error> for ParserError {
    fn from(error: serde_json::Error) -> Self {
        Self::Failed(format!("json parse failed: {error}"))
    }
}

fn flatten_json(value: &Value, out: &mut HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let normalized = normalize_header(key);
                match value {
                    Value::Object(_) | Value::Array(_) => flatten_json(value, out),
                    Value::Null => {}
                    Value::String(text) => {
                        out.entry(normalized).or_insert_with(|| text.clone());
                    }
                    other => {
                        out.entry(normalized).or_insert_with(|| other.to_string());
                    }
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                flatten_json(value, out);
            }
        }
        _ => {}
    }
}

fn xml_event_chunks(text: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut offset = 0;
    while let Some(relative_start) = text[offset..].find("<Event") {
        let start = offset + relative_start;
        let Some(relative_end) = text[start..].find("</Event>") else {
            break;
        };
        let end = start + relative_end + "</Event>".len();
        chunks.push(text[start..end].to_string());
        offset = end;
    }
    chunks
}

fn extract_xml_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = text.find(&open)?;
    let value_start = start + text[start..].find('>')? + 1;
    let close = format!("</{tag}>");
    let value_end = value_start + text[value_start..].find(&close)?;
    clean_opt(Some(decode_xml_entities(&text[value_start..value_end])))
}

fn extract_xml_blocks(text: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    while let Some(relative_start) = text[offset..].find(&open) {
        let start = offset + relative_start;
        let Some(open_end_relative) = text[start..].find('>') else {
            break;
        };
        let open_end = start + open_end_relative + 1;
        let Some(relative_end) = text[open_end..].find(&close) else {
            break;
        };
        let end = open_end + relative_end + close.len();
        out.push(text[start..end].to_string());
        offset = end;
    }
    out
}

fn extract_xml_attr_in_tag(text: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = text.find(&open)?;
    let end = start + text[start..].find('>')?;
    extract_attr(&text[start..=end], attr)
}

fn extract_attr(tag_text: &str, attr: &str) -> Option<String> {
    let pat = format!("{attr}=\"");
    let start = tag_text.find(&pat)? + pat.len();
    let end = start + tag_text[start..].find('"')?;
    clean_opt(Some(decode_xml_entities(&tag_text[start..end])))
}

fn extract_named_data(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut offset = 0;
    while let Some(relative_start) = text[offset..].find("<Data") {
        let start = offset + relative_start;
        let Some(tag_end_relative) = text[start..].find('>') else {
            break;
        };
        let tag_end = start + tag_end_relative;
        let name = extract_attr(&text[start..=tag_end], "Name")
            .unwrap_or_else(|| format!("Data{}", out.len() + 1));
        let value_start = tag_end + 1;
        let Some(close_relative) = text[value_start..].find("</Data>") else {
            break;
        };
        let value_end = value_start + close_relative;
        if let Some(value) = clean_opt(Some(decode_xml_entities(&text[value_start..value_end]))) {
            out.insert(name, value);
        }
        offset = value_end + "</Data>".len();
    }
    out
}

fn decode_xml_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current.trim().to_string());
    fields
}

fn row_map(headers: &[String], cells: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (idx, header) in headers.iter().enumerate() {
        if let Some(value) = cells
            .get(idx)
            .and_then(|value| clean_opt(Some(value.clone())))
        {
            out.insert(header.clone(), value);
        }
    }
    out
}

fn normalize_header(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn cell(row: &HashMap<String, String>, names: &[&str]) -> Option<String> {
    names
        .iter()
        .map(|name| normalize_header(name))
        .find_map(|name| clean_opt(row.get(&name).cloned()))
}

/// Normalize a PID that may be hex ("0x1a4", Security 4688) or decimal (Sysmon).
fn normalize_pid(pid: Option<String>) -> Option<String> {
    let pid = pid?;
    let trimmed = pid.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if let Ok(n) = u64::from_str_radix(hex, 16) {
            return Some(n.to_string());
        }
    }
    clean_opt(Some(trimmed.to_string()))
}

/// Extract normalized process identity across Sysmon (EID 1) and Security (4688).
/// In 4688, `ProcessId` is the creator (parent) and `NewProcessId` is the child;
/// in Sysmon, `ProcessId` is the child and `ParentProcessId` the parent. GUIDs
/// (Sysmon-only) are the reliable per-instance key; PIDs are best-effort.
/// Returns (process_id, process_guid, parent_process_id, parent_process_guid).
fn process_identity(
    row: &HashMap<String, String>,
) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let process_guid = first_named(row, &["ProcessGuid"]);
    let parent_process_guid = first_named(row, &["ParentProcessGuid"]);
    let new_pid = first_named(row, &["NewProcessId"]);
    let (process_id, parent_process_id) = if new_pid.is_some() {
        // Security 4688: NewProcessId = child, ProcessId = creator/parent.
        (new_pid, first_named(row, &["ProcessId", "CreatorProcessId"]))
    } else {
        // Sysmon EID 1 (and generic): ProcessId = child, ParentProcessId = parent.
        (
            first_named(row, &["ProcessId"]),
            first_named(row, &["ParentProcessId"]),
        )
    };
    (
        normalize_pid(process_id),
        process_guid,
        normalize_pid(parent_process_id),
        parent_process_guid,
    )
}

fn first_flat(row: &HashMap<String, String>, names: &[&str]) -> Option<String> {
    cell(row, names)
}

fn first_named(row: &HashMap<String, String>, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        let normalized = normalize_header(name);
        row.iter()
            .find(|(key, _)| normalize_header(key) == normalized)
            .and_then(|(_, value)| clean_opt(Some(value.clone())))
    })
}

fn first_event_field(row: &HashMap<String, String>, names: &[&str]) -> Option<String> {
    first_named(row, names).or_else(|| embedded_event_field(row, names))
}

fn joined_event_fields(row: &HashMap<String, String>, names: &[&str]) -> Option<String> {
    let mut seen = HashSet::new();
    let mut parts = Vec::new();
    for name in names {
        if let Some(value) = first_named(row, &[*name]) {
            if seen.insert(value.clone()) {
                parts.push(value);
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" ¦ "))
    }
}

fn embedded_event_field(row: &HashMap<String, String>, names: &[&str]) -> Option<String> {
    for value in row.values() {
        for name in names {
            if let Some(found) = labeled_event_value(value, name) {
                return Some(found);
            }
        }
    }
    None
}

fn labeled_event_value(text: &str, name: &str) -> Option<String> {
    let wanted = normalize_header(name);
    for segment in text.split(['¦', '\n', '\r']) {
        let segment = segment.trim().trim_matches('"').trim_matches('\'').trim();
        let Some((key, value)) = segment.split_once(':').or_else(|| segment.split_once('=')) else {
            continue;
        };
        if normalize_header(key) == wanted {
            return clean_opt(Some(value.trim().trim_matches('"').to_string()));
        }
    }
    None
}

fn clean_opt(value: Option<String>) -> Option<String> {
    let value = value?.trim().trim_matches('"').to_string();
    if value.is_empty()
        || value == "-"
        || value.eq_ignore_ascii_case("null")
        || value.eq_ignore_ascii_case("n/a")
        || value.eq_ignore_ascii_case("none")
    {
        None
    } else {
        Some(value)
    }
}

/// Reserved Windows virtual-domain markers. When one of these appears mid-string,
/// everything before it is an upstream `evtx` crate binary-misdecode garbage prefix
/// (the BITS event 5 BinXML SID substitution-array misalignment renders binary bytes
/// as UTF-16LE CJK/PUA noise glued onto the resolved account name). A real Windows
/// principal can never carry characters before "NT AUTHORITY\\", "BUILTIN\\", etc.,
/// so dropping that prefix is safe and a no-op on legitimate (incl. non-ASCII) names.
const WELL_KNOWN_ACCOUNT_MARKERS: &[&str] = &[
    "NT AUTHORITY\\",
    "NT SERVICE\\",
    "BUILTIN\\",
    "NT VIRTUAL MACHINE\\",
    "FONT DRIVER HOST\\",
    "WINDOW MANAGER\\",
];

/// Earliest case-insensitive ASCII byte-offset of `needle` within `haystack`.
/// Markers are ASCII, so this never lands inside a multi-byte UTF-8 sequence.
fn ascii_icontains_at(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .find(|&i| haystack[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// Drop a binary-misdecode garbage prefix that the upstream evtx crate emits before a
/// reserved Windows account marker, e.g. "<CJK/PUA garbage>NT AUTHORITY\\NETWORK SERVICE"
/// -> "NT AUTHORITY\\NETWORK SERVICE". No-op when no marker is present (so a legitimate
/// non-ASCII username such as 田中太郎 or CORP\\山田 is returned untouched) and idempotent
/// when the marker is already at offset 0. Apply ONLY to principal/account fields.
fn sanitize_account_name(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut cut: Option<usize> = None;
    for marker in WELL_KNOWN_ACCOUNT_MARKERS {
        if let Some(pos) = ascii_icontains_at(bytes, marker.as_bytes()) {
            cut = Some(cut.map_or(pos, |current| current.min(pos)));
        }
    }
    match cut {
        Some(pos) if pos > 0 && value.is_char_boundary(pos) => value[pos..].to_string(),
        _ => value.to_string(),
    }
}

fn file_name_from_path(value: &str) -> Option<String> {
    value
        .rsplit(|ch| ch == '\\' || ch == '/')
        .next()
        .and_then(|name| clean_opt(Some(name.to_string())))
}

fn extension_from_path(value: &str) -> Option<String> {
    value
        .rsplit(|ch| ch == '\\' || ch == '/')
        .next()
        .and_then(|name| {
            name.rsplit_once('.')
                .map(|(_, ext)| ext.to_ascii_lowercase())
        })
        .and_then(|ext| clean_opt(Some(ext)))
}

fn file_name_from_url(value: &str) -> Option<String> {
    let without_fragment = value.split('#').next().unwrap_or(value);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    file_name_from_path(without_query).filter(|name| name.contains('.'))
}

fn filezilla_server_url(host: &str, port: Option<&str>) -> String {
    let host = host.trim();
    match port.and_then(|value| clean_opt(Some(value.to_string()))) {
        Some(port) => format!("ftp://{host}:{port}"),
        None => format!("ftp://{host}"),
    }
}

fn normalize_filezilla_remote_path(value: &str) -> Option<String> {
    let tokens = value
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return None;
    }
    let mut idx = if tokens.len() > 2 && tokens[0].parse::<usize>().is_ok() {
        2
    } else {
        0
    };
    let mut parts = Vec::new();
    while idx < tokens.len() {
        if tokens[idx].parse::<usize>().is_ok() {
            if let Some(part) = tokens.get(idx + 1) {
                parts.push(part.trim_matches('/').to_string());
            }
            idx += 2;
        } else {
            parts.push(tokens[idx].trim_matches('/').to_string());
            idx += 1;
        }
    }
    parts.retain(|part| !part.is_empty() && part != "0" && part != "1");
    if parts.is_empty() {
        None
    } else {
        Some(format!("/{}", parts.join("/")))
    }
}

fn decode_base64_utf8(value: &str) -> Option<String> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bit_count = 0u8;
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | val;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((buffer >> bit_count) & 0xff) as u8);
            if bit_count > 0 {
                buffer &= (1u32 << bit_count) - 1;
            } else {
                buffer = 0;
            }
        }
    }
    String::from_utf8(out)
        .ok()
        .and_then(|value| clean_opt(Some(value)))
}

fn user_from_path(value: &str) -> Option<String> {
    let mut parts = value
        .split(|ch| ch == '\\' || ch == '/')
        .filter(|part| !part.is_empty());
    while let Some(part) = parts.next() {
        if part.eq_ignore_ascii_case("users") {
            let user = parts.next()?;
            if matches!(
                user.to_ascii_lowercase().as_str(),
                "default" | "public" | "default user" | "all users"
            ) {
                return None;
            }
            return clean_opt(Some(user.to_string()));
        }
    }
    None
}

fn host_from_path(_value: &str) -> Option<String> {
    None
}

fn evtx_user_name(data: &HashMap<String, String>) -> Option<String> {
    first_named(
        data,
        &[
            "TargetUserName",
            "SubjectUserName",
            "AccountName",
            "UserName",
            "User",
            "UserId",
        ],
    )
    .map(|value| sanitize_account_name(&value))
    .and_then(|value| clean_opt(Some(value)))
}

fn evtx_process_name(data: &HashMap<String, String>) -> Option<String> {
    first_named(
        data,
        &[
            "NewProcessName",
            "ProcessName",
            "Image",
            "Application",
            "ServiceFileName",
            "SourceImage",
            "ParentImage",
        ],
    )
    .and_then(|value| file_name_from_path(&value).or(Some(value)))
}

fn evtx_file_path(data: &HashMap<String, String>) -> Option<String> {
    first_named(
        data,
        &[
            "NewProcessName",
            "ProcessName",
            "Image",
            "ObjectName",
            "TargetFilename",
            "ImageLoaded",
            "Path",
            "FullPath",
            "ServiceFileName",
            "SourceImage",
            "TargetImage",
        ],
    )
}

fn lnk_target_from_name(value: &str) -> Option<String> {
    file_name_from_path(value).map(|name| name.trim_end_matches(".lnk").to_string())
}

fn prefetch_executable_from_path(value: &str) -> Option<String> {
    let name = file_name_from_path(value)?;
    let upper = name.to_ascii_uppercase();
    let stem = upper.strip_suffix(".PF").unwrap_or(&upper);
    let executable = stem.rsplit_once('-').map(|(exe, _)| exe).unwrap_or(stem);
    if executable.ends_with(".EXE") {
        Some(executable.to_ascii_lowercase())
    } else {
        None
    }
}

fn prefetch_hash_from_filename(value: &str) -> Option<String> {
    let name = file_name_from_path(value).unwrap_or_else(|| value.to_string());
    let upper = name.to_ascii_uppercase();
    let stem = upper.strip_suffix(".PF").unwrap_or(&upper);
    let (_, hash) = stem.rsplit_once('-')?;
    if hash.len() >= 6 && hash.len() <= 16 && hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(hash.to_ascii_lowercase())
    } else {
        None
    }
}

fn prefetch_suspicion(process_name: &str, referenced_files: &[String]) -> Option<String> {
    let lower = process_name.to_ascii_lowercase();
    if is_suspicious_execution_name(&lower) {
        return Some("lolbin_or_script_interpreter_execution".to_string());
    }
    if referenced_files.iter().any(|path| suspicious_path(path)) {
        return Some("referenced_file_in_user_writable_path".to_string());
    }
    None
}

fn prefetch_severity(suspicion: Option<&str>) -> &'static str {
    match suspicion {
        Some("referenced_file_in_user_writable_path") => "medium",
        Some("lolbin_or_script_interpreter_execution") => "medium",
        Some(_) => "low",
        None => "info",
    }
}

fn prefetch_version(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 8 || !looks_like_prefetch_binary(bytes) {
        return None;
    }
    if bytes.starts_with(b"SCCA") {
        Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
    } else if bytes.get(4..8) == Some(b"SCCA") {
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct PrefetchStructure {
    version_family: &'static str,
    file_size_header: Option<u32>,
    executable_name_header: Option<String>,
    sections: Vec<PrefetchSectionSummary>,
    volume_strings: Vec<String>,
    file_metrics: Vec<PrefetchFileMetricEntry>,
    file_metrics_count: u32,
    trace_chains: Vec<PrefetchTraceChainEntry>,
    trace_chain_count: u32,
    run_count: Option<u32>,
    run_count_offset: Option<usize>,
    run_time_entries: Vec<PrefetchRunTimeEntry>,
}

#[derive(Debug, Clone)]
struct PrefetchSectionSummary {
    name: &'static str,
    offset: usize,
    length: usize,
    count: Option<u32>,
    length_source: &'static str,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct PrefetchRunTimeEntry {
    execution_index: usize,
    offset: usize,
    timestamp: String,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct PrefetchFileMetricEntry {
    index: usize,
    offset: usize,
    length: usize,
    prefetch_start_time_ms: Option<u32>,
    prefetch_duration_ms: Option<u32>,
    average_duration_ms: Option<u32>,
    filename_string_offset: Option<u32>,
    filename_string_char_count: Option<u32>,
    flags: Option<u32>,
    file_reference: Option<u64>,
    filename: Option<String>,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct PrefetchTraceChainEntry {
    index: usize,
    offset: usize,
    length: usize,
    next_index: Option<u32>,
    block_load_count: Option<u32>,
    unknown_flags: Option<u8>,
    sample_duration_ms: Option<u8>,
    unknown_value: Option<u16>,
    confidence: f64,
}

#[derive(Debug, Clone, Copy)]
struct PrefetchLayout {
    family: &'static str,
    file_metrics_entry_size: usize,
    trace_chain_entry_size: usize,
    run_count_offsets: &'static [usize],
    run_time_offsets: &'static [usize],
}

const PF_RUN_COUNT_V17: &[usize] = &[0x90];
const PF_RUN_COUNT_V23: &[usize] = &[0x98, 0x90];
const PF_RUN_COUNT_V26: &[usize] = &[0xd0, 0x98, 0x90];
const PF_RUN_COUNT_V30: &[usize] = &[0xd0, 0x98, 0x90];
const PF_RUN_TIME_V17: &[usize] = &[0x78];
const PF_RUN_TIME_V23: &[usize] = &[0x80, 0x78];
const PF_RUN_TIME_V26: &[usize] = &[0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 0x78];
const PF_RUN_TIME_V30: &[usize] = &[0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 0x78];

fn parse_prefetch_structure(bytes: &[u8], version: Option<u32>) -> PrefetchStructure {
    let layout = prefetch_layout(version);
    let file_size_header = read_u32_le(bytes, 0x0c).filter(|value| {
        let value = *value as usize;
        value >= 84 && value <= bytes.len().saturating_add(4096)
    });
    let executable_name_header = prefetch_header_executable_name(bytes);
    let mut sections = prefetch_section_candidates(bytes, layout);
    sections.sort_by_key(|section| section.offset);
    for idx in 0..sections.len() {
        if sections[idx].length == 0 {
            let next_offset = sections
                .iter()
                .skip(idx + 1)
                .find(|candidate| candidate.offset > sections[idx].offset)
                .map(|candidate| candidate.offset)
                .unwrap_or(bytes.len());
            sections[idx].length = next_offset
                .saturating_sub(sections[idx].offset)
                .min(512 * 1024);
            sections[idx].length_source = "next_section_delta";
            sections[idx].confidence = sections[idx].confidence.min(0.75);
        }
    }
    let volume_strings = sections
        .iter()
        .find(|section| section.name == "volumes")
        .map(|section| {
            let start = section.offset;
            let end = start.saturating_add(section.length).min(bytes.len());
            extract_prefetch_volume_strings(&bytes[start..end])
        })
        .unwrap_or_default();
    let (run_count, run_count_offset) = prefetch_run_count_with_offset(bytes, layout)
        .map(|entry| (Some(entry.0), Some(entry.1)))
        .unwrap_or((None, None));
    let run_time_entries = prefetch_run_time_entries(bytes, layout);
    let file_metrics = parse_prefetch_file_metrics(bytes, version, layout);
    let file_metrics_count = read_u32_le(bytes, 0x58).unwrap_or_default();
    let trace_chains = parse_prefetch_trace_chains(bytes, version, layout);
    let trace_chain_count = read_u32_le(bytes, 0x60).unwrap_or_default();
    PrefetchStructure {
        version_family: layout.family,
        file_size_header,
        executable_name_header,
        sections,
        volume_strings,
        file_metrics,
        file_metrics_count,
        trace_chains,
        trace_chain_count,
        run_count,
        run_count_offset,
        run_time_entries,
    }
}

fn prefetch_layout(version: Option<u32>) -> PrefetchLayout {
    match version {
        Some(17) => PrefetchLayout {
            family: "windows_xp_2003_v17",
            file_metrics_entry_size: 20,
            trace_chain_entry_size: 12,
            run_count_offsets: PF_RUN_COUNT_V17,
            run_time_offsets: PF_RUN_TIME_V17,
        },
        Some(23) => PrefetchLayout {
            family: "windows_vista_7_v23",
            file_metrics_entry_size: 32,
            trace_chain_entry_size: 12,
            run_count_offsets: PF_RUN_COUNT_V23,
            run_time_offsets: PF_RUN_TIME_V23,
        },
        Some(26) => PrefetchLayout {
            family: "windows_8_8_1_v26",
            file_metrics_entry_size: 32,
            trace_chain_entry_size: 12,
            run_count_offsets: PF_RUN_COUNT_V26,
            run_time_offsets: PF_RUN_TIME_V26,
        },
        Some(30) => PrefetchLayout {
            family: "windows_10_11_v30",
            file_metrics_entry_size: 32,
            trace_chain_entry_size: 8,
            run_count_offsets: PF_RUN_COUNT_V30,
            run_time_offsets: PF_RUN_TIME_V30,
        },
        Some(31) => PrefetchLayout {
            family: "windows_11_v31",
            file_metrics_entry_size: 32,
            trace_chain_entry_size: 8,
            run_count_offsets: PF_RUN_COUNT_V30,
            run_time_offsets: PF_RUN_TIME_V30,
        },
        _ => PrefetchLayout {
            family: "unknown_prefetch_layout",
            file_metrics_entry_size: 32,
            trace_chain_entry_size: 8,
            run_count_offsets: PF_RUN_COUNT_V30,
            run_time_offsets: PF_RUN_TIME_V30,
        },
    }
}

fn prefetch_header_executable_name(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 0x4c {
        return None;
    }
    let end = 0x4c.min(bytes.len());
    let name = decode_utf16le_lossy(&bytes[0x10..end]);
    let trimmed = name.trim_matches(char::from(0)).trim();
    if trimmed.len() >= 3 {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn prefetch_section_candidates(
    bytes: &[u8],
    layout: PrefetchLayout,
) -> Vec<PrefetchSectionSummary> {
    let mut out = Vec::new();
    for (name, offset_field, count_field, explicit_size_field, entry_size) in [
        (
            "file_metrics",
            0x54usize,
            0x58usize,
            None,
            layout.file_metrics_entry_size,
        ),
        (
            "trace_chains",
            0x5c,
            0x60,
            None,
            layout.trace_chain_entry_size,
        ),
        ("filename_strings", 0x64, 0x68, Some(0x68usize), 0usize),
        ("volumes", 0x6c, 0x70, None, 96usize),
    ] {
        let Some(offset) = read_u32_le(bytes, offset_field).map(|value| value as usize) else {
            continue;
        };
        if offset < 84 || offset >= bytes.len() {
            continue;
        }
        let count = read_u32_le(bytes, count_field);
        let mut length = explicit_size_field
            .and_then(|field| read_u32_le(bytes, field))
            .map(|value| value as usize)
            .unwrap_or_else(|| {
                count
                    .map(|count| (count as usize).saturating_mul(entry_size))
                    .unwrap_or_default()
            });
        let mut length_source = if explicit_size_field.is_some() {
            "explicit_size"
        } else {
            "count_estimate"
        };
        if length == 0 || offset.saturating_add(length) > bytes.len() {
            length = 0;
            length_source = "pending_next_section_delta";
        }
        out.push(PrefetchSectionSummary {
            name,
            offset,
            length,
            count,
            length_source,
            confidence: if length_source == "explicit_size" {
                0.9
            } else {
                0.7
            },
        });
    }
    out
}

fn prefetch_section_json(sections: &[PrefetchSectionSummary]) -> Vec<Value> {
    sections
        .iter()
        .map(|section| {
            json!({
                "name": section.name,
                "offset": section.offset,
                "length": section.length,
                "count": section.count,
                "length_source": section.length_source,
                "confidence": section.confidence,
            })
        })
        .collect()
}

fn prefetch_file_metric_json(entries: &[PrefetchFileMetricEntry]) -> Vec<Value> {
    entries
        .iter()
        .take(64)
        .map(|entry| {
            json!({
                "index": entry.index,
                "offset": entry.offset,
                "length": entry.length,
                "prefetch_start_time_ms": entry.prefetch_start_time_ms,
                "prefetch_duration_ms": entry.prefetch_duration_ms,
                "average_duration_ms": entry.average_duration_ms,
                "filename_string_offset": entry.filename_string_offset,
                "filename_string_char_count": entry.filename_string_char_count,
                "flags": entry.flags,
                "file_reference": entry.file_reference.map(|value| format!("{value:016x}")),
                "filename": entry.filename.clone(),
                "confidence": entry.confidence,
            })
        })
        .collect()
}

fn prefetch_trace_chain_json(entries: &[PrefetchTraceChainEntry]) -> Vec<Value> {
    entries
        .iter()
        .take(64)
        .map(|entry| {
            json!({
                "index": entry.index,
                "offset": entry.offset,
                "length": entry.length,
                "next_index": entry.next_index,
                "block_load_count": entry.block_load_count,
                "unknown_flags": entry.unknown_flags,
                "sample_duration_ms": entry.sample_duration_ms,
                "unknown_value": entry.unknown_value,
                "confidence": entry.confidence,
            })
        })
        .collect()
}

fn prefetch_run_time_json(entries: &[PrefetchRunTimeEntry]) -> Vec<Value> {
    entries
        .iter()
        .map(|entry| {
            json!({
                "execution_index": entry.execution_index,
                "offset": entry.offset,
                "timestamp": entry.timestamp,
                "confidence": entry.confidence,
            })
        })
        .collect()
}

fn extract_prefetch_volume_strings(bytes: &[u8]) -> Vec<String> {
    extract_utf16le_strings(bytes)
        .into_iter()
        .filter(|value| {
            let lower = value.to_ascii_lowercase();
            lower.contains("\\device\\")
                || lower.contains("\\volume")
                || lower.contains("harddiskvolume")
        })
        .take(8)
        .collect()
}

fn parse_prefetch_file_metrics(
    bytes: &[u8],
    version: Option<u32>,
    layout: PrefetchLayout,
) -> Vec<PrefetchFileMetricEntry> {
    let Some(metrics_offset) = read_u32_le(bytes, 0x54).map(|value| value as usize) else {
        return Vec::new();
    };
    let count = read_u32_le(bytes, 0x58).unwrap_or_default() as usize;
    let filename_strings_offset = read_u32_le(bytes, 0x64).map(|value| value as usize);
    if metrics_offset < 84 || metrics_offset >= bytes.len() || count == 0 {
        return Vec::new();
    }
    let entry_size = layout.file_metrics_entry_size;
    let mut out = Vec::new();
    for idx in 0..count.min(64) {
        let offset = metrics_offset + idx * entry_size;
        if offset.saturating_add(entry_size) > bytes.len() {
            break;
        }
        let (
            start_time,
            duration,
            average_duration,
            filename_string_offset,
            filename_string_char_count,
            flags,
            file_reference,
        ) = if version == Some(17) {
            (
                read_u32_le(bytes, offset),
                read_u32_le(bytes, offset + 4),
                None,
                read_u32_le(bytes, offset + 8),
                read_u32_le(bytes, offset + 12),
                read_u32_le(bytes, offset + 16),
                None,
            )
        } else {
            (
                read_u32_le(bytes, offset),
                read_u32_le(bytes, offset + 4),
                read_u32_le(bytes, offset + 8),
                read_u32_le(bytes, offset + 12),
                read_u32_le(bytes, offset + 16),
                read_u32_le(bytes, offset + 20),
                read_u64_le(bytes, offset + 24).filter(|value| *value != 0),
            )
        };
        let filename = match (
            filename_strings_offset,
            filename_string_offset,
            filename_string_char_count,
        ) {
            (Some(base), Some(relative), Some(chars)) => {
                read_prefetch_filename_string(bytes, base, relative as usize, chars as usize)
            }
            _ => None,
        };
        out.push(PrefetchFileMetricEntry {
            index: idx,
            offset,
            length: entry_size,
            prefetch_start_time_ms: start_time,
            prefetch_duration_ms: duration,
            average_duration_ms: average_duration,
            filename_string_offset,
            filename_string_char_count,
            flags,
            file_reference,
            filename,
            confidence: if version.is_some() { 0.82 } else { 0.62 },
        });
    }
    out
}

fn read_prefetch_filename_string(
    bytes: &[u8],
    filename_strings_offset: usize,
    relative_offset: usize,
    char_count: usize,
) -> Option<String> {
    if char_count == 0 || char_count > 4096 {
        return None;
    }
    let start = filename_strings_offset.checked_add(relative_offset)?;
    let byte_len = char_count.checked_mul(2)?;
    let end = start.checked_add(byte_len)?;
    if end <= bytes.len() {
        return clean_opt(Some(decode_utf16le_lossy(&bytes[start..end])));
    }
    let fallback_relative = relative_offset.checked_mul(2)?;
    let fallback_start = filename_strings_offset.checked_add(fallback_relative)?;
    let fallback_end = fallback_start.checked_add(byte_len)?;
    if fallback_end <= bytes.len() {
        clean_opt(Some(decode_utf16le_lossy(
            &bytes[fallback_start..fallback_end],
        )))
    } else {
        None
    }
}

fn parse_prefetch_trace_chains(
    bytes: &[u8],
    version: Option<u32>,
    layout: PrefetchLayout,
) -> Vec<PrefetchTraceChainEntry> {
    let Some(trace_offset) = read_u32_le(bytes, 0x5c).map(|value| value as usize) else {
        return Vec::new();
    };
    let count = read_u32_le(bytes, 0x60).unwrap_or_default() as usize;
    if trace_offset < 84 || trace_offset >= bytes.len() || count == 0 {
        return Vec::new();
    }
    let entry_size = layout.trace_chain_entry_size;
    let mut out = Vec::new();
    for idx in 0..count.min(64) {
        let offset = trace_offset + idx * entry_size;
        if offset.saturating_add(entry_size) > bytes.len() {
            break;
        }
        let (next_index, block_load_count, unknown_flags, sample_duration_ms, unknown_value) =
            if matches!(version, Some(30 | 31) | None) {
                (
                    None,
                    read_u32_le(bytes, offset),
                    read_u8(bytes, offset + 4),
                    read_u8(bytes, offset + 5),
                    read_u16_le(bytes, offset + 6),
                )
            } else {
                (
                    read_u32_le(bytes, offset).filter(|value| *value != u32::MAX),
                    read_u32_le(bytes, offset + 4),
                    read_u8(bytes, offset + 8),
                    read_u8(bytes, offset + 9),
                    read_u16_le(bytes, offset + 10),
                )
            };
        out.push(PrefetchTraceChainEntry {
            index: idx,
            offset,
            length: entry_size,
            next_index,
            block_load_count,
            unknown_flags,
            sample_duration_ms,
            unknown_value,
            confidence: if version.is_some() { 0.78 } else { 0.58 },
        });
    }
    out
}

fn prefetch_run_count_with_offset(bytes: &[u8], layout: PrefetchLayout) -> Option<(u32, usize)> {
    for offset in layout.run_count_offsets {
        let value = read_u32_le(bytes, *offset)?;
        if (1..=100_000).contains(&value) {
            return Some((value, *offset));
        }
    }
    None
}

fn prefetch_run_time_entries(bytes: &[u8], layout: PrefetchLayout) -> Vec<PrefetchRunTimeEntry> {
    let mut out = Vec::new();
    for offset in layout.run_time_offsets {
        let Some(value) = read_filetime_rfc3339(bytes, *offset) else {
            continue;
        };
        if !is_plausible_forensic_time(&value)
            || out
                .iter()
                .any(|existing: &PrefetchRunTimeEntry| existing.timestamp == value)
        {
            continue;
        }
        out.push(PrefetchRunTimeEntry {
            execution_index: out.len(),
            offset: *offset,
            timestamp: value,
            confidence: if layout.family == "unknown_prefetch_layout" {
                0.55
            } else {
                0.8
            },
        });
    }
    out.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    for (idx, entry) in out.iter_mut().enumerate() {
        entry.execution_index = idx;
    }
    out
}

fn prefetch_referenced_files(strings: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in strings {
        if !looks_like_path(value) {
            continue;
        }
        let lower = value.to_ascii_lowercase();
        if !(lower.contains("\\windows\\")
            || lower.contains("\\program files")
            || lower.contains("\\users\\")
            || lower.ends_with(".dll")
            || lower.ends_with(".exe"))
        {
            continue;
        }
        if out.iter().any(|existing| existing == value) {
            continue;
        }
        out.push(truncate(value, 260));
        if out.len() >= 64 {
            break;
        }
    }
    out
}

fn jump_list_app_id(value: &str) -> Option<String> {
    let name = file_name_from_path(value)?;
    let lower = name.to_ascii_lowercase();
    lower
        .strip_suffix(".automaticdestinations-ms")
        .or_else(|| lower.strip_suffix(".customdestinations-ms"))
        .map(str::to_string)
}

fn suspicious_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("/temp/")
        || lower.contains("\\appdata\\")
        || lower.contains("/appdata/")
        || lower.contains("\\downloads\\")
        || lower.contains("/downloads/")
        || lower.contains("\\programdata\\")
        || lower.contains("/programdata/")
        || lower.contains("\\public\\")
        || lower.contains("/public/")
}

fn is_suspicious_execution_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "wmic.exe"
            | "msiexec.exe"
            | "schtasks.exe"
            | "bitsadmin.exe"
            | "certutil.exe"
            | "forfiles.exe"
            | "installutil.exe"
    )
}

fn is_plausible_forensic_time(value: &str) -> bool {
    let Ok(dt) = DateTime::parse_from_rfc3339(value) else {
        return false;
    };
    let year = dt.year();
    (1990..=2100).contains(&year)
}

fn extract_prefetch_executable_from_strings(bytes: &[u8]) -> Option<String> {
    extract_interesting_strings(bytes, 64)
        .into_iter()
        .find(|value| is_executable_name(value))
        .and_then(|value| file_name_from_path(&value).or(Some(value)))
}

fn extract_url_like(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|part| {
            part.trim_matches(|ch: char| {
                matches!(
                    ch,
                    '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';'
                )
            })
        })
        .find(|part| looks_like_url(part))
        .map(str::to_string)
}

fn extract_domain_like(text: &str) -> Option<String> {
    text.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | '\0'
            )
    })
    .map(|part| {
        part.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | ':' | '/'
            )
        })
    })
    .find_map(|part| {
        let host = part
            .strip_prefix("http://")
            .or_else(|| part.strip_prefix("https://"))
            .or_else(|| part.strip_prefix("ftp://"))
            .unwrap_or(part)
            .split(|ch| matches!(ch, '/' | ':' | '?' | '#'))
            .next()
            .unwrap_or(part);
        if looks_like_domain(host) {
            Some(host.to_string())
        } else if looks_like_domain(part) {
            Some(part.to_string())
        } else {
            None
        }
    })
}

fn extract_ipv4_like(text: &str) -> Option<String> {
    text.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | '\0'
            )
    })
    .map(|part| part.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.'))
    .find(|part| looks_like_ipv4(part))
    .map(str::to_string)
}

fn looks_like_domain(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.len() < 4
        || lower.contains('\\')
        || lower.starts_with('.')
        || lower.ends_with('.')
        || is_executable_name(&lower)
        || lower.parse::<std::net::Ipv4Addr>().is_ok()
    {
        return false;
    }
    let Some((_, tld)) = lower.rsplit_once('.') else {
        return false;
    };
    if !(2..=24).contains(&tld.len()) || !tld.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return false;
    }
    lower.split('.').all(|label| {
        !label.is_empty()
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

fn looks_like_ipv4(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.chars().all(|ch| ch.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

fn artifact_signature(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"%PDF") {
        "pdf"
    } else if bytes.starts_with(b"PK\x03\x04") {
        "zip"
    } else if bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0]) {
        "ole"
    } else if bytes.starts_with(b"SQLite format 3\0") {
        "sqlite"
    } else if bytes.starts_with(b"\x0a\x0d\x0d\x0a") {
        "pcapng"
    } else if bytes.starts_with(&[0xd4, 0xc3, 0xb2, 0xa1])
        || bytes.starts_with(&[0xa1, 0xb2, 0xc3, 0xd4])
        || bytes.starts_with(&[0x4d, 0x3c, 0xb2, 0xa1])
        || bytes.starts_with(&[0xa1, 0xb2, 0x3c, 0x4d])
    {
        "pcap"
    } else if bytes.starts_with(b"Rar!") {
        "rar"
    } else if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        "7z"
    } else {
        "unknown"
    }
}

fn ascii_preview_for_metadata(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4096)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' || matches!(*byte, b'\r' | b'\n' | b'\t') {
                *byte as char
            } else {
                ' '
            }
        })
        .collect()
}

fn extract_interesting_strings(bytes: &[u8], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for value in extract_ascii_strings(bytes)
        .into_iter()
        .chain(extract_utf16le_strings(bytes))
    {
        let value = value.trim_matches(char::from(0)).trim().to_string();
        if value.len() < 4 || out.iter().any(|existing| existing == &value) {
            continue;
        }
        if looks_interesting_string(&value) {
            out.push(truncate(&value, 300));
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn extract_ascii_strings(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    for byte in bytes.iter().copied() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            current.push(byte);
        } else {
            if current.len() >= 4 {
                strings.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        strings.push(String::from_utf8_lossy(&current).to_string());
    }
    strings
}

fn extract_ascii_strings_with_offsets(bytes: &[u8]) -> Vec<(usize, String)> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    let mut start = 0usize;
    for (idx, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            if current.is_empty() {
                start = idx;
            }
            current.push(byte);
        } else {
            if current.len() >= 4 {
                strings.push((start, String::from_utf8_lossy(&current).to_string()));
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        strings.push((start, String::from_utf8_lossy(&current).to_string()));
    }
    strings
}

fn extract_utf16le_strings(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        let ch = char::from_u32(unit as u32);
        if let Some(ch) = ch.filter(|ch| ch.is_ascii_graphic() || *ch == ' ' || *ch == '\t') {
            current.push(ch);
        } else {
            if current.len() >= 4 {
                strings.push(current.iter().copied().collect());
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        strings.push(current.iter().copied().collect());
    }
    strings
}

fn extract_utf16le_strings_with_offsets(bytes: &[u8]) -> Vec<(usize, String)> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    let mut start = 0usize;
    for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
        let offset = idx * 2;
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        let ch = char::from_u32(unit as u32);
        if let Some(ch) = ch.filter(|ch| ch.is_ascii_graphic() || *ch == ' ' || *ch == '\t') {
            if current.is_empty() {
                start = offset;
            }
            current.push(ch);
        } else {
            if current.len() >= 4 {
                strings.push((start, current.iter().copied().collect()));
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        strings.push((start, current.iter().copied().collect()));
    }
    strings
}

fn looks_interesting_string(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    looks_like_path(value)
        || looks_like_url(value)
        || is_executable_name(value)
        || lower.contains("powershell")
        || lower.contains("cmd.exe")
        || lower.contains("teamviewer")
        || lower.contains("onedrive")
        || lower.contains("defender")
        || lower.contains("malware")
        || lower.contains("threat")
        || (matches!(value.len(), 32 | 40 | 64) && value.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn looks_like_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.contains(":\\")
        || value.starts_with("\\\\")
        || value.starts_with('/')
        || lower.contains("/users/")
        || lower.contains("\\users\\")
        || lower.contains("/windows/")
        || lower.contains("\\windows\\")
        || lower.starts_with("\\device\\")
}

fn looks_like_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
}

fn is_executable_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".ps1")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".vbs")
        || lower.ends_with(".js")
}

fn magic_hint(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"ElfFile") {
        "evtx"
    } else if bytes.starts_with(b"FILE") {
        "ntfs_file_record"
    } else if bytes.starts_with(b"SCCA") {
        "prefetch"
    } else if bytes.starts_with(b"SQLite format 3\0") {
        "sqlite"
    } else if bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0]) {
        "ole_cfb"
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        "gzip"
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        "jpeg"
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "png"
    } else if bytes.starts_with(b"regf") {
        "registry_hive"
    } else if bytes.starts_with(b"MZ") {
        "pe"
    } else {
        "unknown"
    }
}

fn metadata_severity(artifact_type: &str, action: &str) -> &'static str {
    if action.contains("evtx") || action.contains("mft") {
        "medium"
    } else if matches!(
        artifact_type,
        "prefetch"
            | "lnk"
            | "jump_list"
            | "defender"
            | "scheduled_task"
            | "srum"
            | "web_cache"
            | "webcache"
    ) {
        "medium"
    } else {
        "info"
    }
}

fn line_timestamp_confident(line: &str) -> bool {
    split_leading_timestamp(line).0.is_some()
}

fn usn_action(reason: Option<&str>) -> String {
    let lower = reason.unwrap_or("").to_ascii_lowercase();
    if lower.contains("delete") {
        "usn_deleted"
    } else if lower.contains("rename") {
        "usn_renamed"
    } else if lower.contains("create") {
        "usn_created"
    } else if lower.contains("overwrite")
        || lower.contains("extend")
        || lower.contains("truncate")
        || lower.contains("data")
    {
        "usn_modified"
    } else {
        "usn_changed"
    }
    .to_string()
}

fn normalize_datetime(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"');
    if value.is_empty()
        || value == "-"
        || value.starts_with("0001-01-01")
        || value.starts_with("1601-01-01")
    {
        return None;
    }
    if let Some(dt) = normalize_numeric_datetime(value) {
        return Some(dt);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Utc).to_rfc3339());
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f %z",
        "%Y-%m-%dT%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%.f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y/%m/%d %H:%M:%S%.f %z",
        "%m/%d/%Y %H:%M:%S%.f %z",
        "%m-%d-%Y %H:%M:%S%.f %z",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(value, fmt) {
            return Some(dt.with_timezone(&Utc).to_rfc3339());
        }
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S",
        "%m-%d-%Y %H:%M:%S%.f",
        "%m-%d-%Y %H:%M:%S",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(value, fmt) {
            return Some(Utc.from_utc_datetime(&dt).to_rfc3339());
        }
    }
    None
}

fn normalize_numeric_datetime(value: &str) -> Option<String> {
    let integer = value.trim().split('.').next().unwrap_or(value).trim();
    if integer.len() < 10 || !integer.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let parsed = integer.parse::<i128>().ok()?;
    let seconds = if integer.len() >= 18 && parsed > 116_444_736_000_000_000 {
        (parsed - 116_444_736_000_000_000) / 10_000_000
    } else if integer.len() >= 16 && parsed > 11_644_473_600_000_000 {
        (parsed - 11_644_473_600_000_000) / 1_000_000
    } else if integer.len() >= 16 {
        parsed / 1_000_000
    } else if integer.len() >= 13 {
        parsed / 1_000
    } else {
        parsed
    };
    if !(631_152_000..=4_102_444_800).contains(&seconds) {
        return None;
    }
    Utc.timestamp_opt(seconds as i64, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
}

fn audit_subcategory_name(data: &HashMap<String, String>) -> Option<String> {
    first_event_field(data, &["SubcategoryName", "Subcategory"])
        .or_else(|| {
            first_event_field(data, &["SubcategoryGuid", "SubcategoryId"])
                .and_then(|value| audit_subcategory_name_from_id(&value).map(str::to_string))
        })
        .or_else(|| first_event_field(data, &["Category"]))
}

fn audit_subcategory_name_from_id(value: &str) -> Option<&'static str> {
    let normalized = value.trim().trim_matches(['{', '}']).to_ascii_uppercase();
    match normalized.as_str() {
        "0CCE9227-69AE-11D9-BED3-505054503030" | "%%12804" | "12804" => {
            Some("Other Object Access Events")
        }
        _ => None,
    }
}

fn enrich_message_with_semantics(mut message: String, semantics: &Value) -> String {
    for (label, key) in [
        ("service", "service_name"),
        ("rule", "rule_name"),
        ("direction", "firewall_direction"),
        ("action", "firewall_action"),
        ("audit_subcategory", "audit_subcategory"),
        ("pipe", "pipe_name"),
    ] {
        let Some(value) = semantics.get(key).and_then(Value::as_str) else {
            continue;
        };
        if value.is_empty() || message.contains(value) {
            continue;
        }
        message.push(' ');
        message.push_str(label);
        message.push('=');
        message.push_str(&truncate(value, 120));
    }
    message
}

fn evtx_semantics(
    event_id: Option<&str>,
    provider: Option<&str>,
    channel: Option<&str>,
    data: &HashMap<String, String>,
    event_time_utc: &str,
    time_original: Option<&str>,
) -> Value {
    let id = event_id.and_then(|value| value.trim().parse::<i64>().ok());
    let provider_lc = provider.unwrap_or_default().to_ascii_lowercase();
    let channel_lc = channel.unwrap_or_default().to_ascii_lowercase();
    let mut labels = Vec::<String>::new();
    let mut family = None::<&str>;
    let mut event_kind = None::<&str>;

    let logon_type = first_event_field(data, &["LogonType", "Type"]);
    let normalized_logon_type = logon_type.as_deref().and_then(logon_type_name);
    if id == Some(4624) && normalized_logon_type == Some("remote_interactive") {
        family = Some("remote_access");
        event_kind = Some("rdp_logon_success");
        labels.push("rdp_logon_type_10".to_string());
    }
    if id == Some(1149)
        || provider_lc.contains("remoteconnectionmanager")
        || channel_lc.contains("terminalservices-remoteconnectionmanager")
    {
        family = Some("remote_access");
        event_kind = Some("rdp_authentication_success");
        labels.push("rdp_1149_authentication".to_string());
    }

    let ticket_encryption_type = first_event_field(data, &["TicketEncryptionType"]);
    let ticket_encryption_name = ticket_encryption_type
        .as_deref()
        .and_then(ticket_encryption_type_name);
    let pre_auth_type = first_event_field(data, &["PreAuthType", "PreAuthenticationType"]);
    let service_name = first_event_field(data, &["ServiceName", "Svc"]);
    if matches!(id, Some(4768) | Some(4769) | Some(4771)) {
        family = Some("kerberos");
        event_kind = match id {
            Some(4768) => Some("kerberos_as_request"),
            Some(4769) => Some("kerberos_tgs_request"),
            Some(4771) => Some("kerberos_preauth_failed"),
            _ => event_kind,
        };
        labels.push(match id {
            Some(4768) => "kerberos_as_req".to_string(),
            Some(4769) => "kerberos_tgs_req".to_string(),
            Some(4771) => "kerberos_preauth_failed".to_string(),
            _ => "kerberos_event".to_string(),
        });
        if ticket_encryption_name == Some("rc4_hmac") {
            labels.push("kerberos_rc4_ticket".to_string());
        }
        if id == Some(4768) && pre_auth_type.as_deref() == Some("0") {
            labels.push("asrep_roast_candidate".to_string());
        }
        if id == Some(4769)
            && ticket_encryption_name == Some("rc4_hmac")
            && service_name
                .as_deref()
                .map(|name| !name.eq_ignore_ascii_case("krbtgt"))
                .unwrap_or(true)
        {
            labels.push("kerberoast_candidate".to_string());
        }
    }

    let rule_name = first_event_field(data, &["RuleName", "Rule Name", "Name"]);
    let firewall_direction = first_event_field(data, &["Direction"])
        .and_then(|value| normalize_firewall_direction(&value).map(str::to_string));
    let firewall_action = first_event_field(data, &["Action", "FWLink", "SettingValue"])
        .and_then(|value| normalize_firewall_action(&value).map(str::to_string));
    if matches!(
        id,
        Some(4946)
            | Some(4947)
            | Some(4948)
            | Some(4949)
            | Some(4950)
            | Some(4954)
            | Some(5152)
            | Some(5156)
            | Some(5157)
            | Some(2004)
            | Some(2005)
            | Some(2006)
    ) || provider_lc.contains("firewall")
        || channel_lc.contains("firewall")
    {
        family = Some("firewall");
        event_kind = match id {
            Some(5156) => Some("firewall_connection_allowed"),
            Some(5157) | Some(5152) => Some("firewall_connection_blocked"),
            Some(4946) | Some(2004) => Some("firewall_rule_added"),
            Some(4947) | Some(2005) => Some("firewall_rule_modified"),
            Some(4948) | Some(2006) => Some("firewall_rule_deleted"),
            Some(4949) | Some(4950) | Some(4954) => Some("firewall_policy_changed"),
            _ => Some("firewall_event"),
        };
        labels.push(event_kind.unwrap_or("firewall_event").to_string());
        if firewall_direction.as_deref() == Some("outbound") {
            labels.push("firewall_outbound".to_string());
        }
        if firewall_action.as_deref() == Some("blocked") {
            labels.push("firewall_block".to_string());
        }
    }

    let audit_subcategory = audit_subcategory_name(data);
    if matches!(
        id,
        Some(4703)
            | Some(4719)
            | Some(4902)
            | Some(4904)
            | Some(4905)
            | Some(4906)
            | Some(4907)
            | Some(4908)
            | Some(4912)
    ) {
        family = Some("audit_policy");
        event_kind = Some(match id {
            Some(4703) => "privilege_rights_changed",
            Some(4719) => "system_audit_policy_changed",
            Some(4902) => "per_user_audit_policy_table_created",
            Some(4904) => "security_event_source_registered",
            Some(4905) => "security_event_source_unregistered",
            Some(4906) | Some(4907) | Some(4908) | Some(4912) => "audit_policy_changed",
            _ => "audit_policy_event",
        });
        labels.push(event_kind.unwrap_or("audit_policy_event").to_string());
    }

    let pipe_name = first_event_field(data, &["PipeName"]);
    let service_name_lc = service_name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let pipe_name_lc = pipe_name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if (provider_lc.contains("sysmon") && matches!(id, Some(17) | Some(18))) || pipe_name.is_some()
    {
        family = family.or(Some("execution"));
        event_kind = match id {
            Some(17) => Some("named_pipe_created"),
            Some(18) => Some("named_pipe_connected"),
            _ => event_kind.or(Some("named_pipe_observed")),
        };
        labels.push(event_kind.unwrap_or("named_pipe_observed").to_string());
        if pipe_name_lc.contains("psexesvc") || pipe_name_lc.contains("paexec") {
            labels.push("psexec_named_pipe".to_string());
        }
    }
    if service_name_lc.contains("psexesvc") {
        family = Some("lateral_movement");
        event_kind = Some("psexec_service_observed");
        labels.push("psexec_service".to_string());
    }

    labels.sort();
    labels.dedup();
    json!({
        "event_family": family,
        "event_kind": event_kind,
        "labels": labels,
        "time_search_terms": event_time_search_terms(event_time_utc, time_original),
        "logon_type": logon_type,
        "logon_type_name": normalized_logon_type,
        "ticket_encryption_type": ticket_encryption_type,
        "ticket_encryption_name": ticket_encryption_name,
        "ticket_encryption_weak": ticket_encryption_name == Some("rc4_hmac"),
        "pre_auth_type": pre_auth_type,
        "service_name": service_name,
        "rule_name": rule_name,
        "firewall_direction": firewall_direction,
        "firewall_action": firewall_action,
        "audit_subcategory": audit_subcategory,
        "pipe_name": pipe_name,
    })
}

fn evtx_semantic_severity(base: &'static str, semantics: &Value) -> &'static str {
    if semantic_label_contains(semantics, "asrep_roast_candidate")
        || semantic_label_contains(semantics, "kerberoast_candidate")
        || semantic_label_contains(semantics, "psexec_service")
        || semantic_label_contains(semantics, "psexec_named_pipe")
        || semantic_label_contains(semantics, "firewall_block")
    {
        "high"
    } else if semantic_label_contains(semantics, "firewall_outbound")
        || semantic_label_contains(semantics, "audit_policy_changed")
        || semantic_label_contains(semantics, "system_audit_policy_changed")
        || semantic_label_contains(semantics, "rdp_logon_type_10")
    {
        if base == "critical" || base == "high" {
            base
        } else {
            "medium"
        }
    } else {
        base
    }
}

fn semantic_label_contains(semantics: &Value, label: &str) -> bool {
    semantics
        .get("labels")
        .and_then(Value::as_array)
        .map(|labels| labels.iter().any(|value| value.as_str() == Some(label)))
        .unwrap_or(false)
}

fn event_time_search_terms(event_time_utc: &str, time_original: Option<&str>) -> Vec<String> {
    let mut terms = Vec::new();
    push_unique_term(&mut terms, event_time_utc);
    if let Some(original) = time_original {
        push_unique_term(&mut terms, original);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(event_time_utc) {
        let utc = dt.with_timezone(&Utc);
        push_unique_term(&mut terms, &utc.format("%Y-%m-%d %H:%M:%S UTC").to_string());
        push_unique_term(&mut terms, &utc.format("%Y/%m/%d %H:%M:%S").to_string());
        push_unique_term(&mut terms, &utc.format("%d/%m/%Y %H:%M:%S").to_string());
        push_unique_term(&mut terms, &utc.format("%m/%d/%Y %H:%M:%S").to_string());
        push_unique_term(&mut terms, &utc.timestamp().to_string());
    }
    terms
}

fn push_unique_term(terms: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && !terms.iter().any(|existing| existing == value) {
        terms.push(value.to_string());
    }
}

fn logon_type_name(value: &str) -> Option<&'static str> {
    match value.trim() {
        "2" => Some("interactive"),
        "3" => Some("network"),
        "4" => Some("batch"),
        "5" => Some("service"),
        "7" => Some("unlock"),
        "8" => Some("network_cleartext"),
        "9" => Some("new_credentials"),
        "10" => Some("remote_interactive"),
        "11" => Some("cached_interactive"),
        _ => None,
    }
}

fn ticket_encryption_type_name(value: &str) -> Option<&'static str> {
    match value
        .trim()
        .trim_start_matches("0x")
        .to_ascii_lowercase()
        .as_str()
    {
        "1" => Some("des_cbc_crc"),
        "3" => Some("des_cbc_md5"),
        "11" => Some("aes128_cts_hmac_sha1_96"),
        "12" => Some("aes256_cts_hmac_sha1_96"),
        "17" => Some("rc4_hmac"),
        "18" => Some("aes256_cts_hmac_sha1_96"),
        "23" => Some("rc4_hmac"),
        _ => None,
    }
}

fn normalize_firewall_direction(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("out") || lower.contains("%%14593") || lower == "2" {
        Some("outbound")
    } else if lower.contains("in") || lower.contains("%%14592") || lower == "1" {
        Some("inbound")
    } else {
        None
    }
}

fn normalize_firewall_action(value: &str) -> Option<&'static str> {
    let lower = value.trim().to_ascii_lowercase();
    if lower.contains("block")
        || lower.contains("deny")
        || lower.contains("%%14598")
        || lower == "2"
    {
        Some("blocked")
    } else if lower.contains("allow")
        || lower.contains("permit")
        || lower.contains("%%14597")
        || lower == "3"
    {
        Some("allowed")
    } else {
        None
    }
}

fn windows_event_action_provider(
    event_id: Option<&str>,
    provider: Option<&str>,
    data: &HashMap<String, String>,
) -> String {
    let provider_lc = provider.unwrap_or_default().to_ascii_lowercase();
    let id = event_id.and_then(|value| value.trim().parse::<i64>().ok());
    if provider_lc.contains("defender") {
        return defender_event_action(event_id, Some(data));
    }
    if provider_lc.contains("sysmon") {
        return match id {
            Some(1) => "process_created".to_string(),
            Some(2) => "file_create_time_changed".to_string(),
            Some(3) => "network_connection".to_string(),
            Some(7) => "image_loaded".to_string(),
            Some(8) => "remote_thread_created".to_string(),
            Some(10) => "process_accessed".to_string(),
            Some(11) => "file_created".to_string(),
            Some(12) => "registry_object_created_deleted".to_string(),
            Some(13) => "registry_value_set".to_string(),
            Some(14) => "registry_object_renamed".to_string(),
            Some(15) => "file_stream_created".to_string(),
            Some(17) => "named_pipe_created".to_string(),
            Some(18) => "named_pipe_connected".to_string(),
            Some(22) => "dns_query".to_string(),
            Some(23) | Some(26) => "file_deleted".to_string(),
            _ => windows_event_action(event_id),
        };
    }
    if provider_lc.contains("taskscheduler") || provider_lc.contains("task-scheduler") {
        return match id {
            Some(106) | Some(4698) => "scheduled_task_created".to_string(),
            Some(140) | Some(4702) => "scheduled_task_updated".to_string(),
            Some(141) | Some(4699) => "scheduled_task_deleted".to_string(),
            Some(200) | Some(201) => "scheduled_task_action_started".to_string(),
            Some(102) | Some(203) => "scheduled_task_completed".to_string(),
            _ => windows_event_action(event_id),
        };
    }
    if provider_lc.contains("service control manager") {
        return match id {
            Some(7045) => "service_installed".to_string(),
            Some(7036) => "service_state_changed".to_string(),
            Some(7030) | Some(7040) => "service_config_changed".to_string(),
            _ => windows_event_action(event_id),
        };
    }
    match id {
        Some(4698) => "scheduled_task_created".to_string(),
        Some(4699) => "scheduled_task_deleted".to_string(),
        Some(4702) => "scheduled_task_updated".to_string(),
        Some(4724) => "password_reset_attempt".to_string(),
        Some(4768) => "kerberos_tgt_requested".to_string(),
        Some(4769) => "kerberos_service_ticket_requested".to_string(),
        Some(4771) => "kerberos_preauth_failed".to_string(),
        Some(4946) | Some(2004) => "firewall_rule_added".to_string(),
        Some(4947) | Some(2005) => "firewall_rule_modified".to_string(),
        Some(4948) | Some(2006) => "firewall_rule_deleted".to_string(),
        Some(4949) | Some(4950) | Some(4954) => "firewall_policy_changed".to_string(),
        Some(5156) => "firewall_connection_allowed".to_string(),
        Some(5152) | Some(5157) => "firewall_connection_blocked".to_string(),
        Some(4719) | Some(4902) | Some(4904) | Some(4905) | Some(4906) | Some(4907)
        | Some(4908) | Some(4912) => "audit_policy_changed".to_string(),
        Some(4703) => "privilege_rights_changed".to_string(),
        Some(5136) => "directory_object_modified".to_string(),
        _ => windows_event_action(event_id),
    }
}

fn windows_event_action(event_id: Option<&str>) -> String {
    match event_id.and_then(|value| value.trim().parse::<i64>().ok()) {
        Some(4624) => "logon_success",
        Some(4625) => "logon_failure",
        Some(4634) => "logoff",
        Some(4648) => "explicit_credentials",
        Some(4672) => "special_privileges_assigned",
        Some(4688) => "process_created",
        Some(4689) => "process_exited",
        Some(4697) | Some(7045) => "service_installed",
        Some(4720) => "user_created",
        Some(4726) => "user_deleted",
        Some(4732) => "group_member_added",
        Some(4733) => "group_member_removed",
        Some(1102) => "audit_log_cleared",
        Some(1) => "process_created",
        Some(3) => "network_connection",
        Some(11) => "file_created",
        Some(_) => "windows_event",
        None => "observed",
    }
    .to_string()
}

fn windows_event_severity(event_id: Option<&str>, level: Option<&str>) -> &'static str {
    if let Some(level) = level {
        let lower = level.to_ascii_lowercase();
        if lower.contains("critical") {
            return "critical";
        }
        if lower.contains("error") || lower.contains("fail") {
            return "high";
        }
        if lower.contains("warn") {
            return "medium";
        }
    }
    match event_id.and_then(|value| value.trim().parse::<i64>().ok()) {
        Some(1102) => "critical",
        Some(4625) | Some(4697) | Some(7045) | Some(5152) | Some(5157) => "high",
        Some(4648) | Some(4672) | Some(4732) | Some(4733) | Some(4719) | Some(4768)
        | Some(4769) | Some(4946) | Some(4947) | Some(4948) | Some(4949) | Some(4950)
        | Some(4954) | Some(5156) => "medium",
        _ => "info",
    }
}

fn format_event_message(
    event_code: Option<&str>,
    action: &str,
    data: &HashMap<String, String>,
) -> String {
    let user = first_event_field(
        data,
        &[
            "TargetUserName",
            "SubjectUserName",
            "AccountName",
            "UserName",
            "User",
        ],
    );
    let process = first_event_field(
        data,
        &["NewProcessName", "ProcessName", "Image", "Application"],
    );
    let ip = first_event_field(
        data,
        &["IpAddress", "SourceNetworkAddress", "ClientAddress"],
    );
    let mut parts = Vec::new();
    if let Some(event_code) = event_code {
        parts.push(format!("EventID {event_code}"));
    }
    parts.push(action.to_string());
    if let Some(user) = user {
        parts.push(format!("user={}", sanitize_account_name(&user)));
    }
    if let Some(process) = process {
        parts.push(format!("process={process}"));
    }
    if let Some(ip) = ip {
        parts.push(format!("ip={ip}"));
    }
    for (label, names) in [
        ("logon_type", &["LogonType"][..]),
        ("ticket_encryption", &["TicketEncryptionType"][..]),
        ("preauth", &["PreAuthType", "PreAuthenticationType"][..]),
        ("service", &["ServiceName"][..]),
        ("rule", &["RuleName", "Rule Name", "Name"][..]),
        ("direction", &["Direction"][..]),
        ("audit_subcategory", &["SubcategoryName", "Subcategory"][..]),
        ("pipe", &["PipeName"][..]),
        ("command", &["CommandLine", "ProcessCommandLine"][..]),
    ] {
        let value = if label == "audit_subcategory" {
            audit_subcategory_name(data)
        } else {
            first_event_field(data, names)
        };
        if let Some(value) = value {
            parts.push(format!("{label}={}", truncate(&value, 120)));
        }
    }
    parts.join(" ")
}

fn defender_event_action(event_id: Option<&str>, data: Option<&HashMap<String, String>>) -> String {
    let action = match event_id.and_then(|value| value.trim().parse::<i64>().ok()) {
        Some(1000) => "defender_scan_started",
        Some(1001) => "defender_scan_completed",
        Some(1002) => "defender_scan_stopped",
        Some(1116) => "defender_threat_detected",
        Some(1117) => "defender_remediation_action",
        Some(1118) => "defender_remediation_failed",
        Some(1119) => "defender_remediation_succeeded",
        Some(1120) => "defender_threat_status_changed",
        Some(1121) => "defender_threat_status_changed",
        Some(5007) => "defender_configuration_changed",
        Some(5013) => "defender_tamper_or_config_blocked",
        Some(_) => "defender_operational_event",
        None => {
            return data
                .and_then(|data| {
                    first_named(
                        data,
                        &["Action", "Category", "EventName", "EventType", "Status"],
                    )
                })
                .map(|value| defender_text_action(&value))
                .unwrap_or_else(|| "defender_event".to_string())
        }
    };
    action.to_string()
}

fn defender_event_severity(
    event_id: Option<&str>,
    level: Option<&str>,
    data: Option<&HashMap<String, String>>,
) -> &'static str {
    if let Some(level) = level {
        let lower = level.to_ascii_lowercase();
        if lower.contains("critical") {
            return "critical";
        }
        if lower.contains("error") || lower.contains("fail") {
            return "high";
        }
        if lower.contains("warn") {
            return "medium";
        }
    }
    match event_id.and_then(|value| value.trim().parse::<i64>().ok()) {
        Some(1116) | Some(1118) | Some(5013) => "high",
        Some(1117) | Some(1119) | Some(1120) | Some(1121) | Some(5007) => "medium",
        _ => data
            .and_then(|data| {
                first_event_field(data, &["Severity", "Threat Severity", "ThreatSeverity"])
            })
            .map(|value| defender_text_severity(&value))
            .unwrap_or("info"),
    }
}

fn defender_message(
    event_code: Option<&str>,
    action: &str,
    threat: Option<&str>,
    path: Option<&str>,
    data: Option<&HashMap<String, String>>,
) -> String {
    let mut parts = Vec::new();
    if let Some(event_code) = event_code {
        parts.push(format!("EventID {event_code}"));
    }
    parts.push(action.to_string());
    if let Some(threat) = threat {
        parts.push(format!("threat={threat}"));
    }
    if let Some(path) = path {
        parts.push(format!("path={path}"));
    }
    if let Some(status) =
        data.and_then(|data| first_event_field(data, &["Status", "Action Status", "ActionStatus"]))
    {
        parts.push(format!("status={status}"));
    }
    parts.join(" ")
}

fn defender_text_action(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("threat") || lower.contains("malware") || lower.contains("detected") {
        "defender_threat_detected"
    } else if lower.contains("quarantine")
        || lower.contains("remediat")
        || lower.contains("clean")
        || lower.contains("remove")
    {
        "defender_remediation_action"
    } else if lower.contains("configuration")
        || lower.contains("preference")
        || lower.contains("setting")
        || lower.contains("policy")
    {
        "defender_configuration_changed"
    } else if lower.contains("scan") {
        "defender_scan"
    } else if lower.contains("error") || lower.contains("fail") {
        "defender_error"
    } else {
        "defender_mplog_observed"
    }
    .to_string()
}

fn defender_text_severity(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("severe") || lower.contains("critical") {
        "critical"
    } else if lower.contains("threat")
        || lower.contains("malware")
        || lower.contains("detected")
        || lower.contains("error")
        || lower.contains("fail")
    {
        "high"
    } else if lower.contains("quarantine")
        || lower.contains("remediat")
        || lower.contains("configuration")
        || lower.contains("policy")
    {
        "medium"
    } else {
        "info"
    }
}

fn split_leading_timestamp(line: &str) -> (Option<String>, String) {
    let trimmed = line.trim().trim_start_matches('[');
    let char_len = trimmed.chars().count();
    for len in [33usize, 29, 26, 25, 24, 23, 22, 19] {
        if char_len >= len {
            let candidate_text = trimmed.chars().take(len).collect::<String>();
            let candidate = candidate_text.trim().trim_end_matches(']');
            if normalize_datetime(candidate).is_some() {
                let rest = trimmed
                    .chars()
                    .skip(len)
                    .collect::<String>()
                    .trim_start_matches(|ch: char| {
                        ch == ']' || ch == ':' || ch == '-' || ch.is_whitespace()
                    })
                    .trim()
                    .to_string();
                return (
                    Some(candidate.to_string()),
                    if rest.is_empty() {
                        line.to_string()
                    } else {
                        rest
                    },
                );
            }
        }
    }
    let mut parts = trimmed.split_whitespace();
    if let (Some(date), Some(time)) = (parts.next(), parts.next()) {
        let candidate = format!("{date} {time}");
        if normalize_datetime(&candidate).is_some() {
            let rest = parts.collect::<Vec<_>>().join(" ");
            return (
                Some(candidate),
                if rest.is_empty() {
                    line.to_string()
                } else {
                    rest
                },
            );
        }
    }
    (None, line.trim().to_string())
}

fn extract_label_value(message: &str, labels: &[&str]) -> Option<String> {
    for label in labels {
        let lower = message.to_ascii_lowercase();
        let label_lower = label.to_ascii_lowercase();
        if let Some(offset) = lower.find(&label_lower) {
            let after = &message[offset + label.len()..];
            let after =
                after.trim_start_matches(|ch: char| ch == ':' || ch == '=' || ch.is_whitespace());
            let value = after.split([';', ',', '\t']).next().unwrap_or(after).trim();
            if let Some(value) = clean_opt(Some(value.to_string())) {
                return Some(value);
            }
        }
    }
    None
}

fn extract_path_like(message: &str) -> Option<String> {
    extract_label_value(message, &["Path", "File", "Resource", "Resources"])
        .and_then(|value| extract_path_like_candidates(&value).into_iter().next())
        .or_else(|| extract_path_like_candidates(message).into_iter().next())
}

fn extract_path_near_label(message: &str, labels: &[&str]) -> Option<String> {
    for label in labels {
        let lower = message.to_ascii_lowercase();
        let label_lower = label.to_ascii_lowercase();
        let Some(offset) = lower.find(&label_lower) else {
            continue;
        };
        let after = &message[offset + label.len()..];
        if let Some(path) = extract_path_like_candidates(after).into_iter().next() {
            return Some(path);
        }
    }
    None
}

fn extract_path_like_candidates(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in message.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | ',' | ';' | '<' | '>' | '(' | ')' | '[' | ']' | '\0'
            )
    }) {
        let Some(candidate) = sanitize_path_candidate(part) else {
            continue;
        };
        if out.iter().any(|existing| existing == &candidate) {
            continue;
        }
        out.push(candidate);
    }
    out
}

fn extract_shellbag_folder_candidate(message: &str) -> Option<String> {
    let candidates = extract_path_like_candidates(message);
    candidates
        .iter()
        .find(|candidate| {
            let lower = candidate.to_ascii_lowercase();
            !lower.starts_with("software\\")
                && !lower.starts_with("system\\")
                && (lower.contains(":\\")
                    || lower.starts_with("\\\\")
                    || lower.contains("\\users\\")
                    || lower.contains("/users/"))
        })
        .cloned()
        .or_else(|| {
            candidates.into_iter().find(|candidate| {
                let lower = candidate.to_ascii_lowercase();
                lower.contains("\\desktop")
                    || lower.contains("\\downloads")
                    || lower.contains("/desktop")
                    || lower.contains("/downloads")
            })
        })
}

fn sanitize_path_candidate(value: &str) -> Option<String> {
    let trimmed = value.trim_matches(|ch: char| {
        ch == '"' || ch == '\'' || ch == ',' || ch == ';' || ch == ':' || ch == ')' || ch == ']'
    });
    if !looks_like_path(trimmed) {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    for suffix in [
        ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".lnk",
    ] {
        if let Some(offset) = lower.find(suffix) {
            let end = offset + suffix.len();
            return clean_opt(Some(trimmed[..end].to_string()));
        }
    }
    clean_opt(Some(trimmed.to_string()))
}

fn extract_recent_document_candidate(value: &str) -> Option<String> {
    value
        .split(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '"' | '\'' | ',' | ';' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '\0'
                )
        })
        .map(|part| part.trim_matches(|ch: char| ch == ':' || ch == '.' || ch == ',' || ch == ';'))
        .find(|part| is_recent_document_name(part))
        .map(str::to_string)
}

fn is_recent_document_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let Some((name, _)) = lower.rsplit_once('.') else {
        return false;
    };
    if name.len() < 1 {
        return false;
    }
    [
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".csv", ".zip",
        ".7z", ".rar", ".jpg", ".jpeg", ".png", ".bmp", ".lnk", ".exe", ".ps1", ".bat", ".cmd",
        ".js", ".vbs",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn extract_hash_like(message: &str) -> Option<String> {
    extract_label_value(message, &["SHA256", "SHA1", "MD5", "Hash"]).or_else(|| {
        message
            .split_whitespace()
            .map(|part| part.trim_matches(|ch: char| !ch.is_ascii_hexdigit()))
            .find(|part| {
                matches!(part.len(), 32 | 40 | 64) && part.chars().all(|ch| ch.is_ascii_hexdigit())
            })
            .map(str::to_string)
    })
}

fn extract_process_name_like(message: &str) -> Option<String> {
    extract_label_value(
        message,
        &[
            "Process Name",
            "ProcessName",
            "Image",
            "Executable",
            "ExecutableName",
            "ProgramName",
        ],
    )
    .and_then(|value| file_name_from_path(&value).or(Some(value)))
    .or_else(|| {
        message
            .split(|ch: char| {
                ch.is_whitespace()
                    || matches!(
                        ch,
                        '"' | '\'' | ',' | ';' | '<' | '>' | '(' | ')' | '[' | ']' | '\0'
                    )
            })
            .find(|part| is_executable_name(part))
            .and_then(|part| file_name_from_path(part).or(Some(part.to_string())))
    })
}

fn contains_any_text(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| hay.contains(needle))
}

fn extract_forensic_strings(bytes: &[u8], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for value in extract_ascii_strings(bytes)
        .into_iter()
        .chain(extract_utf16le_strings(bytes))
    {
        let value = value.trim_matches(char::from(0)).trim().to_string();
        if value.len() < 4 || value.len() > 2048 || out.iter().any(|existing| existing == &value) {
            continue;
        }
        out.push(value);
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn registry_key_hint(context: &str) -> Option<String> {
    let candidates = [
        "CurrentVersion\\Run",
        "CurrentVersion\\RunOnce",
        "\\Services\\",
        "ImagePath",
        "Winlogon",
        "Userinit",
        "Shell",
        "WDigest",
        "UseLogonCredential",
        "UserAssist",
        "ShimCache",
        "AppCompatCache",
        "TypedURLs",
        "TypedPaths",
        "RecentDocs",
        "ShellBags",
        "BagMRU",
        "Amcache",
    ];
    let lower = context.to_ascii_lowercase();
    candidates.iter().find_map(|candidate| {
        let candidate_lower = candidate.to_ascii_lowercase();
        lower.find(&candidate_lower).map(|offset| {
            let start = offset.saturating_sub(80);
            let end = (offset + candidate.len() + 160).min(context.len());
            truncate(&context[start..end], 220)
        })
    })
}

fn database_string_action(
    artifact_type: &str,
    lower: &str,
    url: Option<&str>,
    process_name: Option<&str>,
) -> &'static str {
    match artifact_type {
        "browser" => {
            if url.is_some() && contains_any_text(lower, &["download", ".exe", ".ps1", ".zip"]) {
                "browser_download_observed"
            } else if url.is_some() {
                "browser_url_observed"
            } else if process_name.is_some() {
                "browser_process_string_observed"
            } else {
                "browser_artifact_string_observed"
            }
        }
        "web_cache" => {
            if url.is_some() && contains_any_text(lower, &["download", ".exe", ".ps1", ".zip"]) {
                "webcache_download_observed"
            } else if url.is_some() {
                "webcache_url_observed"
            } else {
                "webcache_cache_artifact_observed"
            }
        }
        "srum" => {
            if process_name.is_some() {
                "srum_process_resource_observed"
            } else if url.is_some() || lower.contains("network") {
                "srum_network_resource_observed"
            } else if contains_any_text(
                lower,
                &[
                    "appresource",
                    "energy",
                    "interface",
                    "resource",
                    "recordoffset",
                    "autoinc",
                ],
            ) {
                "srum_schema_or_resource_observed"
            } else {
                "srum_resource_observed"
            }
        }
        "sqlite" => {
            if url.is_some() {
                "sqlite_url_observed"
            } else {
                "sqlite_artifact_string_observed"
            }
        }
        _ => "ese_artifact_string_observed",
    }
}

fn database_signal_severity(artifact_type: &str, lower: &str) -> &'static str {
    if contains_any_text(
        lower,
        &[
            "powershell",
            "cmd.exe",
            "rundll32",
            "regsvr32",
            "mshta",
            "mimikatz",
            "lsass",
            "malware",
            "trojan",
        ],
    ) {
        "high"
    } else if matches!(artifact_type, "browser" | "web_cache" | "srum" | "sqlite") {
        "medium"
    } else {
        "info"
    }
}

fn defender_process_hint(message: &str) -> Option<String> {
    extract_label_value(
        message,
        &["Process Name", "ProcessName", "Process", "Image"],
    )
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut out = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

fn sanitize_display_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut previous_space = false;
    for ch in value.chars() {
        let replacement = if ch == '\u{fffd}'
            || matches!(
                ch,
                '\u{0000}'..='\u{0008}'
                    | '\u{000b}'
                    | '\u{000c}'
                    | '\u{000e}'..='\u{001f}'
                    | '\u{007f}'..='\u{009f}'
            ) {
            ' '
        } else {
            ch
        };
        if replacement.is_whitespace() {
            if !previous_space {
                out.push(' ');
                previous_space = true;
            }
        } else {
            out.push(replacement);
            previous_space = false;
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn process_identity_sysmon_eid1_uses_guid_and_child_pid() {
        // Sysmon EID 1: ProcessId is the child, ParentProcessId the parent; GUIDs present.
        let row = map(&[
            ("ProcessGuid", "{aaaa-1111}"),
            ("ProcessId", "4321"),
            ("ParentProcessGuid", "{bbbb-2222}"),
            ("ParentProcessId", "1000"),
        ]);
        let (pid, guid, ppid, pguid) = process_identity(&row);
        assert_eq!(pid.as_deref(), Some("4321"));
        assert_eq!(guid.as_deref(), Some("{aaaa-1111}"));
        assert_eq!(ppid.as_deref(), Some("1000"));
        assert_eq!(pguid.as_deref(), Some("{bbbb-2222}"));
    }

    #[test]
    fn process_identity_security_4688_maps_new_pid_to_child_and_hex_to_decimal() {
        // Security 4688: NewProcessId is the child, ProcessId is the creator/parent.
        // Both are hex and must normalize to decimal. No GUIDs available.
        let row = map(&[
            ("NewProcessId", "0x1a4"),
            ("ProcessId", "0x2b8"),
        ]);
        let (pid, guid, ppid, pguid) = process_identity(&row);
        assert_eq!(pid.as_deref(), Some("420")); // 0x1a4
        assert_eq!(ppid.as_deref(), Some("696")); // 0x2b8
        assert!(guid.is_none());
        assert!(pguid.is_none());
    }

    #[test]
    fn sanitize_account_name_strips_evtx_garbage_prefix() {
        // Upstream evtx-crate BITS evt5 misdecode: CJK/PUA garbage glued to the resolved name.
        assert_eq!(
            sanitize_account_name("\u{2d75}\u{c01c}\u{f7f6}NT AUTHORITY\\NETWORK SERVICE"),
            "NT AUTHORITY\\NETWORK SERVICE"
        );
        // Garbage prefix that itself contains an ASCII char must still be dropped wholesale.
        assert_eq!(
            sanitize_account_name("\u{2f22}\u{57aa}0\u{4256b}NT AUTHORITY\\NETWORK SERVICE"),
            "NT AUTHORITY\\NETWORK SERVICE"
        );
        // Already-clean reserved accounts are unchanged (idempotent, marker at offset 0).
        for clean in [
            "NT AUTHORITY\\NETWORK SERVICE",
            "NT AUTHORITY\\SYSTEM",
            "NT SERVICE\\MSSQLSERVER",
            "BUILTIN\\Administrators",
        ] {
            assert_eq!(sanitize_account_name(clean), clean);
        }
        // Legitimate non-ASCII / domain usernames carry no marker -> untouched.
        for legit in ["田中太郎", "CORP\\山田", "Администратор", "moveitsvc"] {
            assert_eq!(sanitize_account_name(legit), legit);
        }
        // Garbage with NO reserved marker is a no-op (zero false positives over truncation).
        assert_eq!(sanitize_account_name("\u{2d75}\u{c01c}"), "\u{2d75}\u{c01c}");
    }

    fn utf16le_bytes(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }

    fn write_utf16le_at(bytes: &mut [u8], offset: usize, value: &str) {
        let encoded = utf16le_bytes(value);
        bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
    }

    fn test_mft_record(
        record_number: u64,
        parent_record_number: Option<u64>,
        file_name: &str,
    ) -> MftNativeRecord {
        test_mft_record_with_sequences(
            record_number,
            1,
            parent_record_number,
            parent_record_number.map(|_| 1),
            file_name,
        )
    }

    fn test_mft_record_with_sequences(
        record_number: u64,
        sequence_number: u16,
        parent_record_number: Option<u64>,
        parent_sequence_number: Option<u16>,
        file_name: &str,
    ) -> MftNativeRecord {
        MftNativeRecord {
            record_number,
            record_offset: record_number * 1024,
            record_size: 1024,
            sequence_number,
            in_use: true,
            is_directory: false,
            parent_record_number,
            parent_sequence_number,
            file_name: Some(file_name.to_string()),
            file_namespace: None,
            file_attributes: None,
            allocated_size: None,
            file_size: None,
            si_created: None,
            si_modified: None,
            si_record_changed: None,
            si_accessed: None,
            fn_created: None,
            fn_modified: None,
            fn_record_changed: None,
            fn_accessed: None,
            attribute_count: 0,
            attributes: Vec::new(),
            resident_contents: Vec::new(),
            data_runs: Vec::new(),
        }
    }

    fn test_filetime_bytes(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> [u8; 8] {
        let dt = Utc
            .with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .unwrap();
        let value = (dt.timestamp() as u64 * 10_000_000) + 116_444_736_000_000_000u64;
        value.to_le_bytes()
    }

    #[test]
    fn mft_path_reconstruction_breaks_parent_cycles() {
        let records = vec![
            test_mft_record(1, Some(2), "child.txt"),
            test_mft_record(2, Some(1), "parent"),
        ];
        let map = mft_path_map(&records);
        let mut cache = HashMap::new();
        let path = mft_path_for_record(1, &map, &mut cache).unwrap();

        assert!(path.ends_with("child.txt"));
        assert!(path.len() < 64);
        assert!(!path.contains("child.txt\\parent\\child.txt"));
    }

    #[test]
    fn mft_path_reconstruction_rejects_stale_parent_sequence() {
        let records = vec![
            test_mft_record_with_sequences(10, 7, Some(5), Some(99), "child.aspx"),
            test_mft_record_with_sequences(5, 3, None, None, "old_parent"),
        ];
        let map = mft_path_map(&records);
        let mut cache = HashMap::new();
        let path = mft_path_for_record(10, &map, &mut cache).unwrap();

        assert_eq!(path, "child.aspx");
    }

    #[test]
    fn mft_path_reconstruction_accepts_matching_parent_sequence() {
        let records = vec![
            test_mft_record_with_sequences(10, 7, Some(5), Some(3), "child.aspx"),
            test_mft_record_with_sequences(5, 3, None, None, "inetpub"),
        ];
        let map = mft_path_map(&records);
        let mut cache = HashMap::new();
        let path = mft_path_for_record(10, &map, &mut cache).unwrap();

        assert_eq!(path, "inetpub\\child.aspx");
    }

    #[test]
    fn fake_parser_emits_lineage_and_raw_records() {
        let parser = FakeParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/demo".into(),
            original_path: "demo.log".into(),
            artifact_type: "text_log".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"INFO start\nERROR stop\n".to_vec(),
        };
        let outcome = parser.parse(input).unwrap();
        let ParserOutcome::Parsed(parsed) = outcome else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert_eq!(parsed.raw_records.len(), 2);
        assert_eq!(parsed.events[1].severity, "high");
        assert_eq!(
            parsed.events[0].raw_record_ref,
            parsed.raw_records[0].raw_record_ref
        );
    }

    #[test]
    fn fake_parser_reports_unsupported() {
        let parser = FakeParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/demo".into(),
            original_path: "demo.evtx".into(),
            artifact_type: "evtx".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"ignored".to_vec(),
        };
        let outcome = parser.parse(input).unwrap();
        assert!(matches!(outcome, ParserOutcome::Unsupported { .. }));
    }

    #[test]
    fn structured_parser_reads_evtx_xml_export() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/demo".into(),
            original_path: "security.evtx.xml".into(),
            artifact_type: "evtx".into(),
            parse_run_id: "parse_1".into(),
            bytes: br#"<Events><Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Computer>HOST1</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">10.0.0.5</Data></EventData></Event></Events>"#.to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert_eq!(parsed.events[0].user_name.as_deref(), Some("alice"));
        assert_eq!(parsed.events[0].event_action, "logon_success");
        assert_eq!(parsed.events[1].event_action, "evtx_record_context_indexed");
        assert_eq!(parsed.events[1].user_name.as_deref(), Some("alice"));
        let context_attrs =
            serde_json::from_str::<Value>(&parsed.events[1].attributes_json).unwrap();
        assert_eq!(
            context_attrs.get("parser_mode").and_then(Value::as_str),
            Some("evtx_xml_context")
        );
        assert_eq!(
            context_attrs["entity_refs"]
                .get("ip")
                .and_then(Value::as_str),
            Some("10.0.0.5")
        );
    }

    #[test]
    fn structured_parser_enriches_windows_security_semantics() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_semantics".into(),
            object_ref: "raw://sha256/evtx-semantics".into(),
            original_path: "security.evtx.xml".into(),
            artifact_type: "evtx".into(),
            parse_run_id: "parse_1".into(),
            bytes: br#"
            <Events>
              <Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4769</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Computer>DC1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">svc-mssql</Data><Data Name="ServiceName">MSSQLSvc/sql.lab.local</Data><Data Name="TicketEncryptionType">0x17</Data></EventData></Event>
              <Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2026-01-01T00:05:00Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">10.0.0.5</Data></EventData></Event>
              <Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5156</EventID><TimeCreated SystemTime="2026-01-01T00:10:00Z"/><Computer>HOST1</Computer><Channel>Security</Channel></System><EventData><Data Name="Direction">%%14593</Data><Data Name="Application">C:\Windows\System32\powershell.exe</Data></EventData></Event>
            </Events>"#
                .to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        let kerberos = parsed
            .events
            .iter()
            .find(|event| event.event_action == "kerberos_service_ticket_requested")
            .expect("kerberos event");
        assert_eq!(kerberos.severity, "high");
        assert!(kerberos.message_full.contains("ticket_encryption=0x17"));
        let attrs = serde_json::from_str::<Value>(&kerberos.attributes_json).unwrap();
        assert_eq!(
            attrs["semantics"]["ticket_encryption_name"].as_str(),
            Some("rc4_hmac")
        );
        assert!(attrs["semantics"]["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label.as_str() == Some("kerberoast_candidate")));

        let rdp = parsed
            .events
            .iter()
            .find(|event| event.message_full.contains("logon_type=10"))
            .expect("rdp logon");
        let rdp_attrs = serde_json::from_str::<Value>(&rdp.attributes_json).unwrap();
        assert_eq!(
            rdp_attrs["semantics"]["logon_type_name"].as_str(),
            Some("remote_interactive")
        );

        let firewall = parsed
            .events
            .iter()
            .find(|event| event.event_action == "firewall_connection_allowed")
            .expect("firewall event");
        let firewall_attrs = serde_json::from_str::<Value>(&firewall.attributes_json).unwrap();
        assert_eq!(
            firewall_attrs["semantics"]["firewall_direction"].as_str(),
            Some("outbound")
        );
    }

    #[test]
    fn structured_parser_enriches_hayabusa_embedded_windows_fields() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_hayabusa_semantics".into(),
            object_ref: "raw://sha256/hayabusa-semantics".into(),
            original_path: "timeline_waf.csv".into(),
            artifact_type: "csv".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"Timestamp,RuleTitle,Level,EventID,Computer,Channel,Details,ExtraFieldInfo\n2023-03-27 14:44:43,Uncommon New Firewall Rule Added In Windows Firewall Exception List,med,2004,HOST1,Firewall,\"RuleName: Metasploit C2 Bypass \xC2\xA6 App: \xC2\xA6 Direction: 2 \xC2\xA6 Action: 3\",RemotePort: 4444\n2023-03-27 14:50:00,Audit Policy Changed,info,4719,HOST1,Security,\"Subcategory: Other Object Access Events \xC2\xA6 Change: Success added\",\n2023-03-27 14:50:03,Audit Policy Changed,info,4719,HOST1,Security,\"SubcategoryGuid: 0CCE9227-69AE-11D9-BED3-505054503030 \xC2\xA6 AuditPolicyChanges: %%8449\",SubcategoryId: %%12804\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        let firewall = parsed
            .events
            .iter()
            .find(|event| event.message_full.contains("Metasploit C2 Bypass"))
            .expect("firewall row");
        let firewall_attrs = serde_json::from_str::<Value>(&firewall.attributes_json).unwrap();
        assert_eq!(
            firewall_attrs["semantics"]["rule_name"].as_str(),
            Some("Metasploit C2 Bypass")
        );
        assert_eq!(
            firewall_attrs["semantics"]["firewall_direction"].as_str(),
            Some("outbound")
        );
        assert_eq!(
            firewall_attrs["semantics"]["firewall_action"].as_str(),
            Some("allowed")
        );

        let audit = parsed
            .events
            .iter()
            .find(|event| event.message_full.contains("Other Object Access Events"))
            .expect("audit row");
        let audit_attrs = serde_json::from_str::<Value>(&audit.attributes_json).unwrap();
        assert_eq!(
            audit_attrs["semantics"]["audit_subcategory"].as_str(),
            Some("Other Object Access Events")
        );

        let audit_guid = parsed
            .events
            .iter()
            .find(|event| event.message_full.contains("SubcategoryGuid"))
            .expect("audit guid row");
        assert!(
            audit_guid
                .message_full
                .contains("Other Object Access Events"),
            "semantic audit subcategory should be searchable"
        );
        let audit_guid_attrs = serde_json::from_str::<Value>(&audit_guid.attributes_json).unwrap();
        assert_eq!(
            audit_guid_attrs["semantics"]["audit_subcategory"].as_str(),
            Some("Other Object Access Events")
        );
    }

    #[test]
    fn structured_parser_reads_raw_evtx_path_fixture_when_configured() {
        let Some(path) = std::env::var_os("TAOTIE4_RAW_EVTX_FIXTURE") else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        let parser = StructuredArtifactParser;
        let metadata = parser.metadata();
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/raw-evtx".into(),
            original_path: path.display().to_string(),
            artifact_type: "evtx".into(),
            parse_run_id: "parse_1".into(),
            bytes: Vec::new(),
        };
        let parsed = parse_evtx_path(&input, &metadata, &path).unwrap();
        assert!(
            !parsed.events.is_empty(),
            "raw EVTX fixture should expand to events"
        );
        assert_eq!(parsed.events[0].artifact_type, "evtx");
        let attrs = serde_json::from_str::<Value>(&parsed.events[0].attributes_json).unwrap();
        assert_eq!(
            attrs.get("parser_mode").and_then(Value::as_str),
            Some("evtx_native")
        );
    }

    #[test]
    fn raw_evtx_path_with_no_records_is_kept_as_observed_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("empty.evtx");
        std::fs::write(&path, b"ElfFile\0\0demo").unwrap();
        let parser = StructuredArtifactParser;
        let metadata = parser.metadata();
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/raw-evtx-empty".into(),
            original_path: path.display().to_string(),
            artifact_type: "evtx".into(),
            parse_run_id: "parse_1".into(),
            bytes: Vec::new(),
        };
        let parsed = parse_evtx_path(&input, &metadata, &path).unwrap();
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].artifact_type, "evtx");
        assert_eq!(parsed.events[0].event_action, "evtx_file_observed");
        let attrs = serde_json::from_str::<Value>(&parsed.events[0].attributes_json).unwrap();
        assert_eq!(
            attrs.get("parser_mode").and_then(Value::as_str),
            Some("file_metadata")
        );
    }

    #[test]
    fn structured_parser_reads_hayabusa_csv_export() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/hayabusa".into(),
            original_path: "hayabusa.csv".into(),
            artifact_type: "csv".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"Timestamp,RuleTitle,Level,EventID,Computer,Channel,Details,MitreTags\n2026-01-01 00:00:00,Encoded PowerShell,high,4688,HOST1,Security,powershell -enc AAA,attack.t1059.001\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].artifact_type, "hayabusa");
        assert_eq!(parsed.events[0].event_action, "hayabusa_detection");
        assert_eq!(parsed.events[0].severity, "high");
        assert!(parsed.events[0].message_full.contains("Encoded PowerShell"));
    }

    #[test]
    fn structured_parser_decodes_cp932_text_logs() {
        let parser = StructuredArtifactParser;
        let mut bytes = b"WARN ".to_vec();
        bytes.extend_from_slice(&[0x83, 0x65, 0x83, 0x58, 0x83, 0x67]);
        bytes.push(b'\n');
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/cp932".into(),
            original_path: "japanese.log".into(),
            artifact_type: "text_log".into(),
            parse_run_id: "parse_1".into(),
            bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert!(parsed.events.iter().any(|event| {
            event.artifact_type == "text_observation" && event.message_full.contains("テスト")
        }));
        assert!(parsed.events.iter().any(|event| {
            event.artifact_type == "text_log" && event.message_full.contains("テスト")
        }));
    }

    #[test]
    fn structured_parser_structures_text_log_line_signals() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_text_log".into(),
            object_ref: "raw://sha256/text-log".into(),
            original_path: "C/Users/jdoe/AppData/Local/Temp/app.log".into(),
            artifact_type: "text_log".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"2026-01-01 00:00:00 INFO powershell.exe connected 10.0.0.5 https://evil.example.test/a.ps1 C:\\Users\\jdoe\\Downloads\\a.ps1\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert!(parsed.events.iter().any(|event| {
            event.artifact_type == "text_observation"
                && event.url.as_deref() == Some("https://evil.example.test/a.ps1")
        }));
        let event = parsed
            .events
            .iter()
            .find(|event| event.event_action == "text_log_download_observed")
            .expect("text_log_download_observed event");
        assert_eq!(event.artifact_type, "text_log");
        assert_eq!(event.event_action, "text_log_download_observed");
        assert_eq!(event.process_name.as_deref(), Some("powershell.exe"));
        assert_eq!(event.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(
            event.url.as_deref(),
            Some("https://evil.example.test/a.ps1")
        );
        assert_eq!(
            event.file_path.as_deref(),
            Some("C:\\Users\\jdoe\\Downloads\\a.ps1")
        );
        let attrs = serde_json::from_str::<Value>(&event.attributes_json).unwrap();
        assert_eq!(
            attrs.get("domain").and_then(Value::as_str),
            Some("evil.example.test")
        );
    }

    #[test]
    fn structured_parser_classifies_iis_text_logs() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_iis".into(),
            object_ref: "raw://sha256/iis".into(),
            original_path: "C/inetpub/logs/LogFiles/W3SVC1/u_ex260101.log".into(),
            artifact_type: "text_log".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"2026-01-01 00:00:00 10.0.0.5 POST /moveitisapi/moveitisapi.dll?action=upload - 443 attacker 203.0.113.9 curl/8.0 500 0 0 15\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        let event = parsed
            .events
            .iter()
            .find(|event| event.event_action == "text_log_http_request_observed")
            .expect("classified http event");
        assert_eq!(event.severity, "medium");
        let attrs = serde_json::from_str::<Value>(&event.attributes_json).unwrap();
        assert_eq!(
            attrs.get("log_family").and_then(Value::as_str),
            Some("web_access")
        );
        assert_eq!(
            attrs.get("http_method").and_then(Value::as_str),
            Some("POST")
        );
        assert_eq!(attrs.get("http_status").and_then(Value::as_i64), Some(500));
    }

    #[test]
    fn structured_parser_classifies_auth_and_powershell_text_logs() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_auth".into(),
            object_ref: "raw://sha256/auth".into(),
            original_path: "var/log/auth.log".into(),
            artifact_type: "text_log".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"Jan 01 00:00:00 host sshd[123]: Failed password for invalid user root from 10.0.0.5 port 22 ssh2\n2026-01-01 00:01:00 powershell.exe -EncodedCommand SQBFAFgA\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        let auth = parsed
            .events
            .iter()
            .find(|event| event.event_action == "text_log_auth_failure_observed")
            .expect("auth failure event");
        assert_eq!(auth.ip.as_deref(), Some("10.0.0.5"));
        let auth_attrs = serde_json::from_str::<Value>(&auth.attributes_json).unwrap();
        assert_eq!(
            auth_attrs.get("classification").and_then(Value::as_str),
            Some("auth_failure")
        );
        let ps = parsed
            .events
            .iter()
            .find(|event| event.event_action == "text_log_powershell_activity_observed")
            .expect("powershell event");
        assert_eq!(ps.severity, "high");
        let ps_attrs = serde_json::from_str::<Value>(&ps.attributes_json).unwrap();
        assert_eq!(
            ps_attrs.get("classification").and_then(Value::as_str),
            Some("suspicious_powershell")
        );
    }

    #[test]
    fn structured_parser_emits_usn_parent_reference_events() {
        let parser = StructuredArtifactParser;
        let name = utf16le_bytes("evil.exe");
        let record_len = 60 + name.len();
        let mut bytes = vec![0u8; record_len];
        bytes[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&0u16.to_le_bytes());
        bytes[8..16].copy_from_slice(&42u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&7u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&1234i64.to_le_bytes());
        bytes[32..40].copy_from_slice(&test_filetime_bytes(2026, 1, 1, 0, 0, 0));
        bytes[40..44].copy_from_slice(&(0x0000_0100u32 | 0x8000_0000u32).to_le_bytes());
        bytes[52..56].copy_from_slice(&0x20u32.to_le_bytes());
        bytes[56..58].copy_from_slice(&(name.len() as u16).to_le_bytes());
        bytes[58..60].copy_from_slice(&60u16.to_le_bytes());
        bytes[60..60 + name.len()].copy_from_slice(&name);
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_usn".into(),
            object_ref: "raw://sha256/usn".into(),
            original_path: "C/$Extend/$J".into(),
            artifact_type: "usn_jrnl".into(),
            parse_run_id: "parse_1".into(),
            bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert_eq!(parsed.events[0].event_action, "usn_created");
        assert_eq!(
            parsed.events[1].event_action,
            "usn_parent_reference_observed"
        );
        let attrs = serde_json::from_str::<Value>(&parsed.events[1].attributes_json).unwrap();
        assert_eq!(
            attrs.get("file_reference").and_then(Value::as_u64),
            Some(42)
        );
        assert_eq!(
            attrs.get("parent_file_reference").and_then(Value::as_u64),
            Some(7)
        );
    }

    #[test]
    fn structured_parser_reads_mft_csv_export() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/demo".into(),
            original_path: "MFT_Output.csv".into(),
            artifact_type: "mft".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"EntryNumber,SequenceNumber,FullPath,Created0x10,LastModified0x10\n1,1,C:\\\\Temp\\\\evil.exe,2026-01-01 00:00:00,2026-01-01 00:05:00\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert_eq!(parsed.events[0].artifact_type, "mft");
        assert_eq!(
            parsed.events[0].file_path.as_deref(),
            Some("C:\\\\Temp\\\\evil.exe")
        );
    }

    #[test]
    fn native_mft_parser_extracts_attribute_summary_and_data_runs() {
        let parser = StructuredArtifactParser;
        let mut record = vec![0u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        record[0x10..0x12].copy_from_slice(&7u16.to_le_bytes());
        record[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
        record[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
        record[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());
        record[0x18..0x1c].copy_from_slice(&0x204u32.to_le_bytes());
        record[0x1c..0x20].copy_from_slice(&1024u32.to_le_bytes());
        record[0x28..0x2a].copy_from_slice(&4u16.to_le_bytes());

        let si_offset = 0x38usize;
        record[si_offset..si_offset + 4].copy_from_slice(&0x10u32.to_le_bytes());
        record[si_offset + 4..si_offset + 8].copy_from_slice(&0x48u32.to_le_bytes());
        record[si_offset + 8] = 0;
        record[si_offset + 14..si_offset + 16].copy_from_slice(&1u16.to_le_bytes());
        record[si_offset + 16..si_offset + 20].copy_from_slice(&0x30u32.to_le_bytes());
        record[si_offset + 20..si_offset + 22].copy_from_slice(&0x18u16.to_le_bytes());
        let si_value = si_offset + 0x18;
        for timestamp_offset in [0usize, 8, 16, 24] {
            record[si_value + timestamp_offset..si_value + timestamp_offset + 8]
                .copy_from_slice(&test_filetime_bytes(2026, 1, 1, 0, 0, 0));
        }
        record[si_value + 32..si_value + 36].copy_from_slice(&0x20u32.to_le_bytes());

        let fn_offset = 0x80usize;
        let name = utf16le_bytes("evil.exe");
        let fn_value_len = 66 + name.len();
        record[fn_offset..fn_offset + 4].copy_from_slice(&0x30u32.to_le_bytes());
        record[fn_offset + 4..fn_offset + 8].copy_from_slice(&0x70u32.to_le_bytes());
        record[fn_offset + 8] = 0;
        record[fn_offset + 14..fn_offset + 16].copy_from_slice(&2u16.to_le_bytes());
        record[fn_offset + 16..fn_offset + 20]
            .copy_from_slice(&(fn_value_len as u32).to_le_bytes());
        record[fn_offset + 20..fn_offset + 22].copy_from_slice(&0x18u16.to_le_bytes());
        let fn_value = fn_offset + 0x18;
        record[fn_value..fn_value + 8].copy_from_slice(&5u64.to_le_bytes());
        record[fn_value + 8..fn_value + 16]
            .copy_from_slice(&test_filetime_bytes(2026, 1, 1, 0, 0, 0));
        record[fn_value + 16..fn_value + 24]
            .copy_from_slice(&test_filetime_bytes(2026, 1, 1, 0, 0, 1));
        record[fn_value + 24..fn_value + 32]
            .copy_from_slice(&test_filetime_bytes(2026, 1, 1, 0, 0, 0));
        record[fn_value + 32..fn_value + 40]
            .copy_from_slice(&test_filetime_bytes(2026, 1, 1, 0, 0, 0));
        record[fn_value + 40..fn_value + 48].copy_from_slice(&4096u64.to_le_bytes());
        record[fn_value + 48..fn_value + 56].copy_from_slice(&0u64.to_le_bytes());
        record[fn_value + 56..fn_value + 60].copy_from_slice(&0x20u32.to_le_bytes());
        record[fn_value + 64] = 8;
        record[fn_value + 65] = 1;
        record[fn_value + 66..fn_value + 66 + name.len()].copy_from_slice(&name);

        let data_offset = 0xf0usize;
        record[data_offset..data_offset + 4].copy_from_slice(&0x80u32.to_le_bytes());
        record[data_offset + 4..data_offset + 8].copy_from_slice(&0x50u32.to_le_bytes());
        record[data_offset + 8] = 1;
        record[data_offset + 14..data_offset + 16].copy_from_slice(&3u16.to_le_bytes());
        record[data_offset + 16..data_offset + 24].copy_from_slice(&0u64.to_le_bytes());
        record[data_offset + 24..data_offset + 32].copy_from_slice(&3u64.to_le_bytes());
        record[data_offset + 32..data_offset + 34].copy_from_slice(&0x40u16.to_le_bytes());
        record[data_offset + 40..data_offset + 48].copy_from_slice(&16384u64.to_le_bytes());
        record[data_offset + 48..data_offset + 56].copy_from_slice(&2048u64.to_le_bytes());
        record[data_offset + 56..data_offset + 64].copy_from_slice(&2048u64.to_le_bytes());
        record[data_offset + 0x40] = 0x11;
        record[data_offset + 0x41] = 0x04;
        record[data_offset + 0x42] = 0x20;
        record[data_offset + 0x43] = 0x00;

        let ads_offset = 0x140usize;
        let ads_name_text = "Zone.Identifier";
        let ads_name = utf16le_bytes(ads_name_text);
        let ads_content = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://example.test/invoice.zip\r\nReferrerUrl=http://example.test/\r\n";
        record[ads_offset..ads_offset + 4].copy_from_slice(&0x80u32.to_le_bytes());
        record[ads_offset + 4..ads_offset + 8].copy_from_slice(&0xc0u32.to_le_bytes());
        record[ads_offset + 8] = 0;
        record[ads_offset + 9] = ads_name_text.encode_utf16().count() as u8;
        record[ads_offset + 10..ads_offset + 12].copy_from_slice(&0x18u16.to_le_bytes());
        record[ads_offset + 14..ads_offset + 16].copy_from_slice(&4u16.to_le_bytes());
        record[ads_offset + 16..ads_offset + 20]
            .copy_from_slice(&(ads_content.len() as u32).to_le_bytes());
        record[ads_offset + 20..ads_offset + 22].copy_from_slice(&0x38u16.to_le_bytes());
        record[ads_offset + 0x18..ads_offset + 0x18 + ads_name.len()].copy_from_slice(&ads_name);
        record[ads_offset + 0x38..ads_offset + 0x38 + ads_content.len()]
            .copy_from_slice(ads_content);

        let end_offset = 0x200usize;
        record[end_offset..end_offset + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());

        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_mft".into(),
            object_ref: "raw://sha256/mft".into(),
            original_path: "C/$MFT".into(),
            artifact_type: "mft".into(),
            parse_run_id: "parse_1".into(),
            bytes: record,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        let event = parsed
            .events
            .iter()
            .find(|event| event.event_action == "mft_modified")
            .expect("mft modified event");
        let attrs = serde_json::from_str::<Value>(&event.attributes_json).unwrap();
        assert_eq!(attrs["record_number"], 0);
        assert_eq!(attrs["sequence_number"], 7);
        assert_eq!(attrs["attribute_count"], 4);
        assert_eq!(attrs["data_run_count"], 1);
        assert_eq!(attrs["non_resident_attribute_count"], 1);
        assert_eq!(attrs["first_data_run_lcn"], 32);
        assert_eq!(attrs["first_data_run_cluster_count"], 4);
        assert_eq!(attrs["structure_available"], true);
        assert_eq!(attrs["structure_inline"], false);
        assert_eq!(attrs["si_fn_timestamp_mismatch"], true);
        assert!(attrs["attribute_types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("DATA")));
        // $FILE_NAME size is 0 here (stale, as Windows leaves it for small dropped files like a
        // failed webshell); the real file size must be taken from the non-resident $DATA real size.
        assert_eq!(attrs["file_size"], 2048);
        assert!(attrs.get("attributes").is_none());
        assert!(attrs.get("data_runs").is_none());

        let structure_event = parsed
            .events
            .iter()
            .find(|event| event.event_action == "mft_record_changed")
            .expect("mft record changed event");
        let structure_attrs =
            serde_json::from_str::<Value>(&structure_event.attributes_json).unwrap();
        assert_eq!(structure_attrs["first_data_run_lcn"], 32);
        assert_eq!(structure_attrs["first_data_run_cluster_count"], 4);
        assert!(structure_attrs.get("data_runs").is_none());
        let structure_raw = parsed
            .raw_records
            .iter()
            .find(|raw| raw.raw_record_ref == structure_event.raw_record_ref)
            .expect("mft record changed raw");
        let raw = serde_json::from_str::<Value>(&structure_raw.raw_record_json).unwrap();
        assert_eq!(raw["structure_available"], true);
        assert_eq!(raw["structure_inline"], false);

        let ads_event = parsed
            .events
            .iter()
            .find(|event| event.event_action == "mft_ads_resident_content_observed")
            .expect("mft ads resident event");
        assert_eq!(
            ads_event.file_path.as_deref(),
            Some("evil.exe:Zone.Identifier")
        );
        assert_eq!(
            ads_event.url.as_deref(),
            Some("http://example.test/invoice.zip")
        );
        assert_eq!(ads_event.severity, "medium");
        let ads_attrs = serde_json::from_str::<Value>(&ads_event.attributes_json).unwrap();
        assert_eq!(ads_attrs["stream_name"].as_str(), Some("Zone.Identifier"));
        assert_eq!(ads_attrs["ZoneId"].as_str(), Some("3"));
        assert_eq!(
            ads_attrs["HostUrl"].as_str(),
            Some("http://example.test/invoice.zip")
        );
        assert!(ads_attrs["resident_sha256"]
            .as_str()
            .is_some_and(|value| value.len() == 64));
    }

    #[test]
    fn structured_parser_reads_prefetch_csv_export() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/prefetch".into(),
            original_path: "PECmd_Output.csv".into(),
            artifact_type: "csv".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"SourceFilename,ExecutableName,RunCount,LastRun,SHA1,FilesLoaded\nC:\\\\Windows\\\\Prefetch\\\\EVIL.EXE-1234ABCD.pf,evil.exe,3,2026-01-01 00:00:00,abc123,C:\\\\Windows\\\\System32\\\\cmd.exe;C:\\\\Users\\\\alice\\\\AppData\\\\Local\\\\Temp\\\\evil.ps1\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed.events.len() >= 3);
        assert_eq!(parsed.events[0].artifact_type, "prefetch");
        assert_eq!(parsed.events[0].event_action, "process_executed");
        assert_eq!(parsed.events[0].process_name.as_deref(), Some("evil.exe"));
        assert_eq!(parsed.events[0].file_path.as_deref(), Some("evil.exe"));
        assert_eq!(parsed.events[0].hash.as_deref(), Some("abc123"));
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "prefetch_referenced_executable"
                && event
                    .file_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("evil.ps1"))
                && event.severity == "medium"
        }));
    }

    #[test]
    fn structured_parser_reads_prefetch_core_scca_v30() {
        let parser = StructuredArtifactParser;
        let mut pf_bytes = vec![0u8; 0x420];
        pf_bytes[0..4].copy_from_slice(&30u32.to_le_bytes());
        pf_bytes[4..8].copy_from_slice(b"SCCA");
        write_utf16le_at(&mut pf_bytes, 0x10, "POWERSHELL.EXE");
        let file_info = 84usize;
        let file_metrics_offset = 0x130usize;
        let trace_chains_offset = 0x170usize;
        let filenames_offset = 0x1a0usize;
        let loaded_exe =
            "\\DEVICE\\HARDDISKVOLUME4\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE";
        let loaded_script =
            "\\DEVICE\\HARDDISKVOLUME4\\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP\\EVIL.PS1";
        let first_filename_bytes = utf16le_bytes(&format!("{loaded_exe}\0")).len();
        let filenames = utf16le_bytes(&format!("{loaded_exe}\0{loaded_script}\0"));
        pf_bytes[file_info..file_info + 4]
            .copy_from_slice(&(file_metrics_offset as u32).to_le_bytes());
        pf_bytes[file_info + 4..file_info + 8].copy_from_slice(&2u32.to_le_bytes());
        pf_bytes[file_info + 8..file_info + 12]
            .copy_from_slice(&(trace_chains_offset as u32).to_le_bytes());
        pf_bytes[file_info + 12..file_info + 16].copy_from_slice(&2u32.to_le_bytes());
        pf_bytes[file_info + 16..file_info + 20]
            .copy_from_slice(&(filenames_offset as u32).to_le_bytes());
        pf_bytes[file_info + 20..file_info + 24]
            .copy_from_slice(&(filenames.len() as u32).to_le_bytes());
        pf_bytes[file_info + 24..file_info + 28].copy_from_slice(&0u32.to_le_bytes());
        pf_bytes[file_info + 28..file_info + 32].copy_from_slice(&0u32.to_le_bytes());
        pf_bytes[file_info + 44..file_info + 52]
            .copy_from_slice(&test_filetime_bytes(2026, 1, 1, 0, 0, 0));
        pf_bytes[file_info + 52..file_info + 60]
            .copy_from_slice(&test_filetime_bytes(2025, 12, 31, 23, 0, 0));
        pf_bytes[file_info + 124..file_info + 128].copy_from_slice(&7u32.to_le_bytes());
        pf_bytes[file_metrics_offset..file_metrics_offset + 4]
            .copy_from_slice(&10u32.to_le_bytes());
        pf_bytes[file_metrics_offset + 4..file_metrics_offset + 8]
            .copy_from_slice(&25u32.to_le_bytes());
        pf_bytes[file_metrics_offset + 8..file_metrics_offset + 12]
            .copy_from_slice(&18u32.to_le_bytes());
        pf_bytes[file_metrics_offset + 12..file_metrics_offset + 16]
            .copy_from_slice(&0u32.to_le_bytes());
        pf_bytes[file_metrics_offset + 16..file_metrics_offset + 20]
            .copy_from_slice(&(loaded_exe.chars().count() as u32).to_le_bytes());
        pf_bytes[file_metrics_offset + 20..file_metrics_offset + 24]
            .copy_from_slice(&3u32.to_le_bytes());
        pf_bytes[file_metrics_offset + 24..file_metrics_offset + 32]
            .copy_from_slice(&0x0001_0000_0000_002au64.to_le_bytes());
        let second_metric = file_metrics_offset + 32;
        pf_bytes[second_metric..second_metric + 4].copy_from_slice(&40u32.to_le_bytes());
        pf_bytes[second_metric + 4..second_metric + 8].copy_from_slice(&55u32.to_le_bytes());
        pf_bytes[second_metric + 8..second_metric + 12].copy_from_slice(&48u32.to_le_bytes());
        pf_bytes[second_metric + 12..second_metric + 16]
            .copy_from_slice(&(first_filename_bytes as u32).to_le_bytes());
        pf_bytes[second_metric + 16..second_metric + 20]
            .copy_from_slice(&(loaded_script.chars().count() as u32).to_le_bytes());
        pf_bytes[second_metric + 20..second_metric + 24].copy_from_slice(&2u32.to_le_bytes());
        pf_bytes[second_metric + 24..second_metric + 32]
            .copy_from_slice(&0x0002_0000_0000_003bu64.to_le_bytes());
        pf_bytes[trace_chains_offset..trace_chains_offset + 4].copy_from_slice(&4u32.to_le_bytes());
        pf_bytes[trace_chains_offset + 4] = 0x02;
        pf_bytes[trace_chains_offset + 5] = 0x01;
        pf_bytes[trace_chains_offset + 6..trace_chains_offset + 8]
            .copy_from_slice(&0xffffu16.to_le_bytes());
        let second_trace = trace_chains_offset + 8;
        pf_bytes[second_trace..second_trace + 4].copy_from_slice(&7u32.to_le_bytes());
        pf_bytes[second_trace + 4] = 0x04;
        pf_bytes[second_trace + 5] = 0x01;
        pf_bytes[second_trace + 6..second_trace + 8].copy_from_slice(&1u16.to_le_bytes());
        pf_bytes[filenames_offset..filenames_offset + filenames.len()].copy_from_slice(&filenames);

        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_prefetch".into(),
            object_ref: "raw://sha256/prefetch".into(),
            original_path: "C/Windows/Prefetch/POWERSHELL.EXE-022A1004.pf".into(),
            artifact_type: "prefetch".into(),
            parse_run_id: "parse_1".into(),
            bytes: pf_bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        let first = parsed
            .events
            .iter()
            .find(|event| event.time_kind == "prefetch_last_run")
            .unwrap_or_else(|| {
                panic!(
                    "last run event; got {:?}",
                    parsed
                        .events
                        .iter()
                        .map(|event| (
                            event.artifact_type.as_str(),
                            event.time_kind.as_str(),
                            event.event_action.as_str(),
                            event.event_time_utc.as_str(),
                            event.process_name.as_deref(),
                            event.file_path.as_deref(),
                        ))
                        .collect::<Vec<_>>()
                )
            });
        assert_eq!(first.artifact_type, "prefetch");
        assert_eq!(first.process_name.as_deref(), Some("POWERSHELL.EXE"));
        assert_eq!(first.event_time_utc, "2026-01-01T00:00:00+00:00");
        let attrs = serde_json::from_str::<Value>(&first.attributes_json).unwrap();
        assert_eq!(attrs["parser_mode"], "prefetch_core_v1");
        assert_eq!(attrs["container"], "scca_raw");
        assert_eq!(attrs["run_count"], 7);
        assert_eq!(attrs["loaded_file_count"], 2);
        assert_eq!(attrs["file_metric_count"], 2);
        assert_eq!(attrs["trace_chain_count"], 2);
        assert_eq!(attrs["file_metrics"][0]["offset"], file_metrics_offset);
        assert_eq!(attrs["file_metrics"][0]["filename"], loaded_exe);
        assert_eq!(attrs["file_metrics"][1]["filename"], loaded_script);
        assert_eq!(attrs["trace_chains"][0]["offset"], trace_chains_offset);
        assert_eq!(attrs["trace_chains"][0]["block_load_count"], 4);
        assert!(parsed.events.iter().any(|event| {
            event.time_kind == "prefetch_previous_run"
                && event.event_time_utc == "2025-12-31T23:00:00+00:00"
        }));
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "prefetch_referenced_executable"
                && event.file_path.as_deref().is_some_and(|path| {
                    path.ends_with("\\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP\\EVIL.PS1")
                })
                && event.severity == "medium"
        }));
    }

    #[test]
    fn structured_parser_reads_real_mam_prefetch_fixture_when_configured() {
        let Some(path) = std::env::var_os("TAOTIE4_RAW_PREFETCH_FIXTURE") else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"MAM\x04"));
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_prefetch".into(),
            object_ref: "raw://sha256/prefetch".into(),
            original_path: path.display().to_string(),
            artifact_type: "prefetch".into(),
            parse_run_id: "parse_1".into(),
            bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed
            .events
            .iter()
            .any(|event| event.time_kind == "prefetch_last_run"));
        let attrs = parsed
            .events
            .iter()
            .find(|event| event.time_kind == "prefetch_last_run")
            .map(|event| serde_json::from_str::<Value>(&event.attributes_json).unwrap())
            .expect("last run attrs");
        assert_eq!(attrs["parser_mode"], "prefetch_core_v1");
        assert_eq!(attrs["container"], "mam_xpress_huffman");
        assert!(attrs["loaded_file_count"].as_u64().unwrap_or(0) > 0);
    }

    #[test]
    fn structured_parser_reads_amcache_csv_export() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/amcache".into(),
            original_path: "Amcache_Output.csv".into(),
            artifact_type: "csv".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"ProgramName,Path,SHA1,LastWriteTimestamp\nEvil,C:\\\\Temp\\\\evil.exe,beef,2026-01-01 00:00:00\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].artifact_type, "amcache");
        assert_eq!(parsed.events[0].event_action, "amcache_program_seen");
        assert_eq!(
            parsed.events[0].file_path.as_deref(),
            Some("C:\\\\Temp\\\\evil.exe")
        );
        assert_eq!(parsed.events[0].hash.as_deref(), Some("beef"));
    }

    #[test]
    fn structured_parser_reads_usn_csv_export() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/usn".into(),
            original_path: "UsnJrnl_Output.csv".into(),
            artifact_type: "csv".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"Timestamp,FileName,FileReferenceNumber,Reason\n2026-01-01 00:03:00,C:\\\\Temp\\\\evil.exe,42,File_Delete\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].artifact_type, "usn_jrnl");
        assert_eq!(parsed.events[0].event_action, "usn_deleted");
        assert_eq!(parsed.events[0].severity, "medium");
        assert_eq!(
            parsed.events[0].file_path.as_deref(),
            Some("C:\\\\Temp\\\\evil.exe")
        );
    }

    #[test]
    fn structured_parser_reads_browser_json_export() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/browser".into(),
            original_path: "browser_history.json".into(),
            artifact_type: "json".into(),
            parse_run_id: "parse_1".into(),
            bytes: br#"[{"url":"https://example.test/download/evil.exe","title":"download","last_visit_time":"2026-01-01T00:01:00Z","user":"alice"}]"#.to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].artifact_type, "browser");
        assert_eq!(parsed.events[0].event_action, "browser_visit");
        assert_eq!(
            parsed.events[0].url.as_deref(),
            Some("https://example.test/download/evil.exe")
        );
        assert_eq!(parsed.events[0].file_path.as_deref(), Some("evil.exe"));
        assert_eq!(parsed.events[0].user_name.as_deref(), Some("alice"));
    }

    #[test]
    fn structured_parser_extracts_browser_profile_json_signals() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/browser-pref".into(),
            original_path:
                "C/Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/Preferences".into(),
            artifact_type: "browser".into(),
            parse_run_id: "parse_1".into(),
            bytes: br#"{
              "download": {"default_directory": "C:\\Users\\alice\\Downloads"},
              "safebrowsing": {"enabled": false},
              "extensions": {"settings": {"abcd": {"path": "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Extensions\\abcd"}}},
              "homepage": "https://example.test/start"
            }"#
            .to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "browser_download_setting_observed"));
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "browser_security_setting_weak"));
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "browser_extension_observed"));
        assert!(parsed
            .events
            .iter()
            .any(|event| event.url.as_deref() == Some("https://example.test/start")));
    }

    #[test]
    fn structured_parser_reads_defender_operational_xml() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/defender".into(),
            original_path: "MPOperationalEvents.txt".into(),
            artifact_type: "defender_operational".into(),
            parse_run_id: "parse_1".into(),
            bytes: br#"<Events><Event><System><Provider Name="Microsoft-Windows-Windows Defender"/><EventID>1116</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Computer>HOST1</Computer><Channel>Microsoft-Windows-Windows Defender/Operational</Channel></System><EventData><Data Name="Threat Name">Trojan:Win32/Demo</Data><Data Name="Path">C:\Temp\evil.exe</Data></EventData></Event></Events>"#.to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].artifact_type, "defender");
        assert_eq!(parsed.events[0].event_action, "defender_threat_detected");
        assert_eq!(parsed.events[0].severity, "high");
        assert_eq!(
            parsed.events[0].file_path.as_deref(),
            Some("C:\\Temp\\evil.exe")
        );
    }

    #[test]
    fn structured_parser_reads_defender_mplog() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/mplog".into(),
            original_path: "MpLog-20260624.log".into(),
            artifact_type: "defender_mplog".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"2026-01-01 00:00:00 Threat Name: Trojan:Win32/Demo Path: C:\\Temp\\evil.exe detected by Microsoft Defender Antivirus\n2026-01-01 00:01:00 Scan completed\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert_eq!(parsed.events[0].artifact_type, "defender");
        assert_eq!(parsed.events[0].event_action, "defender_threat_detected");
        assert_eq!(parsed.events[1].event_action, "defender_scan");
    }

    #[test]
    fn structured_parser_reads_defender_flat_details() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_defender_csv".into(),
            object_ref: "raw://sha256/defender-csv".into(),
            original_path: "timeline_wd.csv".into(),
            artifact_type: "defender_operational".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details,ExtraFieldInfo\n2023-03-27 14:42:34,Antivirus Hacktool Detection,high,HOST1,Defender,1116,440,\"Threat: HackTool:PowerShell/SharpHound.B \xC2\xA6 Severity: High \xC2\xA6 User: HOST1\\analyst \xC2\xA6 Path: containerfile:_C:\\Users\\analyst\\Downloads\\SharpHound-v1.1.0.zip; file:_C:\\Users\\analyst\\Downloads\\SharpHound-v1.1.0.zip->SharpHound.ps1 \xC2\xA6 Proc: Unknown\",Action Name: Not Applicable\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 1);
        let event = &parsed.events[0];
        assert_eq!(event.artifact_type, "defender");
        assert_eq!(event.event_action, "defender_threat_detected");
        assert_eq!(event.severity, "high");
        assert!(event.message_full.contains("SharpHound"));
        assert!(event
            .file_path
            .as_deref()
            .is_some_and(|path| path.contains("SharpHound-v1.1.0.zip")));
        let attrs = serde_json::from_str::<Value>(&event.attributes_json).unwrap();
        assert_eq!(
            attrs["defender_threat"].as_str(),
            Some("HackTool:PowerShell/SharpHound.B")
        );
    }

    #[test]
    fn structured_parser_reads_utf16_defender_mplog_lines() {
        let parser = StructuredArtifactParser;
        let text = "2026-01-01 00:00:00 Threat Name: Trojan:Win32/Demo Path: C:\\Temp\\evil.exe detected by Microsoft Defender Antivirus\r\n2026-01-01 00:01:00 Scan completed\r\n";
        let mut bytes = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_1".into(),
            object_ref: "raw://sha256/mplog-utf16".into(),
            original_path: "C/ProgramData/Microsoft/Windows Defender/Support/MPLog.log".into(),
            artifact_type: "defender_mplog".into(),
            parse_run_id: "parse_1".into(),
            bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert_eq!(parsed.events[0].event_action, "defender_threat_detected");
        assert_eq!(parsed.events[1].event_action, "defender_scan");
    }

    #[test]
    fn structured_parser_reads_windows_search_gather_log() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_gthr".into(),
            object_ref: "raw://sha256/gthr".into(),
            original_path: "C/ProgramData/Microsoft/search/data/applications/windows/GatherLogs/SystemIndex/SystemIndex.14.gthr".into(),
            artifact_type: "windows_search_log".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"c926baa1\t1d9a28c\tfile:C:/Users/alice/Downloads/evil.exe\t80000003\r\n4214aaa7\t1d9a28d\thttps://example.test/payload\t4000000f\r\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 2);
        assert!(parsed.events.iter().any(|event| {
            event.artifact_type == "windows_search_log"
                && event.event_action == "windows_search_indexed_executable"
                && event.user_name.as_deref() == Some("alice")
                && event.process_name.as_deref() == Some("evil.exe")
        }));
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "windows_search_indexed_url"
                && event.url.as_deref() == Some("https://example.test/payload")
        }));
    }

    #[test]
    fn structured_parser_reads_scheduled_task_xml() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_task".into(),
            object_ref: "raw://sha256/task".into(),
            original_path: "C/Windows/System32/Tasks/DemoTask".into(),
            artifact_type: "scheduled_task".into(),
            parse_run_id: "parse_1".into(),
            bytes: br#"<Task version="1.4"><RegistrationInfo><URI>\DemoTask</URI><Author>HOST\alice</Author></RegistrationInfo><Triggers><TimeTrigger><StartBoundary>2026-01-01T00:02:00</StartBoundary></TimeTrigger></Triggers><Principals><Principal id="Author"><UserId>alice</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings><Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoP -EncodedCommand AAA</Arguments><WorkingDirectory>C:\Temp</WorkingDirectory></Exec></Actions></Task>"#.to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 3);
        assert_eq!(parsed.events[0].artifact_type, "scheduled_task");
        assert_eq!(
            parsed.events[0].event_action,
            "scheduled_task_suspicious_exec"
        );
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "scheduled_task_exec_action"));
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "scheduled_task_trigger_observed"));
        assert_eq!(
            parsed.events[0].process_name.as_deref(),
            Some("powershell.exe")
        );
        assert_eq!(parsed.events[0].user_name.as_deref(), Some("alice"));
        assert_eq!(parsed.events[0].severity, "high");
    }

    #[test]
    fn structured_parser_extracts_registry_hive_signals() {
        let parser = StructuredArtifactParser;
        let mut bytes = b"regf\0\0demo".to_vec();
        bytes.extend(utf16le_bytes(
            r"Software\Microsoft\Windows\CurrentVersion\Run Evil C:\Users\alice\AppData\Roaming\evil.exe",
        ));
        bytes.extend(utf16le_bytes(
            r"System\CurrentControlSet\Services\EvilSvc ImagePath C:\Temp\evilsvc.exe",
        ));
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_reg".into(),
            object_ref: "raw://sha256/reg".into(),
            original_path: "C/Users/alice/NTUSER.DAT".into(),
            artifact_type: "registry_hive".into(),
            parse_run_id: "parse_1".into(),
            bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "registry_run_key_persistence"));
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "registry_service_image"
                && event.process_name.as_deref() == Some("evilsvc.exe")
        }));
    }

    #[test]
    fn structured_parser_treats_raw_amcache_as_amcache_signals() {
        let parser = StructuredArtifactParser;
        let mut bytes = b"regf\0\0demo".to_vec();
        bytes.extend(utf16le_bytes(
            r"Root\InventoryApplicationFile\evil.exe ProgramId SHA1 abcdefabcdefabcdefabcdefabcdefabcdefabcd C:\Temp\evil.exe",
        ));
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_amcache".into(),
            object_ref: "raw://sha256/amcachehve".into(),
            original_path: "C/Windows/AppCompat/Programs/Amcache.hve".into(),
            artifact_type: "amcache".into(),
            parse_run_id: "parse_1".into(),
            bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed.events.iter().any(|event| {
            event.artifact_type == "amcache"
                && event.event_action == "amcache_program_seen"
                && event.file_path.as_deref() == Some("C:\\Temp\\evil.exe")
        }));
    }

    #[test]
    fn structured_parser_metadata_parses_raw_evtx_and_mft() {
        let parser = StructuredArtifactParser;
        let evtx = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_evtx".into(),
            object_ref: "raw://sha256/evtx".into(),
            original_path: "C/Windows/System32/winevt/logs/Security.evtx".into(),
            artifact_type: "evtx".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"ElfFile\0\0demo".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(evtx).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events[0].artifact_type, "evtx");
        assert_eq!(parsed.events[0].event_action, "evtx_file_observed");

        let mft = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_mft".into(),
            object_ref: "raw://sha256/mft".into(),
            original_path: "C/$MFT".into(),
            artifact_type: "mft".into(),
            parse_run_id: "parse_2".into(),
            bytes: b"FILE0demo".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(mft).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events[0].artifact_type, "mft");
        assert_eq!(parsed.events[0].event_action, "mft_file_observed");
    }

    #[test]
    fn structured_parser_reads_raw_prefetch_and_lnk_metadata() {
        let parser = StructuredArtifactParser;
        let mut pf_bytes = vec![0u8; 0x240];
        pf_bytes[0..4].copy_from_slice(b"SCCA");
        pf_bytes[4..8].copy_from_slice(&30u32.to_le_bytes());
        pf_bytes[0x0c..0x10].copy_from_slice(&(0x240u32).to_le_bytes());
        let header_name = utf16le_bytes("POWERSHELL.EXE");
        pf_bytes[0x10..0x10 + header_name.len()].copy_from_slice(&header_name);
        pf_bytes[0x54..0x58].copy_from_slice(&0xe0u32.to_le_bytes());
        pf_bytes[0x58..0x5c].copy_from_slice(&1u32.to_le_bytes());
        pf_bytes[0x5c..0x60].copy_from_slice(&0x100u32.to_le_bytes());
        pf_bytes[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
        pf_bytes[0x64..0x68].copy_from_slice(&0x120u32.to_le_bytes());
        pf_bytes[0x68..0x6c].copy_from_slice(&0x70u32.to_le_bytes());
        pf_bytes[0x6c..0x70].copy_from_slice(&0x1a0u32.to_le_bytes());
        pf_bytes[0x70..0x74].copy_from_slice(&1u32.to_le_bytes());
        pf_bytes[0x78..0x80].copy_from_slice(&test_filetime_bytes(2026, 1, 1, 0, 0, 0));
        pf_bytes[0xd0..0xd4].copy_from_slice(&3u32.to_le_bytes());
        let filenames =
            b"powershell.exe\0C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0";
        pf_bytes[0x120..0x120 + filenames.len()].copy_from_slice(filenames);
        let volume = utf16le_bytes("\\Device\\HarddiskVolume4");
        pf_bytes[0x1a0..0x1a0 + volume.len()].copy_from_slice(&volume);
        let prefetch = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_pf".into(),
            object_ref: "raw://sha256/pf".into(),
            original_path: "C/Windows/prefetch/POWERSHELL.EXE-022A1004.pf".into(),
            artifact_type: "prefetch".into(),
            parse_run_id: "parse_1".into(),
            bytes: pf_bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(prefetch).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events[0].artifact_type, "prefetch");
        assert_eq!(parsed.events[0].time_kind, "prefetch_last_run");
        assert_eq!(
            parsed.events[0].process_name.as_deref(),
            Some("powershell.exe")
        );
        let attrs = serde_json::from_str::<Value>(&parsed.events[0].attributes_json).unwrap();
        assert_eq!(attrs.get("run_count").and_then(Value::as_u64), Some(3));
        assert_eq!(
            attrs.get("prefetch_version_family").and_then(Value::as_str),
            Some("windows_10_11_v30")
        );
        assert_eq!(
            attrs.get("run_count_offset").and_then(Value::as_u64),
            Some(0xd0)
        );
        assert_eq!(attrs["run_time_entries"][0]["offset"].as_u64(), Some(0x78));
        assert_eq!(
            attrs.get("prefetch_hash").and_then(Value::as_str),
            Some("022a1004")
        );
        assert_eq!(
            attrs.get("suspicion").and_then(Value::as_str),
            Some("lolbin_or_script_interpreter_execution")
        );
        assert_eq!(attrs.get("section_count").and_then(Value::as_u64), Some(4));
        assert!(attrs["sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| section["name"].as_str() == Some("filename_strings")));
        assert_eq!(
            attrs["volume_strings"][0].as_str(),
            Some("\\Device\\HarddiskVolume4")
        );
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "prefetch_referenced_executable"
                && event.time_kind == "prefetch_reference_observed"
                && event.file_path.as_deref()
                    == Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        }));

        let lnk = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_lnk".into(),
            object_ref: "raw://sha256/lnk".into(),
            original_path: "C/Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/EVIL.lnk"
                .into(),
            artifact_type: "lnk".into(),
            parse_run_id: "parse_2".into(),
            bytes: b"L\0\0\0C:\\Temp\\evil.exe\0".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(lnk).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events[0].artifact_type, "lnk");
        assert_eq!(parsed.events[0].user_name.as_deref(), Some("jdoe"));
        assert_eq!(parsed.events[0].process_name.as_deref(), Some("evil.exe"));
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "lnk_target_reference"
                && event.file_path.as_deref() == Some("C:\\Temp\\evil.exe")
        }));

        let mut lnk_bytes = vec![0u8; 0x4c];
        lnk_bytes[0..4].copy_from_slice(&0x4cu32.to_le_bytes());
        lnk_bytes[0x14..0x18].copy_from_slice(&0x2u32.to_le_bytes());
        lnk_bytes[0x1c..0x24].copy_from_slice(&test_filetime_bytes(2026, 2, 1, 1, 2, 3));
        lnk_bytes[0x24..0x2c].copy_from_slice(&test_filetime_bytes(2026, 2, 2, 1, 2, 3));
        lnk_bytes[0x2c..0x34].copy_from_slice(&test_filetime_bytes(2026, 2, 3, 1, 2, 3));
        lnk_bytes[0x34..0x38].copy_from_slice(&12_345u32.to_le_bytes());
        let volume_label = b"OS\0";
        let network_share = b"\\\\FILESRV\\drop\0";
        let network_device = b"Z:\0";
        let local_base = b"C:\\Temp\\evil.exe\0";
        let suffix = b"\0";
        let volume_offset = 0x1cusize;
        let volume_size = 0x10 + volume_label.len();
        let network_offset = volume_offset + volume_size;
        let network_size = 0x14 + network_share.len() + network_device.len();
        let local_offset = network_offset + network_size;
        let suffix_offset = local_offset + local_base.len();
        let link_info_size = suffix_offset + suffix.len();
        let mut link_info = vec![0u8; link_info_size];
        link_info[0..4].copy_from_slice(&(link_info_size as u32).to_le_bytes());
        link_info[4..8].copy_from_slice(&0x1cu32.to_le_bytes());
        link_info[8..12].copy_from_slice(&0x3u32.to_le_bytes());
        link_info[0x0c..0x10].copy_from_slice(&(volume_offset as u32).to_le_bytes());
        link_info[0x10..0x14].copy_from_slice(&(local_offset as u32).to_le_bytes());
        link_info[0x14..0x18].copy_from_slice(&(network_offset as u32).to_le_bytes());
        link_info[0x18..0x1c].copy_from_slice(&(suffix_offset as u32).to_le_bytes());
        link_info[volume_offset..volume_offset + 4]
            .copy_from_slice(&(volume_size as u32).to_le_bytes());
        link_info[volume_offset + 4..volume_offset + 8].copy_from_slice(&3u32.to_le_bytes());
        link_info[volume_offset + 8..volume_offset + 12]
            .copy_from_slice(&0x1234abcdu32.to_le_bytes());
        link_info[volume_offset + 12..volume_offset + 16].copy_from_slice(&0x10u32.to_le_bytes());
        link_info[volume_offset + 16..volume_offset + 16 + volume_label.len()]
            .copy_from_slice(volume_label);
        link_info[network_offset..network_offset + 4]
            .copy_from_slice(&(network_size as u32).to_le_bytes());
        link_info[network_offset + 4..network_offset + 8].copy_from_slice(&0x2u32.to_le_bytes());
        link_info[network_offset + 8..network_offset + 12].copy_from_slice(&0x14u32.to_le_bytes());
        link_info[network_offset + 12..network_offset + 16]
            .copy_from_slice(&(0x14u32 + network_share.len() as u32).to_le_bytes());
        link_info[network_offset + 16..network_offset + 20]
            .copy_from_slice(&0x0002_0000u32.to_le_bytes());
        link_info[network_offset + 0x14..network_offset + 0x14 + network_share.len()]
            .copy_from_slice(network_share);
        link_info[network_offset + 0x14 + network_share.len()
            ..network_offset + 0x14 + network_share.len() + network_device.len()]
            .copy_from_slice(network_device);
        link_info[local_offset..local_offset + local_base.len()].copy_from_slice(local_base);
        link_info[suffix_offset..suffix_offset + suffix.len()].copy_from_slice(suffix);
        lnk_bytes.extend(link_info);
        let mut tracker = vec![0u8; 0x60];
        tracker[0..4].copy_from_slice(&0x60u32.to_le_bytes());
        tracker[4..8].copy_from_slice(&0xa0000003u32.to_le_bytes());
        tracker[8..12].copy_from_slice(&0x58u32.to_le_bytes());
        tracker[12..16].copy_from_slice(&0u32.to_le_bytes());
        let machine = b"WORKSTATION-01";
        tracker[16..16 + machine.len()].copy_from_slice(machine);
        for (idx, byte) in tracker[0x20..0x60].iter_mut().enumerate() {
            *byte = idx as u8;
        }
        lnk_bytes.extend(tracker);
        let mut property_store = vec![0u8; 0x90];
        property_store[0..4].copy_from_slice(&0x90u32.to_le_bytes());
        property_store[4..8].copy_from_slice(&0xa0000009u32.to_le_bytes());
        property_store[8..24].copy_from_slice(&[
            0x9f, 0x4c, 0x28, 0x9f, 0x89, 0x39, 0x4c, 0x8e, 0xbc, 0x0c, 0x15, 0x5f, 0xa9, 0xf4,
            0x94, 0xe4,
        ]);
        let property_name = utf16le_bytes("System.AppUserModel.ID");
        property_store[0x28..0x28 + property_name.len()].copy_from_slice(&property_name);
        let property_value = utf16le_bytes("Taotie.Test.App");
        property_store[0x60..0x60 + property_value.len()].copy_from_slice(&property_value);
        lnk_bytes.extend(property_store);
        let structured_lnk = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_lnk_struct".into(),
            object_ref: "raw://sha256/lnk2".into(),
            original_path: "C/Users/jdoe/Desktop/evil.lnk".into(),
            artifact_type: "lnk".into(),
            parse_run_id: "parse_3".into(),
            bytes: lnk_bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(structured_lnk).unwrap() else {
            panic!("expected parsed outcome");
        };
        let event = &parsed.events[0];
        assert_eq!(event.event_action, "lnk_target_executable_observed");
        assert_eq!(event.process_name.as_deref(), Some("evil.exe"));
        assert_eq!(event.file_path.as_deref(), Some("C:\\Temp\\evil.exe"));
        assert_eq!(event.time_kind, "lnk_file_import_observed");
        assert!(event.event_time_utc.starts_with("2026-02-03T01:02:03"));
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "lnk_network_share_reference"));
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "lnk_tracker_reference"));
        let attrs = serde_json::from_str::<Value>(&event.attributes_json).unwrap();
        assert_eq!(
            attrs.get("drive_serial").and_then(Value::as_str),
            Some("1234abcd")
        );
        assert_eq!(
            attrs.get("volume_label").and_then(Value::as_str),
            Some("OS")
        );
        assert_eq!(
            attrs.get("network_share_path").and_then(Value::as_str),
            Some("\\\\FILESRV\\drop")
        );
        assert_eq!(
            attrs.get("network_device_name").and_then(Value::as_str),
            Some("Z:")
        );
        assert_eq!(
            attrs.get("tracker_machine_id").and_then(Value::as_str),
            Some("WORKSTATION-01")
        );
        assert_eq!(
            attrs
                .get("tracker_droid")
                .and_then(Value::as_str)
                .map(str::len),
            Some(64)
        );
        assert_eq!(
            attrs.get("file_size_hint").and_then(Value::as_u64),
            Some(12_345)
        );
        assert_eq!(
            attrs.get("extra_data_block_count").and_then(Value::as_u64),
            Some(2)
        );
        assert!(attrs["extra_data_blocks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|block| {
                block["signature_name"].as_str() == Some("PropertyStoreDataBlock")
                    && block["guid_candidates"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|guid| guid.as_str() == Some("9f284c9f-3989-8e4c-bc0c-155fa9f494e4"))
                    && block["property_entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|property| {
                            property["key"].as_str() == Some("System.AppUserModel.ID")
                                && property["value_hint"].as_str() == Some("Taotie.Test.App")
                        })
            }));
    }

    #[test]
    fn structured_parser_recovers_jumplist_and_recentdocs_items() {
        let parser = StructuredArtifactParser;
        let mut jump_bytes = vec![0xd0, 0xcf, 0x11, 0xe0, 0x00, 0x00];
        jump_bytes.extend(utf16le_bytes(
            "DestList C:\\Users\\jdoe\\Documents\\report.docx C:\\Temp\\evil.exe",
        ));
        let jump = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_jump".into(),
            object_ref: "raw://sha256/jump".into(),
            original_path: "C/Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms".into(),
            artifact_type: "jump_list".into(),
            parse_run_id: "parse_1".into(),
            bytes: jump_bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(jump).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed.events.iter().any(|event| {
            event.artifact_type == "jump_list"
                && event.event_action == "jumplist_destlist_entry_observed"
                && event
                    .file_path
                    .as_deref()
                    .is_some_and(|path| path.contains("evil.exe") || path.contains("report.docx"))
        }));

        let mut hive_bytes = b"regf".to_vec();
        hive_bytes.extend(utf16le_bytes(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs report.docx",
        ));
        let hive = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_hive".into(),
            object_ref: "raw://sha256/hive".into(),
            original_path: "C/Users/jdoe/NTUSER.DAT".into(),
            artifact_type: "registry_hive".into(),
            parse_run_id: "parse_2".into(),
            bytes: hive_bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(hive).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "registry_recentdocs_document"
                && event.file_path.as_deref() == Some("report.docx")
        }));

        let mut shellbag_bytes = b"regf".to_vec();
        shellbag_bytes.extend(utf16le_bytes(
            "Software\\Microsoft\\Windows\\Shell\\BagMRU ShellBags C:\\Users\\jdoe\\Downloads",
        ));
        let shellbag = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_shellbag".into(),
            object_ref: "raw://sha256/shellbag".into(),
            original_path: "C/Users/jdoe/NTUSER.DAT".into(),
            artifact_type: "registry_hive".into(),
            parse_run_id: "parse_3".into(),
            bytes: shellbag_bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(shellbag).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "registry_shellbag_folder"
                && event
                    .file_path
                    .as_deref()
                    .is_some_and(|path| path.contains("Downloads"))
        }));
    }

    #[test]
    fn structured_parser_extracts_webcache_string_signals() {
        let parser = StructuredArtifactParser;
        let mut bytes = vec![0u8; 8192];
        bytes[0..4].copy_from_slice(b"\xef\xcd\xab\x89");
        bytes[0xec..0xf0].copy_from_slice(&4096u32.to_le_bytes());
        bytes[4096..4100].copy_from_slice(&0x11223344u32.to_le_bytes());
        bytes[4100..4104].copy_from_slice(&1u32.to_le_bytes());
        let signal = utf16le_bytes(
            "Visited https://example.test/download/evil.exe example.test C:\\Users\\alice\\Downloads\\evil.exe",
        );
        bytes[4300..4300 + signal.len()].copy_from_slice(&signal);
        let table_hint = b"Container_1 UrlHistoryTable";
        bytes[4500..4500 + table_hint.len()].copy_from_slice(table_hint);
        bytes[4096 + 22..4096 + 24].copy_from_slice(&1u16.to_le_bytes());
        bytes[8192 - 4..8192 - 2].copy_from_slice(&204u16.to_le_bytes());
        bytes[8192 - 2..8192].copy_from_slice(&(signal.len() as u16).to_le_bytes());
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_webcache".into(),
            object_ref: "raw://sha256/webcache".into(),
            original_path: "C/Users/alice/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"
                .into(),
            artifact_type: "web_cache".into(),
            parse_run_id: "parse_1".into(),
            bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed.events.iter().any(|event| {
            event.artifact_type == "web_cache"
                && event.event_action == "webcache_download_observed"
                && event.url.as_deref() == Some("https://example.test/download/evil.exe")
        }));
        let event = parsed
            .events
            .iter()
            .find(|event| event.event_action == "webcache_download_observed")
            .unwrap();
        let attrs = serde_json::from_str::<Value>(&event.attributes_json).unwrap();
        assert_eq!(
            attrs.get("ese_page_size").and_then(Value::as_u64),
            Some(4096)
        );
        assert_eq!(attrs.get("ese_page_count").and_then(Value::as_u64), Some(2));
        assert_eq!(
            attrs.get("domain").and_then(Value::as_str),
            Some("example.test")
        );
        assert_eq!(attrs["ese_header"]["signature_offset"].as_u64(), Some(0));
        assert_eq!(attrs["ese_pages"][1]["offset"].as_u64(), Some(4096));
        assert_eq!(
            attrs["ese_pages"][1]["tags"][0]["offset"].as_u64(),
            Some(204)
        );
        assert!(attrs["ese_pages"][1]["table_name_hints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("Container_1 UrlHistoryTable")));
    }

    #[test]
    fn structured_parser_recovers_filezilla_server_context() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_filezilla".into(),
            object_ref: "raw://sha256/filezilla".into(),
            original_path: "C/Users/alice/AppData/Roaming/FileZilla/recentservers.xml".into(),
            artifact_type: "filezilla".into(),
            parse_run_id: "parse_1".into(),
            bytes: br#"<FileZilla3><RecentServers><Server><Host>10.0.0.5</Host><Port>21</Port><User>ftpuser</User><Pass encoding="base64">c2VjcmV0</Pass><RemotePath>1 0 4 home 7 ftpuser 8 projects 6 site-a</RemotePath></Server></RecentServers></FileZilla3>"#.to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events.len(), 1);
        let event = &parsed.events[0];
        assert_eq!(event.artifact_type, "filezilla");
        assert_eq!(event.event_action, "filezilla_saved_password_recovered");
        assert_eq!(event.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(event.url.as_deref(), Some("ftp://10.0.0.5:21"));
        let attrs = serde_json::from_str::<Value>(&event.attributes_json).unwrap();
        assert_eq!(
            attrs.get("password_decoded").and_then(Value::as_str),
            Some("secret")
        );
        assert_eq!(
            attrs.get("remote_path_normalized").and_then(Value::as_str),
            Some("/home/ftpuser/projects/site-a")
        );
    }

    #[test]
    fn structured_parser_adds_sidecar_workflow_metadata() {
        let parser = StructuredArtifactParser;
        let samples = [
            (
                "C/Users/alice/Documents/Database.kdbx",
                "credential_store",
                b"KDBX demo".to_vec(),
                "keepass_recovery_workflow",
                "keepassxc-cli",
            ),
            (
                "C/Users/alice/Documents/secret.pdf",
                "document",
                b"%PDF-1.7 demo".to_vec(),
                "tika_oletools_document_recovery",
                "pdftotext",
            ),
            (
                "C/Users/alice/Network/exfil.pcapng",
                "network_capture",
                b"\x0a\x0d\x0d\x0a demo".to_vec(),
                "zeek_tshark_pcap_analysis",
                "tshark",
            ),
        ];

        for (path, artifact_type, bytes, expected_sidecar, expected_tool) in samples {
            let input = ParserInput {
                case_id: "case_1".into(),
                source_file_id: format!("file_{artifact_type}"),
                object_ref: format!("raw://sha256/{artifact_type}"),
                original_path: path.into(),
                artifact_type: artifact_type.into(),
                parse_run_id: "parse_1".into(),
                bytes,
            };
            let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
                panic!("expected parsed outcome");
            };
            let attrs = serde_json::from_str::<Value>(&parsed.events[0].attributes_json).unwrap();
            assert_eq!(
                attrs.get("sidecar_recommended").and_then(Value::as_str),
                Some(expected_sidecar)
            );
            assert_eq!(
                attrs
                    .get("sidecar_execution_policy")
                    .and_then(Value::as_str),
                Some("manual_or_background_job_only")
            );
            assert!(attrs["sidecar_tool_candidates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_str() == Some(expected_tool)));
            assert!(attrs["sidecar_expected_outputs"]
                .as_array()
                .is_some_and(|values| !values.is_empty()));
        }
    }

    #[test]
    fn structured_parser_extracts_network_capture_string_signals() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_pcap".into(),
            object_ref: "raw://sha256/pcap".into(),
            original_path: "packetcapture.pcapng".into(),
            artifact_type: "network_capture".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"\x0a\x0d\x0d\x0aGET /download/tool.exe HTTP/1.1\r\nHost: evil.example.test\r\nUser-Agent: PowerShell/7.4\r\n\r\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "network_http_observed"));
        assert!(parsed
            .events
            .iter()
            .any(|event| event.event_action == "network_domain_observed"
                && event.message_full.contains("evil.example.test")));
        assert!(parsed
            .events
            .iter()
            .any(|event| event.severity == "high"
                && event.event_action == "network_user_agent_observed"));
    }

    #[test]
    fn structured_parser_expands_html_text_document_signals() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_html".into(),
            object_ref: "raw://sha256/html".into(),
            original_path: "C/Users/jdoe/AppData/Local/Microsoft/Edge/Cache/payload.htm".into(),
            artifact_type: "html".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"<html>\nVisited https://download.example.test/payload.exe download.example.test C:\\Users\\jdoe\\Downloads\\payload.exe\nWARN powershell.exe -enc AAA failed\n</html>\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed.events.len() >= 3);
        assert_eq!(parsed.events[0].event_action, "html_file_observed");
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "html_download_signal"
                && event.url.as_deref() == Some("https://download.example.test/payload.exe")
        }));
        assert!(parsed.events.iter().any(|event| {
            event.severity == "high"
                && event
                    .process_name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case("powershell.exe"))
        }));
    }

    #[test]
    fn structured_parser_reads_onedrive_gzip_log() {
        let parser = StructuredArtifactParser;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(b"2023-05-04 10:35:00 SyncEngine downloaded https://example.test/a.txt\n")
            .unwrap();
        let bytes = encoder.finish().unwrap();
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_gz".into(),
            object_ref: "raw://sha256/gz".into(),
            original_path: "C/Users/jdoe/AppData/Local/Microsoft/OneDrive/logs/Personal/SyncEngine-2023-05-04.odlgz".into(),
            artifact_type: "onedrive_log".into(),
            parse_run_id: "parse_1".into(),
            bytes,
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert_eq!(parsed.events[0].artifact_type, "onedrive_log");
        assert_eq!(parsed.events[0].user_name.as_deref(), Some("jdoe"));
    }

    #[test]
    fn structured_parser_expands_onedrive_settings_and_sync_signals() {
        let parser = StructuredArtifactParser;
        let input = ParserInput {
            case_id: "case_1".into(),
            source_file_id: "file_onedrive_settings".into(),
            object_ref: "raw://sha256/onedrive-settings".into(),
            original_path:
                "C/Users/jdoe/AppData/Local/Microsoft/OneDrive/settings/Personal/global.ini"
                    .into(),
            artifact_type: "config".into(),
            parse_run_id: "parse_1".into(),
            bytes: b"UserCid=1234567890abcdef\nBusiness1=https://contoso-my.sharepoint.com/personal/jdoe\nLocalRoot=C:\\Users\\jdoe\\OneDrive\n2023-05-04 10:35:00 Upload C:\\Users\\jdoe\\OneDrive\\loot.zip to https://contoso-my.sharepoint.com/personal/jdoe/Documents/loot.zip\nSync error retry failed\n".to_vec(),
        };
        let ParserOutcome::Parsed(parsed) = parser.parse(input).unwrap() else {
            panic!("expected parsed outcome");
        };
        assert!(parsed.events.len() >= 4);
        assert!(parsed
            .events
            .iter()
            .all(|event| event.artifact_type == "onedrive_log"));
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "onedrive_upload_observed"
                && event.user_name.as_deref() == Some("jdoe")
        }));
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "onedrive_account_observed"
                || event.event_action == "onedrive_url_observed"
        }));
        assert!(parsed.events.iter().any(|event| {
            event.event_action == "onedrive_error_observed" && event.severity == "medium"
        }));
    }

    #[test]
    fn mft_record_size_detection_prefers_smallest_dense_file_boundary() {
        let mut mft_1024 = vec![0u8; 1024 * 32];
        for chunk in mft_1024.chunks_exact_mut(1024) {
            chunk[..4].copy_from_slice(b"FILE");
        }
        for index in [3usize, 17, 29] {
            mft_1024[index * 1024..index * 1024 + 4].copy_from_slice(b"BAAD");
        }
        assert_eq!(detect_mft_record_size(&mft_1024), Some(1024));

        let mut mft_4096 = vec![0u8; 4096 * 32];
        for chunk in mft_4096.chunks_exact_mut(4096) {
            chunk[..4].copy_from_slice(b"FILE");
        }
        assert_eq!(detect_mft_record_size(&mft_4096), Some(4096));
    }
}
