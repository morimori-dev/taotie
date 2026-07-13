# Schema

## Required Event Fields

- event_id
- case_id
- event_time_utc
- event_time_original
- time_kind
- time_confidence
- source_confidence
- artifact_type
- source_file_id
- parse_run_id
- parser_name
- parser_version
- schema_version
- evidence_ref
- host
- user_name
- process_name
- file_path
- ip
- url
- hash
- event_action
- severity
- message_short
- message_full
- raw_record_ref

## Event List Projection

`event_rows` must be compact and safe for UI lists.

Fields:

- event_id
- event_time_utc
- artifact_type
- host
- user_name
- event_action
- severity
- message_short
- source_file_id
- parser_name
- has_finding

Do not include raw records or large attributes JSON.

## Timestamp Rules

Never collapse timestamp meaning.

Use:

- time_kind
- time_confidence
- event_time_original
- event_time_utc
- timezone, if known

Examples of `time_kind`:

- evtx_event_created
- mft_created
- mft_modified
- mft_accessed
- mft_changed
- prefetch_execution
- registry_last_write
- textlog_line_timestamp
- filesystem_modified
