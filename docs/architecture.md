# Architecture

## Goal

Build a local-first DFIR timeline workbench with accurate evidence tracking and fast UI read paths.

## Main Layers

1. Intake
2. Artifact detection
3. Parser adapters
4. Accurate write model
5. Fast read model
6. Query API
7. UI
8. Background analysis
9. External import adapters

## Accurate Write Model

Stores evidence-linked, reproducible data.

Tables:

- files
- parse_runs
- parser_versions
- schema_versions
- events_full
- raw_records
- metadata
- parser_errors
- unsupported_files

## Fast Read Model

Stores compact UI-oriented projections.

Tables:

- event_rows
- timeline_bins
- coverage_summary
- failed_parser_summary
- finding_summary
- related_event_index

## Hot Path

The hot path must stay small:

```txt
file intake
  -> files inventory
  -> parse job
  -> events_full
  -> event_rows
  -> timeline_bins
```

## Background Path

The background path may be slower:

```txt
events_full
  -> Tantivy
  -> entities
  -> edges
  -> findings
  -> graph cache
  -> external analyzers
```

## External Tool Strategy

Plaso, KAPE, EZ Tools, and Tika must be treated as sidecar/import adapters. They must not block the UI hot path.
