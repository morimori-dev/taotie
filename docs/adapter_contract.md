# Adapter Contract

## Parser Adapter

A parser reads an artifact and emits canonical records.

It must:

- accept file_id and object_ref
- record parser_name and parser_version
- emit events in batches or streams
- report parse errors
- never hide unsupported files
- never execute evidence files

## External Adapter

External adapters wrap tools such as Plaso, EZ Tools, KAPE, and Tika.

They must:

- run as sidecar/import jobs
- have timeout
- have memory budget
- have concurrency limit
- capture stdout/stderr
- capture tool version
- normalize output into canonical records
- write parse_runs or analyzer_runs
- remain off the hot path
