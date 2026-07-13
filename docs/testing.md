# Testing

Add tests for:

- schema serialization/deserialization
- event lineage
- parse_runs recording
- failed parser recording
- unsupported file recording
- timeline bin generation
- paged event query
- event detail lazy loading
- no all-events API
- job cancellation
- sidecar adapter failure handling

Prefer small synthetic fixture data. Do not require real forensic evidence for core tests.
