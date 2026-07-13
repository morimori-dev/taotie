# Security

Evidence files are untrusted input.

Rules:

- never execute evidence files
- do not shell out to evidence paths directly
- external tools run only as bounded sidecar jobs
- capture stdout and stderr from sidecar jobs
- record tool failures instead of hiding them
- use timeout, memory budget, and concurrency limits for external work
- keep raw records out of list payloads
