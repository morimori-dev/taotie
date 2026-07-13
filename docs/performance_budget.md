# Performance Budget

## UI

- tab switch shell: 50-150 ms
- timeline cached bins: 100-300 ms
- event page query: 100-300 ms
- event row visual selection: under 50 ms
- event detail light: under 300 ms
- search first page: 300-800 ms
- small graph: 500-1500 ms

## API Payload Budgets

- event page payload: ideally under 300 KB
- event detail light payload: ideally under 30 KB
- raw_record payload: only on demand
- graph payload: max 200 nodes and 500 edges by default

## Prohibited Hot Path Work

- full graph generation
- Tika extraction
- YARA scan
- Plaso import
- KAPE import
- full entity extraction
- full edge extraction
- whole-case aggregation
