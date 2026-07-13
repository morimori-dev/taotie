# UI Rules

## State

Frontend state may contain:

- current_tab
- selected_event_id
- selected_file_id
- filters
- page cursor
- visible event rows
- visible file rows
- visible timeline bins
- job status summary

Frontend state must not contain:

- all events
- all files
- all raw records
- all entities
- all edges
- whole graph

## Event Selection

Selecting an event must:

1. update selected_event_id immediately
2. show detail shell immediately
3. use event_rows data first
4. lazy-load detail_light
5. lazy-load raw_record only when opened
6. lazy-load graph only when visible

## Tables

Use paged queries and virtualized rendering.

## Graph

Use selected event/entity centered subgraphs only.

Defaults:

- k <= 2
- max_nodes <= 200
- max_edges <= 500
