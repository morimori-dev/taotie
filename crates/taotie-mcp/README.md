# taotie-mcp

A read-only **[Model Context Protocol](https://modelcontextprotocol.io)** server
over a [Taotie](../../README.md) DFIR case. It lets you point Claude — or any MCP
client — at a forensic case and interrogate it in natural language, while the
evidence never leaves your host.

- **Read-only.** Opens the case read-only and only reads; nothing is written, so
  evidence-integrity guarantees are unaffected.
- **Local stdio.** Speaks JSON-RPC 2.0 over stdio. The model client runs on the
  same machine and sees only what its tools return.
- **Same engine as the app.** Reuses the desktop app's query layer, so results
  match what you'd see in the UI (including the full search DSL).

## Tools

| Tool | What it returns |
| --- | --- |
| `case_summary` | Case id, ingested artifact counts, events per artifact type |
| `search_events` | A page of the unified timeline; `query` uses the taotie search DSL, plus a cursor for paging |
| `get_event_detail` | Full detail for one `event_id` |
| `list_findings` | Detections (sigma / heuristics / IOC) grouped by rule, with severity, ATT&CK, affected entities |
| `get_timeline` | Event-volume bins (minute / hour / day) |
| `get_correlation_chains` | Cross-artifact chains keyed on shared host / user / process / file / hash |

### Search DSL (for `search_events`)

Terms combine with AND; quote values that contain spaces. Filters: `after:` /
`before:` (UTC time), `host:` `user:` `process:` `path:` `ip:` `url:` `hash:`
`eid:` `channel:` `level:` `action:` `type:` (artifact type) `severity:`
`finding:true` (only events with detections); bare words are full-text.

```text
finding:true severity:high channel:Security after:2023-05-01T00:00
```

## Usage

The binary is attached to each [release](https://github.com/morimori-dev/taotie/releases)
(and bundled inside the Windows portable zip). Point it at a case with
`--case-root` or the `TAOTIE_CASE_ROOT` environment variable.

Register with Claude Code:

```sh
claude mcp add taotie -- /path/to/taotie-mcp --case-root /path/to/your/case
```

Or with Claude Desktop / any MCP client (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "taotie": {
      "command": "/path/to/taotie-mcp",
      "args": ["--case-root", "/path/to/your/case"]
    }
  }
}
```

A *case root* is a directory Taotie has ingested into (it contains `lake/` and
`read_models/`). Create one with the desktop app, then hand its path to the
server.

## Build

```sh
cargo build --release -p taotie-mcp
# ./target/release/taotie-mcp --case-root /path/to/case
```

## License

Dual-licensed under MIT or Apache-2.0, the same as the rest of the project.
