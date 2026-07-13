use std::env;
use std::time::Instant;

use serde_json::json;
use taotie_api::get_event_page;
use taotie_schema::{EventPageQuery, EventRow};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let Some(case_root) = args.next() else {
        eprintln!("usage: event_search_probe <case_root> [search_term ...]");
        std::process::exit(2);
    };
    let terms = args.collect::<Vec<_>>();
    let terms = if terms.is_empty() {
        vec![
            "1149".to_string(),
            "TerminalServices".to_string(),
            "RemoteConnectionManager".to_string(),
            "LogonType 10".to_string(),
            "4624".to_string(),
        ]
    } else {
        terms
    };

    let rows = terms
        .iter()
        .map(|term| {
            let started = Instant::now();
            let page = get_event_page(
                &case_root,
                EventPageQuery {
                    limit: Some(10),
                    cursor: None,
                    artifact_type: None,
                    user_name: None,
                    search: Some(term.clone()),
                    sort_by: Some("event_time_utc".to_string()),
                    sort_dir: Some("asc".to_string()),
                },
            );
            match page {
                Ok(page) => json!({
                    "term": term,
                    "ok": true,
                    "elapsed_ms": started.elapsed().as_millis(),
                    "count": page.rows.len(),
                    "rows": page.rows.iter().map(sample_row).collect::<Vec<_>>(),
                }),
                Err(error) => json!({
                    "term": term,
                    "ok": false,
                    "elapsed_ms": started.elapsed().as_millis(),
                    "error": error.to_string(),
                }),
            }
        })
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}

fn sample_row(row: &EventRow) -> serde_json::Value {
    json!({
        "event_id": row.event_id,
        "event_time_utc": row.event_time_utc,
        "artifact_type": row.artifact_type,
        "user_name": row.user_name,
        "ip": row.ip,
        "event_action": row.event_action,
        "message_short": row.message_short,
        "source_file_id": row.source_file_id,
    })
}
