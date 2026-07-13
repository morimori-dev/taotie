use std::{env, time::Instant};

use taotie_storage::CaseWorkspace;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let case_root = env::args()
        .nth(1)
        .ok_or("usage: rebuild_event_rows <case_root>")?;
    let started = Instant::now();
    let workspace = CaseWorkspace::open(&case_root)?;
    let count = workspace.query_layer().rebuild_event_rows_from_lake()?;
    println!(
        "{}",
        serde_json::json!({
            "case_root": case_root,
            "event_row_count": count,
            "elapsed_ms": started.elapsed().as_millis(),
        })
    );
    Ok(())
}
