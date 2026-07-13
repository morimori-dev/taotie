use std::env;

use taotie_api::{get_case_summary, ingest_local_path, LocalPathIngestRequest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let Some(case_root) = args.next() else {
        eprintln!("usage: ingest_local_path <case_root> <input_path> [recursive=true|false]");
        std::process::exit(2);
    };
    let Some(input_path) = args.next() else {
        eprintln!("usage: ingest_local_path <case_root> <input_path> [recursive=true|false]");
        std::process::exit(2);
    };
    let recursive = args
        .next()
        .map(|value| !matches!(value.as_str(), "0" | "false" | "False" | "FALSE"))
        .unwrap_or(true);

    let result = ingest_local_path(LocalPathIngestRequest {
        case_root: case_root.clone(),
        input_path,
        recursive: Some(recursive),
    })?;
    let summary = get_case_summary(&case_root)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ingest": {
                "file_count": result.file_count,
                "failed_count": result.failed_count,
                "errors": result.errors,
            },
            "summary": summary,
        }))?
    );
    Ok(())
}
