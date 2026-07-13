use std::{env, time::Instant};

use taotie_api::{
    get_answer_candidates, get_case_summary, get_correlation_chains, get_correlation_summary,
    get_event_context, get_event_detail_light, get_event_evidence_offsets, get_event_page,
    AnswerCandidateQuery,
};
use taotie_schema::{EventContextQuery, EventPageQuery};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(case_root) = env::args().nth(1) else {
        eprintln!("usage: case_probe <case_root>");
        std::process::exit(2);
    };
    let started = Instant::now();
    let summary = get_case_summary(&case_root)?;
    let page = get_event_page(
        &case_root,
        EventPageQuery {
            limit: Some(5),
            cursor: None,
            artifact_type: None,
            user_name: None,
            search: None,
            sort_by: Some("event_time_utc".to_string()),
            sort_dir: Some("asc".to_string()),
        },
    )?;
    let moveit_page = get_event_page(
        &case_root,
        EventPageQuery {
            limit: Some(5),
            cursor: None,
            artifact_type: None,
            user_name: None,
            search: Some("move.aspx".to_string()),
            sort_by: Some("event_time_utc".to_string()),
            sort_dir: Some("asc".to_string()),
        },
    )?;
    let answers = get_answer_candidates(AnswerCandidateQuery {
        case_root: case_root.clone(),
        question_key: None,
        limit: Some(100),
    })?;
    let (
        detail_ms,
        detail_found,
        evidence_offsets_ms,
        evidence_offsets,
        context_ms,
        context_group_count,
    ) = if let Some(first) = page.rows.first() {
        let detail_started = Instant::now();
        let detail = get_event_detail_light(&case_root, &first.event_id)?;
        let detail_ms = detail_started.elapsed().as_millis();
        let evidence_started = Instant::now();
        let evidence_offsets = get_event_evidence_offsets(&case_root, &first.event_id)?;
        let evidence_offsets_ms = evidence_started.elapsed().as_millis();
        let context_started = Instant::now();
        let context = get_event_context(
            &case_root,
            EventContextQuery {
                event_id: first.event_id.clone(),
                window_minutes: Some(15),
                per_group_limit: Some(100),
                same_host_only: Some(true),
            },
        )?;
        let context_ms = context_started.elapsed().as_millis();
        (
            detail_ms,
            detail.is_some(),
            evidence_offsets_ms,
            evidence_offsets,
            context_ms,
            context.map(|row| row.groups.len()).unwrap_or(0),
        )
    } else {
        (0, false, 0, Vec::new(), 0, 0)
    };
    let correlation_started = Instant::now();
    let correlations = get_correlation_summary(&case_root, Some(100))?;
    let correlation_ms = correlation_started.elapsed().as_millis();
    let chains_started = Instant::now();
    let chains = get_correlation_chains(&case_root, Some(100))?;
    let chains_ms = chains_started.elapsed().as_millis();
    println!(
        "{}",
        serde_json::json!({
            "elapsed_ms": started.elapsed().as_millis(),
            "summary": summary,
            "first_page_rows": page.rows.len(),
            "first_page_next_cursor": page.next_cursor,
            "move_aspx_rows": moveit_page.rows.len(),
            "move_aspx_first": moveit_page.rows.first(),
            "first_event_detail_ms": detail_ms,
            "first_event_detail_found": detail_found,
            "first_event_context_ms": context_ms,
            "first_event_context_group_count": context_group_count,
            "first_event_evidence_offsets_ms": evidence_offsets_ms,
            "first_event_evidence_offset_count": evidence_offsets.len(),
            "first_event_evidence_offset_sample": evidence_offsets.first(),
            "correlation_rows": correlations.len(),
            "correlation_ms": correlation_ms,
            "correlation_chain_rows": chains.len(),
            "correlation_chain_ms": chains_ms,
            "answer_count": answers.len(),
            "answers": answers,
        })
    );
    Ok(())
}
