use std::{
    env, thread,
    time::{Duration, Instant},
};

use taotie_api::{
    get_answer_candidates, get_recent_jobs, start_answer_candidate_build, AnswerCandidateQuery,
    StartAnswerCandidateBuildRequest,
};
use taotie_schema::{JobRecord, JobStatus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(case_root) = env::args().nth(1) else {
        eprintln!("usage: answer_candidate_job <case_root>");
        std::process::exit(2);
    };
    let timeout = env::var("TAOTIE4_ANSWER_JOB_TIMEOUT_SEC")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(30 * 60));
    let poll_interval = Duration::from_secs(2);

    let queued = start_answer_candidate_build(StartAnswerCandidateBuildRequest {
        case_root: case_root.clone(),
    })?;
    eprintln!(
        "answer candidate job: {} {} {:.0}%",
        queued.job_id,
        queued.status.as_str(),
        queued.progress * 100.0
    );

    let started = Instant::now();
    let final_job = loop {
        let job = find_job(&case_root, &queued.job_id)?.unwrap_or_else(|| queued.clone());
        eprintln!(
            "answer candidate job: {} {} {:.0}%",
            job.job_id,
            job.status.as_str(),
            job.progress * 100.0
        );
        match job.status {
            JobStatus::Succeeded | JobStatus::Failed | JobStatus::Cancelled => break job,
            JobStatus::Queued | JobStatus::Running => {}
        }
        if started.elapsed() > timeout {
            return Err(format!(
                "answer candidate job timed out after {}s: {}",
                timeout.as_secs(),
                queued.job_id
            )
            .into());
        }
        thread::sleep(poll_interval);
    };

    let answers = get_answer_candidates(AnswerCandidateQuery {
        case_root,
        question_key: None,
        limit: Some(250),
    })?;
    println!(
        "{}",
        serde_json::json!({
            "elapsed_ms": started.elapsed().as_millis(),
            "job": final_job,
            "answer_count": answers.len(),
            "high_confidence_count": answers.iter().filter(|row| row.confidence >= 0.8).count(),
            "needs_followup_count": answers
                .iter()
                .filter(|row| row.status.contains("needs") || row.status.contains("recovery"))
                .count(),
            "top_answers": answers.into_iter().take(25).collect::<Vec<_>>(),
        })
    );
    Ok(())
}

fn find_job(
    case_root: &str,
    job_id: &str,
) -> Result<Option<JobRecord>, Box<dyn std::error::Error>> {
    Ok(get_recent_jobs(case_root, Some(100))?
        .into_iter()
        .find(|job| job.job_id == job_id))
}
