use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use taotie_schema::{new_id, now_utc, JobKind, JobRecord, JobStatus};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JobError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("unknown job kind: {0}")]
    UnknownJobKind(String),
    #[error("unknown job status: {0}")]
    UnknownJobStatus(String),
}

pub type Result<T> = std::result::Result<T, JobError>;

#[derive(Debug)]
pub struct JobQueue {
    conn: Connection,
}

impl JobQueue {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        configure_connection(&conn)?;
        let queue = Self { conn };
        queue.init()?;
        Ok(queue)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        configure_connection(&conn)?;
        let queue = Self { conn };
        queue.init()?;
        Ok(queue)
    }

    pub fn enqueue(
        &self,
        case_id: &str,
        kind: JobKind,
        priority: i64,
        payload_json: impl Into<String>,
        resource_limits_json: impl Into<String>,
    ) -> Result<JobRecord> {
        let now = now_utc();
        let record = JobRecord {
            job_id: new_id("job"),
            case_id: case_id.to_string(),
            kind,
            status: JobStatus::Queued,
            priority,
            progress: 0.0,
            attempts: 0,
            max_attempts: 3,
            created_at: now.clone(),
            updated_at: now,
            started_at: None,
            finished_at: None,
            worker_id: None,
            heartbeat_at: None,
            cancel_requested: false,
            resource_limits_json: resource_limits_json.into(),
            payload_json: payload_json.into(),
            error_message: None,
        };
        self.insert(&record)?;
        Ok(record)
    }

    pub fn claim_next(&self, worker_id: &str) -> Result<Option<JobRecord>> {
        let tx = self.conn.unchecked_transaction()?;
        let next: Option<String> = tx
            .query_row(
                "SELECT job_id FROM jobs WHERE status = 'queued' AND cancel_requested = 0 \
                 ORDER BY priority DESC, created_at ASC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(job_id) = next else {
            tx.commit()?;
            return Ok(None);
        };
        let now = now_utc();
        tx.execute(
            "UPDATE jobs SET status = 'running', attempts = attempts + 1, updated_at = ?1, \
             started_at = COALESCE(started_at, ?1), worker_id = ?2, heartbeat_at = ?1 \
             WHERE job_id = ?3 AND status = 'queued'",
            params![now, worker_id, job_id],
        )?;
        tx.commit()?;
        self.get(&job_id)
    }

    pub fn start(&self, job_id: &str, worker_id: &str) -> Result<Option<JobRecord>> {
        let now = now_utc();
        self.conn.execute(
            "UPDATE jobs SET status = 'running', attempts = attempts + 1, updated_at = ?1, \
             started_at = COALESCE(started_at, ?1), worker_id = ?2, heartbeat_at = ?1 \
             WHERE job_id = ?3 AND status = 'queued' AND cancel_requested = 0",
            params![now, worker_id, job_id],
        )?;
        self.get(job_id)
    }

    pub fn cancel(&self, job_id: &str) -> Result<()> {
        let now = now_utc();
        self.conn.execute(
            "UPDATE jobs SET cancel_requested = 1, updated_at = ?1 WHERE job_id = ?2",
            params![now, job_id],
        )?;
        Ok(())
    }

    pub fn mark_cancelled(&self, job_id: &str) -> Result<()> {
        let now = now_utc();
        self.conn.execute(
            "UPDATE jobs SET status = 'cancelled', progress = 0.0, updated_at = ?1, \
             finished_at = ?1 WHERE job_id = ?2",
            params![now, job_id],
        )?;
        Ok(())
    }

    pub fn update_progress(&self, job_id: &str, progress: f64) -> Result<()> {
        let now = now_utc();
        let progress = progress.clamp(0.0, 1.0);
        self.conn.execute(
            "UPDATE jobs SET progress = ?1, updated_at = ?2 WHERE job_id = ?3",
            params![progress, now, job_id],
        )?;
        Ok(())
    }

    pub fn heartbeat(&self, job_id: &str, worker_id: &str) -> Result<()> {
        let now = now_utc();
        self.conn.execute(
            "UPDATE jobs SET heartbeat_at = ?1, worker_id = ?2, updated_at = ?1 WHERE job_id = ?3",
            params![now, worker_id, job_id],
        )?;
        Ok(())
    }

    pub fn complete(&self, job_id: &str) -> Result<()> {
        let now = now_utc();
        self.conn.execute(
            "UPDATE jobs SET status = 'succeeded', progress = 1.0, updated_at = ?1, \
             finished_at = ?1, error_message = NULL WHERE job_id = ?2",
            params![now, job_id],
        )?;
        Ok(())
    }

    pub fn fail(&self, job_id: &str, error_message: &str) -> Result<()> {
        let now = now_utc();
        self.conn.execute(
            "UPDATE jobs SET status = 'failed', updated_at = ?1, finished_at = ?1, \
             error_message = ?2 WHERE job_id = ?3",
            params![now, error_message, job_id],
        )?;
        Ok(())
    }

    pub fn get(&self, job_id: &str) -> Result<Option<JobRecord>> {
        self.conn
            .query_row(
                "SELECT job_id, case_id, kind, status, priority, progress, attempts, max_attempts, \
                 created_at, updated_at, started_at, finished_at, worker_id, heartbeat_at, \
                 cancel_requested, resource_limits_json, payload_json, error_message \
                 FROM jobs WHERE job_id = ?1",
                params![job_id],
                row_to_job,
            )
            .optional()
            .map_err(JobError::from)
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<JobRecord>> {
        let limit = limit.clamp(1, 500) as i64;
        let mut stmt = self.conn.prepare(
            "SELECT job_id, case_id, kind, status, priority, progress, attempts, max_attempts, \
             created_at, updated_at, started_at, finished_at, worker_id, heartbeat_at, \
             cancel_requested, resource_limits_json, payload_json, error_message \
             FROM jobs ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], row_to_job)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                priority INTEGER NOT NULL,
                progress REAL NOT NULL,
                attempts INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                worker_id TEXT,
                heartbeat_at TEXT,
                cancel_requested INTEGER NOT NULL,
                resource_limits_json TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                error_message TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_jobs_claim
              ON jobs(status, cancel_requested, priority DESC, created_at ASC);
            CREATE INDEX IF NOT EXISTS idx_jobs_case
              ON jobs(case_id, created_at DESC);",
        )?;
        Ok(())
    }

    fn insert(&self, record: &JobRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO jobs (
                job_id, case_id, kind, status, priority, progress, attempts, max_attempts,
                created_at, updated_at, started_at, finished_at, worker_id, heartbeat_at,
                cancel_requested, resource_limits_json, payload_json, error_message
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                record.job_id,
                record.case_id,
                record.kind.as_str(),
                record.status.as_str(),
                record.priority,
                record.progress,
                record.attempts,
                record.max_attempts,
                record.created_at,
                record.updated_at,
                record.started_at,
                record.finished_at,
                record.worker_id,
                record.heartbeat_at,
                record.cancel_requested as i64,
                record.resource_limits_json,
                record.payload_json,
                record.error_message,
            ],
        )?;
        Ok(())
    }
}

fn configure_connection(conn: &Connection) -> Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

fn row_to_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    let kind: String = row.get(2)?;
    let status: String = row.get(3)?;
    let cancel_requested: i64 = row.get(14)?;
    Ok(JobRecord {
        job_id: row.get(0)?,
        case_id: row.get(1)?,
        kind: parse_job_kind(&kind).map_err(to_sql_error)?,
        status: parse_job_status(&status).map_err(to_sql_error)?,
        priority: row.get(4)?,
        progress: row.get(5)?,
        attempts: row.get(6)?,
        max_attempts: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        started_at: row.get(10)?,
        finished_at: row.get(11)?,
        worker_id: row.get(12)?,
        heartbeat_at: row.get(13)?,
        cancel_requested: cancel_requested != 0,
        resource_limits_json: row.get(15)?,
        payload_json: row.get(16)?,
        error_message: row.get(17)?,
    })
}

fn parse_job_kind(value: &str) -> Result<JobKind> {
    Ok(match value {
        "intake_file" => JobKind::IntakeFile,
        "detect_artifact_type" => JobKind::DetectArtifactType,
        "parse_artifact" => JobKind::ParseArtifact,
        "build_event_rows" => JobKind::BuildEventRows,
        "build_timeline_bins" => JobKind::BuildTimelineBins,
        "build_tantivy_index" => JobKind::BuildTantivyIndex,
        "build_answer_candidates" => JobKind::BuildAnswerCandidates,
        "extract_entities" => JobKind::ExtractEntities,
        "build_edges" => JobKind::BuildEdges,
        "build_correlation_chains" => JobKind::BuildCorrelationChains,
        "run_findings" => JobKind::RunFindings,
        "import_plaso" => JobKind::ImportPlaso,
        "import_kape" => JobKind::ImportKape,
        "run_tika" => JobKind::RunTika,
        "run_yara" => JobKind::RunYara,
        "run_sidecar" => JobKind::RunSidecar,
        "run_network_sidecar" => JobKind::RunNetworkSidecar,
        "run_credential_sidecar" => JobKind::RunCredentialSidecar,
        "run_document_sidecar" => JobKind::RunDocumentSidecar,
        "run_archive_sidecar" => JobKind::RunArchiveSidecar,
        other => return Err(JobError::UnknownJobKind(other.to_string())),
    })
}

fn parse_job_status(value: &str) -> Result<JobStatus> {
    Ok(match value {
        "queued" => JobStatus::Queued,
        "running" => JobStatus::Running,
        "succeeded" => JobStatus::Succeeded,
        "failed" => JobStatus::Failed,
        "cancelled" => JobStatus::Cancelled,
        other => return Err(JobError::UnknownJobStatus(other.to_string())),
    })
}

fn to_sql_error(error: JobError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_claim_cancel_and_complete_flow() {
        let queue = JobQueue::open_in_memory().unwrap();
        let job = queue
            .enqueue(
                "case_1",
                JobKind::ParseArtifact,
                10,
                "{}",
                r#"{"timeout_ms":1000}"#,
            )
            .unwrap();
        queue.cancel(&job.job_id).unwrap();
        assert!(queue.claim_next("worker_1").unwrap().is_none());

        let job = queue
            .enqueue("case_1", JobKind::BuildEventRows, 5, "{}", "{}")
            .unwrap();
        let claimed = queue.claim_next("worker_1").unwrap().unwrap();
        assert_eq!(claimed.job_id, job.job_id);
        assert_eq!(claimed.status, JobStatus::Running);
        queue.update_progress(&job.job_id, 0.5).unwrap();
        queue.complete(&job.job_id).unwrap();
        let done = queue.get(&job.job_id).unwrap().unwrap();
        assert_eq!(done.status, JobStatus::Succeeded);
        assert_eq!(done.progress, 1.0);

        let direct_job = queue
            .enqueue("case_1", JobKind::BuildTantivyIndex, 20, "{}", "{}")
            .unwrap();
        let started = queue
            .start(&direct_job.job_id, "worker_2")
            .unwrap()
            .unwrap();
        assert_eq!(started.status, JobStatus::Running);
        assert_eq!(started.worker_id.as_deref(), Some("worker_2"));
    }
}
