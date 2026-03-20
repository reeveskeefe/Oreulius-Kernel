//! Capability-gated download job management.
//!
//! A `DownloadJob` is created when `ContentFilter` or `Policy` decides a
//! response should not be relayed inline.  The kernel offers the download to
//! the owning process, which must `AcceptDownload` (with a destination path)
//! or `RejectDownload`.  Accepted downloads are written to VFS via
//! `storage.rs`.

#![allow(dead_code)]

use super::types::{BrowserSessionId, DownloadId, MimeType, RequestId};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MAX_DOWNLOADS: usize = 16;
pub const FILENAME_MAX: usize = 256;
pub const DEST_PATH_MAX: usize = 256;

// ---------------------------------------------------------------------------
// DownloadState
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DownloadState {
    /// Offered to the client, awaiting accept/reject.
    Pending,
    /// Client accepted; data is being written.
    Active,
    /// Write completed successfully.
    Complete,
    /// Rejected by client or aborted by kernel.
    Rejected,
    /// An I/O error occurred during write.
    Error,
}

// ---------------------------------------------------------------------------
// DownloadJob
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct DownloadJob {
    pub id: DownloadId,
    pub session: BrowserSessionId,
    pub request: RequestId,
    pub state: DownloadState,
    /// Suggested filename from `Content-Disposition`.
    pub filename: [u8; FILENAME_MAX],
    pub filename_len: usize,
    /// Declared MIME type.
    pub mime: MimeType,
    /// Declared content-length (0 = unknown).
    pub size_hint: u64,
    /// Client-supplied destination path (filled on `AcceptDownload`).
    pub dest_path: [u8; DEST_PATH_MAX],
    pub dest_path_len: usize,
    /// Bytes written so far.
    pub bytes_written: u64,
    pub active: bool,
}

impl DownloadJob {
    pub const EMPTY: Self = Self {
        id: DownloadId(0),
        session: BrowserSessionId(0),
        request: RequestId(0),
        state: DownloadState::Rejected,
        filename: [0; FILENAME_MAX],
        filename_len: 0,
        mime: MimeType::from_bytes(b"application/octet-stream"),
        size_hint: 0,
        dest_path: [0; DEST_PATH_MAX],
        dest_path_len: 0,
        bytes_written: 0,
        active: false,
    };
}

// ---------------------------------------------------------------------------
// DownloadManager
// ---------------------------------------------------------------------------

pub struct DownloadManager {
    jobs: [DownloadJob; MAX_DOWNLOADS],
    next_id: u32,
}

impl DownloadManager {
    pub const fn new() -> Self {
        Self {
            jobs: [DownloadJob::EMPTY; MAX_DOWNLOADS],
            next_id: 1,
        }
    }

    // -----------------------------------------------------------------------
    // Create / offer
    // -----------------------------------------------------------------------

    /// Create a new download offer.  Returns the `DownloadId`, or `None` if
    /// the table is full.
    pub fn offer(
        &mut self,
        session: BrowserSessionId,
        request: RequestId,
        filename: &[u8],
        mime: MimeType,
        size_hint: u64,
    ) -> Option<DownloadId> {
        let slot = self.find_free()?;
        let id = DownloadId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1).max(1);

        let name_len = filename.len().min(FILENAME_MAX);
        let mut name = [0u8; FILENAME_MAX];
        name[..name_len].copy_from_slice(&filename[..name_len]);

        self.jobs[slot] = DownloadJob {
            id,
            session,
            request,
            state: DownloadState::Pending,
            filename: name,
            filename_len: name_len,
            mime,
            size_hint,
            dest_path: [0; DEST_PATH_MAX],
            dest_path_len: 0,
            bytes_written: 0,
            active: true,
        };
        Some(id)
    }

    // -----------------------------------------------------------------------
    // Accept / reject
    // -----------------------------------------------------------------------

    /// Mark a download as accepted and record the destination path.
    /// Returns `false` if the id is unknown or not in `Pending` state.
    pub fn accept(&mut self, id: DownloadId, session: BrowserSessionId, dest_path: &[u8]) -> bool {
        let job = match self.find_mut(id, session) {
            Some(j) => j,
            None => return false,
        };
        if job.state != DownloadState::Pending {
            return false;
        }
        let len = dest_path.len().min(DEST_PATH_MAX);
        job.dest_path[..len].copy_from_slice(&dest_path[..len]);
        job.dest_path_len = len;
        job.state = DownloadState::Active;
        true
    }

    /// Reject a pending download.
    pub fn reject(&mut self, id: DownloadId, session: BrowserSessionId) -> bool {
        let job = match self.find_mut(id, session) {
            Some(j) => j,
            None => return false,
        };
        job.state = DownloadState::Rejected;
        job.active = false;
        true
    }

    // -----------------------------------------------------------------------
    // Progress
    // -----------------------------------------------------------------------

    /// Record that `bytes` more have been written.
    pub fn record_progress(&mut self, id: DownloadId, bytes: usize) {
        if let Some(job) = self.find_by_id(id) {
            job.bytes_written = job.bytes_written.saturating_add(bytes as u64);
        }
    }

    /// Mark the download as complete.
    pub fn complete(&mut self, id: DownloadId) {
        if let Some(job) = self.find_by_id(id) {
            job.state = DownloadState::Complete;
        }
    }

    /// Mark the download as errored.
    pub fn error(&mut self, id: DownloadId) {
        if let Some(job) = self.find_by_id(id) {
            job.state = DownloadState::Error;
            job.active = false;
        }
    }

    // -----------------------------------------------------------------------
    // Query
    // -----------------------------------------------------------------------

    pub fn get(&self, id: DownloadId) -> Option<&DownloadJob> {
        self.jobs.iter().find(|j| j.active && j.id == id)
    }

    /// Retrieve the destination path for an active download.
    pub fn dest_path(&self, id: DownloadId) -> Option<(&[u8], usize)> {
        self.get(id)
            .map(|j| (j.dest_path.as_ref(), j.dest_path_len))
    }

    /// Remove all jobs belonging to `session`.
    pub fn purge_session(&mut self, session: BrowserSessionId) {
        for j in &mut self.jobs {
            if j.active && j.session == session {
                j.active = false;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn find_free(&self) -> Option<usize> {
        self.jobs.iter().position(|j| !j.active)
    }

    fn find_by_id(&mut self, id: DownloadId) -> Option<&mut DownloadJob> {
        self.jobs.iter_mut().find(|j| j.active && j.id == id)
    }

    fn find_mut(&mut self, id: DownloadId, session: BrowserSessionId) -> Option<&mut DownloadJob> {
        self.jobs
            .iter_mut()
            .find(|j| j.active && j.id == id && j.session == session)
    }
}
