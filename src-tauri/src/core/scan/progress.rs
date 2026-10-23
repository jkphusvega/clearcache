//! Shared counters + cancel flag, sampled every 200 ms by a reporter thread.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const TICK: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Walk,
    Accounting,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub files: u64,
    pub bytes: u64,
    pub current: String,
    pub elapsed_ms: u64,
    pub phase: Phase,
    /// True on the last event of a phase.
    pub done: bool,
}

pub trait ProgressSink: Send + Sync {
    fn emit(&self, p: ScanProgress);
}

pub struct Progress {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
    current: Mutex<String>,
    cancel: AtomicBool,
    phase: AtomicU8,
    start: Mutex<Instant>,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            files: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            current: Mutex::new(String::new()),
            cancel: AtomicBool::new(false),
            phase: AtomicU8::new(0),
            start: Mutex::new(Instant::now()),
        }
    }
}

impl Progress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn add(&self, files: u64, bytes: u64) {
        self.files.fetch_add(files, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Best effort: skipped when another thread holds the lock (it is only a sample).
    pub fn set_current(&self, path: &std::path::Path) {
        if let Ok(mut c) = self.current.try_lock() {
            c.clear();
            c.push_str(&path.to_string_lossy());
        }
    }

    /// Resets counters and the clock for a new phase.
    pub fn begin_phase(&self, phase: Phase) {
        self.files.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
        self.phase.store(phase as u8, Ordering::Relaxed);
        *self.start.lock().unwrap() = Instant::now();
    }

    pub fn elapsed(&self) -> Duration {
        self.start.lock().unwrap().elapsed()
    }

    pub fn snapshot(&self, done: bool) -> ScanProgress {
        ScanProgress {
            files: self.files.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            current: self.current.lock().map(|c| c.clone()).unwrap_or_default(),
            elapsed_ms: self.elapsed().as_millis() as u64,
            phase: if self.phase.load(Ordering::Relaxed) == Phase::Accounting as u8 {
                Phase::Accounting
            } else {
                Phase::Walk
            },
            done,
        }
    }
}

/// Emits a snapshot every `TICK` until dropped, then one final `done` snapshot.
pub struct Reporter {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Reporter {
    pub fn start(progress: Arc<Progress>, sink: Arc<dyn ProgressSink>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                std::thread::sleep(TICK);
                if s.load(Ordering::Relaxed) {
                    break;
                }
                sink.emit(progress.snapshot(false));
            }
            sink.emit(progress.snapshot(true));
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Reporter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Collect(Mutex<Vec<ScanProgress>>);
    impl ProgressSink for Collect {
        fn emit(&self, p: ScanProgress) {
            self.0.lock().unwrap().push(p);
        }
    }

    #[test]
    fn progress_periodic_then_final_event() {
        let progress = Progress::new();
        let sink = Arc::new(Collect::default());
        progress.begin_phase(Phase::Walk);
        {
            let _r = Reporter::start(progress.clone(), sink.clone());
            progress.add(3, 300);
            std::thread::sleep(TICK * 3);
        }
        let events = sink.0.lock().unwrap();
        assert!(events.len() >= 3, "got {}", events.len());
        assert!(events[..events.len() - 1].iter().all(|e| !e.done));
        let last = events.last().unwrap();
        assert!(last.done);
        assert_eq!((last.files, last.bytes, last.phase), (3, 300, Phase::Walk));
    }
}
