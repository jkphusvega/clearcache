//! App-wide scan state: one scan at a time, its cancel handle, and the latest result.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::accounting::AccountingUpdate;
use super::scan::progress::Progress;
use super::scan::ScanResult;

#[derive(Default)]
pub struct ScanSession {
    busy: AtomicBool,
    progress: Mutex<Option<Arc<Progress>>>,
    result: Mutex<Option<ScanResult>>,
}

/// Held for the whole scan (walk and accounting); releases the slot on drop.
pub struct ScanGuard {
    session: Arc<ScanSession>,
    pub progress: Arc<Progress>,
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.session.busy.store(false, Ordering::SeqCst);
    }
}

impl ScanSession {
    pub fn try_begin(self: &Arc<Self>) -> Result<ScanGuard, String> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err("이미 스캔 중입니다".into());
        }
        let progress = Progress::new();
        *self.progress.lock().unwrap() = Some(progress.clone());
        *self.result.lock().unwrap() = None;
        Ok(ScanGuard {
            session: self.clone(),
            progress,
        })
    }

    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) {
        if let Some(p) = self.progress.lock().unwrap().as_ref() {
            p.cancel();
        }
    }

    pub fn set_result(&self, r: ScanResult) {
        *self.result.lock().unwrap() = Some(r);
    }

    pub fn result(&self) -> Option<ScanResult> {
        self.result.lock().unwrap().clone()
    }

    pub fn apply(&self, u: &AccountingUpdate) {
        if let Some(r) = self.result.lock().unwrap().as_mut() {
            r.apply(u);
        }
    }

    pub fn finish_accounting(&self, completed: bool, ms: u64) {
        if let Some(r) = self.result.lock().unwrap().as_mut() {
            r.finish_accounting(completed, ms);
        }
    }
}
