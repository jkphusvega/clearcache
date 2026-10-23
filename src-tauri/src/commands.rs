//! Tauri commands. They only call `core`; the UI sends target ids, never paths.

use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;
use tauri::ipc::Channel;
use tauri::State;

use crate::core::accounting::{AccountingUpdate, Win32Opener};
use crate::core::scan::progress::{ProgressSink, Reporter, ScanProgress};
use crate::core::scan::{
    self, syncroots, PhaseStatus, ScanConfig, ScanResult, ScanSummary, DEFAULT_THRESHOLD,
};
use crate::core::session::ScanSession;
use crate::core::targets::{self, ScanTarget};

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanEvent {
    Progress(ScanProgress),
    Accounting(AccountingUpdate),
    AccountingDone { completed: bool, accounting_ms: u64 },
}

struct ChannelSink(Channel<ScanEvent>);

impl ProgressSink for ChannelSink {
    fn emit(&self, p: ScanProgress) {
        // The window may be gone; a failed send must not stop the scan.
        let _ = self.0.send(ScanEvent::Progress(p));
    }
}

#[tauri::command]
pub fn list_scan_targets() -> Vec<ScanTarget> {
    targets::list_scan_targets()
}

/// Runs the walk, returns its summary, and continues accounting in the background (D13).
/// The full tree is fetched with `get_scan_result`.
#[tauri::command]
pub async fn start_scan(
    target_id: String,
    on_event: Channel<ScanEvent>,
    session: State<'_, Arc<ScanSession>>,
) -> Result<ScanSummary, String> {
    let guard = session.try_begin()?;
    // Re-query the target list; unknown ids are refused.
    let target = targets::resolve_current(&target_id)?;
    let session = session.inner().clone();

    tauri::async_runtime::spawn_blocking(move || {
        let cfg = ScanConfig::for_target(&target, DEFAULT_THRESHOLD);
        let sync = syncroots::detect_system();
        let progress = guard.progress.clone();
        let sink: Arc<dyn ProgressSink> = Arc::new(ChannelSink(on_event.clone()));

        let walked = {
            let _reporter = Reporter::start(progress.clone(), sink.clone());
            scan::walk_phase(&cfg, &sync, &progress)
        };
        let Some((result, plan)) = walked else {
            return Err("cancelled".to_string());
        };
        let summary = result.summary.clone();
        let needs_accounting = summary.accounting_status == PhaseStatus::Running;
        session.set_result(result);
        if !needs_accounting {
            if let Some(r) = session.result() {
                scan::append_scan_log(&r.summary);
            }
            return Ok(summary);
        }

        std::thread::spawn(move || {
            let _guard = guard; // slot stays busy until accounting ends
            let started = Instant::now();
            let completed = {
                let _reporter = Reporter::start(progress.clone(), sink);
                scan::accounting_phase(&plan, &Win32Opener, &sync, &progress, &mut |u| {
                    session.apply(&u);
                    let _ = on_event.send(ScanEvent::Accounting(u));
                })
            };
            let ms = started.elapsed().as_millis() as u64;
            session.finish_accounting(completed, ms);
            if let Some(r) = session.result() {
                scan::append_scan_log(&r.summary);
            }
            let _ = on_event.send(ScanEvent::AccountingDone {
                completed,
                accounting_ms: ms,
            });
        });
        Ok(summary)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn cancel_scan(session: State<'_, Arc<ScanSession>>) {
    session.cancel();
}

#[tauri::command]
pub fn get_scan_result(session: State<'_, Arc<ScanSession>>) -> Option<ScanResult> {
    session.result()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_second_scan_is_refused_while_busy() {
        let session = Arc::new(ScanSession::default());
        let first = session.try_begin().expect("first scan starts");
        assert!(session.is_busy());
        assert!(session.try_begin().is_err());
        drop(first);
        assert!(!session.is_busy());
        assert!(session.try_begin().is_ok());
    }

    #[test]
    fn commands_cancel_reaches_running_scan() {
        let session = Arc::new(ScanSession::default());
        let guard = session.try_begin().unwrap();
        session.cancel();
        assert!(guard.progress.is_cancelled());
    }

    #[test]
    fn commands_event_json_is_tagged() {
        let e = ScanEvent::AccountingDone {
            completed: true,
            accounting_ms: 3,
        };
        assert_eq!(serde_json::to_value(e).unwrap()["kind"], "accounting_done");
        let u = ScanEvent::Accounting(AccountingUpdate {
            node_id: 1,
            exclusive_bytes: 2,
            shared_bytes: 3,
            unverified_files: 0,
            logical_bytes: 5,
        });
        let v = serde_json::to_value(u).unwrap();
        assert_eq!(
            (v["kind"].as_str(), v["node_id"].as_u64()),
            (Some("accounting"), Some(1))
        );
    }
}
