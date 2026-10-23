//! Dev-only CLI over the same core as the app (D10). Not part of the installer.
//!
//! cargo run --release --example scan -- --list
//! cargo run --release --example scan -- --target user_home [--json] [--threshold-mib N]

use std::process::ExitCode;
use std::sync::Arc;

use clearcache_lib::core::accounting::Win32Opener;
use clearcache_lib::core::scan::progress::{Progress, ProgressSink, Reporter, ScanProgress};
use clearcache_lib::core::scan::{self, syncroots, ScanConfig, DEFAULT_THRESHOLD};
use clearcache_lib::core::targets;

struct Stderr;
impl ProgressSink for Stderr {
    fn emit(&self, p: ScanProgress) {
        if p.done || p.elapsed_ms % 2000 < 200 {
            eprintln!(
                "[{:?}] {} files, {:.2} GiB, {} ms",
                p.phase,
                p.files,
                p.bytes as f64 / scan::GIB as f64,
                p.elapsed_ms
            );
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().any(|a| a == name);
    let value = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    if flag("--list") {
        for t in targets::list_scan_targets() {
            println!("{:<12} {:<16} {}", t.id, t.label, t.root_display);
        }
        return ExitCode::SUCCESS;
    }
    let Some(id) = value("--target") else {
        eprintln!("usage: scan --list | --target <id> [--json] [--threshold-mib N]");
        return ExitCode::from(2);
    };
    let target = match targets::resolve_current(&id) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let threshold = value("--threshold-mib")
        .and_then(|v| v.parse::<u64>().ok())
        .map(|m| m << 20)
        .unwrap_or(DEFAULT_THRESHOLD);

    let cfg = ScanConfig::for_target(&target, threshold);
    let sync = syncroots::detect_system();
    let progress = Progress::new();
    let result = {
        let _r = Reporter::start(progress.clone(), Arc::new(Stderr));
        scan::scan_blocking(&cfg, &sync, &Win32Opener, &progress)
    };
    let Some(result) = result else {
        eprintln!("cancelled");
        return ExitCode::FAILURE;
    };
    scan::append_scan_log(&result.summary);

    let s = &result.summary;
    eprintln!(
        "target={} files={} total={:.2} GiB walk={} ms accounting={:?} ({} ms) skipped={} cloud_only={}",
        s.target_id,
        s.files,
        s.total_logical_bytes as f64 / scan::GIB as f64,
        s.elapsed_ms,
        s.accounting_status,
        s.accounting_ms.unwrap_or(0),
        s.skipped_count,
        s.cloud_only_files
    );

    if flag("--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("serialize")
        );
    } else {
        let depth = |mut id: u32| {
            let mut d = 0;
            while let Some(p) = result.nodes[id as usize].parent_id {
                id = p;
                d += 1;
            }
            d
        };
        for n in &result.nodes {
            let gib = |b: Option<u64>| {
                b.map(|b| format!("{:.2}", b as f64 / scan::GIB as f64))
                    .unwrap_or_else(|| "—".into())
            };
            println!(
                "{}{}  {} GiB  excl={} shared={} {:?}{}",
                "  ".repeat(depth(n.id)),
                n.name,
                gib(n.logical_bytes),
                gib(n.exclusive_bytes),
                gib(n.shared_bytes),
                n.accounting,
                if n.partial {
                    format!("  (일부만 측정: {})", n.skipped_descendants)
                } else {
                    String::new()
                }
            );
        }
    }
    ExitCode::SUCCESS
}
