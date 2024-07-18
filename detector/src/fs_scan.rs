use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use threadpool::ThreadPool;
use walkdir::WalkDir;

use crate::engine::Engine;
use crate::report::Report;
use crate::Arguments;

pub(crate) fn start(args: Arguments, engine: Engine, report: Report) -> Result<(), String> {
    log::info!("Initializing pool with {} workers ...", args.workers);

    let pool = ThreadPool::new(args.workers);

    log::info!("Scanning {} ...", &args.root);

    let engine = Arc::new(engine);
    let report = Arc::new(Mutex::new(report));
    let start = Instant::now();
    let num_scanned = Arc::new(AtomicU32::new(0));
    let num_detected = Arc::new(AtomicU32::new(0));

    for entry in WalkDir::new(&args.root)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let f_path = entry.path();
        let mut do_scan = args.ext.is_empty();

        // Filter by file extension
        if !do_scan {
            if let Some(ext) = f_path.extension() {
                for filter_ext in &args.ext {
                    if filter_ext.to_lowercase() == *ext.to_string_lossy().to_lowercase() {
                        do_scan = true;
                        break;
                    }
                }
            }
        }

        if do_scan {
            let an_engine = engine.clone();
            let f_path = f_path.to_path_buf();
            let num_scanned = num_scanned.clone();
            let num_detected = num_detected.clone();
            let report = report.clone();

            pool.execute(move || {
                // perform the scanning
                let res = an_engine.scan(&f_path);
                if res.detected {
                    num_detected.fetch_add(1, Ordering::SeqCst);
                }
                num_scanned.fetch_add(1, Ordering::SeqCst);

                if let Ok(mut report) = report.lock() {
                    if let Err(e) = report.report(res) {
                        log::error!("Reporting error: {:?}", e);
                    }
                }
            });
        }
    }

    pool.join();

    log::info!(
        "{:?} files scanned in {:?}, {:?} positive detections",
        num_scanned,
        start.elapsed(),
        num_detected
    );

    Ok(())
}
