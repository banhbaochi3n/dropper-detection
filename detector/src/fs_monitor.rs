use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use notify::{watcher, DebouncedEvent, RecursiveMode, Watcher};
use threadpool::ThreadPool;

use crate::engine::Engine;
use crate::report::Report;
use crate::Arguments;

pub(crate) fn start(args: Arguments, engine: Engine, report: Report) -> Result<(), String> {
    log::info!("Initializing filesystem monitor for '{}' ...", &args.root);

    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::ZERO).map_err(|e| e.to_string())?;

    watcher
        .watch(&args.root, RecursiveMode::Recursive)
        .map_err(|e| e.to_string())?;

    log::info!("Initializing pool with {} workers ...", args.workers);

    let pool = ThreadPool::new(args.workers);

    log::info!("Running ...");

    let engine = Arc::new(engine);
    let report = Arc::new(Mutex::new(report));

    // Receive filesystem events
    loop {
        match rx.recv() {
            Ok(event) => match event {
                // Monitoring file-creation and modification events
                DebouncedEvent::Create(path)
                | DebouncedEvent::NoticeWrite(path)
                | DebouncedEvent::Write(path)
                | DebouncedEvent::Rename(_, path) => {
                    if path.is_file() && path.exists() {
                        // create thread safe references
                        let engine = engine.clone();
                        let report = report.clone();

                        // Submit scan job to the threads pool
                        pool.execute(move || {
                            // Perform the scanning
                            let res = engine.scan(&path);
                            // Handle reporting
                            if let Ok(mut report) = report.lock() {
                                if let Err(e) = report.report(res) {
                                    log::error!("Reporting error: {:?}", e);
                                }
                            }
                        });
                    }
                }
                DebouncedEvent::NoticeRemove(path) => {
                    log::trace!("Ignoring remove event for {:?}", path);
                }
                DebouncedEvent::Chmod(path) => {
                    log::trace!("Ignoring chmod event for {:?}", path);
                }
                DebouncedEvent::Remove(path) => {
                    log::trace!("Ignoring remove event for {:?}", path);
                }
                DebouncedEvent::Rescan => {
                    log::debug!("Rescan");
                }
                DebouncedEvent::Error(error, maybe_path) => {
                    log::error!("Error for {:?}: {:?}", maybe_path, error);
                }
            },
            Err(e) => log::error!("Filesystem monitoring error: {:?}", e),
        }
    }
}
