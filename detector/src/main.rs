use crate::{engine::Engine, report::Report};
use clap::Parser;

mod engine;
mod fs_monitor;
mod fs_scan;
mod report;

fn main() -> Result<(), String> {
    pretty_env_logger::init();

    let args = Arguments::parse();
    let config = engine::Configuration {
        data_path: args.rules.clone(),
        timeout: args.scan_timeout,
    };
    let engine = Engine::new(config).unwrap();
    let report = Report::setup(&args).unwrap();

    if args.scan {
        // perform a scan of the root folder and exit
        fs_scan::start(args, engine, report)
    } else {
        // monitor the filesystem
        fs_monitor::start(args, engine, report)
    }
}

#[derive(Parser, Default, Debug, Clone)]
#[clap(about = "Filesystem monitor for dropper malware using YARA rules.")]
struct Arguments {
    #[clap(long, default_value = "/")]
    root: String,
    #[clap(long)]
    rules: String,
    #[clap(long, default_value_t = num_cpus::get() * 2)]
    workers: usize,
    #[clap(long, default_value_t = 30)]
    scan_timeout: i32,
    #[clap(long, takes_value = false)]
    scan: bool,
    #[clap(long)]
    ext: Vec<String>,
    #[clap(long, takes_value = false)]
    report_clean: bool,
    #[clap(long, takes_value = false)]
    report_errors: bool,
    #[clap(long)]
    report_output: Option<String>,
    #[clap(long, takes_value = false)]
    report_json: bool,
}
