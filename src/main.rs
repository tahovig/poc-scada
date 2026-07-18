use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use poc_scada::detections::{self, Finding, SelectBeforeOperateTracker};
use poc_scada::dnp3;
use poc_scada::pcap;

/// DNP3 protocol deep-packet-inspection tool: analyzes captured SCADA/ICS
/// network traffic (pcap files) and flags security-relevant patterns.
#[derive(Parser)]
#[command(name = "poc-scada", version, about)]
struct Cli {
    /// One or more pcap files to analyze.
    #[arg(required = true)]
    pcap_files: Vec<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let mut total_findings = 0usize;

    for path in &cli.pcap_files {
        println!("poc-scada — DNP3 DPI report");
        println!("file: {}", path.display());
        println!("{}", "-".repeat(60));

        let packets = match pcap::read_pcap(path) {
            Ok(packets) => packets,
            Err(e) => {
                eprintln!("error reading {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };

        let findings = analyze(&packets);
        if findings.is_empty() {
            println!("  no findings");
        } else {
            for finding in &findings {
                println!(
                    "  [!] {:<32} t={:<10} {:<24} {}",
                    finding.rule, finding.ts_sec, finding.flow, finding.message
                );
            }
        }
        println!(
            "\n{} packet(s) analyzed, {} finding(s)\n",
            packets.len(),
            findings.len()
        );
        total_findings += findings.len();
    }

    println!("{}", "=".repeat(60));
    println!(
        "total: {total_findings} finding(s) across {} file(s)",
        cli.pcap_files.len()
    );

    ExitCode::SUCCESS
}

fn analyze(packets: &[pcap::Packet]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut select_operate_tracker = SelectBeforeOperateTracker::default();

    for packet in packets {
        for msg in dnp3::find_dnp3_messages(&packet.payload) {
            if let Some(finding) =
                detections::check_dangerous_function_code(&msg, packet.flow, packet.ts_sec)
            {
                findings.push(finding);
            }
            if let Some(finding) = select_operate_tracker.check(&msg, packet.flow, packet.ts_sec) {
                findings.push(finding);
            }
        }
    }

    findings
}
