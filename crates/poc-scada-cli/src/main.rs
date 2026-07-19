use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

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

        let report = match poc_scada_core::analyze_pcap(path) {
            Ok(report) => report,
            Err(e) => {
                eprintln!("error reading {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };

        if report.findings.is_empty() {
            println!("  no findings");
        } else {
            for finding in &report.findings {
                println!(
                    "  [!] {:<32} t={:<10} {:<24} {}",
                    finding.rule, finding.ts_sec, finding.flow, finding.message
                );
            }
        }
        println!(
            "\n{} packet(s) analyzed, {} finding(s)\n",
            report.packet_count,
            report.findings.len()
        );
        total_findings += report.findings.len();
    }

    println!("{}", "=".repeat(60));
    println!(
        "total: {total_findings} finding(s) across {} file(s)",
        cli.pcap_files.len()
    );

    ExitCode::SUCCESS
}
