mod color;
mod spinner;

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use poc_scada_core::detections::Finding;

/// DNP3 protocol deep-packet-inspection tool: analyzes captured SCADA/ICS
/// network traffic (pcap files) and flags security-relevant patterns.
#[derive(Parser)]
#[command(name = "poc-scada", version, about)]
struct Cli {
    /// One or more pcap files to analyze.
    #[arg(required = true)]
    pcap_files: Vec<PathBuf>,

    /// Group findings by rule instead of listing them chronologically.
    #[arg(long)]
    group_by_rule: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let color_enabled = std::io::stdout().is_terminal();

    let mut total_findings = 0usize;

    for path in &cli.pcap_files {
        println!("poc-scada — DNP3 DPI report");
        println!("file: {}", path.display());
        println!("{}", "-".repeat(60));

        let report = spinner::with_spinner(&format!("analyzing {}...", path.display()), || {
            poc_scada_core::analyze_pcap(path)
        });
        let report = match report {
            Ok(report) => report,
            Err(e) => {
                eprintln!("error reading {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };

        print_findings(&report.findings, cli.group_by_rule, color_enabled);

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

fn print_findings(findings: &[Finding], group_by_rule: bool, color_enabled: bool) {
    if findings.is_empty() {
        println!("  no findings");
        return;
    }

    if !group_by_rule {
        for finding in findings {
            let rule = color::colorize(
                &format!("{:<32}", finding.rule),
                finding.rule,
                color_enabled,
            );
            println!(
                "  [!] {rule} t={:<10} {:<24} {}",
                finding.ts_sec, finding.flow, finding.message
            );
        }
        return;
    }

    let mut by_rule: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        by_rule.entry(finding.rule).or_default().push(finding);
    }

    for (rule, group) in &by_rule {
        let heading = color::colorize(
            &color::bold(&format!("{rule} ({})", group.len()), color_enabled),
            rule,
            color_enabled,
        );
        println!("  {heading}");
        for finding in group {
            println!(
                "    t={:<10} {:<24} {}",
                finding.ts_sec, finding.flow, finding.message
            );
        }
    }
}
