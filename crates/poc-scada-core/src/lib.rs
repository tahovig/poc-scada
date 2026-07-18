pub mod detections;
pub mod dnp3;
pub mod pcap;

use std::path::Path;

/// A single DNP3 message observed in the capture, timestamped and tied to
/// the TCP/UDP flow it arrived on. This is the event stream a UI would
/// animate — every message, not just the ones that triggered a finding.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageEvent {
    pub ts_sec: u32,
    pub flow: pcap::Flow,
    pub message: dnp3::Dnp3Message,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisReport {
    pub file: String,
    pub packet_count: usize,
    pub messages: Vec<MessageEvent>,
    pub findings: Vec<detections::Finding>,
}

/// Runs the full pipeline — read pcap, extract DNP3 messages, run both
/// detections — shared by the CLI and the Tauri desktop app so the two
/// front ends can't drift out of sync with each other.
pub fn analyze_pcap(path: &Path) -> Result<AnalysisReport, pcap::Error> {
    let packets = pcap::read_pcap(path)?;

    let mut messages = Vec::new();
    let mut findings = Vec::new();
    let mut select_operate_tracker = detections::SelectBeforeOperateTracker::default();

    for packet in &packets {
        for message in dnp3::find_dnp3_messages(&packet.payload) {
            findings.extend(detections::check_dangerous_function_code(
                &message,
                packet.flow,
                packet.ts_sec,
            ));
            findings.extend(select_operate_tracker.check(&message, packet.flow, packet.ts_sec));

            messages.push(MessageEvent {
                ts_sec: packet.ts_sec,
                flow: packet.flow,
                message,
            });
        }
    }

    Ok(AnalysisReport {
        file: path.display().to_string(),
        packet_count: packets.len(),
        messages,
        findings,
    })
}
