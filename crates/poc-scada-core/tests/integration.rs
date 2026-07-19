use std::path::{Path, PathBuf};

use etherparse::PacketBuilder;
use poc_scada_core::detections::Finding;

fn fixture(relative: &str) -> PathBuf {
    // Repo root's data/ dir, two levels up from this crate.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(relative)
}

fn findings_for(path: &Path) -> Vec<Finding> {
    poc_scada_core::analyze_pcap(path)
        .expect("fixture should parse")
        .findings
}

fn assert_rule_fires(path: &Path, rule: &str) {
    let findings = findings_for(path);
    assert!(
        findings.iter().any(|f| f.rule == rule),
        "expected rule {rule} to fire for {}, findings: {findings:?}",
        path.display()
    );
}

fn assert_no_findings(path: &Path) {
    let findings = findings_for(path);
    assert!(
        findings.is_empty(),
        "expected no findings for {}, got: {findings:?}",
        path.display()
    );
}

#[test]
fn cold_restart_fixture_flags_dangerous_function_code() {
    assert_rule_fires(
        &fixture("dnp3-iti/cold_restart_and_response.pcap"),
        "dangerous-function-code",
    );
}

#[test]
fn warm_restart_fixture_flags_dangerous_function_code() {
    assert_rule_fires(
        &fixture("dnp3-iti/warm_restart_and_response.pcap"),
        "dangerous-function-code",
    );
}

#[test]
fn direct_operate_fixture_flags_dangerous_function_code() {
    assert_rule_fires(
        &fixture("dnp3-iti/directoperate_and_response.pcap"),
        "dangerous-function-code",
    );
}

#[test]
fn direct_operate_no_ack_fixture_flags_dangerous_function_code() {
    assert_rule_fires(
        &fixture("dnp3-iti/direct_operate_no_ack_crob.pcap"),
        "dangerous-function-code",
    );
}

#[test]
fn direct_operate_with_malformed_crob_still_flags_dangerous_function_code() {
    // The malformed CROB object payload doesn't matter to this detection:
    // the function code lives in the first 3 bytes of user data (transport
    // header, app control, function), well before any object-header/payload
    // bytes we don't parse. A malformed object shouldn't be able to hide a
    // dangerous function code from us.
    assert_rule_fires(
        &fixture("dnp3-iti/direct_operate_crob_malform_but_good_crc.pcap"),
        "dangerous-function-code",
    );
}

#[test]
fn direct_operate_aggressive_mode_still_flags_dangerous_function_code() {
    // DNP3 Secure Authentication's aggressive mode appends a MAC directly
    // after the object data in the same application fragment. Same
    // reasoning as the malformed-CROB case above: the function code is read
    // long before that trailer, so it shouldn't affect detection.
    assert_rule_fires(
        &fixture("dnp3-iti/operate_aggressive_mode.pcap"),
        "dangerous-function-code",
    );
}

#[test]
fn select_then_operate_fixture_has_no_findings() {
    assert_no_findings(&fixture("dnp3-iti/select_operate_and_responses.pcap"));
}

#[test]
fn plain_read_fixture_has_no_findings() {
    assert_no_findings(&fixture("dnp3-iti/read_and_response.pcap"));
}

#[test]
fn sics_noise_sample_has_no_false_positives() {
    assert_no_findings(&fixture("4sics/4SICS-GeekLounge-151022-sample.pcap"));
}

#[test]
fn bare_operate_flags_select_before_operate_violation() {
    // The public ITI/4SICS fixtures don't happen to contain a bare Operate
    // (function 4) unpaired with a preceding Select, so this constructs a
    // minimal synthetic pcap end-to-end to exercise that path.
    let dnp3_frame: [u8; 17] = [
        0x05, 0x64, 0x0a, 0xc4, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, // link header + crc
        0xc0, 0xc0, 0x04, 0x00, 0x00, // transport + app_ctrl + func=Operate
        0x00, 0x00, // block crc
    ];
    let path = write_temp_pcap("bare_operate", &dnp3_frame);

    assert_rule_fires(&path, "select-before-operate-violation");

    std::fs::remove_file(path).ok();
}

fn write_temp_pcap(name: &str, tcp_payload: &[u8]) -> PathBuf {
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 64)
        .tcp(49152, 20000, 0, 65535);

    let mut packet = Vec::with_capacity(builder.size(tcp_payload.len()));
    builder.write(&mut packet, tcp_payload).unwrap();

    let mut file_bytes = Vec::new();
    // Legacy pcap global header, microsecond resolution, Ethernet linktype.
    file_bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    file_bytes.extend_from_slice(&2u16.to_le_bytes());
    file_bytes.extend_from_slice(&4u16.to_le_bytes());
    file_bytes.extend_from_slice(&0i32.to_le_bytes());
    file_bytes.extend_from_slice(&0u32.to_le_bytes());
    file_bytes.extend_from_slice(&65535u32.to_le_bytes());
    file_bytes.extend_from_slice(&1u32.to_le_bytes());

    file_bytes.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    file_bytes.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    file_bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // incl_len
    file_bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // orig_len
    file_bytes.extend_from_slice(&packet);

    let path =
        std::env::temp_dir().join(format!("poc-scada-test-{name}-{}.pcap", std::process::id()));
    std::fs::write(&path, file_bytes).unwrap();
    path
}
