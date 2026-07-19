pub mod application;
pub mod link;
pub mod transport;

pub use application::FunctionCode;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Dnp3Message {
    pub dest: u16,
    pub src: u16,
    pub function: FunctionCode,
}

/// Scans a TCP/UDP payload for DNP3 link frames and decodes each into a
/// `Dnp3Message`, lazily. Non-DNP3 bytes (scanner probes, other protocols
/// sharing port 20000, etc.) are skipped by sliding forward one byte at a
/// time until the next `0x05 0x64` sync pattern.
pub fn find_dnp3_messages(payload: &[u8]) -> impl Iterator<Item = Dnp3Message> + '_ {
    let mut offset = 0;

    std::iter::from_fn(move || {
        while offset < payload.len() {
            let Some(frame) = link::parse_link_frame(&payload[offset..]) else {
                offset += 1;
                continue;
            };
            offset += frame.consumed.max(1);

            if let Some(segment) = transport::parse_transport_segment(&frame)
                && let Some(header) = application::parse_application_header(segment.app_data)
            {
                return Some(Dnp3Message {
                    dest: frame.dest,
                    src: frame.src,
                    function: header.function,
                });
            }
            // Valid link frame, but no usable application message inside
            // (e.g. a link-status probe with no payload) — keep scanning.
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_message_in_noisy_payload() {
        let cold_restart_frame: [u8; 17] = [
            0x05, 0x64, 0x0a, 0xc0, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc0, 0xc0, 0x0d, 0x00,
            0x00, 0x00, 0x00,
        ];
        let mut payload = b"GET / HTTP/1.0\r\n\r\n".to_vec();
        payload.extend_from_slice(&cold_restart_frame);

        let messages: Vec<_> = find_dnp3_messages(&payload).collect();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].function, FunctionCode::ColdRestart);
        assert_eq!(messages[0].dest, 10);
        assert_eq!(messages[0].src, 1);
    }

    #[test]
    fn no_sync_bytes_returns_empty() {
        assert!(find_dnp3_messages(b"not dnp3 at all").next().is_none());
    }
}
