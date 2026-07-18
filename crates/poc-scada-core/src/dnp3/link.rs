const START1: u8 = 0x05;
const START2: u8 = 0x64;
const HEADER_LEN: usize = 10;
const MAX_USER_DATA_BLOCK: usize = 16;

#[derive(Debug, Clone)]
pub struct LinkFrame {
    pub control: u8,
    pub dest: u16,
    pub src: u16,
    /// User data with per-block CRCs already stripped.
    pub user_data: Vec<u8>,
    /// Total bytes this frame consumed from `data`, so callers can advance past it.
    pub consumed: usize,
}

/// Parses a single DNP3 link-layer frame starting at a `0x05 0x64` sync pattern.
///
/// Returns `None` if `data` doesn't start with the sync bytes or is too short
/// to contain a complete frame (e.g. a TCP segment boundary split a frame).
pub fn parse_link_frame(data: &[u8]) -> Option<LinkFrame> {
    if data.len() < HEADER_LEN || data[0] != START1 || data[1] != START2 {
        return None;
    }

    let link_len = data[2] as usize;
    if link_len < 5 {
        return None;
    }
    let user_data_len = link_len - 5;

    let control = data[3];
    let dest = u16::from_le_bytes([data[4], data[5]]);
    let src = u16::from_le_bytes([data[6], data[7]]);
    // data[8..10] is the header CRC; not validated in v1.

    let mut user_data = Vec::with_capacity(user_data_len);
    let mut remaining = user_data_len;
    let mut offset = HEADER_LEN;

    while remaining > 0 {
        let block_len = remaining.min(MAX_USER_DATA_BLOCK);
        let block_end = offset + block_len;
        let crc_end = block_end + 2;
        if data.len() < crc_end {
            return None;
        }
        user_data.extend_from_slice(&data[offset..block_end]);
        // data[block_end..crc_end] is the block CRC; not validated in v1.
        offset = crc_end;
        remaining -= block_len;
    }

    Some(LinkFrame {
        control,
        dest,
        src,
        user_data,
        consumed: offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cold_restart_frame() {
        // dest=10 src=1, control=0xc0, 5 bytes of user data (transport + app_ctrl + func)
        let raw = [
            0x05, 0x64, 0x0a, 0xc0, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, // header + crc
            0xc0, 0xc0, 0x0d, 0x00, 0x00, // 5 bytes user data
            0x00, 0x00, // block crc
        ];
        let frame = parse_link_frame(&raw).expect("should parse");
        assert_eq!(frame.dest, 10);
        assert_eq!(frame.src, 1);
        assert_eq!(frame.user_data, vec![0xc0, 0xc0, 0x0d, 0x00, 0x00]);
        assert_eq!(frame.consumed, raw.len());
    }

    #[test]
    fn rejects_missing_sync_bytes() {
        let raw = [0x00; 20];
        assert!(parse_link_frame(&raw).is_none());
    }

    #[test]
    fn rejects_truncated_frame() {
        let raw = [0x05, 0x64, 0x0a, 0xc0, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert!(parse_link_frame(&raw).is_none());
    }
}
