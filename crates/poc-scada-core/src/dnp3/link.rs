const START1: u8 = 0x05;
const START2: u8 = 0x64;
const HEADER_LEN: usize = 10;
const MAX_USER_DATA_BLOCK: usize = 16;

#[derive(Debug, Clone)]
pub struct LinkFrame<'a> {
    pub control: u8,
    pub dest: u16,
    pub src: u16,
    /// The subset of the input covering the user-data blocks and their
    /// CRCs (not the CRCs stripped out — see `user_data_chunks`).
    raw_payload: &'a [u8],
    /// Logical user-data length, excluding block CRCs.
    user_data_len: usize,
    /// Total bytes this frame consumed from `data`, so callers can advance past it.
    pub consumed: usize,
}

impl<'a> LinkFrame<'a> {
    /// Yields each up-to-16-byte user-data block, in order, with its
    /// trailing 2-byte CRC skipped — without copying. Blocks are
    /// discontiguous in memory (each is followed by a CRC that isn't part
    /// of the logical data), so this is an iterator of slices rather than
    /// one combined slice.
    pub fn user_data_chunks(&self) -> impl Iterator<Item = &'a [u8]> {
        let mut remaining = self.user_data_len;
        let mut offset = 0;
        let payload = self.raw_payload;

        std::iter::from_fn(move || {
            if remaining == 0 {
                return None;
            }
            let chunk_len = remaining.min(MAX_USER_DATA_BLOCK);
            let chunk = &payload[offset..offset + chunk_len];
            offset += chunk_len + 2; // skip this block's CRC
            remaining -= chunk_len;
            Some(chunk)
        })
    }
}

/// Parses a single DNP3 link-layer frame starting at a `0x05 0x64` sync pattern.
///
/// Returns `None` if `data` doesn't start with the sync bytes or is too short
/// to contain a complete frame (e.g. a TCP segment boundary split a frame).
///
/// User-data blocks are exposed lazily via `LinkFrame::user_data_chunks`
/// rather than copied into an owned buffer here — DNP3 interleaves a 2-byte
/// CRC every 16 bytes of payload, so there's no single contiguous slice to
/// hand back, and most frames in practice (link-status probes, single
/// small requests) have at most one block anyway. The frame's total byte
/// length is computed directly from the header's length field rather than
/// by walking blocks, since the block/CRC layout is fully determined by
/// that one byte.
pub fn parse_link_frame(data: &[u8]) -> Option<LinkFrame<'_>> {
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

    let block_count = user_data_len.div_ceil(MAX_USER_DATA_BLOCK);
    let payload_len = user_data_len + block_count * 2;
    let consumed = HEADER_LEN + payload_len;
    if data.len() < consumed {
        return None;
    }

    Some(LinkFrame {
        control,
        dest,
        src,
        raw_payload: &data[HEADER_LEN..consumed],
        user_data_len,
        consumed,
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
        assert_eq!(
            frame.user_data_chunks().collect::<Vec<_>>(),
            vec![[0xc0, 0xc0, 0x0d, 0x00, 0x00].as_slice()]
        );
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

    #[test]
    fn zero_length_user_data_has_no_chunks() {
        // Link-status style frame: length byte 5 means user_data_len == 0.
        let raw = [0x05, 0x64, 0x05, 0xc9, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00];
        let frame = parse_link_frame(&raw).expect("should parse");
        assert_eq!(frame.user_data_chunks().count(), 0);
        assert_eq!(frame.consumed, raw.len());
    }

    #[test]
    fn multi_block_frame_yields_chunks_in_order_with_crcs_skipped() {
        // 17 bytes of user data: one full 16-byte block, one 1-byte block.
        let mut raw = vec![0x05, 0x64, 0x16, 0xc0, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00];
        let first_block: Vec<u8> = (0..16).collect();
        let second_block = [0xAA];
        raw.extend_from_slice(&first_block);
        raw.extend_from_slice(&[0x11, 0x22]); // first block's CRC
        raw.extend_from_slice(&second_block);
        raw.extend_from_slice(&[0x33, 0x44]); // second block's CRC

        let frame = parse_link_frame(&raw).expect("should parse");
        let chunks: Vec<&[u8]> = frame.user_data_chunks().collect();
        assert_eq!(
            chunks,
            vec![first_block.as_slice(), second_block.as_slice()]
        );
        assert_eq!(frame.consumed, raw.len());
    }

    #[test]
    fn truncated_second_block_is_rejected() {
        let mut raw = vec![0x05, 0x64, 0x16, 0xc0, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00];
        raw.extend_from_slice(&[0u8; 16]);
        raw.extend_from_slice(&[0x11, 0x22]);
        raw.push(0xAA);
        // missing the second block's trailing CRC bytes
        assert!(parse_link_frame(&raw).is_none());
    }
}
