use super::link::LinkFrame;

const FIN_MASK: u8 = 0b0100_0000;
const FIR_MASK: u8 = 0b1000_0000;

#[derive(Debug, Clone)]
pub struct TransportSegment<'a> {
    pub fir: bool,
    pub fin: bool,
    pub sequence: u8,
    pub app_data: &'a [u8],
}

/// Parses the transport header from a link frame's first user-data block.
///
/// Only the first block is read: the transport header, application control
/// byte, and function code always live at user-data offsets 0-2, which is
/// always within the first 16-byte block regardless of how many blocks the
/// frame has. Bytes beyond the first block (larger object payloads) aren't
/// reachable through this API — `LinkFrame::user_data_chunks` exposes them
/// if that's ever needed, but nothing here reassembles across blocks today.
///
/// DNP3 application fragments can also span multiple *link frames* when
/// FIR/FIN aren't both set; reassembling across frames isn't implemented in
/// v1 either, since the fixture and target traffic here are single-frame
/// requests.
pub fn parse_transport_segment<'a>(frame: &LinkFrame<'a>) -> Option<TransportSegment<'a>> {
    let first_block = frame.user_data_chunks().next()?;
    let header = *first_block.first()?;
    Some(TransportSegment {
        fir: header & FIR_MASK != 0,
        fin: header & FIN_MASK != 0,
        sequence: header & 0b0011_1111,
        app_data: &first_block[1..],
    })
}

#[cfg(test)]
mod tests {
    use super::super::link::parse_link_frame;
    use super::*;

    #[test]
    fn parses_single_frame_segment() {
        let raw = [
            0x05, 0x64, 0x0a, 0xc0, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc0, 0xc0, 0x0d, 0x00,
            0x00, 0x00, 0x00,
        ];
        let frame = parse_link_frame(&raw).expect("should parse");
        let seg = parse_transport_segment(&frame).expect("should parse");
        assert!(seg.fir);
        assert!(seg.fin);
        assert_eq!(seg.sequence, 0);
        assert_eq!(seg.app_data, &[0xc0, 0x0d, 0x00, 0x00]);
    }

    #[test]
    fn empty_user_data_returns_none() {
        // Link-status style frame: length byte 5 means user_data_len == 0.
        let raw = [0x05, 0x64, 0x05, 0xc9, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00];
        let frame = parse_link_frame(&raw).expect("should parse");
        assert!(parse_transport_segment(&frame).is_none());
    }
}
