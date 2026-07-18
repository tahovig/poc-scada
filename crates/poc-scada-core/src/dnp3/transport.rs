const FIN_MASK: u8 = 0b0100_0000;
const FIR_MASK: u8 = 0b1000_0000;

#[derive(Debug, Clone)]
pub struct TransportSegment<'a> {
    pub fir: bool,
    pub fin: bool,
    pub sequence: u8,
    pub app_data: &'a [u8],
}

/// Parses the transport header from a link frame's user data.
///
/// DNP3 application fragments can span multiple link frames when FIR/FIN
/// aren't both set; reassembling across frames isn't implemented in v1
/// since the fixture and target traffic here are single-frame requests.
pub fn parse_transport_segment(user_data: &[u8]) -> Option<TransportSegment<'_>> {
    let header = *user_data.first()?;
    Some(TransportSegment {
        fir: header & FIR_MASK != 0,
        fin: header & FIN_MASK != 0,
        sequence: header & 0b0011_1111,
        app_data: &user_data[1..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_frame_segment() {
        let user_data = [0xc0, 0xc0, 0x0d, 0x00, 0x00];
        let seg = parse_transport_segment(&user_data).expect("should parse");
        assert!(seg.fir);
        assert!(seg.fin);
        assert_eq!(seg.sequence, 0);
        assert_eq!(seg.app_data, &[0xc0, 0x0d, 0x00, 0x00]);
    }

    #[test]
    fn empty_user_data_returns_none() {
        assert!(parse_transport_segment(&[]).is_none());
    }
}
