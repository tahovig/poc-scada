#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum FunctionCode {
    Confirm,
    Read,
    Write,
    Select,
    Operate,
    DirectOperate,
    DirectOperateNoAck,
    ImmediateFreeze,
    ImmediateFreezeNoAck,
    FreezeAndClear,
    FreezeAndClearNoAck,
    ColdRestart,
    WarmRestart,
    Response,
    UnsolicitedResponse,
    Other(u8),
}

impl FunctionCode {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Confirm,
            1 => Self::Read,
            2 => Self::Write,
            3 => Self::Select,
            4 => Self::Operate,
            5 => Self::DirectOperate,
            6 => Self::DirectOperateNoAck,
            7 => Self::ImmediateFreeze,
            8 => Self::ImmediateFreezeNoAck,
            9 => Self::FreezeAndClear,
            10 => Self::FreezeAndClearNoAck,
            13 => Self::ColdRestart,
            14 => Self::WarmRestart,
            129 => Self::Response,
            130 => Self::UnsolicitedResponse,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ApplicationHeader {
    pub function: FunctionCode,
}

/// Parses the DNP3 application-layer header (control byte + function code)
/// from a transport segment's application data.
///
/// Object headers/payload following the function code aren't parsed in v1 —
/// the current detections only need the function code.
pub fn parse_application_header(app_data: &[u8]) -> Option<ApplicationHeader> {
    // app_data[0] is the application control byte (FIR/FIN/CON/UNS + sequence);
    // not needed by current detections.
    let function_byte = *app_data.get(1)?;
    Some(ApplicationHeader {
        function: FunctionCode::from_byte(function_byte),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cold_restart() {
        let app_data = [0xc0, 0x0d, 0x00, 0x00];
        let header = parse_application_header(&app_data).expect("should parse");
        assert_eq!(header.function, FunctionCode::ColdRestart);
    }

    #[test]
    fn parses_direct_operate() {
        let app_data = [0xc0, 0x05];
        let header = parse_application_header(&app_data).expect("should parse");
        assert_eq!(header.function, FunctionCode::DirectOperate);
    }

    #[test]
    fn too_short_returns_none() {
        assert!(parse_application_header(&[0xc0]).is_none());
    }
}
