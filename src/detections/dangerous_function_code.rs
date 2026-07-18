use super::Finding;
use crate::dnp3::{Dnp3Message, FunctionCode};
use crate::pcap::Flow;

/// Function codes that are rare in normal DNP3 polling traffic (dominated by
/// Read/Response) and carry real operational consequences when present:
/// restarting an outstation, or operating a control point without the
/// select/operate safety pattern.
const DANGEROUS: &[FunctionCode] = &[
    FunctionCode::ColdRestart,
    FunctionCode::WarmRestart,
    FunctionCode::DirectOperate,
    FunctionCode::DirectOperateNoAck,
];

pub fn check(msg: &Dnp3Message, flow: Flow, ts_sec: u32) -> Option<Finding> {
    if !DANGEROUS.contains(&msg.function) {
        return None;
    }

    Some(Finding {
        rule: "dangerous-function-code",
        message: format!(
            "{:?} function code seen (dnp3 dest={}, src={})",
            msg.function, msg.dest, msg.src
        ),
        ts_sec,
        flow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow() -> Flow {
        Flow {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 20000,
        }
    }

    #[test]
    fn flags_cold_restart() {
        let msg = Dnp3Message {
            dest: 10,
            src: 1,
            function: FunctionCode::ColdRestart,
        };
        assert!(check(&msg, flow(), 0).is_some());
    }

    #[test]
    fn ignores_read() {
        let msg = Dnp3Message {
            dest: 10,
            src: 1,
            function: FunctionCode::Read,
        };
        assert!(check(&msg, flow(), 0).is_none());
    }
}
