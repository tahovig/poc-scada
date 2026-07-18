use std::collections::HashMap;

use super::Finding;
use crate::dnp3::{Dnp3Message, FunctionCode};
use crate::pcap::Flow;

/// Tracks, per (dnp3_src, dnp3_dest) pair, whether the most recent message
/// was a Select — so an Operate can be checked against the select-before-operate
/// safety pattern real utility control systems rely on. Direct Operate is
/// intentionally not checked here: it bypasses select by design and is
/// already covered by the dangerous-function-code detection.
#[derive(Default)]
pub struct SelectBeforeOperateTracker {
    last_was_select: HashMap<(u16, u16), bool>,
}

impl SelectBeforeOperateTracker {
    pub fn check(&mut self, msg: &Dnp3Message, flow: Flow, ts_sec: u32) -> Option<Finding> {
        let key = (msg.src, msg.dest);
        let preceded_by_select = self.last_was_select.get(&key).copied().unwrap_or(false);

        let finding = (msg.function == FunctionCode::Operate && !preceded_by_select).then(|| {
            Finding {
                rule: "select-before-operate-violation",
                message: format!(
                    "Operate (dnp3 dest={}, src={}) not immediately preceded by a Select from the same pair",
                    msg.dest, msg.src
                ),
                ts_sec,
                flow,
            }
        });

        self.last_was_select
            .insert(key, msg.function == FunctionCode::Select);
        finding
    }
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

    fn msg(function: FunctionCode) -> Dnp3Message {
        Dnp3Message {
            dest: 10,
            src: 1,
            function,
        }
    }

    #[test]
    fn flags_bare_operate() {
        let mut tracker = SelectBeforeOperateTracker::default();
        let finding = tracker.check(&msg(FunctionCode::Operate), flow(), 0);
        assert!(finding.is_some());
    }

    #[test]
    fn allows_select_then_operate() {
        let mut tracker = SelectBeforeOperateTracker::default();
        assert!(
            tracker
                .check(&msg(FunctionCode::Select), flow(), 0)
                .is_none()
        );
        assert!(
            tracker
                .check(&msg(FunctionCode::Operate), flow(), 1)
                .is_none()
        );
    }

    #[test]
    fn flags_operate_after_intervening_message() {
        let mut tracker = SelectBeforeOperateTracker::default();
        tracker.check(&msg(FunctionCode::Select), flow(), 0);
        tracker.check(&msg(FunctionCode::Read), flow(), 1);
        let finding = tracker.check(&msg(FunctionCode::Operate), flow(), 2);
        assert!(finding.is_some());
    }

    #[test]
    fn tracks_pairs_independently() {
        let mut tracker = SelectBeforeOperateTracker::default();
        tracker.check(&msg(FunctionCode::Select), flow(), 0);

        let other = Dnp3Message {
            dest: 20,
            src: 1,
            function: FunctionCode::Operate,
        };
        let finding = tracker.check(&other, flow(), 1);
        assert!(finding.is_some());
    }
}
