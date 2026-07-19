mod dangerous_function_code;
mod select_before_operate;

pub use dangerous_function_code::check as check_dangerous_function_code;
pub use select_before_operate::SelectBeforeOperateTracker;

use crate::pcap::Flow;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub message: String,
    pub ts_sec: u32,
    pub flow: Flow,
}
