const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Color assigned per detection rule: red for function codes that take
/// direct, disruptive control action (Cold/Warm Restart, Direct Operate),
/// yellow for a protocol-safety violation that's serious but isn't itself
/// an active disruptive command.
fn rule_color(rule: &str) -> &'static str {
    match rule {
        "dangerous-function-code" => RED,
        "select-before-operate-violation" => YELLOW,
        _ => "",
    }
}

/// Wraps `text` in the color assigned to `rule`, unless `enabled` is false
/// (piped/non-terminal output) or the rule has no assigned color.
///
/// Takes the already-formatted (e.g. padded) text separately from the rule
/// used to pick the color, since wrapping *after* padding is required —
/// padding a string that already contains ANSI escape bytes miscounts
/// their length as visible width and breaks column alignment.
pub fn colorize(text: &str, rule: &str, enabled: bool) -> String {
    let color = rule_color(rule);
    if !enabled || color.is_empty() {
        text.to_string()
    } else {
        format!("{color}{text}{RESET}")
    }
}

pub fn bold(text: &str, enabled: bool) -> String {
    if enabled {
        format!("{BOLD}{text}{RESET}")
    } else {
        text.to_string()
    }
}
