use std::io::{self, IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const FRAMES: [char; 4] = ['|', '/', '-', '\\'];
const TICK: Duration = Duration::from_millis(80);

/// Runs `f` on the current thread, showing a simple spinner on stdout for
/// as long as it's running. Skipped entirely for non-terminal
/// (piped/redirected) output, same policy as `color`.
///
/// Real captures can take a moment to analyze; this is purely "still
/// working" feedback, not a per-packet progress bar — that would need
/// `analyze_pcap` itself to report progress, which isn't worth the API
/// surface for what's still a batch CLI tool.
pub fn with_spinner<T>(message: &str, f: impl FnOnce() -> T) -> T {
    if !io::stdout().is_terminal() {
        return f();
    }

    let done = Arc::new(AtomicBool::new(false));
    let done_clone = Arc::clone(&done);
    let message = message.to_string();

    let handle = thread::spawn(move || {
        let mut i = 0usize;
        while !done_clone.load(Ordering::Relaxed) {
            print!("\r{} {message}", FRAMES[i % FRAMES.len()]);
            let _ = io::stdout().flush();
            i += 1;
            thread::sleep(TICK);
        }
        print!("\r{}\r", " ".repeat(message.len() + 2));
        let _ = io::stdout().flush();
    });

    let result = f();
    done.store(true, Ordering::Relaxed);
    let _ = handle.join();
    result
}
