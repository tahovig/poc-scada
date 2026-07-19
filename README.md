# poc-scada — DNP3 Protocol DPI Tool

[![CI](https://github.com/tahovig/poc-scada/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tahovig/poc-scada/actions/workflows/ci.yml)

A Rust CLI that performs deep-packet-inspection on DNP3 (SCADA/ICS protocol)
traffic: reads captured `.pcap` files offline and flags security-relevant
patterns. Built around a background in critical infrastructure protection
(energy generation/transmission/distribution, EMS).

Third in a series of portfolio projects supporting a pivot from software
engineering to cybersecurity engineering. First: [poc-osint](https://github.com/tahovig/poc-osint),
an automated subdomain recon tool. Second: [poc-logids](https://github.com/tahovig/poc-logids),
a log-based SSH brute-force detector.

## Status

Working v1: reads legacy `.pcap` files offline (no live capture — see "Tech
stack" below for why) and checks every DNP3 message found against two
detections:

- **Dangerous function codes** — Cold Restart, Warm Restart, Direct Operate,
  and Direct Operate No Ack are rare in normal polling traffic (dominated by
  Read/Response), so their presence on the wire is a meaningful signal.
- **Select-before-operate violations** — an Operate not immediately preceded
  by a Select from the same master/outstation pair, breaking the safety
  pattern real utility control systems rely on.

```
$ cargo run -- data/dnp3-iti/cold_restart_and_response.pcap data/dnp3-iti/select_operate_and_responses.pcap
poc-scada — DNP3 DPI report
file: data/dnp3-iti/cold_restart_and_response.pcap
------------------------------------------------------------
  [!] dangerous-function-code          t=1422552945 192.168.60.1:49423 -> 192.168.60.130:20000 ColdRestart function code seen (dnp3 dest=10, src=1)

2 packet(s) analyzed, 1 finding(s)

poc-scada — DNP3 DPI report
file: data/dnp3-iti/select_operate_and_responses.pcap
------------------------------------------------------------
  no findings

4 packet(s) analyzed, 0 finding(s)

============================================================
total: 1 finding(s) across 2 file(s)
```

(real captured output, verbatim). "2 packet(s) analyzed" for a file that
looks small on disk is expected, not a bug: the test fixtures in
`data/dnp3-iti/` are purpose-built, one-function-per-file captures (a full
TCP handshake + one DNP3 request/response + teardown), and the packet count
poc-scada reports only counts TCP/UDP packets carrying a non-empty payload —
handshake/ACK/teardown packets are correctly excluded. Point it at a real
multi-hour SCADA capture and the count scales accordingly. See `data/README.md`
for exactly what each fixture contains and how it was verified.

A Tauri desktop UI was prototyped on top of this backend and abandoned — see
`CLAUDE.md` for why. Current direction is a richer terminal/ASCII
presentation instead, in keeping with this project's CLI-first style:
findings are colored by rule (red for dangerous function codes, yellow for
select-before-operate violations) on a real terminal — a markdown code
block can't show that, so the examples above/below are the plain-text form
piped output also gets — and a spinner runs while a file is being analyzed.
Both are skipped automatically for non-terminal output (piped, redirected,
CI logs), same policy `poc-logids` uses.

## Usage

```
cargo build --release -p poc-scada-cli
./target/release/poc-scada <PCAP_FILE> [PCAP_FILE ...] [--group-by-rule]
```

Multiple pcap files can be passed at once; each is reported separately, with
a combined total at the end. Both detections always run — there's no flag
to disable either. `--group-by-rule` switches the findings list from
chronological order to grouped-by-rule (each rule as a heading with its
matching findings underneath); default stays chronological.

## How it works

A few decisions worth calling out, since they came from real
investigation rather than being obvious upfront:

- **The spinner is "still working" feedback, not a per-packet progress
  bar.** `analyze_pcap` doesn't report progress as it runs — the spinner
  (`crates/poc-scada-cli/src/spinner.rs`) just ticks on a background thread
  for as long as the call is in flight, joined the moment it returns. A real
  progress bar would need `analyze_pcap` itself to expose incremental
  progress, which isn't worth the API surface for what's still a batch CLI
  tool, and would cut against the same lesson the Tauri attempt taught:
  don't add motion/pacing that isn't earning its keep.
- **Rule colors are a deliberate two-tier split, not an arbitrary palette.**
  Dangerous function codes (Cold/Warm Restart, Direct Operate) are red
  because they're direct, disruptive control actions; select-before-operate
  violations are yellow because they're a real protocol-safety violation
  but not themselves an active disruptive command. See
  `crates/poc-scada-cli/src/color.rs`.
- **DNP3 parsing is hand-rolled**, not from a crate — no mature Rust DNP3
  parser exists. `crates/poc-scada-core/src/dnp3/` implements just enough of
  the link, transport, and application layers (start bytes,
  length/control/address fields, transport segment header, function code) to
  support the two detections; object-header/payload parsing and multi-frame
  transport reassembly across TCP segments are intentionally out of scope
  for v1 (see doc comments in `dnp3/transport.rs`).
- **Parsing and pcap reading are both zero-copy/streaming**, not because it's
  needed for the fixture-sized pcaps used here, but because it's the honest
  way to write a DPI tool: `LinkFrame` borrows from the original packet
  bytes instead of allocating per frame, and `pcap::read_pcap` decodes one
  packet at a time as an iterator instead of reading the whole capture into
  memory before analysis starts — a multi-hour real SCADA capture shouldn't
  need to fit twice in RAM just to be scanned once. See `CLAUDE.md`'s
  "algorithmic/complexity refactor tangent" entry for the detail on what
  changed and why (including where the design deliberately still
  allocates, and why that's fine).
- **The public 4SICS ICS Lab dataset was checked and mostly rejected** as a
  detection-validation source. Of Netresec's three public 4SICS captures,
  one has zero DNP3 traffic (dominated by S7comm), one has port-20000
  traffic that turned out to be scanner noise (Oracle TNS `CONNECT_DATA`,
  raw HTTP `GET /`) rather than DNP3, and the third has only 36 genuine DNP3
  frames — all "Request Link Status" link-layer probes with zero
  application-layer payload, so no Select/Operate/Restart traffic anywhere
  in it. It's kept in `data/4sics/` purely as a non-DNP3-heavy background
  fixture to confirm the tool doesn't false-positive on realistic noise; the
  actual detections are validated against
  [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools)'s
  per-function DNP3 pcaps instead. Full writeup in `data/README.md`.
- **Select-before-operate deliberately doesn't flag Direct Operate.** Direct
  Operate (function code 5) bypasses the select/operate handshake by design
  — that's not a bug in a captured session, it's what the function code
  means — so flagging it there too would double-count the same event under
  two rules. It's covered by the dangerous-function-code check instead.
- **Link/block CRCs aren't validated.** DNP3 frames carry a CRC over the
  header and every 16-byte block of user data; poc-scada strips them during
  reassembly but doesn't check them. Fine for the purpose-built fixtures
  used so far, but a real capture with bit errors or a deliberately malformed
  frame could parse as something other than what was actually on the wire —
  worth revisiting if malformed-frame detection becomes an explicit goal.

## Repo structure

- `crates/poc-scada-core/` — the DPI logic, as a library
  - `src/pcap.rs` — reads legacy `.pcap` files and unwraps Ethernet/IP/TCP/UDP
    down to the raw payload (`pcap-parser` + `etherparse`)
  - `src/dnp3/` — hand-rolled DNP3 link/transport/application-layer parsing
  - `src/detections/` — one module per detection (`dangerous_function_code`,
    `select_before_operate`)
  - `src/lib.rs` — `analyze_pcap`, the shared analysis pipeline
  - `tests/integration.rs` — runs that pipeline against the fixtures in
    `data/`
- `crates/poc-scada-cli/` — the `clap`-based CLI (binary name `poc-scada`)
  - `src/main.rs` — arg parsing, the per-file report loop
  - `src/color.rs` — ANSI rule coloring, skipped for non-terminal output
  - `src/spinner.rs` — the "still working" spinner around each file's analysis
- `data/dnp3-iti/` — primary detection fixtures (one DNP3 function per file)
- `data/4sics/` — background-noise fixture, LFS-tracked like all `*.pcap`

## Tech stack

Rust — chosen deliberately over the faster-to-ramp-up Python/`scapy` option:
parsing untrusted, potentially malformed binary protocol data from a pcap is
exactly the class of problem where memory-corruption bugs are a realistic
risk in C/C++, and where Rust's safety guarantees are a genuine
differentiator for a security-tooling portfolio piece. Offline/batch pcap
analysis only, no live capture — unlike `poc-logids`'s SSH honeypot, there's
no equivalent live ICS network to tap here, and this also sidesteps the
packet-capture privilege requirements (root/`CAP_NET_RAW`) live capture
would need. See `CLAUDE.md` for full design notes and rationale.
