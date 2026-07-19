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

A desktop UI (Tauri) now sits on top of the same Rust backend: pick a pcap
file, and it replays every DNP3 message as an animated packet flying between
labeled source/destination address nodes, red for anything a detection
flagged, alongside the same findings table the CLI prints. Both front ends
call the exact same `poc_scada_core::analyze_pcap` function, so they can't
drift out of sync with each other.

## Usage

CLI:

```
cargo build --release -p poc-scada-cli
./target/release/poc-scada <PCAP_FILE> [PCAP_FILE ...]
```

Multiple pcap files can be passed at once; each is reported separately, with
a combined total at the end. There are no flags to tune yet — both
detections always run.

Desktop app (from the repo root — see "How it works" for why that matters):

```
cargo tauri dev
```

Requires Node.js (`ui/` is a Vite + vanilla TypeScript project) and, on
Linux, `webkit2gtk-4.0`/`libgtk-3`/`libayatana-appindicator3` dev packages —
see `CLAUDE.md` for the exact `apt` line and why it's `4.0` and not the
`4.1` Tauri v2 wants.

## How it works

A few decisions worth calling out, since they came from real
investigation rather than being obvious upfront:

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
- **Tauri v1, not v2.** Tauri v2 requires `webkit2gtk-4.1`, which doesn't
  exist in this project's Ubuntu 20.04 dev environment's repos at all (not a
  config issue — the package genuinely isn't published for that release).
  v1 uses `webkit2gtk-4.0`, which is available, at the cost of using an
  older/less-actively-developed major version.
- **`cargo tauri dev` must be run from the repo root**, not from
  `src-tauri/`. `beforeDevCommand`/`beforeBuildCommand` in
  `src-tauri/tauri.conf.json` run with the CWD of wherever `cargo tauri` was
  invoked from (unlike `devPath`/`distDir`, which are relative to
  `tauri.conf.json` itself) — they're set to `npm --prefix ui run ...`
  specifically because the repo root is the intended invocation point.
- **`tauri.conf.json`'s `productName` must not collide with a Cargo binary
  name elsewhere in the workspace.** `cargo tauri dev` copies the compiled
  app to a path derived from `productName`, not the Cargo package/bin name —
  it was originally set to `"poc-scada"`, silently overwriting the CLI's
  compiled binary (same name, `crates/poc-scada-cli`'s `[[bin]] name`) on
  every dev run. Renamed to `"poc-scada-desktop"` to make the two
  unambiguous.
- **`src-tauri/Cargo.toml` can't use `version.workspace = true` /
  `edition = "2024"`.** `tauri-build`'s manifest parser (`cargo_toml` 0.15.3)
  doesn't resolve Cargo's workspace-inheritance syntax and doesn't recognize
  the `"2024"` edition string (too new for that dependency's release) —
  both are hardcoded in that one crate's manifest instead, safe since
  editions can differ per-crate within a workspace.
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

Cargo workspace with three members, plus a separate npm project for the
desktop app's frontend:

- `crates/poc-scada-core/` — the actual DPI logic, as a library. No CLI or
  GUI dependencies, so both front ends can depend on it without pulling in
  the other's dependency tree.
  - `src/pcap.rs` — reads legacy `.pcap` files and unwraps Ethernet/IP/TCP/UDP
    down to the raw payload (`pcap-parser` + `etherparse`)
  - `src/dnp3/` — hand-rolled DNP3 link/transport/application-layer parsing
  - `src/detections/` — one module per detection (`dangerous_function_code`,
    `select_before_operate`)
  - `src/lib.rs` — `analyze_pcap`, the shared pipeline both front ends call
  - `tests/integration.rs` — runs that pipeline against the fixtures in
    `data/`
- `crates/poc-scada-cli/` — the `clap`-based CLI (binary name `poc-scada`)
- `src-tauri/` — the Tauri v1 desktop app backend; one `#[tauri::command]`
  (`analyze_pcap`) exposing `poc-scada-core`'s report as JSON over IPC
- `ui/` — the desktop app's frontend: Vite + vanilla TypeScript, no
  framework. `src/animation.ts` renders the source/destination flow diagram
  (plain SVG + `<animateMotion>`, no charting library); `src/main.ts` wires
  up the file picker, findings table, and playback.
- `data/dnp3-iti/` — primary detection fixtures (one DNP3 function per file)
- `data/4sics/` — background-noise fixture, LFS-tracked like all `*.pcap`

## Tech stack

**Rust** for the core — chosen deliberately over the faster-to-ramp-up
Python/`scapy` option: parsing untrusted, potentially malformed binary
protocol data from a pcap is exactly the class of problem where
memory-corruption bugs are a realistic risk in C/C++, and where Rust's
safety guarantees are a genuine differentiator for a security-tooling
portfolio piece. Offline/batch pcap analysis only, no live capture — unlike
`poc-logids`'s SSH honeypot, there's no equivalent live ICS network to tap
here, and this also sidesteps the packet-capture privilege requirements
(root/`CAP_NET_RAW`) live capture would need.

**Tauri v1** for the desktop shell — reuses the Rust backend directly over
IPC rather than standing up an HTTP API, and packages as a real native app
rather than requiring a browser. See "How it works" above for the v1-vs-v2
and environment-specific gotchas hit getting it running. See `CLAUDE.md` for
full design notes and rationale.
