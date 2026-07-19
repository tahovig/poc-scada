# Test fixtures

## `dnp3-iti/`

Per-function DNP3 pcaps from [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps/dnp3),
a curated collection of real, well-formed DNP3 traffic organized one function
per file (Select/Operate, Cold/Warm Restart, Direct Operate, etc.). Verified
by hand — decoded link/transport/application-layer bytes for a sample of
these files to confirm the function codes in the filenames match the actual
frame contents — before committing to them as the primary detection fixtures.

## `4sics/`

An 8,000-packet prefix of `4SICS-GeekLounge-151022.pcap` from
[Netresec's public 4SICS ICS Lab captures](https://www.netresec.com/?page=PCAP4SICS).
Used as a "noisy, mostly non-DNP3" background sample to check the tool
doesn't false-positive on realistic mixed ICS/scanner traffic.

Verification note: two of the three public 4SICS captures were checked and
contain **no real DNP3 traffic** at all (one is dominated by S7comm, the
other's port-20000 traffic is scanner probes — Oracle TNS, raw HTTP GETs —
not DNP3). The third (`151022`, used here) does contain a small number of
genuine DNP3 link-layer frames (`0x05 0x64` sync bytes, valid CRCs), but only
"Request Link Status" probes with zero application-layer payload — no
Read/Response, Select/Operate, or Restart traffic. That's why it's used only
as background noise, not as a source for the actual detections.

## `qut-2017/`

Real, large-scale, labeled DNP3 traffic from
[qut-infosec/2017QUT_DNP3](https://github.com/qut-infosec/2017QUT_DNP3)
(Queensland University of Technology, 2017) — a genuinely different class of
fixture from `dnp3-iti/`'s small synthetic per-function captures: this is
real master/outstation polling traffic recorded over hours, with (in the
`injection/` case) real attacker-injected DNP3 commands mixed in. The
upstream repo is ~1.36GB total across 6 attack categories (Control,
Flooding, Injection, MITM, Masquerading, Replay), each with training/testing
× frequent/infrequent subsets and separate `master.pcap`/`slave.pcap`/
`attacker.pcap` captures per subset. Only the `testing/frequent` subset of
two categories is kept here (~702MB) — enough to stay under GitHub's free
1GB Git LFS storage cap while keeping real scale and both categories'
distinct outcomes; the rest of the upstream dataset can be pulled the same
way (see below) if a specific attack category/subset is needed later.

- **`control/`** (`master.pcap`, `slave.pcap`, `attacker.pcap`, ~175MB) —
  verified to be clean, legitimate baseline polling traffic: ~3.15M total
  packets, ~67K real DNP3 messages, function codes are exclusively
  `Confirm`/`Read`/`Response`/`UnsolicitedResponse` across all four
  training/testing × frequent/infrequent subsets (checked all four before
  picking one to keep). `poc-scada` correctly reports **zero findings** on
  it — the point of keeping this category is a real-world negative control,
  not a bug. `attacker.pcap` here isn't DNP3 at all (NTP/NetBIOS/link-layer
  redundancy-protocol frames) — the "Control" category's attack activity
  apparently isn't function-code-based, consistent with the upstream tool's
  own attack-class listing (`Injection/Attack_script_output.txt`) showing
  `injection_ColdRestart`/`injection_WarmRestart` as distinct attack classes
  from whatever "Control" exercises.
- **`injection/`** (`master.pcap`, `slave.pcap`, `attacker.pcap`, ~527MB) —
  verified to contain genuine injected attacks: `slave.pcap` and
  `attacker.pcap` both show real `ColdRestart` (36), `WarmRestart` (42), and
  `ImmediateFreeze` (30) function codes (`master.pcap` doesn't see them —
  consistent with an injection/MITM topology where the outstation's own
  capture point sees both legitimate and injected traffic but the master's
  doesn't). Running `poc-scada` against `slave.pcap` correctly produces
  **78 findings**, all `dangerous-function-code`, with correct
  timestamps/flows/DNP3 addressing — real confirmation against labeled
  attack traffic, not just this project's own synthetic fixtures.

**`select-before-operate-violation` isn't exercised anywhere in this
dataset.** After `dangerous-function-code` validated cleanly against
`injection/`, the natural next question was whether this large real-world
dataset could validate the other detection too. It can't: `Select`(3) and
`Operate`(4) function codes were checked for and never found in *any* of
the 6 attack categories (Control, Injection, Replay, MITM, Flooding,
Masquerading — Replay/MITM checked at both `frequent`/`infrequent`
granularity, given `frequent` was where `injection/`'s attack activity
concentrated). That consistency across capture sessions spanning three
different calendar months (Jul/Aug/Sep 2016) points to this being a
property of the underlying testbed — it apparently never generates a
select-then-operate control sequence, using direct write/freeze/restart
actions instead — rather than something attack-category-specific worth
digging into further. As a side effect, this sweep also confirmed none of
Replay/MITM/Flooding/Masquerading exercise `dangerous-function-code` either
(Flooding shows heavy `ImmediateFreeze`/`Write` flooding, consistent with
its name, but nothing in this project's dangerous-function-code list) — so
across the whole dataset, only `injection/` triggers either current
detection; the other five categories are all negative controls. Only
`Control` is kept as a fixture for that story — the other four were
inspected (function-code tallies only, not committed) and would add
redundant "no findings" coverage at real additional LFS storage cost, so
they're documented here rather than kept as files.

`select-before-operate-violation` coverage instead comes from
`dnp3-iti/select_operate_and_responses.pcap` (the legitimate select-then-operate
case) and `dnp3-iti/directoperate_and_response.pcap` (the bypass case), plus
a synthetic bare-Operate case in `tests/integration.rs` — real DNP3 bytes
either way, just not from this dataset.

Not wired into `tests/integration.rs` — these are multi-hundred-MB,
multi-second-to-analyze real-world captures, appropriate for manual
real-scale validation and demos, not for something `cargo test` runs on
every invocation. The small `dnp3-iti/` fixtures remain the fast,
per-function unit-level test data.
