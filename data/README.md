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
