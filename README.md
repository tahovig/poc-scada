# poc-scada — DNP3 Protocol DPI Tool

A deep-packet-inspection tool for DNP3 (SCADA/ICS protocol) traffic: analyzes captured packet data (pcap files) and flags security-relevant patterns. Built around a background in critical infrastructure protection (energy generation/transmission/distribution, EMS).

Third in a series of portfolio projects supporting a pivot from software engineering to cybersecurity engineering. First: [poc-osint](https://github.com/tahovig/poc-osint), an automated subdomain recon tool. Second: [poc-logids](https://github.com/tahovig/poc-logids), a log-based SSH brute-force detector.

## Status

Working v1: Rust, reading legacy `.pcap` files offline. Detects two DNP3-specific
security patterns:

- **Dangerous function codes** — Cold Restart, Warm Restart, Direct Operate, and
  Direct Operate No Ack are rare in normal polling traffic (dominated by
  Read/Response), so their presence on the wire is a meaningful signal.
- **Select-before-operate violations** — an Operate not immediately preceded by
  a Select from the same master/outstation pair, breaking the safety pattern
  real utility control systems rely on.

```
cargo run -- data/dnp3-iti/cold_restart_and_response.pcap
```

Test fixtures and their provenance/verification are documented in `data/README.md`.
A UI layer (visualizing traffic between source/destination systems) is planned
on top of this Rust backend but not yet started. See `CLAUDE.md` for the full
planning history.
