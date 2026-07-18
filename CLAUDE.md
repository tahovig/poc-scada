# Project: poc-scada (formerly scaffolded as `dpi-dnp3`)

## Goal

Third in a series of portfolio projects supporting a career pivot from software engineering to cybersecurity engineering (first: `poc-osint`, at `~/dev-projects/tah-osint-poc`; second: `poc-logids`, at `~/dev-projects/poc-logids`). A DNP3 protocol deep-packet-inspection (DPI) tool — analyzes captured SCADA/ICS network traffic (pcap files) and flags security-relevant patterns. Built around the user's professional background in critical infrastructure protection (energy generation/transmission/distribution, EMS) — the first project in the series where that specific domain expertise is the headline, not a footnote.

## Origin

Started independently by the user in late May/early June 2026 as `dpi-dnp3`. That repo's GitHub remote was never actually created — local commits existed with `origin` configured to point at `github.com/tahovig/dpi-dnp3`, but `git ls-remote`/`gh repo view` both confirmed nothing existed server-side (local `git status` reporting "up to date with origin" was just stale tracking metadata, not a live check). Picked back up and formalized from within the `poc-logids` session on 2026-07-18: since the old remote never existed, a fresh repo was created directly as `poc-scada` and the existing local commits pushed into it (rather than a true GitHub-side rename). Branch strategy applied (`main` + `develop`, matching `poc-osint`/`poc-logids`), local directory renamed from `dpi-dnp3` to `poc-scada` to match.

This was flagged as a stretch-goal candidate during `poc-logids`'s own data-source discussion (see that project's CLAUDE.md, "DNP3/ICS-SCADA" note) — DNP3/ICS analysis was set aside there specifically because `poc-logids` is deliberately log-based, not packet-capture-based, and DNP3 analysis is overwhelmingly a pcap-native discipline. Neither side knew about the other at the time: the `poc-logids` note assumed this would be a fresh idea, when the user had already independently started exactly this a month and a half earlier. This project is where it gets to be the headline.

## Decided so far

- **Type: pcap-native, offline/batch analysis of already-captured DNP3 traffic — not live packet capture.** Unlike `poc-logids` (which has a real live target: an internet-facing SSH honeypot), there's no equivalent live ICS network to tap here, so no live-tail/`-follow` analog is planned — scope is analyzing static pcap files. This also sidesteps the packet-capture privilege/environment concerns that ruled out live capture for `poc-logids` in the first place (root/`CAP_NET_RAW`, WSL2 networking) — nothing here needs elevated privileges or a live NIC, only file I/O over pcaps that already exist.
- **Git LFS already configured for `*.pcap` files** (carried over from the original `dpi-dnp3` commits, `.gitattributes`) — sensible as-is; pcaps can be large binary files that shouldn't bloat regular git history.

## Open decisions for the next session

1. **Language** — not yet decided. My recommendation: **Rust**. `poc-logids`'s own CLAUDE.md explicitly deferred a "systems-language/memory-safety" narrative as a candidate for "a *future* portfolio project if a systems-language/memory-safety narrative becomes the goal" — this project fits that unusually well: parsing untrusted, potentially malformed binary protocol data (DNP3 frames) from a pcap is exactly the class of problem where memory-corruption bugs are a realistic risk in C/C++, and where Rust's safety guarantees are a genuine, substantive differentiator for a security-tooling portfolio piece, not just a language-diversity checkbox. Alternative: Python + `scapy` (or `pyshark`/`dpkt`) — much lower ramp-up, huge ecosystem, matches `poc-osint`'s already-proven pattern, but doesn't carry the same differentiating narrative. The trade-off is real (Rust = steeper learning curve, more time spent on language mechanics than detection logic — the exact reason it was passed over for `poc-logids`) — worth an actual discussion next session, not something to decide unilaterally here.
2. **Detection scope** — needs the same "core functionality" scoping conversation the other two projects went through (see `poc-osint`'s "Scope" section for the shape of that discussion). Candidates, informed by real, well-documented DNP3 security concerns (vanilla DNP3 has no built-in authentication/encryption in most real deployments — DNP3 Secure Authentication exists as an add-on but is rarely deployed in practice):
   - Dangerous/rare function codes appearing on the wire — e.g., Cold Restart (13), Warm Restart (14), Direct Operate (5), Direct Operate No Ack (6). Rare in normal polling traffic (dominated by Read/Response), so their mere presence is a meaningful signal.
   - Direct Operate without a preceding Select — violates the select-before-operate safety pattern real utility control systems rely on; a concrete, well-documented DNP3-specific check.
   - Broader options exist (unsolicited-response abuse, master/outstation address spoofing, malformed/oversized frames) but per the "one tightly-scoped module, not several loose ones" discipline both prior projects followed, v1 should likely pick one or two of these rather than attempt a general anomaly-detection framework.
3. **Data source** — needs research and verification before committing, same rigor as `poc-logids`'s loghub verification (fetched and directly inspected before trusting it, not assumed). Netresec's public ICS pcap captures (e.g., the "4SICS Geek Lounge" dataset, widely cited in ICS security research) are a plausible starting point, but this has **not** been verified to actually contain DNP3 traffic specifically (as opposed to Modbus or other ICS protocols also present in some of those captures) — confirm before relying on it.
4. **Project structure, testing approach, CI** — not yet discussed; will depend heavily on the language decision (item 1).

## Working preferences (carried over from `poc-osint`/`poc-logids`)

- User prefers concise, direct communication — minimal explanation, no unnecessary verbosity.
- User is comfortable with CLI workflows.
- User wants critical, fact-checked pushback grounded in analysis/logic, not agreement-seeking or validation — verify claims (including your own) rather than assuming they hold.
- User values terminal/ASCII visualizations for tool output where applicable.
- User prefers to be asked before scope/data-source/cost decisions, but is fine with reversible technical implementation choices being made and stated directly rather than asked each time.
