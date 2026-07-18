import { open } from "@tauri-apps/api/dialog";
import { invoke } from "@tauri-apps/api/tauri";

import { createFlowDiagram, type PlaybackEntry } from "./animation";
import type { AnalysisReport, Flow, MessageEvent } from "./types";
import { functionCodeLabel } from "./types";
import "./style.css";

const app = document.querySelector<HTMLDivElement>("#app")!;
app.innerHTML = `
  <header>
    <h1>poc-scada — DNP3 DPI</h1>
    <div class="controls">
      <button id="open-btn">Open pcap file…</button>
      <button id="replay-btn" disabled>Replay</button>
      <span id="file-label"></span>
    </div>
  </header>
  <section id="status"></section>
  <svg id="diagram" class="dnp3-diagram"></svg>
  <section id="summary"></section>
  <section id="findings"></section>
`;

const openBtn = document.querySelector<HTMLButtonElement>("#open-btn")!;
const replayBtn = document.querySelector<HTMLButtonElement>("#replay-btn")!;
const fileLabel = document.querySelector<HTMLSpanElement>("#file-label")!;
const status = document.querySelector<HTMLElement>("#status")!;
const summary = document.querySelector<HTMLElement>("#summary")!;
const findingsEl = document.querySelector<HTMLElement>("#findings")!;
const diagram = createFlowDiagram(document.querySelector<SVGSVGElement>("#diagram")!);

let currentEntries: PlaybackEntry[] = [];

function flowKey(flow: Flow, tsSec: number): string {
  return `${tsSec}|${flow.src_ip}:${flow.src_port}->${flow.dst_ip}:${flow.dst_port}`;
}

function toEntries(report: AnalysisReport): PlaybackEntry[] {
  const findingKeys = new Set(report.findings.map((f) => flowKey(f.flow, f.ts_sec)));
  return report.messages.map((message: MessageEvent) => ({
    message,
    flagged: findingKeys.has(flowKey(message.flow, message.ts_sec)),
  }));
}

function renderSummary(report: AnalysisReport) {
  summary.innerHTML = `<p>${report.packet_count} packet(s) analyzed, ${report.findings.length} finding(s)</p>`;
}

function renderFindings(report: AnalysisReport) {
  if (report.findings.length === 0) {
    findingsEl.innerHTML = "<p class=\"no-findings\">No findings.</p>";
    return;
  }
  const rows = report.findings
    .map(
      (f) => `
      <tr>
        <td class="rule">${f.rule}</td>
        <td>${f.ts_sec}</td>
        <td>${f.flow.src_ip}:${f.flow.src_port} → ${f.flow.dst_ip}:${f.flow.dst_port}</td>
        <td>${f.message}</td>
      </tr>`
    )
    .join("");
  findingsEl.innerHTML = `
    <table>
      <thead><tr><th>Rule</th><th>t</th><th>Flow</th><th>Detail</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function startPlayback() {
  diagram.stop();
  const addresses = currentEntries.flatMap((e) => [e.message.message.src, e.message.message.dest]);
  diagram.setAddresses(addresses);
  diagram.play(currentEntries, (entry) => {
    status.textContent = `${functionCodeLabel(entry.message.message.function)} — addr ${entry.message.message.src} → addr ${entry.message.message.dest}${entry.flagged ? " [FLAGGED]" : ""}`;
  });
}

async function loadFile(path: string) {
  status.textContent = "Analyzing…";
  try {
    const report = await invoke<AnalysisReport>("analyze_pcap", { path });
    fileLabel.textContent = report.file;
    renderSummary(report);
    renderFindings(report);
    currentEntries = toEntries(report);
    replayBtn.disabled = currentEntries.length === 0;
    status.textContent = currentEntries.length > 0 ? "Playing…" : "No DNP3 messages found.";
    startPlayback();
  } catch (err) {
    status.textContent = `Error: ${err}`;
  }
}

openBtn.addEventListener("click", async () => {
  const selected = await open({
    multiple: false,
    filters: [{ name: "pcap", extensions: ["pcap"] }],
  });
  if (typeof selected === "string") {
    await loadFile(selected);
  }
});

replayBtn.addEventListener("click", startPlayback);
