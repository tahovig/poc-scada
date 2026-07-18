import type { MessageEvent } from "./types";

const SVG_NS = "http://www.w3.org/2000/svg";
const VIEW_WIDTH = 800;
const VIEW_HEIGHT = 220;
const NODE_Y = 60;
const NODE_MARGIN = 90;
const PACKET_DURATION_MS = 650;
const PACKET_STAGGER_MS = 350;

interface Point {
  x: number;
  y: number;
}

export interface PlaybackEntry {
  message: MessageEvent;
  flagged: boolean;
}

export interface FlowDiagram {
  setAddresses(addresses: number[]): void;
  play(entries: PlaybackEntry[], onEntry?: (entry: PlaybackEntry) => void): void;
  stop(): void;
}

export function createFlowDiagram(svg: SVGSVGElement): FlowDiagram {
  svg.setAttribute("viewBox", `0 0 ${VIEW_WIDTH} ${VIEW_HEIGHT}`);

  const nodeLayer = document.createElementNS(SVG_NS, "g");
  const packetLayer = document.createElementNS(SVG_NS, "g");
  svg.append(nodeLayer, packetLayer);

  const positions = new Map<number, Point>();
  let playToken = 0;

  function setAddresses(addresses: number[]) {
    nodeLayer.replaceChildren();
    packetLayer.replaceChildren();
    positions.clear();

    const sorted = [...new Set(addresses)].sort((a, b) => a - b);
    const usable = VIEW_WIDTH - NODE_MARGIN * 2;

    sorted.forEach((addr, i) => {
      const x = sorted.length === 1 ? VIEW_WIDTH / 2 : NODE_MARGIN + (usable * i) / (sorted.length - 1);
      positions.set(addr, { x, y: NODE_Y });

      const circle = document.createElementNS(SVG_NS, "circle");
      circle.setAttribute("cx", String(x));
      circle.setAttribute("cy", String(NODE_Y));
      circle.setAttribute("r", "22");
      circle.setAttribute("class", "dnp3-node");
      nodeLayer.appendChild(circle);

      const label = document.createElementNS(SVG_NS, "text");
      label.setAttribute("x", String(x));
      label.setAttribute("y", String(NODE_Y + 44));
      label.setAttribute("class", "dnp3-node-label");
      label.textContent = `addr ${addr}`;
      nodeLayer.appendChild(label);
    });
  }

  function spawnPacket(src: Point, dest: Point, flagged: boolean) {
    const dot = document.createElementNS(SVG_NS, "circle");
    dot.setAttribute("r", "6");
    dot.setAttribute("cx", String(src.x));
    dot.setAttribute("cy", String(src.y));
    dot.setAttribute("class", flagged ? "dnp3-packet dnp3-packet-flagged" : "dnp3-packet");
    packetLayer.appendChild(dot);

    const motion = document.createElementNS(SVG_NS, "animateMotion");
    motion.setAttribute("dur", `${PACKET_DURATION_MS}ms`);
    motion.setAttribute("fill", "freeze");
    // animateMotion applies a relative translation on top of the element's
    // own cx/cy, so the path is a displacement from (0,0), not absolute coords.
    motion.setAttribute("path", `M0,0 L${dest.x - src.x},${dest.y - src.y}`);
    dot.appendChild(motion);

    window.setTimeout(() => {
      dot.remove();
      const ping = document.createElementNS(SVG_NS, "circle");
      ping.setAttribute("cx", String(dest.x));
      ping.setAttribute("cy", String(dest.y));
      ping.setAttribute("r", "22");
      ping.setAttribute("class", flagged ? "dnp3-ping dnp3-ping-flagged" : "dnp3-ping");
      packetLayer.appendChild(ping);
      window.setTimeout(() => ping.remove(), 500);
    }, PACKET_DURATION_MS);
  }

  function play(entries: PlaybackEntry[], onEntry?: (entry: PlaybackEntry) => void) {
    const token = ++playToken;
    let i = 0;

    function step() {
      if (token !== playToken || i >= entries.length) return;
      const entry = entries[i];
      i++;

      const src = positions.get(entry.message.message.src);
      const dest = positions.get(entry.message.message.dest);
      if (src && dest) {
        spawnPacket(src, dest, entry.flagged);
        onEntry?.(entry);
      }

      window.setTimeout(step, PACKET_STAGGER_MS);
    }

    step();
  }

  function stop() {
    playToken++;
    packetLayer.replaceChildren();
  }

  return { setAddresses, play, stop };
}
