// Mirrors the serde output of poc-scada-core's public types
// (crates/poc-scada-core/src/{lib,pcap,dnp3,detections/mod}.rs).

export interface Flow {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
}

// serde's default enum representation: unit variants serialize as a bare
// string ("ColdRestart"); the one tuple variant serializes as { Other: n }.
export type FunctionCode =
  | "Confirm"
  | "Read"
  | "Write"
  | "Select"
  | "Operate"
  | "DirectOperate"
  | "DirectOperateNoAck"
  | "ImmediateFreeze"
  | "ImmediateFreezeNoAck"
  | "FreezeAndClear"
  | "FreezeAndClearNoAck"
  | "ColdRestart"
  | "WarmRestart"
  | "Response"
  | "UnsolicitedResponse"
  | { Other: number };

export interface Dnp3Message {
  dest: number;
  src: number;
  function: FunctionCode;
}

export interface MessageEvent {
  ts_sec: number;
  flow: Flow;
  message: Dnp3Message;
}

export interface Finding {
  rule: string;
  message: string;
  ts_sec: number;
  flow: Flow;
}

export interface AnalysisReport {
  file: string;
  packet_count: number;
  messages: MessageEvent[];
  findings: Finding[];
}

export function functionCodeLabel(fn: FunctionCode): string {
  return typeof fn === "string" ? fn : `Other(${fn.Other})`;
}
