import { ConnState, InterfaceStatus } from "./api";

/** A connection summary the UI renders, including states the daemon can't report. */
export type Summary = ConnState | "Disconnected" | "Offline";

export const SUMMARY_LABEL: Record<Summary, string> = {
  Alive: "Connected",
  Connecting: "Connecting…",
  Stale: "Connection stale",
  Never: "Not connected",
  Disconnected: "Disconnected",
  Offline: "Daemon offline",
};

/** Human-readable byte counts, matching the CLI's `humanize`. */
export function humanizeBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes;
  let unit = "B";
  for (const next of ["KiB", "MiB", "GiB", "TiB"]) {
    if (value < 1024) break;
    value /= 1024;
    unit = next;
  }
  return `${value.toFixed(1)} ${unit}`;
}

/** The tray icon's hover summary: a status headline plus, when connected, the
 *  active peer's traffic and handshake age — mirroring the dashboard hero. */
export function trayTooltip(summary: Summary, status: InterfaceStatus | null): string {
  const head = `wirefinder — ${SUMMARY_LABEL[summary]}`;
  if (!status) return head;
  const peer = status.peers.find((p) => p.state === "Alive") ?? status.peers[0];
  if (!peer) return head;
  return [
    head,
    `↓ ${humanizeBytes(peer.rx_bytes)}   ↑ ${humanizeBytes(peer.tx_bytes)}`,
    `handshake ${humanizeAge(peer.handshake_age_secs)}`,
  ].join("\n");
}

/** "5s", "3m", "2h" — compact relative age for a handshake. */
export function humanizeAge(secs: number | null): string {
  if (secs === null) return "—";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}
