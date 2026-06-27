import { useEffect, useRef, useState } from "react";
import {
  getStatus,
  type InterfaceStatus,
  listServers,
  type ServerInfo,
  setTraySummary,
} from "../api";
import { type Summary, trayTooltip } from "../format";

const POLL_MS = 3000;
/** Tolerate a couple of transient poll failures before declaring the daemon gone. */
const OFFLINE_THRESHOLD = 3;
/** Debounce keystrokes before re-querying the daemon for the filtered list. */
const FILTER_DEBOUNCE_MS = 150;

/**
 * The keys passed to `act()` (and matched against `busy`) for each kind of action.
 * Centralized so the row spinners read the same format the dashboard writes.
 */
export const busyKey = {
  switch: (name: string) => name,
  edit: (name: string) => `edit:${name}`,
  remove: (name: string) => `rm:${name}`,
  disconnect: "__disconnect__",
} as const;

/** Collapse the daemon's per-peer states into one headline state for the hero. */
function summarize(status: InterfaceStatus | null): Summary {
  if (status === null) return "Disconnected";
  let summary: Summary = "Never";
  for (const p of status.peers) {
    if (p.state === "Alive") return "Alive";
    if (p.state === "Connecting") summary = "Connecting";
    else if (p.state === "Stale" && summary === "Never") summary = "Stale";
  }
  return summary;
}

export interface ServerListController {
  servers: ServerInfo[];
  status: InterfaceStatus | null;
  summary: Summary;
  /** The key of the action currently in flight (drives per-row spinners), or null. */
  busy: string | null;
  error: string | null;
  /** The daemon-side filter query (sent with every list request). */
  query: string;
  setQuery: (q: string) => void;
  /** Apply a list the caller already holds (the fresh list from add/remove/import),
   *  guarded against a late callback after unmount. */
  applyServers: (list: ServerInfo[]) => void;
  /** True while the owning component is still mounted — for guarding late callbacks. */
  isMounted: () => boolean;
  /** Re-read the list + status from the daemon, applying the current filter. */
  refresh: () => Promise<void>;
  /**
   * Run an action, then re-read state. `key` drives per-row spinners; `skipRefresh`
   * lets the caller hand off (e.g. removing the last server unmounts us).
   */
  act: (key: string, fn: () => Promise<unknown>, skipRefresh?: boolean) => Promise<void>;
}

/**
 * Owns the dashboard's server data: the polled list + interface status, the derived
 * headline summary, the in-flight action key, and the daemon-side filter query.
 * Centralizes the fetch / poll / retry / race machinery so the view stays declarative.
 */
export function useServerList(onOffline: () => void): ServerListController {
  const [servers, setServers] = useState<ServerInfo[]>([]);
  const [status, setStatus] = useState<InterfaceStatus | null>(null);
  const [summary, setSummary] = useState<Summary>("Offline");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  // Refs the polling closure reads without being re-created: liveness, whether an
  // action is in flight (so the poll backs off), the consecutive-failure count, the
  // current query, and a monotonic id that lets a newer refresh win a race.
  const mounted = useRef(true);
  const busyRef = useRef(false);
  const failures = useRef(0);
  const queryRef = useRef("");
  const refreshSeq = useRef(0);

  async function refresh() {
    const seq = ++refreshSeq.current;
    try {
      const [srv, st] = await Promise.all([listServers(queryRef.current), getStatus()]);
      // Bail if unmounted or a newer refresh has been issued since — applying our
      // (now stale) result would fight the latest filter/poll.
      if (!mounted.current || seq !== refreshSeq.current) return;
      failures.current = 0;
      setServers(srv);
      setStatus(st);
      const next = summarize(st);
      setSummary(next);
      setError(null);
      // Keep the tray summary in step with each poll. Fire-and-forget;
      // a failed tray update must never disrupt the dashboard.
      setTraySummary(trayTooltip(next, st)).catch(() => {});
    } catch (e) {
      // Same staleness guard: a superseded request's failure mustn't trip the
      // offline counter on behalf of a newer in-flight refresh.
      if (!mounted.current || seq !== refreshSeq.current) return;
      failures.current += 1;
      setSummary("Offline");
      setError(String(e));
      setTraySummary(trayTooltip("Offline", null)).catch(() => {});
      if (failures.current >= OFFLINE_THRESHOLD) onOffline();
    }
  }

  // biome-ignore lint/correctness/useExhaustiveDependencies: the poll loop is set up once on mount; refresh reads the latest state through refs.
  useEffect(() => {
    mounted.current = true;
    refresh();
    const id = setInterval(() => {
      // Don't let a background poll race (and clobber) an in-flight action.
      if (!busyRef.current) refresh();
    }, POLL_MS);
    return () => {
      mounted.current = false;
      clearInterval(id);
    };
  }, []);

  // Re-query the daemon when the filter changes. Typing is debounced so we don't
  // round-trip on every keystroke; clearing refetches at once so the full list
  // returns instantly (no flash of the empty state).
  // biome-ignore lint/correctness/useExhaustiveDependencies: refresh reads the latest state through refs; re-run only when the query changes.
  useEffect(() => {
    queryRef.current = query;
    if (query === "") {
      if (!busyRef.current) refresh();
      return;
    }
    const id = setTimeout(() => {
      if (!busyRef.current) refresh();
    }, FILTER_DEBOUNCE_MS);
    return () => clearTimeout(id);
  }, [query]);

  async function act(key: string, fn: () => Promise<unknown>, skipRefresh = false) {
    setBusy(key);
    busyRef.current = true;
    setError(null);
    try {
      await fn();
      if (!skipRefresh && mounted.current) await refresh();
    } catch (e) {
      if (mounted.current) setError(String(e));
    } finally {
      busyRef.current = false;
      if (mounted.current) setBusy(null);
    }
  }

  function applyServers(list: ServerInfo[]) {
    if (mounted.current) setServers(list);
  }

  return {
    servers,
    status,
    summary,
    busy,
    error,
    query,
    setQuery,
    applyServers,
    isMounted: () => mounted.current,
    refresh,
    act,
  };
}
