import { useEffect, useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  addServer,
  disconnect,
  getStatus,
  InterfaceStatus,
  listServers,
  removeServer,
  ServerInfo,
  setTraySummary,
  switchServer,
} from "../api";
import { humanizeAge, humanizeBytes, Summary, SUMMARY_LABEL, trayTooltip } from "../format";
import { cx } from "../lib/cx";
import { ImportForm } from "./ImportForm";
import { ServerForm } from "./ServerForm";
import shared from "./shared.module.css";
import styles from "./Dashboard.module.css";

type AddMode = null | "manual" | "import";

const POLL_MS = 3000;
/** Tolerate a couple of transient poll failures before declaring the daemon gone. */
const OFFLINE_THRESHOLD = 3;

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

interface Props {
  /** Called when removing the last server, to return to onboarding. */
  onServersEmptied: () => void;
  /** Called after repeated poll failures, to show the offline screen. */
  onOffline: () => void;
}

export function Dashboard({ onServersEmptied, onOffline }: Props) {
  const [servers, setServers] = useState<ServerInfo[]>([]);
  const [status, setStatus] = useState<InterfaceStatus | null>(null);
  const [summary, setSummary] = useState<Summary>("Offline");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState<AddMode>(null);

  // Refs that the polling closure reads without needing to be re-created: whether
  // we're still mounted, whether an action is in flight (so the poll backs off),
  // and how many polls have failed in a row.
  const mounted = useRef(true);
  const busyRef = useRef(false);
  const failures = useRef(0);

  async function refresh() {
    try {
      const [srv, st] = await Promise.all([listServers(), getStatus()]);
      if (!mounted.current) return;
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
      if (!mounted.current) return;
      failures.current += 1;
      setSummary("Offline");
      setError(String(e));
      setTraySummary(trayTooltip("Offline", null)).catch(() => {});
      if (failures.current >= OFFLINE_THRESHOLD) onOffline();
    }
  }

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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Run an action, then re-read state. `key` drives per-row spinners. `skipRefresh`
  // lets the caller hand off (e.g. removing the last server unmounts us).
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

  const connected = summary !== "Offline" && summary !== "Disconnected";
  const activePeer = status?.peers.find((p) => p.state === "Alive") ?? status?.peers[0] ?? null;

  return (
    <main className={styles.dashboard}>
      <header className={styles.topbar}>
        <h1>wirefinder</h1>
        <span className={styles.topbarRight}>
          <span className={cx(styles.pill, styles[`pill${summary}`])}>{SUMMARY_LABEL[summary]}</span>
          <button
            className={styles.close}
            aria-label="Close"
            onClick={() => getCurrentWindow().hide()}
          >
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden>
              <line x1="1" y1="1" x2="9" y2="9" stroke="currentColor" strokeWidth="1" />
              <line x1="9" y1="1" x2="1" y2="9" stroke="currentColor" strokeWidth="1" />
            </svg>
          </button>
        </span>
      </header>

      <section className={cx(styles.hero, styles[`hero${summary}`])}>
        <div className={styles.heroRing} aria-hidden>
          <span className={styles.heroDot} />
        </div>
        <div className={styles.heroText}>
          <strong>{SUMMARY_LABEL[summary]}</strong>
          {connected && activePeer && (
            <span className="muted small">
              ↓ {humanizeBytes(activePeer.rx_bytes)} · ↑ {humanizeBytes(activePeer.tx_bytes)} ·
              handshake {humanizeAge(activePeer.handshake_age_secs)}
            </span>
          )}
          {!connected && servers.length > 0 && (
            <span className="muted small">Choose a server below to connect.</span>
          )}
        </div>
        {connected && (
          <button
            className={cx(shared.btn, shared.ghost)}
            disabled={busy !== null}
            onClick={() => act("__disconnect__", disconnect)}
          >
            {busy === "__disconnect__" ? "Disconnecting…" : "Disconnect"}
          </button>
        )}
      </section>

      <section>
        <div className={styles.sectionHead}>
          <h2>Servers</h2>
          {adding === null && (
            <span className={styles.addActions}>
              <button className={cx(shared.btn, shared.ghost, shared.small)} onClick={() => setAdding("import")}>
                Import .conf
              </button>
              <button className={cx(shared.btn, shared.ghost, shared.small)} onClick={() => setAdding("manual")}>
                + Add
              </button>
            </span>
          )}
        </div>

        {adding === "manual" && (
          <div className={cx(shared.card, shared.inset)}>
            <ServerForm
              submitLabel="Add server"
              onCancel={() => setAdding(null)}
              onSubmit={async (server) => {
                await addServer(server);
                setAdding(null);
                await refresh();
              }}
            />
          </div>
        )}

        {adding === "import" && (
          <div className={cx(shared.card, shared.inset)}>
            <ImportForm
              onCancel={() => setAdding(null)}
              onImported={(left) => {
                setAdding(null);
                if (mounted.current) setServers(left);
              }}
            />
          </div>
        )}

        <ul className={styles.servers}>
          {servers.map((s) => (
            <li key={s.name} className={s.active ? styles.active : undefined}>
              <span className={styles.dot} aria-hidden>
                {s.active ? "●" : "○"}
              </span>
              <span className={styles.serverMeta}>
                <span className={styles.name}>{s.name}</span>
                <span className={styles.endpoint}>{s.endpoint}</span>
                <span className={styles.endpoint}>{s.addresses.join(", ")}</span>
              </span>
              <span className={styles.rowActions}>
                <button
                  className={cx(shared.btn, shared.primary, shared.small)}
                  disabled={s.active || busy !== null}
                  onClick={() => act(s.name, () => switchServer(s.name))}
                >
                  {busy === s.name ? "Switching…" : s.active ? "Connected" : "Connect"}
                </button>
                <button
                  className={cx(shared.btn, shared.ghost, shared.small, shared.danger)}
                  disabled={busy !== null}
                  title={`Remove ${s.name}`}
                  onClick={() =>
                    act(
                      `rm:${s.name}`,
                      async () => {
                        // removeServer returns the fresh list; apply it directly so
                        // we never refetch (and never race the parent's unmount when
                        // the last server is gone).
                        const left = await removeServer(s.name);
                        if (left.length === 0) {
                          onServersEmptied();
                        } else if (mounted.current) {
                          setServers(left);
                          // Removing the active server changes the tunnel — re-read
                          // status so the hero doesn't keep showing "Connected".
                          if (s.active) await refresh();
                        }
                      },
                      true, // we've already updated state; skip the trailing refresh
                    )
                  }
                >
                  {busy === `rm:${s.name}` ? "…" : "Remove"}
                </button>
              </span>
            </li>
          ))}
        </ul>

        {servers.length === 0 && adding === null && (
          <p className={cx("muted", styles.empty)}>No servers yet. Add one to get connected.</p>
        )}
      </section>

      {error && (
        <p className={cx("error", styles.toast)} role="alert">
          {error}
        </p>
      )}
    </main>
  );
}
