import { useEffect, useRef, useState } from "react";
import {
  addServer,
  disconnect,
  getStatus,
  InterfaceStatus,
  listServers,
  removeServer,
  ServerInfo,
  switchServer,
} from "../api";
import { humanizeAge, humanizeBytes, Summary, SUMMARY_LABEL } from "../format";
import { CopyButton } from "./CopyField";
import { ImportForm } from "./ImportForm";
import { ServerForm } from "./ServerForm";

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
      setSummary(summarize(st));
      setError(null);
    } catch (e) {
      if (!mounted.current) return;
      failures.current += 1;
      setSummary("Offline");
      setError(String(e));
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
    <main className="dashboard">
      <header className="topbar">
        <h1>wirefinder</h1>
        <span className={`pill pill-${summary}`}>{SUMMARY_LABEL[summary]}</span>
      </header>

      <section className={`hero hero-${summary}`}>
        <div className="hero-ring" aria-hidden>
          <span className="hero-dot" />
        </div>
        <div className="hero-text">
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
            className="btn ghost"
            disabled={busy !== null}
            onClick={() => act("__disconnect__", disconnect)}
          >
            {busy === "__disconnect__" ? "Disconnecting…" : "Disconnect"}
          </button>
        )}
      </section>

      <section className="servers-section">
        <div className="section-head">
          <h2>Servers</h2>
          {adding === null && (
            <span className="add-actions">
              <button className="btn ghost small" onClick={() => setAdding("import")}>
                Import .conf
              </button>
              <button className="btn ghost small" onClick={() => setAdding("manual")}>
                + Add
              </button>
            </span>
          )}
        </div>

        {adding === "manual" && (
          <div className="card inset">
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
          <div className="card inset">
            <ImportForm
              onCancel={() => setAdding(null)}
              onImported={(left) => {
                setAdding(null);
                if (mounted.current) setServers(left);
              }}
            />
          </div>
        )}

        <ul className="servers">
          {servers.map((s) => (
            <li key={s.name} className={s.active ? "active" : ""}>
              <span className="dot" aria-hidden>
                {s.active ? "●" : "○"}
              </span>
              <span className="server-meta">
                <span className="name">{s.name}</span>
                <span className="endpoint">{s.endpoint}</span>
                <span className="endpoint">{s.addresses.join(", ")}</span>
              </span>
              <span className="row-actions">
                <button
                  className="btn primary small"
                  disabled={s.active || busy !== null}
                  onClick={() => act(s.name, () => switchServer(s.name))}
                >
                  {busy === s.name ? "Switching…" : s.active ? "Connected" : "Connect"}
                </button>
                <CopyButton value={s.public_key} />
                <button
                  className="btn ghost small danger"
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
          <p className="muted empty">No servers yet. Add one to get connected.</p>
        )}
      </section>

      {error && (
        <p className="error toast" role="alert">
          {error}
        </p>
      )}
    </main>
  );
}
