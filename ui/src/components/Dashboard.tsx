import { useEffect, useRef, useState } from "react";
import {
  addServer,
  disconnect,
  editServer,
  getServer,
  removeServer,
  type ServerDetail,
  type ServerInfo,
  switchServer,
} from "../api";
import { SUMMARY_LABEL } from "../format";
import { cx } from "../lib/cx";
import styles from "./Dashboard.module.css";
import { Hero } from "./Hero";
import { ImportForm } from "./ImportForm";
import { CloseIcon, SearchIcon } from "./icons";
import { ServerForm } from "./ServerForm";
import { ServerListItem } from "./ServerListItem";
import shared from "./shared.module.css";
import { busyKey, useServerList } from "./useServerList";
import { useServerSearch } from "./useServerSearch";

type AddMode = null | "manual" | "import";

interface Props {
  /** Called when removing the last server, to return to onboarding. */
  onServersEmptied: () => void;
  /** Called after repeated poll failures, to show the offline screen. */
  onOffline: () => void;
}

export function Dashboard({ onServersEmptied, onOffline }: Props) {
  const {
    servers,
    status,
    summary,
    busy,
    error,
    query,
    setQuery,
    applyServers,
    isMounted,
    refresh,
    act,
  } = useServerList(onOffline);

  // Which add flow is open (manual / import / none) and which server is being edited.
  // Only one of {search, add/import form} is shown at a time; they dismiss each other.
  const [adding, setAdding] = useState<AddMode>(null);
  const [editing, setEditing] = useState<ServerDetail | null>(null);
  const editFormRef = useRef<HTMLDivElement | null>(null);

  const search = useServerSearch(query, setQuery, () => setAdding(null));

  // When an edit form opens, bring its top into view — the edited row may be far
  // down the list. Keyed on the edited name so re-opening a different row re-scrolls.
  // biome-ignore lint/correctness/useExhaustiveDependencies: scroll only when the edited server changes, not on every detail update.
  useEffect(() => {
    if (editing) editFormRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [editing?.name]);

  /** Open an add/import flow, dismissing the edit form and the search field. */
  function startAdding(mode: Exclude<AddMode, null>) {
    setEditing(null);
    search.close();
    setAdding(mode);
  }

  // The public key is non-secret (you register it on your server); copy it straight to
  // the clipboard. The private key never leaves the daemon, so it's never offered here.
  async function copyKey(s: ServerInfo): Promise<string> {
    try {
      await navigator.clipboard.writeText(s.public_key);
      return "Copied";
    } catch {
      return "Copy failed";
    }
  }

  // `servers` is already the daemon-filtered result; this just drives the empty-state
  // wording (no servers configured vs none matching the active query).
  const filtering = query.trim() !== "";
  const showSearch = servers.length > 0 || search.open;

  return (
    <main className={styles.dashboard}>
      <div className={cx(styles.ambient, styles[`ambient${summary}`])} aria-hidden />
      <header className={styles.topbar}>
        <h1>Wirefinder</h1>
        <span className={styles.topbarRight}>
          <span className={cx(styles.pill, styles[`pill${summary}`])}>
            {SUMMARY_LABEL[summary]}
          </span>
        </span>
      </header>

      <Hero
        summary={summary}
        status={status}
        disabled={busy !== null}
        disconnecting={busy === busyKey.disconnect}
        onDisconnect={() => act(busyKey.disconnect, disconnect)}
      />

      <section>
        <div className={styles.sectionHead}>
          <h2>Servers</h2>
          <span className={styles.headActions}>
            {showSearch && (
              <button
                type="button"
                className={cx(styles.searchToggle, search.open && styles.searchToggleActive)}
                aria-label={search.open ? "Close search" : "Search servers"}
                aria-expanded={search.open}
                onClick={search.toggle}
              >
                {search.open ? <CloseIcon /> : <SearchIcon />}
              </button>
            )}
            <span className={styles.addActions}>
              <button
                type="button"
                className={cx(shared.btn, shared.ghost, shared.small)}
                onClick={() => startAdding("import")}
              >
                Import .conf
              </button>
              <button
                type="button"
                className={cx(shared.btn, shared.ghost, shared.small)}
                onClick={() => startAdding("manual")}
              >
                + Add
              </button>
            </span>
          </span>
        </div>

        {showSearch && (
          <div className={cx(styles.searchRow, search.open && styles.searchRowOpen)}>
            <SearchIcon className={styles.searchIcon} />
            <input
              ref={search.inputRef}
              type="search"
              className={styles.searchInput}
              placeholder="Filter servers…"
              aria-label="Filter servers by name, endpoint, or address"
              value={query}
              tabIndex={search.open ? 0 : -1}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={search.onFieldKeyDown}
            />
          </div>
        )}

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
                applyServers(left);
              }}
            />
          </div>
        )}

        <ul className={styles.servers}>
          {servers.map((s) => (
            <ServerListItem
              key={s.name}
              server={s}
              busy={busy}
              editing={editing}
              editFormRef={editFormRef}
              onSwitch={() => act(busyKey.switch(s.name), () => switchServer(s.name))}
              onEdit={() =>
                act(
                  busyKey.edit(s.name),
                  async () => {
                    const detail = await getServer(s.name);
                    if (!isMounted()) return;
                    setAdding(null); // only one form open at a time
                    setEditing(detail);
                  },
                  true, // we only opened a form; no list refresh
                )
              }
              onCopyKey={() => copyKey(s)}
              onRemove={() =>
                act(
                  busyKey.remove(s.name),
                  async () => {
                    // removeServer returns the fresh list; apply it directly so we never
                    // refetch (and never race the parent's unmount when the last is gone).
                    const left = await removeServer(s.name);
                    if (left.length === 0) {
                      onServersEmptied();
                    } else {
                      applyServers(left);
                    }
                    if (editing?.name === s.name) setEditing(null);
                  },
                  true, // we've already updated state; skip the trailing refresh
                )
              }
              onCancelEdit={() => setEditing(null)}
              onSubmitEdit={async (server) => {
                await editServer(server);
                setEditing(null);
                await refresh();
              }}
            />
          ))}
        </ul>

        {servers.length === 0 && !filtering && adding === null && (
          <p className={cx("muted", styles.empty)}>No servers yet. Add one to get connected.</p>
        )}

        {servers.length === 0 && filtering && (
          <p className={cx("muted", styles.empty)} role="status">
            No servers match “{query.trim()}”.
          </p>
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
