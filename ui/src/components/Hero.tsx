import type { InterfaceStatus } from "../api";
import { humanizeAge, humanizeBytes, SUMMARY_LABEL, type Summary } from "../format";
import { cx } from "../lib/cx";
import styles from "./Dashboard.module.css";
import shared from "./shared.module.css";

interface Props {
  summary: Summary;
  status: InterfaceStatus | null;
  /** Any action is in flight, so the disconnect button is disabled. */
  disabled: boolean;
  /** The in-flight action is the disconnect (swaps the button label). */
  disconnecting: boolean;
  onDisconnect: () => void;
}

/** The status hero: a state-colored dot/ring, the headline, live traffic, and a
 *  disconnect button while connected. Purely presentational. */
export function Hero({ summary, status, disabled, disconnecting, onDisconnect }: Props) {
  const connected = summary !== "Offline" && summary !== "Disconnected";
  const activePeer = status?.peers.find((p) => p.state === "Alive") ?? status?.peers[0] ?? null;

  return (
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
        {!connected && <span className="muted small">Choose a server below to connect.</span>}
      </div>
      {connected && (
        <button
          type="button"
          className={cx(shared.btn, shared.ghost)}
          disabled={disabled}
          onClick={onDisconnect}
        >
          {disconnecting ? "Disconnecting…" : "Disconnect"}
        </button>
      )}
    </section>
  );
}
