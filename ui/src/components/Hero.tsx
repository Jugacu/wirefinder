import type { InterfaceStatus } from "../api";
import { humanizeAge, humanizeBytes, SUMMARY_LABEL, type Summary } from "../format";
import { cx } from "../lib/cx";
import styles from "./Dashboard.module.css";
import { ArrowDownIcon, ArrowUpIcon, PulseIcon } from "./icons";
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
        <span className={styles.sonar} />
        <span className={styles.sonarB} />
        <svg className={styles.ringSvg} viewBox="0 0 56 56" aria-hidden="true">
          <circle className={styles.ringTrack} cx="28" cy="28" r="25" />
          <circle className={styles.ringArc} cx="28" cy="28" r="25" pathLength={100} />
        </svg>
        <span className={styles.heroDot} />
      </div>
      <div className={styles.heroText}>
        <strong className={styles.heroTitle}>{SUMMARY_LABEL[summary]}</strong>
        {connected && activePeer && (
          <span className={styles.heroStats}>
            <span className={styles.statRow}>
              <span className={styles.stat}>
                <ArrowDownIcon /> {humanizeBytes(activePeer.rx_bytes)}
              </span>
              <span className={styles.stat}>
                <ArrowUpIcon /> {humanizeBytes(activePeer.tx_bytes)}
              </span>
            </span>
            {summary === "Stale" && (
              <span className={styles.stat}>
                <PulseIcon /> handshake {humanizeAge(activePeer.handshake_age_secs)}
              </span>
            )}
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
