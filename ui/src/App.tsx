import { useCallback, useEffect, useState } from "react";
import { listServers, ServerInfo } from "./api";
import { Dashboard } from "./components/Dashboard";
import { Onboarding } from "./components/Onboarding";
import { cx } from "./lib/cx";
import shared from "./components/shared.module.css";
import styles from "./App.module.css";

type Phase =
    | { kind: "loading" }
    | { kind: "offline"; error: string }
    | { kind: "ready"; servers: ServerInfo[] };

export default function App() {
    const [phase, setPhase] = useState<Phase>({ kind: "loading" });

    const load = useCallback(async () => {
        try {
            const servers = await listServers();
            setPhase({ kind: "ready", servers });
        } catch (e) {
            setPhase({ kind: "offline", error: String(e) });
        }
    }, []);

    useEffect(() => {
        load();
    }, [load]);

    if (phase.kind === "loading") {
        return (
            <main className={styles.splash}>
                <span className={styles.spinner} aria-label="Loading" />
            </main>
        );
    }

    if (phase.kind === "offline") {
        return (
            <main className={styles.splash}>
                <div className={cx(shared.card, shared.center)}>
                    <h2>Can't reach the daemon</h2>
                    <p className="muted">
                        wirefinderd isn't responding. Make sure the service is running:
                    </p>
                    <code className="block">sudo systemctl start wirefinderd</code>
                    <p className="muted">
                        You also need to be a member of the <code>wirefinder</code> group to
                        connect. Add yourself and log back in:
                    </p>
                    <code className="block">sudo usermod -aG wirefinder $USER</code>
                    <p className="error small">{phase.error}</p>
                    <br />
                    <button className={cx(shared.btn, shared.primary)} onClick={() => { setPhase({ kind: "loading" }); load(); }}>
                        Retry
                    </button>
                </div>
            </main>
        );
    }

    // No servers yet → onboarding. Removing the last server drops back here.
    if (phase.servers.length === 0) {
        return <Onboarding onComplete={load} />;
    }

    return (
        <Dashboard
            onServersEmptied={load}
            onOffline={() =>
                setPhase({ kind: "offline", error: "Lost connection to wirefinderd." })
            }
        />
    );
}
