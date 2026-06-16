import { useState } from "react";
import { addServer } from "../api";
import logoUrl from "../assets/logo.svg";
import { cx } from "../lib/cx";
import { CopyField } from "./CopyField";
import { ImportForm } from "./ImportForm";
import styles from "./Onboarding.module.css";
import { ServerForm } from "./ServerForm";
import shared from "./shared.module.css";

interface Props {
  /** Called once at least one server exists. */
  onComplete: () => void;
}

type Step =
  | { kind: "welcome" }
  | { kind: "import" }
  | { kind: "manual" }
  // After a manual add we show the generated public key to register.
  | { kind: "registered"; name: string; publicKey: string };

/**
 * First-run flow. A "server" is a complete WireGuard tunnel, so onboarding is just
 * "add your first one" — by importing a `.conf` (the common case) or entering it
 * manually (self-hosted, where we generate a keypair and show you the public key).
 */
export function Onboarding({ onComplete }: Props) {
  const [step, setStep] = useState<Step>({ kind: "welcome" });

  return (
    <main className={styles.onboarding}>
      <header className={styles.onboardingHead}>
        <Logo />
        <h1>wirefinder</h1>
        <p className={styles.tagline}>A calm home for your WireGuard tunnels.</p>
      </header>

      {step.kind === "welcome" && (
        <section className={shared.card}>
          <h2>Add your first server</h2>
          <p className="muted">
            A server is a complete WireGuard config. Import the <code>.conf</code> your provider
            gave you, or enter a self-hosted one by hand.
          </p>
          <button
            type="button"
            className={cx(shared.btn, shared.primary, shared.block)}
            onClick={() => setStep({ kind: "import" })}
          >
            Import a .conf file
          </button>
          <button
            type="button"
            className={cx(shared.btn, shared.ghost, shared.block)}
            onClick={() => setStep({ kind: "manual" })}
          >
            Add manually
          </button>
        </section>
      )}

      {step.kind === "import" && (
        <section className={shared.card}>
          <h2>Import a config</h2>
          <ImportForm onImported={onComplete} onCancel={() => setStep({ kind: "welcome" })} />
        </section>
      )}

      {step.kind === "manual" && (
        <section className={shared.card}>
          <h2>Add a server</h2>
          <p className="muted">This is the WireGuard peer you'll connect to.</p>
          <ServerForm
            submitLabel="Add server"
            onCancel={() => setStep({ kind: "welcome" })}
            onSubmit={async (spec) => {
              const servers = await addServer(spec);
              const me = servers.find((s) => s.name === spec.name);
              // Generated key → show the public key to register; otherwise we're done.
              if (me && spec.private_key === null) {
                setStep({ kind: "registered", name: me.name, publicKey: me.public_key });
              } else {
                onComplete();
              }
            }}
          />
        </section>
      )}

      {step.kind === "registered" && (
        <section className={shared.card}>
          <h2>Register your public key</h2>
          <p className="muted">
            We generated a keypair for <strong>{step.name}</strong>. Add this public key to that
            server's list of peers, then you're ready to connect.
          </p>
          <CopyField value={step.publicKey} />
          <button
            type="button"
            className={cx(shared.btn, shared.primary, shared.block)}
            onClick={onComplete}
          >
            Done
          </button>
        </section>
      )}
    </main>
  );
}

function Logo() {
  // The app/tray icon, reused as the onboarding mark so branding stays consistent.
  return <img className={styles.logo} src={logoUrl} alt="" width="56" height="56" />;
}
