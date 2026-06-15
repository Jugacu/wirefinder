import { type FormEvent, useState } from "react";
import type { ServerSpec } from "../api";
import { cx } from "../lib/cx";
import forms from "./forms.module.css";
import shared from "./shared.module.css";

interface Props {
  /** Submit handler. Throwing/rejecting surfaces as an inline error. */
  onSubmit: (server: ServerSpec) => Promise<void>;
  onCancel?: () => void;
  submitLabel?: string;
}

const csv = (s: string) =>
  s
    .split(",")
    .map((x) => x.trim())
    .filter((x) => x.length > 0);

const numOrNull = (s: string): number | null | undefined => {
  const t = s.trim();
  if (t === "") return null;
  const n = Number(t);
  return Number.isInteger(n) && n >= 0 ? n : undefined; // undefined = invalid
};

/**
 * The add-a-tunnel form for the "create manually" path (self-hosted servers).
 * By default the daemon GENERATES the keypair — the user pastes only the server's
 * public key. The CSV fields are split on submit; cryptographic validation happens
 * daemon-side, so we only enforce that required fields are present and numbers parse.
 */
export function ServerForm({ onSubmit, onCancel, submitLabel = "Add server" }: Props) {
  const [name, setName] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [addresses, setAddresses] = useState("10.0.0.2/24");
  const [allowedIps, setAllowedIps] = useState("0.0.0.0/0");
  const [keyMode, setKeyMode] = useState<"generate" | "import">("generate");
  const [privateKey, setPrivateKey] = useState("");
  const [dns, setDns] = useState("");
  const [presharedKey, setPresharedKey] = useState("");
  const [keepalive, setKeepalive] = useState("25");
  const [listenPort, setListenPort] = useState("");
  const [mtu, setMtu] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (!name.trim() || !publicKey.trim() || !endpoint.trim() || !addresses.trim()) {
      setError("Name, server public key, endpoint, and tunnel address are required.");
      return;
    }
    if (keyMode === "import" && !privateKey.trim()) {
      setError("Paste your private key, or switch to generating one.");
      return;
    }
    const ka = numOrNull(keepalive);
    const port = numOrNull(listenPort);
    const m = numOrNull(mtu);
    if (ka === undefined || port === undefined || m === undefined) {
      setError("Keepalive, listen port, and MTU must be whole numbers (or empty).");
      return;
    }

    const server: ServerSpec = {
      name: name.trim(),
      private_key: keyMode === "import" ? privateKey.trim() : null,
      public_key: publicKey.trim(),
      endpoint: endpoint.trim(),
      addresses: csv(addresses),
      allowed_ips: csv(allowedIps),
      listen_port: port,
      mtu: m,
      dns: csv(dns),
      preshared_key: presharedKey.trim() || null,
      keepalive: ka,
    };

    setBusy(true);
    try {
      await onSubmit(server);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className={forms.form} onSubmit={submit}>
      <label className={forms.field}>
        <span>Name</span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="home"
          autoFocus
        />
      </label>

      <label className={forms.field}>
        <span>Server public key</span>
        <input
          value={publicKey}
          onChange={(e) => setPublicKey(e.target.value)}
          placeholder="base64 public key from your server"
          spellCheck={false}
        />
      </label>

      <label className={forms.field}>
        <span>Endpoint</span>
        <input
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
          placeholder="vpn.example.com:51820"
          spellCheck={false}
        />
      </label>

      <label className={forms.field}>
        <span>Tunnel addresses</span>
        <input
          value={addresses}
          onChange={(e) => setAddresses(e.target.value)}
          placeholder="10.0.0.2/24"
          spellCheck={false}
        />
        <small>
          The address this server assigned to your device. Comma-separated for dual-stack.
        </small>
      </label>

      <label className={forms.field}>
        <span>Allowed IPs</span>
        <input
          value={allowedIps}
          onChange={(e) => setAllowedIps(e.target.value)}
          placeholder="0.0.0.0/0"
          spellCheck={false}
        />
        <small>Comma-separated. 0.0.0.0/0 routes all traffic through the tunnel.</small>
      </label>

      <div className={forms.field}>
        <span>Key</span>
        {/* biome-ignore lint/a11y/useSemanticElements: a segmented toggle, not a form fieldset; <fieldset> would impose unwanted default chrome */}
        <div className={forms.segmented} role="group" aria-label="Key source">
          <button
            type="button"
            aria-pressed={keyMode === "generate"}
            className={keyMode === "generate" ? forms.active : undefined}
            onClick={() => setKeyMode("generate")}
          >
            Generate
          </button>
          <button
            type="button"
            aria-pressed={keyMode === "import"}
            className={keyMode === "import" ? forms.active : undefined}
            onClick={() => setKeyMode("import")}
          >
            Use existing
          </button>
        </div>
        <small>
          {keyMode === "generate"
            ? "We'll create a keypair; register the public key on your server after adding."
            : "Use a private key you already registered with your server."}
        </small>
      </div>

      {keyMode === "import" && (
        <label className={forms.field}>
          <span>Private key</span>
          <input
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="base64 private key"
            spellCheck={false}
          />
        </label>
      )}

      <details className={forms.advanced}>
        <summary>Advanced</summary>
        <label className={forms.field}>
          <span>DNS servers</span>
          <input
            value={dns}
            onChange={(e) => setDns(e.target.value)}
            placeholder="10.0.0.1 (optional)"
            spellCheck={false}
          />
          <small>Comma-separated. Routed through the tunnel while connected.</small>
        </label>
        <label className={forms.field}>
          <span>Pre-shared key</span>
          <input
            value={presharedKey}
            onChange={(e) => setPresharedKey(e.target.value)}
            placeholder="optional extra symmetric key"
            spellCheck={false}
          />
        </label>
        <label className={forms.field}>
          <span>Keepalive (seconds)</span>
          <input
            value={keepalive}
            onChange={(e) => setKeepalive(e.target.value)}
            placeholder="25"
            inputMode="numeric"
          />
          <small>Recommended behind NAT. Leave empty to disable.</small>
        </label>
        <label className={forms.field}>
          <span>Listen port</span>
          <input
            value={listenPort}
            onChange={(e) => setListenPort(e.target.value)}
            placeholder="auto"
            inputMode="numeric"
          />
        </label>
        <label className={forms.field}>
          <span>MTU</span>
          <input
            value={mtu}
            onChange={(e) => setMtu(e.target.value)}
            placeholder="default"
            inputMode="numeric"
          />
        </label>
      </details>

      {error && <p className="error">{error}</p>}

      <div className={forms.formActions}>
        {onCancel && (
          <button
            type="button"
            className={cx(shared.btn, shared.ghost)}
            onClick={onCancel}
            disabled={busy}
          >
            Cancel
          </button>
        )}
        <button type="submit" className={cx(shared.btn, shared.primary)} disabled={busy}>
          {busy ? "Saving…" : submitLabel}
        </button>
      </div>
    </form>
  );
}
