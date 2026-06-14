import { ChangeEvent, useState } from "react";
import { importServer, ServerInfo } from "../api";
import { cx } from "../lib/cx";
import shared from "./shared.module.css";
import forms from "./forms.module.css";

interface Props {
  /** Called with the updated server list after a successful import. */
  onImported: (servers: ServerInfo[]) => void;
  onCancel?: () => void;
}

/**
 * Import a wg-quick `.conf`: pick a file (the OS picker, via a native file input)
 * or paste its contents. The full text is sent to the daemon, which parses and
 * validates it — so all error reporting comes back from there.
 */
export function ImportForm({ onImported, onCancel }: Props) {
  const [name, setName] = useState("");
  const [conf, setConf] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    // Reset the input so picking the SAME file again still fires onChange.
    e.target.value = "";
    if (!file) return;
    setError(null);
    setConf(await file.text());
    // Default the name to the file stem (mullvad-nyc.conf → mullvad-nyc).
    if (!name.trim()) setName(file.name.replace(/\.conf$/i, ""));
  }

  async function submit() {
    setError(null);
    if (!name.trim()) {
      setError("Give this server a name.");
      return;
    }
    if (!conf.trim()) {
      setError("Choose a .conf file or paste its contents.");
      return;
    }
    setBusy(true);
    try {
      onImported(await importServer(name.trim(), conf));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={forms.form}>
      <label className={forms.field}>
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="home" />
      </label>

      <label className={forms.field}>
        <span>WireGuard config file</span>
        <input type="file" accept=".conf,text/plain" onChange={onFile} />
        <small>Pick a .conf file, or paste its contents below.</small>
      </label>

      <label className={forms.field}>
        <span>…or paste it</span>
        <textarea
          value={conf}
          onChange={(e) => setConf(e.target.value)}
          placeholder={"[Interface]\nPrivateKey = …\nAddress = 10.0.0.2/24\n\n[Peer]\n…"}
          rows={6}
          spellCheck={false}
        />
      </label>

      {error && <p className="error">{error}</p>}

      <div className={forms.formActions}>
        {onCancel && (
          <button type="button" className={cx(shared.btn, shared.ghost)} onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        )}
        <button type="button" className={cx(shared.btn, shared.primary)} onClick={submit} disabled={busy}>
          {busy ? "Importing…" : "Import"}
        </button>
      </div>
    </div>
  );
}
