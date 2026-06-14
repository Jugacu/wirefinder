import { useState } from "react";

/** A read-only value with a one-click copy button — used to surface the public key. */
type State = "idle" | "copied" | "failed";

export function CopyField({ value }: { value: string }) {
  const [state, setState] = useState<State>("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      // Clipboard can be unavailable; the value stays selectable by hand.
      setState("failed");
    }
    setTimeout(() => setState("idle"), 1500);
  }

  const label = state === "copied" ? "Copied ✓" : state === "failed" ? "Copy failed" : "Copy";

  return (
    <div className="copy-field">
      <code>{value}</code>
      <button type="button" className="btn ghost small" onClick={copy}>
        {label}
      </button>
    </div>
  );
}

/** A compact copy button (no value shown) — for tight spots like a server row. */
export function CopyButton({ value, label = "Copy key" }: { value: string; label?: string }) {
  const [state, setState] = useState<State>("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
    setTimeout(() => setState("idle"), 1500);
  }

  const text = state === "copied" ? "Copied ✓" : state === "failed" ? "Failed" : label;

  return (
    <button type="button" className="btn ghost small" onClick={copy} title="Copy public key">
      {text}
    </button>
  );
}
