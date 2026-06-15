import { useEffect, useRef, useState } from "react";
import { cx } from "../lib/cx";
import styles from "./Menu.module.css";

export interface MenuItem {
  label: string;
  /** Return a string to confirm in place: the menu stays open and the item's label is
   *  briefly swapped for that string. Return nothing to close the menu on click. */
  // biome-ignore lint/suspicious/noConfusingVoidType: void (not undefined) keeps Promise<void> callers assignable.
  onClick: () => void | string | Promise<void | string>;
  /** Render in the danger color — for destructive actions like Remove. */
  danger?: boolean;
  disabled?: boolean;
}

const CONFIRM_MS = 1500;

/** A small, dependency-free overflow menu: a kebab (⋮) button that opens a popup of
 *  actions. Closes on outside-click, Escape, or after an item is chosen. */
export function Menu({ label = "More actions", items }: { label?: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  // The item (by label) currently showing a transient confirmation, and what to show.
  const [confirm, setConfirm] = useState<{ key: string; text: string } | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Drop any pending confirmation revert if the menu unmounts.
  useEffect(() => () => clearTimeout(timer.current ?? undefined), []);

  async function choose(item: MenuItem) {
    const result = await item.onClick();
    if (typeof result === "string") {
      // Confirm in place: keep the menu open, flash the label, then revert.
      clearTimeout(timer.current ?? undefined);
      setConfirm({ key: item.label, text: result });
      timer.current = setTimeout(() => setConfirm(null), CONFIRM_MS);
    } else {
      setOpen(false);
    }
  }

  return (
    <div className={styles.menu} ref={ref}>
      <button
        type="button"
        className={styles.trigger}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        onClick={() => setOpen((o) => !o)}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" fill="currentColor">
          <circle cx="8" cy="3" r="1.5" />
          <circle cx="8" cy="8" r="1.5" />
          <circle cx="8" cy="13" r="1.5" />
        </svg>
      </button>
      {open && (
        <div className={styles.list} role="menu">
          {items.map((item) => (
            <button
              key={item.label}
              type="button"
              role="menuitem"
              disabled={item.disabled}
              className={cx(styles.item, item.danger && styles.danger)}
              onClick={() => choose(item)}
            >
              {confirm?.key === item.label ? confirm.text : item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
