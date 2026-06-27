import {
  type KeyboardEvent as ReactKeyboardEvent,
  type RefObject,
  useEffect,
  useRef,
  useState,
} from "react";

export interface ServerSearch {
  /** Whether the filter field is revealed. */
  open: boolean;
  /** Ref for the filter input, so the toggle and shortcut can focus it. */
  inputRef: RefObject<HTMLInputElement | null>;
  /** Reveal the field if hidden, or collapse (and clear) it if shown. */
  toggle: () => void;
  /** Collapse the field and clear the active filter. */
  close: () => void;
  /** Escape handling for the field: clear a query, then collapse when empty. */
  onFieldKeyDown: (e: ReactKeyboardEvent<HTMLInputElement>) => void;
}

/**
 * The transient filter affordance: a magnifier that reveals a search field, focuses
 * it, and collapses (clearing the filter) when dismissed. `onReveal` lets the caller
 * dismiss other transient UI — an open add/import form — when search takes over.
 */
export function useServerSearch(
  query: string,
  setQuery: (q: string) => void,
  onReveal: () => void,
): ServerSearch {
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  function reveal() {
    setOpen(true);
    onReveal();
    // The field may still be collapsed (pointer-events: none); focus on the next
    // frame, once the open state has applied.
    requestAnimationFrame(() => inputRef.current?.focus());
  }

  function close() {
    setOpen(false);
    setQuery("");
  }

  function toggle() {
    if (open) close();
    else reveal();
  }

  function onFieldKeyDown(e: ReactKeyboardEvent<HTMLInputElement>) {
    if (e.key !== "Escape") return;
    e.preventDefault();
    // First Escape clears a query; a second (empty) collapses the field.
    if (query) {
      setQuery("");
    } else {
      setOpen(false);
      inputRef.current?.blur();
    }
  }

  // Global shortcut: "/" or Cmd/Ctrl+K reveals the filter. "/" is ignored while the
  // user is typing in another field so it never steals a keystroke from a form;
  // Cmd/Ctrl+K is an explicit chord and works anywhere.
  // biome-ignore lint/correctness/useExhaustiveDependencies: listener is registered once on mount; `reveal` only touches stable setters/refs.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const t = e.target as HTMLElement | null;
      const typing =
        t?.tagName === "INPUT" || t?.tagName === "TEXTAREA" || t?.isContentEditable === true;
      const cmdK = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k";
      const slash = e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey;
      if (cmdK || (slash && !typing)) {
        e.preventDefault();
        reveal();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  return { open, inputRef, toggle, close, onFieldKeyDown };
}
