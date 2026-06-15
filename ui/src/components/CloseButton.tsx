import { getCurrentWindow } from "@tauri-apps/api/window";
import styles from "./CloseButton.module.css";

type CloseButtonProps = {
  onClick?: () => void;
};

/** The window's close control. Pinned to the top-right corner, rendered once at the app shell. */
export function CloseButton({ onClick }: CloseButtonProps) {
  return (
    <button
      type="button"
      className={styles.close}
      aria-label="Close"
      onClick={onClick ?? (() => getCurrentWindow().hide())}
    >
      <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
        <line x1="1" y1="1" x2="9" y2="9" stroke="currentColor" strokeWidth="1" />
        <line x1="9" y1="1" x2="1" y2="9" stroke="currentColor" strokeWidth="1" />
      </svg>
    </button>
  );
}
