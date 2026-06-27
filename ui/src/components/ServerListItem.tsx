import type { Ref } from "react";
import type { ServerDetail, ServerInfo, ServerSpec } from "../api";
import { cx } from "../lib/cx";
import styles from "./Dashboard.module.css";
import { Menu } from "./Menu";
import { ServerForm } from "./ServerForm";
import shared from "./shared.module.css";
import { busyKey } from "./useServerList";

/** Label for a server's switch button, given the in-flight `busy` task (if any). */
function switchButtonLabel(s: ServerInfo, busy: string | null): string {
  if (busy === busyKey.switch(s.name)) return "Switching…";
  if (!s.active) return "Connect";
  return s.state === "Connecting" ? "Connecting…" : "Connected";
}

interface Props {
  server: ServerInfo;
  /** The key of the action currently in flight across the dashboard, or null. */
  busy: string | null;
  /** The server being edited (its secret-free detail), or null. */
  editing: ServerDetail | null;
  /** Attached to the edit form when this row is the one being edited (for scroll). */
  editFormRef: Ref<HTMLDivElement>;
  onSwitch: () => void;
  onEdit: () => void;
  /** Copy the public key; returns the label the menu flashes to confirm. */
  onCopyKey: () => Promise<string>;
  onRemove: () => void;
  onCancelEdit: () => void;
  onSubmitEdit: (server: ServerSpec) => Promise<void>;
}

/** One server in the list: its status row + action menu, plus the inline edit form
 *  when this row is being edited. */
export function ServerListItem({
  server: s,
  busy,
  editing,
  editFormRef,
  onSwitch,
  onEdit,
  onCopyKey,
  onRemove,
  onCancelEdit,
  onSubmitEdit,
}: Props) {
  const isEditing = editing?.name === s.name;

  return (
    <li className={s.active ? styles.active : undefined}>
      <div className={styles.serverRow}>
        <span className={styles.dot} aria-hidden>
          {s.active ? "●" : "○"}
        </span>
        <span className={styles.serverMeta}>
          <span className={styles.name}>{s.name}</span>
          <span className={styles.endpoint}>{s.endpoint}</span>
          <span className={styles.endpoint}>{s.addresses.join(", ")}</span>
        </span>
        <span className={styles.rowActions}>
          <button
            type="button"
            className={cx(shared.btn, shared.primary, shared.small)}
            disabled={s.active || busy !== null}
            onClick={onSwitch}
          >
            {switchButtonLabel(s, busy)}
          </button>
          <Menu
            label={`Actions for ${s.name}`}
            items={[
              {
                // Editing the active tunnel is disallowed (daemon rejects it too);
                // mirror Remove's disabled rule.
                label: busy === busyKey.edit(s.name) ? "Opening…" : "Edit",
                disabled: busy !== null || s.active,
                onClick: onEdit,
              },
              { label: "Copy public key", onClick: onCopyKey },
              {
                label: "Remove",
                danger: true,
                disabled: busy !== null || s.active,
                onClick: onRemove,
              },
            ]}
          />
        </span>
      </div>

      {isEditing && editing && (
        <div className={styles.editForm} ref={editFormRef}>
          <ServerForm
            initial={editing}
            submitLabel="Save changes"
            onCancel={onCancelEdit}
            onSubmit={onSubmitEdit}
          />
        </div>
      )}
    </li>
  );
}
