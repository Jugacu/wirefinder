/**
 * Join class names, dropping falsy values. Lets us combine CSS-module classes
 * (e.g. `styles.btn`) with global utility strings (e.g. "muted") and conditional
 * classes without pulling in a dependency.
 *
 *   cx(styles.btn, styles.primary, isSmall && styles.small)
 *   cx("error", styles.toast)
 */
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
