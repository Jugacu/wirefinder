// Small line icons shared by the server section. 16×16, stroked with `currentColor`
// so they inherit the surrounding text/button color (and its hover transition).

interface IconProps {
  className?: string;
}

/** Magnifier — the search affordance. */
export function SearchIcon({ className }: IconProps) {
  return (
    <svg
      className={className}
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden="true"
    >
      <circle cx="7" cy="7" r="4.5" />
      <line x1="10.5" y1="10.5" x2="14" y2="14" strokeLinecap="round" />
    </svg>
  );
}

/** Down arrow — received traffic in the hero stats. */
export function ArrowDownIcon({ className }: IconProps) {
  return (
    <svg
      className={className}
      width="11"
      height="11"
      viewBox="0 0 12 12"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <line x1="6" y1="1.5" x2="6" y2="10" />
      <polyline points="2.5,6.5 6,10 9.5,6.5" />
    </svg>
  );
}

/** Up arrow — sent traffic in the hero stats. */
export function ArrowUpIcon({ className }: IconProps) {
  return (
    <svg
      className={className}
      width="11"
      height="11"
      viewBox="0 0 12 12"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <line x1="6" y1="10.5" x2="6" y2="2" />
      <polyline points="2.5,5.5 6,2 9.5,5.5" />
    </svg>
  );
}

/** A heartbeat trace — the handshake-age stat in the hero. */
export function PulseIcon({ className }: IconProps) {
  return (
    <svg
      className={className}
      width="11"
      height="11"
      viewBox="0 0 12 12"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="0.75,6 3,6 4.5,2.5 7.5,9.5 9,6 11.25,6" />
    </svg>
  );
}

/** An × — shown on the search toggle while the field is open. */
export function CloseIcon({ className }: IconProps) {
  return (
    <svg
      className={className}
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden="true"
    >
      <line x1="4" y1="4" x2="12" y2="12" strokeLinecap="round" />
      <line x1="12" y1="4" x2="4" y2="12" strokeLinecap="round" />
    </svg>
  );
}
