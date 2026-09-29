/// keyward's mark: a shield with a keyhole. The same motif lives in the menu
/// bar and on the line between a host and a key, so it is a load-bearing
/// element rather than decoration.
export function Mark({ size = 20, tone = "currentColor" }: { size?: number; tone?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 20 5.5v6.2c0 4.7-3.2 8.5-8 10.3-4.8-1.8-8-5.6-8-10.3V5.5L12 2.5Z"
        stroke={tone}
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="10.6" r="2.5" stroke={tone} strokeWidth="1.6" />
      <path d="M12 13.1v3.9" stroke={tone} strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

/// The node on the line between a host pattern and a key. It is the product's
/// signature: a route passes through one keyhole rather than a bunch.
export function Keyhole({ active = false }: { active?: boolean }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true" className={active ? "kh on" : "kh"}>
      <circle cx="7" cy="5.6" r="2.6" stroke="currentColor" strokeWidth="1.4" />
      <path d="M7 8.2v3.2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}
