/** The Watchpost shield and name, used in the sidebar and on the sign-in page. */
export function Brand() {
  return (
    <div className="brand">
      <svg className="brand__mark" viewBox="0 0 32 32" aria-hidden="true">
        <path d="M16 5 6 9v6.5c0 6 4.2 10.4 10 11.5 5.8-1.1 10-5.5 10-11.5V9L16 5z" />
        <circle cx="16" cy="15.5" r="3.2" />
      </svg>
      <span className="brand__name">Watchpost</span>
    </div>
  );
}
