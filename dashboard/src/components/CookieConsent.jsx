import React, { useState } from 'react';

const KEY = 'wa_cookie_ok';

export default function CookieConsent({ onNav }) {
  // Read consent once during initial render; avoids a setState-in-effect.
  const [show, setShow] = useState(() => {
    try { return localStorage.getItem(KEY) !== '1'; } catch { return true; }
  });

  const accept = () => {
    try { localStorage.setItem(KEY, '1'); } catch { /* storage blocked — dismiss anyway */ }
    setShow(false);
  };

  if (!show) return null;
  return (
    <div className="cookie" role="dialog" aria-label="Cookie notice">
      <p>
        This site only uses the browser storage it needs to work. No tracking or advertising cookies.{' '}
        <button className="btn ghost sm" style={{ padding: 0 }} onClick={() => onNav('legal')}>Cookie policy</button>
      </p>
      <button className="btn primary sm" onClick={accept}>Got it</button>
    </div>
  );
}
