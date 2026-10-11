import React from 'react';
import { Icon } from './ui';
import { SOCIALS, AUTHOR, COMPANY } from '../lib/site';

export default function Footer({ onNav }) {
  const year = new Date().getFullYear();
  return (
    <footer className="footer">
      <div>
        © {year} {COMPANY} · Built by{' '}
        <a href="https://github.com/frkndncr" target="_blank" rel="noreferrer">{AUTHOR}</a>
        {' · '}
        <button className="btn ghost sm" style={{ padding: '0 2px' }} onClick={() => onNav('legal')}>Legal &amp; Privacy</button>
      </div>
      <div className="socials">
        {SOCIALS.map((s) => (
          <a key={s.id} className="icon-btn" href={s.url} target="_blank" rel="noreferrer" aria-label={s.label} title={s.label}>
            <Icon name={s.icon} size={16} />
          </a>
        ))}
      </div>
    </footer>
  );
}
