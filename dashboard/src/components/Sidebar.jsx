import React from 'react';
import { Icon } from './ui';
import { SOCIALS } from '../lib/site';

const GROUPS = [
  {
    label: 'Workspace',
    items: [
      { id: 'overview', label: 'Overview', icon: 'overview' },
      { id: 'scan', label: 'New Scan', icon: 'scan' },
      { id: 'results', label: 'Results', icon: 'results' },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { id: 'threat', label: 'Threat Intel', icon: 'target' },
      { id: 'network', label: 'Network Map', icon: 'network' },
      { id: 'attack', label: 'Attack Path', icon: 'route' },
    ],
  },
];

export default function Sidebar({ active, onNav, health }) {
  const online = health?.api_status === 'online';
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="logo">W</div>
        <div>
          <b>WebAnalyzer</b>
          <span>Security Console</span>
        </div>
      </div>

      {GROUPS.map((g) => (
        <React.Fragment key={g.label}>
          <div className="nav-group-label">{g.label}</div>
          {g.items.map((n) => (
            <button key={n.id} className={`nav-item ${active === n.id ? 'active' : ''}`} onClick={() => onNav(n.id)}>
              <Icon name={n.icon} className="nav-ico" />
              {n.label}
            </button>
          ))}
        </React.Fragment>
      ))}

      <div className="nav-group-label">About</div>
      <button className={`nav-item ${active === 'legal' ? 'active' : ''}`} onClick={() => onNav('legal')}>
        <Icon name="scale" className="nav-ico" />
        Legal &amp; Privacy
      </button>

      <div className="sidebar-foot">
        <div className="socials" style={{ marginBottom: 12 }}>
          {SOCIALS.map((s) => (
            <a key={s.id} className="icon-btn" href={s.url} target="_blank" rel="noreferrer" aria-label={s.label} title={s.label}>
              <Icon name={s.icon} size={16} />
            </a>
          ))}
        </div>
        <div>
          <span className={`dot ${online ? 'ok' : 'off'}`} />
          API {online ? 'online' : 'offline'}{health?.version ? ` · v${health.version}` : ''}
        </div>
      </div>
    </aside>
  );
}
