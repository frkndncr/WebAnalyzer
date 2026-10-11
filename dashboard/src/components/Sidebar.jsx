import React from 'react';
import { Icon } from './ui';

const NAV = [
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'scan', label: 'New Scan', icon: 'scan' },
  { id: 'results', label: 'Results', icon: 'results' },
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

      <div className="nav-group-label">Workspace</div>
      {NAV.map((n) => (
        <button
          key={n.id}
          className={`nav-item ${active === n.id ? 'active' : ''}`}
          onClick={() => onNav(n.id)}
        >
          <Icon name={n.icon} className="nav-ico" />
          {n.label}
        </button>
      ))}

      <div className="sidebar-foot">
        <div>
          <span className={`dot ${online ? 'ok' : 'off'}`} />
          API {online ? 'online' : 'offline'}
        </div>
        {health?.version && <div style={{ marginTop: 4 }}>v{health.version}</div>}
      </div>
    </aside>
  );
}
