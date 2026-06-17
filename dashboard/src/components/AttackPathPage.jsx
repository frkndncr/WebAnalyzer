import React, { useState, useEffect, useRef, useCallback } from 'react';
import { getApiUrl } from '../config';

/* ─── Helpers ─── */
const levels = { target: 0, recon: 1, technology: 1, vulnerability: 2, exploit: 3 };

const AttackPathPage = ({ domain, setCurrentDomain }) => {
  const [domainInput, setDomainInput] = useState(domain || '');
  const [recentDomains, setRecentDomains] = useState([]);
  const [intelData, setIntelData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);

  /* ── Fetch recent scans on mount ── */
  useEffect(() => {
    const fetchRecent = async () => {
      try {
        const res = await fetch(getApiUrl('/api/recent-scans'));
        if (res.ok) {
          const data = await res.json();
          const domains = Array.isArray(data)
            ? data.map((s) => s.domain || s.url || s.target).filter(Boolean)
            : [];
          setRecentDomains([...new Set(domains)]);
        }
      } catch (_) {}
    };
    fetchRecent();
  }, []);

  /* ── Fetch threat intel for a domain ── */
  const loadIntel = useCallback(async (targetDomain) => {
    if (!targetDomain || !targetDomain.trim()) return;
    const target = targetDomain.trim().toLowerCase();
    setLoading(true);
    setError('');
    setIntelData(null);
    setSelectedNode(null);
    try {
      const res = await fetch(getApiUrl('/api/threat-intel/' + encodeURIComponent(target)));
      if (!res.ok) throw new Error(`Server responded with ${res.status}`);
      const data = await res.json();
      setIntelData(data);
      if (setCurrentDomain) {
        setCurrentDomain(target);
      }
    } catch (err) {
      setError(err.message || 'Failed to load attack paths');
    } finally {
      setLoading(false);
    }
  }, [setCurrentDomain]);

  /* ── Auto-fetch on mount/domain change ── */
  useEffect(() => {
    if (domain) {
      setDomainInput(domain);
      loadIntel(domain);
    }
  }, [domain, loadIntel]);

  const hasData = intelData ? intelData.has_data !== false : false;
  const nodes = (intelData && intelData.attack_path?.graph?.nodes) || [];
  const edges = (intelData && intelData.attack_path?.graph?.edges) || [];
  const chains = (intelData && intelData.attack_path?.graph?.nodes) ? (intelData.attack_path.exploit_chains || []) : [];

  const handleLoadIntel = (e) => {
    e.preventDefault();
    loadIntel(domainInput);
  };

  const handleDomainSelect = (e) => {
    const val = e.target.value;
    if (val) {
      setDomainInput(val);
      loadIntel(val);
    }
  };

  const severityStyle = (sev) => {
    const map = {
      CRITICAL: { bg: 'rgba(255,0,85,0.15)', color: '#ff0055', border: 'rgba(255,0,85,0.4)' },
      HIGH: { bg: 'rgba(255,159,28,0.15)', color: '#ff9f1c', border: 'rgba(255,159,28,0.4)' },
      MEDIUM: { bg: 'rgba(0,242,254,0.15)', color: '#00f2fe', border: 'rgba(0,242,254,0.4)' },
      LOW: { bg: 'rgba(118,131,144,0.15)', color: '#768390', border: 'rgba(118,131,144,0.4)' },
    };
    const s = map[sev] || map.LOW;
    return {
      display: 'inline-block', padding: '2px 10px', borderRadius: '4px', fontSize: '0.72rem',
      fontWeight: 700, fontFamily: 'var(--font-mono)',
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
    };
  };

  return (
    <div className="animate-fade-in" style={{ maxWidth: '1200px', margin: '0 auto' }}>
      
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '2.2rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span className="text-gradient">ATTACK_PLANNER</span>
          <span style={{
            fontSize: '0.7rem', padding: '3px 12px', borderRadius: '4px',
            background: 'rgba(0,242,254,0.15)', color: '#00f2fe',
            border: '1px solid rgba(0,242,254,0.4)', fontFamily: 'var(--font-mono)',
            fontWeight: 700, letterSpacing: '2px',
            boxShadow: '0 0 12px rgba(0,242,254,0.3)',
          }}>🗺️ DISCOVERY</span>
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>
          Automated Attack Path Exploit Chain Planner & Threat Modeling
        </p>
      </div>

      {/* Domain Input Bar */}
      <form onSubmit={handleLoadIntel} className="glass-panel" style={{
        padding: '1.2rem 1.5rem', marginBottom: '2rem',
        display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap',
      }}>
        <div style={{ flex: 1, minWidth: '220px', position: 'relative' }}>
          <input
            className="input-glass"
            type="text"
            placeholder="Enter target domain (e.g. example.com)"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: '0.9rem' }}
          />
        </div>

        {recentDomains.length > 0 && (
          <select
            className="input-glass"
            onChange={handleDomainSelect}
            value=""
            style={{
              minWidth: '200px', fontFamily: 'var(--font-mono)', fontSize: '0.82rem',
              color: 'var(--text-secondary)', cursor: 'pointer',
              background: 'rgba(13,17,23,0.6)', border: '1px solid var(--panel-border)',
              borderRadius: '6px', padding: '0.55rem 0.8rem',
            }}
          >
            <option value="">📂 Recent Scans...</option>
            {recentDomains.map((d) => (
              <option key={d} value={d} style={{ background: '#0d1117', color: '#f0f6fc' }}>{d}</option>
            ))}
          </select>
        )}

        <button type="submit" className="btn-primary" disabled={loading || !domainInput.trim()} style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '0.6rem 1.6rem', fontFamily: 'var(--font-cyber)',
          fontSize: '0.82rem', letterSpacing: '2px', whiteSpace: 'nowrap',
          opacity: (loading || !domainInput.trim()) ? 0.5 : 1,
        }}>
          {loading ? (
            <>
              <span style={{ display: 'inline-block', animation: 'spin 1s linear infinite' }}>⟳</span>
              LOADING...
            </>
          ) : (
            <>⚡ MAP PATHS</>
          )}
        </button>
      </form>

      {/* Error State */}
      {error && (
        <div className="glass-panel" style={{
          padding: '1.2rem 1.5rem', marginBottom: '2rem',
          borderLeft: '3px solid #ff0055',
          background: 'rgba(255,0,85,0.05)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '1.4rem' }}>⚠️</span>
            <div>
              <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.82rem', color: '#ff0055', marginBottom: '4px' }}>CONNECTION ERROR</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{error}</div>
            </div>
          </div>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="glass-panel animate-fade-in" style={{
          padding: '4rem 2rem', textAlign: 'center', marginBottom: '2rem',
        }}>
          <div style={{ marginBottom: '1.5rem' }}>
            <svg width="60" height="60" viewBox="0 0 60 60" style={{ animation: 'spin 2s linear infinite' }}>
              <circle cx="30" cy="30" r="24" fill="none" stroke="rgba(0,242,254,0.15)" strokeWidth="4" />
              <path d="M30,6 A24,24 0 0,1 54,30" fill="none" stroke="#00f2fe" strokeWidth="4" strokeLinecap="round" />
            </svg>
          </div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '1rem', color: 'var(--accent-blue)', marginBottom: '0.5rem', letterSpacing: '3px' }}>
            CONSTRUCTING SALDIRI HARİTASI
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Processing CVE metrics, mapping pivot paths, modeling cyber kill chain...
          </div>
        </div>
      )}

      {/* Empty / No Data State */}
      {intelData && !hasData && !loading && (
        <div className="glass-panel animate-fade-in" style={{
          padding: '4rem 2rem', textAlign: 'center', marginBottom: '2rem',
          borderLeft: '3px solid var(--accent-blue)',
        }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔎</div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '1.1rem', color: 'var(--text-primary)', marginBottom: '0.8rem', letterSpacing: '2px' }}>
            NO PATH MODEL AVAILABLE
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '500px', margin: '0 auto' }}>
            No target mapping information exists for this domain. Run a full audit scan first.
          </div>
        </div>
      )}

      {/* Initial state */}
      {!intelData && !loading && !error && (
        <div className="glass-panel animate-fade-in" style={{
          padding: '4rem 2rem', textAlign: 'center', marginBottom: '2rem',
        }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🗺️</div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '1.1rem', color: 'var(--text-primary)', marginBottom: '0.8rem', letterSpacing: '2px' }}>
            AWAITING SYSTEM DESIGNATION
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '500px', margin: '0 auto' }}>
            Enter a domain above and click MAP PATHS to analyze potential attack vectors and compromise pivots.
          </div>
        </div>
      )}

      {/* Data display */}
      {intelData && hasData && !loading && (
        <div className="animate-fade-in" style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: '2rem', alignItems: 'start' }}>
          
          {/* Left: SVG Flowchart */}
          <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
            <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-cyber)', marginBottom: '1.2rem', color: 'var(--text-secondary)', letterSpacing: '2px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              🗺️ AUTOMATIC_EXPLOIT_FLOWCHART
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: '0.7rem', padding: '2px 8px',
                borderRadius: '4px', background: 'rgba(0,242,254,0.1)', color: 'var(--accent-blue)',
                border: '1px solid rgba(0,242,254,0.2)',
              }}>
                {nodes.length} nodes
              </span>
            </h3>

            {nodes.length > 0 ? (
              <div style={{ background: 'rgba(10,14,20,0.5)', borderRadius: '12px', border: '1px solid var(--panel-border)', padding: '10px' }}>
                <svg viewBox="0 0 680 450" style={{ width: '100%', minHeight: '400px', display: 'block' }}>
                  <defs>
                    <marker id="arrow" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(0,242,254,0.5)" />
                    </marker>
                    <filter id="nodeGlow" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="6" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                  </defs>

                  {/* Draw Edges */}
                  {(() => {
                    const columns = [[], [], [], []];
                    nodes.forEach(node => {
                      const lvl = levels[node.type] != null ? levels[node.type] : 2;
                      columns[lvl].push(node);
                    });

                    const width = 680;
                    const height = 450;
                    const positions = {};
                    
                    columns.forEach((colNodes, colIndex) => {
                      const x = 70 + colIndex * 180;
                      const n = colNodes.length;
                      colNodes.forEach((node, nodeIndex) => {
                        positions[node.id] = { x, y: (height / (n + 1)) * (nodeIndex + 1) };
                      });
                    });

                    return (
                      <>
                        {edges.map((edge, idx) => {
                          const fromPos = positions[edge.from];
                          const toPos = positions[edge.to];
                          if (!fromPos || !toPos) return null;
                          return (
                            <g key={'edge-' + idx}>
                              <line
                                x1={fromPos.x} y1={fromPos.y}
                                x2={toPos.x} y2={toPos.y}
                                stroke="rgba(0,242,254,0.3)"
                                strokeWidth="2.5"
                                markerEnd="url(#arrow)"
                              />
                              <circle r="4" fill="#00f2fe" filter="url(#nodeGlow)">
                                <animateMotion
                                  dur={`${2.5 + (idx % 2) * 0.8}s`}
                                  repeatCount="indefinite"
                                  path={`M ${fromPos.x} ${fromPos.y} L ${toPos.x} ${toPos.y}`}
                                />
                              </circle>
                              <text
                                x={(fromPos.x + toPos.x) / 2}
                                y={((fromPos.y + toPos.y) / 2) - 8}
                                fill="rgba(118,131,144,0.7)"
                                fontSize="8"
                                fontFamily="var(--font-mono)"
                                textAnchor="middle"
                              >
                                {edge.label}
                              </text>
                            </g>
                          );
                        })}

                        {/* Draw Nodes */}
                        {nodes.map((node) => {
                          const pos = positions[node.id];
                          if (!pos) return null;
                          
                          const isSelected = selectedNode?.id === node.id;
                          const isCritical = node.severity === 'Critical';
                          const isHigh = node.severity === 'High';
                          const nodeColor = isCritical ? '#ff0055' : isHigh ? '#ff9f1c' : node.type === 'target' ? '#00f2fe' : '#39ff14';

                          return (
                            <g
                               key={node.id}
                              style={{ cursor: 'pointer' }}
                              onClick={() => setSelectedNode(node)}
                            >
                              <circle
                                cx={pos.x} cy={pos.y}
                                r={isSelected ? 22 : 17}
                                fill="none"
                                stroke={nodeColor}
                                strokeWidth="2.5"
                                strokeDasharray={isSelected ? '0' : '4 2'}
                                opacity={isSelected ? 1 : 0.4}
                                filter={isSelected ? 'url(#nodeGlow)' : 'none'}
                                style={{ transition: 'all 0.2s ease' }}
                              />
                              <circle
                                cx={pos.x} cy={pos.y}
                                r="13"
                                fill="#0d1117"
                                stroke={nodeColor}
                                strokeWidth="3.5"
                              />
                              <text
                                x={pos.x} y={pos.y + 4}
                                fill={nodeColor}
                                fontSize="11"
                                fontWeight="bold"
                                fontFamily="var(--font-mono)"
                                textAnchor="middle"
                              >
                                {node.type === 'target' ? '🎯' : node.type === 'recon' ? '🔍' : node.type === 'technology' ? '⚙️' : isCritical ? '💀' : '⚠'}
                              </text>
                              <text
                                x={pos.x} y={pos.y + 30}
                                fill={isSelected ? '#ffffff' : 'var(--text-secondary)'}
                                fontSize="9"
                                fontWeight={isSelected ? 'bold' : 'normal'}
                                fontFamily="var(--font-cyber)"
                                textAnchor="middle"
                                style={{ transition: 'fill 0.2s' }}
                              >
                                {node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label}
                              </text>
                            </g>
                          );
                        })}
                      </>
                    );
                  })()}
                </svg>
              </div>
            ) : (
              <div style={{ padding: '3rem 1rem', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                No active compromise route mapped.
              </div>
            )}
          </div>

          {/* Right: Info & Exploit Chains */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            
            {/* Selected Node Panel */}
            <div className="glass-panel" style={{ padding: '1.5rem', minHeight: '180px', borderLeft: selectedNode ? `3px solid ${selectedNode.severity === 'Critical' ? '#ff0055' : selectedNode.severity === 'High' ? '#ff9f1c' : '#00f2fe'}` : '1px solid var(--panel-border)' }}>
              <h4 style={{ fontSize: '0.8rem', fontFamily: 'var(--font-cyber)', color: 'var(--text-secondary)', marginBottom: '1rem', letterSpacing: '1.5px' }}>
                📦 NODE_PARAMETERS
              </h4>

              {selectedNode ? (
                <div className="animate-fade-in">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                    <span style={{ fontSize: '1.2rem' }}>
                      {selectedNode.type === 'target' ? '🎯' : selectedNode.type === 'recon' ? '🔎' : '⚠️'}
                    </span>
                    <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.9rem', color: '#ffffff', fontWeight: 700 }}>
                      {selectedNode.label}
                    </div>
                  </div>

                  <div style={{ marginBottom: '10px' }}>
                    <span style={severityStyle(selectedNode.severity ? selectedNode.severity.toUpperCase() : 'INFO')}>
                      {selectedNode.severity.toUpperCase()}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-secondary)', marginLeft: '10px' }}>
                      Type: {selectedNode.type}
                    </span>
                  </div>

                  <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                    {selectedNode.description}
                  </p>
                </div>
              ) : (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)', textAlign: 'center', padding: '1.5rem 0' }}>
                  ⚡ Click any node inside the flowchart diagram to inspect vulnerabilities and logical mitigation playbooks.
                </div>
              )}
            </div>

            {/* Exploit Chains List */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <h4 style={{ fontSize: '0.8rem', fontFamily: 'var(--font-cyber)', color: 'var(--text-secondary)', marginBottom: '1.2rem', letterSpacing: '1.5px' }}>
                🔗 EXPLOIT_CHAINS_DETAILED
              </h4>

              {chains.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
                  {chains.map((chain, cidx) => {
                    const cColor = chain.severity === 'Critical' ? '#ff0055' : chain.severity === 'High' ? '#ff9f1c' : '#00f2fe';
                    return (
                      <div key={cidx} style={{
                        padding: '10px 12px', borderRadius: '8px',
                        background: 'rgba(255,255,255,0.01)',
                        border: '1px solid var(--panel-border)',
                        borderLeft: `3px solid ${cColor}`
                      }}>
                        <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.82rem', fontWeight: 'bold', color: '#ffffff', marginBottom: '4px' }}>
                          {chain.name}
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-secondary)', marginBottom: '10px' }}>
                          IMPACT: <span style={{ color: cColor }}>{chain.impact}</span>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', position: 'relative', paddingLeft: '14px' }}>
                          <div style={{ position: 'absolute', left: '4px', top: '5px', bottom: '5px', width: '1px', background: 'rgba(255,255,255,0.1)' }} />
                          {chain.steps.map((step, sidx) => (
                            <div key={sidx} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.74rem', fontFamily: 'var(--font-mono)' }}>
                              <div style={{
                                position: 'absolute', left: '2px', width: '5px', height: '5px',
                                borderRadius: '50%', background: sidx === chain.steps.length - 1 ? cColor : 'rgba(255,255,255,0.4)',
                                boxShadow: sidx === chain.steps.length - 1 ? `0 0 6px ${cColor}` : 'none'
                              }} />
                              <span style={{ color: sidx === chain.steps.length - 1 ? cColor : 'var(--text-secondary)' }}>
                                {step}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)', textAlign: 'center' }}>
                  No exploit chains loaded.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* Styles */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes blinkDot {
          0%, 100% { opacity: 0.3; }
          50% { opacity: 1; }
        }
      `}</style>
    </div>
  );
};

export default AttackPathPage;
