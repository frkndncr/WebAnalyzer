import React, { useState } from 'react';

const InteractiveJson = ({ data, initExpanded = false }) => {
  const [expanded, setExpanded] = useState(initExpanded);

  if (typeof data !== 'object' || data === null) {
    let styleClass = 'json-string';
    if (typeof data === 'number') styleClass = 'json-number';
    if (typeof data === 'boolean') styleClass = 'json-boolean';
    if (data === null) {
      data = 'null';
      styleClass = 'json-null';
    }
    return <span className={styleClass}>{String(data)}</span>;
  }

  const isArray = Array.isArray(data);
  const keys = Object.keys(data);

  if (keys.length === 0) {
    return <span>{isArray ? '[]' : '{}'}</span>;
  }

  return (
    <div className="json-node">
      <div className={`json-caret ${expanded ? 'expanded' : ''}`} onClick={() => setExpanded(!expanded)}>
        {isArray ? '[' : '{'} {!expanded && <span style={{ color: 'var(--text-secondary)' }}>...</span>} {!expanded && (isArray ? ']' : '}')}
      </div>
      
      {expanded && (
        <div style={{ marginLeft: '1.2rem', borderLeft: '1px solid var(--panel-border)', paddingLeft: '0.5rem' }}>
          {keys.map((key, index) => (
            <div key={index} style={{ marginBottom: '2px' }}>
              {!isArray && <span className="json-key">"{key}"</span>}
              {!isArray && <span>: </span>}
              <InteractiveJson data={data[key]} />
              {index < keys.length - 1 && <span>,</span>}
            </div>
          ))}
        </div>
      )}
      
      {expanded && <div>{isArray ? ']' : '}'}</div>}
    </div>
  );
};

export default InteractiveJson;
