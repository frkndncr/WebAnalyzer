import React from 'react';
import { useHealth } from '../context/health';
import { dbProblem } from '../lib/analysis';
import { Icon } from './ui';

/** Explains why data looks empty when the database cannot be reached. */
export default function DbBanner() {
  const problem = dbProblem(useHealth());
  if (!problem) return null;
  const reason = problem.reason[0].toUpperCase() + problem.reason.slice(1);
  return (
    <div className="banner" role="status">
      <Icon name="alert" size={18} />
      <div>
        <b>Database offline.</b> {reason}, so saved scans cannot be loaded and new results cannot be saved.
        Scans still run, but their results are only kept until the server restarts.
      </div>
    </div>
  );
}
