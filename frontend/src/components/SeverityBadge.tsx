import React from 'react';
import { FindingSeverity } from '../api/types';

interface SeverityBadgeProps {
  severity: FindingSeverity | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const sev = severity.toLowerCase();

  const styles: Record<string, string> = {
    critical: 'bg-red-950/80 text-red-300 border-red-800/60',
    high: 'bg-orange-950/80 text-orange-300 border-orange-800/60',
    medium: 'bg-amber-950/80 text-amber-300 border-amber-800/60',
    low: 'bg-blue-950/80 text-blue-300 border-blue-800/60',
    info: 'bg-slate-800/80 text-slate-300 border-slate-700/60',
  };

  const currentStyle = styles[sev] || styles.info;
  const padding = size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';

  return (
    <span
      className={`inline-flex items-center uppercase tracking-wider font-mono rounded border ${padding} ${currentStyle}`}
    >
      {sev}
    </span>
  );
};
