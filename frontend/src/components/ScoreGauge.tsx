import React from 'react';

interface ScoreGaugeProps {
  score: number;
  label?: string;
  size?: 'sm' | 'md' | 'lg';
  showStatusText?: boolean;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  label = 'Overall Health',
  size = 'lg',
  showStatusText = true,
}) => {
  const rounded = Math.round(score * 10) / 10;

  // Determine color theme
  let color = '#ef4444'; // red
  let statusText = 'Critical Risks Detected';
  let badgeBg = 'bg-red-950/40 text-red-400 border-red-800/50';

  if (rounded >= 85) {
    color = '#10b981'; // emerald
    statusText = 'Healthy Repository';
    badgeBg = 'bg-emerald-950/40 text-emerald-400 border-emerald-800/50';
  } else if (rounded >= 70) {
    color = '#3b82f6'; // blue
    statusText = 'Fair / Minor Refactoring';
    badgeBg = 'bg-blue-950/40 text-blue-400 border-blue-800/50';
  } else if (rounded >= 50) {
    color = '#f59e0b'; // amber
    statusText = 'Degraded / Moderate Issues';
    badgeBg = 'bg-amber-950/40 text-amber-400 border-amber-800/50';
  }

  const radius = size === 'lg' ? 68 : size === 'md' ? 44 : 30;
  const stroke = size === 'lg' ? 10 : size === 'md' ? 7 : 5;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.min(100, Math.max(0, rounded)) / 100) * circumference;

  const svgSize = (radius + stroke) * 2;

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex items-center justify-center">
        <svg width={svgSize} height={svgSize} className="transform -rotate-90">
          {/* Background circle */}
          <circle
            cx={svgSize / 2}
            cy={svgSize / 2}
            r={radius}
            stroke="#21262d"
            strokeWidth={stroke}
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx={svgSize / 2}
            cy={svgSize / 2}
            r={radius}
            stroke={color}
            strokeWidth={stroke}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        <div className="absolute flex flex-col items-center justify-center text-center">
          <span
            className={`font-mono font-bold tracking-tight text-white ${
              size === 'lg' ? 'text-4xl' : size === 'md' ? 'text-2xl' : 'text-lg'
            }`}
          >
            {rounded}
          </span>
          {size === 'lg' && <span className="text-xs text-slate-400 font-mono">/ 100</span>}
        </div>
      </div>

      {label && <span className="mt-3 text-sm font-medium text-slate-300">{label}</span>}
      {showStatusText && (
        <span
          className={`mt-1.5 inline-block text-xs px-2 py-0.5 rounded-full border ${badgeBg} font-medium`}
        >
          {statusText}
        </span>
      )}
    </div>
  );
};
