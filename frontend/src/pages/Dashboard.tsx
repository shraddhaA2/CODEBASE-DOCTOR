import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Scan, HealthScore, Finding, ArchitectureSummary } from '../api/types';
import { Navbar } from '../components/Navbar';
import { ScoreGauge } from '../components/ScoreGauge';
import { SeverityBadge } from '../components/SeverityBadge';
import {
  Shield,
  Cpu,
  Layers,
  Zap,
  Code2,
  Package,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Info,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

export const Dashboard: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [score, setScore] = useState<HealthScore | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [archSummary, setArchSummary] = useState<ArchitectureSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAuditModal, setShowAuditModal] = useState(false);

  useEffect(() => {
    if (!id) return;
    loadDashboardData();
  }, [id]);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const [scanData, scoreData, findingsData, archData] = await Promise.all([
        api.getScan(id!),
        api.getScore(id!),
        api.getFindings(id!),
        api.getArchitecture(id!),
      ]);
      setScan(scanData);
      setScore(scoreData);
      setFindings(findingsData);
      setArchSummary(archData);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0b0f17] text-slate-200">
        <Navbar />
        <div className="max-w-7xl mx-auto px-4 py-24 text-center">
          <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-sm text-slate-400 font-mono">Loading repository diagnosis...</p>
        </div>
      </div>
    );
  }

  if (error || !score || !scan) {
    return (
      <div className="min-h-screen bg-[#0b0f17] text-slate-200">
        <Navbar githubUrl={scan?.github_url} />
        <div className="max-w-xl mx-auto px-4 py-16 text-center">
          <div className="p-6 bg-[#161b22] border border-red-800/60 rounded-xl">
            <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
            <h2 className="text-lg font-bold text-white mb-2">Error Loading Dashboard</h2>
            <p className="text-xs text-slate-400 font-mono mb-4">{error || 'No score data available.'}</p>
            <Link to="/" className="text-xs text-blue-400 hover:underline">
              Return to scan launcher
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Calculate severity counts
  const severityCounts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  findings.forEach((f) => {
    const s = f.severity.toLowerCase();
    severityCounts[s] = (severityCounts[s] || 0) + 1;
  });

  // Calculate category counts
  const categoryCounts: Record<string, number> = {};
  findings.forEach((f) => {
    categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
  });

  // Calculate scope counts and duplicates
  const scopeCounts: Record<string, number> = {
    source: 0,
    test: 0,
    docs: 0,
    generated: 0,
    vendor: 0,
  };
  let duplicateCount = 0;
  findings.forEach((f) => {
    const sc = f.scope || 'source';
    scopeCounts[sc] = (scopeCounts[sc] || 0) + 1;
    if (f.is_duplicate) duplicateCount += 1;
  });

  const dimensionChartData = [
    { name: 'Security', score: score.security, weight: '25%' },
    { name: 'Architecture', score: score.architecture, weight: '15%' },
    { name: 'Maintainability', score: score.maintainability, weight: '15%' },
    { name: 'Performance', score: score.performance, weight: '10%' },
    { name: 'Quality', score: score.code_quality, weight: '20%' },
    { name: 'Dependencies', score: score.dependencies, weight: '15%' },
  ];

  const categoryChartData = Object.entries(categoryCounts).map(([cat, count]) => ({
    category: cat.replace('_', ' '),
    count,
  }));

  const dimensions = [
    {
      name: 'Security',
      score: score.security,
      weight: '25%',
      icon: Shield,
      color: 'text-red-400',
      description: 'Bandit, Semgrep, and static security rules',
    },
    {
      name: 'Architecture',
      score: score.architecture,
      weight: '15%',
      icon: Cpu,
      color: 'text-purple-400',
      description: `${archSummary?.circular_components_count || 0} cycles, ${archSummary?.hubs.length || 0} hubs`,
    },
    {
      name: 'Maintainability',
      score: score.maintainability,
      weight: '15%',
      icon: Layers,
      color: 'text-amber-400',
      description: 'Dead code, unused imports and functions',
    },
    {
      name: 'Performance',
      score: score.performance,
      weight: '10%',
      icon: Zap,
      color: 'text-blue-400',
      description:
        score.breakdown.performance?.status === 'neutral'
          ? 'No static performance issues detected'
          : 'Static performance rules',
      supportingText:
        score.breakdown.performance?.status === 'neutral'
          ? 'No performance rules triggered. This does not constitute runtime performance testing.'
          : 'This does not constitute runtime performance testing.',
    },
    {
      name: 'Code Quality',
      score: score.code_quality,
      weight: '20%',
      icon: Code2,
      color: 'text-emerald-400',
      description: 'Ruff lints, AST heuristics, and bug patterns',
    },
    {
      name: 'Dependencies',
      score: score.dependencies,
      weight: '15%',
      icon: Package,
      color: 'text-cyan-400',
      description: 'Manifest parsing & pip-audit vulnerabilities',
    },
  ];

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-200">
      <Navbar githubUrl={scan.github_url} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Repo Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-[#21262d]">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <span>{scan.github_url.replace('https://github.com/', '')}</span>
              <a
                href={scan.github_url}
                target="_blank"
                rel="noreferrer"
                className="text-slate-500 hover:text-slate-300"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            </h1>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Commit: {scan.commit_sha || 'latest'} • Analyzed on{' '}
              {new Date(scan.created_at).toLocaleString()}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowAuditModal(!showAuditModal)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#30363d] bg-[#161b22] hover:bg-[#21262d] text-xs font-mono text-slate-300 transition-colors"
            >
              <Info className="w-3.5 h-3.5" />
              {showAuditModal ? 'Hide Score Audit' : 'Auditable Breakdown'}
            </button>
            <Link
              to={`/scans/${id}/findings`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-colors"
            >
              View Findings ({findings.length})
            </Link>
          </div>
        </div>

        {/* Auditable Score Breakdown Expandable Panel */}
        {showAuditModal && (
          <div className="bg-[#161b22] border border-blue-900/40 rounded-xl p-5 text-xs font-mono text-slate-300 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-[#21262d] pb-2">
              <span className="font-semibold text-white uppercase tracking-wider">
                Auditable Score Breakdown
              </span>
              <span className="text-slate-400">{score.breakdown.overall?.formula}</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {Object.entries(score.breakdown)
                .filter(([k]) => k !== 'overall')
                .map(([dim, data]: [string, any]) => (
                  <div key={dim} className="bg-[#0d1117] p-3 rounded-lg border border-[#21262d]">
                    <div className="flex items-center justify-between font-semibold capitalize text-slate-200">
                      <span>{dim.replace('_', ' ')}</span>
                      <span className="text-blue-400">{data.final_score}/100</span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      Start: {data.starting_score} • Deductions: -{data.total_penalty} • Weight:{' '}
                      {(data.weight * 100).toFixed(0)}%
                    </div>
                    {data.explanation && (
                      <div className="text-[10px] text-slate-500 mt-1 italic">{data.explanation}</div>
                    )}
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Top Section: Health Score + Severity Counts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Overall Gauge */}
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-6 flex flex-col items-center justify-center text-center shadow-sm">
            <ScoreGauge score={score.overall} label="Overall Codebase Health" size="lg" />
            <div className="mt-4 text-xs text-slate-400 font-mono">
              Deterministic weighted aggregation across 6 dimensions
            </div>
          </div>

          {/* Severity Breakdown Cards */}
          <div className="lg:col-span-2 bg-[#161b22] border border-[#21262d] rounded-xl p-6 flex flex-col justify-between shadow-sm">
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4">
                Findings by Severity
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
                  <div
                    key={sev}
                    className="bg-[#0d1117] border border-[#21262d] rounded-lg p-3 text-center"
                  >
                    <div className="mb-1">
                      <SeverityBadge severity={sev} size="sm" />
                    </div>
                    <div className="text-2xl font-bold font-mono text-white">
                      {severityCounts[sev]}
                    </div>
                    <div className="text-[10px] text-slate-500 uppercase mt-0.5">findings</div>
                  </div>
                ))}
              </div>

              {/* Findings by Scope */}
              <div className="mt-4 pt-3 border-t border-[#21262d] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                  <span className="text-slate-400 font-semibold uppercase text-[11px]">Scope:</span>
                  <span className="px-2 py-0.5 rounded bg-[#0d1117] border border-blue-900/40 text-blue-300">
                    Source: <strong className="text-white">{scopeCounts.source}</strong>
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#0d1117] border border-purple-900/40 text-purple-300">
                    Test: <strong className="text-white">{scopeCounts.test}</strong>
                  </span>
                  {scopeCounts.docs > 0 && (
                    <span className="px-2 py-0.5 rounded bg-[#0d1117] border border-amber-900/40 text-amber-300">
                      Docs: <strong className="text-white">{scopeCounts.docs}</strong>
                    </span>
                  )}
                  {scopeCounts.generated > 0 && (
                    <span className="px-2 py-0.5 rounded bg-[#0d1117] border border-[#21262d] text-slate-300">
                      Generated: <strong className="text-white">{scopeCounts.generated}</strong>
                    </span>
                  )}
                  {scopeCounts.vendor > 0 && (
                    <span className="px-2 py-0.5 rounded bg-[#0d1117] border border-[#21262d] text-slate-300">
                      Vendor: <strong className="text-white">{scopeCounts.vendor}</strong>
                    </span>
                  )}
                </div>
                {duplicateCount > 0 && (
                  <span className="text-[10px] font-mono text-amber-400/90 bg-amber-950/30 px-2 py-0.5 rounded border border-amber-800/30 shrink-0">
                    {duplicateCount} cross-tool duplicate findings deduplicated
                  </span>
                )}
              </div>
            </div>

            {/* Quick Repo Inventory Stats */}
            {scan.language_stats && (
              <div className="mt-6 pt-4 border-t border-[#21262d] grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block">Total Files</span>
                  <span className="text-white font-semibold">{scan.language_stats.total_files}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Python Files</span>
                  <span className="text-white font-semibold">{scan.language_stats.python_files}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Architecture Modules</span>
                  <span className="text-white font-semibold">{archSummary?.total_modules || 0}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Repo Size</span>
                  <span className="text-white font-semibold">
                    {Math.round((scan.language_stats.total_size_bytes || 0) / 1024)} KB
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Six Dimensions Grid */}
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4">
            Six Health Dimensions
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {dimensions.map((dim) => {
              const Icon = dim.icon;
              return (
                <div
                  key={dim.name}
                  className="bg-[#161b22] border border-[#21262d] rounded-xl p-5 hover:border-[#30363d] transition-colors flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2.5">
                        <div className={`p-2 rounded-lg bg-[#0d1117] border border-[#21262d] ${dim.color}`}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <div>
                          <h3 className="text-sm font-bold text-white">{dim.name}</h3>
                          <span className="text-[11px] font-mono text-slate-500">Weight: {dim.weight}</span>
                        </div>
                      </div>

                      <div className="text-right">
                        <span className="text-xl font-bold font-mono text-white">{dim.score}</span>
                        <span className="text-xs text-slate-500 font-mono">/100</span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{dim.description}</p>
                    {dim.supportingText && (
                      <p className="text-[11px] text-slate-500 mt-1.5 leading-relaxed italic">
                        {dim.supportingText}
                      </p>
                    )}
                  </div>

                  <div className="mt-4 w-full bg-[#0d1117] h-1.5 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-500 ${
                        dim.score >= 80 ? 'bg-emerald-500' : dim.score >= 60 ? 'bg-amber-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${Math.min(100, Math.max(0, dim.score))}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Charts Section: Actual API Data Only */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Dimension Scores Bar Chart */}
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">
              Dimension Performance Comparison
            </h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dimensionChartData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <XAxis dataKey="name" stroke="#8b949e" tick={{ fontSize: 11 }} interval={0} />
                  <YAxis domain={[0, 100]} stroke="#8b949e" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: '#fff' }}
                  />
                  <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                    {dimensionChartData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          entry.score >= 80 ? '#10b981' : entry.score >= 60 ? '#f59e0b' : '#ef4444'
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Findings by Category Chart */}
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">
              Findings Distribution by Category
            </h3>
            {categoryChartData.length > 0 ? (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryChartData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                    <XAxis dataKey="category" stroke="#8b949e" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#8b949e" tick={{ fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: '#fff' }}
                    />
                    <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-slate-500 font-mono text-xs">
                <CheckCircle className="w-8 h-8 text-emerald-500 mb-2" />
                No findings detected by configured analyzers.
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};
