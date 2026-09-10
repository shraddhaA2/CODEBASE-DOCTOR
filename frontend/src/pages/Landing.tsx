import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Scan } from '../api/types';
import {
  ShieldAlert,
  GitBranch,
  ArrowRight,
  Clock,
  AlertCircle,
  Sliders,
  CheckCircle2,
  XCircle,
  Loader2,
} from 'lucide-react';

export const Landing: React.FC = () => {
  const navigate = useNavigate();
  const [githubUrl, setGithubUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Scan limits options
  const [maxSizeMb, setMaxSizeMb] = useState(50);
  const [maxFiles, setMaxFiles] = useState(2000);
  const [timeoutSec, setTimeoutSec] = useState(60);

  useEffect(() => {
    loadRecentScans();
  }, []);

  const loadRecentScans = async () => {
    try {
      const list = await api.listScans(8);
      setRecentScans(list);
    } catch {
      // Ignore initial scan list error
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmed = githubUrl.trim();
    if (!trimmed) {
      setError('Please enter a GitHub repository URL.');
      return;
    }

    if (!trimmed.startsWith('https://github.com/')) {
      setError('Only HTTPS GitHub URLs are permitted (e.g., https://github.com/owner/repository).');
      return;
    }

    setLoading(true);
    try {
      const limits = showAdvanced
        ? { max_clone_size_mb: maxSizeMb, max_file_count: maxFiles, clone_timeout_sec: timeoutSec }
        : undefined;

      const res = await api.createScan(trimmed, limits);
      navigate(`/scans/${res.scan_id}`);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to initiate scan.');
      setLoading(false);
    }
  };

  const sampleRepos = [
    'https://github.com/pallets/click',
    'https://github.com/psf/requests',
    'https://github.com/fastapi/fastapi',
  ];

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-200">
      {/* Hero */}
      <div className="max-w-4xl mx-auto px-4 pt-16 pb-12 sm:px-6 lg:px-8 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-blue-500/30 bg-blue-950/30 text-blue-400 text-xs font-mono font-medium mb-6">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Zero-Execution Deterministic Static Analysis</span>
        </div>

        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-white mb-4">
          Codebase Doctor
        </h1>
        <p className="text-base sm:text-lg text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
          Deep diagnostic static inspection for Python repositories. Identifies vulnerabilities, architecture coupling, circular dependencies, dead code, and calculates an auditable health score.
        </p>

        {/* Input Form */}
        <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-6 shadow-xl text-left">
          <form onSubmit={handleStartScan} className="space-y-4">
            <div>
              <label htmlFor="repo-url" className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                Public GitHub Repository URL
              </label>
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <GitBranch className="w-4 h-4" />
                  </div>
                  <input
                    id="repo-url"
                    type="url"
                    value={githubUrl}
                    onChange={(e) => setGithubUrl(e.target.value)}
                    placeholder="https://github.com/owner/repository"
                    disabled={loading}
                    className="w-full pl-10 pr-4 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono transition-colors"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="inline-flex items-center justify-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white font-medium text-sm rounded-lg transition-colors shadow-sm whitespace-nowrap"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Starting Scan...
                    </>
                  ) : (
                    <>
                      Start Diagnosis
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Quick Fill Samples */}
            <div className="flex items-center gap-2 text-xs text-slate-400 flex-wrap">
              <span className="text-slate-500">Samples:</span>
              {sampleRepos.map((url) => (
                <button
                  key={url}
                  type="button"
                  onClick={() => setGithubUrl(url)}
                  className="px-2 py-0.5 rounded bg-[#21262d] hover:bg-[#30363d] text-slate-300 font-mono text-[11px] transition-colors"
                >
                  {url.replace('https://github.com/', '')}
                </button>
              ))}
            </div>

            {/* Advanced Limit Settings Toggle */}
            <div className="pt-2 border-t border-[#21262d]">
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                <Sliders className="w-3.5 h-3.5" />
                {showAdvanced ? 'Hide Scan Limits' : 'Configure Scan Limits'}
              </button>

              {showAdvanced && (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-3 p-3.5 bg-[#0d1117] rounded-lg border border-[#21262d] text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1">Max Clone Size (MB)</label>
                    <input
                      type="number"
                      value={maxSizeMb}
                      onChange={(e) => setMaxSizeMb(Number(e.target.value))}
                      className="w-full px-2.5 py-1.5 bg-[#161b22] border border-[#30363d] rounded text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Max File Count</label>
                    <input
                      type="number"
                      value={maxFiles}
                      onChange={(e) => setMaxFiles(Number(e.target.value))}
                      className="w-full px-2.5 py-1.5 bg-[#161b22] border border-[#30363d] rounded text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Timeout (seconds)</label>
                    <input
                      type="number"
                      value={timeoutSec}
                      onChange={(e) => setTimeoutSec(Number(e.target.value))}
                      className="w-full px-2.5 py-1.5 bg-[#161b22] border border-[#30363d] rounded text-white font-mono"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Error Message */}
            {error && (
              <div className="flex items-start gap-2 p-3 bg-red-950/50 border border-red-800/60 rounded-lg text-xs text-red-200">
                <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </form>
        </div>
      </div>

      {/* Recent Scans Section */}
      {recentScans.length > 0 && (
        <div className="max-w-4xl mx-auto px-4 pb-16 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Recent Scans
            </h2>
          </div>

          <div className="bg-[#161b22] border border-[#21262d] rounded-xl overflow-hidden divide-y divide-[#21262d]">
            {recentScans.map((scan) => (
              <Link
                key={scan.id}
                to={scan.status === 'succeeded' ? `/scans/${scan.id}/dashboard` : `/scans/${scan.id}`}
                className="flex items-center justify-between px-4 py-3 hover:bg-[#21262d]/50 transition-colors"
              >
                <div className="flex items-center gap-3">
                  {scan.status === 'succeeded' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : scan.status === 'failed' ? (
                    <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                  ) : (
                    <Loader2 className="w-4 h-4 text-blue-400 animate-spin shrink-0" />
                  )}
                  <div>
                    <div className="font-mono text-xs text-slate-200 font-medium">
                      {scan.github_url.replace('https://github.com/', '')}
                    </div>
                    <div className="text-[11px] text-slate-500">
                      {new Date(scan.created_at).toLocaleString()} {scan.commit_sha && `• ${scan.commit_sha.slice(0, 7)}`}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span
                    className={`text-[11px] font-mono uppercase px-2 py-0.5 rounded border ${
                      scan.status === 'succeeded'
                        ? 'bg-emerald-950/50 text-emerald-300 border-emerald-800/40'
                        : scan.status === 'failed'
                        ? 'bg-red-950/50 text-red-300 border-red-800/40'
                        : 'bg-blue-950/50 text-blue-300 border-blue-800/40'
                    }`}
                  >
                    {scan.status}
                  </span>
                  <ArrowRight className="w-4 h-4 text-slate-600" />
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
