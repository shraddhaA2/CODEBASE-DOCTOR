import React from 'react';
import { Link, useLocation, useParams } from 'react-router-dom';
import { Activity, Shield, Cpu, Sparkles, Wrench, Plus, GitBranch } from 'lucide-react';

interface NavbarProps {
  githubUrl?: string;
}

export const Navbar: React.FC<NavbarProps> = ({ githubUrl }) => {
  const location = useLocation();
  const { id } = useParams<{ id: string }>();

  // Extract repo short name from url if available
  let repoName = '';
  if (githubUrl) {
    try {
      const parts = new URL(githubUrl).pathname.split('/').filter(Boolean);
      if (parts.length >= 2) {
        repoName = `${parts[0]}/${parts[1]}`;
      }
    } catch {
      repoName = githubUrl;
    }
  }

  const isScanRoute = Boolean(id);

  return (
    <header className="sticky top-0 z-50 bg-[#0d1117]/95 backdrop-blur border-b border-[#21262d]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Brand */}
          <div className="flex items-center gap-4">
            <Link to="/" className="flex items-center gap-2.5 text-slate-100 font-semibold tracking-tight hover:text-white">
              <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
                <Activity className="w-4 h-4" />
              </div>
              <span className="text-base font-bold tracking-tight">Codebase Doctor</span>
            </Link>

            {/* Current Repo Pill */}
            {isScanRoute && repoName && (
              <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#161b22] border border-[#30363d] text-xs font-mono text-slate-300">
                <GitBranch className="w-3.5 h-3.5 text-slate-400" />
                <span className="truncate max-w-[200px]">{repoName}</span>
              </div>
            )}
          </div>

          {/* Navigation Links for Active Scan */}
          {isScanRoute && (
            <nav className="hidden md:flex items-center gap-1">
              <Link
                to={`/scans/${id}/dashboard`}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  location.pathname.endsWith('/dashboard')
                    ? 'bg-[#21262d] text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#161b22]'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                Overview
              </Link>

              <Link
                to={`/scans/${id}/findings`}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  location.pathname.endsWith('/findings')
                    ? 'bg-[#21262d] text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#161b22]'
                }`}
              >
                <Shield className="w-3.5 h-3.5" />
                Findings
              </Link>

              <Link
                to={`/scans/${id}/architecture`}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  location.pathname.endsWith('/architecture')
                    ? 'bg-[#21262d] text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#161b22]'
                }`}
              >
                <Cpu className="w-3.5 h-3.5" />
                Architecture
              </Link>

              <Link
                to={`/scans/${id}/diagnosis`}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  location.pathname.endsWith('/diagnosis')
                    ? 'bg-[#21262d] text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#161b22]'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                Diagnosis
              </Link>

              <Link
                to={`/scans/${id}/fixes`}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  location.pathname.endsWith('/fixes')
                    ? 'bg-[#21262d] text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#161b22]'
                }`}
              >
                <Wrench className="w-3.5 h-3.5 text-emerald-400" />
                Fix Proposals
              </Link>
            </nav>
          )}

          {/* Action */}
          <div className="flex items-center gap-3">
            <Link
              to="/"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              New Scan
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
};
