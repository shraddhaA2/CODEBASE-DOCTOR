import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Scan, Finding } from '../api/types';
import { Navbar } from '../components/Navbar';
import { SeverityBadge } from '../components/SeverityBadge';
import { CodeViewer } from '../components/CodeViewer';
import {
  Search,
  ChevronRight,
  ChevronDown,
  FileCode,
  Wrench,
  CheckCircle2,
  AlertTriangle,
  Info,
} from 'lucide-react';

export const Findings: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedAnalyzer, setSelectedAnalyzer] = useState<string>('');
  const [selectedScope, setSelectedScope] = useState<string>('');
  const [includeDuplicates, setIncludeDuplicates] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    loadData();
  }, [id, selectedCategory, selectedSeverity, selectedAnalyzer, selectedScope, includeDuplicates]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [scanData, findingsData] = await Promise.all([
        api.getScan(id!),
        api.getFindings(id!, {
          category: selectedCategory || undefined,
          severity: selectedSeverity || undefined,
          analyzer: selectedAnalyzer || undefined,
          scope: selectedScope || undefined,
          include_duplicates: includeDuplicates,
        }),
      ]);
      setScan(scanData);
      setFindings(findingsData);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to load findings.');
    } finally {
      setLoading(false);
    }
  };

  const filteredFindings = findings.filter((f) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.message.toLowerCase().includes(q) ||
      f.file_path.toLowerCase().includes(q) ||
      f.rule_id.toLowerCase().includes(q)
    );
  });

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-200">
      <Navbar githubUrl={scan?.github_url} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#21262d]">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Normalized Findings</h1>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Static analysis results unified across Ruff, Bandit, Semgrep, pip-audit, and AST heuristics.
            </p>
          </div>
          <div className="font-mono text-xs text-slate-400">
            Total Displayed: <span className="font-bold text-white">{filteredFindings.length}</span>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-red-950/40 border border-red-800/60 rounded-xl text-xs text-red-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Filter Controls Bar */}
        <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search message, file, rule..."
                className="w-full pl-9 pr-3 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Scope Filter */}
            <div>
              <select
                value={selectedScope}
                onChange={(e) => setSelectedScope(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="">All Scopes</option>
                <option value="source">Source (Production)</option>
                <option value="test">Test</option>
                <option value="docs">Docs</option>
                <option value="generated">Generated</option>
                <option value="vendor">Vendor</option>
              </select>
            </div>

            {/* Category Filter */}
            <div>
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="">All Categories</option>
                <option value="security">Security</option>
                <option value="architecture">Architecture</option>
                <option value="bug">Bug</option>
                <option value="dead_code">Dead Code</option>
                <option value="quality">Quality</option>
                <option value="dependency">Dependency</option>
              </select>
            </div>

            {/* Severity Filter */}
            <div>
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>

            {/* Analyzer Filter */}
            <div>
              <select
                value={selectedAnalyzer}
                onChange={(e) => setSelectedAnalyzer(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="">All Analyzers</option>
                <option value="bandit">Bandit</option>
                <option value="semgrep">Semgrep</option>
                <option value="ruff">Ruff</option>
                <option value="dependencies">Dependencies (pip-audit)</option>
                <option value="architecture">Architecture AST</option>
                <option value="heuristics">Custom Heuristics</option>
              </select>
            </div>
          </div>

          <div className="flex items-center justify-between pt-1 border-t border-[#21262d]/60 text-xs font-mono text-slate-400">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={includeDuplicates}
                onChange={(e) => setIncludeDuplicates(e.target.checked)}
                className="rounded border-[#30363d] bg-[#0d1117] text-blue-500 focus:ring-0"
              />
              <span>Include cross-analyzer duplicate findings (retained for provenance)</span>
            </label>
          </div>
        </div>

        {/* Findings List */}
        {loading ? (
          <div className="py-16 text-center text-slate-500 font-mono text-xs">
            Loading findings...
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-12 text-center">
            <CheckCircle2 className="w-10 h-10 text-emerald-500 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-white mb-1">No Findings Found</h3>
            <p className="text-xs text-slate-400 font-mono max-w-sm mx-auto">
              No findings matched the selected filters or were detected by the configured analyzers.
            </p>
          </div>
        ) : (
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl overflow-hidden divide-y divide-[#21262d]">
            {filteredFindings.map((finding) => {
              const isExpanded = expandedId === finding.id;
              return (
                <div key={finding.id} className="transition-colors hover:bg-[#1f242c]/40">
                  {/* Summary Bar */}
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                    className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none"
                  >
                    <div className="flex items-start gap-3">
                      <button className="mt-0.5 text-slate-500 hover:text-slate-300">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 text-blue-400" />
                        ) : (
                          <ChevronRight className="w-4 h-4" />
                        )}
                      </button>

                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <SeverityBadge severity={finding.severity} size="sm" />
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#21262d] text-slate-300 border border-[#30363d]">
                            {finding.analyzer}
                          </span>
                          {finding.scope && (
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold border ${
                              finding.scope === 'source' ? 'bg-blue-950/40 text-blue-300 border-blue-800/40' :
                              finding.scope === 'test' ? 'bg-purple-950/40 text-purple-300 border-purple-800/40' :
                              finding.scope === 'docs' ? 'bg-amber-950/40 text-amber-300 border-amber-800/40' :
                              'bg-slate-800/60 text-slate-300 border-slate-700'
                            }`}>
                              {finding.scope}
                            </span>
                          )}
                          {finding.is_duplicate && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/50 text-amber-300 border border-amber-800/50" title="Cross-analyzer duplicate (retained for provenance, not scored)">
                              Duplicate
                            </span>
                          )}
                          <span className="text-[11px] font-mono text-slate-400">
                            {finding.rule_id}
                          </span>
                        </div>
                        <p className="text-xs text-slate-200 font-medium leading-relaxed">
                          {finding.message}
                        </p>
                      </div>
                    </div>

                    <div className="text-left sm:text-right shrink-0">
                      <div className="text-xs font-mono text-slate-400 flex items-center gap-1 sm:justify-end">
                        <FileCode className="w-3.5 h-3.5 text-slate-500" />
                        <span className="truncate max-w-[240px]">{finding.file_path}</span>
                        {finding.start_line && <span>:{finding.start_line}</span>}
                      </div>
                      <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500">
                        {finding.category}
                      </span>
                    </div>
                  </div>

                  {/* Expanded Detail View */}
                  {isExpanded && (
                    <div className="px-6 pb-5 pt-1 bg-[#0d1117]/60 space-y-3">
                      {finding.is_duplicate && (
                        <div className="p-2.5 bg-amber-950/30 border border-amber-800/40 rounded-lg text-xs text-amber-300 font-mono flex items-center gap-2">
                          <Info className="w-4 h-4 text-amber-400 shrink-0" />
                          <span>
                            Cross-analyzer duplicate: Equivalent to canonical primary finding (ID: <span className="text-white">{finding.primary_finding_id?.slice(0, 8)}...</span>). Retained for audit provenance; not penalized in health score.
                          </span>
                        </div>
                      )}
                      {/* Code Snippet Viewer */}
                      {finding.redacted_snippet ? (
                        <div>
                          <div className="text-[11px] font-semibold text-slate-400 mb-1.5 uppercase font-mono">
                            Evidence Snippet (Redacted):
                          </div>
                          <CodeViewer
                            code={finding.redacted_snippet}
                            startLine={finding.start_line}
                            filePath={finding.file_path}
                          />
                        </div>
                      ) : (
                        <div className="text-xs text-slate-500 font-mono italic">
                          No snippet attached to this finding.
                        </div>
                      )}

                      {/* Evidence JSON & Actions */}
                      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pt-2 border-t border-[#21262d] text-xs">
                        <div className="text-slate-400 font-mono text-[11px]">
                          ID: <span className="text-slate-300">{finding.id}</span>
                        </div>

                        <Link
                          to={`/scans/${id}/fixes`}
                          className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 font-medium"
                        >
                          <Wrench className="w-3.5 h-3.5" />
                          View Fix Proposals
                        </Link>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
};
