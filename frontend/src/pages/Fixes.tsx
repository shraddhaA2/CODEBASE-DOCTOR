import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api/client';
import { Scan, PatchProposal } from '../api/types';
import { Navbar } from '../components/Navbar';
import { CodeViewer } from '../components/CodeViewer';
import {
  Wrench,
  AlertTriangle,
  Download,
  Copy,
  Check,
  Loader2,
  FileCode,
  Lock,
  Info,
} from 'lucide-react';
import { DiffEditor } from '@monaco-editor/react';

export const Fixes: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [patches, setPatches] = useState<PatchProposal[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedPatchId, setCopiedPatchId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Record<string, 'diff' | 'monaco'>>({});

  useEffect(() => {
    if (!id) return;
    loadData();
  }, [id]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [scanData, aiData] = await Promise.all([
        api.getScan(id!),
        api.getAIReports(id!),
      ]);
      setScan(scanData);
      setPatches(aiData.patches || []);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to load patch proposals.');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateFixes = async () => {
    setGenerating(true);
    setError(null);
    try {
      const newPatches = await api.generateFixes(id!);
      setPatches(newPatches);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to generate patch proposals.');
    } finally {
      setGenerating(false);
    }
  };

  const handleCopyDiff = (patch: PatchProposal) => {
    navigator.clipboard.writeText(patch.unified_diff);
    setCopiedPatchId(patch.id);
    setTimeout(() => setCopiedPatchId(null), 2000);
  };

  const handleDownloadPatch = (patch: PatchProposal) => {
    const blob = new Blob([patch.unified_diff], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${patch.file_path.replace(/[/\\?%*:|"<>]/g, '_')}.patch`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-200">
      <Navbar githubUrl={scan?.github_url} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#21262d]">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <Wrench className="w-6 h-6 text-emerald-400" />
              AI Patch Proposals
            </h1>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Automated, export-only remediation proposals for detected vulnerabilities and bugs.
            </p>
          </div>

          <button
            onClick={handleGenerateFixes}
            disabled={generating}
            className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 text-white font-medium text-xs rounded-lg transition-colors shadow-sm"
          >
            {generating ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Proposing Patches...
              </>
            ) : (
              <>
                <Wrench className="w-4 h-4" />
                Generate Fix Proposals
              </>
            )}
          </button>
        </div>

        {/* Non-Negotiable Safety Policy Notice */}
        <div className="p-4 bg-[#161b22] border border-blue-900/50 rounded-xl flex items-start gap-3 text-xs">
          <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-white uppercase tracking-wider font-mono">
              Export-Only Security Guarantee
            </span>
            <p className="text-slate-300 leading-relaxed">
              Codebase Doctor treats the scanned repository as untrusted input and{' '}
              <strong>never automatically applies patches or executes repository code</strong>. Developers can inspect, review, and export unified diffs manually.
            </p>
          </div>
        </div>

        {/* Error message */}
        {error && (
          <div className="p-4 bg-amber-950/40 border border-amber-800/60 rounded-xl text-xs text-amber-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Loading */}
        {loading ? (
          <div className="py-24 text-center text-slate-500 font-mono text-xs">
            <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-emerald-400" />
            Loading patch proposals...
          </div>
        ) : patches.length === 0 ? (
          /* Empty State */
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-12 text-center max-w-xl mx-auto">
            <div className="w-12 h-12 rounded-full bg-emerald-950/40 border border-emerald-800/50 flex items-center justify-center text-emerald-400 mx-auto mb-4">
              <Wrench className="w-6 h-6" />
            </div>
            <h2 className="text-lg font-bold text-white mb-2">No Patch Proposals Yet</h2>
            <p className="text-xs text-slate-400 leading-relaxed mb-6 font-mono">
              Generate AI-powered patch proposals to inspect potential fixes for security vulnerabilities and code quality findings.
            </p>
            <button
              onClick={handleGenerateFixes}
              disabled={generating}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 text-white font-medium text-xs rounded-lg transition-colors shadow-sm"
            >
              {generating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Generating Patches...
                </>
              ) : (
                <>
                  <Wrench className="w-4 h-4" />
                  Generate Patch Proposals
                </>
              )}
            </button>
          </div>
        ) : (
          /* List of Patches */
          <div className="space-y-6">
            {patches.map((patch, idx) => {
              const currentTab = activeTab[patch.id] || 'diff';
              return (
                <div
                  key={patch.id || idx}
                  className="bg-[#161b22] border border-[#21262d] rounded-xl overflow-hidden shadow-sm"
                >
                  {/* Patch Header */}
                  <div className="p-4 bg-[#1c2128] border-b border-[#21262d] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="font-mono text-xs font-bold text-white flex items-center gap-1.5">
                        <FileCode className="w-4 h-4 text-slate-400" />
                        {patch.file_path}
                      </span>
                      <span
                        className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
                          patch.risk === 'low'
                            ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                            : patch.risk === 'medium'
                            ? 'bg-amber-950 text-amber-400 border-amber-800'
                            : 'bg-red-950 text-red-400 border-red-800'
                        }`}
                      >
                        {patch.risk} risk
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        Confidence: <strong>{Math.round(patch.confidence * 100)}%</strong>
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      {/* View Mode Toggle */}
                      <div className="flex items-center rounded-lg bg-[#0d1117] p-0.5 border border-[#30363d] text-xs font-mono">
                        <button
                          onClick={() => setActiveTab({ ...activeTab, [patch.id]: 'diff' })}
                          className={`px-2.5 py-1 rounded ${
                            currentTab === 'diff' ? 'bg-[#21262d] text-white' : 'text-slate-400'
                          }`}
                        >
                          Unified Diff
                        </button>
                        <button
                          onClick={() => setActiveTab({ ...activeTab, [patch.id]: 'monaco' })}
                          className={`px-2.5 py-1 rounded ${
                            currentTab === 'monaco' ? 'bg-[#21262d] text-white' : 'text-slate-400'
                          }`}
                        >
                          Monaco Side-by-Side
                        </button>
                      </div>

                      {/* Copy Diff */}
                      <button
                        onClick={() => handleCopyDiff(patch)}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-[#30363d] bg-[#0d1117] hover:bg-[#21262d] text-xs text-slate-300 transition-colors"
                        title="Copy unified diff"
                      >
                        {copiedPatchId === patch.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                        <span className="text-[11px]">{copiedPatchId === patch.id ? 'Copied' : 'Copy Diff'}</span>
                      </button>

                      {/* Download .patch */}
                      <button
                        onClick={() => handleDownloadPatch(patch)}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-[#30363d] bg-[#0d1117] hover:bg-[#21262d] text-xs text-slate-300 transition-colors"
                        title="Download .patch file"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span className="text-[11px]">.patch</span>
                      </button>

                      {/* Explicitly Disabled Apply Button per specification */}
                      <div className="relative group">
                        <button
                          disabled
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 text-slate-500 text-xs font-semibold cursor-not-allowed border border-slate-700/50"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          Apply Patch
                        </button>
                        {/* Tooltip */}
                        <div className="absolute right-0 top-full mt-1.5 w-64 p-2 bg-[#0d1117] border border-[#30363d] text-slate-300 text-[11px] rounded shadow-xl pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-10 font-mono">
                          Export patch only. Codebase Doctor never automatically applies patches.
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Explanation */}
                  <div className="p-4 bg-[#161b22] text-xs text-slate-300 border-b border-[#21262d]">
                    <span className="text-slate-500 font-mono uppercase text-[10px] block mb-1">
                      Rationale & Explanation:
                    </span>
                    {patch.explanation}
                  </div>

                  {/* Diff Display */}
                  <div className="p-4 bg-[#0d1117]">
                    {currentTab === 'diff' ? (
                      <div className="rounded-lg border border-[#21262d] overflow-hidden">
                        <CodeViewer
                          code={patch.unified_diff}
                          filePath={`${patch.file_path} (Unified Diff)`}
                          maxHeight="max-h-96"
                        />
                      </div>
                    ) : (
                      <div className="rounded-lg border border-[#21262d] overflow-hidden h-72">
                        <DiffEditor
                          height="100%"
                          language="python"
                          original={patch.original}
                          modified={patch.proposed}
                          theme="vs-dark"
                          options={{
                            readOnly: true,
                            minimap: { enabled: false },
                            fontSize: 12,
                            scrollBeyondLastLine: false,
                            renderSideBySide: true,
                          }}
                        />
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
};
