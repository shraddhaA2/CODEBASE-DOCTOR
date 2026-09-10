import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Scan, AiReport, DiagnosisReport } from '../api/types';
import { Navbar } from '../components/Navbar';
import {
  Sparkles,
  AlertTriangle,
  Loader2,
  Terminal,
} from 'lucide-react';

export const Diagnosis: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [report, setReport] = useState<AiReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      const diagnosisReport = aiData.reports.find((r) => r.kind === 'diagnosis');
      if (diagnosisReport) {
        setReport(diagnosisReport);
      }
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to load diagnosis.');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateDiagnosis = async () => {
    setGenerating(true);
    setError(null);
    try {
      const newReport = await api.generateDiagnosis(id!);
      setReport(newReport);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to generate AI diagnosis.');
    } finally {
      setGenerating(false);
    }
  };

  const diagnosisContent: DiagnosisReport | null = report?.validated_json || null;

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-200">
      <Navbar githubUrl={scan?.github_url} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#21262d]">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <Sparkles className="w-6 h-6 text-purple-400" />
              AI Codebase Diagnosis
            </h1>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Structured engineering interpretation over static findings and architecture metrics.
            </p>
          </div>

          {!report && (
            <button
              onClick={handleGenerateDiagnosis}
              disabled={generating}
              className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-800 text-white font-medium text-xs rounded-lg transition-colors shadow-sm"
            >
              {generating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Generating Diagnosis...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  Request AI Diagnosis
                </>
              )}
            </button>
          )}
        </div>

        {/* Error / AI Configuration Notice Banner */}
        {error && (
          <div className="p-5 bg-[#161b22] border border-amber-800/60 rounded-xl space-y-3">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <h3 className="text-sm font-bold text-white">AI Layer Status</h3>
                <p className="text-xs text-slate-300 font-mono mt-1">{error}</p>
              </div>
            </div>

            <div className="p-3 bg-[#0d1117] rounded-lg border border-[#21262d] text-xs font-mono text-slate-400">
              <span className="text-slate-300 block mb-1">To enable AI reasoning, configure .env:</span>
              <code>LLM_BASE_URL=https://api.openai.com/v1</code>
              <br />
              <code>LLM_API_KEY=sk-...</code>
              <br />
              <code>LLM_MODEL=gpt-4o-mini</code>
            </div>
          </div>
        )}

        {/* Loading State */}
        {loading ? (
          <div className="py-24 text-center text-slate-500 font-mono text-xs">
            <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-purple-400" />
            Loading AI diagnosis...
          </div>
        ) : !report ? (
          /* Empty State */
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-12 text-center max-w-2xl mx-auto">
            <div className="w-12 h-12 rounded-full bg-purple-950/40 border border-purple-800/50 flex items-center justify-center text-purple-400 mx-auto mb-4">
              <Sparkles className="w-6 h-6" />
            </div>
            <h2 className="text-lg font-bold text-white mb-2">No AI Diagnosis Generated Yet</h2>
            <p className="text-xs text-slate-400 leading-relaxed mb-6">
              Codebase Doctor uses deterministic analyzers first. You can optionally request an AI diagnosis that synthesizes the score breakdown, top security findings, and architecture coupling into executive engineering advice.
            </p>
            <button
              onClick={handleGenerateDiagnosis}
              disabled={generating}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-800 text-white font-medium text-xs rounded-lg transition-colors shadow-sm"
            >
              {generating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Analyzing Structured Evidence...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  Generate AI Diagnosis
                </>
              )}
            </button>
          </div>
        ) : (
          /* Diagnosis Content */
          <div className="space-y-6">
            {/* Executive Summary Card */}
            {diagnosisContent?.summary && (
              <div className="bg-[#161b22] border border-purple-900/40 rounded-xl p-6 shadow-sm">
                <div className="flex items-center gap-2 text-purple-400 font-mono text-xs uppercase tracking-wider font-semibold mb-2">
                  <Terminal className="w-4 h-4" />
                  Executive Diagnostic Summary
                </div>
                <p className="text-sm text-slate-200 leading-relaxed font-sans">
                  {diagnosisContent.summary}
                </p>
                <div className="text-[11px] text-slate-500 font-mono mt-3">
                  Report generated on {new Date(report.created_at).toLocaleString()}
                </div>
              </div>
            )}

            {/* Structured Diagnosis Items */}
            <div className="space-y-4">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
                Prioritized Diagnostic Findings ({diagnosisContent?.diagnoses?.length || 0})
              </h2>

              <div className="grid grid-cols-1 gap-4">
                {diagnosisContent?.diagnoses?.map((item, idx) => (
                  <div
                    key={idx}
                    className="bg-[#161b22] border border-[#21262d] rounded-xl p-5 space-y-4 hover:border-[#30363d] transition-colors"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#21262d] pb-3">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={`text-xs font-mono uppercase px-2.5 py-0.5 rounded font-bold ${
                            item.priority === 'critical'
                              ? 'bg-red-950 text-red-400 border border-red-800'
                              : item.priority === 'high'
                              ? 'bg-orange-950 text-orange-400 border border-orange-800'
                              : item.priority === 'medium'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : 'bg-blue-950 text-blue-400 border border-blue-800'
                          }`}
                        >
                          {item.priority}
                        </span>
                        <h3 className="text-base font-bold text-white tracking-tight">
                          {item.diagnosis}
                        </h3>
                      </div>

                      <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                        <span>Confidence: <strong>{Math.round(item.confidence * 100)}%</strong></span>
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] ${
                            item.evidence_sufficient
                              ? 'text-emerald-400 bg-emerald-950/40 border border-emerald-800/40'
                              : 'text-amber-400 bg-amber-950/40 border border-amber-800/40'
                          }`}
                        >
                          {item.evidence_sufficient ? 'Evidence Grounded' : 'Partial Context'}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      <div className="bg-[#0d1117] p-3 rounded-lg border border-[#21262d]">
                        <span className="text-slate-500 font-mono uppercase text-[10px] block mb-1">
                          Why It Matters
                        </span>
                        <p className="text-slate-300 leading-relaxed">{item.why_it_matters}</p>
                      </div>

                      <div className="bg-[#0d1117] p-3 rounded-lg border border-[#21262d]">
                        <span className="text-slate-500 font-mono uppercase text-[10px] block mb-1">
                          Engineering Impact
                        </span>
                        <p className="text-slate-300 leading-relaxed">{item.impact}</p>
                      </div>
                    </div>

                    <div className="bg-[#0d1117] p-3.5 rounded-lg border border-purple-900/30 text-xs">
                      <span className="text-purple-400 font-mono uppercase text-[10px] font-bold block mb-1">
                        Prescription / Recommended Action
                      </span>
                      <p className="text-slate-200 leading-relaxed">{item.recommended_action}</p>
                    </div>

                    {item.related_finding_ids && item.related_finding_ids.length > 0 && (
                      <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500 pt-1">
                        <span>Related Findings:</span>
                        {item.related_finding_ids.map((fid) => (
                          <Link
                            key={fid}
                            to={`/scans/${id}/findings`}
                            className="px-2 py-0.5 rounded bg-[#21262d] text-blue-400 hover:text-blue-300 transition-colors"
                          >
                            {fid.slice(0, 8)}
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};
