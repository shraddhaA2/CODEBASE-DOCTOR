import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Scan } from '../api/types';
import { Navbar } from '../components/Navbar';
import { Loader2, CheckCircle2, XCircle, Clock, ArrowRight, AlertTriangle } from 'lucide-react';

export const ScanStatus: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollIntervalRef = useRef<any>(null);

  useEffect(() => {
    if (!id) return;

    const fetchStatus = async () => {
      try {
        const data = await api.getScan(id);
        setScan(data);

        if (data.status === 'succeeded') {
          clearInterval(pollIntervalRef.current);
          // Redirect to dashboard after slight delay for visual confirmation
          setTimeout(() => {
            navigate(`/scans/${id}/dashboard`);
          }, 1200);
        } else if (data.status === 'failed') {
          clearInterval(pollIntervalRef.current);
        }
      } catch (err: any) {
        setError(err.detail || err.message || 'Failed to poll scan status');
        clearInterval(pollIntervalRef.current);
      }
    };

    fetchStatus();
    pollIntervalRef.current = setInterval(fetchStatus, 2000);

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [id, navigate]);

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-200">
      <Navbar githubUrl={scan?.github_url} />

      <div className="max-w-2xl mx-auto px-4 py-16 text-center">
        {scan?.status === 'failed' ? (
          <div className="bg-[#161b22] border border-red-900/60 rounded-xl p-8 shadow-xl">
            <div className="w-12 h-12 rounded-full bg-red-950/60 border border-red-800/80 flex items-center justify-center text-red-400 mx-auto mb-4">
              <XCircle className="w-6 h-6" />
            </div>
            <h2 className="text-xl font-bold text-white mb-2">Scan Failed</h2>
            <p className="text-sm text-slate-400 mb-6 font-mono break-words">
              {scan.error || 'An unexpected error occurred during repository analysis.'}
            </p>
            <Link
              to="/"
              className="inline-flex items-center gap-2 px-4 py-2 bg-[#21262d] hover:bg-[#30363d] text-white rounded-lg text-sm font-medium transition-colors"
            >
              Start Another Scan
            </Link>
          </div>
        ) : scan?.status === 'succeeded' ? (
          <div className="bg-[#161b22] border border-emerald-900/60 rounded-xl p-8 shadow-xl">
            <div className="w-12 h-12 rounded-full bg-emerald-950/60 border border-emerald-800/80 flex items-center justify-center text-emerald-400 mx-auto mb-4">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <h2 className="text-xl font-bold text-white mb-2">Analysis Complete</h2>
            <p className="text-sm text-slate-400 mb-6">
              Repository analyzed successfully. Redirecting to dashboard...
            </p>
            <Link
              to={`/scans/${id}/dashboard`}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors"
            >
              Open Dashboard
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        ) : (
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-8 shadow-xl">
            <div className="w-12 h-12 rounded-full bg-blue-950/60 border border-blue-800/80 flex items-center justify-center text-blue-400 mx-auto mb-4">
              <Loader2 className="w-6 h-6 animate-spin" />
            </div>
            <h2 className="text-xl font-bold text-white mb-2">
              {scan?.status === 'queued' ? 'Scan Queued' : 'Analyzing Codebase...'}
            </h2>
            <p className="text-xs font-mono text-slate-400 mb-8 max-w-md mx-auto truncate">
              {scan?.github_url || 'Target repository'}
            </p>

            {/* Step Indicators */}
            <div className="space-y-3 text-left max-w-sm mx-auto">
              <div className="flex items-center gap-3 text-xs text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Validate GitHub URL & SSRF checks</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Isolated shallow workspace clone</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-300">
                <Loader2 className="w-4 h-4 text-blue-400 animate-spin shrink-0" />
                <span>Deterministic static analysis & import graph</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-500">
                <Clock className="w-4 h-4 shrink-0" />
                <span>Compute deterministic health score</span>
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-4 p-3 bg-red-950/40 border border-red-800/50 rounded-lg text-xs text-red-300 flex items-center gap-2 justify-center">
            <AlertTriangle className="w-4 h-4" />
            <span>{error}</span>
          </div>
        )}
      </div>
    </div>
  );
};
