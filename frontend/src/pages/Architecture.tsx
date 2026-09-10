import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api/client';
import { Scan, ArchitectureSummary, ArchitectureMetric } from '../api/types';
import { Navbar } from '../components/Navbar';
import {
  Cpu,
  AlertTriangle,
  CheckCircle2,
  Share2,
  Layers,
  Search,
  ArrowDownRight,
  ArrowUpRight,
} from 'lucide-react';

export const Architecture: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [arch, setArch] = useState<ArchitectureSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchModule, setSearchModule] = useState('');
  const [sortBy, setSortBy] = useState<'total' | 'fan_in' | 'fan_out'>('total');

  useEffect(() => {
    if (!id) return;
    loadData();
  }, [id]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [scanData, archData] = await Promise.all([
        api.getScan(id!),
        api.getArchitecture(id!),
      ]);
      setScan(scanData);
      setArch(archData);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to load architecture data.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0b0f17] text-slate-200">
        <Navbar />
        <div className="max-w-7xl mx-auto px-4 py-24 text-center">
          <div className="animate-spin w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-sm text-slate-400 font-mono">Analyzing import graph and module coupling...</p>
        </div>
      </div>
    );
  }

  if (error || !arch) {
    return (
      <div className="min-h-screen bg-[#0b0f17] text-slate-200">
        <Navbar githubUrl={scan?.github_url} />
        <div className="max-w-xl mx-auto px-4 py-16 text-center">
          <div className="p-6 bg-[#161b22] border border-red-800/60 rounded-xl">
            <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
            <h2 className="text-lg font-bold text-white mb-2">Error Loading Architecture</h2>
            <p className="text-xs text-slate-400 font-mono">{error || 'No architecture metrics available.'}</p>
          </div>
        </div>
      </div>
    );
  }

  // Filter & Sort metrics
  const filteredMetrics = arch.metrics.filter((m) =>
    m.module.toLowerCase().includes(searchModule.toLowerCase())
  );

  filteredMetrics.sort((a, b) => {
    if (sortBy === 'fan_in') return b.fan_in - a.fan_in;
    if (sortBy === 'fan_out') return b.fan_out - a.fan_out;
    return (b.fan_in + b.fan_out) - (a.fan_in + a.fan_out);
  });

  // Group circular components
  const circularGroups: Record<number, ArchitectureMetric[]> = {};
  arch.metrics.forEach((m) => {
    if (m.circular_component_id !== null && m.circular_component_id !== undefined) {
      if (!circularGroups[m.circular_component_id]) {
        circularGroups[m.circular_component_id] = [];
      }
      circularGroups[m.circular_component_id].push(m);
    }
  });

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-200">
      <Navbar githubUrl={scan?.github_url} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Header */}
        <div className="border-b border-[#21262d] pb-4">
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Cpu className="w-6 h-6 text-purple-400" />
            Architecture & Coupling Analysis
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Static AST import graph analysis, circular dependency cycle detection, and module coupling.
          </p>
        </div>

        {/* Summary Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4">
            <div className="text-xs font-mono text-slate-500 uppercase">Total Modules</div>
            <div className="text-2xl font-bold font-mono text-white mt-1">{arch.total_modules}</div>
            <div className="text-[11px] text-slate-400 mt-1">Python packages & files</div>
          </div>

          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4">
            <div className="text-xs font-mono text-slate-500 uppercase">Total Dependencies</div>
            <div className="text-2xl font-bold font-mono text-white mt-1">{arch.total_dependencies}</div>
            <div className="text-[11px] text-slate-400 mt-1">Direct internal import edges</div>
          </div>

          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4">
            <div className="text-xs font-mono text-slate-500 uppercase">Circular Cycles</div>
            <div
              className={`text-2xl font-bold font-mono mt-1 ${
                arch.circular_components_count > 0 ? 'text-red-400' : 'text-emerald-400'
              }`}
            >
              {arch.circular_components_count}
            </div>
            <div className="text-[11px] text-slate-400 mt-1">Strongly connected components</div>
          </div>

          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4">
            <div className="text-xs font-mono text-slate-500 uppercase">Coupling Hubs</div>
            <div className="text-2xl font-bold font-mono text-white mt-1">{arch.hubs.length}</div>
            <div className="text-[11px] text-slate-400 mt-1">Modules with high fan-out</div>
          </div>
        </div>

        {/* Circular Dependency Warning / Clean State */}
        {arch.circular_components_count > 0 ? (
          <div className="bg-red-950/30 border border-red-900/60 rounded-xl p-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div className="space-y-3 w-full">
                <div>
                  <h3 className="text-sm font-bold text-red-300">
                    Circular Dependencies Detected ({arch.circular_components_count} Cycles)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Circular dependencies couple modules tightly, making unit testing difficult and causing unpredictable import order failures.
                  </p>
                </div>

                <div className="space-y-2">
                  {Object.entries(circularGroups).map(([comp_id, mods]) => (
                    <div
                      key={comp_id}
                      className="bg-[#0d1117] border border-red-900/40 rounded-lg p-3 text-xs font-mono"
                    >
                      <span className="text-red-400 font-bold uppercase text-[11px] block mb-1">
                        Cycle Group #{comp_id} ({mods.length} modules):
                      </span>
                      <div className="flex items-center gap-2 flex-wrap">
                        {mods.map((m) => (
                          <span
                            key={m.id}
                            className="px-2 py-0.5 rounded bg-[#161b22] border border-red-800/50 text-slate-200"
                          >
                            {m.module}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-emerald-950/20 border border-emerald-900/40 rounded-xl p-4 flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <div>
              <h3 className="text-xs font-bold text-emerald-300 uppercase font-mono">
                No Circular Dependencies
              </h3>
              <p className="text-xs text-slate-400">
                The import graph is a strict Directed Acyclic Graph (DAG) with zero circular import cycles.
              </p>
            </div>
          </div>
        )}

        {/* Architecture Hubs Section */}
        {arch.hubs.length > 0 && (
          <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2">
              <Share2 className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                Top Architectural Hubs
              </h2>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {arch.hubs.map((hub) => (
                <div
                  key={hub.module}
                  className="bg-[#0d1117] border border-[#21262d] rounded-lg p-3 font-mono text-xs"
                >
                  <div className="font-semibold text-slate-200 truncate mb-2" title={hub.module}>
                    {hub.module}
                  </div>
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="flex items-center gap-1 text-[11px]">
                      <ArrowDownRight className="w-3.5 h-3.5 text-blue-400" />
                      Fan-In: <strong className="text-white">{hub.fan_in}</strong>
                    </span>
                    <span className="flex items-center gap-1 text-[11px]">
                      <ArrowUpRight className="w-3.5 h-3.5 text-purple-400" />
                      Fan-Out: <strong className="text-white">{hub.fan_out}</strong>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Full Module Coupling Table */}
        <div className="bg-[#161b22] border border-[#21262d] rounded-xl overflow-hidden space-y-3 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                Module Coupling Table
              </h2>
            </div>

            <div className="flex items-center gap-3">
              {/* Search */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-500" />
                <input
                  type="text"
                  value={searchModule}
                  onChange={(e) => setSearchModule(e.target.value)}
                  placeholder="Filter module..."
                  className="pl-8 pr-3 py-1 bg-[#0d1117] border border-[#30363d] rounded text-xs text-white font-mono focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Sort selector */}
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="px-2.5 py-1 bg-[#0d1117] border border-[#30363d] rounded text-xs text-slate-300 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="total">Sort: Total Coupling</option>
                <option value="fan_out">Sort: Fan-Out (Outgoing)</option>
                <option value="fan_in">Sort: Fan-In (Incoming)</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-[#21262d] text-slate-400">
                  <th className="py-2.5 px-3">Module Name</th>
                  <th className="py-2.5 px-3 text-center">Fan-In (Inward)</th>
                  <th className="py-2.5 px-3 text-center">Fan-Out (Outward)</th>
                  <th className="py-2.5 px-3 text-center">Total Coupling</th>
                  <th className="py-2.5 px-3 text-right">Cycle Group</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#21262d]/60">
                {filteredMetrics.map((m) => (
                  <tr key={m.id} className="hover:bg-[#21262d]/40 transition-colors">
                    <td className="py-2 px-3 font-semibold text-slate-200 truncate max-w-sm">
                      {m.module}
                    </td>
                    <td className="py-2 px-3 text-center text-blue-400">{m.fan_in}</td>
                    <td className="py-2 px-3 text-center text-purple-400">{m.fan_out}</td>
                    <td className="py-2 px-3 text-center font-bold text-white">
                      {m.fan_in + m.fan_out}
                    </td>
                    <td className="py-2 px-3 text-right">
                      {m.circular_component_id !== null && m.circular_component_id !== undefined ? (
                        <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-800/50 text-[10px] font-bold">
                          CYCLE #{m.circular_component_id}
                        </span>
                      ) : (
                        <span className="text-slate-600 text-[10px]">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
};
