import React, { useState, useEffect } from 'react';
import { Activity, CheckCircle2, XCircle, RefreshCw, Server, ShieldCheck, Cpu, Database } from 'lucide-react';

export default function HealthCard() {
  const [healthData, setHealthData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastCheck, setLastCheck] = useState(null);

  const fetchHealth = async () => {
    setLoading(true);
    const start = performance.now();
    try {
      const response = await fetch('/api/v1/health');
      const latency = Math.round(performance.now() - start);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      setHealthData({ ...data, latency });
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to connect to backend server');
      setHealthData(null);
    } finally {
      setLoading(false);
      setLastCheck(new Date().toLocaleTimeString());
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-6 shadow-2xl backdrop-blur-md">
      <div className="flex items-center justify-between pb-4 border-b border-[#1f293d]">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded-lg text-blue-400 border border-blue-500/20">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 text-lg">Backend API Health Status</h3>
            <p className="text-xs text-slate-400 font-mono">Endpoint: /api/v1/health</p>
          </div>
        </div>

        <button
          onClick={fetchHealth}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700/80 rounded-lg border border-slate-700 transition duration-150 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <div className="mt-5 space-y-4">
        {loading && !healthData && !error && (
          <div className="flex items-center justify-center py-6 text-slate-400 gap-2">
            <Activity className="w-5 h-5 animate-pulse text-blue-400" />
            <span>Pinging backend server...</span>
          </div>
        )}

        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-300 flex items-start gap-3">
            <XCircle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-sm">Connection Failed</p>
              <p className="text-xs text-rose-400/90 mt-1">{error}</p>
              <p className="text-xs text-slate-400 mt-2">
                Make sure the FastAPI backend is running on <code className="text-amber-300 font-mono">http://127.0.0.1:8000</code>.
              </p>
            </div>
          </div>
        )}

        {healthData && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block mb-1">Status</span>
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <CheckCircle2 className="w-3 h-3" />
                  {healthData.status.toUpperCase()}
                </span>
              </div>

              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block mb-1">Latency</span>
                <span className="text-xs font-mono font-semibold text-cyan-400">
                  {healthData.latency} ms
                </span>
              </div>

              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block mb-1">Version</span>
                <span className="text-xs font-mono font-semibold text-slate-200">
                  v{healthData.version}
                </span>
              </div>

              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block mb-1">Last Checked</span>
                <span className="text-xs font-mono text-slate-300">
                  {lastCheck || 'Just now'}
                </span>
              </div>
            </div>

            <div className="p-4 bg-slate-900/40 rounded-lg border border-slate-800">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Module Subsystems Status
              </h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {Object.entries(healthData.modules || {}).map(([mod, st]) => (
                  <div key={mod} className="flex items-center justify-between p-2 bg-slate-950/40 rounded border border-slate-800/60">
                    <span className="font-mono text-slate-300">{mod}</span>
                    <span className="text-emerald-400 font-medium capitalize">{st}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
