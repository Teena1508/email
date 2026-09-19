import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Layers, BookCheck } from 'lucide-react';

export default function SummaryCards({ executiveSummary }) {
  if (!executiveSummary) return null;

  const {
    total_sessions = 0,
    overall_posture_score = 100.0,
    overall_posture_status = 'SECURE',
    severity_counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    compliance_posture = {},
  } = executiveSummary;

  // Status color badge logic
  const getStatusBadge = (status, score) => {
    if (score >= 80 || status === 'SECURE') {
      return {
        label: 'SECURE POSTURE',
        bgColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
        strokeColor: '#10b981',
      };
    }
    if (score >= 50 || status === 'NEEDS ATTENTION') {
      return {
        label: 'NEEDS ATTENTION',
        bgColor: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
        strokeColor: '#f59e0b',
      };
    }
    return {
      label: 'CRITICAL RISK',
      bgColor: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
      strokeColor: '#f43f5e',
    };
  };

  const statusInfo = getStatusBadge(overall_posture_status, overall_posture_score);

  // SVG Gauge Arc computation
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (overall_posture_score / 100) * circumference;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
      {/* Card 1: Total Sessions */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-2xl p-5 flex flex-col justify-between shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase">
            Captured Sessions
          </span>
          <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Layers className="w-4 h-4" />
          </div>
        </div>

        <div className="mt-4">
          <div className="text-3xl font-extrabold text-white tracking-tight font-mono">
            {total_sessions}
          </div>
          <p className="text-xs text-slate-400 mt-1">Reconstructed TCP Mail Streams</p>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center gap-2 font-mono text-[11px]">
          <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
            SMTP
          </span>
          <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
            IMAP
          </span>
          <span className="px-2 py-0.5 rounded bg-pink-500/20 text-pink-300 border border-pink-500/30">
            POP3
          </span>
        </div>
      </div>

      {/* Card 2: Security Posture Score Gauge */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-2xl p-5 flex flex-col justify-between shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase">
            Security Posture
          </span>
          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${statusInfo.bgColor}`}>
            {statusInfo.label}
          </span>
        </div>

        <div className="mt-3 flex items-center gap-4">
          <div className="relative w-20 h-20 flex items-center justify-center flex-shrink-0">
            <svg className="w-full h-full transform -rotate-90">
              <circle
                cx="40"
                cy="40"
                r={radius}
                stroke="#1e293b"
                strokeWidth="7"
                fill="transparent"
              />
              <circle
                cx="40"
                cy="40"
                r={radius}
                stroke={statusInfo.strokeColor}
                strokeWidth="7"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-700 ease-out"
              />
            </svg>
            <div className="absolute font-mono font-extrabold text-white text-base">
              {overall_posture_score}
            </div>
          </div>

          <div>
            <div className="text-sm font-semibold text-slate-200">Cryptographic Rating</div>
            <p className="text-xs text-slate-400 mt-0.5">0.0 (Critical) to 100.0 (Secure)</p>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between font-mono">
          <span>Target Score: <strong>≥ 80.0</strong></span>
          <span className="text-emerald-400 font-bold">NIST Compliant</span>
        </div>
      </div>

      {/* Card 3: Severity Breakdown */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-2xl p-5 flex flex-col justify-between shadow-lg">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase">
            Severity Distribution
          </span>
          <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 mt-3 font-mono">
          <div className="p-2 rounded-xl bg-rose-950/40 border border-rose-800/40 flex items-center justify-between">
            <span className="text-xs text-rose-300">CRITICAL</span>
            <span className="text-sm font-extrabold text-rose-400">{severity_counts.CRITICAL || 0}</span>
          </div>
          <div className="p-2 rounded-xl bg-orange-950/40 border border-orange-800/40 flex items-center justify-between">
            <span className="text-xs text-orange-300">HIGH</span>
            <span className="text-sm font-extrabold text-orange-400">{severity_counts.HIGH || 0}</span>
          </div>
          <div className="p-2 rounded-xl bg-amber-950/40 border border-amber-800/40 flex items-center justify-between">
            <span className="text-xs text-amber-300">MEDIUM</span>
            <span className="text-sm font-extrabold text-amber-400">{severity_counts.MEDIUM || 0}</span>
          </div>
          <div className="p-2 rounded-xl bg-emerald-950/40 border border-emerald-800/40 flex items-center justify-between">
            <span className="text-xs text-emerald-300">LOW</span>
            <span className="text-sm font-extrabold text-emerald-400">{severity_counts.LOW || 0}</span>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 font-mono">
          Highest Severity: <strong className="text-rose-400 uppercase">{severity_counts.CRITICAL > 0 ? 'CRITICAL' : severity_counts.HIGH > 0 ? 'HIGH' : 'LOW'}</strong>
        </div>
      </div>

      {/* Card 4: Compliance Framework Readiness */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-2xl p-5 flex flex-col justify-between shadow-lg">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase">
            Compliance Readiness
          </span>
          <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <BookCheck className="w-4 h-4" />
          </div>
        </div>

        <div className="space-y-2 mt-3 font-mono">
          {Object.entries(compliance_posture).map(([fwName, pct]) => {
            const shortName = fwName.includes('NIST') ? 'NIST SP 800-52' : fwName.includes('PCI') ? 'PCI-DSS 4.0' : fwName.includes('RFC') ? 'RFC 8314' : 'CIS Benchmarks';
            const barColor = pct >= 80 ? 'bg-emerald-500' : pct >= 50 ? 'bg-amber-500' : 'bg-rose-500';
            return (
              <div key={fwName}>
                <div className="flex justify-between text-[11px] text-slate-300 mb-0.5">
                  <span>{shortName}</span>
                  <span className="font-bold">{pct}%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className={`h-full ${barColor} transition-all duration-500`} style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 font-mono flex items-center justify-between">
          <span>Frameworks: <strong>4 Audited</strong></span>
        </div>
      </div>
    </div>
  );
}
