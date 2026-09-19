import React, { useState, useMemo } from 'react';
import { Search, ShieldAlert, ArrowUpDown, Lock, Unlock, Eye, Sparkles } from 'lucide-react';

export default function SessionTable({ sessionDetails, onSelectSession, selectedNodeFilter }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedProtocol, setSelectedProtocol] = useState('ALL');
  const [sortField, setSortField] = useState('risk_score');
  const [sortDirection, setSortDirection] = useState('desc');

  // Filter & sort logic
  const filteredSessions = useMemo(() => {
    if (!sessionDetails) return [];

    return sessionDetails.filter((item) => {
      const sess = item.session || {};
      const ass = item.assessment || {};
      const pred = item.prediction || {};

      // Sankey node filter match if present
      if (selectedNodeFilter) {
        const filterUpper = selectedNodeFilter.toUpperCase();
        const proto = (sess.protocol || '').toUpperCase();
        const enc = (sess.encryption_type || '').toUpperCase();
        const ver = (ass.tls_version_negotiated || '').toUpperCase();
        const cipher = (ass.cipher_suite || '').toUpperCase();

        const matchesNode =
          proto.includes(filterUpper) ||
          enc.includes(filterUpper) ||
          ver.includes(filterUpper) ||
          cipher.includes(filterUpper) ||
          (selectedNodeFilter === 'Implicit TLS' && enc.includes('IMPLICIT')) ||
          (selectedNodeFilter === 'STARTTLS' && enc.includes('STARTTLS')) ||
          (selectedNodeFilter === 'Plaintext' && (enc.includes('NONE') || !ver));

        if (!matchesNode) return false;
      }

      // Severity filter match
      if (selectedSeverity !== 'ALL') {
        if ((pred.severity || '').toUpperCase() !== selectedSeverity) return false;
      }

      // Protocol filter match
      if (selectedProtocol !== 'ALL') {
        if (!(sess.protocol || '').toUpperCase().includes(selectedProtocol)) return false;
      }

      // Search term match
      if (searchTerm.trim() !== '') {
        const term = searchTerm.toLowerCase();
        const matchId = (sess.session_id || '').toLowerCase().includes(term);
        const matchClient = `${sess.client_ip}:${sess.client_port}`.includes(term);
        const matchServer = `${sess.server_ip}:${sess.server_port}`.includes(term);
        const matchCipher = (ass.cipher_suite || '').toLowerCase().includes(term);
        const matchVer = (ass.tls_version_negotiated || '').toLowerCase().includes(term);
        return matchId || matchClient || matchServer || matchCipher || matchVer;
      }

      return true;
    }).sort((a, b) => {
      let valA = 0;
      let valB = 0;

      if (sortField === 'risk_score') {
        valA = a.prediction?.risk_score || 0;
        valB = b.prediction?.risk_score || 0;
      } else if (sortField === 'session_id') {
        valA = a.session?.session_id || '';
        valB = b.session?.session_id || '';
        return sortDirection === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      } else if (sortField === 'protocol') {
        valA = a.session?.protocol || '';
        valB = b.session?.protocol || '';
        return sortDirection === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }

      return sortDirection === 'asc' ? valA - valB : valB - valA;
    });
  }, [sessionDetails, selectedNodeFilter, selectedSeverity, selectedProtocol, searchTerm, sortField, sortDirection]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const getSeverityBadge = (severity) => {
    const s = (severity || 'LOW').toUpperCase();
    switch (s) {
      case 'CRITICAL':
        return 'bg-rose-950/60 text-rose-300 border-rose-700/60';
      case 'HIGH':
        return 'bg-orange-950/60 text-orange-300 border-orange-700/60';
      case 'MEDIUM':
        return 'bg-amber-950/60 text-amber-300 border-amber-700/60';
      default:
        return 'bg-emerald-950/60 text-emerald-300 border-emerald-700/60';
    }
  };

  return (
    <div className="bg-[#111827] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-4">
      {/* Header & Controls Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[#1f293d]">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            Network Session Forensic Inspector
            <span className="text-xs font-mono font-normal px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              {filteredSessions.length} Session(s)
            </span>
          </h3>
          <p className="text-xs text-slate-400">
            Click any session row to inspect SHAP ML risk drivers, X.509 cert chains, and run live What-If simulations
          </p>
        </div>

        {/* Search & Filters */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IP, cipher, ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-[#090d16] border border-[#1f293d] focus:border-blue-500 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none w-48 sm:w-56 font-mono"
            />
          </div>

          {/* Severity Pills */}
          <div className="flex items-center bg-[#090d16] border border-[#1f293d] rounded-xl p-1 font-mono text-[11px]">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded-lg transition ${
                  selectedSeverity === sev
                    ? 'bg-blue-600 text-white font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Protocol Pills */}
          <div className="flex items-center bg-[#090d16] border border-[#1f293d] rounded-xl p-1 font-mono text-[11px]">
            {['ALL', 'SMTP', 'IMAP', 'POP3'].map((proto) => (
              <button
                key={proto}
                onClick={() => setSelectedProtocol(proto)}
                className={`px-2.5 py-1 rounded-lg transition ${
                  selectedProtocol === proto
                    ? 'bg-cyan-600 text-white font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {proto}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Sessions Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left font-sans text-xs">
          <thead>
            <tr className="border-b border-[#1f293d] text-slate-400 font-mono text-[11px] uppercase tracking-wider bg-slate-900/40">
              <th className="py-3 px-3 cursor-pointer hover:text-white" onClick={() => handleSort('session_id')}>
                <div className="flex items-center gap-1">
                  <span>Session Flow ID</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-3 cursor-pointer hover:text-white" onClick={() => handleSort('protocol')}>
                <div className="flex items-center gap-1">
                  <span>Protocol</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-3">Client ➔ Server</th>
              <th className="py-3 px-3">Encryption Mode</th>
              <th className="py-3 px-3">TLS Version</th>
              <th className="py-3 px-3">Negotiated Cipher Suite</th>
              <th className="py-3 px-3 cursor-pointer hover:text-white" onClick={() => handleSort('risk_score')}>
                <div className="flex items-center gap-1">
                  <span>Risk Score</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-3">Severity</th>
              <th className="py-3 px-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f293d]">
            {filteredSessions.length === 0 ? (
              <tr>
                <td colSpan="9" className="py-8 text-center text-slate-500 font-mono">
                  No sessions match the selected filters or search terms.
                </td>
              </tr>
            ) : (
              filteredSessions.map((item) => {
                const sess = item.session || {};
                const ass = item.assessment || {};
                const pred = item.prediction || {};

                const isEncrypted = sess.encryption_type && sess.encryption_type !== 'NONE';

                return (
                  <tr
                    key={sess.session_id}
                    onClick={() => onSelectSession(item)}
                    className="hover:bg-slate-800/40 cursor-pointer transition duration-150 group"
                  >
                    {/* Session ID */}
                    <td className="py-3.5 px-3 font-mono text-slate-200 group-hover:text-blue-400 font-medium truncate max-w-[200px]">
                      {sess.session_id}
                    </td>

                    {/* Protocol */}
                    <td className="py-3.5 px-3 font-mono">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-bold">
                        {sess.protocol}
                      </span>
                    </td>

                    {/* Client -> Server */}
                    <td className="py-3.5 px-3 font-mono text-slate-400 text-[11px]">
                      {sess.client_ip}:{sess.client_port} ➔ {sess.server_ip}:{sess.server_port}
                    </td>

                    {/* Encryption Mode */}
                    <td className="py-3.5 px-3 font-mono">
                      <span className="flex items-center gap-1.5 text-slate-300">
                        {isEncrypted ? (
                          <Lock className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Unlock className="w-3.5 h-3.5 text-rose-400" />
                        )}
                        <span>{sess.encryption_type || 'NONE'}</span>
                      </span>
                    </td>

                    {/* TLS Version */}
                    <td className="py-3.5 px-3 font-mono">
                      {ass.tls_version_negotiated ? (
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                          ass.tls_version_negotiated.includes('1.3')
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            : ass.tls_version_negotiated.includes('1.2')
                            ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        }`}>
                          {ass.tls_version_negotiated}
                        </span>
                      ) : (
                        <span className="text-slate-500 italic">Unencrypted</span>
                      )}
                    </td>

                    {/* Cipher Suite */}
                    <td className="py-3.5 px-3 font-mono text-slate-300 text-[11px] truncate max-w-[220px]">
                      {ass.cipher_suite || 'None'}
                    </td>

                    {/* Risk Score */}
                    <td className="py-3.5 px-3 font-mono font-extrabold text-sm text-white">
                      {pred.risk_score}
                      <span className="text-[10px] text-slate-500 font-normal">/100</span>
                    </td>

                    {/* Severity */}
                    <td className="py-3.5 px-3 font-mono">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getSeverityBadge(pred.severity)}`}>
                        {pred.severity}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="py-3.5 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectSession(item);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/30 text-xs font-medium transition"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
