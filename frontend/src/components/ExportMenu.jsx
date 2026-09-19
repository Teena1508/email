import React, { useState } from 'react';
import { Download, FileCode, FileText, ChevronDown } from 'lucide-react';

export default function ExportMenu({ runId }) {
  const [isOpen, setIsOpen] = useState(false);

  const handleExport = (format) => {
    setIsOpen(false);
    if (!runId) {
      alert('No active analysis run available to export.');
      return;
    }
    const downloadUrl = `/api/v1/reports/${runId}?format=${format}`;
    window.open(downloadUrl, '_blank');
  };

  return (
    <div className="relative inline-block text-left">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-mono text-xs font-semibold shadow-lg shadow-blue-500/20 border border-blue-400/30 transition"
      >
        <Download className="w-4 h-4" />
        <span>Export Report</span>
        <ChevronDown className="w-3.5 h-3.5 opacity-80" />
      </button>

      {isOpen && (
        <div
          className="origin-top-right absolute right-0 mt-2 w-48 rounded-xl bg-[#090d16] border border-[#1f293d] shadow-2xl z-50 p-1 font-mono text-xs animate-in fade-in zoom-in-95 duration-150"
          onMouseLeave={() => setIsOpen(false)}
        >
          <button
            onClick={() => handleExport('pdf')}
            className="w-full text-left px-3 py-2 rounded-lg hover:bg-slate-800 text-slate-200 flex items-center gap-2 transition"
          >
            <FileText className="w-4 h-4 text-rose-400" />
            <div>
              <div className="font-bold text-white">PDF Document</div>
              <div className="text-[10px] text-slate-400">Printable Executive Audit</div>
            </div>
          </button>

          <button
            onClick={() => handleExport('html')}
            className="w-full text-left px-3 py-2 rounded-lg hover:bg-slate-800 text-slate-200 flex items-center gap-2 transition"
          >
            <FileCode className="w-4 h-4 text-cyan-400" />
            <div>
              <div className="font-bold text-white">HTML Report</div>
              <div className="text-[10px] text-slate-400">Interactive Web Report</div>
            </div>
          </button>

          <button
            onClick={() => handleExport('json')}
            className="w-full text-left px-3 py-2 rounded-lg hover:bg-slate-800 text-slate-200 flex items-center gap-2 transition"
          >
            <FileCode className="w-4 h-4 text-amber-400" />
            <div>
              <div className="font-bold text-white">JSON Data</div>
              <div className="text-[10px] text-slate-400">Machine-Readable Export</div>
            </div>
          </button>
        </div>
      )}
    </div>
  );
}
