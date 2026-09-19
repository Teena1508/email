import React, { useState, useMemo } from 'react';
import { Network, Filter } from 'lucide-react';

export default function SankeyFlow({ sessionDetails, onNodeClick, selectedFilterNode }) {
  const [hoveredFlow, setHoveredFlow] = useState(null);

  // Compute node and link metrics for 4-stage flow
  const sankeyData = useMemo(() => {
    if (!sessionDetails || sessionDetails.length === 0) return null;

    const totalSessions = sessionDetails.length;

    // Helper functions for stage categorizations
    const getProtoCategory = (item) => {
      const p = item.session?.protocol?.toUpperCase() || 'SMTP';
      if (p.includes('IMAP')) return 'IMAP';
      if (p.includes('POP')) return 'POP3';
      return 'SMTP';
    };

    const getEncCategory = (item) => {
      const enc = item.session?.encryption_type?.toUpperCase() || 'NONE';
      if (enc.includes('IMPLICIT')) return 'Implicit TLS';
      if (enc.includes('STARTTLS')) return 'STARTTLS';
      return 'Plaintext';
    };

    const getVersionCategory = (item) => {
      const ver = item.assessment?.tls_version_negotiated || 'Plaintext';
      if (ver.includes('1.3')) return 'TLS 1.3';
      if (ver.includes('1.2')) return 'TLS 1.2';
      if (ver.includes('1.0') || ver.includes('1.1') || ver.includes('SSL')) return 'TLS 1.0/1.1';
      return 'Plaintext';
    };

    const getCipherCategory = (item) => {
      const cipher = item.assessment?.cipher_suite || '';
      const ver = item.assessment?.tls_version_negotiated || '';
      const isFs = item.assessment?.is_forward_secrecy;

      if (!ver || ver === 'Plaintext' || cipher === 'None') return 'Plaintext';
      if (cipher.includes('AES_128_GCM') || cipher.includes('AES_256_GCM') || cipher.includes('CHACHA20')) {
        return 'Modern AEAD';
      }
      if (isFs || cipher.includes('ECDHE') || cipher.includes('DHE')) {
        return 'PFS (ECDHE/DHE)';
      }
      return 'Weak / Legacy';
    };

    // Stage 0: Protocol
    // Stage 1: Encryption Mode
    // Stage 2: TLS Version
    // Stage 3: Cipher Strength
    const stage0 = ['SMTP', 'IMAP', 'POP3'];
    const stage1 = ['Implicit TLS', 'STARTTLS', 'Plaintext'];
    const stage2 = ['TLS 1.3', 'TLS 1.2', 'TLS 1.0/1.1', 'Plaintext'];
    const stage3 = ['Modern AEAD', 'PFS (ECDHE/DHE)', 'Weak / Legacy', 'Plaintext'];

    // Count transitions
    const linkCounts01 = {};
    const linkCounts12 = {};
    const linkCounts23 = {};

    const nodeCounts = { 0: {}, 1: {}, 2: {}, 3: {} };

    sessionDetails.forEach((item) => {
      const p = getProtoCategory(item);
      const e = getEncCategory(item);
      const v = getVersionCategory(item);
      const c = getCipherCategory(item);

      nodeCounts[0][p] = (nodeCounts[0][p] || 0) + 1;
      nodeCounts[1][e] = (nodeCounts[1][e] || 0) + 1;
      nodeCounts[2][v] = (nodeCounts[2][v] || 0) + 1;
      nodeCounts[3][c] = (nodeCounts[3][c] || 0) + 1;

      const k01 = `${p}->${e}`;
      const k12 = `${e}->${v}`;
      const k23 = `${v}->${c}`;

      linkCounts01[k01] = (linkCounts01[k01] || 0) + 1;
      linkCounts12[k12] = (linkCounts12[k12] || 0) + 1;
      linkCounts23[k23] = (linkCounts23[k23] || 0) + 1;
    });

    return {
      totalSessions,
      stages: [stage0, stage1, stage2, stage3],
      nodeCounts,
      linkCounts: [linkCounts01, linkCounts12, linkCounts23],
    };
  }, [sessionDetails]);

  if (!sankeyData) return null;

  const width = 1000;
  const height = 340;
  const margin = { top: 40, right: 140, bottom: 20, left: 140 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  const stageX = [
    margin.left,
    margin.left + innerWidth * 0.33,
    margin.left + innerWidth * 0.66,
    margin.left + innerWidth,
  ];

  const nodeColors = {
    // Stage 0
    SMTP: '#3b82f6',
    IMAP: '#8b5cf6',
    POP3: '#ec4899',
    // Stage 1
    'Implicit TLS': '#10b981',
    STARTTLS: '#06b6d4',
    Plaintext: '#ef4444',
    // Stage 2
    'TLS 1.3': '#10b981',
    'TLS 1.2': '#3b82f6',
    'TLS 1.0/1.1': '#f59e0b',
    // Stage 3
    'Modern AEAD': '#10b981',
    'PFS (ECDHE/DHE)': '#06b6d4',
    'Weak / Legacy': '#f97316',
  };

  // Calculate layout nodes
  const nodeWidth = 16;

  // Calculate Y positions for nodes per stage
  const layoutNodes = [];
  const nodeYMap = {};

  sankeyData.stages.forEach((stageNodes, stageIdx) => {
    const x = stageX[stageIdx];
    const totalStageCount = Object.values(sankeyData.nodeCounts[stageIdx]).reduce((a, b) => a + b, 0) || 1;
    
    // Available height per node with spacing
    let currentY = margin.top;
    const spacing = 18;
    const totalSpacing = spacing * (stageNodes.length - 1);
    const availableH = innerHeight - totalSpacing;

    stageNodes.forEach((nodeName) => {
      const count = sankeyData.nodeCounts[stageIdx][nodeName] || 0;
      const h = count > 0 ? Math.max(14, (count / totalStageCount) * availableH) : 0;
      
      const nodeObj = {
        id: `${stageIdx}-${nodeName}`,
        stage: stageIdx,
        name: nodeName,
        x: stageIdx === 3 ? x - nodeWidth : x,
        y: currentY,
        width: nodeWidth,
        height: h,
        count,
        color: nodeColors[nodeName] || '#64748b',
      };

      layoutNodes.push(nodeObj);
      nodeYMap[`${stageIdx}-${nodeName}`] = nodeObj;

      currentY += h + (count > 0 ? spacing : 0);
    });
  });

  // Calculate link paths between adjacent stages
  const layoutLinks = [];

  const createLinksForStage = (fromStageIdx, toStageIdx, linkCountsDict) => {
    const fromStageNodes = sankeyData.stages[fromStageIdx];
    const toStageNodes = sankeyData.stages[toStageIdx];

    // Track Y offsets for stacking links within nodes
    const sourceYOffset = {};
    const targetYOffset = {};

    fromStageNodes.forEach((src) => {
      sourceYOffset[src] = 0;
    });
    toStageNodes.forEach((tgt) => {
      targetYOffset[tgt] = 0;
    });

    Object.entries(linkCountsDict).forEach(([key, count]) => {
      if (count === 0) return;
      const [srcName, tgtName] = key.split('->');

      const srcNode = nodeYMap[`${fromStageIdx}-${srcName}`];
      const tgtNode = nodeYMap[`${toStageIdx}-${tgtName}`];

      if (!srcNode || !tgtNode || srcNode.height === 0 || tgtNode.height === 0) return;

      const srcStageTotal = sankeyData.nodeCounts[fromStageIdx][srcName] || 1;
      const tgtStageTotal = sankeyData.nodeCounts[toStageIdx][tgtName] || 1;

      const linkH = Math.max(2, (count / sankeyData.totalSessions) * innerHeight * 0.8);

      const y1 = srcNode.y + sourceYOffset[srcName] + linkH / 2;
      const y2 = tgtNode.y + targetYOffset[tgtName] + linkH / 2;

      sourceYOffset[srcName] += linkH;
      targetYOffset[tgtName] += linkH;

      const x1 = srcNode.x + srcNode.width;
      const x2 = tgtNode.x;
      const dx = (x2 - x1) / 2;

      const pathStr = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

      layoutLinks.push({
        id: `${fromStageIdx}-${srcName}->${toStageIdx}-${tgtName}`,
        srcName,
        tgtName,
        fromStage: fromStageIdx,
        toStage: toStageIdx,
        count,
        pct: ((count / sankeyData.totalSessions) * 100).toFixed(1),
        path: pathStr,
        strokeWidth: linkH,
        color: srcNode.color,
      });
    });
  };

  createLinksForStage(0, 1, sankeyData.linkCounts[0]);
  createLinksForStage(1, 2, sankeyData.linkCounts[1]);
  createLinksForStage(2, 3, sankeyData.linkCounts[2]);

  const stageTitles = ['1. Protocol', '2. Encryption Mode', '3. TLS Version', '4. Cipher Strength'];

  return (
    <div className="bg-[#111827] border border-[#1f293d] rounded-2xl p-6 shadow-xl relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 pb-3 border-b border-[#1f293d] gap-2">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              Cryptographic Traffic Flow Architecture
              <span className="text-[10px] font-mono font-normal px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                Visual Centerpiece
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Interactive 4-Stage Traffic Flow (Protocol ➔ Handshake ➔ TLS ➔ Cipher Strength)
            </p>
          </div>
        </div>

        {selectedFilterNode && (
          <button
            onClick={() => onNodeClick && onNodeClick(null)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-300 border border-cyan-500/30 transition"
          >
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            <span>Filtered: <strong>{selectedFilterNode}</strong> (Reset)</span>
          </button>
        )}
      </div>

      {/* SVG Diagram Canvas */}
      <div className="relative w-full overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto min-w-[750px]">
          <defs>
            {/* Stage column background guide lines */}
            {stageX.map((x, idx) => (
              <line key={idx} x1={x} y1={margin.top} x2={x} y2={height - margin.bottom} stroke="#1e293b" strokeDasharray="3 3" />
            ))}
          </defs>

          {/* Stage Column Labels */}
          {stageTitles.map((title, idx) => (
            <text
              key={idx}
              x={stageX[idx]}
              y={22}
              textAnchor={idx === 0 ? 'start' : idx === 3 ? 'end' : 'middle'}
              fill="#94a3b8"
              className="text-xs font-mono font-semibold tracking-wider uppercase"
            >
              {title}
            </text>
          ))}

          {/* Flow Link Curves */}
          {layoutLinks.map((link) => {
            const isHovered = hoveredFlow === link.id;
            const isDimmed = hoveredFlow && !isHovered;

            return (
              <path
                key={link.id}
                d={link.path}
                fill="none"
                stroke={link.color}
                strokeWidth={Math.max(2, link.strokeWidth)}
                strokeOpacity={isHovered ? 0.85 : isDimmed ? 0.08 : 0.35}
                className="transition-all duration-200 cursor-pointer"
                onMouseEnter={() => setHoveredFlow(link.id)}
                onMouseLeave={() => setHoveredFlow(null)}
              >
                <title>{`${link.srcName} ➔ ${link.tgtName}: ${link.count} session(s) (${link.pct}%)`}</title>
              </path>
            );
          })}

          {/* Nodes */}
          {layoutNodes.map((node) => {
            if (node.height === 0) return null;

            const isSelected = selectedFilterNode === node.name;

            return (
              <g
                key={node.id}
                className="cursor-pointer group"
                onClick={() => onNodeClick && onNodeClick(isSelected ? null : node.name)}
              >
                {/* Node bar */}
                <rect
                  x={node.x}
                  y={node.y}
                  width={node.width}
                  height={node.height}
                  rx={4}
                  fill={node.color}
                  stroke={isSelected ? '#ffffff' : 'none'}
                  strokeWidth={2}
                  className="transition duration-200 group-hover:brightness-125"
                />

                {/* Node Label Text */}
                <text
                  x={node.stage === 0 ? node.x - 10 : node.stage === 3 ? node.x + node.width + 10 : node.x + node.width / 2}
                  y={node.y + node.height / 2 + 4}
                  textAnchor={node.stage === 0 ? 'end' : node.stage === 3 ? 'start' : 'middle'}
                  fill="#f8fafc"
                  className="text-xs font-mono font-medium drop-shadow-md select-none group-hover:fill-blue-400 transition"
                >
                  {node.name} <tspan fill="#94a3b8" className="text-[10px]">({node.count})</tspan>
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
