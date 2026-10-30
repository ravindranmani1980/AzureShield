/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  FileDown,
  LayoutDashboard,
  HardDrive,
  Users,
  AlertTriangle,
  History,
  FlaskConical,
  Eye,
  Wifi,
  Table2,
  Scale,
  KeyRound,
} from 'lucide-react';
import { ActiveTab } from '../types/security';

export type NavTab = ActiveTab;
export type EnvironmentPreset = 'high_risk' | 'hardened';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  totalFindings: number;
  criticalCount: number;
  remediationLogCount: number;
  currentPreset: 'high_risk' | 'hardened';
  onResetPreset: (preset: 'high_risk' | 'hardened') => void;
  onExportPdf: () => void;
  onPreviewPdf: () => void;
  onOpenSimulator: () => void;
  onOpenLiveSync: () => void;
  onOpenGovernance: () => void;
  isLiveConnected: boolean;
  isDemoData: boolean;
  liveSourceName?: string;
  isWatchMode: boolean;
  onToggleWatchMode: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  totalFindings,
  criticalCount,
  remediationLogCount,
  currentPreset,
  onResetPreset,
  onExportPdf,
  onPreviewPdf,
  onOpenSimulator,
  onOpenLiveSync,
  onOpenGovernance,
  isLiveConnected,
  isDemoData,
  liveSourceName,
  isWatchMode,
  onToggleWatchMode,
}) => {
  const navItems: {
    id: ActiveTab;
    label: string;
    icon: React.ReactNode;
    badge?: number;
  }[] = [
    {
      id: 'overview',
      label: 'Executive Posture',
      icon: <LayoutDashboard className="w-3.5 h-3.5" />,
    },
    {
      id: 'inventory',
      label: 'Inventory',
      icon: <Table2 className="w-3.5 h-3.5" />,
    },
    {
      id: 'storage',
      label: 'Storage Loopholes',
      icon: <HardDrive className="w-3.5 h-3.5" />,
    },
    {
      id: 'rbac',
      label: 'RBAC & Escalation',
      icon: <Users className="w-3.5 h-3.5" />,
    },
    {
      id: 'findings',
      label: 'Findings & Runbooks',
      icon: <AlertTriangle className="w-3.5 h-3.5" />,
      badge: totalFindings,
    },
    {
      id: 'remediation_log',
      label: 'Session Log',
      icon: <History className="w-3.5 h-3.5" />,
      badge: remediationLogCount > 0 ? remediationLogCount : undefined,
    },
  ];

  return (
    <header className="sticky top-0 z-40 shadow-md">
      {/* Row 1: Postrix Dark Navy App Bar */}
      <div className="xh-bar">
        <div className="max-w-7xl w-full mx-auto flex flex-wrap items-center justify-between gap-3">
          {/* Brand & Live Status */}
          <div className="flex items-center gap-3">
            <div className="rm-mono-mark">MS</div>
            <div>
              <div className="xh-title">
                <span>Maniq Shield</span>
                <span className="xh-badge">
                  <span
                    className="xh-dot"
                    style={{
                      background:
                        isLiveConnected && !isDemoData ? '#5fd3bf' : '#d79a45',
                      boxShadow:
                        isLiveConnected && !isDemoData
                          ? '0 0 8px #5fd3bf'
                          : '0 0 8px #d79a45',
                    }}
                  />
                  {isLiveConnected && !isDemoData
                    ? `Live Azure (${liveSourceName || 'Connected'})`
                    : 'Sample Demo Mode'}
                </span>
              </div>
              <div className="xh-sub">
                Azure Storage Account &amp; RBAC Heuristic Scanner · By{' '}
                <a
                  href="https://ravindran.in"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[#5FD3BF] hover:underline font-medium"
                >
                  Mani Ravindran
                </a>
              </div>
            </div>
          </div>

          {/* Right Controls */}
          <div className="flex items-center gap-2 flex-wrap">
            {/* Live Azure Connection Button */}
            <button
              onClick={onOpenLiveSync}
              className="xh-btn ghost"
              style={
                isLiveConnected && !isDemoData
                  ? {
                      borderColor: 'rgba(95, 211, 191, 0.55)',
                      background: 'rgba(43, 181, 160, 0.16)',
                      color: '#5fd3bf',
                    }
                  : {
                      borderColor: 'rgba(215, 154, 69, 0.55)',
                      background: 'rgba(215, 154, 69, 0.14)',
                      color: '#ebc385',
                    }
              }
              title="Configure Azure ARM Bearer Token & Subscription"
            >
              {isLiveConnected && !isDemoData ? (
                <Wifi className="w-3.5 h-3.5 text-[#5fd3bf]" />
              ) : (
                <KeyRound className="w-3.5 h-3.5 text-[#ebc385]" />
              )}
              <span>
                {isLiveConnected && !isDemoData
                  ? 'Live Azure Sync'
                  : 'Azure Connection'}
              </span>
            </button>

            {/* Environment Selector */}
            <select
              aria-label="Select Environment Preset"
              value={currentPreset}
              onChange={(e) =>
                onResetPreset(e.target.value as 'high_risk' | 'hardened')
              }
              className="xh-btn ghost text-xs font-mono cursor-pointer outline-none"
              style={{ paddingTop: '6px', paddingBottom: '6px' }}
            >
              <option value="high_risk" className="bg-[#0a1624] text-white">
                Preset: High-Risk Sample
              </option>
              <option value="hardened" className="bg-[#0a1624] text-white">
                Preset: Hardened Sample
              </option>
            </select>

            {/* Simulated Drift / Loophole Lab */}
            <button
              onClick={onOpenSimulator}
              className="xh-btn ghost"
              title="Inject simulated misconfiguration in browser memory"
            >
              <FlaskConical className="w-3.5 h-3.5 text-[#5fd3bf]" />
              <span className="hidden md:inline">Simulate Drift</span>
            </button>

            {/* Governance & Scope Modal */}
            <button
              onClick={onOpenGovernance}
              className="xh-btn ghost"
              title="Review Scope, Privacy Policy & 13 CSV Recommendations"
            >
              <Scale className="w-3.5 h-3.5 text-[#5fd3bf]" />
              <span className="hidden lg:inline">Scope &amp; Policy</span>
            </button>

            {/* PDF Preview */}
            <button
              onClick={onPreviewPdf}
              className="xh-btn ghost"
              title="Preview Executive PDF Audit Report"
            >
              <Eye className="w-3.5 h-3.5 text-[#5fd3bf]" />
              <span className="hidden sm:inline">Preview PDF</span>
            </button>

            {/* Direct PDF Export */}
            <button onClick={onExportPdf} className="xh-btn primary">
              <FileDown className="w-3.5 h-3.5" />
              <span>Export PDF</span>
            </button>
          </div>
        </div>
      </div>

      {/* Row 2: Postrix Subbar with Navigation Tabs */}
      <div className="xh-subbar">
        <div className="max-w-7xl w-full mx-auto flex flex-wrap items-center justify-between gap-2">
          <nav className="flex items-center gap-1 overflow-x-auto py-0.5">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all whitespace-nowrap cursor-pointer ${
                    isActive
                      ? 'bg-[#2bb5a0] text-[#04211b] font-semibold shadow-xs'
                      : 'text-[#a9b7bf] hover:text-[#eef3f1] hover:bg-white/5'
                  }`}
                >
                  {item.icon}
                  <span>{item.label}</span>
                  {item.badge !== undefined && (
                    <span
                      className={`ml-1 px-1.5 py-0.2 rounded text-[10px] font-mono font-bold tabular-nums ${
                        isActive
                          ? 'bg-[#04211b]/20 text-[#04211b]'
                          : criticalCount > 0 && item.id === 'findings'
                          ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                          : 'bg-white/10 text-[#eef3f1]'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Compact Status Right */}
          <div className="hidden xl:flex items-center gap-2 text-[11px] font-mono text-[#a9b7bf]">
            <button
              onClick={onToggleWatchMode}
              className={`px-2 py-0.5 rounded border text-[11px] font-mono transition-colors cursor-pointer ${
                isWatchMode
                  ? 'border-[#5fd3bf]/50 bg-[#2bb5a0]/15 text-[#5fd3bf]'
                  : 'border-white/10 bg-white/5 text-[#a9b7bf] hover:text-white'
              }`}
              title="Toggle simulated drift ticker"
            >
              {isWatchMode
                ? '● Simulated Ticker: ON'
                : '○ Simulated Ticker: OFF'}
            </button>
            <span>·</span>
            <span>18 Selected Checks</span>
          </div>
        </div>
      </div>
    </header>
  );
};
