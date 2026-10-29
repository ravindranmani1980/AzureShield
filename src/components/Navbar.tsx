/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Bell,
  FileDown,
  Eye,
  Radio,
  CheckCircle2,
  Flame,
  ChevronDown,
} from 'lucide-react';
import { AuditDataset, SecurityAlert, Severity } from '../types/security';

interface NavbarProps {
  activeDataset: AuditDataset;
  onSelectDataset: (presetKey: string) => void;
  onDownloadPdf: () => void;
  onOpenPdfPreview: () => void;
  onOpenSimulator: () => void;
  onOpenLiveSync: () => void;
  isLiveConnected: boolean;
  liveSourceName?: string;
  alerts: SecurityAlert[];
  unreadAlertCount: number;
  onSelectAlert: (findingId: string) => void;
  onMarkAllAlertsRead: () => void;
  isContinuousMonitoring: boolean;
  onToggleContinuousMonitoring: () => void;
  activeTab:
    | 'overview'
    | 'inventory'
    | 'storage'
    | 'rbac'
    | 'findings'
    | 'remediation_log';
  setActiveTab: (
    tab:
      | 'overview'
      | 'inventory'
      | 'storage'
      | 'rbac'
      | 'findings'
      | 'remediation_log'
  ) => void;
  remediationLogCount?: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeDataset,
  onSelectDataset,
  onDownloadPdf,
  onOpenPdfPreview,
  onOpenSimulator,
  onOpenLiveSync,
  isLiveConnected,
  liveSourceName,
  alerts,
  unreadAlertCount,
  onSelectAlert,
  onMarkAllAlertsRead,
  isContinuousMonitoring,
  onToggleContinuousMonitoring,
  activeTab,
  setActiveTab,
  remediationLogCount = 0,
}) => {
  const [showAlertsDropdown, setShowAlertsDropdown] = useState(false);

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-50 text-red-700 border border-red-200';
      case 'HIGH':
        return 'bg-orange-50 text-orange-700 border border-orange-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-800 border border-amber-200';
      default:
        return 'bg-emerald-50 text-emerald-800 border border-emerald-200';
    }
  };

  return (
    <>
      <header className="rm-site-header px-6 no-print">
        <div className="max-w-[1440px] mx-auto flex flex-wrap items-center justify-between gap-6 min-h-[64px] py-2">
          {/* Brand (Postrix RM mark + Source Serif 4 Title) */}
          <div className="flex items-center gap-6 min-w-0">
            <a
              href="#overview"
              onClick={(e) => {
                e.preventDefault();
                setActiveTab('overview');
              }}
              className="rm-brand whitespace-nowrap shrink-0"
            >
              <span className="rm-mono-mark" aria-hidden="true">
                RM
              </span>
              <span>
                Maniq <span className="accent">Shield</span>
              </span>
            </a>

            {/* Primary Navigation Links */}
            <nav
              aria-label="Primary Navigation"
              className="flex items-center gap-6 overflow-x-auto"
            >
              <button
                type="button"
                onClick={() => setActiveTab('overview')}
                aria-current={activeTab === 'overview' ? 'page' : undefined}
                className={`rm-navlink whitespace-nowrap shrink-0 cursor-pointer ${
                  activeTab === 'overview' ? 'rm-navlink-active' : ''
                }`}
              >
                Overview &amp; Analytics
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('inventory')}
                aria-current={activeTab === 'inventory' ? 'page' : undefined}
                className={`rm-navlink whitespace-nowrap shrink-0 cursor-pointer ${
                  activeTab === 'inventory' ? 'rm-navlink-active' : ''
                }`}
              >
                Inventory
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('storage')}
                aria-current={activeTab === 'storage' ? 'page' : undefined}
                className={`rm-navlink whitespace-nowrap shrink-0 cursor-pointer ${
                  activeTab === 'storage' ? 'rm-navlink-active' : ''
                }`}
              >
                Storage Accounts &amp; Blobs
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('rbac')}
                aria-current={activeTab === 'rbac' ? 'page' : undefined}
                className={`rm-navlink whitespace-nowrap shrink-0 cursor-pointer ${
                  activeTab === 'rbac' ? 'rm-navlink-active' : ''
                }`}
              >
                RBAC &amp; Permissions
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('findings')}
                aria-current={activeTab === 'findings' ? 'page' : undefined}
                className={`rm-navlink whitespace-nowrap shrink-0 cursor-pointer ${
                  activeTab === 'findings' ? 'rm-navlink-active' : ''
                }`}
              >
                Remediation Register
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('remediation_log')}
                aria-current={
                  activeTab === 'remediation_log' ? 'page' : undefined
                }
                className={`rm-navlink whitespace-nowrap shrink-0 cursor-pointer inline-flex items-center gap-1.5 ${
                  activeTab === 'remediation_log' ? 'rm-navlink-active' : ''
                }`}
              >
                <span>Remediation Log</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold bg-[#2BB5A0]/20 text-[#5FD3BF] border border-[#5FD3BF]/30 tabular-nums">
                  {remediationLogCount}
                </span>
              </button>
            </nav>
          </div>

          {/* Right Action Controls (Postrix xh-btn style) */}
          <div className="flex items-center flex-wrap justify-end gap-2 shrink-0">
            {/* Live Azure Connect Button */}
            <button
              type="button"
              onClick={onOpenLiveSync}
              className="xh-btn whitespace-nowrap shrink-0"
              title={
                isLiveConnected && liveSourceName
                  ? `Connected: ${liveSourceName}`
                  : 'Connect real-time Azure infrastructure via REST API or CLI'
              }
            >
              <span className="relative flex h-2 w-2 flex-shrink-0">
                {isLiveConnected && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#5FD3BF] opacity-75" />
                )}
                <span
                  className={`relative inline-flex rounded-full h-2 w-2 ${
                    isLiveConnected ? 'bg-[#5FD3BF]' : 'bg-[#7F909A]'
                  }`}
                />
              </span>
              <span className="hidden sm:inline">
                {isLiveConnected ? 'Live Azure Connected' : 'Live Sync'}
              </span>
              <span className="sm:hidden">Live</span>
            </button>

            {/* Simulate Injection Button */}
            <button
              type="button"
              onClick={onOpenSimulator}
              className="xh-btn whitespace-nowrap shrink-0"
              title="Inject a misconfiguration to test real-time alerts"
            >
              <Flame className="w-3.5 h-3.5 text-[#EBC385] flex-shrink-0" />
              <span className="hidden sm:inline">Inject Misconfig</span>
            </button>

            {/* Real-time Alerts Bell */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowAlertsDropdown(!showAlertsDropdown)}
                className="xh-btn relative !px-2.5"
                aria-label={`Real-time Alerts (${unreadAlertCount} unread)`}
              >
                <Bell className="w-4 h-4" />
                {unreadAlertCount > 0 && (
                  <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-600 text-[10px] font-bold text-white">
                    {unreadAlertCount}
                  </span>
                )}
              </button>

              {/* Alerts Dropdown Modal */}
              {showAlertsDropdown && (
                <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-xl bg-white border border-slate-200 shadow-xl p-3.5 z-50 text-[#16232F]">
                  <div className="flex items-center justify-between pb-2.5 mb-2.5 border-b border-slate-200">
                    <div className="flex items-center space-x-1.5">
                      <Bell className="w-4 h-4 text-emerald-700" />
                      <span className="text-xs font-semibold text-slate-900">
                        Real-Time Security Alerts ({alerts.length})
                      </span>
                    </div>
                    {alerts.length > 0 && (
                      <button
                        type="button"
                        onClick={onMarkAllAlertsRead}
                        className="text-[11px] text-emerald-700 hover:underline font-medium cursor-pointer"
                      >
                        Mark all read
                      </button>
                    )}
                  </div>

                  <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
                    {alerts.length === 0 ? (
                      <div className="py-6 text-center text-slate-500 text-xs">
                        <CheckCircle2 className="w-6 h-6 text-emerald-700 mx-auto mb-1.5" />
                        No real-time security alerts detected.
                      </div>
                    ) : (
                      alerts.map((alert) => (
                        <div
                          key={alert.id}
                          onClick={() => {
                            onSelectAlert(alert.findingId);
                            setShowAlertsDropdown(false);
                          }}
                          className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-all ${
                            alert.read
                              ? 'bg-slate-50 border-slate-200 text-slate-600'
                              : 'bg-white border-slate-300 text-slate-900 shadow-xs'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${getSeverityBadge(
                                alert.severity
                              )}`}
                            >
                              {alert.severity}
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              {alert.timestamp}
                            </span>
                          </div>
                          <div className="font-semibold text-slate-900 line-clamp-1 mb-0.5">
                            {alert.title}
                          </div>
                          <p className="text-[11px] text-slate-600 line-clamp-2">
                            {alert.summary}
                          </p>
                          <div className="mt-1.5 text-[10px] text-emerald-700 flex items-center justify-between font-mono font-medium">
                            <span>Target: {alert.resourceName}</span>
                            <span className="hover:underline">Remediate →</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* PDF Report Preview Button */}
            <button
              type="button"
              onClick={onOpenPdfPreview}
              className="xh-btn !px-2.5"
              title="Preview PDF Report with Visual Aids"
              aria-label="Preview PDF Report"
            >
              <Eye className="w-4 h-4" />
            </button>

            {/* Export PDF Button */}
            <button
              type="button"
              onClick={onDownloadPdf}
              className="xh-btn primary whitespace-nowrap shrink-0"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Export PDF Report</span>
              <span className="sm:hidden">PDF</span>
            </button>
          </div>
        </div>
      </header>

      {/* Sub-Header Context Strip (Matches Postrix #0D1C2D telemetry strip) */}
      <div className="bg-[#0D1C2D] text-[#EEF3F1] border-b border-[#3E6E86]/35 px-6 py-2.5 no-print">
        <div className="max-w-[1440px] mx-auto flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-[11px] uppercase tracking-wider text-[#5FD3BF]">
              Active Scope:
            </span>
            <span className="font-semibold text-[#EEF3F1]">
              {activeDataset.presetName}
            </span>
            <span className="text-[#7F909A]">·</span>
            <span className="font-mono text-[#A9B7BF] text-[11px]">
              Sub: {activeDataset.subscriptionId}
            </span>
            <span className="text-[#7F909A] hidden md:inline">·</span>
            <span className="text-[#A9B7BF] text-[11px] hidden md:inline">
              By{' '}
              <a
                href="https://ravindran.in"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#5FD3BF] hover:text-[#EBC385] underline"
              >
                Mani Ravindran (ravindran.in)
              </a>
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Environment Preset Selector */}
            <div className="relative">
              <select
                value={
                  activeDataset.presetName.includes('Breach')
                    ? 'high_risk'
                    : 'hardened'
                }
                onChange={(e) => onSelectDataset(e.target.value)}
                className="bg-[#102236] hover:border-[#5FD3BF] border border-[#3E6E86]/50 text-[#EEF3F1] text-xs rounded-md px-2.5 py-1 pr-7 focus:outline-none focus:border-[#5FD3BF] cursor-pointer appearance-none font-mono"
              >
                <option value="high_risk">
                  Preset: High Risk (Loopholes Active)
                </option>
                <option value="hardened">Preset: CIS Hardened Baseline</option>
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-[#A9B7BF] absolute right-2 top-2 pointer-events-none" />
            </div>

            {/* Continuous Cloud Watch Monitor Toggle */}
            <button
              type="button"
              onClick={onToggleContinuousMonitoring}
              title={
                isContinuousMonitoring
                  ? 'Continuous Cloud Watch is ACTIVE (Simulating live telemetry)'
                  : 'Continuous Cloud Watch is PAUSED'
              }
              className={`inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-mono border transition-all whitespace-nowrap cursor-pointer ${
                isContinuousMonitoring
                  ? 'bg-[#2BB5A0]/15 border-[#5FD3BF]/40 text-[#5FD3BF]'
                  : 'bg-[#102236] border-[#3E6E86]/40 text-[#A9B7BF] hover:text-white'
              }`}
            >
              <Radio
                className={`w-3.5 h-3.5 flex-shrink-0 ${
                  isContinuousMonitoring ? 'animate-pulse text-[#5FD3BF]' : ''
                }`}
              />
              <span>Continuous Watch</span>
            </button>
          </div>
        </div>
      </div>
    </>
  );
};
