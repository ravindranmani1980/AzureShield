/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Bell,
  FileDown,
  Eye,
  Radio,
  PlusCircle,
  CheckCircle2,
  AlertTriangle,
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
  alerts: SecurityAlert[];
  unreadAlertCount: number;
  onSelectAlert: (findingId: string) => void;
  onMarkAllAlertsRead: () => void;
  isContinuousMonitoring: boolean;
  onToggleContinuousMonitoring: () => void;
  activeTab: 'overview' | 'storage' | 'rbac' | 'findings';
  setActiveTab: (tab: 'overview' | 'storage' | 'rbac' | 'findings') => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeDataset,
  onSelectDataset,
  onDownloadPdf,
  onOpenPdfPreview,
  onOpenSimulator,
  onOpenLiveSync,
  isLiveConnected,
  alerts,
  unreadAlertCount,
  onSelectAlert,
  onMarkAllAlertsRead,
  isContinuousMonitoring,
  onToggleContinuousMonitoring,
  activeTab,
  setActiveTab,
}) => {
  const [showAlertsDropdown, setShowAlertsDropdown] = useState(false);

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
    }
  };

  return (
    <header className="sticky top-0 z-40 bg-slate-900/95 backdrop-blur-md border-b border-slate-800 text-slate-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <ShieldAlert className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-300 bg-clip-text text-transparent">
                  AzureShield
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                  CSPM v2.4
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Storage & RBAC Auditor • By{' '}
                <a
                  href="https://ravindran.in"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300 font-medium hover:underline inline-flex items-center space-x-0.5"
                >
                  <span>Mani Ravindran (ravindran.in)</span>
                </a>
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center space-x-1 bg-slate-950/60 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'overview'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              Overview & Analytics
            </button>
            <button
              onClick={() => setActiveTab('storage')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'storage'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              Storage Accounts & Blobs
            </button>
            <button
              onClick={() => setActiveTab('rbac')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'rbac'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              RBAC & Permissions
            </button>
            <button
              onClick={() => setActiveTab('findings')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'findings'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              Remediation Register
            </button>
          </nav>

          {/* Right Action Controls */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            {/* Live Azure Connect Button */}
            <button
              onClick={onOpenLiveSync}
              className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                isLiveConnected
                  ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300 shadow-sm shadow-cyan-500/20'
                  : 'bg-slate-800/80 hover:bg-slate-800 border-slate-700 text-slate-300 hover:text-white'
              }`}
              title="Connect real-time Azure infrastructure via REST API or CLI"
            >
              <span className="relative flex h-2 w-2">
                {isLiveConnected && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                )}
                <span
                  className={`relative inline-flex rounded-full h-2 w-2 ${
                    isLiveConnected ? 'bg-cyan-400' : 'bg-slate-500'
                  }`}
                />
              </span>
              <span className="hidden sm:inline">
                {isLiveConnected ? 'Live Azure Connected' : 'Live Sync'}
              </span>
              <span className="sm:hidden">Live</span>
            </button>

            {/* Environment Preset Selector */}
            <div className="relative hidden lg:block">
              <select
                value={
                  activeDataset.presetName.includes('Breach')
                    ? 'high_risk'
                    : 'hardened'
                }
                onChange={(e) => onSelectDataset(e.target.value)}
                className="bg-slate-800/90 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 pr-7 focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer appearance-none"
              >
                <option value="high_risk">Preset: High Risk (Loopholes Active)</option>
                <option value="hardened">Preset: CIS Hardened Baseline</option>
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2 top-2.5 pointer-events-none" />
            </div>

            {/* Continuous Cloud Watch Monitor Toggle */}
            <button
              onClick={onToggleContinuousMonitoring}
              title={
                isContinuousMonitoring
                  ? 'Continuous Cloud Watch is ACTIVE (Simulating live telemetry)'
                  : 'Continuous Cloud Watch is PAUSED'
              }
              className={`hidden sm:flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                isContinuousMonitoring
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  : 'bg-slate-800/60 border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Radio
                className={`w-3.5 h-3.5 ${
                  isContinuousMonitoring ? 'animate-pulse text-emerald-400' : ''
                }`}
              />
              <span className="hidden xl:inline">Continuous Watch</span>
            </button>

            {/* Simulate Injection Button */}
            <button
              onClick={onOpenSimulator}
              className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition-all shadow-sm"
              title="Inject a misconfiguration to test real-time alerts"
            >
              <Flame className="w-3.5 h-3.5 text-amber-400" />
              <span className="hidden sm:inline">Inject Misconfig</span>
            </button>

            {/* Real-time Alerts Bell */}
            <div className="relative">
              <button
                onClick={() => setShowAlertsDropdown(!showAlertsDropdown)}
                className="relative p-2 rounded-lg bg-slate-800/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-all focus:outline-none"
                aria-label={`Real-time Alerts (${unreadAlertCount} unread)`}
              >
                <Bell className="w-4 h-4" />
                {unreadAlertCount > 0 && (
                  <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white animate-pulse">
                    {unreadAlertCount}
                  </span>
                )}
              </button>

              {/* Alerts Dropdown Modal */}
              {showAlertsDropdown && (
                <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-3 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                  <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
                    <div className="flex items-center space-x-1.5">
                      <Bell className="w-4 h-4 text-blue-400" />
                      <span className="text-xs font-semibold text-slate-200">
                        Real-Time Security Alerts ({alerts.length})
                      </span>
                    </div>
                    {alerts.length > 0 && (
                      <button
                        onClick={onMarkAllAlertsRead}
                        className="text-[11px] text-blue-400 hover:text-blue-300 transition-colors"
                      >
                        Mark all read
                      </button>
                    )}
                  </div>

                  <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
                    {alerts.length === 0 ? (
                      <div className="py-6 text-center text-slate-400 text-xs">
                        <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-1.5" />
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
                              ? 'bg-slate-950/40 border-slate-800/80 text-slate-400'
                              : 'bg-slate-800/80 border-slate-700 text-slate-200 shadow-sm'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${getSeverityBadge(
                                alert.severity
                              )}`}
                            >
                              {alert.severity}
                            </span>
                            <span className="text-[10px] text-slate-500">
                              {alert.timestamp}
                            </span>
                          </div>
                          <div className="font-semibold text-slate-100 line-clamp-1 mb-0.5">
                            {alert.title}
                          </div>
                          <p className="text-[11px] text-slate-400 line-clamp-2">
                            {alert.summary}
                          </p>
                          <div className="mt-1.5 text-[10px] text-blue-400 flex items-center justify-between font-mono">
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
              onClick={onOpenPdfPreview}
              className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-all"
              title="Preview PDF Report with Visual Aids"
              aria-label="Preview PDF Report"
            >
              <Eye className="w-4 h-4" />
            </button>

            {/* Export PDF Button */}
            <button
              onClick={onDownloadPdf}
              className="flex items-center space-x-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-md shadow-blue-600/20 transition-all active:scale-95 flex-shrink-0"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Export PDF Report</span>
              <span className="sm:hidden">PDF</span>
            </button>
          </div>
        </div>

        {/* Mobile Navigation Tabs */}
        <div className="flex md:hidden items-center justify-around py-2 border-t border-slate-800/80 overflow-x-auto text-[11px]">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
              activeTab === 'overview'
                ? 'bg-blue-600 text-white font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('storage')}
            className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
              activeTab === 'storage'
                ? 'bg-blue-600 text-white font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Storage
          </button>
          <button
            onClick={() => setActiveTab('rbac')}
            className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
              activeTab === 'rbac'
                ? 'bg-blue-600 text-white font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            RBAC
          </button>
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
              activeTab === 'findings'
                ? 'bg-blue-600 text-white font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Remediation
          </button>
        </div>
      </div>
    </header>
  );
};
