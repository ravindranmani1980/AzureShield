/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  AlertTriangle,
  Info,
  Server,
  Users,
  Unlock,
  KeyRound,
  FileCheck2,
  ArrowUpRight,
  TrendingDown,
  Sparkles,
} from 'lucide-react';
import { AuditMetrics, Finding } from '../types/security';

interface OverviewDashboardProps {
  metrics: AuditMetrics;
  findings: Finding[];
  onNavigateTab: (tab: 'storage' | 'rbac' | 'findings') => void;
  onFilterCategory?: (category: string) => void;
  onSelectFinding: (findingId: string) => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  metrics,
  findings,
  onNavigateTab,
  onFilterCategory,
  onSelectFinding,
}) => {
  // Posture Score color
  const getScoreColor = (score: number) => {
    if (score >= 85) return 'text-emerald-400 stroke-emerald-500';
    if (score >= 70) return 'text-amber-400 stroke-amber-500';
    return 'text-red-400 stroke-red-500';
  };

  const getRiskGradeBg = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
      case 'B':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'C':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default:
        return 'bg-red-500/20 text-red-400 border-red-500/30';
    }
  };

  const categoryBreakdown = [
    {
      name: 'Storage Accounts & Blobs',
      count: findings.filter((f) => f.category === 'storage').length,
      icon: Server,
      color: 'from-blue-600 to-cyan-500',
      tab: 'storage' as const,
    },
    {
      name: 'RBAC & Overprivileged Roles',
      count: findings.filter((f) => f.category === 'rbac').length,
      icon: Users,
      color: 'from-purple-600 to-indigo-500',
      tab: 'rbac' as const,
    },
    {
      name: 'Privilege Escalation Risks',
      count: findings.filter((f) => f.category === 'privilege_escalation').length,
      icon: Unlock,
      color: 'from-rose-600 to-red-500',
      tab: 'rbac' as const,
    },
    {
      name: 'Network Perimeter & Firewalls',
      count: findings.filter((f) => f.category === 'network').length,
      icon: ShieldAlert,
      color: 'from-amber-600 to-orange-500',
      tab: 'storage' as const,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner / Summary */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 p-6 border border-slate-700/80 shadow-xl">
        <div className="absolute top-0 right-0 -mt-10 -mr-10 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30 flex items-center space-x-1">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Continuous Cloud Posture Audit</span>
              </span>
              <span className="text-xs text-slate-400">
                • {metrics.totalResources} Azure Assets Evaluated
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Storage Loopholes & RBAC Vulnerability Posture
            </h1>
            <p className="text-sm text-slate-300 max-w-2xl mt-1 leading-relaxed">
              Auditing Azure Storage Accounts for anonymous blob exposure, insecure HTTP transport, deprecated TLS versions, and analyzing Azure Entra ID / RBAC assignments for privilege escalation and excessive credentials.
            </p>
          </div>

          {/* Quick Metrics Badges */}
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={() => onNavigateTab('storage')}
              className="flex items-center space-x-3 px-4 py-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-700/80 transition-all text-left group"
            >
              <div className="p-2.5 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30">
                <Server className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs text-slate-400">Exposed Containers</div>
                <div className="text-lg font-bold text-white group-hover:text-blue-400 transition-colors flex items-center space-x-1">
                  <span>{metrics.exposedContainerCount || metrics.openBucketCount} Containers</span>
                  <ArrowUpRight className="w-4 h-4 opacity-50 group-hover:opacity-100" />
                </div>
              </div>
            </button>

            <button
              onClick={() => onNavigateTab('rbac')}
              className="flex items-center space-x-3 px-4 py-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-700/80 transition-all text-left group"
            >
              <div className="p-2.5 rounded-lg bg-purple-500/20 text-purple-400 border border-purple-500/30">
                <Unlock className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs text-slate-400">Escalation Risks</div>
                <div className="text-lg font-bold text-white group-hover:text-purple-400 transition-colors flex items-center space-x-1">
                  <span>{metrics.privilegeEscalationCount} Paths</span>
                  <ArrowUpRight className="w-4 h-4 opacity-50 group-hover:opacity-100" />
                </div>
              </div>
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Posture Meter & Severity Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Posture Meter Card */}
        <div className="lg:col-span-4 bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-slate-100 text-sm tracking-wide">
              SECURITY POSTURE SCORE
            </h3>
            <span
              className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${getRiskGradeBg(
                metrics.riskGrade
              )}`}
            >
              Grade {metrics.riskGrade}
            </span>
          </div>

          {/* Circular Score Visual */}
          <div className="flex flex-col items-center justify-center my-4">
            <div className="relative w-40 h-40 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                {/* Background Track */}
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  className="stroke-slate-800 fill-none"
                  strokeWidth="8"
                />
                {/* Animated Value Arc */}
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  className={`fill-none transition-all duration-1000 ease-out ${getScoreColor(
                    metrics.postureScore
                  )}`}
                  strokeWidth="8"
                  strokeDasharray={264}
                  strokeDashoffset={264 - (264 * metrics.postureScore) / 100}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="text-4xl font-extrabold text-white tracking-tighter">
                  {metrics.postureScore}
                </span>
                <span className="text-[11px] text-slate-400 font-medium">
                  OUT OF 100
                </span>
              </div>
            </div>

            <p className="text-xs text-center text-slate-400 mt-3 max-w-xs">
              {metrics.postureScore >= 80
                ? 'Healthy posture. Low attack surface on storage and role privileges.'
                : metrics.postureScore >= 60
                ? 'Moderate posture risk. Address high-priority storage & RBAC issues.'
                : 'CRITICAL EXPOSURE. Public storage containers or excessive RBAC roles require immediate remediation.'}
            </p>
          </div>

          {/* Quick Metrics Footer */}
          <div className="pt-4 border-t border-slate-800 grid grid-cols-2 gap-3 text-center">
            <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80">
              <div className="text-xs text-slate-400">Total Loopholes</div>
              <div className="text-xl font-bold text-white">
                {metrics.totalFindings}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80">
              <div className="text-xs text-slate-400">Dormant Accounts</div>
              <div className="text-xl font-bold text-amber-400">
                {metrics.inactiveRoleCount}
              </div>
            </div>
          </div>
        </div>

        {/* Severity Matrix & Visual Analytics */}
        <div className="lg:col-span-8 space-y-6">
          {/* Severity Counters Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-2xl bg-red-950/30 border border-red-500/30 hover:border-red-500/50 cursor-pointer transition-all shadow-sm group"
            >
              <div className="flex items-center justify-between text-red-400 mb-1">
                <span className="text-xs font-bold tracking-wider uppercase">
                  Critical
                </span>
                <AlertOctagon className="w-4 h-4" />
              </div>
              <div className="text-2xl font-black text-white group-hover:text-red-400 transition-colors">
                {metrics.criticalCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Zero-barrier exploits
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-2xl bg-orange-950/30 border border-orange-500/30 hover:border-orange-500/50 cursor-pointer transition-all shadow-sm group"
            >
              <div className="flex items-center justify-between text-orange-400 mb-1">
                <span className="text-xs font-bold tracking-wider uppercase">
                  High
                </span>
                <AlertTriangle className="w-4 h-4" />
              </div>
              <div className="text-2xl font-black text-white group-hover:text-orange-400 transition-colors">
                {metrics.highCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Perimeter & token risks
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-2xl bg-amber-950/30 border border-amber-500/30 hover:border-amber-500/50 cursor-pointer transition-all shadow-sm group"
            >
              <div className="flex items-center justify-between text-amber-400 mb-1">
                <span className="text-xs font-bold tracking-wider uppercase">
                  Medium
                </span>
                <Info className="w-4 h-4" />
              </div>
              <div className="text-2xl font-black text-white group-hover:text-amber-400 transition-colors">
                {metrics.mediumCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Governance & logging gaps
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-2xl bg-blue-950/30 border border-blue-500/30 hover:border-blue-500/50 cursor-pointer transition-all shadow-sm group"
            >
              <div className="flex items-center justify-between text-blue-400 mb-1">
                <span className="text-xs font-bold tracking-wider uppercase">
                  Low
                </span>
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div className="text-2xl font-black text-white group-hover:text-blue-400 transition-colors">
                {metrics.lowCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Hardening recommendations
              </div>
            </div>
          </div>

          {/* Visual Aids: Frequency by Category */}
          <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-lg">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-slate-100 text-sm tracking-wide">
                MISCONFIGURATION FREQUENCY BY DOMAIN
              </h3>
              <span className="text-xs text-slate-400">
                Visual Analytics (Included in PDF)
              </span>
            </div>

            <div className="space-y-3.5">
              {categoryBreakdown.map((item) => {
                const max = Math.max(1, metrics.totalFindings);
                const percent = Math.round((item.count / max) * 100);
                const Icon = item.icon;

                return (
                  <div
                    key={item.name}
                    onClick={() => onNavigateTab(item.tab)}
                    className="group cursor-pointer"
                  >
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <div className="flex items-center space-x-2 text-slate-300 group-hover:text-white font-medium transition-colors">
                        <Icon className="w-4 h-4 text-slate-400 group-hover:text-blue-400 transition-colors" />
                        <span>{item.name}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-slate-400">
                          {item.count} issues
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-bold">
                          {percent}%
                        </span>
                      </div>
                    </div>
                    {/* Track */}
                    <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800/80">
                      <div
                        className={`h-full bg-gradient-to-r ${item.color} rounded-full transition-all duration-700`}
                        style={{ width: `${Math.max(4, percent)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Framework Scorecards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-400 tracking-wider uppercase">
              CIS Azure Foundations 2.0
            </span>
            <FileCheck2 className="w-4 h-4 text-blue-400" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-black text-white">
              {metrics.complianceScores.cisAzure}%
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Passing benchmark controls
            </div>
          </div>
          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full ${
                metrics.complianceScores.cisAzure >= 80
                  ? 'bg-emerald-500'
                  : 'bg-amber-500'
              }`}
              style={{ width: `${metrics.complianceScores.cisAzure}%` }}
            />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-400 tracking-wider uppercase">
              Microsoft Cloud Security (MCSB)
            </span>
            <FileCheck2 className="w-4 h-4 text-purple-400" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-black text-white">
              {metrics.complianceScores.mcsb}%
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Data protection & identity baseline
            </div>
          </div>
          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full ${
                metrics.complianceScores.mcsb >= 80
                  ? 'bg-emerald-500'
                  : 'bg-amber-500'
              }`}
              style={{ width: `${metrics.complianceScores.mcsb}%` }}
            />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-400 tracking-wider uppercase">
              NIST SP 800-53 Rev. 5
            </span>
            <FileCheck2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-black text-white">
              {metrics.complianceScores.nist}%
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Access control (AC) & encryption (SC)
            </div>
          </div>
          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full ${
                metrics.complianceScores.nist >= 80
                  ? 'bg-emerald-500'
                  : 'bg-amber-500'
              }`}
              style={{ width: `${metrics.complianceScores.nist}%` }}
            />
          </div>
        </div>
      </div>

      {/* Critical Action Items List */}
      <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="font-bold text-slate-100 text-sm tracking-wide">
              IMMEDIATE ACTION ITEMS (CRITICAL SEVERITY)
            </h3>
            <p className="text-xs text-slate-400">
              High-exploitability vulnerabilities that should be patched first
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('findings')}
            className="text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center space-x-1"
          >
            <span>View All ({findings.length})</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="space-y-3">
          {findings
            .filter((f) => f.severity === 'CRITICAL')
            .slice(0, 4)
            .map((finding) => (
              <div
                key={finding.id}
                onClick={() => onSelectFinding(finding.id)}
                className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-red-500/40 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
              >
                <div className="flex items-start space-x-3">
                  <div className="p-2 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30 flex-shrink-0 mt-0.5">
                    <AlertOctagon className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-white group-hover:text-red-300 transition-colors">
                        {finding.title}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                        {finding.category.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">
                      {finding.description}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3 self-end sm:self-center flex-shrink-0">
                  <span className="text-xs font-mono text-slate-400">
                    {finding.resourceName}
                  </span>
                  <button className="px-3 py-1 rounded-lg text-xs font-semibold bg-red-600/20 text-red-300 border border-red-500/30 group-hover:bg-red-600 group-hover:text-white transition-all">
                    Remediate
                  </button>
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
};
