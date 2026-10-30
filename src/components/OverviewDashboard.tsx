/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  ShieldAlert,
  Lock,
  Unlock,
  Users,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Database,
  KeyRound,
  TrendingDown,
  TrendingUp,
  Sparkles,
  Wrench,
  Info,
  HelpCircle,
} from 'lucide-react';
import {
  ActiveTab,
  AuditMetrics,
  Finding,
  RemediationLogEntry,
  StorageAccount,
} from '../types/security';
import { DashboardWidget } from './DashboardWidget';
import { TimeSeriesWidget } from './TimeSeriesWidget';

interface OverviewDashboardProps {
  metrics: AuditMetrics;
  findings: Finding[];
  storageAccounts: StorageAccount[];
  remediationLogs?: RemediationLogEntry[];
  isDemoData?: boolean;
  collectionSource?: string;
  lastCollectedAt?: string;
  onSelectTab: (tab: ActiveTab) => void;
  onSelectFinding: (finding: Finding) => void;
  onHardenAll: () => void;
  onHardenAccount?: (accountId: string) => void;
  onOpenGovernance?: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  metrics,
  findings,
  storageAccounts,
  remediationLogs = [],
  isDemoData = true,
  collectionSource = 'Demo Sample Dataset',
  lastCollectedAt = 'Sample Dataset',
  onSelectTab,
  onSelectFinding,
  onHardenAll,
  onHardenAccount,
  onOpenGovernance,
}) => {
  const topCriticalFindings = findings
    .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 5);

  const cisChecks = metrics.frameworkChecks?.cisAzure || {
    passed: 0,
    failed: 0,
    unknown: 7,
    totalSelected: 7,
    passRate: 0,
  };
  const mcsbChecks = metrics.frameworkChecks?.mcsb || {
    passed: 0,
    failed: 0,
    unknown: 6,
    totalSelected: 6,
    passRate: 0,
  };
  const nistChecks = metrics.frameworkChecks?.nist || {
    passed: 0,
    failed: 0,
    unknown: 5,
    totalSelected: 5,
    passRate: 0,
  };

  return (
    <div className="space-y-6">
      {/* Top Executive Banner */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Posture Score Card — Postrix Dark Navy Hero Card */}
        <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-[#081420] text-[#F3F5F1] p-6 flex flex-col justify-between relative overflow-hidden shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-[#5FD3BF] font-bold">
                SELECTED-CONTROL POSTURE SCORE
              </span>
              <h2 className="font-serif text-lg font-bold text-white mt-0.5">
                {metrics.isEvaluationComplete === false
                  ? 'Evaluation Incomplete (0 Resources)'
                  : metrics.postureScore >= 80
                  ? 'Selected Checks Passing'
                  : metrics.postureScore >= 55
                  ? 'Elevated Exposure Detected'
                  : 'High-Priority Loopholes Present'}
              </h2>
            </div>

            <div
              className={`w-12 h-12 rounded-xl flex items-center justify-center font-serif font-bold text-2xl border ${
                metrics.isEvaluationComplete === false
                  ? 'bg-white/10 border-white/20 text-[#B7C3CC]'
                  : metrics.riskGrade === 'A'
                  ? 'bg-[#2BB5A0]/20 border-[#2BB5A0]/40 text-[#5FD3BF]'
                  : metrics.riskGrade === 'B' || metrics.riskGrade === 'C'
                  ? 'bg-[#D79A45]/20 border-[#D79A45]/40 text-[#EBC385]'
                  : 'bg-red-500/20 border-red-500/40 text-red-400'
              }`}
            >
              {metrics.isEvaluationComplete === false ? '?' : metrics.riskGrade}
            </div>
          </div>

          <div className="my-6 flex items-baseline space-x-3">
            <span className="font-serif text-5xl font-bold tracking-tight text-white">
              {metrics.isEvaluationComplete === false
                ? 'Unknown'
                : metrics.postureScore}
            </span>
            {metrics.isEvaluationComplete !== false && (
              <span className="text-sm text-[#B7C3CC] font-mono">/ 100 pts</span>
            )}
            <span
              className={`ml-auto text-xs font-mono flex items-center px-2 py-0.5 rounded ${
                metrics.isEvaluationComplete === false
                  ? 'bg-white/10 text-[#B7C3CC]'
                  : metrics.postureScore >= 80
                  ? 'bg-[#2BB5A0]/20 text-[#5FD3BF]'
                  : 'bg-red-500/20 text-red-300'
              }`}
            >
              {metrics.isEvaluationComplete === false ? (
                <>
                  <HelpCircle className="w-3.5 h-3.5 mr-1" />
                  18 Checks Unknown
                </>
              ) : metrics.postureScore >= 80 ? (
                <>
                  <TrendingUp className="w-3.5 h-3.5 mr-1" />
                  Low Risk Profile
                </>
              ) : (
                <>
                  <TrendingDown className="w-3.5 h-3.5 mr-1" />
                  Remediation Advised
                </>
              )}
            </span>
          </div>

          <div className="space-y-3">
            <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  metrics.postureScore >= 80
                    ? 'bg-[#2BB5A0]'
                    : metrics.postureScore >= 50
                    ? 'bg-[#D79A45]'
                    : 'bg-red-500'
                }`}
                style={{ width: `${metrics.postureScore}%` }}
              />
            </div>

            <div className="flex items-center justify-between text-xs text-[#B7C3CC] pt-1">
              <span>
                {metrics.criticalCount} Critical · {metrics.highCount} High ·{' '}
                {metrics.mediumCount} Medium
              </span>
              {findings.length > 0 && (
                <button
                  onClick={onHardenAll}
                  className="xh-btn primary text-[11px] py-1 px-2.5"
                  title="Simulates hardening in browser memory without modifying live Azure resources"
                >
                  <Sparkles className="w-3 h-3" />
                  <span>Simulate Hardening (In-Memory)</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Selected-Check Framework Cross-Reference & Metric Tiles (Rec #3, #9, #10) */}
        <div className="lg:col-span-8 grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Selected-Control Pass/Fail/Unknown Breakdown Card */}
          <div className="sm:col-span-3 rounded-xl border border-slate-200/90 bg-white p-5 shadow-xs">
            <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
              <div>
                <span className="rm-kicker">
                  INFORMATIONAL CONTROL CROSS-REFERENCE
                </span>
                <h3 className="font-serif text-sm font-bold text-[#16232F]">
                  Selected Heuristic Checks: Passed / Failed / Unknown (18 Rules)
                </h3>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-[11px] text-[#546471] font-mono">
                  Not a formal compliance certification
                </span>
                {onOpenGovernance && (
                  <button
                    onClick={onOpenGovernance}
                    className="text-[11px] font-semibold text-[#1F8A79] hover:underline flex items-center space-x-1"
                  >
                    <Info className="w-3.5 h-3.5" />
                    <span>Scope &amp; Formula</span>
                  </button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {/* CIS Azure Subset */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200/80 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#546471] font-medium">
                    CIS Azure v2.0 (7 Checks)
                  </span>
                  <span className="font-mono font-bold text-[#16232F]">
                    {cisChecks.unknown > 0 ? 'Incomplete' : `${cisChecks.passRate}% Pass`}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="text-[#1F8A79] font-bold">{cisChecks.passed} Passed</span>
                  <span className="text-red-600 font-bold">{cisChecks.failed} Failed</span>
                  <span className="text-slate-500 font-bold">{cisChecks.unknown} Unknown</span>
                </div>
                <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-[#2BB5A0] h-full"
                    style={{ width: `${cisChecks.passRate}%` }}
                  />
                </div>
              </div>

              {/* MCSB Subset */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200/80 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#546471] font-medium">
                    MCSB v1.0 (6 Checks)
                  </span>
                  <span className="font-mono font-bold text-[#16232F]">
                    {mcsbChecks.unknown > 0 ? 'Incomplete' : `${mcsbChecks.passRate}% Pass`}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="text-[#1F8A79] font-bold">{mcsbChecks.passed} Passed</span>
                  <span className="text-red-600 font-bold">{mcsbChecks.failed} Failed</span>
                  <span className="text-slate-500 font-bold">{mcsbChecks.unknown} Unknown</span>
                </div>
                <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-[#0E2238] h-full"
                    style={{ width: `${mcsbChecks.passRate}%` }}
                  />
                </div>
              </div>

              {/* NIST SP 800-53 Subset */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200/80 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#546471] font-medium">
                    NIST 800-53 (5 Checks)
                  </span>
                  <span className="font-mono font-bold text-[#16232F]">
                    {nistChecks.unknown > 0 ? 'Incomplete' : `${nistChecks.passRate}% Pass`}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="text-[#1F8A79] font-bold">{nistChecks.passed} Passed</span>
                  <span className="text-red-600 font-bold">{nistChecks.failed} Failed</span>
                  <span className="text-slate-500 font-bold">{nistChecks.unknown} Unknown</span>
                </div>
                <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-[#D79A45] h-full"
                    style={{ width: `${nistChecks.passRate}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* 3 Loophole Domain KPI Cards (Rec #10: distinguish Confirmed Exposure from Guardrail Gap) */}
          <button
            onClick={() => onSelectTab('storage')}
            className="text-left p-4 rounded-xl border border-slate-200/90 bg-white hover:border-[#2BB5A0] transition-all group shadow-xs"
          >
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-red-50 text-red-600 border border-red-200">
                <Unlock className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-[#1F8A79] group-hover:translate-x-0.5 transition-all" />
            </div>
            <div className="mt-3">
              <div className="font-serif text-2xl font-bold text-[#16232F]">
                {metrics.exposedContainerCount}{' '}
                <span className="text-xs font-normal text-[#546471]">
                  Confirmed Public
                </span>
              </div>
              <div className="text-xs text-[#546471] mt-0.5">
                Anonymous Containers ({metrics.guardrailGapAccountCount || 0} Guardrail Gap Account{metrics.guardrailGapAccountCount === 1 ? '' : 's'})
              </div>
            </div>
          </button>

          <button
            onClick={() => onSelectTab('rbac')}
            className="text-left p-4 rounded-xl border border-slate-200/90 bg-white hover:border-[#2BB5A0] transition-all group shadow-xs"
          >
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-amber-50 text-amber-700 border border-amber-200">
                <KeyRound className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-[#1F8A79] group-hover:translate-x-0.5 transition-all" />
            </div>
            <div className="mt-3">
              <div className="font-serif text-2xl font-bold text-[#16232F]">
                {metrics.privilegeEscalationCount}
              </div>
              <div className="text-xs text-[#546471] mt-0.5">
                Privilege Escalation &amp; Wildcard Roles
              </div>
            </div>
          </button>

          <button
            onClick={() => onSelectTab('rbac')}
            className="text-left p-4 rounded-xl border border-slate-200/90 bg-white hover:border-[#2BB5A0] transition-all group shadow-xs"
          >
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-teal-50 text-[#1F8A79] border border-teal-200">
                <Users className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-[#1F8A79] group-hover:translate-x-0.5 transition-all" />
            </div>
            <div className="mt-3">
              <div className="font-serif text-2xl font-bold text-[#16232F]">
                {metrics.externalGuestRiskCount}
              </div>
              <div className="text-xs text-[#546471] mt-0.5">
                External B2B Guests with High Privilege
              </div>
            </div>
          </button>
        </div>
      </div>

      {/* Analytics Row: 30-Day Historical Posture TimeSeriesWidget + Comparative Compliance Radar Widget */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7">
          <TimeSeriesWidget
            metrics={metrics}
            remediationLogs={remediationLogs}
            isDemoData={isDemoData}
            collectionSource={collectionSource}
            lastCollectedAt={lastCollectedAt}
          />
        </div>

        {/* Comparative Compliance Status Radar Widget (CIS, MCSB, NIST) */}
        <div className="lg:col-span-5">
          <DashboardWidget
            metrics={metrics}
            onOpenGovernance={onOpenGovernance}
          />
        </div>
      </div>

      {/* Middle Section: Storage Exposure Matrix + Critical Attack Paths */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Storage Account Security Matrix */}
        <div className="lg:col-span-7 rounded-xl border border-slate-200/90 bg-white p-5 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <span className="rm-kicker">STORAGE CONFIGURATION MATRIX</span>
                <div className="flex items-center space-x-2 mt-0.5">
                  <Database className="w-4 h-4 text-[#1F8A79]" />
                  <h3 className="font-serif text-base font-bold text-[#16232F]">
                    Storage Account Guardrails &amp; Default Encryption Status
                  </h3>
                </div>
              </div>
              <button
                onClick={() => onSelectTab('storage')}
                className="text-xs text-[#1F8A79] hover:text-[#15695B] font-semibold flex items-center space-x-1"
              >
                <span>Deep Inspect</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 text-[11px] font-mono uppercase text-[#546471]">
                    <th className="py-2.5 pr-3">Storage Account</th>
                    <th className="py-2.5 px-2 text-center">Anonymous Access</th>
                    <th className="py-2.5 px-2 text-center">Shared Key</th>
                    <th className="py-2.5 px-2 text-center">Firewall</th>
                    <th className="py-2.5 px-2 text-center">At-Rest Encryption</th>
                    <th className="py-2.5 pl-2 text-right">Simulate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-xs">
                  {storageAccounts.map((acc) => {
                    const openContainers = acc.containers.filter(
                      (c) => c.publicAccess !== 'None'
                    ).length;

                    const isHardened =
                      !acc.allowBlobPublicAccess &&
                      !acc.allowSharedKeyAccess &&
                      acc.defaultAction === 'Deny' &&
                      acc.minimumTlsVersion === 'TLS1_2';

                    return (
                      <tr
                        key={acc.id}
                        className="hover:bg-slate-50 transition-colors"
                      >
                        <td className="py-3 pr-3">
                          <div className="font-mono font-semibold text-[#16232F]">
                            {acc.name}
                          </div>
                          <div className="text-[11px] text-[#546471]">
                            {acc.resourceGroup} · {acc.location}
                          </div>
                        </td>

                        {/* Anonymous Access Status (Rec #10: Guardrail Gap vs Confirmed Exposure) */}
                        <td className="py-3 px-2 text-center">
                          {acc.allowBlobPublicAccess && openContainers > 0 ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-red-50 text-red-700 border border-red-200">
                              {openContainers} Public Container{openContainers > 1 ? 's' : ''}
                            </span>
                          ) : acc.allowBlobPublicAccess ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-amber-50 text-amber-800 border border-amber-200">
                              Guardrail On (0 Public)
                            </span>
                          ) : (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-50 text-[#1F8A79] border border-emerald-200">
                              Blocked
                            </span>
                          )}
                        </td>

                        {/* Shared Key Access */}
                        <td className="py-3 px-2 text-center">
                          {acc.allowSharedKeyAccess ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-amber-50 text-amber-800 border border-amber-200">
                              Enabled
                            </span>
                          ) : (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-50 text-[#1F8A79] border border-emerald-200">
                              Disabled (Entra)
                            </span>
                          )}
                        </td>

                        {/* Network Default Action */}
                        <td className="py-3 px-2 text-center">
                          {acc.defaultAction === 'Allow' ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-red-50 text-red-700 border border-red-200">
                              0.0.0.0/0 Allow
                            </span>
                          ) : (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-50 text-[#1F8A79] border border-emerald-200">
                              Deny + VNet
                            </span>
                          )}
                        </td>

                        {/* Default At-Rest Encryption vs CMK (Rec #11) */}
                        <td className="py-3 px-2 text-center font-mono">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                              acc.encryptionKeySource === 'Microsoft.Keyvault'
                                ? 'bg-emerald-50 text-[#1F8A79] border border-emerald-200'
                                : 'bg-slate-100 text-[#16232F] border border-slate-300'
                            }`}
                            title="Azure Storage encrypts all data at rest by default using 256-bit AES Microsoft-Managed Keys (MMK)"
                          >
                            {acc.encryptionKeySource === 'Microsoft.Keyvault'
                              ? 'Encrypted (CMK)'
                              : 'Encrypted (Default MMK)'}
                          </span>
                        </td>

                        {/* Simulate Hardening Button (Rec #6) */}
                        <td className="py-3 pl-2 text-right">
                          {isHardened ? (
                            <span className="inline-flex items-center space-x-1 text-[11px] text-[#1F8A79] font-mono font-semibold">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Hardened</span>
                            </span>
                          ) : (
                            onHardenAccount && (
                              <button
                                onClick={() => onHardenAccount(acc.id)}
                                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-[#0E2238] hover:bg-[#15314E] text-white text-[11px] font-semibold transition-all"
                                title="Simulates hardening in UI memory only"
                              >
                                <Wrench className="w-3 h-3" />
                                <span>Simulate</span>
                              </button>
                            )
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-xs text-[#546471]">
            <span>
              <strong>Note:</strong> Azure encrypts all Storage accounts at rest by default (256-bit AES MMK). Account-level <code>allowBlobPublicAccess=true</code> with 0 public containers is a guardrail gap, not active public exposure.
            </span>
          </div>
        </div>

        {/* Right: Top Priority Loopholes & Attack Vectors */}
        <div className="lg:col-span-5 rounded-xl border border-slate-200/90 bg-white p-5 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <span className="rm-kicker">HIGHEST PRIORITY FINDINGS</span>
                <div className="flex items-center space-x-2 mt-0.5">
                  <ShieldAlert className="w-4 h-4 text-red-600" />
                  <h3 className="font-serif text-base font-bold text-[#16232F]">
                    Priority Loopholes to Remediate
                  </h3>
                </div>
              </div>
              <button
                onClick={() => onSelectTab('findings')}
                className="text-xs text-[#1F8A79] hover:text-[#15695B] font-semibold flex items-center space-x-1"
              >
                <span>View All ({findings.length})</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {topCriticalFindings.length === 0 ? (
              <div className="p-8 text-center space-y-2">
                <CheckCircle2 className="w-10 h-10 text-[#1F8A79] mx-auto" />
                <div className="text-sm font-serif font-bold text-[#16232F]">
                  {metrics.isEvaluationComplete === false
                    ? '0 Resources Evaluated (Unknown Scope)'
                    : 'Zero Critical or High Loopholes!'}
                </div>
                <p className="text-xs text-[#546471]">
                  {metrics.isEvaluationComplete === false
                    ? 'Authenticate with a valid Azure ARM Bearer Access Token and Reader scope to evaluate resources.'
                    : 'All evaluated Storage Accounts and RBAC role scopes pass selected critical checks.'}
                </p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {topCriticalFindings.map((finding) => (
                  <div
                    key={finding.id}
                    onClick={() => onSelectFinding(finding)}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50/70 hover:bg-white hover:border-[#2BB5A0] transition-all cursor-pointer group"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                            finding.severity === 'CRITICAL'
                              ? 'bg-red-100 text-red-700 border border-red-200'
                              : 'bg-orange-100 text-orange-800 border border-orange-200'
                          }`}
                        >
                          {finding.severity}
                        </span>
                        <span className="text-xs font-semibold text-[#16232F] group-hover:text-[#1F8A79] transition-colors line-clamp-1">
                          {finding.title}
                        </span>
                      </div>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[11px] text-[#546471]">
                      <span className="font-mono truncate max-w-[220px]">
                        Target: {finding.resourceName}
                      </span>
                      <span className="text-[#1F8A79] font-semibold group-hover:underline flex-shrink-0">
                        Fix Runbook →
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-xs text-[#546471]">
            <div className="flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
              <span>Click any finding for Pre-Check, CLI &amp; Rollback runbooks</span>
            </div>
            <Lock className="w-3.5 h-3.5 text-slate-400" />
          </div>
        </div>
      </div>
    </div>
  );
};
