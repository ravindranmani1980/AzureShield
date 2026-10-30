/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  UserX,
  Terminal,
  ChevronRight,
  UserCheck,
  Bot,
  Copy,
  Check,
  Flame,
  ArrowRight,
  Wrench,
} from 'lucide-react';
import { RbacAssignment, Finding } from '../types/security';

interface RbacAuditorProps {
  roleAssignments: RbacAssignment[];
  findings?: Finding[];
  onSelectFinding?: (finding: Finding) => void;
  onRevokeAssignment?: (assignmentId: string) => void;
}

export const RbacAuditor: React.FC<RbacAuditorProps> = ({
  roleAssignments = [],
  findings = [],
  onSelectFinding,
  onRevokeAssignment,
}) => {
  const [filterMode, setFilterMode] = useState<
    'all' | 'overprivileged' | 'escalation' | 'dormant' | 'guest'
  >('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const rbacFindings = findings.filter(
    (f) => f.category === 'rbac' || f.category === 'privilege_escalation'
  );

  const privilegeEscalationFindings = findings.filter(
    (f) => f.category === 'privilege_escalation'
  );

  const dormantCount = roleAssignments.filter((r) => r.lastActiveDays > 90).length;
  const guestCount = roleAssignments.filter((r) => r.isExternalGuest).length;
  const overprivilegedCount = roleAssignments.filter(
    (r) =>
      r.roleDefinitionName === 'Owner' ||
      r.isExternalGuest ||
      (r.actions ?? []).includes('*')
  ).length;

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredAssignments = roleAssignments.filter((assignment) => {
    const actionsList = assignment.actions ?? [];
    const matchesSearch =
      assignment.principalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      assignment.roleDefinitionName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      assignment.scope.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;

    if (filterMode === 'overprivileged') {
      return (
        assignment.roleDefinitionName === 'Owner' ||
        assignment.isExternalGuest ||
        actionsList.includes('*')
      );
    }
    if (filterMode === 'escalation') {
      return actionsList.some(
        (a) =>
          a.includes('roleAssignments/write') ||
          a === 'Microsoft.Authorization/*' ||
          a === '*'
      );
    }
    if (filterMode === 'dormant') {
      return assignment.lastActiveDays > 90;
    }
    if (filterMode === 'guest') {
      return assignment.isExternalGuest;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header (.xh-panel) */}
      <section className="xh-panel space-y-5">
        <div className="xh-kicker">
          <span className="k">Identity &amp; Access Management · RBAC Auditor</span>
          <span className="tag">{roleAssignments.length} Role Assignments Audited</span>
        </div>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl sm:text-2xl font-semibold text-[#EEF3F1] tracking-tight">
              Maniq Shield — Role-Based Access Control (RBAC) &amp; IAM Analyzer
            </h2>
            <p className="text-xs text-[#A9B7BF] mt-1 max-w-3xl leading-relaxed">
              Auditing Azure Active Directory / Entra ID role assignments for excessive privileges, dormant accounts, external guest access, and privilege escalation attack vectors.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
          <div className="xh-metric">
            <div className="lbl">
              <span>TOTAL ASSIGNMENTS</span>
            </div>
            <div className="num tabular-nums">{roleAssignments.length}</div>
            <p>Evaluated across subscription &amp; resource group scopes</p>
          </div>
          <div className="xh-metric">
            <div className="lbl">
              <span>ESCALATION RISKS</span>
            </div>
            <div className="num hi tabular-nums">{privilegeEscalationFindings.length}</div>
            <p>Identities with roleAssignments/write or wildcard authority</p>
          </div>
          <div className="xh-metric">
            <div className="lbl">
              <span>DORMANT (&gt;90 DAYS)</span>
            </div>
            <div className="num tabular-nums">{dormantCount}</div>
            <p>{guestCount} external guest (#EXT#) principals active</p>
          </div>
        </div>
      </section>

      {/* Privilege Escalation Threat Vector Spotlight */}
      {privilegeEscalationFindings.length > 0 && (
        <div className="p-5 rounded-xl bg-white border border-red-300 shadow-xs">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 rounded-lg bg-red-600 text-white flex-shrink-0">
              <Flame className="w-5 h-5" />
            </div>
            <div className="flex-1">
              <div className="flex items-center space-x-2 mb-1">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200">
                  CRITICAL EXPLOIT CHAIN DETECTED
                </span>
                <span className="text-xs font-mono text-slate-500">
                  Potential Administrative Takeover Path
                </span>
              </div>
              <h3 className="text-base font-serif font-semibold text-slate-900">
                Unauthorized Privilege Escalation via &apos;roleAssignments/write&apos;
              </h3>
              <p className="text-xs text-slate-600 mt-1 max-w-3xl leading-relaxed">
                Non-Owner identities hold permission to create or modify Azure role assignments. Threat actors compromising these service accounts or custom operators can issue API calls to self-grant &apos;Owner&apos; or &apos;Storage Blob Data Owner&apos;, completely bypassing organizational access boundaries.
              </p>

              {/* Visual Attack Chain Graph */}
              <div className="mt-4 p-3.5 rounded-lg bg-slate-50 border border-slate-200 flex flex-col md:flex-row items-center gap-3 text-xs font-mono">
                <div className="px-3 py-1.5 rounded bg-white text-slate-800 border border-slate-300">
                  1. Compromise Operator / SP
                </div>
                <ArrowRight className="w-4 h-4 text-red-600 rotate-90 md:rotate-0" />
                <div className="px-3 py-1.5 rounded bg-red-50 text-red-800 border border-red-200">
                  2. Invoke roleAssignments/write
                </div>
                <ArrowRight className="w-4 h-4 text-red-600 rotate-90 md:rotate-0" />
                <div className="px-3 py-1.5 rounded bg-red-600 text-white font-bold">
                  3. Self-Promote to Subscription Owner
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Controls & Filter Bar */}
      <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 sm:pb-0">
          <button
            type="button"
            onClick={() => setFilterMode('all')}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer whitespace-nowrap ${
              filterMode === 'all'
                ? 'bg-[#0E2238] text-[#EEF3F1]'
                : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
            }`}
          >
            All Identities ({roleAssignments.length})
          </button>
          <button
            type="button"
            onClick={() => setFilterMode('escalation')}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer whitespace-nowrap ${
              filterMode === 'escalation'
                ? 'bg-red-600 text-white'
                : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
            }`}
          >
            Escalation Paths ({privilegeEscalationFindings.length})
          </button>
          <button
            type="button"
            onClick={() => setFilterMode('overprivileged')}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer whitespace-nowrap ${
              filterMode === 'overprivileged'
                ? 'bg-[#0E2238] text-[#EEF3F1]'
                : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
            }`}
          >
            Overprivileged ({overprivilegedCount})
          </button>
          <button
            type="button"
            onClick={() => setFilterMode('dormant')}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer whitespace-nowrap ${
              filterMode === 'dormant'
                ? 'bg-[#0E2238] text-[#EEF3F1]'
                : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
            }`}
          >
            Dormant &gt;90d ({dormantCount})
          </button>
          <button
            type="button"
            onClick={() => setFilterMode('guest')}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer whitespace-nowrap ${
              filterMode === 'guest'
                ? 'bg-[#0E2238] text-[#EEF3F1]'
                : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
            }`}
          >
            External Guests ({guestCount})
          </button>
        </div>

        <input
          type="text"
          placeholder="Search by identity or role..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="bg-slate-50 border border-slate-200 focus:border-[#0E2238] focus:bg-white text-slate-900 text-xs rounded-lg px-3 py-1.5 focus:outline-none w-full sm:w-64"
        />
      </div>

      {/* Role Assignments Grid / Cards */}
      <div className="grid grid-cols-1 gap-4">
        {filteredAssignments.map((assignment) => {
          const associatedFindings = findings.filter(
            (f) =>
              f.resourceName === assignment.principalName ||
              f.resourceId.includes(assignment.id)
          );
          const hasCritical = associatedFindings.some((f) => f.severity === 'CRITICAL');
          const isDormant = assignment.lastActiveDays > 90;

          return (
            <div
              key={assignment.id}
              className={`p-5 rounded-xl bg-white border transition-all shadow-xs ${
                hasCritical
                  ? 'border-red-300'
                  : associatedFindings.length > 0
                  ? 'border-amber-300'
                  : 'border-slate-200'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-200">
                <div className="flex items-start space-x-3.5">
                  <div
                    className={`p-2.5 rounded-lg flex-shrink-0 border ${
                      assignment.principalType === 'GuestUser'
                        ? 'bg-red-50 text-red-700 border-red-200'
                        : assignment.principalType === 'ServicePrincipal'
                        ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        : 'bg-slate-100 text-slate-800 border-slate-200'
                    }`}
                  >
                    {assignment.principalType === 'ServicePrincipal' ? (
                      <Bot className="w-5 h-5" />
                    ) : assignment.principalType === 'GuestUser' ? (
                      <UserX className="w-5 h-5" />
                    ) : (
                      <UserCheck className="w-5 h-5" />
                    )}
                  </div>

                  <div>
                    <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                      <span className="font-mono font-bold text-sm text-slate-900">
                        {assignment.principalName}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 font-mono">
                        {assignment.principalType}
                      </span>
                      {assignment.isExternalGuest && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-red-600 text-white font-mono font-bold">
                          EXTERNAL GUEST (#EXT#)
                        </span>
                      )}
                      {isDormant && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 font-mono font-bold">
                          DORMANT ({assignment.lastActiveDays} DAYS INACTIVE)
                        </span>
                      )}
                      {!assignment.mfaEnforced && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 font-mono font-bold">
                          MFA MISSING
                        </span>
                      )}
                    </div>

                    <div className="text-xs text-slate-600 mt-1 flex items-center space-x-2 font-mono">
                      <span>
                        Role:{' '}
                        <strong className="text-emerald-800">
                          {assignment.roleDefinitionName}
                        </strong>
                      </span>
                      <span>·</span>
                      <span className="truncate max-w-xs">
                        Scope: {assignment.scope}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center flex-wrap gap-2 self-end lg:self-center">
                  <span className="text-xs font-mono text-slate-500">
                    Last active:{' '}
                    <strong className="text-slate-900">
                      {assignment.lastActiveDays}d ago
                    </strong>
                  </span>
                  {onRevokeAssignment &&
                    (associatedFindings.length > 0 ||
                      assignment.isExternalGuest ||
                      !assignment.mfaEnforced ||
                      isDormant) && (
                      <button
                        type="button"
                        onClick={() => onRevokeAssignment(assignment.id)}
                        className="px-3 py-1.5 rounded-md text-xs font-semibold bg-amber-50 hover:bg-amber-100 text-amber-900 border border-amber-200 flex items-center space-x-1.5 cursor-pointer transition-colors"
                        title="Simulates role downgrade/revocation in UI memory without modifying live Azure resources"
                      >
                        <Wrench className="w-3.5 h-3.5 text-amber-700" />
                        <span>Simulate Least-Privilege (In-Memory)</span>
                      </button>
                    )}
                  {associatedFindings.length > 0 && onSelectFinding && (
                    <button
                      type="button"
                      onClick={() => onSelectFinding(associatedFindings[0])}
                      className="px-3 py-1.5 rounded-md text-xs font-semibold bg-[#0E2238] hover:bg-[#081420] text-[#EEF3F1] flex items-center space-x-1 cursor-pointer transition-colors"
                    >
                      <span>Remediation Runbook</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>

              {/* Actionable Findings for this Identity */}
              {associatedFindings.length > 0 && (
                <div className="mt-3 space-y-3 pt-2">
                  {associatedFindings.map((finding) => (
                    <div
                      key={finding.id}
                      className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              finding.severity === 'CRITICAL'
                                ? 'bg-red-50 text-red-700 border-red-200'
                                : 'bg-orange-50 text-orange-700 border-orange-200'
                            }`}
                          >
                            {finding.severity}
                          </span>
                          <span className="font-bold text-slate-900">
                            {finding.title}
                          </span>
                        </div>
                        {finding.compliance.cisAzure && (
                          <span className="text-[10px] text-slate-600 font-mono">
                            CIS {finding.compliance.cisAzure}
                          </span>
                        )}
                      </div>

                      <p className="text-slate-600 leading-relaxed">
                        {finding.description}
                      </p>

                      {/* Remediation Azure CLI snippet */}
                      <div className="space-y-1 pt-1">
                        <div className="flex items-center justify-between text-[11px] text-slate-600 font-medium">
                          <span className="flex items-center space-x-1">
                            <Terminal className="w-3.5 h-3.5 text-emerald-700" />
                            <span>Remediation Command:</span>
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              copyToClipboard(finding.remediation.cliCommand, finding.id)
                            }
                            className="text-emerald-700 hover:underline flex items-center space-x-1 text-[10px] font-mono cursor-pointer"
                          >
                            {copiedId === finding.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-700" />
                                <span>Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy CLI</span>
                              </>
                            )}
                          </button>
                        </div>
                        <div className="bg-[#081420] p-3 rounded-lg border border-[#3E6E86]/40 text-[#5FD3BF] font-mono text-xs overflow-x-auto whitespace-pre">
                          {finding.remediation.cliCommand}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
