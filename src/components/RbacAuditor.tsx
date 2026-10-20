/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Users,
  ShieldAlert,
  UserX,
  Unlock,
  KeyRound,
  Terminal,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  UserCheck,
  Bot,
  Copy,
  Check,
  AlertTriangle,
  Flame,
  ArrowRight,
} from 'lucide-react';
import { RbacAssignment, Finding } from '../types/security';

interface RbacAuditorProps {
  roleAssignments: RbacAssignment[];
  findings: Finding[];
  onSelectFinding: (findingId: string) => void;
}

export const RbacAuditor: React.FC<RbacAuditorProps> = ({
  roleAssignments,
  findings,
  onSelectFinding,
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
  const overprivilegedCount = rbacFindings.filter(
    (f) => f.id.includes('OWNER') || f.id.includes('GUEST') || f.id.includes('SP-OVER')
  ).length;

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredAssignments = roleAssignments.filter((assignment) => {
    const matchesSearch =
      assignment.principalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      assignment.roleDefinitionName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      assignment.scope.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;

    if (filterMode === 'overprivileged') {
      return (
        assignment.roleDefinitionName === 'Owner' ||
        assignment.isExternalGuest ||
        assignment.actions.includes('*')
      );
    }
    if (filterMode === 'escalation') {
      return assignment.actions.some(
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
      {/* Header */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-3 rounded-xl bg-purple-500/20 text-purple-400 border border-purple-500/30">
              <Users className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                Role-Based Access Control (RBAC) & IAM Analyzer
              </h2>
              <p className="text-xs text-slate-400">
                Auditing Azure Active Directory / Entra ID role assignments for excessive privileges, dormant accounts, external guest access, and privilege escalation attack vectors.
              </p>
            </div>
          </div>

          {/* Metric Badges */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="px-3 py-1.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs">
              <span className="text-slate-400">Total Assignments: </span>
              <span className="font-bold text-white">{roleAssignments.length}</span>
            </div>
            <div className="px-3 py-1.5 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-300">
              <span className="text-red-400">Escalation Risks: </span>
              <span className="font-bold">{privilegeEscalationFindings.length}</span>
            </div>
            <div className="px-3 py-1.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300">
              <span className="text-amber-400">Dormant (&gt;90d): </span>
              <span className="font-bold">{dormantCount}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Privilege Escalation Threat Vector Spotlight */}
      {privilegeEscalationFindings.length > 0 && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-red-950/60 via-slate-900 to-slate-900 border border-red-500/40 shadow-xl relative overflow-hidden">
          <div className="flex items-start space-x-3.5 relative z-10">
            <div className="p-2.5 rounded-xl bg-red-600 text-white flex-shrink-0">
              <Flame className="w-5 h-5 animate-bounce" />
            </div>
            <div className="flex-1">
              <div className="flex items-center space-x-2 mb-1">
                <span className="text-xs font-black uppercase tracking-wider px-2 py-0.5 rounded-full bg-red-600 text-white">
                  CRITICAL EXPLOIT CHAIN DETECTED
                </span>
                <span className="text-xs text-slate-400">
                  Potential Administrative Takeover Path
                </span>
              </div>
              <h3 className="text-base font-bold text-white">
                Unauthorized Privilege Escalation via 'roleAssignments/write'
              </h3>
              <p className="text-xs text-slate-300 mt-1 max-w-3xl leading-relaxed">
                Non-Owner identities hold permission to create or modify Azure role assignments. Threat actors compromising these service accounts or custom operators can issue API calls to self-grant 'Owner' or 'Storage Blob Data Owner', completely bypassing organizational access boundaries.
              </p>

              {/* Visual Attack Chain Graph */}
              <div className="mt-4 p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col md:flex-row items-center gap-3 text-xs font-mono">
                <div className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-200 border border-slate-700">
                  1. Compromise Operator / SP
                </div>
                <ArrowRight className="w-4 h-4 text-red-400 rotate-90 md:rotate-0" />
                <div className="px-3 py-1.5 rounded-lg bg-red-950/80 text-red-300 border border-red-500/40">
                  2. Invoke roleAssignments/write
                </div>
                <ArrowRight className="w-4 h-4 text-red-400 rotate-90 md:rotate-0" />
                <div className="px-3 py-1.5 rounded-lg bg-red-600 text-white font-bold shadow-lg shadow-red-600/30">
                  3. Self-Promote to Subscription Owner
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Controls & Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 sm:pb-0">
          <button
            onClick={() => setFilterMode('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filterMode === 'all'
                ? 'bg-purple-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            All Identities ({roleAssignments.length})
          </button>
          <button
            onClick={() => setFilterMode('escalation')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filterMode === 'escalation'
                ? 'bg-red-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            Escalation Paths ({privilegeEscalationFindings.length})
          </button>
          <button
            onClick={() => setFilterMode('overprivileged')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filterMode === 'overprivileged'
                ? 'bg-purple-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            Overprivileged ({overprivilegedCount})
          </button>
          <button
            onClick={() => setFilterMode('dormant')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filterMode === 'dormant'
                ? 'bg-purple-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            Dormant &gt;90d ({dormantCount})
          </button>
          <button
            onClick={() => setFilterMode('guest')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filterMode === 'guest'
                ? 'bg-purple-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
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
          className="bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-xl px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 w-full sm:w-64"
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
              className={`p-5 rounded-2xl border transition-all ${
                hasCritical
                  ? 'bg-slate-900/90 border-red-500/40 shadow-lg'
                  : associatedFindings.length > 0
                  ? 'bg-slate-900/90 border-amber-500/30'
                  : 'bg-slate-900 border-slate-800'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
                <div className="flex items-start space-x-3.5">
                  <div
                    className={`p-2.5 rounded-xl flex-shrink-0 ${
                      assignment.principalType === 'GuestUser'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : assignment.principalType === 'ServicePrincipal'
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
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
                      <span className="font-bold text-sm text-white">
                        {assignment.principalName}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                        {assignment.principalType}
                      </span>
                      {assignment.isExternalGuest && (
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-600 text-white font-bold">
                          EXTERNAL GUEST (#EXT#)
                        </span>
                      )}
                      {isDormant && (
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 font-bold">
                          DORMANT ({assignment.lastActiveDays} DAYS INACTIVE)
                        </span>
                      )}
                      {!assignment.mfaEnforced && (
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 font-bold">
                          MFA MISSING
                        </span>
                      )}
                    </div>

                    <div className="text-xs text-slate-400 mt-1 flex items-center space-x-2 font-mono">
                      <span>Role: <strong className="text-purple-300">{assignment.roleDefinitionName}</strong></span>
                      <span>•</span>
                      <span className="truncate max-w-xs">Scope: {assignment.scope}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-3 self-end lg:self-center">
                  <span className="text-xs text-slate-400">
                    Last active: <strong className="text-slate-200">{assignment.lastActiveDays}d ago</strong>
                  </span>
                  {associatedFindings.length > 0 && (
                    <button
                      onClick={() => onSelectFinding(associatedFindings[0].id)}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white shadow-sm flex items-center space-x-1"
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
                      className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-extrabold ${
                              finding.severity === 'CRITICAL'
                                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                : 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                            }`}
                          >
                            {finding.severity}
                          </span>
                          <span className="font-bold text-slate-100">
                            {finding.title}
                          </span>
                        </div>
                        {finding.compliance.cisAzure && (
                          <span className="text-[10px] text-slate-400 font-mono">
                            CIS {finding.compliance.cisAzure}
                          </span>
                        )}
                      </div>

                      <p className="text-slate-300 leading-relaxed">
                        {finding.description}
                      </p>

                      {/* Remediation Azure CLI snippet */}
                      <div className="space-y-1 pt-1">
                        <div className="flex items-center justify-between text-[11px] text-slate-400 font-medium">
                          <span className="flex items-center space-x-1">
                            <Terminal className="w-3.5 h-3.5 text-purple-400" />
                            <span>Remediation Command:</span>
                          </span>
                          <button
                            onClick={() =>
                              copyToClipboard(finding.remediation.cliCommand, finding.id)
                            }
                            className="text-purple-400 hover:text-purple-300 flex items-center space-x-1 text-[10px]"
                          >
                            {copiedId === finding.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span className="text-emerald-400">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy CLI</span>
                              </>
                            )}
                          </button>
                        </div>
                        <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 text-purple-300 font-mono text-xs overflow-x-auto whitespace-pre">
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
