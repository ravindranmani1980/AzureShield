/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  FileWarning,
  Search,
  Terminal,
  Globe,
  Code2,
  CheckCircle2,
  Download,
  AlertTriangle,
} from 'lucide-react';
import { Finding, Severity } from '../types/security';

interface FindingsListProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onRemediateFinding?: (findingId: string) => void;
}

/**
 * Generates an operator-safe Bash remediation script (Recommendation #14):
 * - Defaults to DRY_RUN=true unless --apply-live-changes is explicitly passed
 * - Requires interactive confirmation before modifying live Azure resources
 * - Prints pre-check and rollback commands for every finding
 */
function downloadSafeRemediationBashScript(findings: Finding[]) {
  const lines: string[] = [
    '#!/usr/bin/env bash',
    '# ============================================================================',
    '# MANIQ SHIELD — AZURE STORAGE & RBAC REMEDIATION RUNBOOK SCRIPT (SAFE MODE)',
    `# Generated: ${new Date().toISOString()}`,
    `# Total Findings Included: ${findings.length}`,
    '# Tool Author: Mani Ravindran (https://ravindran.in)',
    '# ============================================================================',
    '# SAFETY GUARDRAILS (RECOMMENDATION #14):',
    '# 1. By default, this script runs in DRY_RUN=true mode and makes ZERO changes.',
    '# 2. Validate all commands in a non-production/staging subscription first.',
    '# 3. To execute live changes, pass "--apply-live-changes" and confirm interactively.',
    '# ============================================================================',
    'set -euo pipefail',
    '',
    'DRY_RUN=true',
    'if [[ "${1:-}" == "--apply-live-changes" ]]; then',
    '  DRY_RUN=false',
    '  echo "WARNING: You have requested LIVE changes against Azure ARM resources."',
    '  read -r -p "Have you validated these changes in staging and backed up current state? (yes/NO): " CONFIRM',
    '  if [[ "$CONFIRM" != "yes" ]]; then',
    '    echo "Aborted by operator. Re-running in safe DRY_RUN mode."',
    '    DRY_RUN=true',
    '  fi',
    'else',
    '  echo "INFO: Running in safe DRY_RUN mode (no Azure resources will be modified)."',
    '  echo "      Pass --apply-live-changes after reviewing pre-checks and rollback steps."',
    'fi',
    '',
    'run_cmd() {',
    '  if [[ "$DRY_RUN" == "true" ]]; then',
    '    echo "[DRY-RUN] Would execute: $*"',
    '  else',
    '    echo "[LIVE-EXEC] Executing: $*"',
    '    eval "$*"',
    '  fi',
    '}',
    '',
  ];

  findings.forEach((f, idx) => {
    lines.push(
      `# ----------------------------------------------------------------------------`
    );
    lines.push(`# [${idx + 1}] [${f.severity}] ${f.title}`);
    lines.push(`# Target Resource: ${f.resourceName} (${f.resourceType})`);
    lines.push(`# Operational Impact: ${f.remediation.impactNotice}`);
    if (f.remediation.preCheckCommand) {
      lines.push(`# Pre-Check (Read-Only): ${f.remediation.preCheckCommand.replace(/\n/g, ' ')}`);
    }
    if (f.remediation.rollbackCommand) {
      lines.push(`# Rollback Command: ${f.remediation.rollbackCommand.replace(/\n/g, ' ')}`);
    }
    lines.push(
      `# ----------------------------------------------------------------------------`
    );
    lines.push(`echo ">>> [${idx + 1}/${findings.length}] ${f.title} (${f.resourceName})..."`);
    lines.push(`run_cmd ${JSON.stringify(f.remediation.cliCommand.replace(/\\\n/g, ' '))}`);
    lines.push('');
  });

  lines.push('echo "Runbook complete (DRY_RUN=$DRY_RUN)."');

  const blob = new Blob([lines.join('\n')], { type: 'text/x-sh' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `maniq-shield-remediation-dryrun-${new Date()
    .toISOString()
    .slice(0, 10)}.sh`;
  a.click();
  URL.revokeObjectURL(url);
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  onSelectFinding,
  onRemediateFinding,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<
    'ALL' | 'storage' | 'rbac' | 'privilege_escalation'
  >('ALL');

  const filteredFindings = findings.filter((f) => {
    const matchesSeverity =
      severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesCategory =
      categoryFilter === 'ALL' || f.category === categoryFilter;
    const matchesSearch =
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.resourceName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-5">
      {/* Filter & Search Bar */}
      <div className="p-4 rounded-xl border border-slate-200/90 bg-white flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4 shadow-xs">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search findings by resource name, loophole title, or CVE/CIS control..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-50 border border-slate-300 text-xs text-[#16232F] rounded-lg pl-10 pr-4 py-2 focus:outline-none focus:border-[#2BB5A0]"
          />
        </div>

        {/* Severity Filter Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center space-x-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
            {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded-md font-mono font-bold transition-all ${
                  severityFilter === sev
                    ? 'bg-[#0E2238] text-white'
                    : 'text-[#546471] hover:text-[#16232F]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Category Filter */}
          <select
            aria-label="Category Filter"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value as any)}
            className="bg-slate-50 border border-slate-300 text-xs text-[#16232F] rounded-lg px-3 py-2 focus:outline-none focus:border-[#2BB5A0] font-medium"
          >
            <option value="ALL">All Domains ({findings.length})</option>
            <option value="storage">Storage Loopholes</option>
            <option value="rbac">RBAC Over-Privilege</option>
            <option value="privilege_escalation">Privilege Escalation</option>
          </select>

          {/* Export Safe Dry-Run Remediation Bash Script (Rec #14) */}
          {findings.length > 0 && (
            <button
              onClick={() => downloadSafeRemediationBashScript(filteredFindings)}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all"
              title="Downloads a safe DRY_RUN=true Bash script with pre-checks and rollback steps"
            >
              <Download className="w-3.5 h-3.5 text-[#5FD3BF]" />
              <span>Export Dry-Run .sh Script</span>
            </button>
          )}
        </div>
      </div>

      {/* Safe Remediation Script Disclosure (Rec #14) */}
      <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-950 text-xs flex items-center space-x-2">
        <AlertTriangle className="w-4 h-4 text-amber-700 flex-shrink-0" />
        <span>
          <strong>Remediation Safety Guardrails (Rec #14):</strong> Every finding runbook includes read-only <em>Pre-Checks</em> and <em>Emergency Rollback</em> commands. Exported <code>.sh</code> scripts default to <code>DRY_RUN=true</code> and require <code>--apply-live-changes</code> plus interactive confirmation after staging validation.
        </span>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="p-10 text-center rounded-xl border border-slate-200 bg-white text-[#546471] text-sm">
            No security findings match the current filter criteria.
          </div>
        ) : (
          filteredFindings.map((finding) => (
            <div
              key={finding.id}
              onClick={() => onSelectFinding(finding)}
              className="p-4 rounded-xl border border-slate-200/90 bg-white hover:border-[#2BB5A0] transition-all cursor-pointer group shadow-xs"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center space-x-2.5 flex-wrap gap-y-1">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      finding.severity === 'CRITICAL'
                        ? 'bg-red-100 text-red-700 border border-red-200'
                        : finding.severity === 'HIGH'
                        ? 'bg-orange-100 text-orange-800 border border-orange-200'
                        : 'bg-amber-100 text-amber-800 border border-amber-200'
                    }`}
                  >
                    {finding.severity}
                  </span>

                  {/* Recommendation #10: Guardrail Gap vs Confirmed Exposure Badge */}
                  {finding.findingType === 'guardrail_gap' && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-300">
                      GUARDRAIL GAP (0 PUBLIC CONTAINERS)
                    </span>
                  )}
                  {finding.findingType === 'confirmed_exposure' && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-50 text-red-700 border border-red-300">
                      CONFIRMED ANONYMOUS EXPOSURE
                    </span>
                  )}

                  <span className="text-xs font-mono text-[#546471]">
                    [{finding.category.toUpperCase().replace('_', ' ')}]
                  </span>
                  <h3 className="font-serif text-sm font-bold text-[#16232F] group-hover:text-[#1F8A79] transition-colors">
                    {finding.title}
                  </h3>
                </div>

                <div className="flex items-center space-x-2 text-[11px] font-mono text-[#546471]">
                  {finding.compliance.cisAzure && (
                    <span
                      className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-[#16232F]"
                      title="Informational cross-reference to selected control"
                    >
                      CIS Ref {finding.compliance.cisAzure}
                    </span>
                  )}
                  {finding.compliance.mcsb && (
                    <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-[#16232F]">
                      {finding.compliance.mcsb}
                    </span>
                  )}
                </div>
              </div>

              <p className="text-xs text-[#546471] mt-2 leading-relaxed line-clamp-2">
                {finding.description}
              </p>

              <div className="mt-3 pt-3 border-t border-slate-200 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center space-x-2 text-[#546471] font-mono">
                  <FileWarning className="w-3.5 h-3.5 text-[#1F8A79]" />
                  <span>Resource:</span>
                  <span className="text-[#16232F] font-semibold">
                    {finding.resourceName}
                  </span>
                  <span className="text-slate-300">|</span>
                  <span>{finding.resourceType}</span>
                </div>

                <div className="flex items-center space-x-3">
                  <span className="inline-flex items-center space-x-1 text-[11px] text-[#546471]">
                    <Terminal className="w-3 h-3 text-[#1F8A79]" />
                    <span>Pre-Check + CLI + Rollback</span>
                  </span>
                  <span className="inline-flex items-center space-x-1 text-[11px] text-[#546471]">
                    <Globe className="w-3 h-3 text-[#1F8A79]" />
                    <span>Portal</span>
                  </span>
                  <span className="inline-flex items-center space-x-1 text-[11px] text-[#546471]">
                    <Code2 className="w-3 h-3 text-[#D79A45]" />
                    <span>Terraform</span>
                  </span>
                  {onRemediateFinding && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onRemediateFinding(finding.id);
                      }}
                      className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-emerald-50 hover:bg-emerald-100 text-[#1F8A79] border border-emerald-200 text-[11px] font-semibold transition-all"
                      title="Marks finding acknowledged in session memory (unverified in Azure)"
                    >
                      <CheckCircle2 className="w-3 h-3" />
                      <span>Acknowledge (In-Memory)</span>
                    </button>
                  )}
                  <span className="text-[#1F8A79] font-semibold group-hover:translate-x-0.5 transition-transform">
                    Open Runbook →
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
