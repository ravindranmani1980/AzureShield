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
 * Generates an operator-safe, structured Bulk Bash remediation script (Recommendation #14):
 * - Groups pending remediation CLI commands by Severity and Domain Category
 * - Includes Azure CLI pre-flight authentication & subscription verification
 * - Defaults to DRY_RUN=true unless --apply-live-changes is explicitly passed
 * - Prints pre-check, primary CLI remediation, and rollback commands for every finding
 */
function exportBulkRemediationScript(
  findingsToExport: Finding[],
  scopeLabel = 'All Pending Findings'
) {
  const generatedAt = new Date().toISOString();
  const dateSlug = generatedAt.slice(0, 10);

  const severityOrder: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };

  const sortedFindings = [...findingsToExport].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  const criticalCount = sortedFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = sortedFindings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = sortedFindings.filter((f) => f.severity === 'MEDIUM').length;

  const lines: string[] = [
    '#!/usr/bin/env bash',
    '# ==============================================================================',
    '# MANIQ SHIELD — BULK AZURE STORAGE & RBAC REMEDIATION DEPLOYMENT SCRIPT (.sh)',
    `# Generated At       : ${generatedAt}`,
    `# Export Scope       : ${scopeLabel}`,
    `# Pending Commands   : ${sortedFindings.length} (${criticalCount} Critical, ${highCount} High, ${mediumCount} Medium)`,
    '# Author             : Mani Ravindran (https://ravindran.in)',
    '# ==============================================================================',
    '# USAGE:',
    '#   1. Dry-Run Preview (Default — zero live Azure modifications):',
    `#      chmod +x maniq-shield-bulk-remediation-${dateSlug}.sh`,
    `#      ./maniq-shield-bulk-remediation-${dateSlug}.sh`,
    '#',
    '#   2. Live Bulk Deployment (Requires staging validation & confirmation):',
    `#      ./maniq-shield-bulk-remediation-${dateSlug}.sh --apply-live-changes`,
    '# ==============================================================================',
    'set -euo pipefail',
    '',
    'DRY_RUN=true',
    'if [[ "${1:-}" == "--apply-live-changes" ]]; then',
    '  DRY_RUN=false',
    '  echo "=============================================================================="',
    '  echo "WARNING: LIVE BULK REMEDIATION MODE ENABLED"',
    '  echo "Target Azure CLI session will execute remediation changes across resources."',
    '  echo "=============================================================================="',
    '  if ! command -v az >/dev/null 2>&1; then',
    '    echo "ERROR: Azure CLI (az) is not installed or not in PATH." >&2',
    '    exit 1',
    '  fi',
    '  echo "Verifying active Azure CLI account context..."',
    '  az account show --output table || { echo "ERROR: Run az login first." >&2; exit 1; }',
    '  read -r -p "Confirm bulk execution of pending remediation commands? (yes/NO): " CONFIRM',
    '  if [[ "$CONFIRM" != "yes" ]]; then',
    '    echo "Aborted by operator. Falling back to safe DRY_RUN preview mode."',
    '    DRY_RUN=true',
    '  fi',
    'else',
    '  echo "INFO: Running in safe DRY_RUN mode (no Azure resources will be modified)."',
    '  echo "      Pass --apply-live-changes to deploy live Azure CLI remediations."',
    'fi',
    '',
    'TOTAL_COMMANDS=' + sortedFindings.length,
    'EXECUTED_COUNT=0',
    '',
    'run_remediation_step() {',
    '  local step_num="$1"',
    '  local finding_id="$2"',
    '  local severity="$3"',
    '  local resource_name="$4"',
    '  local cmd="$5"',
    '  EXECUTED_COUNT=$((EXECUTED_COUNT + 1))',
    '  echo ""',
    '  echo "[$step_num/$TOTAL_COMMANDS] [$severity] $finding_id — Resource: $resource_name"',
    '  if [[ "$DRY_RUN" == "true" ]]; then',
    '    echo "  [DRY-RUN] $cmd"',
    '  else',
    '    echo "  [APPLYING] $cmd"',
    '    eval "$cmd"',
    '  fi',
    '}',
    '',
  ];

  const categories: Array<{ key: Finding['category']; title: string }> = [
    { key: 'storage', title: 'SECTION 1: AZURE STORAGE ACCOUNT & CONTAINER HARDENING' },
    { key: 'rbac', title: 'SECTION 2: AZURE RBAC LEAST-PRIVILEGE REMEDIATION' },
    { key: 'privilege_escalation', title: 'SECTION 3: PRIVILEGE ESCALATION & WILDCARD MITIGATION' },
  ];

  let stepCounter = 0;

  categories.forEach((section) => {
    const sectionFindings = sortedFindings.filter((f) => f.category === section.key);
    if (sectionFindings.length === 0) return;

    lines.push('# ==============================================================================');
    lines.push(`# ${section.title} (${sectionFindings.length} Pending)`);
    lines.push('# ==============================================================================');
    lines.push('');

    sectionFindings.forEach((f) => {
      stepCounter += 1;
      const singleLineCli = f.remediation.cliCommand
        .replace(/\\\r?\n/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

      lines.push(`# ------------------------------------------------------------------------------`);
      lines.push(`# Step ${stepCounter}: [${f.severity}] ${f.title}`);
      lines.push(`# Finding ID         : ${f.id}`);
      lines.push(`# Target Resource    : ${f.resourceName} (${f.resourceType})`);
      lines.push(
        `# Compliance Mapping : CIS ${f.compliance.cisAzure || 'N/A'} | MCSB ${
          f.compliance.mcsb || 'N/A'
        } | NIST ${f.compliance.nist || 'N/A'}`
      );
      lines.push(`# Operational Impact : ${f.remediation.impactNotice}`);
      if (f.remediation.preCheckCommand) {
        lines.push(
          `# Pre-Check Command  : ${f.remediation.preCheckCommand
            .replace(/\\\r?\n/g, ' ')
            .replace(/\s+/g, ' ')
            .trim()}`
        );
      }
      if (f.remediation.rollbackCommand) {
        lines.push(
          `# Emergency Rollback : ${f.remediation.rollbackCommand
            .replace(/\\\r?\n/g, ' ')
            .replace(/\s+/g, ' ')
            .trim()}`
        );
      }
      lines.push(`# ------------------------------------------------------------------------------`);
      lines.push(
        `run_remediation_step "${stepCounter}" ${JSON.stringify(f.id)} ${JSON.stringify(
          f.severity
        )} ${JSON.stringify(f.resourceName)} ${JSON.stringify(singleLineCli)}`
      );
      lines.push('');
    });
  });

  lines.push('echo ""');
  lines.push('echo "=============================================================================="');
  lines.push(
    'echo "Bulk remediation runbook finished: $EXECUTED_COUNT/$TOTAL_COMMANDS commands processed (DRY_RUN=$DRY_RUN)."'
  );
  lines.push('echo "=============================================================================="');

  const blob = new Blob([lines.join('\n')], { type: 'text/x-sh;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `maniq-shield-bulk-remediation-${dateSlug}.sh`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
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
  const [exportedFeedback, setExportedFeedback] = useState(false);

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

  const isFilteredSubset = filteredFindings.length !== findings.length;

  const handleDownloadBulkSh = (targetFindings: Finding[], label: string) => {
    exportBulkRemediationScript(targetFindings, label);
    setExportedFeedback(true);
    setTimeout(() => setExportedFeedback(false), 2500);
  };

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

        {/* Severity Filter Pills & Bulk Export Action */}
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

          {/* Download All Pending Remediation CLI Commands (.sh) */}
          {findings.length > 0 && (
            <div className="flex items-center gap-1.5">
              <button
                onClick={() =>
                  handleDownloadBulkSh(
                    findings,
                    `All Pending Remediation Findings (${findings.length})`
                  )
                }
                className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all shadow-xs cursor-pointer"
                title="Export all pending remediation Azure CLI commands into a structured .sh deployment script"
              >
                <Download className="w-3.5 h-3.5 text-[#5FD3BF]" />
                <span>
                  {exportedFeedback
                    ? 'Downloaded .sh Script!'
                    : `Download Bulk Remediation .sh (${findings.length})`}
                </span>
              </button>

              {isFilteredSubset && filteredFindings.length > 0 && (
                <button
                  onClick={() =>
                    handleDownloadBulkSh(
                      filteredFindings,
                      `Filtered Pending Findings (${filteredFindings.length})`
                    )
                  }
                  className="flex items-center space-x-1 px-2.5 py-2 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-[#16232F] border border-slate-300 transition-all cursor-pointer"
                  title="Export only the currently filtered findings into a .sh script"
                >
                  <Terminal className="w-3.5 h-3.5 text-[#1F8A79]" />
                  <span>Export Filtered ({filteredFindings.length})</span>
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Safe Remediation Script Disclosure (Rec #14) */}
      <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-950 text-xs flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-amber-700 flex-shrink-0" />
          <span>
            <strong>Bulk CLI Deployment Guardrails (Rec #14):</strong> Exported <code>.sh</code> scripts group all pending Azure CLI commands by domain with read-only <em>Pre-Checks</em> and <em>Emergency Rollback</em> steps. Scripts default to <code>DRY_RUN=true</code> and require <code>--apply-live-changes</code> for live execution.
          </span>
        </div>
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
