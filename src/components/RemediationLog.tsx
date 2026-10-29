/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  History,
  CheckCircle2,
  Clock,
  Search,
  Download,
  Trash2,
  Terminal,
  Code2,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  TrendingUp,
  FileJson,
  FileSpreadsheet,
  Server,
  UserCheck,
  Tag,
} from 'lucide-react';
import {
  RemediationLogEntry,
  Severity,
  VulnerabilityCategory,
} from '../types/security';

interface RemediationLogProps {
  entries: RemediationLogEntry[];
  onClearLog?: () => void;
  compact?: boolean;
  onViewAllClick?: () => void;
}

export const RemediationLog: React.FC<RemediationLogProps> = ({
  entries,
  onClearLog,
  compact = false,
  onViewAllClick,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'ALL'>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<VulnerabilityCategory | 'ALL'>('ALL');
  const [expandedEntryId, setExpandedEntryId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredEntries = entries.filter((entry) => {
    const query = searchQuery.toLowerCase();
    const matchesSearch =
      entry.title.toLowerCase().includes(query) ||
      entry.findingId.toLowerCase().includes(query) ||
      entry.resourceName.toLowerCase().includes(query) ||
      entry.resourceId.toLowerCase().includes(query) ||
      entry.remediationSummary.toLowerCase().includes(query) ||
      entry.formattedTimestamp.toLowerCase().includes(query);

    const matchesSeverity =
      selectedSeverity === 'ALL' || entry.severity === selectedSeverity;
    const matchesCategory =
      selectedCategory === 'ALL' || entry.category === selectedCategory;

    return matchesSearch && matchesSeverity && matchesCategory;
  });

  const displayedEntries = compact ? filteredEntries.slice(0, 5) : filteredEntries;

  const criticalAndHighCount = entries.filter(
    (e) => e.severity === 'CRITICAL' || e.severity === 'HIGH'
  ).length;

  const latestEntry = entries[0] || null;

  const earliestScore =
    entries.length > 0 ? entries[entries.length - 1].postureScoreBefore : 0;
  const latestScore =
    entries.length > 0 ? entries[0].postureScoreAfter : 0;
  const netPostureGain = Math.max(0, latestScore - earliestScore);

  const exportAsJson = () => {
    const payload = {
      application: 'Maniq Shield CSPM',
      exportedAt: new Date().toISOString(),
      totalRemediatedFindings: entries.length,
      sessionEntries: entries,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `maniq_shield_remediation_log_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportAsCsv = () => {
    const headers = [
      'Log ID',
      'Timestamp (ISO)',
      'Formatted Time',
      'Finding ID',
      'Title',
      'Severity',
      'Category',
      'Resource Name',
      'Resource Type',
      'Resource ID',
      'Remediation Method',
      'CIS Azure',
      'MCSB',
      'NIST',
      'Score Before (%)',
      'Score After (%)',
      'Operator',
      'Remediation Summary',
    ];

    const rows = entries.map((e) => [
      e.id,
      e.remediatedAt,
      e.formattedTimestamp,
      e.findingId,
      `"${e.title.replace(/"/g, '""')}"`,
      e.severity,
      e.category,
      e.resourceName,
      e.resourceType,
      e.resourceId,
      e.remediationMethod,
      e.compliance.cisAzure || '',
      e.compliance.mcsb || '',
      e.compliance.nist || '',
      e.postureScoreBefore,
      e.postureScoreAfter,
      e.operator,
      `"${e.remediationSummary.replace(/"/g, '""')}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `maniq_shield_remediation_log_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityBadgeStyle = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-300 border border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-300 border border-amber-500/40';
      default:
        return 'bg-blue-500/20 text-blue-300 border border-blue-500/40';
    }
  };

  return (
    <div className="space-y-5" data-testid="remediation-log">
      {/* Header & Session Metrics */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start space-x-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex-shrink-0 mt-0.5">
              <History className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
                  Session Remediation Log
                </h2>
                <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">
                  {entries.length} Remediated
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Immutable session audit trail tracking timestamps, Azure resource metadata, compliance mappings, and posture score deltas for every remediated security finding.
              </p>
            </div>
          </div>

          <div className="flex items-center flex-wrap gap-2">
            {entries.length > 0 && (
              <>
                <button
                  onClick={exportAsJson}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all"
                  title="Export Remediation Log as JSON"
                >
                  <FileJson className="w-3.5 h-3.5 text-blue-400" />
                  <span>Export JSON</span>
                </button>
                <button
                  onClick={exportAsCsv}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all"
                  title="Export Remediation Log as CSV"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Export CSV</span>
                </button>
                {onClearLog && !compact && (
                  <button
                    onClick={onClearLog}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-red-950/40 hover:bg-red-900/50 text-red-300 border border-red-500/30 transition-all"
                    title="Clear current session remediation log"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Clear Log</span>
                  </button>
                )}
              </>
            )}
            {compact && onViewAllClick && (
              <button
                onClick={onViewAllClick}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white border border-blue-500/30 transition-all"
              >
                <span>Open Full Remediation Log</span>
              </button>
            )}
          </div>
        </div>

        {/* Summary KPI Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 border-t border-slate-800/80">
          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80">
            <div className="text-[11px] text-slate-400 flex items-center space-x-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Total Remediated</span>
            </div>
            <div className="text-xl font-extrabold text-white mt-0.5">
              {entries.length}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80">
            <div className="text-[11px] text-slate-400 flex items-center space-x-1">
              <ShieldCheck className="w-3.5 h-3.5 text-red-400" />
              <span>Critical / High Fixed</span>
            </div>
            <div className="text-xl font-extrabold text-emerald-400 mt-0.5">
              {criticalAndHighCount}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80">
            <div className="text-[11px] text-slate-400 flex items-center space-x-1">
              <TrendingUp className="w-3.5 h-3.5 text-blue-400" />
              <span>Posture Score Gain</span>
            </div>
            <div className="text-xl font-extrabold text-blue-400 mt-0.5">
              +{netPostureGain}%
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80">
            <div className="text-[11px] text-slate-400 flex items-center space-x-1">
              <Clock className="w-3.5 h-3.5 text-amber-400" />
              <span>Latest Remediation</span>
            </div>
            <div className="text-xs font-mono font-bold text-slate-200 mt-1 truncate">
              {latestEntry ? latestEntry.formattedTimestamp : 'No activity yet'}
            </div>
          </div>
        </div>

        {/* Search & Filter Controls (shown when entries exist and not compact, or when > 3 entries) */}
        {(!compact || entries.length > 3) && entries.length > 0 && (
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pt-3 border-t border-slate-800">
            <div className="flex items-center space-x-2 overflow-x-auto pb-1 lg:pb-0">
              <div className="flex items-center space-x-1 bg-slate-950/80 p-1 rounded-xl border border-slate-800 text-xs">
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(
                  (sev) => (
                    <button
                      key={sev}
                      onClick={() => setSelectedSeverity(sev)}
                      className={`px-2.5 py-1 rounded-lg font-semibold transition-all ${
                        selectedSeverity === sev
                          ? 'bg-emerald-600 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {sev}
                    </button>
                  )
                )}
              </div>

              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value as any)}
                className="bg-slate-950/80 border border-slate-800 text-slate-300 text-xs rounded-xl px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-emerald-500 cursor-pointer"
              >
                <option value="ALL">All Categories</option>
                <option value="storage">Storage & Containers</option>
                <option value="rbac">RBAC & IAM</option>
                <option value="privilege_escalation">Privilege Escalation</option>
                <option value="network">Network Perimeter</option>
                <option value="encryption">Encryption & TLS</option>
              </select>
            </div>

            <div className="relative w-full lg:w-72">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Filter log by resource, ID, timestamp..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950/80 border border-slate-800 text-slate-200 text-xs rounded-xl pl-9 pr-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>
          </div>
        )}
      </div>

      {/* Log Entries List */}
      {entries.length === 0 ? (
        <div className="p-8 rounded-2xl bg-slate-900/70 border border-slate-800/80 text-center space-y-2">
          <History className="w-8 h-8 text-slate-500 mx-auto" />
          <div className="text-sm font-bold text-slate-300">
            No Remediations Logged in Current Session
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Remediate any security finding using the <strong>Harden</strong> button on the dashboard, inside a finding runbook modal, or via <strong>Harden All Remaining</strong> to record real-time timestamps and resource metadata here.
          </p>
        </div>
      ) : displayedEntries.length === 0 ? (
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 text-center text-xs text-slate-400">
          No remediation log entries match the current search/filter criteria.
        </div>
      ) : (
        <div className="space-y-3">
          {displayedEntries.map((entry) => {
            const isExpanded = expandedEntryId === entry.id;

            return (
              <div
                key={entry.id}
                data-testid="remediation-log-entry"
                className="rounded-2xl bg-slate-900 border border-slate-800 hover:border-emerald-500/40 transition-all shadow-md"
              >
                <div
                  onClick={() =>
                    setExpandedEntryId(isExpanded ? null : entry.id)
                  }
                  className="p-4 cursor-pointer flex flex-col lg:flex-row lg:items-center justify-between gap-3"
                >
                  <div className="flex items-start space-x-3">
                    <div className="p-2 rounded-xl bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex-shrink-0 mt-0.5">
                      <CheckCircle2 className="w-4 h-4" />
                    </div>

                    <div className="space-y-1">
                      {/* Badges & Timestamp */}
                      <div className="flex items-center flex-wrap gap-1.5">
                        <span
                          className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${getSeverityBadgeStyle(
                            entry.severity
                          )}`}
                        >
                          {entry.severity}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                          {entry.findingId}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-medium">
                          {entry.remediationMethod}
                        </span>
                        {entry.compliance.cisAzure && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                            CIS {entry.compliance.cisAzure}
                          </span>
                        )}
                        {entry.compliance.mcsb && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 font-mono">
                            MCSB {entry.compliance.mcsb}
                          </span>
                        )}
                        {entry.compliance.nist && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                            NIST {entry.compliance.nist}
                          </span>
                        )}
                      </div>

                      {/* Finding Title */}
                      <h4 className="text-sm font-bold text-white">
                        {entry.title}
                      </h4>

                      {/* Resource & Action Summary */}
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
                        <span className="font-mono flex items-center space-x-1">
                          <Server className="w-3.5 h-3.5 text-slate-500" />
                          <span>
                            Target:{' '}
                            <strong className="text-slate-200">
                              {entry.resourceName}
                            </strong>{' '}
                            ({entry.resourceType})
                          </span>
                        </span>
                        <span>•</span>
                        <span className="text-emerald-400 font-medium">
                          {entry.remediationSummary}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right Side: Timestamp & Score Impact */}
                  <div className="flex items-center justify-between lg:justify-end gap-3 pt-2 lg:pt-0 border-t lg:border-t-0 border-slate-800/80 flex-shrink-0">
                    <div className="text-left lg:text-right">
                      <div className="flex items-center lg:justify-end space-x-1 text-xs font-mono text-slate-200">
                        <Clock className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                        <time dateTime={entry.remediatedAt}>
                          {entry.formattedTimestamp}
                        </time>
                      </div>
                      <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                        ISO: {entry.remediatedAt}
                      </div>
                    </div>

                    <div className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-right">
                      <div className="text-[10px] text-slate-400 uppercase">
                        Posture Delta
                      </div>
                      <div className="text-xs font-mono font-bold text-emerald-400">
                        {entry.postureScoreBefore}% → {entry.postureScoreAfter}%
                      </div>
                    </div>

                    <div className="p-1 text-slate-400 hover:text-white">
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </div>
                  </div>
                </div>

                {/* Expanded Metadata & Audit Details */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-2 border-t border-slate-800/80 space-y-3 bg-slate-950/40 rounded-b-2xl">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/90 space-y-1">
                        <div className="text-[10px] font-bold uppercase text-slate-400 flex items-center space-x-1">
                          <Tag className="w-3 h-3 text-blue-400" />
                          <span>Finding Metadata</span>
                        </div>
                        <div className="font-mono text-slate-300 break-all">
                          <div>ID: {entry.findingId}</div>
                          <div>Category: {entry.category.toUpperCase()}</div>
                          <div>Severity: {entry.severity}</div>
                        </div>
                      </div>

                      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/90 space-y-1">
                        <div className="text-[10px] font-bold uppercase text-slate-400 flex items-center space-x-1">
                          <Server className="w-3 h-3 text-purple-400" />
                          <span>Azure Resource Context</span>
                        </div>
                        <div className="font-mono text-slate-300 break-all">
                          <div>Name: {entry.resourceName}</div>
                          <div>Type: {entry.resourceType}</div>
                          <div className="text-[11px] text-slate-400">
                            ARM ID: {entry.resourceId}
                          </div>
                        </div>
                      </div>

                      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/90 space-y-1">
                        <div className="text-[10px] font-bold uppercase text-slate-400 flex items-center space-x-1">
                          <UserCheck className="w-3 h-3 text-emerald-400" />
                          <span>Execution & Audit Context</span>
                        </div>
                        <div className="font-mono text-slate-300 break-all">
                          <div>Operator: {entry.operator}</div>
                          <div>Method: {entry.remediationMethod}</div>
                          <div>Subscription: {entry.subscriptionId}</div>
                        </div>
                      </div>
                    </div>

                    {/* Executed CLI Command */}
                    {entry.cliCommandExecuted && (
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-semibold text-slate-300 flex items-center space-x-1.5">
                            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Executed Azure CLI Remediation Command</span>
                          </span>
                          <button
                            onClick={() =>
                              copyToClipboard(entry.cliCommandExecuted, entry.id)
                            }
                            className="text-xs text-blue-400 hover:text-blue-300 flex items-center space-x-1"
                          >
                            {copiedId === entry.id ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-emerald-400">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span>Copy CLI</span>
                              </>
                            )}
                          </button>
                        </div>
                        <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto whitespace-pre">
                          {entry.cliCommandExecuted}
                        </div>
                      </div>
                    )}

                    {/* Terraform Snippet if available */}
                    {entry.terraformSnippet && (
                      <div className="space-y-1.5">
                        <div className="flex items-center space-x-1.5 text-xs font-semibold text-slate-300">
                          <Code2 className="w-3.5 h-3.5 text-purple-400" />
                          <span>Corresponding Terraform State Enforcement</span>
                        </div>
                        <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-purple-300 font-mono text-xs overflow-x-auto whitespace-pre">
                          {entry.terraformSnippet}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
