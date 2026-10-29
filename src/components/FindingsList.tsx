/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Download,
  Terminal,
  Globe,
  Code2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
} from 'lucide-react';
import {
  Finding,
  RemediationLogEntry,
  Severity,
  VulnerabilityCategory,
} from '../types/security';
import { RemediationLog } from './RemediationLog';

interface FindingsListProps {
  findings: Finding[];
  onSelectFinding: (findingId: string) => void;
  onRemediateFinding?: (findingId: string) => void;
  remediationLog?: RemediationLogEntry[];
  onClearRemediationLog?: () => void;
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  onSelectFinding,
  onRemediateFinding,
  remediationLog = [],
  onClearRemediationLog,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'ALL'>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<VulnerabilityCategory | 'ALL'>('ALL');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [activeRemediationTab, setActiveRemediationTab] = useState<'cli' | 'portal' | 'terraform'>('cli');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredFindings = findings.filter((finding) => {
    const matchesSearch =
      finding.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.resourceName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity =
      selectedSeverity === 'ALL' || finding.severity === selectedSeverity;
    const matchesCategory =
      selectedCategory === 'ALL' || finding.category === selectedCategory;

    return matchesSearch && matchesSeverity && matchesCategory;
  });

  const generateRemediationBashScript = () => {
    const header = `#!/usr/bin/env bash\n# =========================================================\n# Maniq Shield Automated Remediation Script\n# Generated: ${new Date().toISOString()}\n# Total Issues Addressed: ${findings.length}\n# =========================================================\nset -euo pipefail\n\necho "[+] Starting Azure Cloud Hardening..."\n\n`;
    const commands = findings
      .map((f, i) => `# [${f.severity}] #${i + 1}: ${f.title}\n${f.remediation.cliCommand}\n`)
      .join('\n');
    const footer = `\necho "[+] All Azure remediation commands applied successfully."\n`;

    const blob = new Blob([header + commands + footer], { type: 'text/x-shellscript' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `maniq_shield_remediation_${Date.now()}.sh`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Header (.xh-panel) */}
      <section className="xh-panel space-y-4">
        <div className="xh-kicker">
          <span className="k">Remediation Register &amp; Action Runbooks</span>
          <span className="tag">{findings.length} Security Loopholes Cataloged</span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl sm:text-2xl font-semibold text-[#EEF3F1] tracking-tight">
              Maniq Shield — Remediation Register &amp; Action Runbooks
            </h2>
            <p className="text-xs text-[#A9B7BF] mt-1">
              Complete catalog of detected storage loopholes, unauthorized RBAC access, and step-by-step remediation commands.
            </p>
          </div>

          <button
            type="button"
            onClick={generateRemediationBashScript}
            className="xh-btn primary self-start sm:self-center whitespace-nowrap shrink-0"
            title="Download unified Bash script with all Azure CLI remediation commands"
          >
            <Download className="w-4 h-4" />
            <span>Export maniq_shield_remediation.sh</span>
          </button>
        </div>
      </section>

      {/* Filter Controls */}
      <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="flex items-center space-x-2 overflow-x-auto pb-1 lg:pb-0">
          {/* Severity Filter */}
          <div className="flex items-center space-x-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
            {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                  selectedSeverity === sev
                    ? 'bg-[#0E2238] text-[#EEF3F1]'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Category Filter */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value as any)}
            className="bg-slate-50 border border-slate-200 text-slate-800 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#0E2238] cursor-pointer font-mono"
          >
            <option value="ALL">All Categories</option>
            <option value="storage">Storage &amp; Containers</option>
            <option value="rbac">RBAC &amp; IAM</option>
            <option value="privilege_escalation">Privilege Escalation</option>
            <option value="network">Network Perimeter</option>
            <option value="encryption">Encryption &amp; TLS</option>
          </select>
        </div>

        {/* Search Box */}
        <div className="relative w-full lg:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search findings, resources, CVEs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-50 border border-slate-200 focus:border-[#0E2238] focus:bg-white text-slate-900 text-xs rounded-lg pl-9 pr-3 py-1.5 focus:outline-none"
          />
        </div>
      </div>

      {/* Findings Count Summary */}
      <div className="flex items-center justify-between text-xs text-slate-600 font-mono px-1">
        <span>
          Showing <strong className="text-slate-900">{filteredFindings.length}</strong> of{' '}
          <strong className="text-slate-900">{findings.length}</strong> security loophole(s)
        </span>
      </div>

      {/* Findings Accordion / Card Register */}
      <div className="space-y-3">
        {filteredFindings.map((finding) => {
          const isExpanded = expandedFindingId === finding.id;

          return (
            <div
              key={finding.id}
              className={`rounded-xl bg-white border transition-all shadow-xs ${
                finding.severity === 'CRITICAL'
                  ? 'border-red-300 hover:border-red-400'
                  : finding.severity === 'HIGH'
                  ? 'border-orange-300 hover:border-orange-400'
                  : 'border-slate-200 hover:border-slate-300'
              }`}
            >
              {/* Card Header */}
              <div
                onClick={() =>
                  setExpandedFindingId(isExpanded ? null : finding.id)
                }
                className="p-4 sm:p-5 cursor-pointer flex items-start justify-between gap-3"
              >
                <div className="flex items-start space-x-3.5">
                  <div
                    className={`p-2 rounded-lg flex-shrink-0 mt-0.5 border ${
                      finding.severity === 'CRITICAL'
                        ? 'bg-red-50 text-red-700 border-red-200'
                        : finding.severity === 'HIGH'
                        ? 'bg-orange-50 text-orange-700 border-orange-200'
                        : 'bg-amber-50 text-amber-800 border-amber-200'
                    }`}
                  >
                    <ShieldAlert className="w-5 h-5" />
                  </div>

                  <div>
                    <div className="flex items-center space-x-2 flex-wrap gap-y-1 mb-1">
                      <span
                        className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                          finding.severity === 'CRITICAL'
                            ? 'bg-red-600 text-white'
                            : finding.severity === 'HIGH'
                            ? 'bg-orange-600 text-white'
                            : 'bg-amber-600 text-white'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 font-mono">
                        {finding.category.toUpperCase().replace('_', ' ')}
                      </span>
                      {finding.compliance.cisAzure && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-50 text-slate-700 border border-slate-200 font-mono">
                          CIS {finding.compliance.cisAzure}
                        </span>
                      )}
                      {finding.compliance.nist && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-mono">
                          NIST {finding.compliance.nist}
                        </span>
                      )}
                    </div>

                    <h3 className="text-sm font-bold text-slate-900">
                      {finding.title}
                    </h3>

                    <div className="text-xs text-slate-500 mt-0.5 font-mono">
                      Resource:{' '}
                      <span className="text-slate-800 font-semibold">
                        {finding.resourceName}
                      </span>{' '}
                      ({finding.resourceType})
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  {onRemediateFinding && (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onRemediateFinding(finding.id);
                      }}
                      className="px-3 py-1.5 rounded-md text-xs font-semibold bg-emerald-50 hover:bg-[#2BB5A0] text-emerald-800 hover:text-[#04211B] border border-emerald-200 transition-all cursor-pointer"
                    >
                      Harden
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectFinding(finding.id);
                    }}
                    className="hidden sm:inline-flex px-3 py-1.5 rounded-md text-xs font-semibold bg-[#0E2238] hover:bg-[#081420] text-[#EEF3F1] transition-all cursor-pointer"
                  >
                    Deep Dive
                  </button>
                  <div className="p-1 rounded-lg text-slate-500 hover:text-slate-900">
                    {isExpanded ? (
                      <ChevronUp className="w-5 h-5" />
                    ) : (
                      <ChevronDown className="w-5 h-5" />
                    )}
                  </div>
                </div>
              </div>

              {/* Expanded Remediation Drawer */}
              {isExpanded && (
                <div className="px-5 pb-5 pt-3 border-t border-slate-200 space-y-4">
                  {/* Exploit Scenario & Impact */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-50 p-3.5 rounded-lg border border-slate-200">
                    <div>
                      <span className="font-bold text-slate-900 block mb-1">
                        Threat Mechanics &amp; Exploit Vector:
                      </span>
                      <p className="text-slate-600 leading-relaxed">
                        {finding.exploitScenario}
                      </p>
                    </div>
                    <div>
                      <span className="font-bold text-slate-900 block mb-1">
                        Business &amp; Compliance Impact:
                      </span>
                      <p className="text-slate-600 leading-relaxed">
                        {finding.businessImpact}
                      </p>
                    </div>
                  </div>

                  {/* Remediation Tabs */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
                        <button
                          type="button"
                          onClick={() => setActiveRemediationTab('cli')}
                          className={`flex items-center space-x-1.5 px-3 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                            activeRemediationTab === 'cli'
                              ? 'bg-[#0E2238] text-[#EEF3F1]'
                              : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Azure CLI</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveRemediationTab('portal')}
                          className={`flex items-center space-x-1.5 px-3 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                            activeRemediationTab === 'portal'
                              ? 'bg-[#0E2238] text-[#EEF3F1]'
                              : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <Globe className="w-3.5 h-3.5" />
                          <span>Azure Portal</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveRemediationTab('terraform')}
                          className={`flex items-center space-x-1.5 px-3 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                            activeRemediationTab === 'terraform'
                              ? 'bg-[#0E2238] text-[#EEF3F1]'
                              : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <Code2 className="w-3.5 h-3.5" />
                          <span>Terraform IaC</span>
                        </button>
                      </div>

                      {activeRemediationTab === 'cli' && (
                        <button
                          type="button"
                          onClick={() =>
                            copyToClipboard(
                              finding.remediation.cliCommand,
                              finding.id
                            )
                          }
                          className="text-xs text-emerald-700 hover:underline font-mono flex items-center space-x-1 cursor-pointer"
                        >
                          {copiedId === finding.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-700" />
                              <span>Copied to Clipboard!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>Copy Command</span>
                            </>
                          )}
                        </button>
                      )}
                    </div>

                    {/* Tab Contents */}
                    {activeRemediationTab === 'cli' && (
                      <div className="bg-[#081420] p-3.5 rounded-lg border border-[#3E6E86]/40 text-[#5FD3BF] font-mono text-xs overflow-x-auto whitespace-pre">
                        {finding.remediation.cliCommand}
                      </div>
                    )}

                    {activeRemediationTab === 'portal' && (
                      <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200 space-y-2">
                        {finding.remediation.portalSteps.map((step, idx) => (
                          <div
                            key={idx}
                            className="flex items-start space-x-2 text-xs text-slate-700"
                          >
                            <span className="w-5 h-5 rounded-full bg-[#0E2238] text-[#EEF3F1] flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0 mt-0.5">
                              {idx + 1}
                            </span>
                            <span className="leading-relaxed">{step}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {activeRemediationTab === 'terraform' && (
                      <div className="bg-[#081420] p-3.5 rounded-lg border border-[#3E6E86]/40 text-[#EBC385] font-mono text-xs overflow-x-auto whitespace-pre">
                        {finding.remediation.terraformSnippet}
                      </div>
                    )}
                  </div>

                  {/* Impact Notice */}
                  <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-900 text-xs flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-700" />
                    <span>
                      <strong>Operational Considerations: </strong>
                      {finding.remediation.impactNotice}
                    </span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Session Remediation Log inside Remediation Register */}
      <RemediationLog
        entries={remediationLog}
        onClearLog={onClearRemediationLog}
      />
    </div>
  );
};
