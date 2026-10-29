/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Download,
  Terminal,
  Globe,
  Code2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  FileCode,
  Layers,
  Sparkles,
} from 'lucide-react';
import { Finding, Severity, VulnerabilityCategory } from '../types/security';

interface FindingsListProps {
  findings: Finding[];
  onSelectFinding: (findingId: string) => void;
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  onSelectFinding,
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
    const header = `#!/usr/bin/env bash\n# =========================================================\n# AzureShield Automated Remediation Script\n# Generated: ${new Date().toISOString()}\n# Total Issues Addressed: ${findings.length}\n# =========================================================\nset -euo pipefail\n\necho "[+] Starting Azure Cloud Hardening..."\n\n`;
    const commands = findings.map((f, i) => `# [${f.severity}] #${i + 1}: ${f.title}\n${f.remediation.cliCommand}\n`).join('\n');
    const footer = `\necho "[+] All Azure remediation commands applied successfully."\n`;
    
    const blob = new Blob([header + commands + footer], { type: 'text/x-shellscript' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `azure_remediation_${Date.now()}.sh`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Search Bar */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Remediation Register & Action Runbooks
            </h2>
            <p className="text-xs text-slate-400">
              Complete catalog of detected storage loopholes, unauthorized RBAC access, and step-by-step remediation commands.
            </p>
          </div>

          <button
            onClick={generateRemediationBashScript}
            className="flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/20 transition-all self-start sm:self-center"
            title="Download unified Bash script with all Azure CLI remediation commands"
          >
            <Download className="w-4 h-4" />
            <span>Export az_remediation.sh</span>
          </button>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pt-3 border-t border-slate-800">
          <div className="flex items-center space-x-2 overflow-x-auto pb-1 lg:pb-0">
            {/* Severity Filter */}
            <div className="flex items-center space-x-1 bg-slate-950/80 p-1 rounded-xl border border-slate-800 text-xs">
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`px-2.5 py-1 rounded-lg font-semibold transition-all ${
                    selectedSeverity === sev
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
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
              className="bg-slate-950/80 border border-slate-800 text-slate-300 text-xs rounded-xl px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer"
            >
              <option value="ALL">All Categories</option>
              <option value="storage">Storage & Containers</option>
              <option value="rbac">RBAC & IAM</option>
              <option value="privilege_escalation">Privilege Escalation</option>
              <option value="network">Network Perimeter</option>
              <option value="encryption">Encryption & TLS</option>
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
              className="w-full bg-slate-950/80 border border-slate-800 text-slate-200 text-xs rounded-xl pl-9 pr-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>
      </div>

      {/* Findings Count Summary */}
      <div className="flex items-center justify-between text-xs text-slate-400 px-1">
        <span>
          Showing <strong>{filteredFindings.length}</strong> of{' '}
          <strong>{findings.length}</strong> security loophole(s)
        </span>
      </div>

      {/* Findings Accordion / Card Register */}
      <div className="space-y-3">
        {filteredFindings.map((finding) => {
          const isExpanded = expandedFindingId === finding.id;

          return (
            <div
              key={finding.id}
              className={`rounded-2xl border transition-all ${
                finding.severity === 'CRITICAL'
                  ? 'bg-slate-900/90 border-red-500/30 hover:border-red-500/50'
                  : finding.severity === 'HIGH'
                  ? 'bg-slate-900/90 border-orange-500/30 hover:border-orange-500/50'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700'
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
                    className={`p-2 rounded-xl flex-shrink-0 mt-0.5 ${
                      finding.severity === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : finding.severity === 'HIGH'
                        ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    <ShieldAlert className="w-5 h-5" />
                  </div>

                  <div>
                    <div className="flex items-center space-x-2 flex-wrap gap-y-1 mb-1">
                      <span
                        className={`text-[10px] font-black uppercase px-2 py-0.5 rounded ${
                          finding.severity === 'CRITICAL'
                            ? 'bg-red-600 text-white'
                            : finding.severity === 'HIGH'
                            ? 'bg-orange-600 text-white'
                            : 'bg-amber-600 text-white'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                        {finding.category.toUpperCase().replace('_', ' ')}
                      </span>
                      {finding.compliance.cisAzure && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                          CIS {finding.compliance.cisAzure}
                        </span>
                      )}
                      {finding.compliance.nist && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                          NIST {finding.compliance.nist}
                        </span>
                      )}
                    </div>

                    <h3 className="text-sm font-bold text-white">
                      {finding.title}
                    </h3>

                    <div className="text-xs text-slate-400 mt-0.5 font-mono">
                      Resource: <span className="text-slate-200">{finding.resourceName}</span> ({finding.resourceType})
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectFinding(finding.id);
                    }}
                    className="hidden sm:inline-flex px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all"
                  >
                    Deep Dive
                  </button>
                  <div className="p-1 rounded-lg text-slate-400 hover:text-white">
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
                <div className="px-5 pb-5 pt-1 border-t border-slate-800/80 space-y-4 animate-in fade-in duration-150">
                  {/* Exploit Scenario & Impact */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
                    <div>
                      <span className="font-bold text-slate-200 block mb-1">
                        Threat Mechanics & Exploit Vector:
                      </span>
                      <p className="text-slate-400 leading-relaxed">
                        {finding.exploitScenario}
                      </p>
                    </div>
                    <div>
                      <span className="font-bold text-slate-200 block mb-1">
                        Business & Compliance Impact:
                      </span>
                      <p className="text-slate-400 leading-relaxed">
                        {finding.businessImpact}
                      </p>
                    </div>
                  </div>

                  {/* Remediation Tabs */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
                        <button
                          onClick={() => setActiveRemediationTab('cli')}
                          className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg font-semibold transition-all ${
                            activeRemediationTab === 'cli'
                              ? 'bg-blue-600 text-white shadow-sm'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Azure CLI</span>
                        </button>
                        <button
                          onClick={() => setActiveRemediationTab('portal')}
                          className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg font-semibold transition-all ${
                            activeRemediationTab === 'portal'
                              ? 'bg-blue-600 text-white shadow-sm'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          <Globe className="w-3.5 h-3.5" />
                          <span>Azure Portal</span>
                        </button>
                        <button
                          onClick={() => setActiveRemediationTab('terraform')}
                          className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg font-semibold transition-all ${
                            activeRemediationTab === 'terraform'
                              ? 'bg-blue-600 text-white shadow-sm'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          <Code2 className="w-3.5 h-3.5" />
                          <span>Terraform IaC</span>
                        </button>
                      </div>

                      {activeRemediationTab === 'cli' && (
                        <button
                          onClick={() =>
                            copyToClipboard(
                              finding.remediation.cliCommand,
                              finding.id
                            )
                          }
                          className="text-xs text-blue-400 hover:text-blue-300 flex items-center space-x-1"
                        >
                          {copiedId === finding.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span className="text-emerald-400">Copied to Clipboard!</span>
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
                      <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto whitespace-pre">
                        {finding.remediation.cliCommand}
                      </div>
                    )}

                    {activeRemediationTab === 'portal' && (
                      <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                        {finding.remediation.portalSteps.map((step, idx) => (
                          <div
                            key={idx}
                            className="flex items-start space-x-2 text-xs text-slate-300"
                          >
                            <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30 flex items-center justify-center font-bold text-[10px] flex-shrink-0 mt-0.5">
                              {idx + 1}
                            </span>
                            <span className="leading-relaxed">{step}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {activeRemediationTab === 'terraform' && (
                      <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-purple-300 font-mono text-xs overflow-x-auto whitespace-pre">
                        {finding.remediation.terraformSnippet}
                      </div>
                    )}
                  </div>

                  {/* Impact Notice */}
                  <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-400" />
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
    </div>
  );
};
