/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Terminal,
  Globe,
  Code2,
  Copy,
  Check,
  AlertTriangle,
  FileCheck2,
  Lock,
  ArrowRight,
  ExternalLink,
} from 'lucide-react';
import { Finding } from '../types/security';

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onRemediate?: (findingId: string) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onRemediate,
}) => {
  const [activeTab, setActiveTab] = useState<'cli' | 'portal' | 'terraform'>('cli');
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isCritical = finding.severity === 'CRITICAL';
  const isHigh = finding.severity === 'HIGH';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl p-6 text-slate-100 space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          aria-label="Close dialog"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-start space-x-3.5 pr-10">
          <div
            className={`p-3 rounded-2xl flex-shrink-0 ${
              isCritical
                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                : isHigh
                ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
            }`}
          >
            <ShieldAlert className="w-7 h-7" />
          </div>

          <div>
            <div className="flex items-center space-x-2 flex-wrap gap-y-1 mb-1">
              <span
                className={`text-xs font-black uppercase tracking-wider px-2.5 py-0.5 rounded-full ${
                  isCritical
                    ? 'bg-red-600 text-white'
                    : isHigh
                    ? 'bg-orange-600 text-white'
                    : 'bg-amber-600 text-white'
                }`}
              >
                {finding.severity}
              </span>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                {finding.category.toUpperCase().replace('_', ' ')}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                ID: {finding.id}
              </span>
            </div>

            <h2 className="text-lg sm:text-xl font-extrabold text-white">
              {finding.title}
            </h2>
            <div className="text-xs text-slate-400 mt-1 font-mono">
              Target: <span className="text-blue-400 font-semibold">{finding.resourceName}</span> ({finding.resourceType})
            </div>
          </div>
        </div>

        {/* Description & Threat Mechanics */}
        <div className="space-y-3 bg-slate-950/70 p-4 rounded-2xl border border-slate-800">
          <div>
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-1">
              Vulnerability Overview:
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              {finding.description}
            </p>
          </div>

          <div>
            <h4 className="text-xs font-bold text-red-400 uppercase tracking-wider mb-1">
              Adversary Exploit Scenario:
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              {finding.exploitScenario}
            </p>
          </div>

          {finding.privilegeEscalationPath && (
            <div className="pt-2 border-t border-slate-800">
              <h4 className="text-xs font-bold text-purple-400 uppercase tracking-wider mb-1">
                Privilege Escalation Path:
              </h4>
              <div className="p-2.5 rounded-xl bg-purple-950/40 border border-purple-500/30 font-mono text-xs text-purple-200">
                {finding.privilegeEscalationPath}
              </div>
            </div>
          )}
        </div>

        {/* Actionable Remediation Runbook */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white tracking-wide flex items-center space-x-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <span>Actionable Remediation Runbook</span>
            </h3>

            {/* Tab switchers */}
            <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
              <button
                onClick={() => setActiveTab('cli')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg font-semibold transition-all ${
                  activeTab === 'cli'
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Azure CLI</span>
              </button>
              <button
                onClick={() => setActiveTab('portal')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg font-semibold transition-all ${
                  activeTab === 'portal'
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Azure Portal</span>
              </button>
              <button
                onClick={() => setActiveTab('terraform')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg font-semibold transition-all ${
                  activeTab === 'terraform'
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>Terraform</span>
              </button>
            </div>
          </div>

          {/* Active Tab View */}
          {activeTab === 'cli' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Run this command via Azure Cloud Shell or Bash:</span>
                <button
                  onClick={() => copyToClipboard(finding.remediation.cliCommand)}
                  className="flex items-center space-x-1 text-blue-400 hover:text-blue-300 font-medium"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy CLI Script</span>
                    </>
                  )}
                </button>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                {finding.remediation.cliCommand}
              </div>
            </div>
          )}

          {activeTab === 'portal' && (
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2.5">
              <div className="text-xs font-semibold text-slate-300 mb-2">
                Click-by-click instructions in Azure Management Portal:
              </div>
              {finding.remediation.portalSteps.map((step, idx) => (
                <div key={idx} className="flex items-start space-x-2.5 text-xs text-slate-300">
                  <span className="w-5 h-5 rounded-full bg-blue-600/30 text-blue-400 border border-blue-500/40 flex items-center justify-center font-bold text-[10px] flex-shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <span className="leading-relaxed">{step}</span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'terraform' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Infrastructure as Code (Terraform azurerm provider):</span>
                <button
                  onClick={() => copyToClipboard(finding.remediation.terraformSnippet)}
                  className="flex items-center space-x-1 text-blue-400 hover:text-blue-300 font-medium"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Terraform</span>
                    </>
                  )}
                </button>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-purple-300 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                {finding.remediation.terraformSnippet}
              </div>
            </div>
          )}

          {/* Operational Impact Banner */}
          <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center space-x-2.5">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-400" />
            <span>
              <strong>Operational Consideration: </strong>
              {finding.remediation.impactNotice}
            </span>
          </div>
        </div>

        {/* Compliance Mappings */}
        <div className="pt-2 border-t border-slate-800 flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center space-x-2 text-slate-400">
            <FileCheck2 className="w-4 h-4 text-blue-400" />
            <span>Benchmark Mappings:</span>
            {finding.compliance.cisAzure && (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                CIS Azure {finding.compliance.cisAzure}
              </span>
            )}
            {finding.compliance.mcsb && (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                {finding.compliance.mcsb}
              </span>
            )}
            {finding.compliance.nist && (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                NIST {finding.compliance.nist}
              </span>
            )}
          </div>

          <button
            onClick={() => {
              if (onRemediate) onRemediate(finding.id);
              onClose();
            }}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-md shadow-emerald-600/20 transition-all ml-auto"
          >
            Acknowledge & Mark Remediated
          </button>
        </div>
      </div>
    </div>
  );
};
