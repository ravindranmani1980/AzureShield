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
  RotateCcw,
  SearchCheck,
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#081420]/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto bg-white border border-slate-200 rounded-2xl shadow-2xl p-6 text-[#16232F] space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-lg text-[#546471] hover:text-[#16232F] hover:bg-slate-100 transition-colors"
          aria-label="Close dialog"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-start space-x-3.5 pr-10">
          <div
            className={`p-3 rounded-xl flex-shrink-0 border ${
              isCritical
                ? 'bg-red-50 text-red-600 border-red-200'
                : isHigh
                ? 'bg-orange-50 text-orange-600 border-orange-200'
                : 'bg-amber-50 text-amber-700 border-amber-200'
            }`}
          >
            <ShieldAlert className="w-7 h-7" />
          </div>

          <div>
            <div className="flex items-center space-x-2 flex-wrap gap-y-1 mb-1 font-mono text-xs">
              <span
                className={`font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                  isCritical
                    ? 'bg-red-600 text-white'
                    : isHigh
                    ? 'bg-orange-600 text-white'
                    : 'bg-amber-600 text-white'
                }`}
              >
                {finding.severity}
              </span>
              {finding.findingType === 'guardrail_gap' && (
                <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-900 font-bold">
                  GUARDRAIL GAP (0 PUBLIC CONTAINERS)
                </span>
              )}
              {finding.findingType === 'confirmed_exposure' && (
                <span className="px-2 py-0.5 rounded bg-red-100 text-red-800 font-bold">
                  CONFIRMED ANONYMOUS EXPOSURE
                </span>
              )}
              <span className="text-[#546471]">
                {finding.category.toUpperCase().replace('_', ' ')}
              </span>
              <span className="text-slate-300">·</span>
              <span className="text-[#546471]">ID: {finding.id}</span>
            </div>

            <h2 className="font-serif text-lg sm:text-xl font-bold text-[#16232F]">
              {finding.title}
            </h2>
            <div className="text-xs text-[#546471] mt-1 font-mono">
              Target: <span className="text-[#1F8A79] font-semibold">{finding.resourceName}</span> ({finding.resourceType})
            </div>
          </div>
        </div>

        {/* Description & Threat Mechanics */}
        <div className="space-y-3 bg-slate-50 p-4 rounded-xl border border-slate-200">
          <div>
            <h4 className="rm-kicker mb-1">
              Technical Finding Overview
            </h4>
            <p className="text-xs text-[#16232F] leading-relaxed">
              {finding.description}
            </p>
          </div>

          <div>
            <h4 className="text-[11px] font-mono font-bold text-red-700 uppercase tracking-wider mb-1">
              Potential Risk Scenario
            </h4>
            <p className="text-xs text-[#546471] leading-relaxed">
              {finding.exploitScenario}
            </p>
          </div>

          {finding.privilegeEscalationPath && (
            <div className="pt-2 border-t border-slate-200">
              <h4 className="text-[11px] font-mono font-bold text-purple-800 uppercase tracking-wider mb-1">
                Privilege Escalation Path
              </h4>
              <div className="p-2.5 rounded-lg bg-purple-50 border border-purple-200 font-mono text-xs text-purple-900">
                {finding.privilegeEscalationPath}
              </div>
            </div>
          )}
        </div>

        {/* Actionable Remediation Runbook (Rec #14: Pre-Check, CLI, Rollback & Staging Validation) */}
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-serif text-sm font-bold text-[#16232F] flex items-center space-x-2">
              <Lock className="w-4 h-4 text-[#1F8A79]" />
              <span>Safe Remediation Runbook (Pre-Check, CLI &amp; Rollback)</span>
            </h3>

            {/* Tab switchers */}
            <div className="flex items-center space-x-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
              <button
                onClick={() => setActiveTab('cli')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-md font-semibold transition-all ${
                  activeTab === 'cli'
                    ? 'bg-[#0E2238] text-white'
                    : 'text-[#546471] hover:text-[#16232F]'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Azure CLI + Rollback</span>
              </button>
              <button
                onClick={() => setActiveTab('portal')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-md font-semibold transition-all ${
                  activeTab === 'portal'
                    ? 'bg-[#0E2238] text-white'
                    : 'text-[#546471] hover:text-[#16232F]'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Azure Portal</span>
              </button>
              <button
                onClick={() => setActiveTab('terraform')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-md font-semibold transition-all ${
                  activeTab === 'terraform'
                    ? 'bg-[#0E2238] text-white'
                    : 'text-[#546471] hover:text-[#16232F]'
                }`}
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>Terraform</span>
              </button>
            </div>
          </div>

          {/* Active Tab View */}
          {activeTab === 'cli' && (
            <div className="space-y-3">
              {/* Step 1: Read-Only Pre-Check */}
              {finding.remediation.preCheckCommand && (
                <div className="space-y-1">
                  <div className="flex items-center space-x-1.5 text-xs font-semibold text-[#1F8A79]">
                    <SearchCheck className="w-3.5 h-3.5" />
                    <span>1. Read-Only Pre-Check &amp; State Backup (Run First):</span>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-xl border border-slate-800 text-slate-200 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                    {finding.remediation.preCheckCommand}
                  </div>
                </div>
              )}

              {/* Step 2: Remediation Command */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs text-[#546471]">
                  <span className="font-semibold text-[#16232F]">
                    2. Remediation Command (Validate in Staging Before Production):
                  </span>
                  <button
                    onClick={() => copyToClipboard(finding.remediation.cliCommand)}
                    className="flex items-center space-x-1 text-[#1F8A79] hover:text-[#15695B] font-semibold"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-[#1F8A79]" />
                        <span>Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy CLI Script</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="bg-[#081420] p-4 rounded-xl border border-slate-800 text-[#5FD3BF] font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                  {finding.remediation.cliCommand}
                </div>
              </div>

              {/* Step 3: Emergency Rollback Command */}
              {finding.remediation.rollbackCommand && (
                <div className="space-y-1">
                  <div className="flex items-center space-x-1.5 text-xs font-semibold text-amber-800">
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>3. Emergency Rollback Command (If Workload Impact Occurs):</span>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-xl border border-slate-800 text-[#EBC385] font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                    {finding.remediation.rollbackCommand}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'portal' && (
            <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-2.5">
              <div className="text-xs font-semibold text-[#16232F] mb-2">
                Click-by-click instructions in Azure Management Portal:
              </div>
              {finding.remediation.portalSteps.map((step, idx) => (
                <div key={idx} className="flex items-start space-x-2.5 text-xs text-[#16232F]">
                  <span className="w-5 h-5 rounded-full bg-[#0E2238] text-[#5FD3BF] flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <span className="leading-relaxed">{step}</span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'terraform' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-[#546471]">
                <span>Infrastructure as Code (Terraform azurerm provider):</span>
                <button
                  onClick={() => copyToClipboard(finding.remediation.terraformSnippet)}
                  className="flex items-center space-x-1 text-[#1F8A79] hover:text-[#15695B] font-semibold"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[#1F8A79]" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Terraform</span>
                    </>
                  )}
                </button>
              </div>
              <div className="bg-[#081420] p-4 rounded-xl border border-slate-800 text-[#EBC385] font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                {finding.remediation.terraformSnippet}
              </div>
            </div>
          )}

          {/* Operational Impact Banner */}
          <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-amber-900 text-xs flex items-center space-x-2.5">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-600" />
            <span>
              <strong>Operational &amp; Staging Consideration (Rec #14): </strong>
              {finding.remediation.impactNotice}
            </span>
          </div>
        </div>

        {/* Informational Compliance Mappings & In-Memory Acknowledge (Rec #6 & #9) */}
        <div className="pt-3 border-t border-slate-200 flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center space-x-2 text-[#546471] font-mono">
            <FileCheck2 className="w-4 h-4 text-[#1F8A79]" />
            <span>Informational Cross-Refs:</span>
            {finding.compliance.cisAzure && (
              <span>CIS Azure {finding.compliance.cisAzure}</span>
            )}
            {finding.compliance.mcsb && (
              <>
                <span className="text-slate-300">·</span>
                <span>{finding.compliance.mcsb}</span>
              </>
            )}
            {finding.compliance.nist && (
              <>
                <span className="text-slate-300">·</span>
                <span>NIST {finding.compliance.nist}</span>
              </>
            )}
          </div>

          <button
            onClick={() => {
              if (onRemediate) onRemediate(finding.id);
              onClose();
            }}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all ml-auto"
          >
            Acknowledge in Session UI (Unverified in Azure)
          </button>
        </div>
      </div>
    </div>
  );
};
