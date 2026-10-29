/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Server,
  FolderLock,
  FolderCheck,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Terminal,
  Globe,
  Radio,
  ExternalLink,
  ChevronRight,
  Database,
  Copy,
  Check,
} from 'lucide-react';
import { StorageAccount, Finding } from '../types/security';

interface StorageAuditorProps {
  storageAccounts: StorageAccount[];
  findings: Finding[];
  onSelectFinding: (findingId: string) => void;
  onRemediateAccount?: (accountName: string, action: string) => void;
}

export const StorageAuditor: React.FC<StorageAuditorProps> = ({
  storageAccounts,
  findings,
  onSelectFinding,
  onRemediateAccount,
}) => {
  const [selectedAccountName, setSelectedAccountName] = useState<string>(
    storageAccounts[0]?.name || ''
  );
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const selectedAccount =
    storageAccounts.find((a) => a.name === selectedAccountName) ||
    storageAccounts[0];

  const accountFindings = findings.filter(
    (f) =>
      f.resourceName.includes(selectedAccount?.name || '') ||
      f.resourceId.includes(selectedAccount?.name || '')
  );

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg">
        <div className="flex items-center space-x-3">
          <div className="p-3 rounded-xl bg-blue-500/20 text-blue-400 border border-blue-500/30">
            <Server className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Maniq Shield — Azure Blob Storage & Containers Audit
            </h2>
            <p className="text-xs text-slate-400">
              Identifying anonymous container exposure, insecure HTTP transfer, deprecated TLS, and unexpired SAS policies.
            </p>
          </div>
        </div>

        {/* Account Selector Pill */}
        <div className="flex items-center space-x-2 overflow-x-auto pb-1 sm:pb-0">
          {storageAccounts.map((account) => {
            const hasCrit = findings.some(
              (f) =>
                f.severity === 'CRITICAL' &&
                (f.resourceName.includes(account.name) ||
                  f.resourceId.includes(account.name))
            );
            return (
              <button
                key={account.name}
                onClick={() => setSelectedAccountName(account.name)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all whitespace-nowrap ${
                  selectedAccountName === account.name
                    ? 'bg-blue-600 text-white border-blue-500 shadow-md shadow-blue-500/20'
                    : 'bg-slate-950/60 text-slate-300 border-slate-800 hover:bg-slate-800'
                }`}
              >
                <span>{account.name}</span>
                {hasCrit && (
                  <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {selectedAccount && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Security Control Posture Checklist */}
          <div className="lg:col-span-5 space-y-4">
            <div className="bg-slate-900 rounded-2xl p-5 border border-slate-800 shadow-lg">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
                <div>
                  <h3 className="font-bold text-white text-sm">
                    {selectedAccount.name}
                  </h3>
                  <span className="text-[11px] font-mono text-slate-400">
                    RG: {selectedAccount.resourceGroup} • {selectedAccount.location}
                  </span>
                </div>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${
                    accountFindings.some((f) => f.severity === 'CRITICAL')
                      ? 'bg-red-500/20 text-red-400 border-red-500/30'
                      : accountFindings.length > 0
                      ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                  }`}
                >
                  {accountFindings.length} Loopholes Detected
                </span>
              </div>

              {/* Security Controls Table */}
              <div className="space-y-3">
                {/* 1. Public Blob Access */}
                <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.allowBlobPublicAccess ? (
                      <Unlock className="w-4 h-4 text-red-400 flex-shrink-0" />
                    ) : (
                      <Lock className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-200">
                        Allow Blob Public Access
                      </div>
                      <div className="text-[10px] text-slate-400">
                        CIS Azure Control 3.7
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-bold px-2 py-0.5 rounded ${
                      selectedAccount.allowBlobPublicAccess
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}
                  >
                    {selectedAccount.allowBlobPublicAccess ? 'ALLOWED (Vulnerable)' : 'Disabled (Secure)'}
                  </span>
                </div>

                {/* 2. Secure Transfer Required (HTTPS) */}
                <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.supportsHttpsTrafficOnly ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-200">
                        Secure Transfer Required
                      </div>
                      <div className="text-[10px] text-slate-400">
                        CIS Azure Control 3.1
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-bold px-2 py-0.5 rounded ${
                      selectedAccount.supportsHttpsTrafficOnly
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-red-500/20 text-red-400 border border-red-500/30'
                    }`}
                  >
                    {selectedAccount.supportsHttpsTrafficOnly ? 'HTTPS Only' : 'HTTP Allowed (Insecure)'}
                  </span>
                </div>

                {/* 3. Minimum TLS Version */}
                <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.minimumTlsVersion === 'TLS1_2' ||
                    selectedAccount.minimumTlsVersion === 'TLS1_3' ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-orange-400 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-200">
                        Minimum TLS Protocol
                      </div>
                      <div className="text-[10px] text-slate-400">
                        CIS Azure Control 3.8
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-bold px-2 py-0.5 rounded font-mono ${
                      selectedAccount.minimumTlsVersion === 'TLS1_2' ||
                      selectedAccount.minimumTlsVersion === 'TLS1_3'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                    }`}
                  >
                    {selectedAccount.minimumTlsVersion}
                  </span>
                </div>

                {/* 4. Public Network Access & Firewall */}
                <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.publicNetworkAccess === 'Disabled' ||
                    selectedAccount.defaultAction === 'Deny' ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <Globe className="w-4 h-4 text-orange-400 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-200">
                        Network Firewall & Perimeter
                      </div>
                      <div className="text-[10px] text-slate-400">
                        {selectedAccount.ipRulesCount} IP Rules • {selectedAccount.privateEndpointConnectionsCount} Private Endpoints
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-bold px-2 py-0.5 rounded ${
                      selectedAccount.publicNetworkAccess === 'Disabled' ||
                      selectedAccount.defaultAction === 'Deny'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                    }`}
                  >
                    {selectedAccount.publicNetworkAccess === 'Enabled' && selectedAccount.defaultAction === 'Allow'
                      ? 'Open to All Internet'
                      : 'Restricted / Private'}
                  </span>
                </div>

                {/* 5. Soft Delete Protection */}
                <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.softDeleteEnabled ? (
                      <FolderCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <FolderLock className="w-4 h-4 text-amber-400 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-200">
                        Blob Soft Delete (Ransomware)
                      </div>
                      <div className="text-[10px] text-slate-400">
                        {selectedAccount.softDeleteEnabled
                          ? `${selectedAccount.blobRetentionDays} Days Retention`
                          : 'Immediate Permanent Deletion'}
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-bold px-2 py-0.5 rounded ${
                      selectedAccount.softDeleteEnabled
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {selectedAccount.softDeleteEnabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </div>
            </div>

            {/* Containers List */}
            <div className="bg-slate-900 rounded-2xl p-5 border border-slate-800 shadow-lg">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2">
                  <Database className="w-4 h-4 text-blue-400" />
                  <h3 className="font-bold text-white text-sm">
                    Blob Containers ({selectedAccount.containers.length})
                  </h3>
                </div>
                <span className="text-[11px] text-slate-400">
                  Anonymous Read Access Audit
                </span>
              </div>

              <div className="space-y-2.5">
                {selectedAccount.containers.map((container) => {
                  const isExposed = container.publicAccess !== 'None';
                  return (
                    <div
                      key={container.name}
                      className={`p-3 rounded-xl border transition-all ${
                        isExposed
                          ? 'bg-red-950/20 border-red-500/40 text-slate-200'
                          : 'bg-slate-950/60 border-slate-800/80 text-slate-300'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-xs font-bold text-white">
                            {container.name}
                          </span>
                          {container.dataClassification && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-medium">
                              {container.dataClassification}
                            </span>
                          )}
                        </div>
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                            container.publicAccess === 'Container'
                              ? 'bg-red-600 text-white animate-pulse'
                              : container.publicAccess === 'Blob'
                              ? 'bg-red-500/30 text-red-300 border border-red-500/40'
                              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          {container.publicAccess === 'None'
                            ? 'Private (Secure)'
                            : `PUBLIC (${container.publicAccess})`}
                        </span>
                      </div>

                      <div className="text-[11px] text-slate-400 flex items-center justify-between mt-2 pt-2 border-t border-slate-800/60">
                        <span>
                          {container.blobCount?.toLocaleString() || '0'} Stored Blobs
                        </span>
                        {container.hasStoredAccessPolicyWithNoExpiry && (
                          <span className="text-amber-400 font-semibold text-[10px]">
                            ⚠️ Perpetual SAS Policy
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Right Column: Identified Findings & Instant Remediation Commands */}
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-slate-900 rounded-2xl p-5 border border-slate-800 shadow-lg">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="font-bold text-white text-sm tracking-wide">
                    STORAGE VULNERABILITY FINDINGS & RUNBOOKS
                  </h3>
                  <p className="text-xs text-slate-400">
                    Remediation commands ready for execution via Azure CLI or Portal
                  </p>
                </div>
                <span className="text-xs text-blue-400 font-mono">
                  {accountFindings.length} Action Items
                </span>
              </div>

              {accountFindings.length === 0 ? (
                <div className="py-12 text-center text-slate-400 bg-slate-950/40 rounded-xl border border-slate-800">
                  <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                  <p className="text-sm font-semibold text-slate-200">
                    Zero Vulnerabilities Detected in {selectedAccount.name}
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    Compliant with CIS Azure Foundations 3.x storage benchmarks.
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {accountFindings.map((finding) => (
                    <div
                      key={finding.id}
                      className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition-all space-y-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <span
                              className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                                finding.severity === 'CRITICAL'
                                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                  : finding.severity === 'HIGH'
                                  ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                                  : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              }`}
                            >
                              {finding.severity}
                            </span>
                            {finding.compliance.cisAzure && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                                CIS {finding.compliance.cisAzure}
                              </span>
                            )}
                          </div>
                          <h4 className="text-sm font-bold text-white">
                            {finding.title}
                          </h4>
                        </div>

                        <button
                          onClick={() => onSelectFinding(finding.id)}
                          className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center space-x-1 whitespace-nowrap"
                        >
                          <span>Full Runbook</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed">
                        {finding.description}
                      </p>

                      {/* Monospace Azure CLI Remediation Block */}
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] text-slate-400 font-medium">
                          <span className="flex items-center space-x-1">
                            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Azure CLI Hardening Command:</span>
                          </span>
                          <button
                            onClick={() =>
                              copyToClipboard(finding.remediation.cliCommand, finding.id)
                            }
                            className="text-blue-400 hover:text-blue-300 flex items-center space-x-1 text-[10px]"
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
                        <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto whitespace-pre">
                          {finding.remediation.cliCommand}
                        </div>
                      </div>

                      {/* Operational Impact Notice */}
                      <div className="text-[11px] text-amber-300/90 bg-amber-500/10 p-2 rounded-lg border border-amber-500/20">
                        <span className="font-semibold">Operational Impact: </span>
                        {finding.remediation.impactNotice}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
