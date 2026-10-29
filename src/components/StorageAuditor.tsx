/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  FolderLock,
  FolderCheck,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Terminal,
  Globe,
  Database,
  Copy,
  Check,
  ChevronRight,
  Network,
} from 'lucide-react';
import { StorageAccount, Finding, RbacAssignment } from '../types/security';
import { StorageAccessGraphD3 } from './StorageAccessGraphD3';

interface StorageAuditorProps {
  storageAccounts: StorageAccount[];
  roleAssignments?: RbacAssignment[];
  findings: Finding[];
  onSelectFinding: (findingId: string) => void;
  onRemediateAccount?: (accountName: string, action: string) => void;
}

export const StorageAuditor: React.FC<StorageAuditorProps> = ({
  storageAccounts,
  roleAssignments = [],
  findings,
  onSelectFinding,
}) => {
  const [selectedAccountName, setSelectedAccountName] = useState<string>(
    storageAccounts[0]?.name || ''
  );
  const [showTopologyGraph, setShowTopologyGraph] = useState<boolean>(true);
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
      {/* Header (.xh-panel) */}
      <section className="xh-panel space-y-4">
        <div className="xh-kicker">
          <span className="k">Azure Blob Storage &amp; Container Auditor</span>
          <span className="tag">{storageAccounts.length} Storage Accounts Indexed</span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl sm:text-2xl font-semibold text-[#EEF3F1] tracking-tight">
              Maniq Shield — Azure Blob Storage &amp; Containers Audit
            </h2>
            <p className="text-xs text-[#A9B7BF] mt-1">
              Identifying anonymous container exposure, RBAC access paths, insecure HTTP transfer, deprecated TLS, and unexpired SAS policies.
            </p>
          </div>

          {/* Account Selector & Graph Toggle */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setShowTopologyGraph(!showTopologyGraph)}
              className="xh-btn whitespace-nowrap"
            >
              <Network className="w-3.5 h-3.5 text-[#5FD3BF]" />
              <span>{showTopologyGraph ? 'Hide Access Graph' : 'Show Access Graph'}</span>
            </button>

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
                    type="button"
                    onClick={() => setSelectedAccountName(account.name)}
                    className={`xh-btn ${
                      selectedAccountName === account.name ? 'primary' : ''
                    } whitespace-nowrap`}
                  >
                    <span className="font-mono">{account.name}</span>
                    {hasCrit && (
                      <span className="text-[10px] font-mono font-bold text-red-400">
                        CRIT
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {/* D3 Node-Link Access Path & RBAC Relationship Topology */}
      {showTopologyGraph && (
        <StorageAccessGraphD3
          storageAccounts={storageAccounts}
          roleAssignments={roleAssignments}
          findings={findings}
          selectedAccountName={selectedAccount?.name || ''}
          onSelectAccount={(accName) => setSelectedAccountName(accName)}
          onSelectFinding={onSelectFinding}
        />
      )}

      {storageAccounts.length === 0 && (
        <div className="p-8 rounded-xl bg-white border border-slate-200 shadow-xs text-center space-y-2">
          <Database className="w-10 h-10 text-emerald-700 mx-auto" />
          <h3 className="text-base font-serif font-semibold text-slate-900">
            0 Storage Accounts &amp; 0 Containers Returned from Live Azure Subscription
          </h3>
          <p className="text-xs text-slate-600 max-w-xl mx-auto leading-relaxed">
            Connected to live Azure Resource Manager (
            <code className="text-emerald-800 font-mono">management.azure.com</code>
            ). No Storage Accounts or Blob Containers were returned for the active subscription / RBAC scope.
          </p>
        </div>
      )}

      {selectedAccount && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Security Control Posture Checklist */}
          <div className="lg:col-span-5 space-y-4">
            <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-xs">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-200">
                <div>
                  <span className="rm-kicker">Selected Storage Account</span>
                  <h3 className="font-mono font-bold text-slate-900 text-base">
                    {selectedAccount.name}
                  </h3>
                  <span className="text-[11px] font-mono text-slate-500">
                    RG: {selectedAccount.resourceGroup} · {selectedAccount.location}
                  </span>
                </div>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded font-mono font-semibold border ${
                    accountFindings.some((f) => f.severity === 'CRITICAL')
                      ? 'bg-red-50 text-red-700 border-red-200'
                      : accountFindings.length > 0
                      ? 'bg-amber-50 text-amber-800 border-amber-200'
                      : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                  }`}
                >
                  {accountFindings.length} Loopholes Detected
                </span>
              </div>

              {/* Security Controls Table */}
              <div className="space-y-3">
                {/* 1. Public Blob Access */}
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.allowBlobPublicAccess ? (
                      <Unlock className="w-4 h-4 text-red-600 flex-shrink-0" />
                    ) : (
                      <Lock className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-900">
                        Allow Blob Public Access
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        CIS Azure Control 3.7
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${
                      selectedAccount.allowBlobPublicAccess
                        ? 'bg-red-50 text-red-700 border-red-200'
                        : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    }`}
                  >
                    {selectedAccount.allowBlobPublicAccess
                      ? 'ALLOWED (Vulnerable)'
                      : 'Disabled (Secure)'}
                  </span>
                </div>

                {/* 2. Secure Transfer Required (HTTPS) */}
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.supportsHttpsTrafficOnly ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-red-600 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-900">
                        Secure Transfer Required
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        CIS Azure Control 3.1
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${
                      selectedAccount.supportsHttpsTrafficOnly
                        ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        : 'bg-red-50 text-red-700 border-red-200'
                    }`}
                  >
                    {selectedAccount.supportsHttpsTrafficOnly
                      ? 'HTTPS Only'
                      : 'HTTP Allowed (Insecure)'}
                  </span>
                </div>

                {/* 3. Minimum TLS Version */}
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.minimumTlsVersion === 'TLS1_2' ||
                    selectedAccount.minimumTlsVersion === 'TLS1_3' ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-orange-600 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-900">
                        Minimum TLS Protocol
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        CIS Azure Control 3.8
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${
                      selectedAccount.minimumTlsVersion === 'TLS1_2' ||
                      selectedAccount.minimumTlsVersion === 'TLS1_3'
                        ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        : 'bg-orange-50 text-orange-700 border-orange-200'
                    }`}
                  >
                    {selectedAccount.minimumTlsVersion}
                  </span>
                </div>

                {/* 4. Public Network Access & Firewall */}
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.publicNetworkAccess === 'Disabled' ||
                    selectedAccount.defaultAction === 'Deny' ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                    ) : (
                      <Globe className="w-4 h-4 text-orange-600 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-900">
                        Network Firewall &amp; Perimeter
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        {selectedAccount.ipRulesCount} IP Rules ·{' '}
                        {selectedAccount.privateEndpointConnectionsCount} Private Endpoints
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${
                      selectedAccount.publicNetworkAccess === 'Disabled' ||
                      selectedAccount.defaultAction === 'Deny'
                        ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        : 'bg-orange-50 text-orange-700 border-orange-200'
                    }`}
                  >
                    {selectedAccount.publicNetworkAccess === 'Enabled' &&
                    selectedAccount.defaultAction === 'Allow'
                      ? 'Open to All Internet'
                      : 'Restricted / Private'}
                  </span>
                </div>

                {/* 5. Soft Delete Protection */}
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <div className="flex items-center space-x-2.5">
                    {selectedAccount.softDeleteEnabled ? (
                      <FolderCheck className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                    ) : (
                      <FolderLock className="w-4 h-4 text-amber-700 flex-shrink-0" />
                    )}
                    <div>
                      <div className="text-xs font-semibold text-slate-900">
                        Blob Soft Delete (Ransomware)
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        {selectedAccount.softDeleteEnabled
                          ? `${selectedAccount.blobRetentionDays} Days Retention`
                          : 'Immediate Permanent Deletion'}
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${
                      selectedAccount.softDeleteEnabled
                        ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        : 'bg-amber-50 text-amber-800 border-amber-200'
                    }`}
                  >
                    {selectedAccount.softDeleteEnabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </div>
            </div>

            {/* Containers List */}
            <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-xs">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2">
                  <Database className="w-4 h-4 text-emerald-700" />
                  <h3 className="font-serif font-semibold text-slate-900 text-base">
                    Blob Containers ({selectedAccount.containers.length})
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-slate-500">
                  Anonymous Read Access Audit
                </span>
              </div>

              <div className="space-y-2.5">
                {selectedAccount.containers.length === 0 ? (
                  <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500 text-center">
                    0 Blob Containers in {selectedAccount.name}
                  </div>
                ) : (
                  selectedAccount.containers.map((container) => {
                    const isExposed = container.publicAccess !== 'None';
                    return (
                      <div
                        key={container.name}
                        className={`p-3 rounded-lg border transition-all ${
                          isExposed
                            ? 'bg-red-50/70 border-red-200 text-slate-900'
                            : 'bg-slate-50 border-slate-200 text-slate-800'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center space-x-2">
                            <span className="font-mono text-xs font-bold text-slate-900">
                              {container.name}
                            </span>
                            {container.dataClassification && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-600 font-mono">
                                {container.dataClassification}
                              </span>
                            )}
                          </div>
                          <span
                            className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                              container.publicAccess === 'Container'
                                ? 'bg-red-600 text-white border-red-600'
                                : container.publicAccess === 'Blob'
                                ? 'bg-red-50 text-red-700 border-red-200'
                                : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                            }`}
                          >
                            {container.publicAccess === 'None'
                              ? 'Private (Secure)'
                              : `PUBLIC (${container.publicAccess})`}
                          </span>
                        </div>

                        <div className="text-[11px] text-slate-600 flex items-center justify-between mt-2 pt-2 border-t border-slate-200 font-mono">
                          <span>
                            {container.blobCount?.toLocaleString() || '0'} Stored Blobs
                          </span>
                          {container.hasStoredAccessPolicyWithNoExpiry && (
                            <span className="text-amber-800 font-semibold text-[10px]">
                              Perpetual SAS Policy
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>

          {/* Right Column: Identified Findings & Instant Remediation Commands */}
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-xs">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <span className="rm-kicker">Actionable Remediation</span>
                  <h3 className="font-serif font-semibold text-slate-900 text-lg">
                    Storage Vulnerability Findings &amp; Runbooks
                  </h3>
                  <p className="text-xs text-slate-600">
                    Remediation commands ready for execution via Azure CLI or Portal
                  </p>
                </div>
                <span className="text-xs text-emerald-700 font-mono font-semibold">
                  {accountFindings.length} Action Items
                </span>
              </div>

              {accountFindings.length === 0 ? (
                <div className="py-12 text-center text-slate-600 bg-slate-50 rounded-xl border border-slate-200">
                  <ShieldCheck className="w-10 h-10 text-emerald-700 mx-auto mb-2" />
                  <p className="text-sm font-semibold text-slate-900">
                    Zero Vulnerabilities Detected in {selectedAccount.name}
                  </p>
                  <p className="text-xs text-slate-500 mt-1">
                    Compliant with CIS Azure Foundations 3.x storage benchmarks.
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {accountFindings.map((finding) => (
                    <div
                      key={finding.id}
                      className="p-4 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-300 transition-all space-y-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <span
                              className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                                finding.severity === 'CRITICAL'
                                  ? 'bg-red-50 text-red-700 border-red-200'
                                  : finding.severity === 'HIGH'
                                  ? 'bg-orange-50 text-orange-700 border-orange-200'
                                  : 'bg-amber-50 text-amber-800 border-amber-200'
                              }`}
                            >
                              {finding.severity}
                            </span>
                            {finding.compliance.cisAzure && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-white text-slate-700 border border-slate-200 font-mono">
                                CIS {finding.compliance.cisAzure}
                              </span>
                            )}
                          </div>
                          <h4 className="text-sm font-bold text-slate-900">
                            {finding.title}
                          </h4>
                        </div>

                        <button
                          type="button"
                          onClick={() => onSelectFinding(finding.id)}
                          className="text-xs text-emerald-700 hover:underline font-semibold flex items-center space-x-1 whitespace-nowrap cursor-pointer"
                        >
                          <span>Full Runbook</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>

                      <p className="text-xs text-slate-600 leading-relaxed">
                        {finding.description}
                      </p>

                      {/* Monospace Azure CLI Remediation Block */}
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] text-slate-600 font-medium">
                          <span className="flex items-center space-x-1">
                            <Terminal className="w-3.5 h-3.5 text-emerald-700" />
                            <span>Azure CLI Hardening Command:</span>
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

                      {/* Operational Impact Notice */}
                      <div className="text-[11px] text-amber-900 bg-amber-50 p-2.5 rounded-lg border border-amber-200">
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
