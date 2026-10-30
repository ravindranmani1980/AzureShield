/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  Database,
  Globe,
  Lock,
  Unlock,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  FolderOpen,
  FileWarning,
  Wrench,
} from 'lucide-react';
import { RbacAssignment, StorageAccount } from '../types/security';
import { StorageAccessGraphD3 } from './StorageAccessGraphD3';

interface StorageAuditorProps {
  storageAccounts: StorageAccount[];
  roleAssignments: RbacAssignment[];
  onHardenAccount: (accountId: string) => void;
}

export const StorageAuditor: React.FC<StorageAuditorProps> = ({
  storageAccounts,
  roleAssignments,
  onHardenAccount,
}) => {
  return (
    <div className="space-y-6">
      {/* Header Description */}
      <div className="p-5 rounded-xl border border-slate-200/90 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-xs">
        <div>
          <span className="rm-kicker">STORAGE LOOPHOLE &amp; GUARDRAIL AUDITOR</span>
          <div className="flex items-center space-x-2 mt-0.5">
            <Database className="w-5 h-5 text-[#1F8A79]" />
            <h2 className="font-serif text-lg font-bold text-[#16232F]">
              Azure Storage Account &amp; Blob Container Inspector
            </h2>
          </div>
          <p className="text-xs text-[#546471] mt-1">
            Distinguishes account-level <code className="font-mono">allowBlobPublicAccess</code> guardrail gaps from confirmed container-level anonymous exposure (Rec #10) and reflects default 256-bit AES Microsoft-Managed Key encryption at rest (Rec #11).
          </p>
        </div>
        <div className="text-xs font-mono text-[#16232F] bg-slate-100 px-3 py-2 rounded-lg border border-slate-200 font-semibold">
          Auditing {storageAccounts.length} Storage Accounts
        </div>
      </div>

      {/* Visual D3 Node-Link Access Graph */}
      <StorageAccessGraphD3
        storageAccounts={storageAccounts}
        roleAssignments={roleAssignments}
      />

      {/* Storage Account Cards */}
      <div className="space-y-5">
        {storageAccounts.map((acc) => {
          const openContainersCount = acc.containers.filter(
            (c) => c.publicAccess !== 'None'
          ).length;

          const isHardened =
            !acc.allowBlobPublicAccess &&
            !acc.allowSharedKeyAccess &&
            acc.defaultAction === 'Deny' &&
            acc.minimumTlsVersion === 'TLS1_2';

          return (
            <div
              key={acc.id}
              className="rounded-xl border border-slate-200/90 bg-white overflow-hidden shadow-xs"
            >
              {/* Account Top Bar */}
              <div className="p-5 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-50/70">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5 flex-wrap gap-y-1">
                    <span className="font-mono font-bold text-base text-[#16232F]">
                      {acc.name}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-white text-[#546471] font-mono border border-slate-200">
                      {acc.sku} · {acc.kind}
                    </span>
                    {isHardened ? (
                      <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-[#1F8A79] border border-emerald-200">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Hardened Baseline</span>
                      </span>
                    ) : openContainersCount > 0 ? (
                      <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-200">
                        <ShieldAlert className="w-3.5 h-3.5" />
                        <span>Confirmed Anonymous Container Exposure ({openContainersCount})</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-50 text-amber-800 border border-amber-200">
                        <ShieldAlert className="w-3.5 h-3.5" />
                        <span>Guardrail Hardening Recommended</span>
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-[#546471] font-mono">
                    Resource Group: <strong className="text-[#16232F]">{acc.resourceGroup}</strong> · Region:{' '}
                    <strong className="text-[#16232F]">{acc.location}</strong>
                  </div>
                </div>

                {!isHardened && (
                  <button
                    onClick={() => onHardenAccount(acc.id)}
                    className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all self-start lg:self-center"
                    title="Simulates hardening in UI memory without modifying live Azure resources"
                  >
                    <Wrench className="w-3.5 h-3.5" />
                    <span>Simulate Account Hardening (In-Memory)</span>
                  </button>
                )}
              </div>

              {/* 6 Control-Plane Guardrail Indicators */}
              <div className="p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
                {/* 1. Anonymous Blob Public Access (Rec #10) */}
                <div
                  className={`p-3.5 rounded-lg border ${
                    acc.allowBlobPublicAccess && openContainersCount > 0
                      ? 'bg-red-50/70 border-red-200'
                      : acc.allowBlobPublicAccess
                      ? 'bg-amber-50/70 border-amber-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-[#546471]">1. Anonymous Blob Guardrail</span>
                    {acc.allowBlobPublicAccess ? (
                      <Unlock
                        className={`w-4 h-4 ${
                          openContainersCount > 0 ? 'text-red-600' : 'text-amber-600'
                        }`}
                      />
                    ) : (
                      <Lock className="w-4 h-4 text-[#1F8A79]" />
                    )}
                  </div>
                  <div
                    className={`mt-1 text-sm font-mono font-bold ${
                      acc.allowBlobPublicAccess && openContainersCount > 0
                        ? 'text-red-700'
                        : acc.allowBlobPublicAccess
                        ? 'text-amber-800'
                        : 'text-[#1F8A79]'
                    }`}
                  >
                    {acc.allowBlobPublicAccess && openContainersCount > 0
                      ? `EXPOSED (${openContainersCount} Public Container)`
                      : acc.allowBlobPublicAccess
                      ? 'GUARDRAIL GAP (0 Public Containers)'
                      : 'BLOCKED (Compliant)'}
                  </div>
                  <p className="text-[11px] text-[#546471] mt-1">
                    {acc.allowBlobPublicAccess && openContainersCount === 0
                      ? 'Account permits public containers, but all existing containers are set to None (Private).'
                      : 'Controls whether individual containers can be made anonymous.'}
                  </p>
                </div>

                {/* 2. Shared Key Authorization */}
                <div
                  className={`p-3.5 rounded-lg border ${
                    acc.allowSharedKeyAccess
                      ? 'bg-amber-50/70 border-amber-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-[#546471]">2. Shared Key Access</span>
                    <KeyRound
                      className={`w-4 h-4 ${
                        acc.allowSharedKeyAccess
                          ? 'text-amber-600'
                          : 'text-[#1F8A79]'
                      }`}
                    />
                  </div>
                  <div
                    className={`mt-1 text-sm font-mono font-bold ${
                      acc.allowSharedKeyAccess
                        ? 'text-amber-800'
                        : 'text-[#1F8A79]'
                    }`}
                  >
                    {acc.allowSharedKeyAccess
                      ? 'ENABLED (Bypass Risk)'
                      : 'DISABLED (Entra OAuth Only)'}
                  </div>
                  <p className="text-[11px] text-[#546471] mt-1">
                    Account keys bypass Entra ID Conditional Access &amp; PIM.
                  </p>
                </div>

                {/* 3. Network Firewall Default Action */}
                <div
                  className={`p-3.5 rounded-lg border ${
                    acc.defaultAction === 'Allow'
                      ? 'bg-red-50/70 border-red-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-[#546471]">3. Storage Firewall</span>
                    <Globe
                      className={`w-4 h-4 ${
                        acc.defaultAction === 'Allow'
                          ? 'text-red-600'
                          : 'text-[#1F8A79]'
                      }`}
                    />
                  </div>
                  <div
                    className={`mt-1 text-sm font-mono font-bold ${
                      acc.defaultAction === 'Allow'
                        ? 'text-red-700'
                        : 'text-[#1F8A79]'
                    }`}
                  >
                    {acc.defaultAction === 'Allow'
                      ? 'ALLOW ALL (0.0.0.0/0)'
                      : 'DENY BY DEFAULT'}
                  </div>
                  <p className="text-[11px] text-[#546471] mt-1">
                    Private Endpoints:{' '}
                    {acc.privateEndpointConnections.length > 0
                      ? acc.privateEndpointConnections.join(', ')
                      : 'None Configured'}
                  </p>
                </div>

                {/* 4. Minimum TLS & HTTPS */}
                <div
                  className={`p-3.5 rounded-lg border ${
                    acc.minimumTlsVersion !== 'TLS1_2' ||
                    !acc.supportsHttpsTrafficOnly
                      ? 'bg-red-50/70 border-red-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-[#546471]">4. Transit Encryption</span>
                    <Lock className="w-4 h-4 text-[#1F8A79]" />
                  </div>
                  <div
                    className={`mt-1 text-sm font-mono font-bold ${
                      acc.minimumTlsVersion !== 'TLS1_2' ||
                      !acc.supportsHttpsTrafficOnly
                        ? 'text-red-700'
                        : 'text-[#1F8A79]'
                    }`}
                  >
                    Min {acc.minimumTlsVersion} · HTTPS:{' '}
                    {acc.supportsHttpsTrafficOnly ? 'Required' : 'Optional'}
                  </div>
                  <p className="text-[11px] text-[#546471] mt-1">
                    TLS 1.0/1.1 or HTTP allows downgrade/cleartext interception.
                  </p>
                </div>

                {/* 5. Encryption at Rest (Rec #11: Note default 256-bit AES MMK encryption) */}
                <div className="p-3.5 rounded-lg border bg-slate-50 border-slate-200">
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-[#546471]">5. Encryption at Rest (Rec #11)</span>
                    <KeyRound className="w-4 h-4 text-[#1F8A79]" />
                  </div>
                  <div className="mt-1 text-sm font-mono font-bold text-[#16232F]">
                    {acc.encryptionKeySource === 'Microsoft.Keyvault'
                      ? '256-bit AES (Key Vault CMK)'
                      : '256-bit AES (Default MMK)'}
                  </div>
                  <p className="text-[11px] text-[#546471] mt-1">
                    Azure encrypts all Storage data at rest by default using Microsoft-Managed Keys (MMK). CMK is optional per org policy.
                  </p>
                </div>

                {/* 6. Data Recovery & Soft Delete */}
                <div className="p-3.5 rounded-lg border bg-slate-50 border-slate-200">
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-[#546471]">6. Ransomware Resilience</span>
                    <Database className="w-4 h-4 text-[#1F8A79]" />
                  </div>
                  <div
                    className={`mt-1 text-sm font-mono font-bold ${
                      acc.blobSoftDeleteDays > 0 && acc.versioningEnabled
                        ? 'text-[#1F8A79]'
                        : 'text-amber-800'
                    }`}
                  >
                    Soft Delete: {acc.blobSoftDeleteDays}d · Versioning:{' '}
                    {acc.versioningEnabled ? 'ON' : 'OFF'}
                  </div>
                  <p className="text-[11px] text-[#546471] mt-1">
                    Protects against destructive blob overwrite or ransomware wipe.
                  </p>
                </div>
              </div>

              {/* Containers Breakdown Table */}
              <div className="px-5 pb-5">
                <div className="text-xs font-bold text-[#16232F] uppercase tracking-wider mb-2.5 flex items-center space-x-1.5">
                  <FolderOpen className="w-4 h-4 text-[#1F8A79]" />
                  <span>Blob Containers ({acc.containers.length})</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {acc.containers.map((container) => {
                    const isExposed =
                      acc.allowBlobPublicAccess &&
                      container.publicAccess !== 'None';

                    return (
                      <div
                        key={container.name}
                        className={`p-3.5 rounded-lg border flex items-start justify-between gap-3 ${
                          isExposed
                            ? 'bg-red-50/70 border-red-200'
                            : 'bg-slate-50 border-slate-200'
                        }`}
                      >
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className="font-mono font-bold text-xs text-[#16232F]">
                              {container.name}
                            </span>
                            {container.hasSensitiveData && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-100 text-red-700 border border-red-200 flex items-center space-x-1 font-semibold">
                                <FileWarning className="w-3 h-3" />
                                <span>Sensitive Data</span>
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-[#546471] font-mono">
                            {container.blobCount.toLocaleString()} blobs ·{' '}
                            {container.sizeGb} GB · WORM Immutability:{' '}
                            {container.immutabilityPolicy ? 'Locked' : 'None'}
                          </div>
                        </div>

                        <div className="text-right flex-shrink-0">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                              isExposed
                                ? 'bg-red-600 text-white'
                                : 'bg-emerald-50 text-[#1F8A79] border border-emerald-200'
                            }`}
                          >
                            {isExposed
                              ? `PUBLIC (${container.publicAccess})`
                              : 'PRIVATE (None)'}
                          </span>
                          <div className="text-[10px] text-[#546471] mt-1">
                            {isExposed
                              ? 'Anonymous Read/List'
                              : 'Auth Required'}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
