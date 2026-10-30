/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  Search,
  Database,
  Lock,
  Unlock,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  FolderOpen,
  Filter,
  Wrench,
  CheckCircle2,
  Globe,
  HardDrive,
} from 'lucide-react';
import { StorageAccount } from '../types/security';

interface StorageInventoryProps {
  storageAccounts: StorageAccount[];
  onHardenAccount?: (accountId: string) => void;
  isDemoData?: boolean;
}

interface InventoryRow {
  rowId: string;
  accountId: string;
  accountName: string;
  subscriptionId: string;
  resourceGroup: string;
  location: string;
  sku: string;
  kind: string;
  containerName: string;
  containerPublicAccess: 'Container' | 'Blob' | 'None';
  effectiveAnonymousExposure: boolean;
  isGuardrailGapOnly: boolean;
  blobCount: number;
  sizeGb: number;
  hasSensitiveData: boolean;
  immutabilityPolicy: boolean;
  lastModified: string;
  allowBlobPublicAccess: boolean;
  allowSharedKeyAccess: boolean;
  encryptionKeySource: 'Microsoft.Storage' | 'Microsoft.Keyvault';
  minimumTlsVersion: 'TLS1_0' | 'TLS1_1' | 'TLS1_2';
  supportsHttpsTrafficOnly: boolean;
  defaultAction: 'Allow' | 'Deny';
  publicNetworkAccess: 'Enabled' | 'Disabled';
  isAccountHardened: boolean;
}

export const StorageInventory: React.FC<StorageInventoryProps> = ({
  storageAccounts,
  onHardenAccount,
  isDemoData = true,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [accessFilter, setAccessFilter] = useState<'ALL' | 'PUBLIC' | 'GUARDRAIL_GAP' | 'PRIVATE'>('ALL');
  const [encryptionFilter, setEncryptionFilter] = useState<
    'ALL' | 'Microsoft.Storage' | 'Microsoft.Keyvault'
  >('ALL');
  const [subscriptionFilter, setSubscriptionFilter] = useState<string>('ALL');

  const subscriptions = useMemo(() => {
    const subs = new Set<string>();
    storageAccounts.forEach((acc) => {
      if (acc.subscriptionId) subs.add(acc.subscriptionId);
    });
    return Array.from(subs);
  }, [storageAccounts]);

  const rows: InventoryRow[] = useMemo(() => {
    const list: InventoryRow[] = [];

    storageAccounts.forEach((acc) => {
      const isAccountHardened =
        !acc.allowBlobPublicAccess &&
        !acc.allowSharedKeyAccess &&
        acc.defaultAction === 'Deny' &&
        acc.minimumTlsVersion === 'TLS1_2' &&
        acc.supportsHttpsTrafficOnly;

      if (acc.containers.length === 0) {
        list.push({
          rowId: `${acc.id}-empty`,
          accountId: acc.id,
          accountName: acc.name,
          subscriptionId: acc.subscriptionId || 'default-subscription',
          resourceGroup: acc.resourceGroup,
          location: acc.location,
          sku: acc.sku,
          kind: acc.kind,
          containerName: '(0 containers)',
          containerPublicAccess: 'None',
          effectiveAnonymousExposure: false,
          isGuardrailGapOnly: acc.allowBlobPublicAccess,
          blobCount: 0,
          sizeGb: 0,
          hasSensitiveData: false,
          immutabilityPolicy: false,
          lastModified: '—',
          allowBlobPublicAccess: acc.allowBlobPublicAccess,
          allowSharedKeyAccess: acc.allowSharedKeyAccess,
          encryptionKeySource: acc.encryptionKeySource,
          minimumTlsVersion: acc.minimumTlsVersion,
          supportsHttpsTrafficOnly: acc.supportsHttpsTrafficOnly,
          defaultAction: acc.defaultAction,
          publicNetworkAccess: acc.publicNetworkAccess,
          isAccountHardened,
        });
      } else {
        acc.containers.forEach((c) => {
          const effectivePublic =
            acc.allowBlobPublicAccess && c.publicAccess !== 'None';
          const guardrailGapOnly =
            acc.allowBlobPublicAccess && c.publicAccess === 'None';
          list.push({
            rowId: `${acc.id}-${c.name}`,
            accountId: acc.id,
            accountName: acc.name,
            subscriptionId: acc.subscriptionId || 'default-subscription',
            resourceGroup: acc.resourceGroup,
            location: acc.location,
            sku: acc.sku,
            kind: acc.kind,
            containerName: c.name,
            containerPublicAccess: c.publicAccess,
            effectiveAnonymousExposure: effectivePublic,
            isGuardrailGapOnly: guardrailGapOnly,
            blobCount: c.blobCount,
            sizeGb: c.sizeGb,
            hasSensitiveData: c.hasSensitiveData,
            immutabilityPolicy: c.immutabilityPolicy,
            lastModified: c.lastModified,
            allowBlobPublicAccess: acc.allowBlobPublicAccess,
            allowSharedKeyAccess: acc.allowSharedKeyAccess,
            encryptionKeySource: acc.encryptionKeySource,
            minimumTlsVersion: acc.minimumTlsVersion,
            supportsHttpsTrafficOnly: acc.supportsHttpsTrafficOnly,
            defaultAction: acc.defaultAction,
            publicNetworkAccess: acc.publicNetworkAccess,
            isAccountHardened,
          });
        });
      }
    });

    return list;
  }, [storageAccounts]);

  const filteredRows = useMemo(() => {
    return rows.filter((row) => {
      const q = searchQuery.trim().toLowerCase();
      const matchesSearch =
        !q ||
        row.accountName.toLowerCase().includes(q) ||
        row.containerName.toLowerCase().includes(q) ||
        row.resourceGroup.toLowerCase().includes(q) ||
        row.location.toLowerCase().includes(q) ||
        row.subscriptionId.toLowerCase().includes(q) ||
        row.encryptionKeySource.toLowerCase().includes(q);

      const matchesAccess =
        accessFilter === 'ALL' ||
        (accessFilter === 'PUBLIC' && row.effectiveAnonymousExposure) ||
        (accessFilter === 'GUARDRAIL_GAP' && row.isGuardrailGapOnly) ||
        (accessFilter === 'PRIVATE' && !row.effectiveAnonymousExposure && !row.isGuardrailGapOnly);

      const matchesEncryption =
        encryptionFilter === 'ALL' ||
        row.encryptionKeySource === encryptionFilter;

      const matchesSub =
        subscriptionFilter === 'ALL' ||
        row.subscriptionId === subscriptionFilter;

      return (
        matchesSearch && matchesAccess && matchesEncryption && matchesSub
      );
    });
  }, [rows, searchQuery, accessFilter, encryptionFilter, subscriptionFilter]);

  const totalContainers = storageAccounts.reduce(
    (acc, s) => acc + s.containers.length,
    0
  );
  const exposedContainersCount = rows.filter(
    (r) => r.effectiveAnonymousExposure
  ).length;
  const cmkAccountsCount = storageAccounts.filter(
    (s) => s.encryptionKeySource === 'Microsoft.Keyvault'
  ).length;

  return (
    <div className="space-y-6">
      {/* Header & Summary KPI Strip */}
      <div className="p-5 rounded-xl border border-slate-200/90 bg-white flex flex-col lg:flex-row lg:items-center justify-between gap-4 shadow-xs">
        <div>
          <span className="rm-kicker">
            {isDemoData
              ? 'DEMO INVENTORY — NO LIVE ASSESSMENT'
              : 'LIVE AZURE STORAGE & CONTAINER INVENTORY'}
          </span>
          <div className="flex items-center space-x-2 mt-0.5">
            <Database className="w-5 h-5 text-[#1F8A79]" />
            <h2 className="font-serif text-lg font-bold text-[#16232F]">
              Storage Accounts &amp; Blob Containers Inventory
            </h2>
          </div>
          <p className="text-xs text-[#546471] mt-1">
            Distinguishes account-level <code className="font-mono">allowBlobPublicAccess</code> guardrail gaps from confirmed public containers (Rec #10), and notes Azure&apos;s default 256-bit AES Microsoft-Managed Key encryption at rest (Rec #11).
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="px-3.5 py-2 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[10px] font-mono uppercase text-[#546471]">
              Storage Accounts
            </div>
            <div className="font-serif text-base font-bold text-[#16232F] mt-0.5">
              {storageAccounts.length}
            </div>
          </div>
          <div className="px-3.5 py-2 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[10px] font-mono uppercase text-[#546471]">
              Total Containers
            </div>
            <div className="font-serif text-base font-bold text-[#1F8A79] mt-0.5">
              {totalContainers}
            </div>
          </div>
          <div className="px-3.5 py-2 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[10px] font-mono uppercase text-[#546471]">
              Confirmed Public
            </div>
            <div
              className={`font-serif text-base font-bold mt-0.5 ${
                exposedContainersCount > 0
                  ? 'text-red-600'
                  : 'text-[#1F8A79]'
              }`}
            >
              {exposedContainersCount}
            </div>
          </div>
          <div className="px-3.5 py-2 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[10px] font-mono uppercase text-[#546471]">
              Encrypted (CMK / MMK)
            </div>
            <div className="font-serif text-base font-bold text-[#0E2238] mt-0.5">
              {cmkAccountsCount} CMK / {storageAccounts.length - cmkAccountsCount} MMK
            </div>
          </div>
        </div>
      </div>

      {/* Search & Filter Controls */}
      <div className="p-4 rounded-xl border border-slate-200/90 bg-white flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 shadow-xs">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by storage account, container name, resource group, region, or subscription..."
            className="w-full bg-slate-50 border border-slate-300 rounded-lg pl-9 pr-4 py-2 text-xs text-[#16232F] placeholder-slate-400 focus:outline-none focus:border-[#2BB5A0]"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <div className="flex items-center space-x-1.5 bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1.5">
            <Filter className="w-3.5 h-3.5 text-[#546471]" />
            <span className="text-[#546471]">Access:</span>
            <select
              aria-label="Filter by Public Access"
              value={accessFilter}
              onChange={(e) =>
                setAccessFilter(e.target.value as 'ALL' | 'PUBLIC' | 'GUARDRAIL_GAP' | 'PRIVATE')
              }
              className="bg-transparent text-[#16232F] font-semibold focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Containers</option>
              <option value="PUBLIC">Confirmed Public (Anonymous)</option>
              <option value="GUARDRAIL_GAP">Guardrail Gap Only (Private Container)</option>
              <option value="PRIVATE">Strictly Private (Guardrail Blocked)</option>
            </select>
          </div>

          <div className="flex items-center space-x-1.5 bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1.5">
            <KeyRound className="w-3.5 h-3.5 text-[#546471]" />
            <span className="text-[#546471]">Encryption:</span>
            <select
              aria-label="Filter by Encryption Key Source"
              value={encryptionFilter}
              onChange={(e) =>
                setEncryptionFilter(
                  e.target.value as
                    | 'ALL'
                    | 'Microsoft.Storage'
                    | 'Microsoft.Keyvault'
                )
              }
              className="bg-transparent text-[#16232F] font-semibold focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Encrypted (MMK + CMK)</option>
              <option value="Microsoft.Keyvault">Customer-Managed Key (CMK)</option>
              <option value="Microsoft.Storage">Default Microsoft-Managed (MMK)</option>
            </select>
          </div>

          {subscriptions.length > 1 && (
            <div className="flex items-center space-x-1.5 bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1.5">
              <Globe className="w-3.5 h-3.5 text-[#546471]" />
              <span className="text-[#546471]">Subscription:</span>
              <select
                aria-label="Filter by Subscription"
                value={subscriptionFilter}
                onChange={(e) => setSubscriptionFilter(e.target.value)}
                className="bg-transparent text-[#16232F] font-semibold focus:outline-none cursor-pointer"
              >
                <option value="ALL">All Subscriptions</option>
                {subscriptions.map((sub) => (
                  <option key={sub} value={sub}>
                    {sub}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>

      {/* Searchable Inventory Table */}
      <div className="rounded-xl border border-slate-200/90 bg-white overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-mono uppercase text-[#546471]">
                <th className="py-3 px-4">Storage Account</th>
                <th className="py-3 px-4">Container Name</th>
                <th className="py-3 px-3">Public Access Status (Rec #10)</th>
                <th className="py-3 px-3">At-Rest Encryption &amp; TLS (Rec #11)</th>
                <th className="py-3 px-3">Network &amp; Auth</th>
                <th className="py-3 px-3 text-right">Volume / Blobs</th>
                <th className="py-3 px-4 text-right">Simulate (Rec #6)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-xs">
              {filteredRows.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="py-10 text-center text-[#546471] font-mono"
                  >
                    No storage accounts or containers match your current search filter.
                  </td>
                </tr>
              ) : (
                filteredRows.map((row) => (
                  <tr
                    key={row.rowId}
                    className="hover:bg-slate-50/80 transition-colors"
                  >
                    {/* Storage Account Column */}
                    <td className="py-3.5 px-4 align-top">
                      <div className="flex items-center space-x-2">
                        <HardDrive className="w-4 h-4 text-[#1F8A79] flex-shrink-0" />
                        <span className="font-mono font-bold text-[#16232F]">
                          {row.accountName}
                        </span>
                      </div>
                      <div className="text-[11px] text-[#546471] mt-0.5 font-mono">
                        {row.resourceGroup} · {row.location} · {row.sku}
                      </div>
                    </td>

                    {/* Container Name Column */}
                    <td className="py-3.5 px-4 align-top">
                      <div className="flex items-center space-x-2">
                        <FolderOpen
                          className={`w-4 h-4 flex-shrink-0 ${
                            row.effectiveAnonymousExposure
                              ? 'text-red-600'
                              : 'text-slate-400'
                          }`}
                        />
                        <span
                          className={`font-mono font-semibold ${
                            row.containerName === '(0 containers)'
                              ? 'text-slate-400 italic'
                              : 'text-[#16232F]'
                          }`}
                        >
                          {row.containerName}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 mt-1">
                        {row.hasSensitiveData && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-red-50 text-red-700 border border-red-200 font-semibold">
                            Sensitive Data
                          </span>
                        )}
                        {row.immutabilityPolicy && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-emerald-50 text-[#1F8A79] border border-emerald-200 font-semibold">
                            WORM Locked
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Public Access Column (Rec #10) */}
                    <td className="py-3.5 px-3 align-top">
                      <div className="space-y-1">
                        {row.effectiveAnonymousExposure ? (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-red-50 text-red-700 border border-red-200">
                            <Unlock className="w-3 h-3" />
                            <span>Confirmed Public ({row.containerPublicAccess})</span>
                          </span>
                        ) : row.isGuardrailGapOnly ? (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-50 text-amber-800 border border-amber-200">
                            <Lock className="w-3 h-3" />
                            <span>Container Private (Account Guardrail Gap)</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-50 text-[#1F8A79] border border-emerald-200">
                            <Lock className="w-3 h-3" />
                            <span>Private (Guardrail Blocked)</span>
                          </span>
                        )}
                        <div className="text-[11px] text-[#546471] font-mono">
                          Account allowBlobPublicAccess:{' '}
                          <span
                            className={
                              row.allowBlobPublicAccess
                                ? 'text-amber-700 font-semibold'
                                : 'text-[#1F8A79] font-semibold'
                            }
                          >
                            {row.allowBlobPublicAccess ? 'true' : 'false'}
                          </span>
                        </div>
                      </div>
                    </td>

                    {/* Encryption Settings Column (Rec #11) */}
                    <td className="py-3.5 px-3 align-top">
                      <div className="space-y-1 font-mono">
                        <span
                          className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-semibold ${
                            row.encryptionKeySource === 'Microsoft.Keyvault'
                              ? 'bg-emerald-50 text-[#1F8A79] border border-emerald-200'
                              : 'bg-slate-100 text-[#16232F] border border-slate-300'
                          }`}
                        >
                          <KeyRound className="w-3 h-3" />
                          <span>
                            {row.encryptionKeySource === 'Microsoft.Keyvault'
                              ? '256-bit AES (Key Vault CMK)'
                              : '256-bit AES (Default MMK)'}
                          </span>
                        </span>
                        <div className="text-[11px] text-[#546471]">
                          Min TLS:{' '}
                          <span
                            className={
                              row.minimumTlsVersion === 'TLS1_2'
                                ? 'text-[#1F8A79] font-semibold'
                                : 'text-red-600 font-semibold'
                            }
                          >
                            {row.minimumTlsVersion}
                          </span>{' '}
                          · HTTPS:{' '}
                          <span
                            className={
                              row.supportsHttpsTrafficOnly
                                ? 'text-[#1F8A79] font-semibold'
                                : 'text-red-600 font-semibold'
                            }
                          >
                            {row.supportsHttpsTrafficOnly ? 'Required' : 'Optional'}
                          </span>
                        </div>
                      </div>
                    </td>

                    {/* Network & Shared Key Auth Column */}
                    <td className="py-3.5 px-3 align-top font-mono">
                      <div className="space-y-1">
                        <span
                          className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-semibold ${
                            row.defaultAction === 'Deny'
                              ? 'bg-emerald-50 text-[#1F8A79] border border-emerald-200'
                              : 'bg-red-50 text-red-700 border border-red-200'
                          }`}
                        >
                          {row.defaultAction === 'Deny' ? (
                            <ShieldCheck className="w-3 h-3" />
                          ) : (
                            <ShieldAlert className="w-3 h-3" />
                          )}
                          <span>Firewall: {row.defaultAction}</span>
                        </span>
                        <div className="text-[11px] text-[#546471]">
                          Shared Key:{' '}
                          <span
                            className={
                              row.allowSharedKeyAccess
                                ? 'text-amber-700 font-semibold'
                                : 'text-[#1F8A79] font-semibold'
                            }
                          >
                            {row.allowSharedKeyAccess ? 'Enabled' : 'Disabled'}
                          </span>
                        </div>
                      </div>
                    </td>

                    {/* Volume / Blobs Column */}
                    <td className="py-3.5 px-3 align-top text-right font-mono">
                      <div className="text-[#16232F] font-semibold">
                        {row.sizeGb.toFixed(1)} GB
                      </div>
                      <div className="text-[11px] text-[#546471]">
                        {row.blobCount.toLocaleString()} blobs
                      </div>
                    </td>

                    {/* Action Column (Rec #6) */}
                    <td className="py-3.5 px-4 align-top text-right">
                      {row.isAccountHardened ? (
                        <span className="inline-flex items-center space-x-1 text-[11px] text-[#1F8A79] font-mono font-semibold">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Hardened</span>
                        </span>
                      ) : (
                        onHardenAccount && (
                          <button
                            onClick={() => onHardenAccount(row.accountId)}
                            className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-[#0E2238] hover:bg-[#15314E] text-white text-[11px] font-semibold transition-all"
                            title="Simulates hardening in UI memory only"
                          >
                            <Wrench className="w-3 h-3" />
                            <span>Simulate Hardening</span>
                          </button>
                        )
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Footer Count */}
        <div className="px-4 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-[#546471]">
          <span>
            Showing <strong className="text-[#16232F]">{filteredRows.length}</strong> of{' '}
            <strong className="text-[#16232F]">{rows.length}</strong> inventory records
          </span>
          <span className="font-mono text-[11px]">
            All Azure Storage accounts are encrypted at rest by default (256-bit AES MMK)
          </span>
        </div>
      </div>
    </div>
  );
};
