/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  Search,
  ChevronDown,
  ChevronRight,
  Download,
  ArrowUpDown,
  RotateCcw,
  ExternalLink,
  SlidersHorizontal,
} from 'lucide-react';
import { Finding, StorageAccount, StorageContainer } from '../types/security';

interface StorageInventoryProps {
  storageAccounts: StorageAccount[];
  findings: Finding[];
  onSelectFinding: (findingId: string) => void;
  onNavigateToAuditor?: () => void;
  onSelectDataset?: (presetKey: string) => void;
}

type InventoryViewMode = 'unified' | 'accounts' | 'containers';
type AccessFilter = 'all' | 'exposed' | 'private';
type EncryptionFilter = 'all' | 'weak' | 'hardened';
type SortField =
  | 'accountName'
  | 'containerName'
  | 'location'
  | 'publicAccess'
  | 'encryption'
  | 'blobCount'
  | 'findings';

interface FlattenedInventoryRow {
  rowId: string;
  rowType: 'container' | 'account_empty';
  account: StorageAccount;
  container: StorageContainer | null;
  accountFindings: Finding[];
  rowFindings: Finding[];
  isPubliclyExposed: boolean;
  hasWeakEncryption: boolean;
}

export const StorageInventory: React.FC<StorageInventoryProps> = ({
  storageAccounts,
  findings,
  onSelectFinding,
  onNavigateToAuditor,
  onSelectDataset,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<InventoryViewMode>('unified');
  const [accessFilter, setAccessFilter] = useState<AccessFilter>('all');
  const [encryptionFilter, setEncryptionFilter] = useState<EncryptionFilter>('all');
  const [sortField, setSortField] = useState<SortField>('accountName');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [expandedAccounts, setExpandedAccounts] = useState<Record<string, boolean>>({});

  const isAccountExpanded = (accountName: string) => {
    return expandedAccounts[accountName] ?? true;
  };

  const toggleAccountExpanded = (accountName: string) => {
    setExpandedAccounts((prev) => ({
      ...prev,
      [accountName]: !(prev[accountName] ?? true),
    }));
  };

  // Build flattened rows combining Storage Accounts and their Blob Containers
  const allRows: FlattenedInventoryRow[] = useMemo(() => {
    const rows: FlattenedInventoryRow[] = [];

    storageAccounts.forEach((acc) => {
      const accountFindings = findings.filter(
        (f) =>
          f.resourceName === acc.name ||
          f.resourceName.startsWith(`${acc.name}/`) ||
          f.resourceId === acc.id ||
          f.resourceId.startsWith(`${acc.id}/`)
      );

      const accountHasWeakEncryption =
        !acc.supportsHttpsTrafficOnly ||
        acc.minimumTlsVersion === 'TLS1_0' ||
        acc.minimumTlsVersion === 'TLS1_1' ||
        !acc.customerManagedKeyEnabled;

      if (acc.containers.length === 0) {
        const isPubliclyExposed =
          acc.allowBlobPublicAccess ||
          (acc.publicNetworkAccess === 'Enabled' && acc.defaultAction === 'Allow');

        rows.push({
          rowId: `${acc.id}::no-container`,
          rowType: 'account_empty',
          account: acc,
          container: null,
          accountFindings,
          rowFindings: accountFindings,
          isPubliclyExposed,
          hasWeakEncryption: accountHasWeakEncryption,
        });
      } else {
        acc.containers.forEach((cont) => {
          const contFindings = accountFindings.filter(
            (f) =>
              f.resourceName.includes(cont.name) ||
              f.resourceId.endsWith(`/${cont.name}`) ||
              f.resourceId.includes(`/${cont.name}/`) ||
              f.resourceType === 'StorageAccount'
          );

          const isPubliclyExposed =
            cont.publicAccess !== 'None' ||
            acc.allowBlobPublicAccess ||
            cont.hasStoredAccessPolicyWithNoExpiry ||
            cont.sasTokenIssuedWithFullPermissions;

          rows.push({
            rowId: `${acc.id}::${cont.id || cont.name}`,
            rowType: 'container',
            account: acc,
            container: cont,
            accountFindings,
            rowFindings: contFindings,
            isPubliclyExposed,
            hasWeakEncryption: accountHasWeakEncryption,
          });
        });
      }
    });

    return rows;
  }, [storageAccounts, findings]);

  // Filter rows by search query, public access filter, and encryption filter
  const filteredRows = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();

    return allRows
      .filter((row) => {
        if (viewMode === 'containers' && !row.container) {
          return false;
        }

        if (accessFilter === 'exposed' && !row.isPubliclyExposed) {
          return false;
        }
        if (accessFilter === 'private' && row.isPubliclyExposed) {
          return false;
        }

        if (encryptionFilter === 'weak' && !row.hasWeakEncryption) {
          return false;
        }
        if (encryptionFilter === 'hardened' && row.hasWeakEncryption) {
          return false;
        }

        if (!q) return true;

        const acc = row.account;
        const cont = row.container;

        const encryptionKeywords = [
          acc.supportsHttpsTrafficOnly ? 'https required secure transfer' : 'http allowed insecure',
          acc.minimumTlsVersion.toLowerCase(),
          acc.minimumTlsVersion.replace('_', '.').toLowerCase(),
          acc.customerManagedKeyEnabled ? 'cmk customer managed key vault' : 'mmk microsoft managed key',
          acc.infrastructureEncryption ? 'double infrastructure encryption' : 'standard encryption',
          cont?.immutabilityPolicyEnabled ? 'worm immutability locked' : '',
        ].join(' ');

        const accessKeywords = [
          acc.allowBlobPublicAccess ? 'blob public access allowed enabled' : 'blob public access disabled private',
          `network ${acc.publicNetworkAccess.toLowerCase()}`,
          `firewall ${acc.defaultAction.toLowerCase()}`,
          cont ? `container ${cont.publicAccess.toLowerCase()}` : 'no containers',
          cont?.publicAccess === 'None' ? 'private' : 'public anonymous exposed',
        ].join(' ');

        const searchableText = [
          acc.name,
          acc.resourceGroup,
          acc.location,
          acc.subscriptionId,
          cont?.name || '',
          cont?.dataClassification || '',
          encryptionKeywords,
          accessKeywords,
        ]
          .join(' ')
          .toLowerCase();

        return searchableText.includes(q);
      })
      .sort((a, b) => {
        const dir = sortDirection === 'asc' ? 1 : -1;
        switch (sortField) {
          case 'accountName':
            return a.account.name.localeCompare(b.account.name) * dir;
          case 'containerName':
            return (a.container?.name || '').localeCompare(b.container?.name || '') * dir;
          case 'location':
            return a.account.location.localeCompare(b.account.location) * dir;
          case 'publicAccess': {
            const rankAccess = (r: FlattenedInventoryRow) => {
              if (r.container?.publicAccess === 'Container') return 3;
              if (r.container?.publicAccess === 'Blob') return 2;
              if (r.account.allowBlobPublicAccess) return 1;
              return 0;
            };
            return (rankAccess(b) - rankAccess(a)) * dir;
          }
          case 'encryption': {
            const rankEnc = (r: FlattenedInventoryRow) => {
              let score = 0;
              if (r.account.supportsHttpsTrafficOnly) score += 2;
              if (r.account.minimumTlsVersion === 'TLS1_2' || r.account.minimumTlsVersion === 'TLS1_3') score += 2;
              if (r.account.customerManagedKeyEnabled) score += 2;
              if (r.account.infrastructureEncryption) score += 1;
              return score;
            };
            return (rankEnc(a) - rankEnc(b)) * dir;
          }
          case 'blobCount':
            return ((a.container?.blobCount || 0) - (b.container?.blobCount || 0)) * dir;
          case 'findings':
            return (b.rowFindings.length - a.rowFindings.length) * dir;
          default:
            return 0;
        }
      });
  }, [allRows, searchQuery, viewMode, accessFilter, encryptionFilter, sortField, sortDirection]);

  // Filtered Storage Accounts for the 'accounts' view mode
  const filteredAccounts = useMemo(() => {
    const matchedAccountIds = new Set(filteredRows.map((r) => r.account.id));
    return storageAccounts.filter((acc) => matchedAccountIds.has(acc.id));
  }, [storageAccounts, filteredRows]);

  // Inventory Summary Metrics
  const summaryStats = useMemo(() => {
    const totalAccounts = storageAccounts.length;
    const totalContainers = storageAccounts.reduce(
      (sum, acc) => sum + acc.containers.length,
      0
    );
    const totalBlobs = storageAccounts.reduce(
      (sum, acc) =>
        sum + acc.containers.reduce((cSum, c) => cSum + (c.blobCount || 0), 0),
      0
    );
    const publicAccountsCount = storageAccounts.filter(
      (acc) => acc.allowBlobPublicAccess
    ).length;
    const exposedContainersCount = storageAccounts.reduce(
      (sum, acc) =>
        sum + acc.containers.filter((c) => c.publicAccess !== 'None').length,
      0
    );
    const cmkEncryptedAccountsCount = storageAccounts.filter(
      (acc) => acc.customerManagedKeyEnabled
    ).length;
    const tlsHardenedAccountsCount = storageAccounts.filter(
      (acc) =>
        acc.supportsHttpsTrafficOnly &&
        (acc.minimumTlsVersion === 'TLS1_2' || acc.minimumTlsVersion === 'TLS1_3')
    ).length;

    return {
      totalAccounts,
      totalContainers,
      totalBlobs,
      publicAccountsCount,
      exposedContainersCount,
      cmkEncryptedAccountsCount,
      tlsHardenedAccountsCount,
    };
  }, [storageAccounts]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const resetFilters = () => {
    setSearchQuery('');
    setAccessFilter('all');
    setEncryptionFilter('all');
    setViewMode('unified');
  };

  // Export current filtered inventory to CSV
  const handleExportCsv = () => {
    const headers = [
      'Storage Account',
      'Resource Group',
      'Location',
      'Subscription ID',
      'Account Public Blob Access',
      'Public Network Access',
      'Firewall Default Action',
      'Container Name',
      'Container Public Access',
      'Data Classification',
      'Blob Count',
      'Stored Access Policy No Expiry',
      'Full Permission SAS Issued',
      'HTTPS Traffic Only',
      'Minimum TLS Version',
      'Key Management (CMK vs MMK)',
      'Infrastructure Double Encryption',
      'Shared Key Access',
      'Soft Delete (Days)',
      'WORM Immutability',
      'Open Findings Count',
    ];

    const csvRows = filteredRows.map((r) => {
      const acc = r.account;
      const cont = r.container;
      return [
        acc.name,
        acc.resourceGroup,
        acc.location,
        acc.subscriptionId,
        acc.allowBlobPublicAccess ? 'Enabled (Allowed)' : 'Disabled',
        acc.publicNetworkAccess,
        acc.defaultAction,
        cont ? cont.name : 'No Containers',
        cont ? cont.publicAccess : 'N/A',
        cont?.dataClassification || 'Unclassified',
        cont?.blobCount ?? 0,
        cont?.hasStoredAccessPolicyWithNoExpiry ? 'Yes' : 'No',
        cont?.sasTokenIssuedWithFullPermissions ? 'Yes' : 'No',
        acc.supportsHttpsTrafficOnly ? 'HTTPS Required' : 'HTTP Permitted',
        acc.minimumTlsVersion.replace('_', '.'),
        acc.customerManagedKeyEnabled ? 'Customer-Managed Key (CMK)' : 'Microsoft-Managed Key (MMK)',
        acc.infrastructureEncryption ? 'Enabled' : 'Disabled',
        acc.allowSharedKeyAccess ? 'Enabled' : 'Disabled (Entra Only)',
        acc.softDeleteEnabled ? `${acc.blobRetentionDays}d` : 'Disabled',
        cont?.immutabilityPolicyEnabled ? 'Enabled' : 'Disabled',
        r.rowFindings.length,
      ]
        .map((val) => `"${String(val).replace(/"/g, '""')}"`)
        .join(',');
    });

    const csvContent = [headers.join(','), ...csvRows].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `maniq_shield_storage_inventory_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header & Top Actions */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-6 rounded-2xl bg-slate-900 border border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">
            Azure Storage & Container Asset Inventory
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Searchable tabular directory of all synchronized Azure Storage Accounts and Blob Containers, detailing anonymous public access configuration, network perimeter rules, transport security, and encryption key management.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {onNavigateToAuditor && (
            <button
              type="button"
              onClick={onNavigateToAuditor}
              className="px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
            >
              <span>Open Topology & Auditor View</span>
              <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
            </button>
          )}
          <button
            type="button"
            onClick={handleExportCsv}
            disabled={filteredRows.length === 0}
            className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Inventory CSV</span>
          </button>
        </div>
      </div>

      {/* Inventory KPI Summary Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs text-slate-400">Storage Accounts</div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums mt-1">
            {summaryStats.totalAccounts}
          </div>
          <div className="text-xs text-slate-500 mt-1 font-mono tabular-nums">
            {summaryStats.publicAccountsCount} allowing public blob access ·{' '}
            {summaryStats.totalAccounts - summaryStats.publicAccountsCount} private
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs text-slate-400">Blob Containers & Objects</div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums mt-1">
            {summaryStats.totalContainers}
          </div>
          <div className="text-xs text-slate-500 mt-1 font-mono tabular-nums">
            {summaryStats.totalBlobs.toLocaleString()} total indexed blobs
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs text-slate-400">Public Access Exposure</div>
          <div
            className={`text-2xl font-bold font-mono tabular-nums mt-1 ${
              summaryStats.exposedContainersCount > 0
                ? 'text-red-400'
                : 'text-emerald-400'
            }`}
          >
            {summaryStats.exposedContainersCount} Exposed
          </div>
          <div className="text-xs text-slate-500 mt-1 font-mono tabular-nums">
            {summaryStats.totalContainers - summaryStats.exposedContainersCount} private containers
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs text-slate-400">Encryption & Transport</div>
          <div className="text-2xl font-bold text-cyan-400 font-mono tabular-nums mt-1">
            {summaryStats.tlsHardenedAccountsCount}/{summaryStats.totalAccounts} HTTPS+TLS1.2
          </div>
          <div className="text-xs text-slate-500 mt-1 font-mono tabular-nums">
            {summaryStats.cmkEncryptedAccountsCount} CMK Key Vault ·{' '}
            {summaryStats.totalAccounts - summaryStats.cmkEncryptedAccountsCount} Microsoft-Managed
          </div>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by storage account, container name, resource group, region, public access (Container/Blob/None), or encryption (CMK/MMK/TLS)..."
              aria-label="Search storage inventory"
              className="w-full bg-slate-950 border border-slate-800 focus:border-blue-500 rounded-xl pl-10 pr-20 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none transition-colors"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[11px] text-slate-400 hover:text-white font-medium"
              >
                Clear
              </button>
            )}
          </div>

          {/* Segmented View Mode Switcher */}
          <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-xl self-start lg:self-auto shrink-0">
            <button
              type="button"
              onClick={() => setViewMode('unified')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                viewMode === 'unified'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Unified Table ({filteredRows.length})
            </button>
            <button
              type="button"
              onClick={() => setViewMode('accounts')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                viewMode === 'accounts'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              By Storage Account ({filteredAccounts.length})
            </button>
            <button
              type="button"
              onClick={() => setViewMode('containers')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                viewMode === 'containers'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Containers Only ({filteredRows.filter((r) => r.container !== null).length})
            </button>
          </div>
        </div>

        {/* Secondary Filter Bar: Public Access & Encryption Posture */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            {/* Public Access Filter */}
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-medium flex items-center gap-1">
                <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
                <span>Public Access:</span>
              </span>
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                <button
                  type="button"
                  onClick={() => setAccessFilter('all')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    accessFilter === 'all'
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={() => setAccessFilter('exposed')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    accessFilter === 'exposed'
                      ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Public / Exposed
                </button>
                <button
                  type="button"
                  onClick={() => setAccessFilter('private')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    accessFilter === 'private'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Private Only
                </button>
              </div>
            </div>

            {/* Encryption Filter */}
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-medium">Encryption:</span>
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                <button
                  type="button"
                  onClick={() => setEncryptionFilter('all')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    encryptionFilter === 'all'
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={() => setEncryptionFilter('weak')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    encryptionFilter === 'weak'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  HTTP / Legacy TLS / MMK
                </button>
                <button
                  type="button"
                  onClick={() => setEncryptionFilter('hardened')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    encryptionFilter === 'hardened'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  HTTPS + TLS 1.2+ & CMK
                </button>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 text-slate-400 font-mono tabular-nums">
            <span>
              Showing <strong className="text-white">{filteredRows.length}</strong> of{' '}
              {allRows.length} inventory records
            </span>
            {(searchQuery || accessFilter !== 'all' || encryptionFilter !== 'all') && (
              <button
                type="button"
                onClick={resetFilters}
                className="flex items-center gap-1 text-blue-400 hover:text-blue-300 font-sans font-medium"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Reset Filters</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Empty State Handling */}
      {storageAccounts.length === 0 ? (
        <div className="p-10 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-3">
          <div className="text-base font-bold text-white">
            No Azure Storage Accounts Synchronized in Current View
          </div>
          <p className="text-xs text-slate-400 max-w-lg mx-auto leading-relaxed">
            The active subscription currently returned 0 Storage Accounts from Azure Resource Manager, or the current Bearer Token does not yet hold subscription-level Reader access on Microsoft.Storage/storageAccounts.
          </p>
          {onSelectDataset && (
            <div className="pt-2 flex items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => onSelectDataset('high_risk')}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition-colors"
              >
                Load High-Risk Sample Inventory
              </button>
              <button
                type="button"
                onClick={() => onSelectDataset('hardened')}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
              >
                Load CIS Hardened Baseline Inventory
              </button>
            </div>
          )}
        </div>
      ) : filteredRows.length === 0 ? (
        <div className="p-10 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-3">
          <div className="text-base font-bold text-white">
            No Matching Storage Accounts or Containers
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            No inventory rows matched your current search query or filter criteria.
          </p>
          <button
            type="button"
            onClick={resetFilters}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition-colors"
          >
            Reset All Filters
          </button>
        </div>
      ) : viewMode === 'accounts' ? (
        /* Hierarchical Storage Accounts View with Expandable Container Sub-Tables */
        <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-semibold text-slate-400">
                  <th className="py-3 px-4">Storage Account & Scope</th>
                  <th className="py-3 px-4">Location</th>
                  <th className="py-3 px-4">Account Public Access & Network</th>
                  <th className="py-3 px-4">Encryption & Transport Settings</th>
                  <th className="py-3 px-4 text-right">Containers</th>
                  <th className="py-3 px-4 text-right">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-xs">
                {filteredAccounts.map((acc) => {
                  const expanded = isAccountExpanded(acc.name);
                  const accFindings = findings.filter(
                    (f) =>
                      f.resourceName === acc.name ||
                      f.resourceName.startsWith(`${acc.name}/`) ||
                      f.resourceId === acc.id ||
                      f.resourceId.startsWith(`${acc.id}/`)
                  );
                  const exposedContCount = acc.containers.filter(
                    (c) => c.publicAccess !== 'None'
                  ).length;

                  return (
                    <React.Fragment key={acc.id}>
                      <tr
                        onClick={() => toggleAccountExpanded(acc.name)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-2">
                            {expanded ? (
                              <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
                            ) : (
                              <ChevronRight className="w-4 h-4 text-slate-400 shrink-0" />
                            )}
                            <div>
                              <div className="font-mono font-bold text-white">
                                {acc.name}
                              </div>
                              <div className="text-[11px] text-slate-400 font-mono">
                                RG: {acc.resourceGroup} · Sub: {acc.subscriptionId.slice(0, 8)}...
                              </div>
                            </div>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 font-mono text-slate-300">
                          {acc.location}
                        </td>

                        <td className="py-3.5 px-4">
                          <div className="space-y-0.5">
                            <div
                              className={`font-medium ${
                                acc.allowBlobPublicAccess
                                  ? 'text-red-400'
                                  : 'text-emerald-400'
                              }`}
                            >
                              Blob Public Access:{' '}
                              {acc.allowBlobPublicAccess ? 'Enabled (Allowed)' : 'Disabled'}
                            </div>
                            <div className="text-[11px] text-slate-400 font-mono tabular-nums">
                              Network: {acc.publicNetworkAccess} · Firewall: {acc.defaultAction} ·{' '}
                              {acc.privateEndpointConnectionsCount} Private Endpoints
                            </div>
                          </div>
                        </td>

                        <td className="py-3.5 px-4">
                          <div className="space-y-0.5">
                            <div className="font-medium text-slate-200">
                              Key: {acc.customerManagedKeyEnabled ? 'Customer-Managed (CMK)' : 'Microsoft-Managed (MMK)'}
                              {' · '}
                              Infra Double Enc: {acc.infrastructureEncryption ? 'On' : 'Off'}
                            </div>
                            <div
                              className={`text-[11px] font-mono ${
                                !acc.supportsHttpsTrafficOnly ||
                                acc.minimumTlsVersion === 'TLS1_0' ||
                                acc.minimumTlsVersion === 'TLS1_1'
                                  ? 'text-amber-400'
                                  : 'text-slate-400'
                              }`}
                            >
                              {acc.supportsHttpsTrafficOnly ? 'HTTPS Only' : 'HTTP Allowed'} ·{' '}
                              Min TLS: {acc.minimumTlsVersion.replace('_', '.')} ·{' '}
                              Shared Key: {acc.allowSharedKeyAccess ? 'Enabled' : 'Disabled'}
                            </div>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 text-right font-mono tabular-nums">
                          <div className="font-bold text-white">
                            {acc.containers.length} total
                          </div>
                          <div
                            className={`text-[11px] ${
                              exposedContCount > 0 ? 'text-red-400' : 'text-emerald-400'
                            }`}
                          >
                            {exposedContCount} public
                          </div>
                        </td>

                        <td className="py-3.5 px-4 text-right font-mono tabular-nums">
                          {accFindings.length > 0 ? (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectFinding(accFindings[0].id);
                              }}
                              className="text-red-400 hover:text-red-300 underline font-semibold"
                            >
                              {accFindings.length} open
                            </button>
                          ) : (
                            <span className="text-emerald-400">0 issues</span>
                          )}
                        </td>
                      </tr>

                      {expanded && (
                        <tr className="bg-slate-950/60">
                          <td colSpan={6} className="px-8 py-3">
                            {acc.containers.length === 0 ? (
                              <div className="text-xs text-slate-500 py-2 font-mono">
                                No Blob Containers present in storage account {acc.name}.
                              </div>
                            ) : (
                              <div className="border border-slate-800/90 rounded-xl overflow-hidden">
                                <table className="w-full text-left border-collapse">
                                  <thead>
                                    <tr className="bg-slate-900/90 border-b border-slate-800 text-[11px] text-slate-400">
                                      <th className="py-2 px-3">Container Name</th>
                                      <th className="py-2 px-3">Container Public Access</th>
                                      <th className="py-2 px-3">SAS & Access Policy</th>
                                      <th className="py-2 px-3">WORM Immutability & Classification</th>
                                      <th className="py-2 px-3 text-right">Blobs</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-800/60 text-xs">
                                    {acc.containers.map((cont) => (
                                      <tr
                                        key={cont.id || cont.name}
                                        className="hover:bg-slate-900/50"
                                      >
                                        <td className="py-2.5 px-3 font-mono font-semibold text-cyan-300">
                                          {cont.name}
                                        </td>
                                        <td className="py-2.5 px-3">
                                          <span
                                            className={`font-medium ${
                                              cont.publicAccess === 'Container'
                                                ? 'text-red-400'
                                                : cont.publicAccess === 'Blob'
                                                ? 'text-amber-400'
                                                : 'text-emerald-400'
                                            }`}
                                          >
                                            {cont.publicAccess === 'Container'
                                              ? 'Container (Anonymous Read/List)'
                                              : cont.publicAccess === 'Blob'
                                              ? 'Blob (Anonymous Read Only)'
                                              : 'None (Private)'}
                                          </span>
                                        </td>
                                        <td className="py-2.5 px-3 text-[11px] text-slate-300">
                                          {cont.hasStoredAccessPolicyWithNoExpiry
                                            ? 'Infinite Stored Policy'
                                            : 'Standard Expiry'}{' '}
                                          ·{' '}
                                          {cont.sasTokenIssuedWithFullPermissions
                                            ? 'Full-Perm SAS Active'
                                            : 'Scoped SAS'}
                                        </td>
                                        <td className="py-2.5 px-3 text-[11px] text-slate-300">
                                          WORM: {cont.immutabilityPolicyEnabled ? 'Locked' : 'Unlocked'}{' '}
                                          · Class: {cont.dataClassification || 'Internal'}
                                        </td>
                                        <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-200">
                                          {(cont.blobCount ?? 0).toLocaleString()}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Unified & Containers-Only Flat Searchable Table View */
        <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-semibold text-slate-400">
                  <th className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleSort('accountName')}
                      className="flex items-center gap-1 hover:text-white transition-colors whitespace-nowrap"
                    >
                      <span>Storage Account & Resource Group</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleSort('containerName')}
                      className="flex items-center gap-1 hover:text-white transition-colors whitespace-nowrap"
                    >
                      <span>Blob Container & Classification</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleSort('publicAccess')}
                      className="flex items-center gap-1 hover:text-white transition-colors whitespace-nowrap"
                    >
                      <span>Public Access Settings</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleSort('encryption')}
                      className="flex items-center gap-1 hover:text-white transition-colors whitespace-nowrap"
                    >
                      <span>Encryption & Transport Settings</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4 text-right">
                    <button
                      type="button"
                      onClick={() => handleSort('blobCount')}
                      className="flex items-center justify-end gap-1 ml-auto hover:text-white transition-colors whitespace-nowrap"
                    >
                      <span>Blobs</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4 text-right">
                    <button
                      type="button"
                      onClick={() => handleSort('findings')}
                      className="flex items-center justify-end gap-1 ml-auto hover:text-white transition-colors whitespace-nowrap"
                    >
                      <span>Audit Status</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-xs">
                {filteredRows.map((row) => {
                  const { account: acc, container: cont, rowFindings } = row;
                  const topFinding = rowFindings[0];

                  return (
                    <tr
                      key={row.rowId}
                      className="hover:bg-slate-800/40 transition-colors"
                    >
                      {/* Storage Account & Resource Group */}
                      <td className="py-3.5 px-4 align-top">
                        <div className="font-mono font-bold text-white">
                          {acc.name}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                          {acc.resourceGroup} · {acc.location}
                        </div>
                      </td>

                      {/* Container Name & Classification */}
                      <td className="py-3.5 px-4 align-top">
                        {cont ? (
                          <div>
                            <div className="font-mono font-semibold text-cyan-300">
                              {cont.name}
                            </div>
                            <div className="text-[11px] text-slate-400 mt-0.5">
                              {cont.dataClassification || 'Internal'} ·{' '}
                              {cont.immutabilityPolicyEnabled
                                ? 'WORM Locked'
                                : 'No WORM Policy'}
                            </div>
                          </div>
                        ) : (
                          <span className="text-slate-500 font-mono">
                            No containers provisioned
                          </span>
                        )}
                      </td>

                      {/* Public Access Settings (Account + Container) */}
                      <td className="py-3.5 px-4 align-top">
                        <div className="space-y-0.5">
                          {cont ? (
                            <div
                              className={`font-semibold ${
                                cont.publicAccess === 'Container'
                                  ? 'text-red-400'
                                  : cont.publicAccess === 'Blob'
                                  ? 'text-amber-400'
                                  : 'text-emerald-400'
                              }`}
                            >
                              Container Access:{' '}
                              {cont.publicAccess === 'Container'
                                ? 'Container (Anonymous Read/List)'
                                : cont.publicAccess === 'Blob'
                                ? 'Blob (Anonymous Read)'
                                : 'None (Private)'}
                            </div>
                          ) : (
                            <div className="text-slate-400 font-medium">
                              Container Access: N/A
                            </div>
                          )}

                          <div className="text-[11px] text-slate-400 font-mono">
                            Account Public Blob:{' '}
                            <span
                              className={
                                acc.allowBlobPublicAccess
                                  ? 'text-red-300'
                                  : 'text-emerald-300'
                              }
                            >
                              {acc.allowBlobPublicAccess ? 'Allowed' : 'Disabled'}
                            </span>{' '}
                            · Firewall: {acc.defaultAction} ({acc.publicNetworkAccess})
                          </div>

                          {cont &&
                            (cont.hasStoredAccessPolicyWithNoExpiry ||
                              cont.sasTokenIssuedWithFullPermissions) && (
                              <div className="text-[11px] text-amber-300 font-mono">
                                {cont.hasStoredAccessPolicyWithNoExpiry
                                  ? 'No-Expiry Policy'
                                  : ''}
                                {cont.hasStoredAccessPolicyWithNoExpiry &&
                                cont.sasTokenIssuedWithFullPermissions
                                  ? ' · '
                                  : ''}
                                {cont.sasTokenIssuedWithFullPermissions
                                  ? 'Full-Perm SAS'
                                  : ''}
                              </div>
                            )}
                        </div>
                      </td>

                      {/* Encryption & Transport Settings */}
                      <td className="py-3.5 px-4 align-top">
                        <div className="space-y-0.5">
                          <div className="font-medium text-slate-200">
                            {acc.customerManagedKeyEnabled
                              ? 'Customer-Managed Key (CMK)'
                              : 'Microsoft-Managed Key (MMK)'}{' '}
                            ·{' '}
                            <span className="text-slate-400">
                              {acc.infrastructureEncryption
                                ? 'Double Infra Enc'
                                : 'Standard Enc'}
                            </span>
                          </div>
                          <div
                            className={`text-[11px] font-mono ${
                              !acc.supportsHttpsTrafficOnly ||
                              acc.minimumTlsVersion === 'TLS1_0' ||
                              acc.minimumTlsVersion === 'TLS1_1'
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {acc.supportsHttpsTrafficOnly
                              ? 'HTTPS Required'
                              : 'HTTP Allowed (Insecure)'}{' '}
                            · {acc.minimumTlsVersion.replace('_', '.')} ·{' '}
                            {acc.allowSharedKeyAccess
                              ? 'Shared Key Enabled'
                              : 'Entra ID Only'}
                          </div>
                        </div>
                      </td>

                      {/* Blob Count */}
                      <td className="py-3.5 px-4 align-top text-right font-mono tabular-nums text-slate-200">
                        {cont ? (cont.blobCount ?? 0).toLocaleString() : '—'}
                      </td>

                      {/* Audit Status / Findings Drill-Down */}
                      <td className="py-3.5 px-4 align-top text-right font-mono tabular-nums">
                        {rowFindings.length > 0 && topFinding ? (
                          <button
                            type="button"
                            onClick={() => onSelectFinding(topFinding.id)}
                            className="text-red-400 hover:text-red-300 underline font-semibold whitespace-nowrap"
                          >
                            {rowFindings.length}{' '}
                            {rowFindings.length === 1 ? 'finding' : 'findings'} →
                          </button>
                        ) : (
                          <span className="text-emerald-400 whitespace-nowrap">
                            Hardened
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
