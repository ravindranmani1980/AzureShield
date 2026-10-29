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
      {/* Header & Top Actions (Postrix .xh-panel) */}
      <section className="xh-panel space-y-5">
        <div className="xh-kicker">
          <span className="k">Asset Configuration Directory · Storage &amp; Containers</span>
          <span className="tag">
            {summaryStats.totalAccounts} Accounts · {summaryStats.totalContainers} Containers
          </span>
        </div>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl sm:text-2xl font-semibold text-[#EEF3F1] tracking-tight">
              Azure Storage &amp; Container Asset Inventory
            </h2>
            <p className="text-xs text-[#A9B7BF] mt-1 max-w-3xl leading-relaxed">
              Searchable tabular directory of all synchronized Azure Storage Accounts and Blob Containers, detailing anonymous public access configuration, network perimeter rules, transport security, and encryption key management.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            {onNavigateToAuditor && (
              <button
                type="button"
                onClick={onNavigateToAuditor}
                className="xh-btn whitespace-nowrap shrink-0"
              >
                <span>Open Topology &amp; Auditor View</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            )}
            <button
              type="button"
              onClick={handleExportCsv}
              disabled={filteredRows.length === 0}
              className="xh-btn primary disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Inventory CSV</span>
            </button>
          </div>
        </div>

        {/* Inventory KPI Summary Strip (.xh-metric) */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
          <div className="xh-metric">
            <div className="lbl">
              <span>STORAGE ACCOUNTS</span>
            </div>
            <div className="num tabular-nums">{summaryStats.totalAccounts}</div>
            <p>
              {summaryStats.publicAccountsCount} allowing public blob access ·{' '}
              {summaryStats.totalAccounts - summaryStats.publicAccountsCount} private
            </p>
          </div>

          <div className="xh-metric">
            <div className="lbl">
              <span>BLOB CONTAINERS</span>
            </div>
            <div className="num tabular-nums">{summaryStats.totalContainers}</div>
            <p>{summaryStats.totalBlobs.toLocaleString()} total indexed blobs</p>
          </div>

          <div className="xh-metric">
            <div className="lbl">
              <span>PUBLIC ACCESS EXPOSURE</span>
            </div>
            <div className="num hi tabular-nums">
              {summaryStats.exposedContainersCount} Exposed
            </div>
            <p>
              {summaryStats.totalContainers - summaryStats.exposedContainersCount} private containers
            </p>
          </div>

          <div className="xh-metric">
            <div className="lbl">
              <span>ENCRYPTION &amp; TRANSPORT</span>
            </div>
            <div className="num hi tabular-nums">
              {summaryStats.tlsHardenedAccountsCount}/{summaryStats.totalAccounts} HTTPS+TLS1.2
            </div>
            <p>
              {summaryStats.cmkEncryptedAccountsCount} CMK Key Vault ·{' '}
              {summaryStats.totalAccounts - summaryStats.cmkEncryptedAccountsCount} Microsoft-Managed
            </p>
          </div>
        </div>
      </section>

      {/* Search & Filter Toolbar */}
      <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-3">
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
              className="w-full bg-slate-50 border border-slate-200 focus:border-[#0E2238] focus:bg-white rounded-lg pl-10 pr-20 py-2 text-xs text-slate-900 placeholder-slate-500 focus:outline-none transition-colors"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[11px] text-slate-500 hover:text-slate-900 font-medium cursor-pointer"
              >
                Clear
              </button>
            )}
          </div>

          {/* Segmented View Mode Switcher */}
          <div className="flex items-center gap-1 p-1 bg-slate-100 border border-slate-200 rounded-lg self-start lg:self-auto shrink-0">
            <button
              type="button"
              onClick={() => setViewMode('unified')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                viewMode === 'unified'
                  ? 'bg-[#0E2238] text-[#EEF3F1]'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Unified Table ({filteredRows.length})
            </button>
            <button
              type="button"
              onClick={() => setViewMode('accounts')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                viewMode === 'accounts'
                  ? 'bg-[#0E2238] text-[#EEF3F1]'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              By Storage Account ({filteredAccounts.length})
            </button>
            <button
              type="button"
              onClick={() => setViewMode('containers')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                viewMode === 'containers'
                  ? 'bg-[#0E2238] text-[#EEF3F1]'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Containers Only ({filteredRows.filter((r) => r.container !== null).length})
            </button>
          </div>
        </div>

        {/* Secondary Filter Bar: Public Access & Encryption Posture */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-200 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            {/* Public Access Filter */}
            <div className="flex items-center gap-2">
              <span className="text-slate-600 font-medium flex items-center gap-1">
                <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
                <span>Public Access:</span>
              </span>
              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
                <button
                  type="button"
                  onClick={() => setAccessFilter('all')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    accessFilter === 'all'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={() => setAccessFilter('exposed')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    accessFilter === 'exposed'
                      ? 'bg-red-50 text-red-700 border border-red-200'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Public / Exposed
                </button>
                <button
                  type="button"
                  onClick={() => setAccessFilter('private')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    accessFilter === 'private'
                      ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Private Only
                </button>
              </div>
            </div>

            {/* Encryption Filter */}
            <div className="flex items-center gap-2">
              <span className="text-slate-600 font-medium">Encryption:</span>
              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
                <button
                  type="button"
                  onClick={() => setEncryptionFilter('all')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    encryptionFilter === 'all'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={() => setEncryptionFilter('weak')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    encryptionFilter === 'weak'
                      ? 'bg-amber-50 text-amber-800 border border-amber-200'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  HTTP / Legacy TLS / MMK
                </button>
                <button
                  type="button"
                  onClick={() => setEncryptionFilter('hardened')}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    encryptionFilter === 'hardened'
                      ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  HTTPS + TLS 1.2+ &amp; CMK
                </button>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 text-slate-600 font-mono tabular-nums">
            <span>
              Showing <strong className="text-slate-900">{filteredRows.length}</strong> of{' '}
              {allRows.length} inventory records
            </span>
            {(searchQuery || accessFilter !== 'all' || encryptionFilter !== 'all') && (
              <button
                type="button"
                onClick={resetFilters}
                className="flex items-center gap-1 text-emerald-700 hover:underline font-sans font-medium cursor-pointer"
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
        <div className="p-10 rounded-xl bg-white border border-slate-200 shadow-xs text-center space-y-3">
          <div className="text-base font-serif font-semibold text-slate-900">
            No Azure Storage Accounts Synchronized in Current View
          </div>
          <p className="text-xs text-slate-600 max-w-lg mx-auto leading-relaxed">
            The active subscription currently returned 0 Storage Accounts from Azure Resource Manager, or the current Bearer Token does not yet hold subscription-level Reader access on Microsoft.Storage/storageAccounts.
          </p>
          {onSelectDataset && (
            <div className="pt-2 flex items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => onSelectDataset('high_risk')}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#081420] text-[#EEF3F1] transition-colors cursor-pointer"
              >
                Load High-Risk Sample Inventory
              </button>
              <button
                type="button"
                onClick={() => onSelectDataset('hardened')}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-300 transition-colors cursor-pointer"
              >
                Load CIS Hardened Baseline Inventory
              </button>
            </div>
          )}
        </div>
      ) : filteredRows.length === 0 ? (
        <div className="p-10 rounded-xl bg-white border border-slate-200 shadow-xs text-center space-y-3">
          <div className="text-base font-serif font-semibold text-slate-900">
            No Matching Storage Accounts or Containers
          </div>
          <p className="text-xs text-slate-600 max-w-md mx-auto">
            No inventory rows matched your current search query or filter criteria.
          </p>
          <button
            type="button"
            onClick={resetFilters}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#081420] text-[#EEF3F1] transition-colors cursor-pointer"
          >
            Reset All Filters
          </button>
        </div>
      ) : viewMode === 'accounts' ? (
        /* Hierarchical Storage Accounts View with Expandable Container Sub-Tables */
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-mono uppercase tracking-wider font-semibold text-slate-600">
                  <th className="py-3 px-4">Storage Account &amp; Scope</th>
                  <th className="py-3 px-4">Location</th>
                  <th className="py-3 px-4">Account Public Access &amp; Network</th>
                  <th className="py-3 px-4">Encryption &amp; Transport Settings</th>
                  <th className="py-3 px-4 text-right">Containers</th>
                  <th className="py-3 px-4 text-right">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-xs">
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
                        className="hover:bg-slate-50/80 cursor-pointer transition-colors"
                      >
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-2">
                            {expanded ? (
                              <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                            ) : (
                              <ChevronRight className="w-4 h-4 text-slate-500 shrink-0" />
                            )}
                            <div>
                              <div className="font-mono font-bold text-slate-900">
                                {acc.name}
                              </div>
                              <div className="text-[11px] text-slate-500 font-mono">
                                RG: {acc.resourceGroup} · Sub: {acc.subscriptionId.slice(0, 8)}...
                              </div>
                            </div>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 font-mono text-slate-700">
                          {acc.location}
                        </td>

                        <td className="py-3.5 px-4">
                          <div className="space-y-0.5">
                            <div
                              className={`font-semibold ${
                                acc.allowBlobPublicAccess
                                  ? 'text-red-700'
                                  : 'text-emerald-700'
                              }`}
                            >
                              Blob Public Access:{' '}
                              {acc.allowBlobPublicAccess ? 'Enabled (Allowed)' : 'Disabled'}
                            </div>
                            <div className="text-[11px] text-slate-500 font-mono tabular-nums">
                              Network: {acc.publicNetworkAccess} · Firewall: {acc.defaultAction} ·{' '}
                              {acc.privateEndpointConnectionsCount} Private Endpoints
                            </div>
                          </div>
                        </td>

                        <td className="py-3.5 px-4">
                          <div className="space-y-0.5">
                            <div className="font-medium text-slate-800">
                              Key: {acc.customerManagedKeyEnabled ? 'Customer-Managed (CMK)' : 'Microsoft-Managed (MMK)'}
                              {' · '}
                              Infra Double Enc: {acc.infrastructureEncryption ? 'On' : 'Off'}
                            </div>
                            <div
                              className={`text-[11px] font-mono ${
                                !acc.supportsHttpsTrafficOnly ||
                                acc.minimumTlsVersion === 'TLS1_0' ||
                                acc.minimumTlsVersion === 'TLS1_1'
                                  ? 'text-amber-700 font-semibold'
                                  : 'text-slate-600'
                              }`}
                            >
                              {acc.supportsHttpsTrafficOnly ? 'HTTPS Only' : 'HTTP Allowed'} ·{' '}
                              Min TLS: {acc.minimumTlsVersion.replace('_', '.')} ·{' '}
                              Shared Key: {acc.allowSharedKeyAccess ? 'Enabled' : 'Disabled'}
                            </div>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 text-right font-mono tabular-nums">
                          <div className="font-bold text-slate-900">
                            {acc.containers.length} total
                          </div>
                          <div
                            className={`text-[11px] ${
                              exposedContCount > 0 ? 'text-red-700 font-semibold' : 'text-emerald-700'
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
                              className="text-red-700 hover:underline font-semibold cursor-pointer"
                            >
                              {accFindings.length} open
                            </button>
                          ) : (
                            <span className="text-emerald-700 font-semibold">0 issues</span>
                          )}
                        </td>
                      </tr>

                      {expanded && (
                        <tr className="bg-slate-50/70">
                          <td colSpan={6} className="px-8 py-3">
                            {acc.containers.length === 0 ? (
                              <div className="text-xs text-slate-500 py-2 font-mono">
                                No Blob Containers present in storage account {acc.name}.
                              </div>
                            ) : (
                              <div className="border border-slate-200 bg-white rounded-lg overflow-hidden">
                                <table className="w-full text-left border-collapse">
                                  <thead>
                                    <tr className="bg-slate-100 border-b border-slate-200 text-[11px] font-mono text-slate-600">
                                      <th className="py-2 px-3">Container Name</th>
                                      <th className="py-2 px-3">Container Public Access</th>
                                      <th className="py-2 px-3">SAS &amp; Access Policy</th>
                                      <th className="py-2 px-3">WORM Immutability &amp; Classification</th>
                                      <th className="py-2 px-3 text-right">Blobs</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-200 text-xs">
                                    {acc.containers.map((cont) => (
                                      <tr
                                        key={cont.id || cont.name}
                                        className="hover:bg-slate-50"
                                      >
                                        <td className="py-2.5 px-3 font-mono font-semibold text-emerald-800">
                                          {cont.name}
                                        </td>
                                        <td className="py-2.5 px-3">
                                          <span
                                            className={`font-semibold ${
                                              cont.publicAccess === 'Container'
                                                ? 'text-red-700'
                                                : cont.publicAccess === 'Blob'
                                                ? 'text-amber-700'
                                                : 'text-emerald-700'
                                            }`}
                                          >
                                            {cont.publicAccess === 'Container'
                                              ? 'Container (Anonymous Read/List)'
                                              : cont.publicAccess === 'Blob'
                                              ? 'Blob (Anonymous Read Only)'
                                              : 'None (Private)'}
                                          </span>
                                        </td>
                                        <td className="py-2.5 px-3 text-[11px] text-slate-700">
                                          {cont.hasStoredAccessPolicyWithNoExpiry
                                            ? 'Infinite Stored Policy'
                                            : 'Standard Expiry'}{' '}
                                          ·{' '}
                                          {cont.sasTokenIssuedWithFullPermissions
                                            ? 'Full-Perm SAS Active'
                                            : 'Scoped SAS'}
                                        </td>
                                        <td className="py-2.5 px-3 text-[11px] text-slate-700">
                                          WORM: {cont.immutabilityPolicyEnabled ? 'Locked' : 'Unlocked'}{' '}
                                          · Class: {cont.dataClassification || 'Internal'}
                                        </td>
                                        <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-900">
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
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-mono uppercase tracking-wider font-semibold text-slate-600">
                  <th className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleSort('accountName')}
                      className="flex items-center gap-1 hover:text-slate-900 transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <span>Storage Account &amp; Resource Group</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleSort('containerName')}
                      className="flex items-center gap-1 hover:text-slate-900 transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <span>Blob Container &amp; Classification</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleSort('publicAccess')}
                      className="flex items-center gap-1 hover:text-slate-900 transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <span>Public Access Settings</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleSort('encryption')}
                      className="flex items-center gap-1 hover:text-slate-900 transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <span>Encryption &amp; Transport Settings</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4 text-right">
                    <button
                      type="button"
                      onClick={() => handleSort('blobCount')}
                      className="flex items-center justify-end gap-1 ml-auto hover:text-slate-900 transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <span>Blobs</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4 text-right">
                    <button
                      type="button"
                      onClick={() => handleSort('findings')}
                      className="flex items-center justify-end gap-1 ml-auto hover:text-slate-900 transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <span>Audit Status</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-xs">
                {filteredRows.map((row) => {
                  const { account: acc, container: cont, rowFindings } = row;
                  const topFinding = rowFindings[0];

                  return (
                    <tr
                      key={row.rowId}
                      className="hover:bg-slate-50/80 transition-colors"
                    >
                      <td className="py-3.5 px-4 align-top">
                        <div className="font-mono font-bold text-slate-900">
                          {acc.name}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                          {acc.resourceGroup} · {acc.location}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top">
                        {cont ? (
                          <div>
                            <div className="font-mono font-semibold text-emerald-800">
                              {cont.name}
                            </div>
                            <div className="text-[11px] text-slate-500 mt-0.5">
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

                      <td className="py-3.5 px-4 align-top">
                        <div className="space-y-0.5">
                          {cont ? (
                            <div
                              className={`font-semibold ${
                                cont.publicAccess === 'Container'
                                  ? 'text-red-700'
                                  : cont.publicAccess === 'Blob'
                                  ? 'text-amber-700'
                                  : 'text-emerald-700'
                              }`}
                            >
                              Container:{' '}
                              {cont.publicAccess === 'Container'
                                ? 'Public (Container Read/List)'
                                : cont.publicAccess === 'Blob'
                                ? 'Public (Blob Read Only)'
                                : 'Private (None)'}
                            </div>
                          ) : (
                            <div className="text-slate-600 font-medium">
                              Container: N/A
                            </div>
                          )}

                          <div className="text-[11px] text-slate-600 font-mono">
                            Account Blob Public:{' '}
                            <span
                              className={
                                acc.allowBlobPublicAccess
                                  ? 'text-red-700 font-semibold'
                                  : 'text-emerald-700'
                              }
                            >
                              {acc.allowBlobPublicAccess ? 'Allowed' : 'Disabled'}
                            </span>{' '}
                            · Firewall: {acc.defaultAction}
                          </div>

                          {cont &&
                            (cont.hasStoredAccessPolicyWithNoExpiry ||
                              cont.sasTokenIssuedWithFullPermissions) && (
                              <div className="text-[11px] text-amber-700 font-mono font-semibold">
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

                      <td className="py-3.5 px-4 align-top">
                        <div className="space-y-0.5">
                          <div className="font-medium text-slate-800">
                            {acc.customerManagedKeyEnabled
                              ? 'Customer-Managed Key (CMK)'
                              : 'Microsoft-Managed Key (MMK)'}{' '}
                            ·{' '}
                            <span className="text-slate-500">
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
                                ? 'text-amber-700 font-semibold'
                                : 'text-emerald-700'
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

                      <td className="py-3.5 px-4 align-top text-right font-mono tabular-nums text-slate-900">
                        {cont ? (cont.blobCount ?? 0).toLocaleString() : '—'}
                      </td>

                      <td className="py-3.5 px-4 align-top text-right font-mono tabular-nums">
                        {rowFindings.length > 0 && topFinding ? (
                          <button
                            type="button"
                            onClick={() => onSelectFinding(topFinding.id)}
                            className="text-red-700 hover:underline font-semibold whitespace-nowrap cursor-pointer"
                          >
                            {rowFindings.length}{' '}
                            {rowFindings.length === 1 ? 'finding' : 'findings'} →
                          </button>
                        ) : (
                          <span className="text-emerald-700 font-semibold whitespace-nowrap">
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
