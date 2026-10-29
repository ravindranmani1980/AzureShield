/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  X,
  Radio,
  Server,
  Key,
  Terminal,
  CheckCircle2,
  AlertCircle,
  FileCode,
  ArrowRight,
  RefreshCw,
  Zap,
  Globe,
  Upload,
  Layers,
  Sparkles,
} from 'lucide-react';
import {
  fetchLiveAzureResources,
  parseAzureRoleAssignmentsJson,
  parseAzureStorageAccountsJson,
} from '../utils/azureLiveApi';
import { RbacAssignment, StorageAccount } from '../types/security';

interface LiveAzureSyncModalProps {
  isOpen: boolean;
  onClose: () => void;
  onApplyLiveResources: (data: {
    storageAccounts: StorageAccount[];
    roleAssignments: RbacAssignment[];
    subscriptionId: string;
    sourceName: string;
  }) => void;
  isLiveConnected: boolean;
  onToggleContinuousEventStream: () => void;
  isEventStreamActive: boolean;
}

export const LiveAzureSyncModal: React.FC<LiveAzureSyncModalProps> = ({
  isOpen,
  onClose,
  onApplyLiveResources,
  isLiveConnected,
  onToggleContinuousEventStream,
  isEventStreamActive,
}) => {
  const [activeTab, setActiveTab] = useState<'api' | 'cli' | 'stream'>('api');

  // REST API credentials
  const [subscriptionId, setSubscriptionId] = useState(
    'a8f93e11-44bb-4e92-91ef-00129a883100'
  );
  const [tenantId, setTenantId] = useState('');
  const [accessToken, setAccessToken] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [syncStatus, setSyncStatus] = useState<{
    type: 'success' | 'error' | 'idle';
    message?: string;
  }>({ type: 'idle' });

  // CLI JSON paste state
  const [storageJsonText, setStorageJsonText] = useState('');
  const [rbacJsonText, setRbacJsonText] = useState('');
  const [cliError, setCliError] = useState<string | null>(null);

  if (!isOpen) return null;

  // Handle direct REST API live fetch
  const handleFetchFromAzure = async () => {
    if (!subscriptionId.trim()) {
      setSyncStatus({
        type: 'error',
        message: 'Please provide a valid Azure Subscription ID.',
      });
      return;
    }
    if (!accessToken.trim()) {
      setSyncStatus({
        type: 'error',
        message:
          'Please paste an Azure Access Token. Generate one via: az account get-access-token --resource https://management.azure.com --query accessToken -o tsv',
      });
      return;
    }

    setIsLoading(true);
    setSyncStatus({ type: 'idle' });

    try {
      const result = await fetchLiveAzureResources({
        subscriptionId,
        tenantId,
        accessToken,
      });

      onApplyLiveResources({
        storageAccounts: result.storageAccounts,
        roleAssignments: result.roleAssignments,
        subscriptionId,
        sourceName: `Live Azure Subscription (${subscriptionId.slice(0, 8)}...)`,
      });

      setSyncStatus({
        type: 'success',
        message: `Successfully synchronized live Azure environment: Discovered ${result.storageAccounts.length} Storage Account(s) and ${result.roleAssignments.length} RBAC Assignment(s).`,
      });
    } catch (err: any) {
      console.warn('Live API fetch error, providing diagnostics:', err);
      // Browser cross-origin or auth expired guidance
      setSyncStatus({
        type: 'error',
        message: `Live ARM REST API Error: ${err.message || 'Network/CORS restriction'}. Tip: Use the 'Azure Cloud Shell CLI Ingestion' tab to paste your live az output directly with zero CORS restrictions.`,
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Handle raw CLI output parsing
  const handleParseCliJson = () => {
    setCliError(null);
    try {
      let parsedStorage: StorageAccount[] = [];
      let parsedRbac: RbacAssignment[] = [];

      if (storageJsonText.trim()) {
        const rawStorage = JSON.parse(storageJsonText);
        parsedStorage = parseAzureStorageAccountsJson(rawStorage);
      }

      if (rbacJsonText.trim()) {
        const rawRbac = JSON.parse(rbacJsonText);
        parsedRbac = parseAzureRoleAssignmentsJson(rawRbac);
      }

      if (parsedStorage.length === 0 && parsedRbac.length === 0) {
        setCliError('Please paste valid JSON for either Storage Accounts or Role Assignments.');
        return;
      }

      onApplyLiveResources({
        storageAccounts: parsedStorage,
        roleAssignments: parsedRbac,
        subscriptionId: parsedStorage[0]?.subscriptionId || 'live-azure-sub',
        sourceName: 'Live Azure CLI Ingestion',
      });

      onClose();
    } catch (err: any) {
      setCliError(`JSON Parse Error: ${err.message}. Please ensure the input is valid JSON.`);
    }
  };

  // Quick sample loader for live demo
  const loadRealWorldAzureSnapshot = () => {
    const sampleLiveStorage = [
      {
        id: `/subscriptions/${subscriptionId}/resourceGroups/rg-prod-eu/providers/Microsoft.Storage/storageAccounts/cloudprodstore99`,
        name: 'cloudprodstore99',
        location: 'westeurope',
        resourceGroup: 'rg-prod-eu',
        properties: {
          allowBlobPublicAccess: true,
          supportsHttpsTrafficOnly: false,
          minimumTlsVersion: 'TLS1_0',
          publicNetworkAccess: 'Enabled',
          networkAcls: { defaultAction: 'Allow', ipRules: [] },
          encryption: { requireInfrastructureEncryption: false },
        },
        containers: [
          {
            name: 'live-customer-orders',
            publicAccess: 'Blob',
            blobCount: 4210,
            hasStoredAccessPolicyWithNoExpiry: true,
          },
          {
            name: 'database-snapshots',
            publicAccess: 'None',
            blobCount: 65,
          },
        ],
      },
    ];

    const sampleLiveRbac = [
      {
        id: 'live-assign-1',
        properties: {
          roleDefinitionName: 'Owner',
          principalName: 'devops_consultant#EXT#@external-vendor.com',
          principalType: 'User',
          scope: `/subscriptions/${subscriptionId}`,
          lastActiveDays: 14,
          mfaEnforced: false,
        },
      },
      {
        id: 'live-assign-2',
        properties: {
          roleDefinitionName: 'Deployment Service Principal',
          principalName: 'sp-automated-pipeline',
          principalType: 'ServicePrincipal',
          scope: `/subscriptions/${subscriptionId}`,
          actions: ['Microsoft.Storage/*', 'Microsoft.Authorization/roleAssignments/write'],
          lastActiveDays: 1,
        },
      },
    ];

    setStorageJsonText(JSON.stringify(sampleLiveStorage, null, 2));
    setRbacJsonText(JSON.stringify(sampleLiveRbac, null, 2));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl text-slate-100 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/70">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/20">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="font-bold text-sm text-white">
                  Live Azure Integration & Real-Time Sync
                </h3>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold flex items-center space-x-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping mr-1" />
                  Live Sync Engine
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Connect directly to your real Azure tenant via ARM REST API or Azure Cloud Shell telemetry.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center px-6 pt-3 border-b border-slate-800 bg-slate-950/40 space-x-2 text-xs">
          <button
            onClick={() => setActiveTab('api')}
            className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
              activeTab === 'api'
                ? 'border-blue-500 text-white'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-4 h-4 text-blue-400" />
            <span>Azure ARM REST API</span>
          </button>
          <button
            onClick={() => setActiveTab('cli')}
            className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
              activeTab === 'cli'
                ? 'border-blue-500 text-white'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>Azure Cloud Shell / CLI Stream</span>
          </button>
          <button
            onClick={() => setActiveTab('stream')}
            className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
              activeTab === 'stream'
                ? 'border-blue-500 text-white'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-4 h-4 text-emerald-400" />
            <span>Real-Time Activity Event Stream</span>
          </button>
        </div>

        {/* Tab 1: Direct ARM REST API Sync */}
        {activeTab === 'api' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1">
            <div className="p-3.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300 leading-relaxed">
              <strong>Direct REST API Connection:</strong> Queries{' '}
              <code className="bg-slate-950 px-1 py-0.5 rounded text-cyan-300 font-mono">
                https://management.azure.com/providers/Microsoft.Storage
              </code>{' '}
              and{' '}
              <code className="bg-slate-950 px-1 py-0.5 rounded text-cyan-300 font-mono">
                /providers/Microsoft.Authorization/roleAssignments
              </code>{' '}
              to inspect live cloud infrastructure in real time.
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-bold text-slate-300 mb-1">
                  Azure Subscription ID:
                </label>
                <input
                  type="text"
                  value={subscriptionId}
                  onChange={(e) => setSubscriptionId(e.target.value)}
                  placeholder="e.g. 4b8e219a-94fc-4809-b6bb-2a1e8a93ef01"
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-xl px-3 py-2 font-mono focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-bold text-slate-300">
                    Azure Access Token (Bearer):
                  </label>
                  <span className="text-[11px] text-slate-400 font-mono">
                    Session token from Azure CLI
                  </span>
                </div>
                <textarea
                  rows={3}
                  value={accessToken}
                  onChange={(e) => setAccessToken(e.target.value)}
                  placeholder="Paste access token from: az account get-access-token --resource https://management.azure.com --query accessToken -o tsv"
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-xl p-3 font-mono focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
                <div className="mt-1 text-[11px] text-slate-400">
                  Tip: Generate quickly in Azure Cloud Shell:{' '}
                  <code className="bg-slate-950 px-1.5 py-0.5 rounded text-cyan-300 font-mono">
                    az account get-access-token -o tsv --query accessToken
                  </code>
                </div>
              </div>

              {/* Status Message */}
              {syncStatus.type === 'error' && (
                <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-300 text-xs flex items-start space-x-2">
                  <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>{syncStatus.message}</span>
                </div>
              )}

              {syncStatus.type === 'success' && (
                <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs flex items-start space-x-2">
                  <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>{syncStatus.message}</span>
                </div>
              )}
            </div>

            <div className="pt-2 flex items-center justify-between">
              <button
                type="button"
                onClick={() => setActiveTab('cli')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
              >
                Switch to Direct CLI JSON Ingestion →
              </button>

              <button
                type="button"
                onClick={handleFetchFromAzure}
                disabled={isLoading}
                className="flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-blue-600/20 transition-all active:scale-95 disabled:opacity-50"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Synchronizing Azure...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    <span>Fetch Live Real-Time Infrastructure</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Tab 2: CLI Output Ingestion */}
        {activeTab === 'cli' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-300 font-medium">
                Paste real-time JSON outputs from Azure CLI or CI/CD pipelines:
              </span>
              <button
                onClick={loadRealWorldAzureSnapshot}
                className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center space-x-1"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Load Live Sample Payload</span>
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-bold text-slate-300 font-mono">
                    1. az storage account list -o json
                  </span>
                  <span className="text-[11px] text-slate-500">
                    Storage accounts & containers
                  </span>
                </div>
                <textarea
                  rows={4}
                  value={storageJsonText}
                  onChange={(e) => setStorageJsonText(e.target.value)}
                  placeholder='[ { "name": "corpstore01", "properties": { "allowBlobPublicAccess": true, ... } } ]'
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-xl p-3 font-mono focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-bold text-slate-300 font-mono">
                    2. az role assignment list --all -o json
                  </span>
                  <span className="text-[11px] text-slate-500">
                    RBAC role assignments
                  </span>
                </div>
                <textarea
                  rows={4}
                  value={rbacJsonText}
                  onChange={(e) => setRbacJsonText(e.target.value)}
                  placeholder='[ { "properties": { "roleDefinitionName": "Owner", "principalName": "user#EXT#@partner.com", ... } } ]'
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-xl p-3 font-mono focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {cliError && (
                <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-300 text-xs flex items-center space-x-2">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{cliError}</span>
                </div>
              )}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                type="button"
                onClick={handleParseCliJson}
                className="flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-blue-600/20 transition-all active:scale-95"
              >
                <Layers className="w-4 h-4" />
                <span>Ingest & Run Live Loophole Audit</span>
              </button>
            </div>
          </div>
        )}

        {/* Tab 3: Real-Time Event Stream */}
        {activeTab === 'stream' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1">
            <div className="flex items-center justify-between p-4 rounded-2xl bg-slate-950 border border-slate-800">
              <div className="flex items-center space-x-3">
                <div
                  className={`p-3 rounded-xl ${
                    isEventStreamActive
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  <Radio
                    className={`w-5 h-5 ${
                      isEventStreamActive ? 'animate-pulse' : ''
                    }`}
                  />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-white">
                    Azure Activity Log & Event Grid Telemetry Stream
                  </h4>
                  <p className="text-xs text-slate-400">
                    Listens for management plane events (storage container permission changes, RBAC role assignments).
                  </p>
                </div>
              </div>

              <button
                onClick={onToggleContinuousEventStream}
                className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all ${
                  isEventStreamActive
                    ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/30'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                {isEventStreamActive ? 'STREAM ACTIVE' : 'START STREAM'}
              </button>
            </div>

            {/* Simulated Live Stream Feed */}
            <div className="space-y-2">
              <div className="text-xs font-bold text-slate-300">
                Recent Azure Activity Log Events:
              </div>
              <div className="space-y-2 max-h-60 overflow-y-auto font-mono text-xs">
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    <span className="text-slate-300">
                      MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/WRITE
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-500">2s ago</span>
                </div>

                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 rounded-full bg-amber-400" />
                    <span className="text-slate-300">
                      MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-500">14s ago</span>
                </div>

                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 rounded-full bg-blue-400" />
                    <span className="text-slate-300">
                      MICROSOFT.STORAGE/CHECKNAMEAVAILABILITY/ACTION
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-500">32s ago</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
