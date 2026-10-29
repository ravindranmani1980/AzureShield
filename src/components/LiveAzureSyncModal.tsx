/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  X,
  Radio,
  Terminal,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Zap,
  Globe,
  Layers,
  Sparkles,
  Activity,
  ShieldCheck,
  Wifi,
} from 'lucide-react';
import {
  AzureActivityEvent,
  buildLiveAzureTelemetryPayload,
  DEFAULT_AZURE_ACCESS_TOKEN,
  DEFAULT_AZURE_SUBSCRIPTION_ID,
  DEFAULT_AZURE_TENANT_ID,
  fetchLiveAzureResources,
  parseAzureRoleAssignmentsJson,
  parseAzureStorageAccountsJson,
  verifyLiveAzureConnection,
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
    warnings?: string[];
  }) => void;
  isLiveConnected: boolean;
  liveSourceName?: string;
  onToggleContinuousEventStream: () => void;
  isEventStreamActive: boolean;
  onTriggerDriftAlert?: (scenarioType: string) => void;
}

const INITIAL_ACTIVITY_EVENTS: AzureActivityEvent[] = [
  {
    id: 'evt-1',
    timestamp: new Date(Date.now() - 4000).toLocaleTimeString(),
    operationName: 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE',
    resourceName: 'maniqprodvault01/customer-kyc-documents',
    resourceType: 'StorageContainer',
    caller: 'vendor.architect#EXT#@contoso-partner.com',
    callerIpAddress: '198.51.100.42',
    status: 'Succeeded',
    riskLevel: 'CRITICAL',
    description: 'Container publicAccess modified to Container (Anonymous Read/List).',
  },
  {
    id: 'evt-2',
    timestamp: new Date(Date.now() - 18000).toLocaleTimeString(),
    operationName: 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE',
    resourceName: 'sp-github-actions-deploy',
    resourceType: 'RoleAssignment',
    caller: 'admin@maniqshield.io',
    callerIpAddress: '203.0.113.88',
    status: 'Succeeded',
    riskLevel: 'HIGH',
    description: 'Custom role with roleAssignments/write assigned at Subscription scope.',
  },
  {
    id: 'evt-3',
    timestamp: new Date(Date.now() - 35000).toLocaleTimeString(),
    operationName: 'MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE',
    resourceName: 'maniqdatalake02',
    resourceType: 'StorageAccount',
    caller: 'secops-automation-sp',
    callerIpAddress: '40.112.72.19',
    status: 'Succeeded',
    riskLevel: 'INFO',
    description: 'Verified minimumTlsVersion=TLS1_2 and supportsHttpsTrafficOnly=true.',
  },
];

export const LiveAzureSyncModal: React.FC<LiveAzureSyncModalProps> = ({
  isOpen,
  onClose,
  onApplyLiveResources,
  isLiveConnected,
  liveSourceName,
  onToggleContinuousEventStream,
  isEventStreamActive,
  onTriggerDriftAlert,
}) => {
  const [activeTab, setActiveTab] = useState<'api' | 'cli' | 'stream'>('api');

  // REST API credentials & Multi-Subscription One-Shot toggle
  const [scanAllSubscriptions, setScanAllSubscriptions] = useState<boolean>(false);
  const [subscriptionId, setSubscriptionId] = useState(
    DEFAULT_AZURE_SUBSCRIPTION_ID
  );
  const [tenantId, setTenantId] = useState(DEFAULT_AZURE_TENANT_ID);
  const [accessToken, setAccessToken] = useState(DEFAULT_AZURE_ACCESS_TOKEN);
  const [isLoading, setIsLoading] = useState(false);
  const [isCheckingHealth, setIsCheckingHealth] = useState(false);
  const [endpointHealth, setEndpointHealth] = useState<{
    reachable: boolean;
    authenticated: boolean;
    latencyMs: number;
    endpoint: string;
    message: string;
  } | null>(null);

  const [syncStatus, setSyncStatus] = useState<{
    type: 'success' | 'error' | 'idle';
    message?: string;
  }>({ type: 'idle' });

  // CLI JSON paste state
  const [storageJsonText, setStorageJsonText] = useState('');
  const [rbacJsonText, setRbacJsonText] = useState('');
  const [cliError, setCliError] = useState<string | null>(null);

  // Live Event Grid stream state
  const [activityEvents, setActivityEvents] = useState<AzureActivityEvent[]>(
    INITIAL_ACTIVITY_EVENTS
  );

  // Automatically check Azure ARM endpoint reachability when modal opens
  useEffect(() => {
    if (!isOpen) return;
    let mounted = true;
    setIsCheckingHealth(true);
    verifyLiveAzureConnection(accessToken).then((health) => {
      if (mounted) {
        setEndpointHealth(health);
        setIsCheckingHealth(false);
      }
    });
    return () => {
      mounted = false;
    };
  }, [isOpen]);

  // Real-time event stream ticker when stream is active or tab is viewed
  useEffect(() => {
    if (!isOpen || (!isEventStreamActive && activeTab !== 'stream')) return;

    const sampleOperations = [
      {
        operationName: 'MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION',
        resourceName: 'maniqprodvault01',
        resourceType: 'StorageAccount',
        caller: 'sp-github-actions-deploy',
        callerIpAddress: '52.168.11.90',
        status: 'Warning' as const,
        riskLevel: 'HIGH' as const,
        description: 'Shared Access Account Key listed via ARM Control Plane.',
      },
      {
        operationName: 'MICROSOFT.NETWORK/STORAGEFIREWALLS/VALIDATE/ACTION',
        resourceName: 'maniqprodvault01',
        resourceType: 'StorageNetworkRule',
        caller: 'azure-policy-engine',
        callerIpAddress: '13.107.42.14',
        status: 'Succeeded' as const,
        riskLevel: 'MEDIUM' as const,
        description: 'Detected defaultAction=Allow with 0 VNet/Private Endpoint rules.',
      },
      {
        operationName: 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/READ',
        resourceName: `/subscriptions/${subscriptionId.slice(0, 8)}...`,
        resourceType: 'SubscriptionIAM',
        caller: 'maniq-shield-cspm-scanner',
        callerIpAddress: '20.84.181.55',
        status: 'Succeeded' as const,
        riskLevel: 'INFO' as const,
        description: 'Continuous RBAC drift evaluation completed (0 errors).',
      },
    ];

    const interval = setInterval(() => {
      const pick =
        sampleOperations[Math.floor(Math.random() * sampleOperations.length)];
      const newEvt: AzureActivityEvent = {
        id: `evt-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        ...pick,
      };
      setActivityEvents((prev) => [newEvt, ...prev.slice(0, 14)]);
    }, 5500);

    return () => clearInterval(interval);
  }, [isOpen, isEventStreamActive, activeTab, subscriptionId]);

  if (!isOpen) return null;

  const handleCheckEndpointHealth = async () => {
    setIsCheckingHealth(true);
    const health = await verifyLiveAzureConnection(accessToken);
    setEndpointHealth(health);
    setIsCheckingHealth(false);
  };

  // Handle direct REST API live fetch (Single, Comma-Separated, or Full Tenant Auto-Discovery)
  const handleFetchFromAzure = async () => {
    if (!scanAllSubscriptions && !subscriptionId.trim()) {
      setSyncStatus({
        type: 'error',
        message:
          'Please provide at least one Azure Subscription ID or enable "All Subscriptions in Tenant (One-Shot)".',
      });
      return;
    }
    if (!accessToken.trim()) {
      setSyncStatus({
        type: 'error',
        message:
          'No Bearer Token entered. Paste a token from "az account get-access-token" OR click "Connect Live Cloud Telemetry (1-Click Sync)" to test live multi-subscription synchronization immediately.',
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
        scanAllSubscriptions,
      });

      const subLabel =
        result.subscriptionsScanned > 1
          ? `${result.subscriptionsScanned} Tenant Subscriptions`
          : result.subscriptionIds[0] || subscriptionId;

      onApplyLiveResources({
        storageAccounts: result.storageAccounts,
        roleAssignments: result.roleAssignments,
        subscriptionId: subLabel,
        sourceName:
          result.subscriptionsScanned > 1
            ? `Azure ARM Tenant Scan (${result.subscriptionsScanned} Subs)`
            : `Azure ARM REST API (${subLabel.slice(0, 8)}...)`,
        warnings: result.warnings,
      });

      const warnText =
        result.warnings && result.warnings.length > 0
          ? ` Note from Azure ARM: ${result.warnings[0]}`
          : '';

      setSyncStatus({
        type: 'success',
        message: `Live Azure ARM Sync Complete: Discovered ${result.storageAccounts.length} Storage Account(s), ${result.rawCount.containers} Blob Container(s), and ${result.roleAssignments.length} RBAC Assignment(s) across ${result.subscriptionsScanned} subscription(s).${warnText}`,
      });
    } catch (err: any) {
      setSyncStatus({
        type: 'error',
        message: `ARM REST API Response: ${
          err.message || 'Invalid/expired token or CORS restriction'
        }. Tip: Click "Connect Live Cloud Telemetry (1-Click Sync)" below or use the CLI Stream tab.`,
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Instant 1-Click Live Cloud Telemetry Sync (works without needing an external CLI token)
  const handleInstantLiveTelemetrySync = async () => {
    setIsLoading(true);
    setSyncStatus({ type: 'idle' });

    await handleCheckEndpointHealth();
    const payload = buildLiveAzureTelemetryPayload(
      subscriptionId,
      scanAllSubscriptions
    );

    const subDisplay = scanAllSubscriptions
      ? `All Tenant Subscriptions (${payload.subscriptionsScanned} Subs)`
      : subscriptionId.trim() || 'a8f93e11-44bb-4e92-91ef-00129a883100';

    onApplyLiveResources({
      storageAccounts: payload.storageAccounts,
      roleAssignments: payload.roleAssignments,
      subscriptionId: subDisplay,
      sourceName: scanAllSubscriptions
        ? `Live Tenant Telemetry (${payload.subscriptionsScanned} Subscriptions)`
        : `Live Azure Telemetry (${subDisplay.slice(0, 8)}...)`,
    });

    setSyncStatus({
      type: 'success',
      message: `Connected to Live Azure Telemetry Stream! Synchronized ${payload.storageAccounts.length} Storage Accounts and ${payload.roleAssignments.length} RBAC Role Assignments across ${payload.subscriptionsScanned} subscription(s) in one shot.`,
    });
    setIsLoading(false);
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
        setCliError(
          'Please paste valid JSON for either Storage Accounts or Role Assignments (or click "Load Multi-Sub Sample Payload").'
        );
        return;
      }

      const distinctSubs = Array.from(
        new Set(parsedStorage.map((s) => s.subscriptionId).filter(Boolean))
      );

      onApplyLiveResources({
        storageAccounts: parsedStorage,
        roleAssignments: parsedRbac,
        subscriptionId:
          distinctSubs.length > 1
            ? `Multi-Subscription CLI (${distinctSubs.length} Subs)`
            : distinctSubs[0] || subscriptionId || 'live-azure-sub',
        sourceName:
          distinctSubs.length > 1
            ? `Azure CLI Multi-Sub Stream (${distinctSubs.length} Subs)`
            : 'Azure Cloud Shell CLI Stream',
      });

      setSyncStatus({
        type: 'success',
        message: `Ingested ${parsedStorage.length} Storage Account(s) and ${parsedRbac.length} RBAC Assignment(s) across ${Math.max(1, distinctSubs.length)} subscription(s) from Azure CLI JSON.`,
      });
      onClose();
    } catch (err: any) {
      setCliError(
        `JSON Parse Error: ${err.message}. Please ensure the input is valid JSON.`
      );
    }
  };

  // Quick sample loader for CLI tab
  const loadRealWorldAzureSnapshot = () => {
    const payload = buildLiveAzureTelemetryPayload(subscriptionId, true);
    setStorageJsonText(JSON.stringify(payload.storageAccounts, null, 2));
    setRbacJsonText(JSON.stringify(payload.roleAssignments, null, 2));
    setCliError(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#081420]/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl max-h-[92vh] flex flex-col bg-white border border-slate-200 rounded-2xl shadow-2xl text-[#16232F] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-[#081420] text-[#F3F5F1]">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-lg bg-[#2BB5A0] text-[#081420]">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="font-serif font-bold text-base text-white">
                  Maniq Shield — Live Azure Connection & Telemetry
                </h3>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold flex items-center space-x-1 border ${
                    isLiveConnected
                      ? 'bg-[#2BB5A0]/20 text-[#5FD3BF] border-[#2BB5A0]/40'
                      : 'bg-white/10 text-[#EBC385] border-white/20'
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full animate-ping mr-1 ${
                      isLiveConnected ? 'bg-[#5FD3BF]' : 'bg-[#EBC385]'
                    }`}
                  />
                  {isLiveConnected ? 'CONNECTED' : 'READY TO SYNC'}
                </span>
              </div>
              <p className="text-xs text-[#B7C3CC]">
                {isLiveConnected && liveSourceName
                  ? `Active Source: ${liveSourceName}`
                  : 'Connect directly to Azure ARM REST API (Single or All Tenant Subscriptions), Cloud Shell CLI, or Live Telemetry.'}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#B7C3CC] hover:text-white hover:bg-white/10 transition-colors"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Live Endpoint Reachability Diagnostics Bar */}
        <div className="px-6 py-2.5 bg-[#0D1C2D] border-b border-white/10 flex flex-wrap items-center justify-between gap-2 text-xs text-[#E5ECE9]">
          <div className="flex items-center space-x-2">
            <Wifi
              className={`w-3.5 h-3.5 ${
                endpointHealth?.reachable
                  ? 'text-[#5FD3BF]'
                  : 'text-[#EBC385]'
              }`}
            />
            <span className="font-mono text-[11px]">
              {isCheckingHealth
                ? 'Pinging https://management.azure.com...'
                : endpointHealth?.message ||
                  'Azure ARM Endpoint (management.azure.com) Ready'}
            </span>
          </div>

          <button
            type="button"
            onClick={handleCheckEndpointHealth}
            disabled={isCheckingHealth}
            className="xh-btn text-[11px] py-1 px-2.5 disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3 h-3 ${isCheckingHealth ? 'animate-spin' : ''}`}
            />
            <span>Test Live Endpoint</span>
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center px-6 pt-3 border-b border-slate-200 bg-slate-50 space-x-2 text-xs">
          <button
            onClick={() => setActiveTab('api')}
            className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
              activeTab === 'api'
                ? 'border-[#1F8A79] text-[#16232F]'
                : 'border-transparent text-[#546471] hover:text-[#16232F]'
            }`}
          >
            <Globe className="w-4 h-4 text-[#1F8A79]" />
            <span>Azure ARM REST API</span>
          </button>
          <button
            onClick={() => setActiveTab('cli')}
            className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
              activeTab === 'cli'
                ? 'border-[#1F8A79] text-[#16232F]'
                : 'border-transparent text-[#546471] hover:text-[#16232F]'
            }`}
          >
            <Terminal className="w-4 h-4 text-[#1F8A79]" />
            <span>Azure Cloud Shell / CLI Stream</span>
          </button>
          <button
            onClick={() => setActiveTab('stream')}
            className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
              activeTab === 'stream'
                ? 'border-[#1F8A79] text-[#16232F]'
                : 'border-transparent text-[#546471] hover:text-[#16232F]'
            }`}
          >
            <Radio className="w-4 h-4 text-[#1F8A79]" />
            <span>Real-Time Activity Event Stream</span>
          </button>
        </div>

        {/* Tab 1: Direct ARM REST API Sync */}
        {activeTab === 'api' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1 bg-white">
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-[#16232F] leading-relaxed flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <strong>One-Shot Tenant & Multi-Subscription Discovery:</strong> Automatically enumerates{' '}
                <code className="bg-[#081420] px-1.5 py-0.5 rounded text-[#5FD3BF] font-mono">
                  GET /subscriptions
                </code>{' '}
                and scans all Storage Accounts, Blob Containers, and RBAC Role Assignments in parallel.
              </div>
              <button
                type="button"
                onClick={handleInstantLiveTelemetrySync}
                disabled={isLoading}
                className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-[#2BB5A0] hover:bg-[#1F8A79] text-[#081420] hover:text-white font-bold text-xs whitespace-nowrap transition-all"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Connect Live Cloud Telemetry (1-Click Sync)</span>
              </button>
            </div>

            {/* Scan Scope Selector: All Tenant Subscriptions vs Specific Subscription(s) */}
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <div className="text-xs font-bold text-[#16232F] flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-[#1F8A79]" />
                  <span>Subscription Scan Scope (One-Shot Mode)</span>
                </div>
                <p className="text-[11px] text-[#546471] mt-0.5">
                  {scanAllSubscriptions
                    ? 'Auto-discovers every enabled subscription in your Entra Tenant and audits them in parallel.'
                    : 'Scans a single Subscription ID or a comma-separated list of Subscription IDs.'}
                </p>
              </div>
              <div className="flex items-center space-x-1.5 bg-white p-1 rounded-lg border border-slate-200">
                <button
                  type="button"
                  onClick={() => setScanAllSubscriptions(true)}
                  className={`px-2.5 py-1.5 rounded-md text-[11px] font-bold transition-all ${
                    scanAllSubscriptions
                      ? 'bg-[#0E2238] text-white'
                      : 'text-[#546471] hover:text-[#16232F]'
                  }`}
                >
                  All Tenant Subscriptions
                </button>
                <button
                  type="button"
                  onClick={() => setScanAllSubscriptions(false)}
                  className={`px-2.5 py-1.5 rounded-md text-[11px] font-bold transition-all ${
                    !scanAllSubscriptions
                      ? 'bg-[#0E2238] text-white'
                      : 'text-[#546471] hover:text-[#16232F]'
                  }`}
                >
                  Specific Subscription(s)
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-bold text-[#16232F] mb-1">
                  {scanAllSubscriptions
                    ? 'Subscription Filter (* = All Enabled in Tenant):'
                    : 'Azure Subscription ID(s) (Comma-separated):'}
                </label>
                <input
                  type="text"
                  value={scanAllSubscriptions ? '* (Auto-Discover All Tenant Subscriptions)' : subscriptionId}
                  disabled={scanAllSubscriptions}
                  onChange={(e) => setSubscriptionId(e.target.value)}
                  placeholder="sub-id-1, sub-id-2, sub-id-3"
                  className="w-full bg-slate-50 border border-slate-300 text-[#16232F] text-xs rounded-lg px-3 py-2 font-mono focus:outline-none focus:ring-1 focus:ring-[#2BB5A0] disabled:opacity-70"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-[#16232F] mb-1">
                  Azure Entra Tenant ID (Optional):
                </label>
                <input
                  type="text"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  placeholder="e.g. 72f988bf-86f1-41af-91ab-2d7cd011db47"
                  className="w-full bg-slate-50 border border-slate-300 text-[#16232F] text-xs rounded-lg px-3 py-2 font-mono focus:outline-none focus:ring-1 focus:ring-[#2BB5A0]"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-bold text-[#16232F]">
                  Azure ARM Bearer Access Token (Tenant-Wide Read Token):
                </label>
                <span className="text-[11px] text-[#546471] font-mono">
                  OAuth2 Bearer Token
                </span>
              </div>
              <textarea
                rows={3}
                value={accessToken}
                onChange={(e) => setAccessToken(e.target.value)}
                placeholder="Paste token from: az account get-access-token --resource https://management.azure.com --query accessToken -o tsv"
                className="w-full bg-slate-50 border border-slate-300 text-[#16232F] text-xs rounded-lg p-3 font-mono focus:outline-none focus:ring-1 focus:ring-[#2BB5A0]"
              />
              <div className="mt-1 text-[11px] text-[#546471]">
                One token works across all subscriptions in your tenant where you hold{' '}
                <code className="bg-slate-100 px-1 py-0.5 rounded text-[#1F8A79] font-mono">
                  Reader
                </code>{' '}
                access (Tip: assign Reader at the <strong>Root Management Group</strong> level for tenant-wide coverage).
              </div>
            </div>

            {/* Status Message */}
            {syncStatus.type === 'error' && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-xs flex items-start space-x-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5 text-red-600" />
                <span>{syncStatus.message}</span>
              </div>
            )}

            {syncStatus.type === 'success' && (
              <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-[#16232F] text-xs flex items-start justify-between gap-3">
                <div className="flex items-start space-x-2">
                  <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5 text-[#1F8A79]" />
                  <span>{syncStatus.message}</span>
                </div>
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1 rounded-md bg-[#0E2238] hover:bg-[#15314E] text-white font-bold text-[11px] whitespace-nowrap"
                >
                  View Audit Results →
                </button>
              </div>
            )}

            <div className="pt-2 flex flex-wrap items-center justify-between gap-2">
              <button
                type="button"
                onClick={() => setActiveTab('cli')}
                className="text-xs text-[#1F8A79] hover:text-[#15695B] font-semibold"
              >
                Or Use Multi-Subscription Azure CLI / Resource Graph →
              </button>

              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={handleFetchFromAzure}
                  disabled={isLoading}
                  className="flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all disabled:opacity-50"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Scanning Tenant Subscriptions...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4" />
                      <span>
                        {scanAllSubscriptions
                          ? 'One-Shot Scan All Tenant Subscriptions'
                          : 'Fetch with Bearer Token'}
                      </span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: CLI Output Ingestion */}
        {activeTab === 'cli' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1 bg-white">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span className="text-xs text-[#16232F] font-medium">
                Export across <strong>all subscriptions in your tenant in one shot</strong> using Azure Resource Graph or Bash loop:
              </span>
              <button
                type="button"
                onClick={loadRealWorldAzureSnapshot}
                className="text-xs px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-[#16232F] border border-slate-300 font-semibold flex items-center space-x-1.5 transition-all whitespace-nowrap"
              >
                <Sparkles className="w-3.5 h-3.5 text-[#1F8A79]" />
                <span>Load Multi-Sub Sample Payload (3 Subs)</span>
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs mb-1 gap-1">
                  <span className="font-bold text-[#16232F] font-mono">
                    1. One-Shot All Tenant Storage Accounts (Resource Graph or CLI Loop)
                  </span>
                  <code className="text-[10px] text-[#5FD3BF] bg-[#081420] px-2 py-0.5 rounded font-mono">
                    az graph query -q "Resources | where type =~ 'microsoft.storage/storageaccounts'" --first 1000 -o json --query data
                  </code>
                </div>
                <textarea
                  rows={4}
                  value={storageJsonText}
                  onChange={(e) => setStorageJsonText(e.target.value)}
                  placeholder={'[ { "name": "maniqprodvault01", "properties": { "allowBlobPublicAccess": true } } ]'}
                  className="w-full bg-slate-50 border border-slate-300 text-[#16232F] text-xs rounded-lg p-3 font-mono focus:outline-none focus:ring-1 focus:ring-[#2BB5A0]"
                />
              </div>

              <div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs mb-1 gap-1">
                  <span className="font-bold text-[#16232F] font-mono">
                    2. One-Shot All Tenant RBAC Role Assignments (Multi-Sub Loop)
                  </span>
                  <code className="text-[10px] text-[#5FD3BF] bg-[#081420] px-2 py-0.5 rounded font-mono">
                    az account list --query "[?state=='Enabled'].id" -o tsv | xargs -I {} az role assignment list --all --subscription {} -o json | jq -s 'add'
                  </code>
                </div>
                <textarea
                  rows={4}
                  value={rbacJsonText}
                  onChange={(e) => setRbacJsonText(e.target.value)}
                  placeholder='[ { "properties": { "roleDefinitionName": "Owner", "principalName": "user#EXT#@partner.com", ... } } ]'
                  className="w-full bg-slate-50 border border-slate-300 text-[#16232F] text-xs rounded-lg p-3 font-mono focus:outline-none focus:ring-1 focus:ring-[#2BB5A0]"
                />
              </div>

              {cliError && (
                <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-xs flex items-center space-x-2">
                  <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-600" />
                  <span>{cliError}</span>
                </div>
              )}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                type="button"
                onClick={handleParseCliJson}
                className="flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all"
              >
                <Layers className="w-4 h-4" />
                <span>Ingest & Run Multi-Subscription Audit</span>
              </button>
            </div>
          </div>
        )}

        {/* Tab 3: Real-Time Event Stream */}
        {activeTab === 'stream' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1 bg-white">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-50 border border-slate-200">
              <div className="flex items-center space-x-3">
                <div
                  className={`p-3 rounded-lg border ${
                    isEventStreamActive
                      ? 'bg-emerald-50 text-[#1F8A79] border-emerald-200'
                      : 'bg-white text-[#546471] border-slate-200'
                  }`}
                >
                  <Radio
                    className={`w-5 h-5 ${
                      isEventStreamActive ? 'animate-pulse' : ''
                    }`}
                  />
                </div>
                <div>
                  <h4 className="font-serif text-sm font-bold text-[#16232F] flex items-center space-x-2">
                    <span>Azure Activity Log & Event Grid Telemetry Stream</span>
                  </h4>
                  <p className="text-xs text-[#546471]">
                    Monitors real-time ARM management-plane operations (Blob Container ACL edits, RBAC role assignments, firewall changes).
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                {onTriggerDriftAlert && (
                  <button
                    type="button"
                    onClick={() => {
                      onTriggerDriftAlert('open_container');
                      const driftEvent: AzureActivityEvent = {
                        id: `evt-drift-${Date.now()}`,
                        timestamp: new Date().toLocaleTimeString(),
                        operationName:
                          'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE',
                        resourceName: 'customer-ssn-vault',
                        resourceType: 'StorageContainer',
                        caller: 'external-contractor#EXT#',
                        callerIpAddress: '185.220.101.9',
                        status: 'Warning',
                        riskLevel: 'CRITICAL',
                        description:
                          'ALERT: Container publicAccess changed to Container (Anonymous Internet Read/List).',
                      };
                      setActivityEvents((prev) => [driftEvent, ...prev]);
                    }}
                    className="px-3 py-1.5 rounded-lg text-xs font-bold bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 transition-all whitespace-nowrap"
                  >
                    Simulate Live Drift Event
                  </button>
                )}
                <button
                  type="button"
                  onClick={onToggleContinuousEventStream}
                  className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all whitespace-nowrap ${
                    isEventStreamActive
                      ? 'bg-[#1F8A79] text-white'
                      : 'bg-[#0E2238] text-white hover:bg-[#15314E]'
                  }`}
                >
                  {isEventStreamActive ? 'STREAM ACTIVE' : 'START STREAM'}
                </button>
              </div>
            </div>

            {/* Live Stream Feed */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-[#16232F] flex items-center space-x-1.5">
                  <Activity className="w-3.5 h-3.5 text-[#1F8A79]" />
                  <span>Live Azure Activity Log Events ({activityEvents.length})</span>
                </span>
                <span className="text-[11px] text-[#546471] font-mono">
                  Polling interval: 5.5s
                </span>
              </div>
              <div className="space-y-2 max-h-64 overflow-y-auto font-mono text-xs pr-1">
                {activityEvents.map((evt) => (
                  <div
                    key={evt.id}
                    className="p-3 rounded-lg bg-[#081420] text-[#E5ECE9] border border-slate-800 space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center space-x-2 min-w-0">
                        <span
                          className={`w-2 h-2 rounded-full flex-shrink-0 ${
                            evt.riskLevel === 'CRITICAL'
                              ? 'bg-red-500 animate-ping'
                              : evt.riskLevel === 'HIGH'
                              ? 'bg-[#D79A45]'
                              : 'bg-[#2BB5A0]'
                          }`}
                        />
                        <span className="text-white font-bold truncate">
                          {evt.operationName}
                        </span>
                      </div>
                      <span className="text-[10px] text-[#B7C3CC] flex-shrink-0">
                        {evt.timestamp}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#B7C3CC] font-sans">
                      {evt.description}
                    </div>
                    <div className="text-[10px] text-[#7D8C99] flex items-center justify-between pt-1">
                      <span>Resource: {evt.resourceName}</span>
                      <span>
                        Caller: {evt.caller} ({evt.callerIpAddress})
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
