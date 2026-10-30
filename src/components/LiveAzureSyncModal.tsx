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
  Lock,
  Trash2,
  KeyRound,
  AlertTriangle,
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
    isDemoData?: boolean;
  }) => void;
  isLiveConnected: boolean;
  liveSourceName?: string;
  onToggleContinuousEventStream: () => void;
  isEventStreamActive: boolean;
  onTriggerDriftAlert?: (scenarioType: string) => void;
  onPurgeToken?: () => void;
}

const INITIAL_ACTIVITY_EVENTS: AzureActivityEvent[] = [
  {
    id: 'evt-1',
    timestamp: new Date(Date.now() - 4000).toLocaleTimeString(),
    operationName: 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE',
    resourceName: 'maniqprodvault01/customer-kyc-documents (SIMULATED)',
    resourceType: 'StorageContainer',
    caller: 'vendor.architect#EXT#@contoso-partner.com',
    callerIpAddress: '198.51.100.42',
    status: 'Succeeded',
    riskLevel: 'CRITICAL',
    description: '[Simulated Demo Event] Container publicAccess modified to Container (Anonymous Read/List).',
  },
  {
    id: 'evt-2',
    timestamp: new Date(Date.now() - 18000).toLocaleTimeString(),
    operationName: 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE',
    resourceName: 'sp-github-actions-deploy (SIMULATED)',
    resourceType: 'RoleAssignment',
    caller: 'admin@maniqshield.io',
    callerIpAddress: '203.0.113.88',
    status: 'Succeeded',
    riskLevel: 'HIGH',
    description: '[Simulated Demo Event] Custom role with roleAssignments/write assigned at Subscription scope.',
  },
  {
    id: 'evt-3',
    timestamp: new Date(Date.now() - 35000).toLocaleTimeString(),
    operationName: 'MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE',
    resourceName: 'maniqdatalake02 (SIMULATED)',
    resourceType: 'StorageAccount',
    caller: 'secops-automation-sp',
    callerIpAddress: '40.112.72.19',
    status: 'Succeeded',
    riskLevel: 'INFO',
    description: '[Simulated Demo Event] Verified minimumTlsVersion=TLS1_2 and supportsHttpsTrafficOnly=true.',
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
  onPurgeToken,
}) => {
  const [activeTab, setActiveTab] = useState<'api' | 'cli' | 'stream'>('api');

  // REST API credentials & Multi-Subscription One-Shot toggle
  // Recommendation #7: Default to single subscription least-privilege scope and require explicit confirmation for tenant-wide scans
  const [scanAllSubscriptions, setScanAllSubscriptions] = useState<boolean>(false);
  const [confirmMultiSubScan, setConfirmMultiSubScan] = useState<boolean>(false);
  const [authorizedOwnerConfirmed, setAuthorizedOwnerConfirmed] = useState<boolean>(true);
  const [subscriptionId, setSubscriptionId] = useState(
    DEFAULT_AZURE_SUBSCRIPTION_ID
  );
  const [tenantId, setTenantId] = useState(DEFAULT_AZURE_TENANT_ID);
  // DEFAULT_AZURE_ACCESS_TOKEN is '' — prompts user to enter value
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

  // Simulated Event Grid stream state (Recommendation #4)
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

  // Simulated event stream ticker when stream is active or tab is viewed
  useEffect(() => {
    if (!isOpen || (!isEventStreamActive && activeTab !== 'stream')) return;

    const sampleOperations = [
      {
        operationName: 'MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION',
        resourceName: 'maniqprodvault01 (SIMULATED)',
        resourceType: 'StorageAccount',
        caller: 'sp-github-actions-deploy',
        callerIpAddress: '52.168.11.90',
        status: 'Warning' as const,
        riskLevel: 'HIGH' as const,
        description: '[Simulated Demo Event] Shared Access Account Key listed via ARM Control Plane.',
      },
      {
        operationName: 'MICROSOFT.NETWORK/STORAGEFIREWALLS/VALIDATE/ACTION',
        resourceName: 'maniqprodvault01 (SIMULATED)',
        resourceType: 'StorageNetworkRule',
        caller: 'azure-policy-engine',
        callerIpAddress: '13.107.42.14',
        status: 'Succeeded' as const,
        riskLevel: 'MEDIUM' as const,
        description: '[Simulated Demo Event] Detected defaultAction=Allow with 0 VNet/Private Endpoint rules.',
      },
      {
        operationName: 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/READ',
        resourceName: `/subscriptions/${subscriptionId.slice(0, 8)}... (SIMULATED)`,
        resourceType: 'SubscriptionIAM',
        caller: 'maniq-shield-cspm-scanner',
        callerIpAddress: '20.84.181.55',
        status: 'Succeeded' as const,
        riskLevel: 'INFO' as const,
        description: '[Simulated Demo Event] Periodic RBAC drift evaluation completed.',
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

  const handleClearTokenFromMemory = () => {
    setAccessToken('');
    setSyncStatus({
      type: 'idle',
    });
    if (onPurgeToken) {
      onPurgeToken();
    }
  };

  // Handle direct REST API live fetch
  const handleFetchFromAzure = async () => {
    if (!authorizedOwnerConfirmed) {
      setSyncStatus({
        type: 'error',
        message:
          'Authorized Use Required (Rec #13): Please confirm that you have account-owner authorization to scan the target Azure subscription(s).',
      });
      return;
    }

    if (scanAllSubscriptions && !confirmMultiSubScan) {
      setSyncStatus({
        type: 'error',
        message:
          'Explicit Confirmation Required (Rec #7): Please check the box confirming multi-subscription tenant enumeration before scanning all subscriptions.',
      });
      return;
    }

    if (!scanAllSubscriptions && !subscriptionId.trim()) {
      setSyncStatus({
        type: 'error',
        message:
          'Please enter a target Azure Subscription ID or explicitly enable multi-subscription scanning.',
      });
      return;
    }

    if (!accessToken.trim()) {
      setSyncStatus({
        type: 'error',
        message:
          'Azure ARM Bearer Access Token Required: Please enter your OAuth2 Bearer Token from "az account get-access-token --resource https://management.azure.com --query accessToken -o tsv" in the field above.',
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
            ? `Live Azure ARM Tenant Scan (${result.subscriptionsScanned} Subs)`
            : `Live Azure ARM REST API (${subLabel.slice(0, 8)}...)`,
        warnings: result.warnings,
        isDemoData: false,
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
        }. Please verify your Bearer Access Token is valid and unexpired.`,
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Simulated Sandbox Multi-Subscription Telemetry Loader (labeled clearly as Demo Data per Rec #4 & #5)
  const handleLoadSimulatedSandboxTelemetry = async () => {
    setIsLoading(true);
    setSyncStatus({ type: 'idle' });

    await handleCheckEndpointHealth();
    const payload = buildLiveAzureTelemetryPayload(
      subscriptionId,
      scanAllSubscriptions
    );

    const subDisplay = scanAllSubscriptions
      ? `Simulated Tenant Sandbox (${payload.subscriptionsScanned} Demo Subs)`
      : `${subscriptionId.trim() || '834dcd8e-ecbe-4340-b734-3729000c7562'} (Demo Sandbox)`;

    onApplyLiveResources({
      storageAccounts: payload.storageAccounts,
      roleAssignments: payload.roleAssignments,
      subscriptionId: subDisplay,
      sourceName: `Demo Data — Simulated Multi-Sub Sandbox (No Live Assessment)`,
      isDemoData: true,
    });

    setSyncStatus({
      type: 'success',
      message: `Loaded Simulated Sandbox Dataset (DEMO DATA — NO LIVE ASSESSMENT): ${payload.storageAccounts.length} sample Storage Accounts and ${payload.roleAssignments.length} sample RBAC Role Assignments across ${payload.subscriptionsScanned} simulated subscription(s). Enter a real Bearer Token above for a live Azure assessment.`,
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
          'Please paste valid JSON for either Storage Accounts or Role Assignments (or click "Load Demo Sample CLI Payload").'
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
            : distinctSubs[0] || subscriptionId || 'cli-imported-sub',
        sourceName:
          distinctSubs.length > 1
            ? `Azure CLI Imported JSON (${distinctSubs.length} Subs)`
            : 'Azure Cloud Shell CLI Imported JSON',
        isDemoData: false,
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
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="font-serif font-bold text-base text-white">
                  Azure ARM Bearer Token &amp; Live Assessment Connection
                </h3>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold flex items-center space-x-1 border ${
                    isLiveConnected
                      ? 'bg-[#2BB5A0]/20 text-[#5FD3BF] border-[#2BB5A0]/40'
                      : 'bg-amber-500/20 text-[#EBC385] border-amber-400/30'
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full animate-ping mr-1 ${
                      isLiveConnected ? 'bg-[#5FD3BF]' : 'bg-[#EBC385]'
                    }`}
                  />
                  {isLiveConnected ? 'LIVE AZURE CONNECTED' : 'TOKEN REQUIRED FOR LIVE SCAN'}
                </span>
              </div>
              <p className="text-xs text-[#B7C3CC]">
                {isLiveConnected && liveSourceName
                  ? `Active Source: ${liveSourceName}`
                  : 'Please enter your Azure ARM Bearer Access Token below to run a live assessment.'}
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
                  'Azure ARM Endpoint (management.azure.com) Ready — Enter Bearer Token to Authenticate'}
            </span>
          </div>

          <div className="flex items-center space-x-2">
            {accessToken && (
              <button
                type="button"
                onClick={handleClearTokenFromMemory}
                className="px-2.5 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-400/30 font-mono text-[11px] flex items-center space-x-1"
              >
                <Trash2 className="w-3 h-3" />
                <span>Purge Token</span>
              </button>
            )}
            <button
              type="button"
              onClick={handleCheckEndpointHealth}
              disabled={isCheckingHealth}
              className="xh-btn text-[11px] py-1 px-2.5 disabled:opacity-50"
            >
              <RefreshCw
                className={`w-3 h-3 ${isCheckingHealth ? 'animate-spin' : ''}`}
              />
              <span>Test Endpoint</span>
            </button>
          </div>
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
            <span>1. Azure ARM Bearer Token (Live API)</span>
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
            <span>2. Azure CLI JSON Import</span>
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
            <span>3. Simulated Activity Stream (Demo)</span>
          </button>
        </div>

        {/* Tab 1: Direct ARM REST API Sync */}
        {activeTab === 'api' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1 bg-white">
            {/* Bearer Token Entry Request Banner */}
            <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-950 space-y-1.5">
              <div className="font-bold flex items-center justify-between">
                <span className="flex items-center space-x-2">
                  <KeyRound className="w-4 h-4 text-amber-700" />
                  <span>Action Required: Please Enter Your Azure ARM Bearer Access Token</span>
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-200/70 text-amber-900 font-bold">
                  NO DEFAULT TOKEN STORED
                </span>
              </div>
              <p className="text-[#546471]">
                For security and credential hygiene (Recommendation #12), no default Bearer Token is pre-loaded. Generate a short-lived read token in Azure Cloud Shell or terminal and paste it below:
              </p>
              <code className="block bg-[#081420] text-[#5FD3BF] px-2.5 py-1.5 rounded font-mono text-[11px]">
                az account get-access-token --resource https://management.azure.com --query accessToken -o tsv
              </code>
            </div>

            {/* Tenant & Subscription Inputs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-bold text-[#16232F] mb-1">
                  Azure Entra Tenant ID (Default Configured):
                </label>
                <input
                  type="text"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  placeholder="9dbe6987-92ff-43c8-9f71-a39d689cb817"
                  className="w-full bg-slate-50 border border-slate-300 text-[#16232F] text-xs rounded-lg px-3 py-2 font-mono focus:outline-none focus:ring-1 focus:ring-[#2BB5A0]"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-[#16232F] mb-1">
                  {scanAllSubscriptions
                    ? 'Subscription Scope (All Enabled in Tenant):'
                    : 'Target Azure Subscription ID (Default Configured):'}
                </label>
                <input
                  type="text"
                  value={
                    scanAllSubscriptions
                      ? '* (Enumerate All Accessible Subscriptions)'
                      : subscriptionId
                  }
                  disabled={scanAllSubscriptions}
                  onChange={(e) => setSubscriptionId(e.target.value)}
                  placeholder="834dcd8e-ecbe-4340-b734-3729000c7562"
                  className="w-full bg-slate-50 border border-slate-300 text-[#16232F] text-xs rounded-lg px-3 py-2 font-mono focus:outline-none focus:ring-1 focus:ring-[#2BB5A0] disabled:opacity-70"
                />
              </div>
            </div>

            {/* Bearer Token Input */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-bold text-[#16232F] flex items-center space-x-1.5">
                  <span>Azure ARM Bearer Access Token (Required for Live Scan):</span>
                  <span className="text-red-600">*</span>
                </label>
                <div className="flex items-center space-x-2">
                  {accessToken && (
                    <button
                      type="button"
                      onClick={handleClearTokenFromMemory}
                      className="text-[11px] text-red-600 hover:underline font-semibold"
                    >
                      Clear Token
                    </button>
                  )}
                  <span className="text-[11px] text-[#546471] font-mono">
                    Volatile Memory Only
                  </span>
                </div>
              </div>
              <textarea
                rows={3}
                value={accessToken}
                onChange={(e) => setAccessToken(e.target.value)}
                placeholder="Please enter your Azure ARM Bearer Access Token (eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...)"
                className="w-full bg-slate-50 border-2 border-[#2BB5A0]/60 text-[#16232F] text-xs rounded-lg p-3 font-mono focus:outline-none focus:ring-2 focus:ring-[#2BB5A0]"
              />
              {/* Recommendation #7: Least-Privilege Scope Guidance */}
              <div className="mt-1.5 text-[11px] text-[#546471] flex items-start space-x-1.5">
                <ShieldCheck className="w-4 h-4 text-[#1F8A79] flex-shrink-0 mt-0.5" />
                <span>
                  <strong>Least-Privilege Scope (Rec #7):</strong> Use an identity with built-in{' '}
                  <code className="bg-slate-100 px-1 py-0.5 rounded text-[#1F8A79] font-mono">
                    Reader
                  </code>{' '}
                  on the target Resource Group or single Subscription. Avoid Root Management Group assignments or Global Administrator elevation.
                </span>
              </div>
            </div>

            {/* Scope Selector & Explicit Multi-Subscription Confirmation (Rec #7 & #13) */}
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5 text-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <span className="font-bold text-[#16232F]">
                    Assessment Scope Selection
                  </span>
                  <p className="text-[11px] text-[#546471]">
                    Single-subscription scope is recommended by default for least privilege.
                  </p>
                </div>
                <div className="flex items-center space-x-1.5 bg-white p-1 rounded-lg border border-slate-200">
                  <button
                    type="button"
                    onClick={() => {
                      setScanAllSubscriptions(false);
                      setConfirmMultiSubScan(false);
                    }}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition-all ${
                      !scanAllSubscriptions
                        ? 'bg-[#0E2238] text-white'
                        : 'text-[#546471] hover:text-[#16232F]'
                    }`}
                  >
                    Single / Listed Subscription (Default)
                  </button>
                  <button
                    type="button"
                    onClick={() => setScanAllSubscriptions(true)}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition-all ${
                      scanAllSubscriptions
                        ? 'bg-[#0E2238] text-white'
                        : 'text-[#546471] hover:text-[#16232F]'
                    }`}
                  >
                    All Tenant Subscriptions
                  </button>
                </div>
              </div>

              {scanAllSubscriptions && (
                <label className="flex items-start space-x-2 p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-950 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={confirmMultiSubScan}
                    onChange={(e) => setConfirmMultiSubScan(e.target.checked)}
                    className="mt-0.5 rounded accent-[#1F8A79]"
                  />
                  <span className="text-[11px] leading-relaxed">
                    <strong>Explicit Multi-Subscription Confirmation (Rec #7):</strong> I confirm that I intend to enumerate <code>GET /subscriptions</code> and query Storage Accounts and Role Assignments across all accessible subscriptions in this tenant.
                  </span>
                </label>
              )}

              <label className="flex items-start space-x-2 text-[11px] text-[#546471] cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={authorizedOwnerConfirmed}
                  onChange={(e) => setAuthorizedOwnerConfirmed(e.target.checked)}
                  className="mt-0.5 rounded accent-[#1F8A79]"
                />
                <span>
                  <strong>Authorized Use (Rec #13):</strong> I am authorized by the Azure subscription/tenant owner to perform this read-only configuration assessment.
                </span>
              </label>
            </div>

            {/* Privacy & Credential Handling Summary Box (Rec #12) */}
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-[11px] text-[#546471] flex items-start space-x-2">
              <Lock className="w-4 h-4 text-[#1F8A79] flex-shrink-0 mt-0.5" />
              <div>
                <strong>Privacy &amp; Token Notice (Rec #12):</strong> Your Bearer Token is kept exclusively in volatile in-memory React state, transmitted only via direct browser HTTPS calls to <code>https://management.azure.com</code>, never logged or persisted to disk/storage, and purged immediately when you click <em>Purge Token</em> or close this tab.
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
                  View Results →
                </button>
              </div>
            )}

            <div className="pt-2 flex flex-wrap items-center justify-between gap-2 border-t border-slate-200">
              <button
                type="button"
                onClick={handleLoadSimulatedSandboxTelemetry}
                disabled={isLoading}
                className="px-3 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-[#16232F] border border-slate-300 font-semibold text-xs flex items-center space-x-1.5 transition-all"
              >
                <Sparkles className="w-3.5 h-3.5 text-[#D79A45]" />
                <span>Load Simulated Multi-Sub Sandbox (Demo Data)</span>
              </button>

              <button
                type="button"
                onClick={handleFetchFromAzure}
                disabled={isLoading}
                className="flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all disabled:opacity-50"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Scanning Azure ARM...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 text-[#5FD3BF]" />
                    <span>
                      {scanAllSubscriptions
                        ? 'Authenticate & Scan All Tenant Subscriptions'
                        : 'Authenticate & Fetch Live Azure Resources'}
                    </span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Tab 2: CLI Output Ingestion */}
        {activeTab === 'cli' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1 bg-white">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span className="text-xs text-[#16232F] font-medium">
                Paste JSON output from Azure CLI or Resource Graph (processed locally in browser memory):
              </span>
              <button
                type="button"
                onClick={loadRealWorldAzureSnapshot}
                className="text-xs px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-[#16232F] border border-slate-300 font-semibold flex items-center space-x-1.5 transition-all whitespace-nowrap"
              >
                <Sparkles className="w-3.5 h-3.5 text-[#1F8A79]" />
                <span>Load Demo Sample CLI Payload (3 Subs)</span>
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs mb-1 gap-1">
                  <span className="font-bold text-[#16232F] font-mono">
                    1. Storage Accounts JSON (Single Sub or Resource Graph)
                  </span>
                  <code className="text-[10px] text-[#5FD3BF] bg-[#081420] px-2 py-0.5 rounded font-mono">
                    az storage account list --subscription {subscriptionId || '<sub-id>'} -o json
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
                    2. RBAC Role Assignments JSON
                  </span>
                  <code className="text-[10px] text-[#5FD3BF] bg-[#081420] px-2 py-0.5 rounded font-mono">
                    az role assignment list --all --subscription {subscriptionId || '<sub-id>'} -o json
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
                <span>Ingest CLI JSON &amp; Run Assessment</span>
              </button>
            </div>
          </div>
        )}

        {/* Tab 3: Simulated Event Stream (Recommendation #4) */}
        {activeTab === 'stream' && (
          <div className="p-6 space-y-4 overflow-y-auto flex-1 bg-white">
            <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-950 text-xs flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-amber-700 flex-shrink-0" />
              <span>
                <strong>SIMULATED MONITORING STREAM (DEMO DATA — REC #4):</strong> The events and drift alerts below are synthetic in-browser training simulations and do not represent live Azure Activity Log or Event Grid traffic from your tenant.
              </span>
            </div>

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
                    <span>Simulated Activity Log &amp; Drift Sandbox</span>
                  </h4>
                  <p className="text-xs text-[#546471]">
                    Demonstrates how control-plane drift events (Container ACL edits, RBAC role writes) affect posture scoring.
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
                        resourceName: 'customer-ssn-vault (SIMULATED)',
                        resourceType: 'StorageContainer',
                        caller: 'external-contractor#EXT#',
                        callerIpAddress: '185.220.101.9',
                        status: 'Warning',
                        riskLevel: 'CRITICAL',
                        description:
                          '[SIMULATED DRIFT] Container publicAccess changed to Container (Anonymous Read/List).',
                      };
                      setActivityEvents((prev) => [driftEvent, ...prev]);
                    }}
                    className="px-3 py-1.5 rounded-lg text-xs font-bold bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 transition-all whitespace-nowrap"
                  >
                    Inject Simulated Drift Event
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
                  {isEventStreamActive ? 'SIMULATION ACTIVE' : 'START SIMULATION'}
                </button>
              </div>
            </div>

            {/* Simulated Stream Feed */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-[#16232F] flex items-center space-x-1.5">
                  <Activity className="w-3.5 h-3.5 text-[#1F8A79]" />
                  <span>Simulated Activity Events ({activityEvents.length})</span>
                </span>
                <span className="text-[11px] text-[#546471] font-mono">
                  Synthetic interval: 5.5s
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
