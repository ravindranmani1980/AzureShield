/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { OverviewDashboard } from './components/OverviewDashboard';
import { StorageAuditor } from './components/StorageAuditor';
import { StorageInventory } from './components/StorageInventory';
import { RbacAuditor } from './components/RbacAuditor';
import { FindingsList } from './components/FindingsList';
import { RemediationLog } from './components/RemediationLog';
import { FindingDetailModal } from './components/FindingDetailModal';
import { PdfPreviewModal } from './components/PdfPreviewModal';
import { MisconfigurationSimulatorModal } from './components/MisconfigurationSimulatorModal';
import { LiveAzureSyncModal } from './components/LiveAzureSyncModal';
import { GovernanceReviewModal } from './components/GovernanceReviewModal';
import { AlertNotificationBanner } from './components/AlertNotificationBanner';
import {
  SAMPLE_HIGH_RISK_DATASET,
  SAMPLE_HARDENED_DATASET,
} from './utils/defaultData';
import {
  DEFAULT_AZURE_ACCESS_TOKEN,
  DEFAULT_AZURE_SUBSCRIPTION_ID,
  DEFAULT_AZURE_TENANT_ID,
  fetchLiveAzureResources,
} from './utils/azureLiveApi';
import { evaluateAzurePosture } from './utils/securityEngine';
import { downloadSecurityAuditPdf } from './utils/pdfGenerator';
import {
  ActiveTab,
  Finding,
  RemediationLogEntry,
  SecurityAlertNotification,
} from './types/security';
import {
  KeyRound,
  AlertTriangle,
  ShieldCheck,
  Scale,
  Lock,
  ExternalLink,
} from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [currentPreset, setCurrentPreset] = useState<'high_risk' | 'hardened'>(
    'high_risk'
  );

  // Stateful Azure Environment Data (defaults to clearly labeled Demo Data until user enters Bearer Token)
  const [storageAccounts, setStorageAccounts] = useState(
    SAMPLE_HIGH_RISK_DATASET.storageAccounts
  );
  const [roleAssignments, setRoleAssignments] = useState(
    SAMPLE_HIGH_RISK_DATASET.roleAssignments
  );

  // Selected Finding Modal State
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // PDF Preview Modal State
  const [isPdfPreviewOpen, setIsPdfPreviewOpen] = useState(false);

  // Misconfiguration Simulator Modal State
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);

  // Live Azure Connection Modal State
  const [isLiveSyncOpen, setIsLiveSyncOpen] = useState(false);
  const [isLiveConnected, setIsLiveConnected] = useState(false);
  const [isDemoData, setIsDemoData] = useState(true);
  const [liveSourceName, setLiveSourceName] = useState<string>(
    'Demo Data — High-Risk Sample Scenario (No Live Assessment)'
  );
  const [lastCollectedAt, setLastCollectedAt] = useState<string>(
    'Sample Dataset (No Live Scan Performed)'
  );
  const [liveSyncWarnings, setLiveSyncWarnings] = useState<string[]>([]);

  // Governance, Privacy & Recommendations Review Modal State
  const [isGovernanceOpen, setIsGovernanceOpen] = useState(false);

  // Simulated Drift Watch Mode & Alert Notifications
  const [isWatchMode, setIsWatchMode] = useState(false);
  const [alerts, setAlerts] = useState<SecurityAlertNotification[]>([]);

  // Session Activity Log (In-Memory Simulation & Acknowledgment — Rec #6)
  const [remediationLogs, setRemediationLogs] = useState<RemediationLogEntry[]>(
    []
  );
  const [remediatedFindingIds, setRemediatedFindingIds] = useState<string[]>(
    []
  );

  // Evaluate Security Posture dynamically
  const rawAuditResult = useMemo(() => {
    return evaluateAzurePosture(storageAccounts, roleAssignments);
  }, [storageAccounts, roleAssignments]);

  // Filter out manually acknowledged findings while keeping metrics synchronized
  const activeFindings = useMemo(() => {
    return rawAuditResult.findings.filter(
      (f) => !remediatedFindingIds.includes(f.id)
    );
  }, [rawAuditResult.findings, remediatedFindingIds]);

  const metrics = useMemo(() => {
    if (remediatedFindingIds.length === 0) return rawAuditResult.metrics;

    const criticalCount = activeFindings.filter(
      (f) => f.severity === 'CRITICAL'
    ).length;
    const highCount = activeFindings.filter((f) => f.severity === 'HIGH').length;
    const mediumCount = activeFindings.filter(
      (f) => f.severity === 'MEDIUM'
    ).length;
    const lowCount = activeFindings.filter((f) => f.severity === 'LOW').length;

    const bonus = Math.min(35, remediatedFindingIds.length * 8);
    const postureScore = Math.min(
      100,
      rawAuditResult.metrics.postureScore + bonus
    );

    let riskGrade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';
    if (postureScore >= 90) riskGrade = 'A';
    else if (postureScore >= 80) riskGrade = 'B';
    else if (postureScore >= 65) riskGrade = 'C';
    else if (postureScore >= 50) riskGrade = 'D';
    else riskGrade = 'F';

    return {
      ...rawAuditResult.metrics,
      postureScore,
      riskGrade,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      complianceScores: {
        cisAzure: Math.min(
          100,
          rawAuditResult.metrics.complianceScores.cisAzure + bonus
        ),
        mcsb: Math.min(
          100,
          rawAuditResult.metrics.complianceScores.mcsb + bonus
        ),
        nist: Math.min(
          100,
          rawAuditResult.metrics.complianceScores.nist + bonus
        ),
      },
    };
  }, [rawAuditResult.metrics, activeFindings, remediatedFindingIds]);

  // Helper to push a real-time alert notification
  const pushAlert = (
    title: string,
    message: string,
    severity: 'CRITICAL' | 'HIGH' | 'INFO'
  ) => {
    const newAlert: SecurityAlertNotification = {
      id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toLocaleTimeString(),
      title,
      message,
      severity,
    };
    setAlerts((prev) => [newAlert, ...prev.slice(0, 4)]);
  };

  // Helper to record an in-memory session activity entry (Rec #6)
  const recordRemediationLog = (
    actionTitle: string,
    resourceName: string,
    category: 'storage' | 'rbac' | 'privilege_escalation',
    previousScore: number,
    newScore: number,
    cliExecuted: string,
    verificationStatus: 'in_memory_simulation' | 'acknowledged_unverified' = 'in_memory_simulation'
  ) => {
    const entry: RemediationLogEntry = {
      id: `rem-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toLocaleTimeString(),
      actionTitle,
      resourceName,
      category,
      previousScore,
      newScore,
      cliExecuted,
      verificationStatus,
    };
    setRemediationLogs((prev) => [entry, ...prev]);
  };

  // Auto-connect to Azure ARM on startup when DEFAULT_AZURE_ACCESS_TOKEN is provided
  useEffect(() => {
    if (!DEFAULT_AZURE_ACCESS_TOKEN) return;
    let cancelled = false;
    fetchLiveAzureResources({
      subscriptionId: DEFAULT_AZURE_SUBSCRIPTION_ID,
      tenantId: DEFAULT_AZURE_TENANT_ID,
      accessToken: DEFAULT_AZURE_ACCESS_TOKEN,
      scanAllSubscriptions: false,
    })
      .then((res) => {
        if (cancelled) return;
        setStorageAccounts(res.storageAccounts);
        setRoleAssignments(res.roleAssignments);
        setRemediatedFindingIds([]);
        setIsLiveConnected(true);
        setIsDemoData(false);
        setLiveSourceName(`Azure Sub ${DEFAULT_AZURE_SUBSCRIPTION_ID.slice(0, 8)}...`);
        setLastCollectedAt(new Date().toLocaleString());
        setLiveSyncWarnings(res.warnings || []);
      })
      .catch(() => {
        // Keep fallback sample dataset if network or token fails
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Simulated Drift Watch Mode effect (labeled clearly as Simulated per Rec #4)
  useEffect(() => {
    if (!isWatchMode) return;
    pushAlert(
      'Simulated Drift Sandbox Active (Demo Only)',
      'Simulating synthetic storage and RBAC drift events in browser memory (not connected to live Azure Event Grid).',
      'INFO'
    );

    const timer = setTimeout(() => {
      pushAlert(
        'SIMULATED DRIFT ALERT: Anonymous Container Access',
        '[Demo Simulation] Detector observed synthetic publicAccess="Container" on maniqprodvault01.',
        'CRITICAL'
      );
    }, 8000);

    return () => clearTimeout(timer);
  }, [isWatchMode]);

  // Preset Switcher (Demo Datasets — Rec #5)
  const handleResetPreset = (preset: 'high_risk' | 'hardened') => {
    setCurrentPreset(preset);
    setRemediatedFindingIds([]);
    setIsLiveConnected(false);
    setIsDemoData(true);
    setLiveSyncWarnings([]);
    setLastCollectedAt('Sample Dataset (No Live Scan Performed)');
    if (preset === 'high_risk') {
      setStorageAccounts(SAMPLE_HIGH_RISK_DATASET.storageAccounts);
      setRoleAssignments(SAMPLE_HIGH_RISK_DATASET.roleAssignments);
      setLiveSourceName(
        'Demo Data — High-Risk Sample Scenario (No Live Assessment)'
      );
    } else {
      setStorageAccounts(SAMPLE_HARDENED_DATASET.storageAccounts);
      setRoleAssignments(SAMPLE_HARDENED_DATASET.roleAssignments);
      setLiveSourceName(
        'Demo Data — Hardened Reference Sample (No Live Assessment)'
      );
    }
  };

  // Purge Token & Reset to Demo State (Rec #12)
  const handlePurgeTokenAndReset = () => {
    handleResetPreset('high_risk');
    pushAlert(
      'Bearer Token Purged from Memory',
      'Cleared in-memory credentials and reset workspace to Demo Sample state.',
      'INFO'
    );
  };

  // Simulate Hardening of a Storage Account in memory (Rec #6)
  const handleHardenAccount = (accountId: string) => {
    const targetAcc = storageAccounts.find((a) => a.id === accountId);
    if (!targetAcc) return;

    const prevScore = metrics.postureScore;

    const updatedAccounts = storageAccounts.map((acc) => {
      if (acc.id !== accountId) return acc;
      return {
        ...acc,
        allowBlobPublicAccess: false,
        allowSharedKeyAccess: false,
        minimumTlsVersion: 'TLS1_2' as const,
        supportsHttpsTrafficOnly: true,
        publicNetworkAccess: 'Disabled' as const,
        defaultAction: 'Deny' as const,
        privateEndpointConnections:
          acc.privateEndpointConnections.length > 0
            ? acc.privateEndpointConnections
            : [`pe-${acc.name}-blob`],
        containers: acc.containers.map((c) => ({
          ...c,
          publicAccess: 'None' as const,
        })),
      };
    });

    const newEval = evaluateAzurePosture(updatedAccounts, roleAssignments);
    setStorageAccounts(updatedAccounts);

    recordRemediationLog(
      `[Simulated In-Memory] Hardened Storage Account (${targetAcc.name})`,
      targetAcc.name,
      'storage',
      prevScore,
      newEval.metrics.postureScore,
      `# Pre-check first, then apply in staging:\naz storage account update --name ${targetAcc.name} --resource-group ${targetAcc.resourceGroup} --allow-blob-public-access false --allow-shared-key-access false --min-tls-version TLS1_2 --https-only true --default-action Deny`,
      'in_memory_simulation'
    );

    pushAlert(
      `In-Memory Simulation: ${targetAcc.name}`,
      `Simulated hardening in UI memory: Posture Score changed from ${prevScore} to ${newEval.metrics.postureScore}. Run CLI runbook to apply to Azure.`,
      'INFO'
    );
  };

  // Simulate Revoking an RBAC Role Assignment in memory (Rec #6)
  const handleRevokeAssignment = (assignmentId: string) => {
    const targetRole = roleAssignments.find((r) => r.id === assignmentId);
    if (!targetRole) return;

    const prevScore = metrics.postureScore;
    const updatedRoles = roleAssignments.filter((r) => r.id !== assignmentId);
    const newEval = evaluateAzurePosture(storageAccounts, updatedRoles);

    setRoleAssignments(updatedRoles);

    recordRemediationLog(
      `[Simulated In-Memory] Revoked ${targetRole.roleDefinitionName} for ${targetRole.principalName}`,
      targetRole.principalName,
      'rbac',
      prevScore,
      newEval.metrics.postureScore,
      `# Verify active workload dependencies before deleting:\naz role assignment delete --ids "${targetRole.id}"`,
      'in_memory_simulation'
    );

    pushAlert(
      `In-Memory Simulation: ${targetRole.principalName}`,
      `Simulated removal of ${targetRole.roleDefinitionName} on ${targetRole.scopeName} in UI memory.`,
      'INFO'
    );
  };

  // Acknowledge / Simulate remediation of a specific finding by ID (Rec #6)
  const handleRemediateFinding = (findingId: string) => {
    const finding = activeFindings.find((f) => f.id === findingId);
    if (!finding) return;

    const prevScore = metrics.postureScore;
    setRemediatedFindingIds((prev) => [...prev, findingId]);
    const newScore = Math.min(100, prevScore + 8);

    recordRemediationLog(
      `[Acknowledged in UI — Unverified in Azure] ${finding.title}`,
      finding.resourceName,
      finding.category,
      prevScore,
      newScore,
      finding.remediation.cliCommand.replace(/\\\n/g, ' '),
      'acknowledged_unverified'
    );

    pushAlert(
      'Finding Acknowledged in Session UI',
      `${finding.title} (${finding.resourceName}) marked acknowledged in memory. Verify change in Azure ARM.`,
      'INFO'
    );
  };

  // Simulate Hardening All Loopholes in memory (Rec #6)
  const handleHardenAll = () => {
    const prevScore = metrics.postureScore;
    setStorageAccounts(SAMPLE_HARDENED_DATASET.storageAccounts);
    setRoleAssignments(SAMPLE_HARDENED_DATASET.roleAssignments);
    setCurrentPreset('hardened');
    setIsDemoData(true);
    setRemediatedFindingIds([]);

    const newEval = evaluateAzurePosture(
      SAMPLE_HARDENED_DATASET.storageAccounts,
      SAMPLE_HARDENED_DATASET.roleAssignments
    );

    recordRemediationLog(
      '[Simulated In-Memory] Applied Baseline Hardening Simulation',
      'All Sample Storage Accounts & Subscriptions',
      'storage',
      prevScore,
      newEval.metrics.postureScore,
      '# In-memory simulation only — export Dry-Run Bash script from Findings tab to review CLI commands.',
      'in_memory_simulation'
    );

    pushAlert(
      'In-Memory Hardening Simulation Applied',
      `Simulated baseline hardening in UI memory (Score: ${prevScore} → ${newEval.metrics.postureScore}). No live Azure changes were made.`,
      'INFO'
    );
  };

  // Inject Misconfiguration Scenario (Simulator)
  const handleInjectScenario = (
    scenarioType:
      | 'open_container'
      | 'guest_owner'
      | 'custom_wildcard_role'
      | 'disable_firewall'
  ) => {
    setIsDemoData(true);
    if (scenarioType === 'open_container') {
      setStorageAccounts((prev) =>
        prev.map((acc, idx) =>
          idx === 0
            ? {
                ...acc,
                allowBlobPublicAccess: true,
                containers: [
                  ...acc.containers,
                  {
                    name: `leaked-payroll-export-${Math.floor(
                      100 + Math.random() * 900
                    )}`,
                    publicAccess: 'Container',
                    lastModified: new Date().toISOString().slice(0, 10),
                    blobCount: 1450,
                    sizeGb: 19.4,
                    hasSensitiveData: true,
                    immutabilityPolicy: false,
                  },
                ],
              }
            : acc
        )
      );
      pushAlert(
        'SIMULATION: Anonymous Container Injected',
        'Simulated creation of public container with publicAccess="Container" (Demo Data).',
        'CRITICAL'
      );
    } else if (scenarioType === 'guest_owner') {
      setRoleAssignments((prev) => [
        ...prev,
        {
          id: `role-sim-guest-${Date.now()}`,
          principalId: `pid-guest-${Date.now()}`,
          principalName: 'contractor_temp#EXT#@untrusted-vendor.org',
          principalType: 'GuestUser',
          roleDefinitionName: 'Owner',
          roleType: 'BuiltInRole',
          scope: '/subscriptions/prod-sub-001',
          scopeLevel: 'ManagementGroup',
          scopeName: 'Root Management Group (mg-enterprise-root)',
          actions: ['*'],
          dataActions: ['*'],
          isExternalGuest: true,
          lastActiveDays: 180,
          assignedDate: new Date().toISOString().slice(0, 10),
        },
      ]);
      pushAlert(
        'SIMULATION: External Guest Owner Injected',
        'contractor_temp#EXT#@untrusted-vendor.org granted Owner in simulation memory.',
        'CRITICAL'
      );
    } else if (scenarioType === 'custom_wildcard_role') {
      setRoleAssignments((prev) => [
        ...prev,
        {
          id: `role-sim-wild-${Date.now()}`,
          principalId: `pid-wild-${Date.now()}`,
          principalName: 'sp-rogue-automation-pipeline',
          principalType: 'ServicePrincipal',
          roleDefinitionName: 'Custom-Shadow-Admin-Role',
          roleType: 'CustomRole',
          scope: '/subscriptions/prod-sub-001',
          scopeLevel: 'Subscription',
          scopeName: 'Production-Core-Sub',
          actions: [
            'Microsoft.Authorization/*',
            'Microsoft.Storage/storageAccounts/listKeys/action',
          ],
          dataActions: ['Microsoft.Storage/*'],
          isExternalGuest: false,
          lastActiveDays: 1,
          assignedDate: new Date().toISOString().slice(0, 10),
        },
      ]);
      pushAlert(
        'SIMULATION: Shadow Admin Custom Role Injected',
        'sp-rogue-automation-pipeline granted Microsoft.Authorization/* in simulation memory.',
        'HIGH'
      );
    } else if (scenarioType === 'disable_firewall') {
      setStorageAccounts((prev) =>
        prev.map((acc) => ({
          ...acc,
          publicNetworkAccess: 'Enabled',
          defaultAction: 'Allow',
          minimumTlsVersion: 'TLS1_0',
          supportsHttpsTrafficOnly: false,
        }))
      );
      pushAlert(
        'SIMULATION: Storage Network Firewalls Disabled',
        'All sample storage accounts set to defaultAction="Allow" and TLS 1.0 in simulation memory.',
        'CRITICAL'
      );
    }
  };

  // Apply Live Resources from Azure ARM REST API or CLI Stream
  const handleApplyLiveResources = (data: {
    storageAccounts: typeof storageAccounts;
    roleAssignments: typeof roleAssignments;
    subscriptionId: string;
    sourceName: string;
    warnings?: string[];
    isDemoData?: boolean;
  }) => {
    const demoFlag = data.isDemoData ?? false;
    setStorageAccounts(data.storageAccounts);
    setRoleAssignments(data.roleAssignments);
    setRemediatedFindingIds([]);
    setIsLiveConnected(!demoFlag);
    setIsDemoData(demoFlag);
    setLiveSourceName(data.sourceName);
    setLastCollectedAt(new Date().toLocaleString());
    setLiveSyncWarnings(data.warnings || []);

    const liveEval = evaluateAzurePosture(
      data.storageAccounts,
      data.roleAssignments
    );

    recordRemediationLog(
      demoFlag
        ? `Loaded Simulated Sandbox Dataset (${data.sourceName})`
        : `Synchronized Live Azure Resources (${data.sourceName})`,
      data.subscriptionId,
      'storage',
      metrics.postureScore,
      liveEval.metrics.postureScore,
      demoFlag
        ? '# Simulated sandbox dataset loaded in memory'
        : `az storage account list --subscription "${data.subscriptionId}" && az role assignment list --all`,
      'in_memory_simulation'
    );

    if (data.warnings && data.warnings.length > 0) {
      pushAlert(
        'Live Azure ARM Notice',
        data.warnings[0],
        'HIGH'
      );
    } else {
      pushAlert(
        demoFlag ? 'Simulated Sandbox Loaded' : 'Live Azure Telemetry Synchronized!',
        `Evaluated ${data.storageAccounts.length} Storage Accounts and ${data.roleAssignments.length} RBAC Assignments (${data.sourceName}).`,
        'INFO'
      );
    }
  };

  // Export PDF Handler with Demo/Live & Redaction support (Rec #15)
  const handleExportPdf = (redactIdentifiers = false) => {
    downloadSecurityAuditPdf(
      metrics,
      activeFindings,
      storageAccounts,
      roleAssignments,
      liveSourceName,
      {
        isDemoData,
        redactIdentifiers,
        collectionSource: liveSourceName,
        lastCollectedAt,
      }
    );
  };

  return (
    <div className="min-h-screen bg-[#F3F5F1] text-[#16232F] flex flex-col selection:bg-[#2BB5A0]/25 selection:text-[#081420]">
      {/* Real-time Floating Notification Banner */}
      <AlertNotificationBanner
        alerts={alerts}
        onDismiss={(id) => setAlerts((prev) => prev.filter((a) => a.id !== id))}
        onClearAll={() => setAlerts([])}
      />

      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        criticalCount={metrics.criticalCount}
        totalFindings={activeFindings.length}
        remediationLogCount={remediationLogs.length}
        onExportPdf={() => handleExportPdf(false)}
        onPreviewPdf={() => setIsPdfPreviewOpen(true)}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        onOpenLiveSync={() => setIsLiveSyncOpen(true)}
        onOpenGovernance={() => setIsGovernanceOpen(true)}
        isLiveConnected={isLiveConnected}
        isDemoData={isDemoData}
        liveSourceName={liveSourceName}
        onResetPreset={handleResetPreset}
        currentPreset={currentPreset}
        isWatchMode={isWatchMode}
        onToggleWatchMode={() => setIsWatchMode((prev) => !prev)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Compact Status & Connection Strip */}
        <div className="mb-5 px-4 py-2.5 rounded-xl bg-white border border-slate-200/90 shadow-xs flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-2.5">
            {isDemoData ? (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-amber-50 text-amber-900 border border-amber-200 font-mono font-semibold text-[11px]">
                <KeyRound className="w-3 h-3 text-amber-700" />
                <span>Sample Demo Dataset</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-50 text-[#1F8A79] border border-emerald-200 font-mono font-semibold text-[11px]">
                <ShieldCheck className="w-3.5 h-3.5 text-[#1F8A79]" />
                <span>Live Azure ARM Connected</span>
              </span>
            )}
            <span className="text-[#546471]">
              Source: <strong className="font-mono text-[#16232F]">{liveSourceName}</strong>
              {' · '}
              Tenant: <code className="font-mono text-[#16232F]">{DEFAULT_AZURE_TENANT_ID.slice(0, 8)}...</code>
              {' · '}
              Sub: <code className="font-mono text-[#16232F]">{DEFAULT_AZURE_SUBSCRIPTION_ID.slice(0, 8)}...</code>
              {' · '}
              Collected: <code className="font-mono">{lastCollectedAt}</code>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsGovernanceOpen(true)}
              className="px-2.5 py-1 rounded-md bg-slate-100 hover:bg-slate-200 text-[#16232F] border border-slate-200 font-medium text-[11px] flex items-center gap-1 transition-colors cursor-pointer"
            >
              <Scale className="w-3 h-3 text-[#1F8A79]" />
              <span>Scope &amp; Governance</span>
            </button>
            <button
              onClick={() => setIsLiveSyncOpen(true)}
              className="px-2.5 py-1 rounded-md bg-[#0E2238] hover:bg-[#15314E] text-white font-medium text-[11px] flex items-center gap-1 transition-colors cursor-pointer"
            >
              <KeyRound className="w-3 h-3 text-[#5FD3BF]" />
              <span>Configure Token</span>
            </button>
            {!isDemoData && (
              <button
                onClick={handlePurgeTokenAndReset}
                className="px-2.5 py-1 rounded-md bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 font-medium text-[11px] transition-colors cursor-pointer"
              >
                Purge Token
              </button>
            )}
          </div>
        </div>

        {/* Concise Diagnostic Notice if Azure ARM returned warnings */}
        {liveSyncWarnings.length > 0 && (
          <div className="mb-5 px-4 py-3 rounded-xl bg-amber-50/90 border border-amber-200 text-amber-950 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div className="space-y-0.5">
              <div className="font-semibold text-amber-900 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-700 flex-shrink-0" />
                <span>Azure ARM Telemetry Notice ({liveSourceName})</span>
              </div>
              <p className="text-amber-800 font-mono text-[11px]">
                {liveSyncWarnings[0]}
              </p>
            </div>
            <button
              onClick={() => setIsLiveSyncOpen(true)}
              className="px-3 py-1.5 rounded-lg bg-[#0E2238] hover:bg-[#15314E] text-white font-semibold text-xs whitespace-nowrap transition-all cursor-pointer"
            >
              Inspect Connection →
            </button>
          </div>
        )}

        {activeTab === 'overview' && (
          <OverviewDashboard
            metrics={metrics}
            findings={activeFindings}
            storageAccounts={storageAccounts}
            remediationLogs={remediationLogs}
            isDemoData={isDemoData}
            collectionSource={liveSourceName}
            lastCollectedAt={lastCollectedAt}
            onSelectTab={setActiveTab}
            onSelectFinding={(f) => setSelectedFinding(f)}
            onHardenAll={handleHardenAll}
            onHardenAccount={handleHardenAccount}
            onOpenGovernance={() => setIsGovernanceOpen(true)}
          />
        )}

        {activeTab === 'inventory' && (
          <StorageInventory
            storageAccounts={storageAccounts}
            onHardenAccount={handleHardenAccount}
            isDemoData={isDemoData}
          />
        )}

        {activeTab === 'storage' && (
          <StorageAuditor
            storageAccounts={storageAccounts}
            roleAssignments={roleAssignments}
            onHardenAccount={handleHardenAccount}
          />
        )}

        {activeTab === 'rbac' && (
          <RbacAuditor
            roleAssignments={roleAssignments}
            onRevokeAssignment={handleRevokeAssignment}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsList
            findings={activeFindings}
            onSelectFinding={(f) => setSelectedFinding(f)}
            onRemediateFinding={handleRemediateFinding}
          />
        )}

        {activeTab === 'remediation_log' && (
          <RemediationLog
            logs={remediationLogs}
            onClearLogs={() => setRemediationLogs([])}
          />
        )}
      </main>

      {/* Postrix Dark Navy Footer with Scope, Privacy & Independence Disclosures (Rec #8, #9, #12, #13) */}
      <footer className="border-t border-white/10 bg-[#081420] py-6 px-4 text-xs text-[#B7C3CC] mt-12">
        <div className="max-w-7xl mx-auto space-y-3">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center space-x-2 flex-wrap gap-y-1">
              <span className="font-serif font-bold text-white">Maniq Shield</span>
              <span>—</span>
              <span>
                Azure Storage &amp; RBAC Heuristic Scanner · Tool Author:{' '}
                <a
                  href="https://ravindran.in"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[#5FD3BF] hover:underline font-medium inline-flex items-center space-x-1"
                >
                  <span>Mani Ravindran (ravindran.in)</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </span>
            </div>
            <div className="flex items-center space-x-3 text-[11px] font-mono">
              <button
                onClick={() => setIsGovernanceOpen(true)}
                className="text-[#5FD3BF] hover:underline flex items-center space-x-1"
              >
                <Lock className="w-3 h-3" />
                <span>Privacy, Token Policy &amp; CSV Recommendations (13/13)</span>
              </button>
            </div>
          </div>

          <div className="pt-3 border-t border-white/10 text-[11px] text-[#8FA1B0] leading-relaxed">
            <strong>Authorized Use, Scope &amp; Independence Notice (Rec #3, #8, #9, #12, #13):</strong> Use only on Azure subscriptions where you hold explicit owner authorization. Bearer Tokens are processed strictly in volatile browser memory via direct HTTPS requests to <code>management.azure.com</code> and are never logged or stored. Cross-references to CIS Azure Foundations v2.0, Microsoft Cloud Security Benchmark (MCSB), and NIST SP 800-53 Rev 5 cover a selected subset of 18 automated checks for informational guidance only — Maniq Shield is independent and not affiliated with, endorsed by, or certified by Microsoft Corporation, CIS, or NIST.
          </div>
        </div>
      </footer>

      {/* Finding Remediation Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onRemediate={handleRemediateFinding}
      />

      {/* Interactive PDF Preview & Visual Aids Modal */}
      <PdfPreviewModal
        isOpen={isPdfPreviewOpen}
        onClose={() => setIsPdfPreviewOpen(false)}
        findings={activeFindings}
        metrics={metrics}
        onDownloadPdf={(redact) => handleExportPdf(redact)}
        isDemoData={isDemoData}
        collectionSource={liveSourceName}
        lastCollectedAt={lastCollectedAt}
      />

      {/* Live Misconfiguration Simulator Modal */}
      <MisconfigurationSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onInjectScenario={handleInjectScenario}
      />

      {/* Live Azure Connection & Real-Time Event Grid Stream Modal */}
      <LiveAzureSyncModal
        isOpen={isLiveSyncOpen}
        onClose={() => setIsLiveSyncOpen(false)}
        onApplyLiveResources={handleApplyLiveResources}
        isLiveConnected={isLiveConnected}
        liveSourceName={liveSourceName}
        onToggleContinuousEventStream={() => setIsWatchMode((prev) => !prev)}
        isEventStreamActive={isWatchMode}
        onTriggerDriftAlert={(scenario) =>
          handleInjectScenario(scenario as any)
        }
        onPurgeToken={handlePurgeTokenAndReset}
      />

      {/* Governance, Privacy & CSV Recommendations Review Modal */}
      <GovernanceReviewModal
        isOpen={isGovernanceOpen}
        onClose={() => setIsGovernanceOpen(false)}
        onOpenLiveSync={() => setIsLiveSyncOpen(true)}
        onPurgeToken={handlePurgeTokenAndReset}
        isDemoData={isDemoData}
      />
    </div>
  );
}

export default App;
