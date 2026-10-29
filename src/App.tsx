/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  SAMPLE_HIGH_RISK_DATASET,
  SAMPLE_HARDENED_DATASET,
} from './utils/defaultData';
import {
  AuditDataset,
  Finding,
  RbacAssignment,
  RemediationLogEntry,
  SecurityAlert,
  StorageAccount,
} from './types/security';
import { executeFullAudit } from './utils/securityEngine';
import { generateAzureSecurityPdfReport } from './utils/pdfGenerator';
import { Navbar } from './components/Navbar';
import { AlertNotificationBanner } from './components/AlertNotificationBanner';
import { OverviewDashboard } from './components/OverviewDashboard';
import { StorageAuditor } from './components/StorageAuditor';
import { RbacAuditor } from './components/RbacAuditor';
import { FindingsList } from './components/FindingsList';
import { RemediationLog } from './components/RemediationLog';
import { FindingDetailModal } from './components/FindingDetailModal';
import { PdfPreviewModal } from './components/PdfPreviewModal';
import { MisconfigurationSimulatorModal } from './components/MisconfigurationSimulatorModal';
import { LiveAzureSyncModal } from './components/LiveAzureSyncModal';
import {
  DEFAULT_AZURE_ACCESS_TOKEN,
  DEFAULT_AZURE_SUBSCRIPTION_ID,
  DEFAULT_AZURE_TENANT_ID,
  fetchLiveAzureResources,
} from './utils/azureLiveApi';

export default function App() {
  const [activePresetKey, setActivePresetKey] = useState<'high_risk' | 'hardened'>('high_risk');
  const [storageAccounts, setStorageAccounts] = useState<StorageAccount[]>(
    SAMPLE_HIGH_RISK_DATASET.storageAccounts
  );
  const [roleAssignments, setRoleAssignments] = useState<RbacAssignment[]>(
    SAMPLE_HIGH_RISK_DATASET.roleAssignments
  );
  const [activeTab, setActiveTab] = useState<
    'overview' | 'storage' | 'rbac' | 'findings' | 'remediation_log'
  >('overview');
  const [remediationLog, setRemediationLog] = useState<RemediationLogEntry[]>([]);
  
  // Real-time alerting states
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [activeBannerAlert, setActiveBannerAlert] = useState<SecurityAlert | null>(null);
  const [isContinuousMonitoring, setIsContinuousMonitoring] = useState<boolean>(true);

  // Live Azure connection states
  const [isLiveConnected, setIsLiveConnected] = useState<boolean>(false);
  const [isLiveSyncModalOpen, setIsLiveSyncModalOpen] = useState<boolean>(false);
  const [liveSourceName, setLiveSourceName] = useState<string>('');
  const [liveSubscriptionId, setLiveSubscriptionId] = useState<string>(
    DEFAULT_AZURE_SUBSCRIPTION_ID
  );
  const [isEventStreamActive, setIsEventStreamActive] = useState<boolean>(true);

  // Automatically attempt live Azure ARM sync on startup using configured defaults
  useEffect(() => {
    let mounted = true;
    fetchLiveAzureResources({
      subscriptionId: DEFAULT_AZURE_SUBSCRIPTION_ID,
      tenantId: DEFAULT_AZURE_TENANT_ID,
      accessToken: DEFAULT_AZURE_ACCESS_TOKEN,
      scanAllSubscriptions: false,
    })
      .then((res) => {
        if (
          mounted &&
          (res.storageAccounts.length > 0 || res.roleAssignments.length > 0)
        ) {
          setStorageAccounts(res.storageAccounts);
          setRoleAssignments(res.roleAssignments);
          setLiveSubscriptionId(
            res.subscriptionIds[0] || DEFAULT_AZURE_SUBSCRIPTION_ID
          );
          setLiveSourceName(
            `Azure ARM REST API (${DEFAULT_AZURE_SUBSCRIPTION_ID.slice(0, 8)}...)`
          );
          setIsLiveConnected(true);
        }
      })
      .catch(() => {
        // Keep default dataset ready if browser CORS or token blocks direct background call
      });
    return () => {
      mounted = false;
    };
  }, []);

  // Modals
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [isPdfPreviewOpen, setIsPdfPreviewOpen] = useState(false);
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);

  // Run audit engine whenever storage accounts or roles update
  const { findings, metrics } = useMemo(() => {
    return executeFullAudit(storageAccounts, roleAssignments);
  }, [storageAccounts, roleAssignments]);

  // Active dataset representation
  const activeDataset: AuditDataset = useMemo(() => {
    return {
      presetName: isLiveConnected
        ? liveSourceName || 'Live Azure Subscription'
        : activePresetKey === 'high_risk'
        ? SAMPLE_HIGH_RISK_DATASET.presetName
        : SAMPLE_HARDENED_DATASET.presetName,
      description: isLiveConnected
        ? 'Real-time synchronized Azure Storage Accounts, Blob Containers, and RBAC Role Assignments.'
        : activePresetKey === 'high_risk'
        ? SAMPLE_HIGH_RISK_DATASET.description
        : SAMPLE_HARDENED_DATASET.description,
      subscriptionId: isLiveConnected
        ? liveSubscriptionId || DEFAULT_AZURE_SUBSCRIPTION_ID
        : activePresetKey === 'high_risk'
        ? SAMPLE_HIGH_RISK_DATASET.subscriptionId
        : SAMPLE_HARDENED_DATASET.subscriptionId,
      storageAccounts,
      roleAssignments,
    };
  }, [
    isLiveConnected,
    liveSourceName,
    liveSubscriptionId,
    activePresetKey,
    storageAccounts,
    roleAssignments,
  ]);

  // Helper to trigger a real-time alert
  const triggerRealTimeAlert = useCallback((finding: Finding) => {
    const newAlert: SecurityAlert = {
      id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      findingId: finding.id,
      title: `[NEW LOOPHOLE] ${finding.title}`,
      severity: finding.severity,
      resourceName: finding.resourceName,
      category: finding.category,
      timestamp: new Date().toLocaleTimeString(),
      summary: finding.description,
      read: false,
    };

    setAlerts((prev) => [newAlert, ...prev]);
    setActiveBannerAlert(newAlert);
  }, []);

  // Initialize initial alerts on mount for the existing critical findings
  useEffect(() => {
    document.title = 'Maniq Shield';
    if (findings.length > 0 && alerts.length === 0) {
      const initialAlerts: SecurityAlert[] = findings
        .filter((f) => f.severity === 'CRITICAL')
        .slice(0, 3)
        .map((f, i) => ({
          id: `initial-alert-${i}`,
          findingId: f.id,
          title: f.title,
          severity: f.severity,
          resourceName: f.resourceName,
          category: f.category,
          timestamp: new Date().toLocaleTimeString(),
          summary: f.description,
          read: false,
        }));
      setAlerts(initialAlerts);
    }
  }, [findings, alerts.length]);

  // Continuous Cloud Watch Simulator: periodically checks posture
  useEffect(() => {
    if (!isContinuousMonitoring) return;

    // Simulate heartbeats and checks every 20 seconds
    const interval = setInterval(() => {
      // Periodic check confirmation (internal telemetry simulation)
    }, 20000);

    return () => clearInterval(interval);
  }, [isContinuousMonitoring]);

  // Handle Preset Switching
  const handleSelectDataset = (key: string) => {
    setIsLiveConnected(false);
    if (key === 'hardened') {
      setActivePresetKey('hardened');
      setStorageAccounts(SAMPLE_HARDENED_DATASET.storageAccounts);
      setRoleAssignments(SAMPLE_HARDENED_DATASET.roleAssignments);
    } else {
      setActivePresetKey('high_risk');
      setStorageAccounts(SAMPLE_HIGH_RISK_DATASET.storageAccounts);
      setRoleAssignments(SAMPLE_HIGH_RISK_DATASET.roleAssignments);
    }
  };

  // Handle live Azure resources sync
  const handleApplyLiveResources = (data: {
    storageAccounts: StorageAccount[];
    roleAssignments: RbacAssignment[];
    subscriptionId: string;
    sourceName: string;
  }) => {
    if (data.storageAccounts.length > 0) setStorageAccounts(data.storageAccounts);
    if (data.roleAssignments.length > 0) setRoleAssignments(data.roleAssignments);
    setIsLiveConnected(true);
    setLiveSourceName(data.sourceName);
    setLiveSubscriptionId(data.subscriptionId);
    setIsEventStreamActive(true);

    const auditResult = executeFullAudit(
      data.storageAccounts.length > 0 ? data.storageAccounts : storageAccounts,
      data.roleAssignments.length > 0 ? data.roleAssignments : roleAssignments
    );
    const firstCrit = auditResult.findings.find((f) => f.severity === 'CRITICAL');
    if (firstCrit) {
      triggerRealTimeAlert(firstCrit);
    }
  };

  // Real-time Misconfiguration Injection handler
  const handleInjectMisconfiguration = (scenarioType: string) => {
    const timestamp = Date.now();

    if (scenarioType === 'open_container' || scenarioType === 'open_bucket') {
      // Injects public access container on an existing storage account
      const updatedAccounts = storageAccounts.map((acc, idx) => {
        if (idx === 0) {
          return {
            ...acc,
            allowBlobPublicAccess: true,
            containers: [
              {
                id: `cont-leaked-${timestamp}`,
                name: 'customer-ssn-vault',
                publicAccess: 'Container' as const,
                hasStoredAccessPolicyWithNoExpiry: true,
                sasTokenIssuedWithFullPermissions: true,
                immutabilityPolicyEnabled: false,
                blobCount: 840,
                dataClassification: 'PII/Financial' as const,
              },
              ...acc.containers,
            ],
          };
        }
        return acc;
      });

      setStorageAccounts(updatedAccounts);

      // Trigger immediate alert
      setTimeout(() => {
        const injectedFinding: Finding = {
          id: `SEC-CONT-${storageAccounts[0]?.name}-customer-ssn-vault-EXPOSED`,
          title: "Public Anonymous Access Open on Container 'customer-ssn-vault' (Container)",
          category: 'storage',
          severity: 'CRITICAL',
          resourceId: `${storageAccounts[0]?.id}/containers/customer-ssn-vault`,
          resourceName: `${storageAccounts[0]?.name}/customer-ssn-vault`,
          resourceType: 'StorageContainer',
          description:
            "Container 'customer-ssn-vault' has just been exposed to anonymous public read/list access! Anyone on the internet can download stored Social Security and financial documents.",
          exploitScenario:
            "Unauthenticated threat actors can enumerate https://blob.core.windows.net/customer-ssn-vault and dump all classified customer records.",
          businessImpact: "Direct regulatory breach and GDPR/HIPAA compliance violation.",
          compliance: { cisAzure: '3.7', mcsb: 'DP-2', nist: 'AC-3' },
          remediation: {
            summary: "Set container public access to Private immediately.",
            cliCommand: `az storage container set-permission --account-name "${storageAccounts[0]?.name}" --name "customer-ssn-vault" --public-access off`,
            portalSteps: [
              "Navigate to Azure Portal > Storage Accounts.",
              "Open container 'customer-ssn-vault'.",
              "Change access level to 'Private (no anonymous access)'.",
            ],
            terraformSnippet: `resource "azurerm_storage_container" "vault" {\n  name = "customer-ssn-vault"\n  container_access_type = "private"\n}`,
            impactNotice: "Requires authenticated tokens for all client access.",
          },
          detectedAt: new Date().toISOString(),
        };
        triggerRealTimeAlert(injectedFinding);
      }, 300);
    } else if (scenarioType === 'guest_owner') {
      const newGuestAssignment: RbacAssignment = {
        id: `ra-guest-${timestamp}`,
        principalId: `guest-ext-${timestamp}`,
        principalName: `unverified-contractor#EXT#@external-supplier.com`,
        principalType: 'GuestUser',
        roleDefinitionName: 'Owner',
        roleDefinitionId: '8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
        scope: `/subscriptions/${activeDataset.subscriptionId}`,
        isCustomRole: false,
        actions: ['*'],
        notActions: [],
        dataActions: [],
        lastActiveDays: 0,
        mfaEnforced: false,
        isExternalGuest: true,
        assignedDate: new Date().toISOString(),
      };

      setRoleAssignments((prev) => [newGuestAssignment, ...prev]);

      setTimeout(() => {
        const injectedFinding: Finding = {
          id: `SEC-RBAC-GUEST-${timestamp}`,
          title: "External Guest Account Has High-Privilege Role 'Owner' (unverified-contractor#EXT#)",
          category: 'rbac',
          severity: 'CRITICAL',
          resourceId: newGuestAssignment.id,
          resourceName: newGuestAssignment.principalName,
          resourceType: 'RoleAssignment',
          description:
            "External guest identity from an outside tenant has been granted full subscription Owner authority without MFA enforcement.",
          exploitScenario:
            "External identity provider breach permits direct cloud administrative takeover of all storage and computing resources.",
          businessImpact: "Third-party vendor compromise leading to full infrastructure loss.",
          compliance: { cisAzure: '1.3', mcsb: 'PA-1', nist: 'AC-2' },
          remediation: {
            summary: "Revoke external guest Owner assignment immediately.",
            cliCommand: `az role assignment delete --assignee "${newGuestAssignment.principalId}" --role "Owner" --scope "${newGuestAssignment.scope}"`,
            portalSteps: [
              "Go to Azure Portal > Subscriptions > Access control (IAM).",
              "Filter by 'Owner'.",
              "Select external guest user and click Remove.",
            ],
            terraformSnippet: "# Revoke subscription-level role assignments to external guest principals",
            impactNotice: "Contractor will lose subscription management access.",
          },
          detectedAt: new Date().toISOString(),
        };
        triggerRealTimeAlert(injectedFinding);
      }, 300);
    } else if (scenarioType === 'priv_esc') {
      const privEscRole: RbacAssignment = {
        id: `ra-esc-${timestamp}`,
        principalId: `sp-esc-${timestamp}`,
        principalName: `automation-helper-daemon`,
        principalType: 'ServicePrincipal',
        roleDefinitionName: 'Privilege Escalation Risk Role',
        roleDefinitionId: `custom-esc-${timestamp}`,
        scope: `/subscriptions/${activeDataset.subscriptionId}`,
        isCustomRole: true,
        actions: [
          'Microsoft.Storage/*',
          'Microsoft.Authorization/roleAssignments/write',
        ],
        notActions: [],
        dataActions: [],
        lastActiveDays: 0,
        mfaEnforced: true,
        isExternalGuest: false,
        assignedDate: new Date().toISOString(),
      };

      setRoleAssignments((prev) => [privEscRole, ...prev]);

      setTimeout(() => {
        const injectedFinding: Finding = {
          id: `SEC-ESC-DAEMON-${timestamp}`,
          title: "Privilege Escalation Vulnerability: 'roleAssignments/write' Permitted for 'automation-helper-daemon'",
          category: 'privilege_escalation',
          severity: 'CRITICAL',
          resourceId: privEscRole.id,
          resourceName: privEscRole.principalName,
          resourceType: 'RoleDefinition',
          description:
            "Non-owner service principal has permission to grant role assignments, enabling self-elevation to full Subscription Administrator.",
          exploitScenario:
            "Compromised service principal secret allows adversary to execute 'az role assignment create --role Owner --assignee <attacker-id>'.",
          businessImpact: "Total administrative takeover of cloud tenancy.",
          compliance: { cisAzure: '1.24', mcsb: 'PA-7', nist: 'AC-6' },
          remediation: {
            summary: "Remove 'Microsoft.Authorization/roleAssignments/*' from custom role definition.",
            cliCommand: `az role definition update --role-definition '{ "Name": "${privEscRole.roleDefinitionName}", "NotActions": ["Microsoft.Authorization/roleAssignments/*"] }'`,
            portalSteps: [
              "Go to Access control (IAM) > Roles.",
              "Edit custom role.",
              "Exclude role assignment permissions.",
            ],
            terraformSnippet: 'not_actions = ["Microsoft.Authorization/roleAssignments/*"]',
            impactNotice: "Automated service principal will not be able to delegate permissions.",
          },
          privilegeEscalationPath: `automation-helper-daemon -> roleAssignments/write -> Self-assign 'Owner' -> Full Control`,
          detectedAt: new Date().toISOString(),
        };
        triggerRealTimeAlert(injectedFinding);
      }, 300);
    } else if (scenarioType === 'insecure_http') {
      const updatedAccounts = storageAccounts.map((acc, idx) =>
        idx === 0 ? { ...acc, supportsHttpsTrafficOnly: false } : acc
      );
      setStorageAccounts(updatedAccounts);

      setTimeout(() => {
        const injectedFinding: Finding = {
          id: `SEC-HTTP-${timestamp}`,
          title: `Insecure HTTP Traffic Allowed on '${storageAccounts[0]?.name}'`,
          category: 'network',
          severity: 'CRITICAL',
          resourceId: storageAccounts[0]?.id || '',
          resourceName: storageAccounts[0]?.name || '',
          resourceType: 'StorageAccount',
          description: "Storage account has been reconfigured to allow plaintext HTTP traffic over port 80.",
          exploitScenario: "Man-in-the-middle sniffing of storage access keys and unencrypted payloads in transit.",
          businessImpact: "Non-compliance with PCI-DSS 4.0 and loss of cryptographic data confidentiality.",
          compliance: { cisAzure: '3.1', mcsb: 'DP-4', nist: 'SC-8' },
          remediation: {
            summary: "Enforce 'Secure transfer required' immediately.",
            cliCommand: `az storage account update --name "${storageAccounts[0]?.name}" --https-only true`,
            portalSteps: ["Storage Accounts > Configuration > Set 'Secure transfer required' to Enabled."],
            terraformSnippet: "enable_https_traffic_only = true",
            impactNotice: "HTTP clients must switch to HTTPS.",
          },
          detectedAt: new Date().toISOString(),
        };
        triggerRealTimeAlert(injectedFinding);
      }, 300);
    } else if (scenarioType === 'legacy_tls') {
      const updatedAccounts = storageAccounts.map((acc, idx) =>
        idx === 0 ? { ...acc, minimumTlsVersion: 'TLS1_0' as const } : acc
      );
      setStorageAccounts(updatedAccounts);

      setTimeout(() => {
        const injectedFinding: Finding = {
          id: `SEC-TLS-${timestamp}`,
          title: `Obsolete Protocol Version (TLS 1.0) Permitted on '${storageAccounts[0]?.name}'`,
          category: 'encryption',
          severity: 'HIGH',
          resourceId: storageAccounts[0]?.id || '',
          resourceName: storageAccounts[0]?.name || '',
          resourceType: 'StorageAccount',
          description: "Storage account protocol downgraded to TLS 1.0, exposing sessions to cryptographic downgrade attacks.",
          exploitScenario: "Exploiting known CBC-mode flaws in TLS 1.0 (POODLE / BEAST) to decrypt session secrets.",
          businessImpact: "Failure of CIS Azure 3.8 and NIST guidelines.",
          compliance: { cisAzure: '3.8', mcsb: 'DP-4', nist: 'SC-8' },
          remediation: {
            summary: "Enforce TLS 1.2 minimum version.",
            cliCommand: `az storage account update --name "${storageAccounts[0]?.name}" --min-tls-version TLS1_2`,
            portalSteps: ["Storage Account > Configuration > Minimum TLS version > Set to TLS 1.2."],
            terraformSnippet: 'min_tls_version = "TLS1_2"',
            impactNotice: "Clients without TLS 1.2 support will be rejected.",
          },
          detectedAt: new Date().toISOString(),
        };
        triggerRealTimeAlert(injectedFinding);
      }, 300);
    }
  };

  // Export PDF Report function
  const handleDownloadPdf = () => {
    try {
      const doc = generateAzureSecurityPdfReport(findings, metrics, {
        subscriptionId: activeDataset.subscriptionId,
        subscriptionName: activeDataset.presetName,
      });
      doc.save(`Maniq_Shield_Security_Loophole_Report_${Date.now()}.pdf`);
    } catch (err) {
      console.error('Error generating PDF report:', err);
    }
  };

  // Mark an individual finding as remediated / hardened in memory and log session remediation metadata
  const handleRemediateFinding = (findingId: string) => {
    const targetFinding =
      findings.find((f) => f.id === findingId) ||
      findings.find(
        (f) =>
          f.id.includes(findingId) ||
          findingId.includes(f.resourceName) ||
          f.resourceName.includes(findingId)
      );

    if (targetFinding) {
      const now = new Date();
      const totalEval = metrics.totalEvaluatedFindings || Math.max(1, findings.length);
      const hardenedBefore = metrics.hardenedFindingsCount || 0;
      const scoreBefore = metrics.postureScore;
      const scoreAfter = Math.min(
        100,
        Math.round(((hardenedBefore + 1) / totalEval) * 100)
      );

      const newLogEntry: RemediationLogEntry = {
        id: `remed-log-${now.getTime()}-${Math.random().toString(36).slice(2, 7)}`,
        findingId: targetFinding.id,
        title: targetFinding.title,
        category: targetFinding.category,
        severity: targetFinding.severity,
        resourceId: targetFinding.resourceId,
        resourceName: targetFinding.resourceName,
        resourceType: targetFinding.resourceType,
        remediatedAt: now.toISOString(),
        formattedTimestamp: now.toLocaleString(),
        remediationMethod: selectedFindingId === targetFinding.id
          ? 'Runbook Execution'
          : 'Single Remediation',
        remediationSummary: targetFinding.remediation.summary,
        cliCommandExecuted: targetFinding.remediation.cliCommand,
        terraformSnippet: targetFinding.remediation.terraformSnippet,
        compliance: targetFinding.compliance,
        subscriptionId: activeDataset.subscriptionId,
        postureScoreBefore: scoreBefore,
        postureScoreAfter: scoreAfter,
        operator: 'Mani Ravindran (SecOps Admin)',
      };

      setRemediationLog((prev) => [newLogEntry, ...prev]);
    }

    setStorageAccounts((prev) =>
      prev.map((acc) => {
        const matchesAccount =
          findingId.includes(acc.name) ||
          targetFinding?.resourceId === acc.id ||
          targetFinding?.resourceId?.startsWith(`${acc.id}/`);

        if (!matchesAccount) return acc;

        if (findingId.includes('PUB-ACCESS')) {
          return { ...acc, allowBlobPublicAccess: false };
        }
        if (findingId.includes('EXPOSED')) {
          return {
            ...acc,
            containers: acc.containers.map((c) =>
              findingId.includes(c.name) || targetFinding?.resourceId?.endsWith(`/${c.name}`)
                ? { ...c, publicAccess: 'None' }
                : c
            ),
          };
        }
        if (findingId.includes('INFINITE')) {
          return {
            ...acc,
            containers: acc.containers.map((c) =>
              findingId.includes(c.name) || targetFinding?.resourceId?.includes(`/${c.name}/`)
                ? { ...c, hasStoredAccessPolicyWithNoExpiry: false }
                : c
            ),
          };
        }
        if (findingId.includes('INSECURE-HTTP') || findingId.includes('SEC-HTTP')) {
          return { ...acc, supportsHttpsTrafficOnly: true };
        }
        if (findingId.includes('LEGACY-TLS') || findingId.includes('SEC-TLS')) {
          return { ...acc, minimumTlsVersion: 'TLS1_2' };
        }
        if (findingId.includes('NO-FIREWALL')) {
          return { ...acc, defaultAction: 'Deny', ipRulesCount: Math.max(2, acc.ipRulesCount) };
        }
        if (findingId.includes('SHARED-KEY')) {
          return { ...acc, allowSharedKeyAccess: false };
        }
        if (findingId.includes('NO-SOFT-DELETE')) {
          return { ...acc, softDeleteEnabled: true, blobRetentionDays: 30 };
        }
        if (findingId.includes('NO-LOGGING')) {
          return { ...acc, loggingEnabled: true };
        }
        if (findingId.includes('NO-DEFENDER')) {
          return { ...acc, defenderForStorageEnabled: true };
        }
        if (findingId.includes('NO-CMK')) {
          return { ...acc, customerManagedKeyEnabled: true };
        }
        if (findingId.includes('CROSS-TENANT')) {
          return { ...acc, crossTenantReplicationRestricted: true };
        }
        return acc;
      })
    );

    setRoleAssignments((prev) =>
      prev.map((r) => {
        const matchesRole =
          findingId.includes(r.id) ||
          targetFinding?.resourceId === r.id ||
          targetFinding?.resourceName === r.principalName;

        if (!matchesRole) return r;

        if (findingId.includes('SUB-OWNER')) {
          return {
            ...r,
            scope: r.scope.includes('/resourceGroups/')
              ? r.scope
              : `${r.scope}/resourceGroups/rg-scoped-workload`,
          };
        }
        if (findingId.includes('GUEST')) {
          return { ...r, isExternalGuest: false, roleDefinitionName: 'Reader', actions: ['*/read'] };
        }
        if (findingId.includes('PRIV-ESCALATION') || findingId.includes('ESC')) {
          return {
            ...r,
            actions: r.actions.filter(
              (a) =>
                a !== '*' &&
                !a.includes('roleAssignments/write') &&
                !a.includes('roleAssignments/*') &&
                a !== 'Microsoft.Authorization/*'
            ),
          };
        }
        if (findingId.includes('SP-OVERPRIVILEGED')) {
          return {
            ...r,
            roleDefinitionName: 'Storage Blob Data Reader',
            actions: ['Microsoft.Storage/storageAccounts/read'],
          };
        }
        if (findingId.includes('DORMANT')) {
          return { ...r, lastActiveDays: 0 };
        }
        if (findingId.includes('NO-MFA')) {
          return { ...r, mfaEnforced: true };
        }
        return r;
      })
    );

    // Dismiss banner if it matches
    if (activeBannerAlert?.findingId === findingId) {
      setActiveBannerAlert(null);
    }
  };

  // Harden all active findings across all storage accounts, containers, and RBAC assignments
  const handleHardenAllFindings = () => {
    if (findings.length > 0) {
      const now = new Date();
      const totalEval = metrics.totalEvaluatedFindings || Math.max(1, findings.length);
      const hardenedBefore = metrics.hardenedFindingsCount || 0;

      const bulkEntries: RemediationLogEntry[] = findings.map((f, index) => {
        const entryTime = new Date(now.getTime() + index);
        const stepBefore = Math.min(
          100,
          Math.round(((hardenedBefore + index) / totalEval) * 100)
        );
        const stepAfter = Math.min(
          100,
          Math.round(((hardenedBefore + index + 1) / totalEval) * 100)
        );

        return {
          id: `remed-log-${entryTime.getTime()}-${index}-${Math.random()
            .toString(36)
            .slice(2, 6)}`,
          findingId: f.id,
          title: f.title,
          category: f.category,
          severity: f.severity,
          resourceId: f.resourceId,
          resourceName: f.resourceName,
          resourceType: f.resourceType,
          remediatedAt: entryTime.toISOString(),
          formattedTimestamp: entryTime.toLocaleString(),
          remediationMethod: 'Bulk Hardening',
          remediationSummary: f.remediation.summary,
          cliCommandExecuted: f.remediation.cliCommand,
          terraformSnippet: f.remediation.terraformSnippet,
          compliance: f.compliance,
          subscriptionId: activeDataset.subscriptionId,
          postureScoreBefore: stepBefore,
          postureScoreAfter: stepAfter,
          operator: 'Mani Ravindran (SecOps Admin)',
        };
      });

      setRemediationLog((prev) => [...bulkEntries.reverse(), ...prev]);
    }

    setStorageAccounts((prev) =>
      prev.map((acc) => ({
        ...acc,
        allowBlobPublicAccess: false,
        defaultAction: 'Deny',
        ipRulesCount: Math.max(2, acc.ipRulesCount),
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion:
          acc.minimumTlsVersion === 'TLS1_0' || acc.minimumTlsVersion === 'TLS1_1'
            ? 'TLS1_2'
            : acc.minimumTlsVersion,
        allowSharedKeyAccess: false,
        customerManagedKeyEnabled: true,
        softDeleteEnabled: true,
        blobRetentionDays: Math.max(30, acc.blobRetentionDays),
        loggingEnabled: true,
        defenderForStorageEnabled: true,
        crossTenantReplicationRestricted: true,
        containers: acc.containers.map((c) => ({
          ...c,
          publicAccess: 'None',
          hasStoredAccessPolicyWithNoExpiry: false,
        })),
      }))
    );

    setRoleAssignments((prev) =>
      prev.map((r) => ({
        ...r,
        scope:
          r.roleDefinitionName === 'Owner' && !r.scope.includes('/resourceGroups/')
            ? `${r.scope}/resourceGroups/rg-scoped-workload`
            : r.scope,
        isExternalGuest: false,
        roleDefinitionName:
          r.principalType === 'ServicePrincipal' && r.roleDefinitionName === 'Owner'
            ? 'Storage Blob Data Reader'
            : r.roleDefinitionName,
        actions: r.actions.filter(
          (a) =>
            a !== '*' &&
            !a.includes('roleAssignments/write') &&
            !a.includes('roleAssignments/*') &&
            a !== 'Microsoft.Authorization/*'
        ),
        lastActiveDays: Math.min(r.lastActiveDays, 15),
        mfaEnforced: true,
      }))
    );

    setActiveBannerAlert(null);
  };

  // Lookup selected finding with fallback matching
  const selectedFinding = useMemo(() => {
    if (!selectedFindingId) return null;
    return (
      findings.find((f) => f.id === selectedFindingId) ||
      findings.find(
        (f) =>
          f.resourceName.includes(selectedFindingId) ||
          selectedFindingId.includes(f.resourceName) ||
          f.id.includes(selectedFindingId)
      ) ||
      findings[0] ||
      null
    );
  }, [findings, selectedFindingId]);

  const unreadAlertCount = alerts.filter((a) => !a.read).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans antialiased selection:bg-blue-600 selection:text-white">
      {/* Top Navbar */}
      <Navbar
        activeDataset={activeDataset}
        onSelectDataset={handleSelectDataset}
        onDownloadPdf={handleDownloadPdf}
        onOpenPdfPreview={() => setIsPdfPreviewOpen(true)}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        onOpenLiveSync={() => setIsLiveSyncModalOpen(true)}
        isLiveConnected={isLiveConnected}
        liveSourceName={liveSourceName}
        alerts={alerts}
        unreadAlertCount={unreadAlertCount}
        onSelectAlert={(findingId) => setSelectedFindingId(findingId)}
        onMarkAllAlertsRead={() =>
          setAlerts((prev) => prev.map((a) => ({ ...a, read: true })))
        }
        isContinuousMonitoring={isContinuousMonitoring}
        onToggleContinuousMonitoring={() =>
          setIsContinuousMonitoring(!isContinuousMonitoring)
        }
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        remediationLogCount={remediationLog.length}
      />

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <OverviewDashboard
            metrics={metrics}
            findings={findings}
            remediationLog={remediationLog}
            onClearRemediationLog={() => setRemediationLog([])}
            onNavigateTab={(tab) => setActiveTab(tab)}
            onSelectFinding={(id) => setSelectedFindingId(id)}
            onRemediateFinding={handleRemediateFinding}
            onHardenAll={handleHardenAllFindings}
          />
        )}

        {activeTab === 'storage' && (
          <StorageAuditor
            storageAccounts={storageAccounts}
            roleAssignments={roleAssignments}
            findings={findings}
            onSelectFinding={(id) => setSelectedFindingId(id)}
          />
        )}

        {activeTab === 'rbac' && (
          <RbacAuditor
            roleAssignments={roleAssignments}
            findings={findings}
            onSelectFinding={(id) => setSelectedFindingId(id)}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsList
            findings={findings}
            onSelectFinding={(id) => setSelectedFindingId(id)}
            onRemediateFinding={handleRemediateFinding}
            remediationLog={remediationLog}
            onClearRemediationLog={() => setRemediationLog([])}
          />
        )}

        {activeTab === 'remediation_log' && (
          <RemediationLog
            entries={remediationLog}
            onClearLog={() => setRemediationLog([])}
          />
        )}
      </main>

      {/* Real-time Alert Notification Banner (Float on newly detected loophole) */}
      <AlertNotificationBanner
        activeAlert={activeBannerAlert}
        onDismiss={() => setActiveBannerAlert(null)}
        onViewRemediation={(findingId) => {
          setSelectedFindingId(findingId);
          setActiveBannerAlert(null);
        }}
      />

      {/* Finding Drill-down & Remediation Runbook Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFindingId(null)}
        onRemediate={handleRemediateFinding}
      />

      {/* PDF Report Live Preview Modal */}
      <PdfPreviewModal
        isOpen={isPdfPreviewOpen}
        onClose={() => setIsPdfPreviewOpen(false)}
        findings={findings}
        metrics={metrics}
        onDownloadPdf={handleDownloadPdf}
      />

      {/* Misconfiguration Injection Simulator Modal */}
      <MisconfigurationSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onInject={handleInjectMisconfiguration}
      />

      {/* Live Azure REST API & CLI Ingestion Modal */}
      <LiveAzureSyncModal
        isOpen={isLiveSyncModalOpen}
        onClose={() => setIsLiveSyncModalOpen(false)}
        onApplyLiveResources={handleApplyLiveResources}
        isLiveConnected={isLiveConnected}
        liveSourceName={liveSourceName}
        onToggleContinuousEventStream={() =>
          setIsEventStreamActive(!isEventStreamActive)
        }
        isEventStreamActive={isEventStreamActive}
        onTriggerDriftAlert={handleInjectMisconfiguration}
      />

      {/* Author & Reference Footer */}
      <footer className="mt-16 border-t border-slate-800/80 bg-slate-950/80 py-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="font-semibold text-slate-300">Maniq Shield CSPM</span>
            <span>•</span>
            <span>Storage & RBAC Security Loophole Auditor</span>
          </div>
          <div className="flex items-center space-x-2">
            <span>Author: <strong className="text-slate-200">Mani Ravindran</strong></span>
            <span>•</span>
            <span>Reference:</span>
            <a
              href="https://ravindran.in"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:text-blue-300 underline font-medium"
            >
              ravindran.in
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
