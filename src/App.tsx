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
import { FindingDetailModal } from './components/FindingDetailModal';
import { PdfPreviewModal } from './components/PdfPreviewModal';
import { MisconfigurationSimulatorModal } from './components/MisconfigurationSimulatorModal';

export default function App() {
  const [activePresetKey, setActivePresetKey] = useState<'high_risk' | 'hardened'>('high_risk');
  const [storageAccounts, setStorageAccounts] = useState<StorageAccount[]>(
    SAMPLE_HIGH_RISK_DATASET.storageAccounts
  );
  const [roleAssignments, setRoleAssignments] = useState<RbacAssignment[]>(
    SAMPLE_HIGH_RISK_DATASET.roleAssignments
  );
  const [activeTab, setActiveTab] = useState<'overview' | 'storage' | 'rbac' | 'findings'>('overview');
  
  // Real-time alerting states
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [activeBannerAlert, setActiveBannerAlert] = useState<SecurityAlert | null>(null);
  const [isContinuousMonitoring, setIsContinuousMonitoring] = useState<boolean>(true);

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
      presetName:
        activePresetKey === 'high_risk'
          ? SAMPLE_HIGH_RISK_DATASET.presetName
          : SAMPLE_HARDENED_DATASET.presetName,
      description:
        activePresetKey === 'high_risk'
          ? SAMPLE_HIGH_RISK_DATASET.description
          : SAMPLE_HARDENED_DATASET.description,
      subscriptionId:
        activePresetKey === 'high_risk'
          ? SAMPLE_HIGH_RISK_DATASET.subscriptionId
          : SAMPLE_HARDENED_DATASET.subscriptionId,
      storageAccounts,
      roleAssignments,
    };
  }, [activePresetKey, storageAccounts, roleAssignments]);

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

  // Real-time Misconfiguration Injection handler
  const handleInjectMisconfiguration = (scenarioType: string) => {
    const timestamp = Date.now();

    if (scenarioType === 'open_bucket') {
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
      doc.save(`AzureShield_Security_Loophole_Report_${Date.now()}.pdf`);
    } catch (err) {
      console.error('Error generating PDF report:', err);
    }
  };

  // Mark an individual finding as remediated in memory
  const handleRemediateFinding = (findingId: string) => {
    // If it's a storage public access finding
    if (findingId.includes('PUB-ACCESS') || findingId.includes('EXPOSED')) {
      setStorageAccounts((prev) =>
        prev.map((acc) => ({
          ...acc,
          allowBlobPublicAccess: false,
          containers: acc.containers.map((c) => ({
            ...c,
            publicAccess: 'None',
          })),
        }))
      );
    } else if (findingId.includes('INSECURE-HTTP')) {
      setStorageAccounts((prev) =>
        prev.map((acc) => ({ ...acc, supportsHttpsTrafficOnly: true }))
      );
    } else if (findingId.includes('LEGACY-TLS')) {
      setStorageAccounts((prev) =>
        prev.map((acc) => ({ ...acc, minimumTlsVersion: 'TLS1_2' }))
      );
    } else if (findingId.includes('NO-FIREWALL')) {
      setStorageAccounts((prev) =>
        prev.map((acc) => ({
          ...acc,
          defaultAction: 'Deny',
          ipRulesCount: 2,
        }))
      );
    } else if (findingId.includes('GUEST') || findingId.includes('SUB-OWNER')) {
      // Remove or demote the role assignment
      setRoleAssignments((prev) =>
        prev.filter((r) => !findingId.includes(r.id) && !r.isExternalGuest)
      );
    } else if (findingId.includes('PRIV-ESCALATION') || findingId.includes('ESC')) {
      // Remove roleAssignments/write permission
      setRoleAssignments((prev) =>
        prev.map((r) => ({
          ...r,
          actions: r.actions.filter(
            (a) =>
              !a.includes('roleAssignments/write') &&
              a !== 'Microsoft.Authorization/*'
          ),
        }))
      );
    } else if (findingId.includes('DORMANT')) {
      // Revoke dormant role assignment
      setRoleAssignments((prev) => prev.filter((r) => r.lastActiveDays <= 90));
    }

    // Dismiss banner if it matches
    if (activeBannerAlert?.findingId === findingId) {
      setActiveBannerAlert(null);
    }
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
      />

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <OverviewDashboard
            metrics={metrics}
            findings={findings}
            onNavigateTab={(tab) => setActiveTab(tab)}
            onSelectFinding={(id) => setSelectedFindingId(id)}
          />
        )}

        {activeTab === 'storage' && (
          <StorageAuditor
            storageAccounts={storageAccounts}
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
    </div>
  );
}
