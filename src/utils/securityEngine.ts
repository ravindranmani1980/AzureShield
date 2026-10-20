/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  AuditMetrics,
  Finding,
  RbacAssignment,
  Severity,
  StorageAccount,
  StorageContainer,
  VulnerabilityCategory,
} from '../types/security';

export function auditStorageAccount(account: StorageAccount): Finding[] {
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  // 1. Critical: Public Blob Access Enabled on Account
  if (account.allowBlobPublicAccess) {
    findings.push({
      id: `SEC-STOR-${account.name}-PUB-ACCESS`,
      title: `Public Blob Access Allowed on Storage Account '${account.name}'`,
      category: 'storage',
      severity: 'CRITICAL',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' permits anonymous public read access at the account level. Even if individual containers are currently private, any user with Contributor rights can create an openly accessible blob container without restriction.`,
      exploitScenario: `Attackers search for exposed storage account endpoints or brute-force container names (e.g. /data, /backups, /export) to exfiltrate proprietary data, customer PII, or internal database dumps without any authentication.`,
      businessImpact: `Severe regulatory fines (GDPR, HIPAA), massive data breach publicity, data leakage of proprietary business secrets.`,
      compliance: {
        cisAzure: '3.7',
        cisTitle: 'Ensure that "Public access level" is set to Private for blob containers',
        mcsb: 'DP-2: Protect sensitive data',
        nist: 'AC-3, AC-4',
        iso27001: 'A.9.4.1',
      },
      remediation: {
        summary: `Disallow public blob access at the storage account level. This overrides container-level settings and blocks all anonymous requests.`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --allow-blob-public-access false`,
        portalSteps: [
          `Navigate to Azure Portal > Storage Accounts > select '${account.name}'.`,
          `Under 'Settings', select 'Configuration'.`,
          `Set 'Allow Blob anonymous access' to 'Disabled'.`,
          `Click 'Save' at the top of the blade.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  name                     = "${account.name}"\n  resource_group_name      = "${account.resourceGroup}"\n  location                 = "${account.location}"\n  account_tier             = "Standard"\n  account_replication_type = "GRS"\n  allow_nested_items_to_be_public = false\n}`,
        bicepSnippet: `resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: '${account.name}'\n  location: '${account.location}'\n  properties: {\n    allowBlobPublicAccess: false\n  }\n}`,
        impactNotice: `Any public-facing static assets (like public logos) must be served through Azure Front Door or Azure CDN with signed tokens or private endpoints.`,
      },
      detectedAt: now,
    });
  }

  // 2. Critical / High: Anonymous Container Access
  account.containers.forEach((container: StorageContainer) => {
    if (container.publicAccess !== 'None') {
      const isFullContainer = container.publicAccess === 'Container';
      findings.push({
        id: `SEC-CONT-${account.name}-${container.name}-EXPOSED`,
        title: `Public Anonymous Access Open on Container '${container.name}' (${container.publicAccess})`,
        category: 'storage',
        severity: 'CRITICAL',
        resourceId: `${account.id}/containers/${container.name}`,
        resourceName: `${account.name}/${container.name}`,
        resourceType: 'StorageContainer',
        description: `Container '${container.name}' is explicitly configured with public read access (${container.publicAccess}). ${
          isFullContainer
            ? 'Anonymous users can list and download every single blob in this container.'
            : 'Anonymous users can download blobs if they guess or know the blob URL.'
        }`,
        exploitScenario: `Unauthenticated threat actors can perform HTTP GET requests against https://${account.name}.blob.core.windows.net/${container.name} and enumerate or exfiltrate all stored files.`,
        businessImpact: `Direct unauthenticated exfiltration of classified enterprise files (${container.dataClassification || 'Internal'}). Immediate compliance failure.`,
        compliance: {
          cisAzure: '3.7',
          cisTitle: 'Ensure container public access level is Private',
          mcsb: 'DP-2: Protect sensitive data',
          nist: 'AC-3, SC-7',
        },
        remediation: {
          summary: `Change the container public access level immediately to 'Private' (no anonymous access).`,
          cliCommand: `az storage container set-permission \\\n  --account-name "${account.name}" \\\n  --name "${container.name}" \\\n  --public-access off \\\n  --auth-mode login`,
          portalSteps: [
            `Navigate to Storage Accounts > '${account.name}' > Containers.`,
            `Click on the container '${container.name}'.`,
            `Click 'Change access level'.`,
            `Select 'Private (no anonymous access)' and click OK.`,
          ],
          terraformSnippet: `resource "azurerm_storage_container" "${container.name}" {\n  name                  = "${container.name}"\n  storage_account_name  = "${account.name}"\n  container_access_type = "private"\n}`,
          impactNotice: `Legitimate clients must now authenticate using Azure Entra ID OAuth tokens or time-limited Shared Access Signatures (SAS).`,
        },
        detectedAt: now,
      });
    }

    // SAS / Access Policy loophole
    if (container.hasStoredAccessPolicyWithNoExpiry) {
      findings.push({
        id: `SEC-SAS-${account.name}-${container.name}-INFINITE`,
        title: `Indefinite Stored Access Policy on Container '${container.name}'`,
        category: 'storage',
        severity: 'HIGH',
        resourceId: `${account.id}/containers/${container.name}/policies`,
        resourceName: `${account.name}/${container.name}`,
        resourceType: 'StorageContainer',
        description: `A Stored Access Policy on container '${container.name}' has no expiration timestamp. Any SAS URL generated against this policy will grant indefinite access until manually revoked.`,
        exploitScenario: `If a developer or vendor leaks a SAS URL in GitHub, logs, or chat, an attacker retains permanent persistence to the container without being invalidated by credential expiration.`,
        businessImpact: `Persistent unauthorized backdoor into corporate storage infrastructure.`,
        compliance: {
          cisAzure: '3.10',
          mcsb: 'PA-3: Review and manage authorization policies',
          nist: 'AC-2, IA-5',
        },
        remediation: {
          summary: `Enforce a strict expiration date (<= 1 hour or 24 hours max) on all stored access policies, or migrate to Azure AD RBAC.`,
          cliCommand: `az storage container policy update \\\n  --account-name "${account.name}" \\\n  --container-name "${container.name}" \\\n  --name "legacy-policy" \\\n  --expiry $(date -u -d "+1 day" +%Y-%m-%dT%H:%M:%SZ) \\\n  --auth-mode login`,
          portalSteps: [
            `Go to Container '${container.name}' > 'Access policy'.`,
            `Edit the stored access policy and specify an expiration date & time.`,
            `Save changes.`,
          ],
          terraformSnippet: `# Avoid creating perpetual stored access policies without expiry blocks`,
          impactNotice: `Ensure integrated client applications are refreshed before expiration occurs.`,
        },
        detectedAt: now,
      });
    }
  });

  // 3. Critical: Secure Transfer (HTTPS) Required Disabled
  if (!account.supportsHttpsTrafficOnly) {
    findings.push({
      id: `SEC-STOR-${account.name}-INSECURE-HTTP`,
      title: `Insecure HTTP Traffic Allowed on '${account.name}'`,
      category: 'network',
      severity: 'CRITICAL',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' allows unencrypted plaintext HTTP traffic. Data in transit is vulnerable to interception, manipulation, and eavesdropping.`,
      exploitScenario: `Man-in-the-middle (MitM) attackers on corporate networks, public Wi-Fi, or intermediate routing hops can sniff data payloads and harvest storage account credentials or SAS tokens transmitted over HTTP.`,
      businessImpact: `Data compromise in transit, loss of confidentiality, non-compliance with PCI-DSS 4.0 and HIPAA encryption mandates.`,
      compliance: {
        cisAzure: '3.1',
        cisTitle: 'Ensure that "Secure transfer required" is set to "Enabled"',
        mcsb: 'DP-4: Encrypt sensitive data in transit',
        nist: 'SC-8, SC-13',
        iso27001: 'A.10.1.1',
      },
      remediation: {
        summary: `Enable 'Secure transfer required' to reject all non-HTTPS requests automatically.`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --https-only true`,
        portalSteps: [
          `Go to Storage Account > '${account.name}' > 'Configuration'.`,
          `Set 'Secure transfer required' to 'Enabled'.`,
          `Click 'Save'.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  enable_https_traffic_only = true\n}`,
        impactNotice: `Legacy applications hardcoded to 'http://' will receive HTTP 400 Bad Request until updated to HTTPS.`,
      },
      detectedAt: now,
    });
  }

  // 4. High: Legacy TLS Version (< TLS 1.2)
  if (account.minimumTlsVersion === 'TLS1_0' || account.minimumTlsVersion === 'TLS1_1') {
    findings.push({
      id: `SEC-STOR-${account.name}-LEGACY-TLS`,
      title: `Obsolete Protocol Version (${account.minimumTlsVersion}) Permitted on '${account.name}'`,
      category: 'encryption',
      severity: 'HIGH',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' accepts connections using deprecated cryptographic protocols (${account.minimumTlsVersion}), which are vulnerable to POODLE, BEAST, and SWEET32 cryptographic downgrade attacks.`,
      exploitScenario: `An adversary forces a protocol downgrade to TLS 1.0 or 1.1 to decrypt cipher suites using known cryptographic weaknesses.`,
      businessImpact: `Non-compliance with NIST, FedRAMP, and PCI-DSS requirements requiring TLS 1.2 minimum.`,
      compliance: {
        cisAzure: '3.8',
        cisTitle: 'Ensure that "Minimum TLS version" is set to "Version 1.2"',
        mcsb: 'DP-4: Encrypt data in transit',
        nist: 'SC-8',
      },
      remediation: {
        summary: `Enforce TLS 1.2 or TLS 1.3 as the minimum transport protocol version.`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --min-tls-version TLS1_2`,
        portalSteps: [
          `Open Storage Account '${account.name}' > 'Configuration'.`,
          `Set 'Minimum TLS version' to 'Version 1.2' or 'Version 1.3'.`,
          `Click 'Save'.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  min_tls_version = "TLS1_2"\n}`,
        impactNotice: `Ensure all legacy clients/agents support TLS 1.2 before enforcing.`,
      },
      detectedAt: now,
    });
  }

  // 5. High: Unrestricted Public Network Access
  if (
    account.publicNetworkAccess === 'Enabled' &&
    account.defaultAction === 'Allow' &&
    account.ipRulesCount === 0 &&
    account.virtualNetworkRulesCount === 0 &&
    account.privateEndpointConnectionsCount === 0
  ) {
    findings.push({
      id: `SEC-NET-${account.name}-NO-FIREWALL`,
      title: `Storage Account Open to All Internet IP Addresses (${account.name})`,
      category: 'network',
      severity: 'HIGH',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' has public network access enabled with default network rule set to 'Allow'. There are zero firewall IP whitelist rules, zero VNet endpoints, and zero Private Endpoints restricting connectivity.`,
      exploitScenario: `Any internet host can reach the storage control and data plane endpoints, increasing surface area for credential stuffing, brute force, and zero-day exploitation.`,
      businessImpact: `Lack of network segmentation; violates zero-trust architecture guidelines.`,
      compliance: {
        cisAzure: '3.6',
        cisTitle: 'Ensure default network access rule for Storage Accounts is set to deny',
        mcsb: 'NS-2: Connect private networks together',
        nist: 'SC-7: Boundary Protection',
      },
      remediation: {
        summary: `Configure firewall rules to allow only trusted corporate IP ranges and VNet Service Endpoints or deploy an Azure Private Endpoint.`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --default-action Deny`,
        portalSteps: [
          `Go to Storage Account '${account.name}' > 'Networking'.`,
          `Under 'Public network access', select 'Enabled from selected virtual networks and IP addresses'.`,
          `Add your corporate outbound CIDR ranges or configure Private Endpoints.`,
          `Click 'Save'.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account_network_rules" "rules" {\n  storage_account_id = azurerm_storage_account.${account.name}.id\n  default_action     = "Deny"\n  ip_rules           = ["203.0.113.0/24"]\n  bypass             = ["AzureServices"]\n}`,
        impactNotice: `Verify all authorized workloads, Azure functions, and build pipelines have appropriate firewall exceptions.`,
      },
      detectedAt: now,
    });
  }

  // 6. Medium: Shared Access Key Authentication Permitted
  if (account.allowSharedKeyAccess) {
    findings.push({
      id: `SEC-STOR-${account.name}-SHARED-KEY`,
      title: `Shared Access Key (Account Key) Authentication Permitted on '${account.name}'`,
      category: 'storage',
      severity: 'MEDIUM',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage Account Keys grant uncurated full root access to all data and control operations in '${account.name}'. Permitting SharedKey access prevents fine-grained Entra ID RBAC authorization and audit trails.`,
      exploitScenario: `A developer accidentally commits the primary account key to a Git repository or environment variable, allowing immediate full takeover without MFA or identity logging.`,
      businessImpact: `Unrestricted data access bypasses Entra ID conditional access, MFA, and PAM tools.`,
      compliance: {
        cisAzure: '3.11',
        mcsb: 'PA-1: Protect identity and access lifecycle',
        nist: 'AC-2, IA-2',
      },
      remediation: {
        summary: `Disable Shared Key access to mandate Azure Active Directory / Entra ID RBAC authentication.`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --allow-shared-key-access false`,
        portalSteps: [
          `Go to Storage Account '${account.name}' > 'Configuration'.`,
          `Set 'Allow storage account key access' to 'Disabled'.`,
          `Save changes.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  shared_access_key_enabled = false\n}`,
        impactNotice: `Applications must authenticate using Managed Identities (system-assigned or user-assigned) or Service Principals with Entra ID.`,
      },
      detectedAt: now,
    });
  }

  // 7. Medium: Soft Delete Disabled
  if (!account.softDeleteEnabled) {
    findings.push({
      id: `SEC-STOR-${account.name}-NO-SOFT-DELETE`,
      title: `Blob Soft Delete Disabled on '${account.name}'`,
      category: 'storage',
      severity: 'MEDIUM',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Soft delete for blobs is disabled. Deleted blobs or containers are permanently expunged immediately without any retention recovery window.`,
      exploitScenario: `Ransomware or a rogue insider issues recursive delete commands on blobs. Without soft delete, recovery is impossible without offline cold backups.`,
      businessImpact: `Catastrophic permanent data loss and business downtime.`,
      compliance: {
        cisAzure: '3.9',
        cisTitle: 'Ensure soft delete is enabled for Azure Storage',
        mcsb: 'BR-1: Ensure regular automated backups',
        nist: 'CP-9: Information System Backup',
      },
      remediation: {
        summary: `Enable Blob Soft Delete with a minimum retention period of 14-30 days.`,
        cliCommand: `az storage blob service-properties delete-policy update \\\n  --account-name "${account.name}" \\\n  --enable true \\\n  --days-retained 30 \\\n  --auth-mode login`,
        portalSteps: [
          `Go to Storage Account '${account.name}' > 'Data protection'.`,
          `Check 'Enable soft delete for blobs' and specify retention days (e.g. 30 days).`,
          `Check 'Enable soft delete for containers'.`,
          `Click 'Save'.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  blob_properties {\n    delete_retention_policy {\n      days = 30\n    }\n  }\n}`,
        impactNotice: `Slight increase in storage costs for retaining deleted data during the retention window.`,
      },
      detectedAt: now,
    });
  }

  // 8. Medium: Logging / Diagnostics Missing
  if (!account.loggingEnabled) {
    findings.push({
      id: `SEC-STOR-${account.name}-NO-LOGGING`,
      title: `Diagnostic Logging Not Configured for '${account.name}'`,
      category: 'storage',
      severity: 'MEDIUM',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage read/write/delete operations are not routed to Azure Log Analytics or Azure Monitor. Security teams cannot detect abnormal access patterns or investigate breaches.`,
      exploitScenario: `An adversary performs stealthy data exfiltration or changes container permissions without generating security telemetry for SOC teams.`,
      businessImpact: `Failure to satisfy incident response and audit compliance obligations.`,
      compliance: {
        cisAzure: '5.1',
        mcsb: 'LT-1: Enable threat detection capabilities',
        nist: 'AU-2, AU-3, AU-6',
      },
      remediation: {
        summary: `Configure Diagnostic Settings to send StorageRead, StorageWrite, and StorageDelete logs to a central Log Analytics workspace.`,
        cliCommand: `az monitor diagnostic-settings create \\\n  --name "StorageSecurityLogs" \\\n  --resource "${account.id}/blobServices/default" \\\n  --workspace "/subscriptions/${account.subscriptionId}/resourceGroups/${account.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/central-soc-law" \\\n  --logs '[{"category": "StorageRead","enabled": true},{"category": "StorageWrite","enabled": true},{"category": "StorageDelete","enabled": true}]'`,
        portalSteps: [
          `Go to Storage Account '${account.name}' > 'Diagnostic settings'.`,
          `Click 'Add diagnostic setting'.`,
          `Select 'StorageRead', 'StorageWrite', 'StorageDelete'.`,
          `Target a Log Analytics Workspace or Event Hub.`,
        ],
        terraformSnippet: `resource "azurerm_monitor_diagnostic_setting" "storage_diag" {\n  name               = "storage-audit"\n  target_resource_id = "\${azurerm_storage_account.${account.name}.id}/blobServices/default"\n  log_analytics_workspace_id = var.law_id\n  # ...\n}`,
        impactNotice: `Minimal Log Analytics ingestion cost.`,
      },
      detectedAt: now,
    });
  }

  return findings;
}

export function auditRbacAssignment(assignment: RbacAssignment): Finding[] {
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  // 1. Critical: Subscription or Root-level 'Owner' Assignment
  const isSubscriptionScope = assignment.scope.startsWith('/subscriptions/') && !assignment.scope.includes('/resourceGroups/');
  if (assignment.roleDefinitionName === 'Owner' && isSubscriptionScope) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-SUB-OWNER`,
      title: `Overly Permissive 'Owner' Role at Subscription Scope (${assignment.principalName})`,
      category: 'rbac',
      severity: 'CRITICAL',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleAssignment',
      description: `Identity '${assignment.principalName}' (${assignment.principalType}) is assigned full 'Owner' privileges at the subscription level. This grants unrestricted control over all cloud resources, IAM permissions, billing, and security settings across the entire subscription.`,
      exploitScenario: `If this identity's credentials or access token are compromised, the attacker has complete administrative dominion: they can disable security tools, exfiltrate data from all storage accounts, create backdoors, and delete resources.`,
      businessImpact: `Total cloud infrastructure compromise, ransomware deployment, uninhibited lateral movement.`,
      compliance: {
        cisAzure: '1.23',
        cisTitle: 'Ensure that no more than 3 owners are assigned to your subscription',
        mcsb: 'PA-1: Limit administrative privilege',
        nist: 'AC-6: Least Privilege',
      },
      remediation: {
        summary: `Demote this standing Owner assignment. Use Azure Privileged Identity Management (PIM) for Just-In-Time (JIT) elevation with approval and MFA, or scope permissions down to specific Resource Groups.`,
        cliCommand: `az role assignment delete \\\n  --assignee "${assignment.principalId}" \\\n  --role "Owner" \\\n  --scope "${assignment.scope}"`,
        portalSteps: [
          `Go to Azure Portal > Subscriptions > select subscription.`,
          `Select 'Access control (IAM)' > 'Role assignments'.`,
          `Filter by Role: 'Owner'.`,
          `Select the assignment for '${assignment.principalName}' and click 'Remove'.`,
          `Re-assign least-privileged role (e.g. Contributor or Reader) at the specific Resource Group.`,
        ],
        terraformSnippet: `# Remove broad subscription assignment and use scoped resource group assignment\nresource "azurerm_role_assignment" "scoped_assignment" {\n  scope                = azurerm_resource_group.rg.id\n  role_definition_name = "Contributor"\n  principal_id         = "${assignment.principalId}"\n}`,
        impactNotice: `User will need to activate PIM role or request scoped permissions for maintenance tasks.`,
      },
      detectedAt: now,
    });
  }

  // 2. Critical: External / Guest User with Elevated Privileges
  if (assignment.isExternalGuest && (assignment.roleDefinitionName === 'Owner' || assignment.roleDefinitionName === 'Contributor' || assignment.roleDefinitionName.includes('Admin'))) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-GUEST-ELEVATED`,
      title: `External Guest Account Has High-Privilege Role '${assignment.roleDefinitionName}' (${assignment.principalName})`,
      category: 'rbac',
      severity: 'CRITICAL',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleAssignment',
      description: `External B2B guest user '${assignment.principalName}' has been granted '${assignment.roleDefinitionName}'. External guest identities are managed in foreign Entra ID tenants, meaning your security team cannot enforce password policies, revoke MFA tokens, or detect credential compromise in their home tenant.`,
      exploitScenario: `A compromise in the vendor or partner company's identity provider automatically compromises your Azure production environment with elevated privileges.`,
      businessImpact: `Third-party vendor supply chain breach; unmanaged external access to sensitive internal storage and compute.`,
      compliance: {
        cisAzure: '1.3',
        cisTitle: 'Ensure external accounts with administrative privileges are removed',
        mcsb: 'PA-1: Protect identity lifecycle',
        nist: 'AC-2, AC-3',
      },
      remediation: {
        summary: `Remove external guest administrative role assignments immediately. Require external partners to use managed internal corporate accounts with corporate MFA, or restrict to read-only roles.`,
        cliCommand: `az role assignment delete \\\n  --assignee "${assignment.principalId}" \\\n  --role "${assignment.roleDefinitionName}" \\\n  --scope "${assignment.scope}"`,
        portalSteps: [
          `Navigate to Access Control (IAM) at '${assignment.scope}'.`,
          `Locate external user '${assignment.principalName}' (marked #EXT#).`,
          `Click 'Remove' to revoke the '${assignment.roleDefinitionName}' role.`,
        ],
        terraformSnippet: `# Delete or exclude external principal IDs from elevated role assignment definitions`,
        impactNotice: `Vendor will need to coordinate through an internal sponsor or designated non-privileged interface.`,
      },
      detectedAt: now,
    });
  }

  // 3. Critical: Privilege Escalation Loophole via 'roleAssignments/write'
  const hasRoleAssignmentWrite = assignment.actions.some(
    (action) =>
      action === '*' ||
      action === 'Microsoft.Authorization/*' ||
      action === 'Microsoft.Authorization/roleAssignments/write' ||
      action === 'Microsoft.Authorization/roleAssignments/*'
  );

  if (hasRoleAssignmentWrite && assignment.roleDefinitionName !== 'Owner') {
    findings.push({
      id: `SEC-ESC-${assignment.id}-PRIV-ESCALATION`,
      title: `Privilege Escalation Vulnerability: 'roleAssignments/write' Permitted for '${assignment.principalName}'`,
      category: 'privilege_escalation',
      severity: 'CRITICAL',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleDefinition',
      description: `Identity '${assignment.principalName}' holds '${assignment.roleDefinitionName}', which contains 'Microsoft.Authorization/roleAssignments/write' permission. This allows this non-Owner principal to grant themselves or another entity 'Owner' or 'Storage Blob Data Owner' privileges, effectively bypassing all role limitations.`,
      exploitScenario: `An attacker compromising this identity executes 'az role assignment create --role Owner --assignee <attacker-id>'. The principal escalates from an operator or custom role to a full subscription Administrator.`,
      businessImpact: `Complete authorization bypass, persistent backdoors created without approval, unconstrained administrative takeover.`,
      compliance: {
        cisAzure: '1.24',
        mcsb: 'PA-7: Prevent privilege escalation',
        nist: 'AC-6: Least privilege',
      },
      remediation: {
        summary: `Revoke 'Microsoft.Authorization/roleAssignments/write' from custom roles. Only dedicated Identity Governance / PIM systems should be able to create role assignments.`,
        cliCommand: `az role definition update --role-definition '{ "Name": "${assignment.roleDefinitionName}", "NotActions": ["Microsoft.Authorization/roleAssignments/*"] }'`,
        portalSteps: [
          `Go to Azure Portal > Subscriptions > 'Access control (IAM)' > 'Roles'.`,
          `Select '${assignment.roleDefinitionName}' and click 'Edit'.`,
          `Under 'Permissions', remove 'Microsoft.Authorization/roleAssignments/*' or add it to 'NotActions'.`,
          `Save the role definition.`,
        ],
        terraformSnippet: `resource "azurerm_role_definition" "custom_role" {\n  name        = "${assignment.roleDefinitionName}"\n  scope       = "/subscriptions/..."\n  # ...\n  not_actions = [\n    "Microsoft.Authorization/roleAssignments/*",\n    "Microsoft.Authorization/elevateAccess/Action"\n  ]\n}`,
        impactNotice: `The principal will no longer be able to delegate roles to other accounts.`,
      },
      privilegeEscalationPath: `Principal '${assignment.principalName}' -> Microsoft.Authorization/roleAssignments/write -> Self-assign 'Owner' -> Full Control`,
      detectedAt: now,
    });
  }

  // 4. High: Service Principal with High-Privilege Wildcard Permissions
  if (assignment.principalType === 'ServicePrincipal' && (assignment.roleDefinitionName === 'Owner' || assignment.actions.includes('*'))) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-SP-OVERPRIVILEGED`,
      title: `Overprivileged Non-Human Service Principal '${assignment.principalName}'`,
      category: 'rbac',
      severity: 'HIGH',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleAssignment',
      description: `Automated Service Principal '${assignment.principalName}' has been assigned broad wildcard administrative privileges. Machine identities are frequently targeted in CI/CD pipelines, container secrets, and key vaults.`,
      exploitScenario: `CI/CD pipeline logs or code repo leaks the Client Secret / Certificate of '${assignment.principalName}'. Attackers leverage the secret to access Azure management APIs with unthrottled access.`,
      businessImpact: `Compromised automation pipelines leading to malicious infrastructure provisioning or mass data wiping.`,
      compliance: {
        cisAzure: '1.20',
        mcsb: 'PA-2: Protect non-human identities',
        nist: 'IA-2, AC-6',
      },
      remediation: {
        summary: `Scope the service principal to a custom role containing only the exact APIs needed (e.g. deployment of specific resources), and enforce workload identity federation rather than static secrets.`,
        cliCommand: `az role assignment delete --assignee "${assignment.principalId}" --role "${assignment.roleDefinitionName}" --scope "${assignment.scope}"`,
        portalSteps: [
          `Navigate to Azure Entra ID > App Registrations > '${assignment.principalName}'.`,
          `Audit its API permissions and assigned roles.`,
          `Replace standing subscription Owner role with workload-specific Resource Group roles.`,
        ],
        terraformSnippet: `# Restrict service principal to specific resource group\nresource "azurerm_role_assignment" "sp_restricted" {\n  scope                = azurerm_resource_group.rg.id\n  role_definition_name = "Reader"\n  principal_id         = "${assignment.principalId}"\n}`,
        impactNotice: `Automated pipelines may fail if they rely on undeclared permissions; test thoroughly in staging.`,
      },
      detectedAt: now,
    });
  }

  // 5. Medium / High: Inactive / Dormant Role Assignment (> 90 days)
  if (assignment.lastActiveDays > 90) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-DORMANT`,
      title: `Inactive / Stale Role Assignment: '${assignment.principalName}' Inactive for ${assignment.lastActiveDays} Days`,
      category: 'rbac',
      severity: assignment.lastActiveDays > 180 ? 'HIGH' : 'MEDIUM',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleAssignment',
      description: `Account '${assignment.principalName}' holds active role '${assignment.roleDefinitionName}' but has not authenticated or performed actions in the tenant for ${assignment.lastActiveDays} days. Stale elevated accounts represent abandoned attack surface.`,
      exploitScenario: `A former employee or departed contractor's dormant account is left active; an attacker who buys leaked credentials on dark web marketplaces logs in unnoticed because normal activity baselines are missing.`,
      businessImpact: `Zombie credentials granting unauthorized access into company cloud environment.`,
      compliance: {
        cisAzure: '1.10',
        cisTitle: 'Ensure inactive accounts are disabled or role assignments revoked',
        mcsb: 'PA-1: Review and reconcile identity access regularly',
        nist: 'AC-2: Account Management',
      },
      remediation: {
        summary: `Revoke the dormant role assignment and configure Entra ID Access Reviews to automatically disable or unassign stale accounts.`,
        cliCommand: `az role assignment delete \\\n  --assignee "${assignment.principalId}" \\\n  --role "${assignment.roleDefinitionName}" \\\n  --scope "${assignment.scope}"`,
        portalSteps: [
          `Go to Entra ID > Users > Check sign-in logs for '${assignment.principalName}'.`,
          `Remove role assignment under Access control (IAM).`,
          `Disable the user account in Entra ID if the employee has departed.`,
        ],
        terraformSnippet: `# Automate access reviews using Azure AD PIM or identity governance policies`,
        impactNotice: `The user must submit an IT ticket or request re-provisioning if they return to active duties.`,
      },
      detectedAt: now,
    });
  }

  // 6. High: Privileged Role without MFA Enforcement
  if (!assignment.mfaEnforced && (assignment.roleDefinitionName === 'Owner' || assignment.roleDefinitionName === 'Contributor' || assignment.roleDefinitionName.includes('Admin'))) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-NO-MFA`,
      title: `MFA Not Enforced for Privileged Identity '${assignment.principalName}'`,
      category: 'rbac',
      severity: 'HIGH',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'IAM',
      description: `Identity '${assignment.principalName}' holds elevated role '${assignment.roleDefinitionName}' but is not subject to a strict Multi-Factor Authentication (MFA) Conditional Access Policy.`,
      exploitScenario: `Phishing, password spray, or credential stuffing attacks against this account allow direct login without a second-factor challenge.`,
      businessImpact: `Single-factor compromise leading directly to cloud tenant administrative takeover.`,
      compliance: {
        cisAzure: '1.1',
        cisTitle: 'Ensure that multi-factor authentication is enabled for all privileged users',
        mcsb: 'PA-4: Enforce MFA for privileged users',
        nist: 'IA-2: Identification and Authentication',
      },
      remediation: {
        summary: `Enforce Conditional Access Policy requiring Phishing-resistant MFA (FIDO2 or Microsoft Authenticator) for all Azure Management access.`,
        cliCommand: `# Azure CLI to audit Conditional Access Policy compliance:\naz rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"`,
        portalSteps: [
          `Navigate to Entra ID > 'Security' > 'Conditional Access'.`,
          `Create or update policy 'Require MFA for Azure Management'.`,
          `Include all users with Directory Roles or Subscription Roles.`,
          `Grant Access: 'Require multifactor authentication' or 'Require authentication strength'.`,
        ],
        terraformSnippet: `resource "azuread_conditional_access_policy" "require_mfa" {\n  display_name = "Require MFA for Azure Management"\n  state        = "enabled"\n  # ...\n}`,
        impactNotice: `The user will be prompted to register and verify MFA during their next interactive sign-in.`,
      },
      detectedAt: now,
    });
  }

  return findings;
}

export function executeFullAudit(
  storageAccounts: StorageAccount[],
  roleAssignments: RbacAssignment[]
): { findings: Finding[]; metrics: AuditMetrics } {
  const allFindings: Finding[] = [];

  for (const account of storageAccounts) {
    allFindings.push(...auditStorageAccount(account));
  }

  for (const assignment of roleAssignments) {
    allFindings.push(...auditRbacAssignment(assignment));
  }

  const totalResources =
    storageAccounts.length +
    storageAccounts.reduce((acc, curr) => acc + curr.containers.length, 0) +
    roleAssignments.length;

  const criticalCount = allFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = allFindings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = allFindings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = allFindings.filter((f) => f.severity === 'LOW').length;

  const storageFindingCount = allFindings.filter((f) => f.category === 'storage').length;
  const rbacFindingCount = allFindings.filter((f) => f.category === 'rbac').length;
  const privilegeEscalationCount = allFindings.filter((f) => f.category === 'privilege_escalation').length;
  const inactiveRoleCount = allFindings.filter((f) => f.id.includes('DORMANT')).length;
  const openBucketCount = allFindings.filter(
    (f) => f.id.includes('PUB-ACCESS') || f.id.includes('EXPOSED')
  ).length;

  // Posture Score calculation (Starts at 100, drops with severity)
  let penalty =
    criticalCount * 22 +
    highCount * 10 +
    mediumCount * 4 +
    lowCount * 1;

  let postureScore = Math.max(0, Math.min(100, Math.round(100 - penalty)));

  let riskGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'A+';
  if (postureScore >= 95) riskGrade = 'A+';
  else if (postureScore >= 85) riskGrade = 'A';
  else if (postureScore >= 70) riskGrade = 'B';
  else if (postureScore >= 55) riskGrade = 'C';
  else if (postureScore >= 40) riskGrade = 'D';
  else riskGrade = 'F';

  // Compliance scores based on pass rates
  const cisPassRate = Math.max(15, Math.round(100 - (criticalCount * 18 + highCount * 8)));
  const mcsbPassRate = Math.max(20, Math.round(100 - (criticalCount * 15 + highCount * 7 + mediumCount * 2)));
  const nistPassRate = Math.max(18, Math.round(100 - (criticalCount * 16 + highCount * 7)));

  const metrics: AuditMetrics = {
    totalResources,
    totalFindings: allFindings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    postureScore,
    riskGrade,
    storageFindingCount,
    rbacFindingCount,
    privilegeEscalationCount,
    inactiveRoleCount,
    openBucketCount,
    complianceScores: {
      cisAzure: Math.min(100, cisPassRate),
      mcsb: Math.min(100, mcsbPassRate),
      nist: Math.min(100, nistPassRate),
    },
  };

  return { findings: allFindings, metrics };
}
