/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  AuditMetrics,
  Finding,
  RbacAssignment,
  StorageAccount,
  StorageContainer,
} from '../types/security';

export function auditStorageAccount(account: StorageAccount): Finding[] {
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  const publicContainers = account.containers.filter(
    (c) => c.publicAccess !== 'None'
  );
  const hasEffectivePublicContainers =
    account.allowBlobPublicAccess && publicContainers.length > 0;

  // 1. Account-level anonymous access setting (Recommendation #10: distinguish guardrail gap from confirmed exposure)
  if (account.allowBlobPublicAccess) {
    findings.push({
      id: `SEC-STOR-${account.name}-PUB-ACCESS`,
      title: hasEffectivePublicContainers
        ? `Account-Level Anonymous Blob Access Enabled on '${account.name}' (${publicContainers.length} Public Container(s) Active)`
        : `Account-Level Anonymous Blob Access Guardrail Enabled on '${account.name}' (Guardrail Gap — 0 Public Containers Confirmed)`,
      category: 'storage',
      severity: 'CRITICAL',
      findingType: hasEffectivePublicContainers
        ? 'confirmed_exposure'
        : 'guardrail_gap',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: hasEffectivePublicContainers
        ? `Storage account '${account.name}' has allowBlobPublicAccess=true AND contains ${publicContainers.length} container(s) configured with publicAccess !== 'None' (${publicContainers.map((c) => c.name).join(', ')}). Effective anonymous access is active.`
        : `Guardrail Gap Notice: Storage account '${account.name}' has allowBlobPublicAccess=true at the account configuration level, but 0 inspected containers currently have publicAccess enabled (or container list was not returned). This does not confirm active anonymous data exposure on its own, but lacks the account-wide guardrail that prevents future containers from being made public.`,
      exploitScenario: hasEffectivePublicContainers
        ? `Unauthenticated callers can read or list blobs in exposed containers (${publicContainers.map((c) => c.name).join(', ')}) because both account-level and container-level settings permit anonymous access.`
        : `While existing private containers block anonymous requests, any principal with Storage Account Contributor or Blob Data Owner permissions could set a container's publicAccess level to 'Blob' or 'Container' unless the account-level guardrail is disabled.`,
      businessImpact: `Potential unauthorized data disclosure if container-level ACLs are misconfigured; disabling allowBlobPublicAccess enforces a tenant-wide preventative guardrail.`,
      compliance: {
        cisAzure: '3.7',
        cisTitle: 'Ensure that "Allow Blob anonymous access" is set to Disabled',
        mcsb: 'DP-2: Protect sensitive data',
        nist: 'AC-3, AC-4',
        iso27001: 'A.9.4.1',
      },
      remediation: {
        summary: `Disable allowBlobPublicAccess at the storage account level after verifying that no production workloads depend on unauthenticated static asset URLs.`,
        preCheckCommand: `az storage account show --name "${account.name}" --resource-group "${account.resourceGroup}" --query "{allowBlobPublicAccess:allowBlobPublicAccess}" -o json`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --allow-blob-public-access false`,
        rollbackCommand: `az storage account update --name "${account.name}" --resource-group "${account.resourceGroup}" --allow-blob-public-access true`,
        portalSteps: [
          `Verify in Azure Monitor / Storage logs that no legitimate unauthenticated clients read blobs from '${account.name}'.`,
          `Navigate to Azure Portal > Storage Accounts > select '${account.name}'.`,
          `Under 'Settings', select 'Configuration'.`,
          `Set 'Allow Blob anonymous access' to 'Disabled' and click 'Save'.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  name                            = "${account.name}"\n  resource_group_name             = "${account.resourceGroup}"\n  location                        = "${account.location}"\n  account_tier                    = "Standard"\n  account_replication_type        = "GRS"\n  allow_nested_items_to_be_public = false\n}`,
        bicepSnippet: `resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: '${account.name}'\n  location: '${account.location}'\n  properties: {\n    allowBlobPublicAccess: false\n  }\n}`,
        impactNotice: `Review workload impact before applying in production: any public-facing static assets served directly from blob URLs will return HTTP 403/409 unlessfronted by Azure Front Door/CDN with managed identity or SAS.`,
      },
      detectedAt: now,
    });
  }

  // 2. Container-level anonymous access & SAS policy checks
  account.containers.forEach((container: StorageContainer) => {
    if (container.publicAccess !== 'None') {
      const isFullContainer = container.publicAccess === 'Container';
      const isEffectivelyExposed = account.allowBlobPublicAccess !== false;

      findings.push({
        id: `SEC-CONT-${account.name}-${container.name}-EXPOSED`,
        title: isEffectivelyExposed
          ? `Confirmed Anonymous Access Open on Container '${container.name}' (${container.publicAccess})`
          : `Container '${container.name}' Configured as '${container.publicAccess}' (Currently Blocked by Account Guardrail)`,
        category: 'storage',
        severity: isEffectivelyExposed ? 'CRITICAL' : 'MEDIUM',
        findingType: isEffectivelyExposed ? 'confirmed_exposure' : 'guardrail_gap',
        resourceId: `${account.id}/containers/${container.name}`,
        resourceName: `${account.name}/${container.name}`,
        resourceType: 'StorageContainer',
        description: isEffectivelyExposed
          ? `Confirmed Exposure: Container '${container.name}' has publicAccess='${container.publicAccess}' AND parent storage account '${account.name}' permits public blob access. ${
              isFullContainer
                ? 'Unauthenticated users can enumerate and download all blobs in this container.'
                : 'Unauthenticated users can read blobs by URL without credentials.'
            }`
          : `Container '${container.name}' has its container ACL set to '${container.publicAccess}', though anonymous access is currently overridden by allowBlobPublicAccess=false on '${account.name}'. Set the container ACL to 'None' so re-enabling the account setting does not expose data.`,
        exploitScenario: `Unauthenticated HTTP GET requests against https://${account.name}.blob.core.windows.net/${container.name} can read or list stored objects when both account and container public access are enabled.`,
        businessImpact: `Potential unauthenticated disclosure of container contents (${container.dataClassification || 'Internal'}).`,
        compliance: {
          cisAzure: '3.7',
          cisTitle: 'Ensure container public access level is set to Private',
          mcsb: 'DP-2: Protect sensitive data',
          nist: 'AC-3, SC-7',
        },
        remediation: {
          summary: `Set container '${container.name}' public access level to 'Private' (off) after validating client authentication requirements.`,
          preCheckCommand: `az storage container show-permission --account-name "${account.name}" --name "${container.name}" --auth-mode login -o json`,
          cliCommand: `az storage container set-permission \\\n  --account-name "${account.name}" \\\n  --name "${container.name}" \\\n  --public-access off \\\n  --auth-mode login`,
          rollbackCommand: `az storage container set-permission --account-name "${account.name}" --name "${container.name}" --public-access ${container.publicAccess.toLowerCase()} --auth-mode login`,
          portalSteps: [
            `Navigate to Storage Accounts > '${account.name}' > Containers.`,
            `Select container '${container.name}' > 'Change access level'.`,
            `Select 'Private (no anonymous access)' and click OK.`,
          ],
          terraformSnippet: `resource "azurerm_storage_container" "${container.name}" {\n  name                  = "${container.name}"\n  storage_account_name  = "${account.name}"\n  container_access_type = "private"\n}`,
          impactNotice: `Ensure authorized applications authenticate via Entra ID RBAC or scoped SAS tokens before revoking anonymous container access.`,
        },
        detectedAt: now,
      });
    }

    // SAS / Access Policy check
    if (container.hasStoredAccessPolicyWithNoExpiry) {
      findings.push({
        id: `SEC-SAS-${account.name}-${container.name}-INFINITE`,
        title: `Indefinite Stored Access Policy on Container '${container.name}'`,
        category: 'storage',
        severity: 'HIGH',
        findingType: 'configuration_hardening',
        resourceId: `${account.id}/containers/${container.name}/policies`,
        resourceName: `${account.name}/${container.name}`,
        resourceType: 'StorageContainer',
        description: `A Stored Access Policy on container '${container.name}' has no expiration timestamp. SAS tokens bound to this policy remain valid indefinitely unless the policy is updated or deleted.`,
        exploitScenario: `If a SAS URL backed by an non-expiring stored access policy is leaked in source control or logs, external callers retain access until manual policy rotation.`,
        businessImpact: `Long-lived bearer credentials increase the window of unauthorized storage access.`,
        compliance: {
          cisAzure: '3.10',
          mcsb: 'PA-3: Review and manage authorization policies',
          nist: 'AC-2, IA-5',
        },
        remediation: {
          summary: `Configure a bounded expiration timestamp on stored access policies or transition clients to Entra ID user-delegation SAS tokens.`,
          preCheckCommand: `az storage container policy list --account-name "${account.name}" --container-name "${container.name}" --auth-mode login -o json`,
          cliCommand: `az storage container policy update \\\n  --account-name "${account.name}" \\\n  --container-name "${container.name}" \\\n  --name "legacy-policy" \\\n  --expiry $(date -u -d "+7 days" +%Y-%m-%dT%H:%M:%SZ) \\\n  --auth-mode login`,
          portalSteps: [
            `Go to Container '${container.name}' > 'Access policy'.`,
            `Inspect active stored access policies, coordinate token rotation with application owners, and set an expiry timestamp.`,
          ],
          terraformSnippet: `# Replace non-expiring stored access policies with time-bounded user delegation SAS`,
          impactNotice: `Modifying or deleting a stored access policy immediately invalidates existing SAS tokens bound to that policy identifier. Validate in staging first.`,
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
      findingType: 'configuration_hardening',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' has supportsHttpsTrafficOnly=false, permitting unencrypted HTTP requests over port 80.`,
      exploitScenario: `Network eavesdroppers on untrusted links can intercept plaintext HTTP requests, SAS tokens, or blob payloads in transit.`,
      businessImpact: `Data in transit lacks cryptographic transport protection.`,
      compliance: {
        cisAzure: '3.1',
        cisTitle: 'Ensure that "Secure transfer required" is set to "Enabled"',
        mcsb: 'DP-4: Encrypt sensitive data in transit',
        nist: 'SC-8, SC-13',
        iso27001: 'A.10.1.1',
      },
      remediation: {
        summary: `Enable 'Secure transfer required' so Azure Storage rejects plaintext HTTP connections.`,
        preCheckCommand: `az storage account show --name "${account.name}" --resource-group "${account.resourceGroup}" --query supportsHttpsTrafficOnly -o tsv`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --https-only true`,
        rollbackCommand: `az storage account update --name "${account.name}" --resource-group "${account.resourceGroup}" --https-only false`,
        portalSteps: [
          `Go to Storage Account > '${account.name}' > 'Configuration'.`,
          `Set 'Secure transfer required' to 'Enabled' and click 'Save'.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  enable_https_traffic_only = true\n}`,
        impactNotice: `Legacy clients using 'http://' endpoints or SMB without encryption will be rejected until updated to HTTPS / SMB 3.0+.`,
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
      findingType: 'configuration_hardening',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' permits connections negotiated with deprecated transport protocol ${account.minimumTlsVersion}.`,
      exploitScenario: `Clients negotiating TLS 1.0 or 1.1 use weaker cipher suites that do not meet modern cryptographic transport baselines.`,
      businessImpact: `Misalignment with TLS 1.2+ transport security requirements.`,
      compliance: {
        cisAzure: '3.8',
        cisTitle: 'Ensure that "Minimum TLS version" is set to "Version 1.2"',
        mcsb: 'DP-4: Encrypt data in transit',
        nist: 'SC-8',
      },
      remediation: {
        summary: `Set minimumTlsVersion to TLS1_2 after checking Azure Storage diagnostic logs for legacy TLS client handshakes.`,
        preCheckCommand: `az storage account show --name "${account.name}" --resource-group "${account.resourceGroup}" --query minimumTlsVersion -o tsv`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --min-tls-version TLS1_2`,
        rollbackCommand: `az storage account update --name "${account.name}" --resource-group "${account.resourceGroup}" --min-tls-version ${account.minimumTlsVersion}`,
        portalSteps: [
          `Open Storage Account '${account.name}' > 'Configuration'.`,
          `Set 'Minimum TLS version' to 'Version 1.2' and click 'Save'.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  min_tls_version = "TLS1_2"\n}`,
        impactNotice: `Older SDKs or OS runtimes that do not support TLS 1.2 will fail TLS handshakes until upgraded.`,
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
      title: `Storage Account Network Perimeter Open to All Networks (${account.name})`,
      category: 'network',
      severity: 'HIGH',
      findingType: 'guardrail_gap',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' has publicNetworkAccess='Enabled' and networkAcls.defaultAction='Allow' with 0 IP rules, 0 VNet rules, and 0 Private Endpoints. Note: Authentication is still required for private containers, but the network endpoint is reachable from any public IP.`,
      exploitScenario: `Any internet host can reach the storage data-plane endpoint directly without network-layer filtering.`,
      businessImpact: `Absence of network-level perimeter segmentation.`,
      compliance: {
        cisAzure: '3.6',
        cisTitle: 'Ensure default network access rule for Storage Accounts is set to deny',
        mcsb: 'NS-2: Connect private networks together',
        nist: 'SC-7: Boundary Protection',
      },
      remediation: {
        summary: `Whitelist authorized VNet subnets, Private Endpoints, and egress IP ranges BEFORE changing defaultAction to Deny.`,
        preCheckCommand: `az storage account show --name "${account.name}" --resource-group "${account.resourceGroup}" --query networkRuleSet -o json`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --default-action Deny`,
        rollbackCommand: `az storage account update --name "${account.name}" --resource-group "${account.resourceGroup}" --default-action Allow`,
        portalSteps: [
          `Inventory all VNet subnets, IP ranges, and Azure services that connect to '${account.name}'.`,
          `Go to Storage Account '${account.name}' > 'Networking'.`,
          `Add required Virtual Networks and IP CIDR ranges first, then select 'Enabled from selected virtual networks and IP addresses'.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account_network_rules" "rules" {\n  storage_account_id = azurerm_storage_account.${account.name}.id\n  default_action     = "Deny"\n  ip_rules           = ["203.0.113.0/24"]\n  bypass             = ["AzureServices"]\n}`,
        impactNotice: `WARNING: Setting default-action to Deny without first adding your workload VNet/IP rules will immediately block network connectivity for unlisted clients.`,
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
      findingType: 'configuration_hardening',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' allows SharedKey (storage account key) authentication in addition to Microsoft Entra ID.`,
      exploitScenario: `Shared account keys grant full administrative data-plane access and bypass per-user Entra ID Conditional Access policies.`,
      businessImpact: `Reduced identity-level attribution if shared keys are used instead of Entra ID RBAC.`,
      compliance: {
        cisAzure: '3.11',
        mcsb: 'PA-1: Protect identity and access lifecycle',
        nist: 'AC-2, IA-2',
      },
      remediation: {
        summary: `Migrate workloads to Managed Identities / Entra ID RBAC first, then set allowSharedKeyAccess to false.`,
        preCheckCommand: `az storage account show --name "${account.name}" --resource-group "${account.resourceGroup}" --query allowSharedKeyAccess -o tsv`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --allow-shared-key-access false`,
        rollbackCommand: `az storage account update --name "${account.name}" --resource-group "${account.resourceGroup}" --allow-shared-key-access true`,
        portalSteps: [
          `Audit Azure Monitor logs to confirm no active services authenticate via SharedKey or account-key SAS.`,
          `Go to Storage Account '${account.name}' > 'Configuration'.`,
          `Set 'Allow storage account key access' to 'Disabled' and save.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  shared_access_key_enabled = false\n}`,
        impactNotice: `Any application or script still using connection strings with AccountKey=... will immediately fail authentication until migrated to Entra ID.`,
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
      findingType: 'configuration_hardening',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Soft delete for blobs is not enabled on '${account.name}', reducing recoverability if blobs are accidentally or maliciously deleted.`,
      exploitScenario: `Accidental or unauthorized delete operations permanently remove blobs without a retention recovery period.`,
      businessImpact: `Increased recovery time objective (RTO) in the event of accidental deletion.`,
      compliance: {
        cisAzure: '3.9',
        cisTitle: 'Ensure soft delete is enabled for Azure Storage',
        mcsb: 'BR-1: Ensure regular automated backups',
        nist: 'CP-9: Information System Backup',
      },
      remediation: {
        summary: `Enable Blob Soft Delete with an organizationally approved retention period (e.g., 14–30 days).`,
        cliCommand: `az storage blob service-properties delete-policy update \\\n  --account-name "${account.name}" \\\n  --enable true \\\n  --days-retained 30 \\\n  --auth-mode login`,
        rollbackCommand: `az storage blob service-properties delete-policy update --account-name "${account.name}" --enable false --auth-mode login`,
        portalSteps: [
          `Go to Storage Account '${account.name}' > 'Data protection'.`,
          `Enable soft delete for blobs and containers with your target retention window.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  blob_properties {\n    delete_retention_policy {\n      days = 30\n    }\n  }\n}`,
        impactNotice: `Retained soft-deleted blobs incur standard storage capacity charges during the retention period.`,
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
      findingType: 'configuration_hardening',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Diagnostic read/write/delete logging for '${account.name}' was not detected in the inspected properties.`,
      exploitScenario: `Data-plane operations may lack centralized audit logs for forensic investigation.`,
      businessImpact: `Reduced visibility during security incident response.`,
      compliance: {
        cisAzure: '5.1',
        mcsb: 'LT-1: Enable threat detection capabilities',
        nist: 'AU-2, AU-3, AU-6',
      },
      remediation: {
        summary: `Configure Azure Monitor Diagnostic Settings to forward StorageRead, StorageWrite, and StorageDelete logs to Log Analytics.`,
        cliCommand: `az monitor diagnostic-settings create \\\n  --name "StorageSecurityLogs" \\\n  --resource "${account.id}/blobServices/default" \\\n  --workspace "/subscriptions/${account.subscriptionId}/resourceGroups/${account.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/central-soc-law" \\\n  --logs '[{"category": "StorageRead","enabled": true},{"category": "StorageWrite","enabled": true},{"category": "StorageDelete","enabled": true}]'`,
        portalSteps: [
          `Go to Storage Account '${account.name}' > 'Diagnostic settings' > 'blob'.`,
          `Add a diagnostic setting routing StorageRead, StorageWrite, and StorageDelete to your Log Analytics Workspace.`,
        ],
        terraformSnippet: `resource "azurerm_monitor_diagnostic_setting" "storage_diag" {\n  name                       = "storage-audit"\n  target_resource_id         = "\${azurerm_storage_account.${account.name}.id}/blobServices/default"\n  log_analytics_workspace_id = var.law_id\n}`,
        impactNotice: `High-volume storage accounts may generate significant Log Analytics ingestion volume; review pricing tiers first.`,
      },
      detectedAt: now,
    });
  }

  // 9. Medium: Microsoft Defender for Storage Disabled
  if (account.defenderForStorageEnabled === false) {
    findings.push({
      id: `SEC-STOR-${account.name}-NO-DEFENDER`,
      title: `Microsoft Defender for Storage Not Enabled on '${account.name}'`,
      category: 'storage',
      severity: 'MEDIUM',
      findingType: 'configuration_hardening',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Microsoft Defender for Storage is not enabled on '${account.name}'.`,
      exploitScenario: `Unusual data access patterns or malicious file uploads will not generate Defender for Storage alerts.`,
      businessImpact: `Absence of managed anomaly and malware detection on storage transactions.`,
      compliance: {
        cisAzure: '3.12',
        cisTitle: 'Ensure that Microsoft Defender for Storage is set to On',
        mcsb: 'LT-1: Threat Detection & Malware Protection',
        nist: 'SI-3, SI-4',
      },
      remediation: {
        summary: `Evaluate enabling Microsoft Defender for Storage on accounts storing sensitive or untrusted uploads.`,
        cliCommand: `az security atp storage update \\\n  --resource-group "${account.resourceGroup}" \\\n  --storage-account "${account.name}" \\\n  --is-enabled true`,
        rollbackCommand: `az security atp storage update --resource-group "${account.resourceGroup}" --storage-account "${account.name}" --is-enabled false`,
        portalSteps: [
          `Go to Storage Account '${account.name}' > 'Microsoft Defender for Cloud'.`,
          `Enable Microsoft Defender for Storage per your subscription security plan.`,
        ],
        terraformSnippet: `resource "azurerm_advanced_threat_protection" "threat_protection" {\n  target_resource_id = azurerm_storage_account.${account.name}.id\n  enabled            = true\n}`,
        impactNotice: `Incurs per-storage-account and transaction/malware-scanning charges under Microsoft Defender for Cloud.`,
      },
      detectedAt: now,
    });
  }

  // 10. Low: Customer-Managed Keys (Recommendation #11: State that Azure encrypts data at rest by default with MMK)
  if (!account.customerManagedKeyEnabled) {
    findings.push({
      id: `SEC-STOR-${account.name}-NO-CMK`,
      title: `Encrypted at Rest by Default (Microsoft-Managed Keys); Optional Customer-Managed Key (CMK) Not Configured on '${account.name}'`,
      category: 'encryption',
      severity: 'LOW',
      findingType: 'configuration_hardening',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Default Encryption Active: Azure Storage automatically encrypts all data at rest by default using 256-bit AES Microsoft-Managed Keys (MMK) on '${account.name}'. This low-priority advisory notes that optional Customer-Managed Keys (CMK) in Azure Key Vault are not configured. Missing CMK is NOT a lack of encryption; assess against your organization's documented key-management requirements.`,
      exploitScenario: `Data at rest IS encrypted by Microsoft-Managed Keys; however, organizations subject to strict BYOK/CMK policies may require direct control over key rotation and revocation in Azure Key Vault.`,
      businessImpact: `Informational/Governance check: only applicable if organizational or regulatory policy explicitly mandates Customer-Managed Keys (CMK) over default Microsoft-Managed Keys (MMK).`,
      compliance: {
        cisAzure: '3.5',
        cisTitle: 'Evaluate Customer-Managed Keys (CMK) where required by organizational policy',
        mcsb: 'DP-5: Use customer-managed key option in data at rest encryption when required',
        nist: 'SC-12, SC-28',
      },
      remediation: {
        summary: `No action needed if Microsoft-Managed Keys (MMK) satisfy your security policy. If organizational policy requires CMK, link an Azure Key Vault key with Soft Delete and Purge Protection enabled.`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --encryption-key-name "storage-master-key" \\\n  --encryption-key-vault "https://corp-vault.vault.azure.net" \\\n  --encryption-key-source "Microsoft.Keyvault"`,
        rollbackCommand: `az storage account update --name "${account.name}" --resource-group "${account.resourceGroup}" --encryption-key-source "Microsoft.Storage"`,
        portalSteps: [
          `Confirm whether organizational compliance policy requires Customer-Managed Keys (CMK) for '${account.name}'.`,
          `If required, navigate to Storage Account '${account.name}' > 'Encryption' > 'Customer-managed keys' and select a Key Vault key with Purge Protection enabled.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account_customer_managed_key" "cmk" {\n  storage_account_id = azurerm_storage_account.${account.name}.id\n  key_vault_id       = azurerm_key_vault.vault.id\n  key_name           = "storage-kek"\n}`,
        impactNotice: `If the linked Key Vault key is disabled or permissions are accidentally revoked, the storage account will become inaccessible.`,
      },
      detectedAt: now,
    });
  }

  // 11. Medium: Cross-Tenant Replication Scope Permissive
  if (account.crossTenantReplicationRestricted === false) {
    findings.push({
      id: `SEC-STOR-${account.name}-CROSS-TENANT`,
      title: `Cross-Tenant Object Replication Permitted on '${account.name}'`,
      category: 'network',
      severity: 'MEDIUM',
      findingType: 'guardrail_gap',
      resourceId: account.id,
      resourceName: account.name,
      resourceType: 'StorageAccount',
      description: `Storage account '${account.name}' has allowCrossTenantReplication=true, allowing object replication policies across different Entra ID tenants if configured by an authorized operator.`,
      exploitScenario: `An identity with storage configuration rights could establish object replication to an external tenant storage account.`,
      businessImpact: `Permissive cross-tenant replication guardrail.`,
      compliance: {
        cisAzure: '3.13',
        mcsb: 'DP-2: Protect sensitive data from exfiltration',
        nist: 'AC-4: Information Flow Enforcement',
      },
      remediation: {
        summary: `Disable allowCrossTenantReplication unless cross-tenant object replication is explicitly required.`,
        cliCommand: `az storage account update \\\n  --name "${account.name}" \\\n  --resource-group "${account.resourceGroup}" \\\n  --allow-cross-tenant-replication false`,
        rollbackCommand: `az storage account update --name "${account.name}" --resource-group "${account.resourceGroup}" --allow-cross-tenant-replication true`,
        portalSteps: [
          `Open Storage Account '${account.name}' > 'Object replication' / 'Configuration'.`,
          `Uncheck 'Allow cross-tenant replication' and save.`,
        ],
        terraformSnippet: `resource "azurerm_storage_account" "${account.name}" {\n  # ...\n  cross_tenant_replication_enabled = false\n}`,
        impactNotice: `Blocks cross-tenant object replication policies; validate whether any partner replication workflows exist.`,
      },
      detectedAt: now,
    });
  }

  return findings;
}

export function auditRbacAssignment(assignment: RbacAssignment): Finding[] {
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  // 1. Critical: Subscription-level 'Owner' Assignment
  const isSubscriptionScope =
    assignment.scope.startsWith('/subscriptions/') &&
    !assignment.scope.includes('/resourceGroups/');
  if (assignment.roleDefinitionName === 'Owner' && isSubscriptionScope) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-SUB-OWNER`,
      title: `Broad 'Owner' Role Assigned at Subscription Scope (${assignment.principalName})`,
      category: 'rbac',
      severity: 'CRITICAL',
      findingType: 'configuration_hardening',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleAssignment',
      description: `Identity '${assignment.principalName}' (${assignment.principalType}) holds standing 'Owner' permissions at subscription scope (${assignment.scope}), granting full resource and RBAC management across the subscription.`,
      exploitScenario: `Compromise of a standing subscription Owner identity permits full control over all resources and role assignments in the subscription.`,
      businessImpact: `Broad blast radius across subscription resources.`,
      compliance: {
        cisAzure: '1.23',
        cisTitle: 'Limit standing subscription Owner assignments and prefer scoped/JIT access',
        mcsb: 'PA-1: Limit administrative privilege',
        nist: 'AC-6: Least Privilege',
      },
      remediation: {
        summary: `Verify break-glass and administrative requirements first; replace standing subscription Owner assignments with Resource-Group-scoped roles or Entra ID Privileged Identity Management (PIM) eligible roles.`,
        preCheckCommand: `az role assignment list --scope "${assignment.scope}" --role "Owner" -o json`,
        cliCommand: `az role assignment delete \\\n  --assignee "${assignment.principalId}" \\\n  --role "Owner" \\\n  --scope "${assignment.scope}"`,
        rollbackCommand: `az role assignment create --assignee "${assignment.principalId}" --role "Owner" --scope "${assignment.scope}"`,
        portalSteps: [
          `Confirm that at least two emergency break-glass accounts or approved administrators remain before removing any Owner assignment.`,
          `Go to Azure Portal > Subscriptions > Access control (IAM) > Role assignments.`,
          `Scope '${assignment.principalName}' to the specific Resource Group and least-privileged role required.`,
        ],
        terraformSnippet: `resource "azurerm_role_assignment" "scoped_assignment" {\n  scope                = azurerm_resource_group.rg.id\n  role_definition_name = "Contributor"\n  principal_id         = "${assignment.principalId}"\n}`,
        impactNotice: `CAUTION: Never remove the last remaining Owner from a subscription. Provision replacement scoped or PIM roles before deleting the existing assignment.`,
      },
      detectedAt: now,
    });
  }

  // 2. Critical: External / Guest User with Elevated Privileges
  if (
    assignment.isExternalGuest &&
    (assignment.roleDefinitionName === 'Owner' ||
      assignment.roleDefinitionName === 'Contributor' ||
      assignment.roleDefinitionName.includes('Admin'))
  ) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-GUEST-ELEVATED`,
      title: `External Guest Account Holds Elevated Role '${assignment.roleDefinitionName}' (${assignment.principalName})`,
      category: 'rbac',
      severity: 'CRITICAL',
      findingType: 'configuration_hardening',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleAssignment',
      description: `External B2B guest identity '${assignment.principalName}' holds '${assignment.roleDefinitionName}' at scope '${assignment.scope}'.`,
      exploitScenario: `External guest accounts authenticate against an external home directory unless restricted by strict cross-tenant access settings.`,
      businessImpact: `Elevated third-party access across cloud resources.`,
      compliance: {
        cisAzure: '1.3',
        cisTitle: 'Review and restrict external guest accounts with administrative privileges',
        mcsb: 'PA-1: Protect identity lifecycle',
        nist: 'AC-2, AC-3',
      },
      remediation: {
        summary: `Review partner authorization with the resource owner and scope guest access to least-privilege Reader or specific resource groups.`,
        preCheckCommand: `az role assignment list --assignee "${assignment.principalId}" --all -o json`,
        cliCommand: `az role assignment delete \\\n  --assignee "${assignment.principalId}" \\\n  --role "${assignment.roleDefinitionName}" \\\n  --scope "${assignment.scope}"`,
        rollbackCommand: `az role assignment create --assignee "${assignment.principalId}" --role "${assignment.roleDefinitionName}" --scope "${assignment.scope}"`,
        portalSteps: [
          `Navigate to Access Control (IAM) at '${assignment.scope}'.`,
          `Review external user '${assignment.principalName}' (#EXT#) with the business owner and downgrade or remove elevated roles.`,
        ],
        terraformSnippet: `# Restrict external guest principals to scoped, least-privileged roles`,
        impactNotice: `Coordinate with external partner workflows before revoking role assignments.`,
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
      title: `Privilege Escalation Risk: 'roleAssignments/write' Permitted for '${assignment.principalName}'`,
      category: 'privilege_escalation',
      severity: 'CRITICAL',
      findingType: 'configuration_hardening',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleDefinition',
      description: `Identity '${assignment.principalName}' is assigned '${assignment.roleDefinitionName}', which includes 'Microsoft.Authorization/roleAssignments/write' without ABAC role-assignment conditions.`,
      exploitScenario: `A principal with unconstrained roleAssignments/write permissions can assign Owner or Blob Data Owner roles to itself or other identities.`,
      businessImpact: `Potential privilege elevation beyond intended operational duties.`,
      compliance: {
        cisAzure: '1.24',
        mcsb: 'PA-7: Prevent privilege escalation',
        nist: 'AC-6: Least privilege',
      },
      remediation: {
        summary: `Add 'Microsoft.Authorization/roleAssignments/*' to NotActions in custom roles, or constrain delegation using Azure ABAC role assignment conditions.`,
        preCheckCommand: `az role definition list --name "${assignment.roleDefinitionName}" -o json`,
        cliCommand: `az role definition update --role-definition '{ "Name": "${assignment.roleDefinitionName}", "NotActions": ["Microsoft.Authorization/roleAssignments/*"] }'`,
        portalSteps: [
          `Export the current custom role JSON definition for backup.`,
          `Go to Azure Portal > Subscriptions > 'Access control (IAM)' > 'Roles'.`,
          `Edit '${assignment.roleDefinitionName}' to exclude 'Microsoft.Authorization/roleAssignments/*' or add ABAC conditions restricting delegable roles.`,
        ],
        terraformSnippet: `resource "azurerm_role_definition" "custom_role" {\n  name        = "${assignment.roleDefinitionName}"\n  scope       = "/subscriptions/..."\n  not_actions = [\n    "Microsoft.Authorization/roleAssignments/*",\n    "Microsoft.Authorization/elevateAccess/Action"\n  ]\n}`,
        impactNotice: `If this identity is a CI/CD deployment pipeline that legitimately provisions role assignments, use Azure ABAC conditions to restrict which specific roles it can assign rather than removing the permission outright.`,
      },
      privilegeEscalationPath: `Principal '${assignment.principalName}' -> Microsoft.Authorization/roleAssignments/write -> Assign elevated role -> Expanded Scope Control`,
      detectedAt: now,
    });
  }

  // 4. High: Service Principal with High-Privilege Wildcard Permissions
  if (
    assignment.principalType === 'ServicePrincipal' &&
    (assignment.roleDefinitionName === 'Owner' || assignment.actions.includes('*'))
  ) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-SP-OVERPRIVILEGED`,
      title: `Overprivileged Non-Human Service Principal '${assignment.principalName}'`,
      category: 'rbac',
      severity: 'HIGH',
      findingType: 'configuration_hardening',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleAssignment',
      description: `Service Principal '${assignment.principalName}' holds wildcard ('*') actions via role '${assignment.roleDefinitionName}' at scope '${assignment.scope}'.`,
      exploitScenario: `If workload credentials or CI/CD secrets for '${assignment.principalName}' are exposed, callers gain broad management-plane permissions.`,
      businessImpact: `Expanded blast radius for non-human workload identity.`,
      compliance: {
        cisAzure: '1.20',
        mcsb: 'PA-2: Protect non-human identities',
        nist: 'IA-2, AC-6',
      },
      remediation: {
        summary: `Replace wildcard subscription roles on Service Principals with resource-group-scoped, workload-specific roles and Federated Credentials.`,
        preCheckCommand: `az role assignment list --assignee "${assignment.principalId}" --all -o json`,
        cliCommand: `az role assignment delete --assignee "${assignment.principalId}" --role "${assignment.roleDefinitionName}" --scope "${assignment.scope}"`,
        rollbackCommand: `az role assignment create --assignee "${assignment.principalId}" --role "${assignment.roleDefinitionName}" --scope "${assignment.scope}"`,
        portalSteps: [
          `Assign the replacement least-privilege role to '${assignment.principalName}' in staging and verify pipeline runs.`,
          `Remove the standing wildcard role assignment once verified.`,
        ],
        terraformSnippet: `resource "azurerm_role_assignment" "sp_restricted" {\n  scope                = azurerm_resource_group.rg.id\n  role_definition_name = "Storage Blob Data Contributor"\n  principal_id         = "${assignment.principalId}"\n}`,
        impactNotice: `Assign the new scoped role BEFORE deleting the existing role assignment to prevent CI/CD or application downtime.`,
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
      findingType: 'configuration_hardening',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'RoleAssignment',
      description: `Role assignment for '${assignment.principalName}' ('${assignment.roleDefinitionName}') shows ${assignment.lastActiveDays} days since last recorded activity.`,
      exploitScenario: `Unused role assignments increase standing privilege exposure if an inactive account is compromised.`,
      businessImpact: `Accumulation of unnecessary standing permissions.`,
      compliance: {
        cisAzure: '1.10',
        cisTitle: 'Review and revoke unused role assignments',
        mcsb: 'PA-1: Review and reconcile identity access regularly',
        nist: 'AC-2: Account Management',
      },
      remediation: {
        summary: `Conduct an Entra ID Access Review with the account owner and remove unneeded role assignments.`,
        preCheckCommand: `az role assignment list --assignee "${assignment.principalId}" --all -o json`,
        cliCommand: `az role assignment delete \\\n  --assignee "${assignment.principalId}" \\\n  --role "${assignment.roleDefinitionName}" \\\n  --scope "${assignment.scope}"`,
        rollbackCommand: `az role assignment create --assignee "${assignment.principalId}" --role "${assignment.roleDefinitionName}" --scope "${assignment.scope}"`,
        portalSteps: [
          `Verify sign-in activity in Entra ID sign-in logs for '${assignment.principalName}'.`,
          `Remove the role assignment under Access control (IAM) if no longer required.`,
        ],
        terraformSnippet: `# Use Entra ID Access Reviews to periodically recertify role assignments`,
        impactNotice: `Confirm the principal is not used for infrequent quarterly/annual disaster-recovery tasks before removal.`,
      },
      detectedAt: now,
    });
  }

  // 6. High: Privileged Role without MFA Enforcement
  if (
    !assignment.mfaEnforced &&
    (assignment.roleDefinitionName === 'Owner' ||
      assignment.roleDefinitionName === 'Contributor' ||
      assignment.roleDefinitionName.includes('Admin'))
  ) {
    findings.push({
      id: `SEC-RBAC-${assignment.id}-NO-MFA`,
      title: `MFA Enforcement Not Confirmed for Privileged Identity '${assignment.principalName}'`,
      category: 'rbac',
      severity: 'HIGH',
      findingType: 'configuration_hardening',
      resourceId: assignment.id,
      resourceName: assignment.principalName,
      resourceType: 'IAM',
      description: `Privileged identity '${assignment.principalName}' ('${assignment.roleDefinitionName}') is flagged without confirmed Multi-Factor Authentication (MFA) enforcement in the inspected dataset.`,
      exploitScenario: `Single-factor credentials for privileged roles are susceptible to password spray and phishing attacks.`,
      businessImpact: `Elevated risk of unauthorized management-plane sign-in.`,
      compliance: {
        cisAzure: '1.1',
        cisTitle: 'Ensure multi-factor authentication is enabled for all privileged users',
        mcsb: 'PA-4: Enforce MFA for privileged users',
        nist: 'IA-2: Identification and Authentication',
      },
      remediation: {
        summary: `Enforce phishing-resistant MFA for Azure Management sign-ins via Entra ID Conditional Access (in report-only mode first).`,
        cliCommand: `# Audit Conditional Access policies via Microsoft Graph:\naz rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"`,
        portalSteps: [
          `Navigate to Entra ID > Security > Conditional Access.`,
          `Validate a policy targeting Windows Azure Service Management API in 'Report-only' mode first, ensuring break-glass accounts are excluded, then set to 'On'.`,
        ],
        terraformSnippet: `resource "azuread_conditional_access_policy" "require_mfa" {\n  display_name = "Require MFA for Azure Management"\n  state        = "enabledForReportingButNotEnforced"\n}`,
        impactNotice: `Always test Conditional Access policies in 'Report-only' mode and exclude emergency break-glass accounts to prevent tenant lockout.`,
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
  const privilegeEscalationCount = allFindings.filter(
    (f) => f.category === 'privilege_escalation'
  ).length;
  const inactiveRoleCount = allFindings.filter((f) => f.id.includes('DORMANT')).length;

  // Recommendation #10: Separate confirmed anonymous container exposure from account-level guardrail gaps
  const confirmedExposedContainerCount = allFindings.filter(
    (f) => f.id.includes('EXPOSED') && f.findingType === 'confirmed_exposure'
  ).length;
  const guardrailGapAccountCount = allFindings.filter(
    (f) => f.id.includes('PUB-ACCESS')
  ).length;
  const exposedContainerCount = confirmedExposedContainerCount;

  // Total security controls evaluated across inspected resources:
  // 10 account-level rules per StorageAccount + 2 container-level rules per StorageContainer + 6 rules per RbacAssignment
  const rawTotalChecks =
    storageAccounts.length * 10 +
    storageAccounts.reduce((acc, curr) => acc + curr.containers.length * 2, 0) +
    roleAssignments.length * 6;

  // Recommendation #3: When 0 resources are evaluated (e.g., unauthenticated or empty scope),
  // do NOT report 100% posture or 100% compliance! Mark checks as Unknown (18 selected rule definitions).
  const isEvaluationComplete = totalResources > 0;
  const totalEvaluatedFindings = isEvaluationComplete
    ? Math.max(allFindings.length, rawTotalChecks)
    : 0;
  const hardenedFindingsCount = isEvaluationComplete
    ? Math.max(0, totalEvaluatedFindings - allFindings.length)
    : 0;
  const unknownChecksCount = isEvaluationComplete ? 0 : 18;

  const postureScore = isEvaluationComplete
    ? Math.max(
        0,
        Math.min(100, Math.round((hardenedFindingsCount / totalEvaluatedFindings) * 100))
      )
    : 0;

  let riskGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'C';
  if (!isEvaluationComplete) {
    riskGrade = 'C';
  } else if (postureScore >= 95) {
    riskGrade = 'A+';
  } else if (postureScore >= 85) {
    riskGrade = 'A';
  } else if (postureScore >= 70) {
    riskGrade = 'B';
  } else if (postureScore >= 55) {
    riskGrade = 'C';
  } else if (postureScore >= 40) {
    riskGrade = 'D';
  } else {
    riskGrade = 'F';
  }

  // Selected check pass/fail/unknown counts by reference framework (Recommendation #3)
  const cisFailed = allFindings.filter((f) => Boolean(f.compliance.cisAzure)).length;
  const mcsbFailed = allFindings.filter((f) => Boolean(f.compliance.mcsb)).length;
  const nistFailed = allFindings.filter((f) => Boolean(f.compliance.nist)).length;

  const cisTotal = isEvaluationComplete ? Math.max(cisFailed, totalEvaluatedFindings) : 18;
  const mcsbTotal = isEvaluationComplete ? Math.max(mcsbFailed, totalEvaluatedFindings) : 18;
  const nistTotal = isEvaluationComplete ? Math.max(nistFailed, totalEvaluatedFindings) : 18;

  const cisPassed = isEvaluationComplete ? Math.max(0, cisTotal - cisFailed) : 0;
  const mcsbPassed = isEvaluationComplete ? Math.max(0, mcsbTotal - mcsbFailed) : 0;
  const nistPassed = isEvaluationComplete ? Math.max(0, nistTotal - nistFailed) : 0;

  const cisPassRate = isEvaluationComplete
    ? Math.round((cisPassed / Math.max(1, cisTotal)) * 100)
    : 0;
  const mcsbPassRate = isEvaluationComplete
    ? Math.round((mcsbPassed / Math.max(1, mcsbTotal)) * 100)
    : 0;
  const nistPassRate = isEvaluationComplete
    ? Math.round((nistPassed / Math.max(1, nistTotal)) * 100)
    : 0;

  const externalGuestRiskCount = allFindings.filter(
    (f) => f.id.includes('GUEST')
  ).length;

  const metrics: AuditMetrics = {
    totalResources,
    totalFindings: allFindings.length,
    hardenedFindingsCount,
    totalEvaluatedFindings,
    unknownChecksCount,
    isEvaluationComplete,
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
    externalGuestRiskCount,
    exposedContainerCount,
    guardrailGapAccountCount,
    openBucketCount: exposedContainerCount,
    complianceScores: {
      cisAzure: Math.min(100, cisPassRate),
      mcsb: Math.min(100, mcsbPassRate),
      nist: Math.min(100, nistPassRate),
    },
    frameworkChecks: {
      cisAzure: {
        passed: cisPassed,
        failed: cisFailed,
        unknown: isEvaluationComplete ? 0 : 7,
        totalSelected: isEvaluationComplete ? cisTotal : 7,
        passRate: cisPassRate,
      },
      mcsb: {
        passed: mcsbPassed,
        failed: mcsbFailed,
        unknown: isEvaluationComplete ? 0 : 6,
        totalSelected: isEvaluationComplete ? mcsbTotal : 6,
        passRate: mcsbPassRate,
      },
      nist: {
        passed: nistPassed,
        failed: nistFailed,
        unknown: isEvaluationComplete ? 0 : 5,
        totalSelected: isEvaluationComplete ? nistTotal : 5,
        passRate: nistPassRate,
      },
    },
  };

  return { findings: allFindings, metrics };
}

export const evaluateAzurePosture = executeFullAudit;

