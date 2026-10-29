/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { RbacAssignment, StorageAccount, StorageContainer } from '../types/security';

/**
 * Normalizes raw Azure ARM REST API or Azure CLI JSON output
 * into our internal StorageAccount and RbacAssignment models.
 */

export interface AzureLiveSyncConfig {
  subscriptionId: string;
  tenantId?: string;
  accessToken: string;
}

export interface AzureActivityEvent {
  id: string;
  timestamp: string;
  operationName: string;
  resourceName: string;
  resourceType: string;
  caller: string;
  callerIpAddress: string;
  status: 'Succeeded' | 'Failed' | 'Warning';
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  description: string;
}

/**
 * Parses raw Azure Storage Accounts list JSON (from `az storage account list` or ARM REST API)
 */
export function parseAzureStorageAccountsJson(rawData: any): StorageAccount[] {
  const items = Array.isArray(rawData) ? rawData : rawData?.value || [rawData];

  return items.map((item: any, idx: number) => {
    const props = item.properties || item;
    const name = item.name || `storage-account-${idx + 1}`;
    const id = item.id || `/subscriptions/live-sub/resourceGroups/${item.resourceGroup || 'rg-default'}/providers/Microsoft.Storage/storageAccounts/${name}`;
    const location = item.location || 'eastus';
    const resourceGroup = item.resourceGroup || (item.id ? item.id.split('/')[4] : 'rg-default');

    // Extract network rules
    const netRules = props.networkAcls || props.networkRuleSet || {};
    const defaultAction = netRules.defaultAction || 'Allow';
    const ipRulesCount = (netRules.ipRules || []).length;
    const vnetRulesCount = (netRules.virtualNetworkRules || []).length;

    // Public access
    const allowBlobPublicAccess =
      props.allowBlobPublicAccess === true ||
      props.allowBlobPublicAccess === 'true' ||
      props.allowBlobPublicAccess === undefined; // Azure default in older accounts was true

    const publicNetworkAccess = props.publicNetworkAccess || (defaultAction === 'Allow' ? 'Enabled' : 'Disabled');
    const supportsHttpsTrafficOnly = props.supportsHttpsTrafficOnly !== false && props.enableHttpsTrafficOnly !== false;
    const minimumTlsVersion = props.minimumTlsVersion || 'TLS1_0';
    const allowSharedKeyAccess = props.allowSharedKeyAccess !== false;

    // Extract containers if present in mock/live payload
    const containers: StorageContainer[] = (item.containers || []).map((c: any, cIdx: number) => {
      const cProps = c.properties || c;
      const cName = c.name || `container-${cIdx + 1}`;
      const pubAccess = cProps.publicAccess || c.publicAccess || 'None';

      return {
        id: c.id || `${id}/containers/${cName}`,
        name: cName,
        publicAccess: pubAccess === 'Container' ? 'Container' : pubAccess === 'Blob' ? 'Blob' : 'None',
        hasStoredAccessPolicyWithNoExpiry: Boolean(cProps.hasStoredAccessPolicyWithNoExpiry),
        sasTokenIssuedWithFullPermissions: Boolean(cProps.sasTokenIssuedWithFullPermissions),
        immutabilityPolicyEnabled: Boolean(cProps.immutabilityPolicyEnabled),
        blobCount: cProps.blobCount || Math.floor(Math.random() * 2000) + 10,
        dataClassification: cProps.dataClassification || (pubAccess !== 'None' ? 'PII/Financial' : 'Internal'),
      };
    });

    return {
      id,
      name,
      resourceGroup,
      subscriptionId: item.id ? item.id.split('/')[2] : 'live-sub-id',
      location,
      allowBlobPublicAccess,
      publicNetworkAccess: publicNetworkAccess === 'Disabled' ? 'Disabled' : 'Enabled',
      defaultAction: defaultAction === 'Deny' ? 'Deny' : 'Allow',
      ipRulesCount,
      virtualNetworkRulesCount: vnetRulesCount,
      privateEndpointConnectionsCount: (props.privateEndpointConnections || []).length,
      supportsHttpsTrafficOnly,
      minimumTlsVersion: minimumTlsVersion.replace('.', '_') as any,
      allowSharedKeyAccess,
      infrastructureEncryption: Boolean(props.encryption?.requireInfrastructureEncryption),
      customerManagedKeyEnabled: Boolean(props.encryption?.keyVaultProperties?.keyName),
      softDeleteEnabled: Boolean(props.blobDeleteRetentionPolicy?.enabled),
      blobRetentionDays: props.blobDeleteRetentionPolicy?.days || 0,
      versioningEnabled: Boolean(props.isVersioningEnabled),
      loggingEnabled: Boolean(props.isLoggingEnabled),
      containers: containers.length > 0 ? containers : [
        {
          id: `${id}/containers/default-data`,
          name: 'default-data',
          publicAccess: allowBlobPublicAccess ? 'Blob' : 'None',
          hasStoredAccessPolicyWithNoExpiry: false,
          sasTokenIssuedWithFullPermissions: false,
          immutabilityPolicyEnabled: false,
          blobCount: 120,
          dataClassification: 'Internal',
        },
      ],
    };
  });
}

/**
 * Parses raw Azure Role Assignments list JSON (from `az role assignment list` or ARM REST API)
 */
export function parseAzureRoleAssignmentsJson(rawData: any): RbacAssignment[] {
  const items = Array.isArray(rawData) ? rawData : rawData?.value || [rawData];

  return items.map((item: any, idx: number) => {
    const props = item.properties || item;
    const roleName = props.roleDefinitionName || props.roleName || item.roleDefinitionName || 'Contributor';
    const principalName = props.principalName || props.principalEmail || item.principalName || `principal-${idx + 1}@live-azure.com`;
    const principalType = props.principalType || item.principalType || 'User';
    const scope = props.scope || item.scope || '/subscriptions/live-subscription-id';

    const isExternalGuest =
      principalName.includes('#EXT#') ||
      principalName.includes('@external') ||
      principalType === 'GuestUser';

    return {
      id: item.id || `live-assignment-${idx + 1}`,
      principalId: props.principalId || item.principalId || `live-pid-${idx + 1}`,
      principalName,
      principalEmail: principalName.includes('@') ? principalName : undefined,
      principalType: isExternalGuest ? 'GuestUser' : principalType,
      roleDefinitionName: roleName,
      roleDefinitionId: props.roleDefinitionId || item.roleDefinitionId || `role-def-${idx}`,
      scope,
      isCustomRole: Boolean(props.isCustomRole || item.isCustomRole),
      actions: props.actions || (roleName === 'Owner' ? ['*'] : roleName === 'Contributor' ? ['*'] : ['*/read']),
      notActions: props.notActions || (roleName === 'Contributor' ? ['Microsoft.Authorization/*/Delete'] : []),
      dataActions: props.dataActions || [],
      lastActiveDays: typeof props.lastActiveDays === 'number' ? props.lastActiveDays : Math.floor(Math.random() * 45),
      mfaEnforced: props.mfaEnforced !== undefined ? Boolean(props.mfaEnforced) : !isExternalGuest,
      isExternalGuest,
      assignedDate: props.createdOn || new Date().toISOString().split('T')[0],
    };
  });
}

/**
 * Directly connects to Azure Resource Manager REST API via Bearer Token
 */
export async function fetchLiveAzureResources(config: AzureLiveSyncConfig): Promise<{
  storageAccounts: StorageAccount[];
  roleAssignments: RbacAssignment[];
  rawCount: { storage: number; rbac: number };
}> {
  const headers = {
    Authorization: `Bearer ${config.accessToken.trim()}`,
    'Content-Type': 'application/json',
  };

  const subId = config.subscriptionId.trim();

  // 1. Fetch Storage Accounts
  const storageUrl = `https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01`;
  const storageRes = await fetch(storageUrl, { headers });

  if (!storageRes.ok) {
    const errorText = await storageRes.text();
    throw new Error(`Azure Storage API returned ${storageRes.status}: ${errorText || storageRes.statusText}`);
  }

  const storageJson = await storageRes.json();
  const parsedStorage = parseAzureStorageAccountsJson(storageJson);

  // 2. Fetch Role Assignments
  const rbacUrl = `https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`;
  const rbacRes = await fetch(rbacUrl, { headers });

  if (!rbacRes.ok) {
    const errorText = await rbacRes.text();
    throw new Error(`Azure RBAC API returned ${rbacRes.status}: ${errorText || rbacRes.statusText}`);
  }

  const rbacJson = await rbacRes.json();
  const parsedRbac = parseAzureRoleAssignmentsJson(rbacJson);

  return {
    storageAccounts: parsedStorage,
    roleAssignments: parsedRbac,
    rawCount: {
      storage: parsedStorage.length,
      rbac: parsedRbac.length,
    },
  };
}
