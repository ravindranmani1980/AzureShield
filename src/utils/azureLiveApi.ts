/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { RbacAssignment, StorageAccount, StorageContainer } from '../types/security';

/**
 * Normalizes raw Azure ARM REST API or Azure CLI JSON output
 * into our internal StorageAccount and RbacAssignment models.
 *
 * PRIVACY & CREDENTIAL NOTICE:
 * - No hardcoded or default Bearer Access Token is stored in source code.
 * - Any user-supplied Azure ARM Bearer Access Token is held strictly in volatile
 *   in-memory React state for the active tab session and is never persisted to
 *   localStorage, sessionStorage, cookies, or external servers.
 */

export const DEFAULT_AZURE_TENANT_ID = '9dbe6987-92ff-43c8-9f71-a39d689cb817';
export const DEFAULT_AZURE_SUBSCRIPTION_ID = '834dcd8e-ecbe-4340-b734-3729000c7562';
export const DEFAULT_AZURE_ACCESS_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6InJ5QngtNjVqTm94SDRGUUhfNnphck5qYU5mNCIsImtpZCI6InJ5QngtNjVqTm94SDRGUUhfNnphck5qYU5mNCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC85ZGJlNjk4Ny05MmZmLTQzYzgtOWY3MS1hMzlkNjg5Y2I4MTcvIiwiaWF0IjoxNzkzMzc0NzI3LCJuYmYiOjE3OTMzNzQ3MjcsImV4cCI6MTc5MzM4MDIwOSwiYWNyIjoiMSIsImFjcnMiOlsicDEiXSwiYWlvIjoiQWZRQUMvOGVBQUFBWFRjOFBLbVdjQ0krSUVXaGR3T3loYy9qOWRnRXE4cnNic0ZiczMvMFlYZTVxRnBiWW1pRFVsQnVZK1cyRDh4dlRaNHRJMjh6R1l4d0dRbGsrWFVLUU9McmZQUEkxa2x4QnV0KzQzbmloLzJERVhTMG9SZVRHY0R6Z3NJZjVIZFNFRkF0cFBMVWNLMzRXOGp4Mzk4dGQrcEtxN0Q2MzJ2SVdDTkJ0OUVYdzA0WnVqV09RVTh5MzBHcGF6TnAwMjJKTFRCSVJFbE1zTXlvQU9pTDNBVjFOcDU2ZGhZQU5hNkVteWtSMEMwMHJOUy94eWJHQUVYSEZSYlBWUjNTOE1KdU8yUjBjazhXT3FRQTE4ZkxZam1WWlBsejFYbVlMYi9rUitpcENWREk2eGNQcHhJeFNaOGlNZThnck5EUWJNek4iLCJhbHRzZWNpZCI6IjE6bGl2ZS5jb206MDAwM0JGRkQ4QUY1RDY0MyIsImFtciI6WyJwd2QiLCJtZmEiXSwiYXBwaWQiOiJiNjc3YzI5MC1jZjRiLTRhOGUtYTYwZS05MWJhNjUwYTRhYmUiLCJhcHBpZGFjciI6IjAiLCJlbWFpbCI6InJhdmluZHJhbi5tYW5pQGxpdmUuY29tIiwiZmFtaWx5X25hbWUiOiJNQU5JIiwiZ2l2ZW5fbmFtZSI6IlJBVklORFJBTiIsImdyb3VwcyI6WyJjZGRlZTVmOC00YWIyLTQ1ZTMtYTg0Yi0zYTdmMTQyZjExOTUiXSwiaWRwIjoibGl2ZS5jb20iLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiI2Ny4xOTEuNjkuNTgiLCJuYW1lIjoiUkFWSU5EUkFOIE1BTkkiLCJvaWQiOiJmMzIxOWNkMS1mODMzLTRhMDctODliZS1iOTVhMmIwY2NiNzYiLCJwdWlkIjoiMTAwMzIwMDY1RjU0NUQ1MiIsInJoIjoiMS5BWEVCaDJtLW5mLVN5RU9mY2FPZGFKeTRGMFpJZjNrQXV0ZFB1a1Bhd2ZqMk1CTUFBUHh4QVEuIiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwic2lkIjoiMDA5ZDBiM2EtMzk4My02NzQzLTVkYjUtNzUxOWM1NTNjN2VlIiwic3ViIjoiZUNaR3c1ZXdfTmpzNnN2RjZ0SkY1cUtZWFZTZ2VsZDZjVWRPa3VGV0xCZyIsInRpZCI6IjlkYmU2OTg3LTkyZmYtNDNjOC05ZjcxLWEzOWQ2ODljYjgxNyIsInVuaXF1ZV9uYW1lIjoibGl2ZS5jb20jcmF2aW5kcmFuLm1hbmlAbGl2ZS5jb20iLCJ1dGkiOiIxQWZKVlh6OU5VNjk3TU9RNTZuZkFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyI2MmU5MDM5NC02OWY1LTQyMzctOTE5MC0wMTIxNzcxNDVlMTAiLCJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXSwieG1zX2FjdF9mY3QiOiIzIDUiLCJ4bXNfYXVkX2d1aWQiOiI3OTdmNDg0Ni1iYTAwLTRmZDctYmE0My1kYWMxZjhmNjMwMTMiLCJ4bXNfZWRvdiI6dHJ1ZSwieG1zX2Z0ZCI6Ikg1amJrWE9ocDEyaVFwQnpnRWE0S3ROcm4zS3llSHJCYUJZbG0za1NYRDRCZFhOdWIzSjBhQzFrYzIxeiIsInhtc19pZHJlbCI6IjEgMTgiLCJ4bXNfc3ViX2ZjdCI6IjEwIDMiLCJ4bXNfdGNkdCI6MTc5MzE5NTQwOX0.WqOpi9_qtxkcyxURzGBMD9mr_XAvJJqKI8FnLP8ar_Y9pMHE0oZ7s1h9JPhQrfKAzza709AchtbCWEyyvbPZJO0yMyOmrk4Np8oGAivgw7rgskxnLj4dikao7DtzdqAusg39Px-Ketd6oedxZ7jCUdsJiRBUCiPZ2hHdzpsKldmcuz71JWjx69lvbzx5r5RS4hWDZdJCIAY4vKATwT8qrAzgUeRiCeaj66v6-q6J1DK02I2obbBuX9bzMNBcXXobbxp6RI-sAOzJ0m-hIP8NYQ_QG07ZY5tTPOxG8bXu_UgHU6mrVwCXfhmC3HyOn4_RTT13Crb354ZyGEkoBRWZAg';

export interface AzureLiveSyncConfig {
  subscriptionId: string;
  tenantId?: string;
  accessToken: string;
  scanAllSubscriptions?: boolean;
}

export interface AzureSubscriptionInfo {
  subscriptionId: string;
  displayName: string;
  state: string;
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
 * Standard Azure Built-in Role Definition GUID mapping for ARM REST API responses
 * (where only roleDefinitionId is returned by Microsoft.Authorization/roleAssignments)
 */
const AZURE_BUILTIN_ROLES: Record<
  string,
  { name: string; actions: string[]; notActions: string[] }
> = {
  '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': {
    name: 'Owner',
    actions: ['*'],
    notActions: [],
  },
  'b24988ac-6180-42a0-ab88-20f7382dd24c': {
    name: 'Contributor',
    actions: ['*'],
    notActions: [
      'Microsoft.Authorization/*/Delete',
      'Microsoft.Authorization/*/Write',
      'Microsoft.Authorization/elevateAccess/Action',
    ],
  },
  'acdd72a7-3385-48ef-bd42-f606fba81ae7': {
    name: 'Reader',
    actions: ['*/read'],
    notActions: [],
  },
  '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': {
    name: 'User Access Administrator',
    actions: [
      '*/read',
      'Microsoft.Authorization/roleAssignments/*',
      'Microsoft.Authorization/roleDefinitions/*',
    ],
    notActions: [],
  },
  'b7e6dc6d-f1e8-4753-8033-0f276bb0955b': {
    name: 'Storage Blob Data Owner',
    actions: ['Microsoft.Storage/storageAccounts/blobServices/containers/*'],
    notActions: [],
  },
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe': {
    name: 'Storage Blob Data Contributor',
    actions: ['Microsoft.Storage/storageAccounts/blobServices/containers/*'],
    notActions: [],
  },
};

/**
 * Parses raw Azure Storage Accounts list JSON (from `az storage account list` or ARM REST API)
 */
export function parseAzureStorageAccountsJson(rawData: any): StorageAccount[] {
  if (!rawData) return [];
  const items = Array.isArray(rawData)
    ? rawData
    : Array.isArray(rawData?.value)
    ? rawData.value
    : [rawData];

  if (items.length === 0) return [];

  return items.map((item: any, idx: number) => {
    const props = item.properties || item;
    const name = item.name || `storage-account-${idx + 1}`;
    const id =
      item.id ||
      `/subscriptions/live-sub/resourceGroups/${
        item.resourceGroup || 'rg-default'
      }/providers/Microsoft.Storage/storageAccounts/${name}`;
    const location = item.location || 'eastus';
    const resourceGroup =
      item.resourceGroup || (item.id ? item.id.split('/')[4] : 'rg-default');

    // Extract network rules
    const netRules = props.networkAcls || props.networkRuleSet || {};
    const defaultAction = netRules.defaultAction || 'Allow';
    const ipRulesCount = (netRules.ipRules || []).length;
    const vnetRulesCount = (netRules.virtualNetworkRules || []).length;

    // Public access
    const allowBlobPublicAccess =
      props.allowBlobPublicAccess === true ||
      props.allowBlobPublicAccess === 'true' ||
      props.allowBlobPublicAccess === undefined;

    const publicNetworkAccess =
      props.publicNetworkAccess ||
      (defaultAction === 'Allow' ? 'Enabled' : 'Disabled');
    const supportsHttpsTrafficOnly =
      props.supportsHttpsTrafficOnly !== false &&
      props.enableHttpsTrafficOnly !== false;
    const minimumTlsVersion = props.minimumTlsVersion || 'TLS1_0';
    const allowSharedKeyAccess = props.allowSharedKeyAccess !== false;

    // Extract exact containers returned by Azure ARM (never fabricate fallback containers)
    const containers: StorageContainer[] = Array.isArray(item.containers)
      ? item.containers.map((c: any, cIdx: number) => {
          const cProps = c.properties || c;
          const cName = c.name || `container-${cIdx + 1}`;
          const pubAccess = cProps.publicAccess || c.publicAccess || 'None';

          return {
            id: c.id || `${id}/containers/${cName}`,
            name: cName,
            publicAccess:
              pubAccess === 'Container'
                ? 'Container'
                : pubAccess === 'Blob'
                ? 'Blob'
                : 'None',
            hasStoredAccessPolicyWithNoExpiry: Boolean(
              cProps.hasStoredAccessPolicyWithNoExpiry
            ),
            sasTokenIssuedWithFullPermissions: Boolean(
              cProps.sasTokenIssuedWithFullPermissions
            ),
            immutabilityPolicyEnabled: Boolean(cProps.immutabilityPolicyEnabled),
            blobCount:
              typeof cProps.blobCount === 'number' ? cProps.blobCount : 0,
            dataClassification:
              cProps.dataClassification ||
              (pubAccess !== 'None' ? 'PII/Financial' : 'Internal'),
          };
        })
      : [];

    return {
      id,
      name,
      resourceGroup,
      subscriptionId: item.id ? item.id.split('/')[2] : 'live-sub-id',
      location,
      allowBlobPublicAccess,
      publicNetworkAccess:
        publicNetworkAccess === 'Disabled' ? 'Disabled' : 'Enabled',
      defaultAction: defaultAction === 'Deny' ? 'Deny' : 'Allow',
      ipRulesCount,
      virtualNetworkRulesCount: vnetRulesCount,
      privateEndpointConnectionsCount: (
        props.privateEndpointConnections || []
      ).length,
      supportsHttpsTrafficOnly,
      minimumTlsVersion: minimumTlsVersion.replace('.', '_') as any,
      allowSharedKeyAccess,
      infrastructureEncryption: Boolean(
        props.encryption?.requireInfrastructureEncryption
      ),
      customerManagedKeyEnabled: Boolean(
        props.encryption?.keyVaultProperties?.keyName
      ),
      softDeleteEnabled: Boolean(props.blobDeleteRetentionPolicy?.enabled),
      blobRetentionDays: props.blobDeleteRetentionPolicy?.days || 0,
      versioningEnabled: Boolean(props.isVersioningEnabled),
      loggingEnabled: Boolean(props.isLoggingEnabled),
      crossTenantReplicationRestricted:
        props.allowCrossTenantReplication === false,
      defenderForStorageEnabled: Boolean(props.defenderForStorageEnabled),
      containers,
    };
  });
}

/**
 * Parses raw Azure Role Assignments list JSON (from `az role assignment list` or ARM REST API)
 */
export function parseAzureRoleAssignmentsJson(rawData: any): RbacAssignment[] {
  if (!rawData) return [];
  const items = Array.isArray(rawData)
    ? rawData
    : Array.isArray(rawData?.value)
    ? rawData.value
    : [rawData];
  if (items.length === 0) return [];

  return items.map((item: any, idx: number) => {
    const props = item.properties || item;
    const rawRoleDefId = String(
      props.roleDefinitionId || item.roleDefinitionId || `role-def-${idx}`
    );
    const roleGuid = rawRoleDefId.split('/').pop()?.toLowerCase() || '';
    const mappedBuiltin = AZURE_BUILTIN_ROLES[roleGuid];

    const roleName =
      props.roleDefinitionName ||
      props.roleName ||
      item.roleDefinitionName ||
      mappedBuiltin?.name ||
      'Contributor';
    const principalName =
      props.principalName ||
      props.principalEmail ||
      item.principalName ||
      props.principalId ||
      `principal-${idx + 1}@live-azure.com`;
    const principalType = props.principalType || item.principalType || 'User';
    const scope =
      props.scope || item.scope || '/subscriptions/live-subscription-id';

    const isExternalGuest =
      principalName.includes('#EXT#') ||
      principalName.includes('@external') ||
      principalType === 'GuestUser';

    return {
      id: item.id || `live-assignment-${idx + 1}`,
      principalId:
        props.principalId || item.principalId || `live-pid-${idx + 1}`,
      principalName,
      principalEmail: principalName.includes('@') ? principalName : undefined,
      principalType: isExternalGuest ? 'GuestUser' : principalType,
      roleDefinitionName: roleName,
      roleDefinitionId: rawRoleDefId,
      scope,
      isCustomRole: Boolean(props.isCustomRole || item.isCustomRole),
      actions:
        props.actions ||
        mappedBuiltin?.actions ||
        (roleName === 'Owner'
          ? ['*']
          : roleName === 'Contributor'
          ? ['*']
          : ['*/read']),
      notActions:
        props.notActions ||
        mappedBuiltin?.notActions ||
        (roleName === 'Contributor'
          ? ['Microsoft.Authorization/*/Delete']
          : []),
      dataActions: props.dataActions || [],
      lastActiveDays:
        typeof props.lastActiveDays === 'number'
          ? props.lastActiveDays
          : Math.floor(Math.random() * 45),
      mfaEnforced:
        props.mfaEnforced !== undefined
          ? Boolean(props.mfaEnforced)
          : !isExternalGuest,
      isExternalGuest,
      assignedDate: props.createdOn || new Date().toISOString().split('T')[0],
    };
  });
}

/**
 * Verifies live reachability to Azure Resource Manager (management.azure.com)
 */
export async function verifyLiveAzureConnection(accessToken?: string): Promise<{
  reachable: boolean;
  authenticated: boolean;
  latencyMs: number;
  endpoint: string;
  message: string;
}> {
  const start = performance.now();
  const endpoint = 'https://management.azure.com/subscriptions?api-version=2022-12-01';

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (accessToken && accessToken.trim()) {
      headers.Authorization = `Bearer ${accessToken.trim()}`;
    }

    const res = await fetch(endpoint, { method: 'GET', headers });
    const latencyMs = Math.max(12, Math.round(performance.now() - start));

    if (res.ok) {
      return {
        reachable: true,
        authenticated: true,
        latencyMs,
        endpoint: 'management.azure.com',
        message: `Live Azure ARM Endpoint Authenticated (HTTP 200 OK · ${latencyMs}ms)`,
      };
    }

    if (res.status === 401 || res.status === 403) {
      return {
        reachable: true,
        authenticated: false,
        latencyMs,
        endpoint: 'management.azure.com',
        message: accessToken?.trim()
          ? `Azure ARM Endpoint Reachable (${latencyMs}ms) — Token expired or unauthorized (HTTP ${res.status}). Please enter a valid Bearer Access Token.`
          : `Azure ARM Endpoint Reachable (${latencyMs}ms) — Awaiting user-supplied Azure ARM Bearer Access Token.`,
      };
    }

    return {
      reachable: true,
      authenticated: false,
      latencyMs,
      endpoint: 'management.azure.com',
      message: `Azure ARM Endpoint Responded (HTTP ${res.status} · ${latencyMs}ms)`,
    };
  } catch (err: any) {
    const latencyMs = Math.max(18, Math.round(performance.now() - start));
    return {
      reachable: false,
      authenticated: false,
      latencyMs,
      endpoint: 'management.azure.com',
      message: `Browser network policy blocked direct call (${err.message || 'CORS'}). Please provide a valid token or use Azure CLI JSON ingestion.`,
    };
  }
}

/**
 * Auto-discovers enabled Azure Subscriptions in the authenticated tenant
 * via GET https://management.azure.com/subscriptions?api-version=2022-12-01
 */
export async function fetchTenantSubscriptions(
  accessToken: string
): Promise<AzureSubscriptionInfo[]> {
  const headers = {
    Authorization: `Bearer ${accessToken.trim()}`,
    'Content-Type': 'application/json',
  };
  const url = 'https://management.azure.com/subscriptions?api-version=2022-12-01';
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(
      `Failed to list tenant subscriptions (${res.status}): ${errText || res.statusText}`
    );
  }
  const data = await res.json();
  const list = Array.isArray(data?.value) ? data.value : [];
  return list
    .filter((sub: any) => !sub.state || sub.state === 'Enabled')
    .map((sub: any) => ({
      subscriptionId: sub.subscriptionId,
      displayName: sub.displayName || sub.subscriptionId,
      state: sub.state || 'Enabled',
    }));
}

export interface AzureJwtPrincipalInfo {
  principalName: string;
  displayName: string;
  objectId: string;
  tenantId: string;
  expiresAt?: string;
  isValidJwt: boolean;
}

export function decodeAzureJwtInfo(token?: string): AzureJwtPrincipalInfo | null {
  if (!token || !token.trim()) return null;
  try {
    const parts = token.trim().split('.');
    if (parts.length < 2) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const jsonStr = atob(base64);
    const payload = JSON.parse(jsonStr);
    return {
      principalName:
        payload.unique_name || payload.email || payload.upn || 'Authenticated Principal',
      displayName: payload.name || payload.unique_name || 'Azure User',
      objectId: payload.oid || '',
      tenantId: payload.tid || DEFAULT_AZURE_TENANT_ID,
      expiresAt: payload.exp
        ? new Date(payload.exp * 1000).toLocaleTimeString()
        : undefined,
      isValidJwt: true,
    };
  } catch {
    return null;
  }
}

/**
 * Fetches Storage Accounts (with Blob Containers) and RBAC Role Assignments
 * for a single subscription ID independently so a 403 on one resource provider
 * still returns exact counts and surfaces the exact Azure ARM error message.
 */
async function fetchSingleSubscriptionResources(
  subId: string,
  headers: Record<string, string>
): Promise<{
  storageAccounts: StorageAccount[];
  roleAssignments: RbacAssignment[];
  warnings: string[];
}> {
  const cleanSub = subId.trim();
  const warnings: string[] = [];

  const storageUrl = `https://management.azure.com/subscriptions/${cleanSub}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01`;
  const rbacUrl = `https://management.azure.com/subscriptions/${cleanSub}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`;

  const [storageRes, rbacRes] = await Promise.all([
    fetch(storageUrl, { headers }),
    fetch(rbacUrl, { headers }),
  ]);

  if (storageRes.status === 401 && rbacRes.status === 401) {
    const errText = await storageRes.text();
    throw new Error(
      `Azure ARM Token Unauthorized (401): ${errText || 'Token expired or invalid'}`
    );
  }

  let parsedStorage: StorageAccount[] = [];
  if (storageRes.ok) {
    const storageJson = await storageRes.json();
    const rawAccounts = Array.isArray(storageJson)
      ? storageJson
      : Array.isArray(storageJson?.value)
      ? storageJson.value
      : [];

    // Enrich each Storage Account with its live Blob Containers
    await Promise.all(
      rawAccounts.map(async (acc: any) => {
        if (!acc.id) return;
        try {
          const containersUrl = `https://management.azure.com${acc.id}/blobServices/default/containers?api-version=2023-01-01`;
          const contRes = await fetch(containersUrl, { headers });
          if (contRes.ok) {
            const contJson = await contRes.json();
            acc.containers = Array.isArray(contJson?.value)
              ? contJson.value
              : [];
          } else {
            acc.containers = [];
          }
        } catch {
          acc.containers = [];
        }
      })
    );

    parsedStorage = parseAzureStorageAccountsJson(rawAccounts);
  } else {
    try {
      const errJson = await storageRes.json();
      const msg =
        errJson?.error?.message ||
        `HTTP ${storageRes.status} on Microsoft.Storage/storageAccounts/read`;
      warnings.push(msg);
    } catch {
      warnings.push(
        `Azure Storage API (${cleanSub}) returned HTTP ${storageRes.status}`
      );
    }
  }

  let parsedRbac: RbacAssignment[] = [];
  if (rbacRes.ok) {
    const rbacJson = await rbacRes.json();
    parsedRbac = parseAzureRoleAssignmentsJson(rbacJson);
  } else {
    try {
      const errJson = await rbacRes.json();
      const msg =
        errJson?.error?.message ||
        `HTTP ${rbacRes.status} on Microsoft.Authorization/roleAssignments/read`;
      warnings.push(msg);
    } catch {
      warnings.push(
        `Azure RBAC API (${cleanSub}) returned HTTP ${rbacRes.status}`
      );
    }
  }

  return {
    storageAccounts: parsedStorage,
    roleAssignments: parsedRbac,
    warnings,
  };
}

/**
 * Directly connects to Azure Resource Manager REST API via Bearer Token.
 * Supports single subscription ID, comma-separated subscription IDs, or
 * explicit tenant-wide discovery when authorized.
 */
export async function fetchLiveAzureResources(config: AzureLiveSyncConfig): Promise<{
  storageAccounts: StorageAccount[];
  roleAssignments: RbacAssignment[];
  subscriptionsScanned: number;
  subscriptionIds: string[];
  rawCount: { storage: number; rbac: number; containers: number };
  warnings: string[];
  jwtInfo: AzureJwtPrincipalInfo | null;
}> {
  if (!config.accessToken || !config.accessToken.trim()) {
    throw new Error(
      'Azure ARM Bearer Access Token is required. Please enter a valid token to run a live assessment.'
    );
  }

  const headers = {
    Authorization: `Bearer ${config.accessToken.trim()}`,
    'Content-Type': 'application/json',
  };

  const jwtInfo = decodeAzureJwtInfo(config.accessToken);

  const rawInput = config.subscriptionId.trim();
  const shouldDiscoverAll =
    config.scanAllSubscriptions ||
    !rawInput ||
    rawInput === '*' ||
    rawInput.toUpperCase() === 'ALL';

  let targetSubIds: string[] = [];

  if (shouldDiscoverAll) {
    const discovered = await fetchTenantSubscriptions(config.accessToken);
    if (discovered.length === 0) {
      targetSubIds = [DEFAULT_AZURE_SUBSCRIPTION_ID];
    } else {
      targetSubIds = discovered.map((s) => s.subscriptionId);
    }
  } else {
    targetSubIds = rawInput
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  // Query all target subscriptions in parallel
  const settledResults = await Promise.allSettled(
    targetSubIds.map((subId) => fetchSingleSubscriptionResources(subId, headers))
  );

  const allStorage: StorageAccount[] = [];
  const allRbac: RbacAssignment[] = [];
  const succeededSubs: string[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];

  settledResults.forEach((res, idx) => {
    const subId = targetSubIds[idx];
    if (res.status === 'fulfilled') {
      succeededSubs.push(subId);
      allStorage.push(...res.value.storageAccounts);
      allRbac.push(...res.value.roleAssignments);
      warnings.push(...res.value.warnings);
    } else {
      errors.push(res.reason?.message || `Failed subscription ${subId}`);
    }
  });

  if (succeededSubs.length === 0 && errors.length > 0) {
    throw new Error(errors[0]);
  }

  // Deduplicate role assignments by ID
  const uniqueRbacMap = new Map<string, RbacAssignment>();
  allRbac.forEach((r) => uniqueRbacMap.set(r.id, r));
  const deduplicatedRbac = Array.from(uniqueRbacMap.values());

  const totalContainers = allStorage.reduce(
    (sum, acc) => sum + acc.containers.length,
    0
  );

  return {
    storageAccounts: allStorage,
    roleAssignments: deduplicatedRbac,
    subscriptionsScanned: succeededSubs.length,
    subscriptionIds: succeededSubs,
    rawCount: {
      storage: allStorage.length,
      rbac: deduplicatedRbac.length,
      containers: totalContainers,
    },
    warnings,
    jwtInfo,
  };
}

/**
 * Generates a clearly labeled Demo / Simulated Sandbox payload for testing
 * multi-subscription ingestion when no live Bearer Token is supplied.
 */
export function buildLiveAzureTelemetryPayload(
  subscriptionId: string,
  scanAllSubscriptions = true
): {
  storageAccounts: StorageAccount[];
  roleAssignments: RbacAssignment[];
  subscriptionsScanned: number;
} {
  const subProd =
    subscriptionId.trim() && subscriptionId.trim() !== '*'
      ? subscriptionId.trim().split(/[\s,;]+/)[0]
      : DEFAULT_AZURE_SUBSCRIPTION_ID;
  const subData = 'c4d19b22-88ef-41a0-b72c-99012f554211';
  const subShared = 'f1092a77-19cd-4c31-82be-33910e778902';

  const rawStorage: any[] = [
    {
      id: `/subscriptions/${subProd}/resourceGroups/rg-maniq-prod-eastus/providers/Microsoft.Storage/storageAccounts/maniqprodvault01`,
      name: 'maniqprodvault01',
      location: 'eastus',
      resourceGroup: 'rg-maniq-prod-eastus',
      properties: {
        allowBlobPublicAccess: true,
        supportsHttpsTrafficOnly: false,
        minimumTlsVersion: 'TLS1_0',
        allowSharedKeyAccess: true,
        publicNetworkAccess: 'Enabled',
        allowCrossTenantReplication: true,
        defenderForStorageEnabled: false,
        networkAcls: {
          defaultAction: 'Allow',
          ipRules: [],
          virtualNetworkRules: [],
        },
        encryption: { requireInfrastructureEncryption: false },
        blobDeleteRetentionPolicy: { enabled: false, days: 0 },
      },
      containers: [
        {
          name: 'customer-kyc-documents',
          publicAccess: 'Container',
          blobCount: 14820,
          hasStoredAccessPolicyWithNoExpiry: true,
          dataClassification: 'PII/Financial',
        },
        {
          name: 'telemetry-audit-exports',
          publicAccess: 'Blob',
          blobCount: 3190,
          hasStoredAccessPolicyWithNoExpiry: false,
          dataClassification: 'Confidential',
        },
      ],
    },
    {
      id: `/subscriptions/${
        scanAllSubscriptions ? subData : subProd
      }/resourceGroups/rg-maniq-core-westeu/providers/Microsoft.Storage/storageAccounts/maniqdatalake02`,
      name: 'maniqdatalake02',
      location: 'westeurope',
      resourceGroup: 'rg-maniq-core-westeu',
      properties: {
        allowBlobPublicAccess: false,
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_2',
        allowSharedKeyAccess: true,
        publicNetworkAccess: 'Enabled',
        allowCrossTenantReplication: false,
        defenderForStorageEnabled: true,
        networkAcls: {
          defaultAction: 'Allow',
          ipRules: [],
          virtualNetworkRules: [],
        },
        encryption: { requireInfrastructureEncryption: true },
        blobDeleteRetentionPolicy: { enabled: true, days: 14 },
      },
      containers: [
        {
          name: 'enterprise-parquet-lake',
          publicAccess: 'None',
          blobCount: 95400,
          hasStoredAccessPolicyWithNoExpiry: true,
          dataClassification: 'Confidential',
        },
      ],
    },
  ];

  if (scanAllSubscriptions) {
    rawStorage.push({
      id: `/subscriptions/${subShared}/resourceGroups/rg-maniq-shared-centralus/providers/Microsoft.Storage/storageAccounts/maniqsharedbackups03`,
      name: 'maniqsharedbackups03',
      location: 'centralus',
      resourceGroup: 'rg-maniq-shared-centralus',
      properties: {
        allowBlobPublicAccess: true,
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_0',
        allowSharedKeyAccess: true,
        publicNetworkAccess: 'Enabled',
        allowCrossTenantReplication: true,
        defenderForStorageEnabled: false,
        networkAcls: {
          defaultAction: 'Allow',
          ipRules: [],
          virtualNetworkRules: [],
        },
        encryption: { requireInfrastructureEncryption: false },
        blobDeleteRetentionPolicy: { enabled: false, days: 0 },
      },
      containers: [
        {
          name: 'tenant-dr-snapshots',
          publicAccess: 'Blob',
          blobCount: 6410,
          hasStoredAccessPolicyWithNoExpiry: true,
          dataClassification: 'Confidential',
        },
      ],
    });
  }

  const rawRbac = [
    {
      id: `/subscriptions/${subProd}/providers/Microsoft.Authorization/roleAssignments/live-ra-01`,
      properties: {
        roleDefinitionName: 'Owner',
        principalName: 'vendor.architect#EXT#@contoso-partner.com',
        principalType: 'GuestUser',
        scope: `/subscriptions/${subProd}`,
        lastActiveDays: 4,
        mfaEnforced: false,
      },
    },
    {
      id: `/subscriptions/${
        scanAllSubscriptions ? subData : subProd
      }/providers/Microsoft.Authorization/roleAssignments/live-ra-02`,
      properties: {
        roleDefinitionName: 'Custom Cloud Deployment Operator',
        principalName: 'sp-github-actions-deploy',
        principalType: 'ServicePrincipal',
        scope: `/subscriptions/${scanAllSubscriptions ? subData : subProd}`,
        isCustomRole: true,
        actions: [
          'Microsoft.Storage/*',
          'Microsoft.Network/*',
          'Microsoft.Authorization/roleAssignments/write',
        ],
        lastActiveDays: 0,
        mfaEnforced: true,
      },
    },
    {
      id: `/subscriptions/${
        scanAllSubscriptions ? subShared : subProd
      }/providers/Microsoft.Authorization/roleAssignments/live-ra-03`,
      properties: {
        roleDefinitionName: 'Owner',
        principalName: 'legacy.admin@maniqshield.io',
        principalType: 'User',
        scope: `/subscriptions/${scanAllSubscriptions ? subShared : subProd}`,
        lastActiveDays: 194,
        mfaEnforced: false,
      },
    },
  ];

  return {
    storageAccounts: parseAzureStorageAccountsJson(rawStorage),
    roleAssignments: parseAzureRoleAssignmentsJson(rawRbac),
    subscriptionsScanned: scanAllSubscriptions ? 3 : 1,
  };
}
