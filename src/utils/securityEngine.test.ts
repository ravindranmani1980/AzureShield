/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditStorageAccount,
  auditRbacAssignment,
  executeFullAudit,
} from './securityEngine';
import { StorageAccount, RbacAssignment } from '../types/security';

test('detects public blob access loophole on storage account', () => {
  const account: StorageAccount = {
    id: '/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/proddata01',
    name: 'proddata01',
    resourceGroup: 'rg-prod',
    subscriptionId: 'sub-1',
    location: 'eastus',
    allowBlobPublicAccess: true, // Vulnerable
    publicNetworkAccess: 'Enabled',
    defaultAction: 'Allow',
    ipRulesCount: 0,
    virtualNetworkRulesCount: 0,
    privateEndpointConnectionsCount: 0,
    supportsHttpsTrafficOnly: true,
    minimumTlsVersion: 'TLS1_2',
    allowSharedKeyAccess: false,
    infrastructureEncryption: true,
    customerManagedKeyEnabled: true,
    softDeleteEnabled: true,
    blobRetentionDays: 30,
    versioningEnabled: true,
    loggingEnabled: true,
    containers: [],
  };

  const findings = auditStorageAccount(account);
  const publicAccessFinding = findings.find((f) => f.id.includes('PUB-ACCESS'));
  assert.ok(publicAccessFinding, 'Expected to find public blob access finding');
  assert.equal(publicAccessFinding?.severity, 'CRITICAL');
  assert.ok(publicAccessFinding?.remediation.cliCommand.includes('--allow-blob-public-access false'));
});

test('detects insecure HTTP traffic and legacy TLS 1.0', () => {
  const account: StorageAccount = {
    id: '/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/legacystor',
    name: 'legacystor',
    resourceGroup: 'rg-prod',
    subscriptionId: 'sub-1',
    location: 'eastus',
    allowBlobPublicAccess: false,
    publicNetworkAccess: 'Disabled',
    defaultAction: 'Deny',
    ipRulesCount: 1,
    virtualNetworkRulesCount: 0,
    privateEndpointConnectionsCount: 1,
    supportsHttpsTrafficOnly: false, // Insecure HTTP
    minimumTlsVersion: 'TLS1_0', // Legacy TLS
    allowSharedKeyAccess: false,
    infrastructureEncryption: true,
    customerManagedKeyEnabled: false,
    softDeleteEnabled: true,
    blobRetentionDays: 14,
    versioningEnabled: true,
    loggingEnabled: true,
    containers: [],
  };

  const findings = auditStorageAccount(account);
  const httpFinding = findings.find((f) => f.id.includes('INSECURE-HTTP'));
  assert.ok(httpFinding, 'Expected insecure HTTP finding');
  assert.equal(httpFinding?.severity, 'CRITICAL');

  const tlsFinding = findings.find((f) => f.id.includes('LEGACY-TLS'));
  assert.ok(tlsFinding, 'Expected legacy TLS finding');
  assert.equal(tlsFinding?.severity, 'HIGH');
});

test('detects overprivileged Owner role at subscription scope', () => {
  const assignment: RbacAssignment = {
    id: 'assign-1',
    principalId: 'user-1',
    principalName: 'Dev Contractor',
    principalType: 'User',
    roleDefinitionName: 'Owner',
    roleDefinitionId: '8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
    scope: '/subscriptions/1111-2222-3333', // Broad subscription scope
    isCustomRole: false,
    actions: ['*'],
    notActions: [],
    dataActions: [],
    lastActiveDays: 12,
    mfaEnforced: true,
    isExternalGuest: false,
    assignedDate: '2025-01-15',
  };

  const findings = auditRbacAssignment(assignment);
  const ownerFinding = findings.find((f) => f.id.includes('SUB-OWNER'));
  assert.ok(ownerFinding, 'Expected finding for subscription-wide Owner');
  assert.equal(ownerFinding?.severity, 'CRITICAL');
});

test('detects external guest user with elevated administrative role', () => {
  const guestAssignment: RbacAssignment = {
    id: 'assign-2',
    principalId: 'guest-1',
    principalName: 'external_vendor#EXT#@partner.com',
    principalType: 'GuestUser',
    roleDefinitionName: 'Contributor',
    roleDefinitionId: 'b24988ac-6180-42a0-ab88-20f7382dd24c',
    scope: '/subscriptions/1111/resourceGroups/rg-prod',
    isCustomRole: false,
    actions: ['*'],
    notActions: ['Microsoft.Authorization/*/Delete'],
    dataActions: [],
    lastActiveDays: 5,
    mfaEnforced: false,
    isExternalGuest: true,
    assignedDate: '2025-03-01',
  };

  const findings = auditRbacAssignment(guestAssignment);
  const guestFinding = findings.find((f) => f.id.includes('GUEST-ELEVATED'));
  assert.ok(guestFinding, 'Expected critical finding for external guest with elevated permissions');
  assert.equal(guestFinding?.severity, 'CRITICAL');
});

test('detects privilege escalation loophole via roleAssignments/write', () => {
  const customRoleAssignment: RbacAssignment = {
    id: 'assign-3',
    principalId: 'user-3',
    principalName: 'Junior DevOps Operator',
    principalType: 'User',
    roleDefinitionName: 'Custom Storage Deployer',
    roleDefinitionId: 'custom-role-99',
    scope: '/subscriptions/1111/resourceGroups/rg-prod',
    isCustomRole: true,
    actions: [
      'Microsoft.Storage/storageAccounts/*',
      'Microsoft.Authorization/roleAssignments/write', // Escalation loophole!
    ],
    notActions: [],
    dataActions: [],
    lastActiveDays: 1,
    mfaEnforced: true,
    isExternalGuest: false,
    assignedDate: '2025-02-10',
  };

  const findings = auditRbacAssignment(customRoleAssignment);
  const privEscFinding = findings.find((f) => f.category === 'privilege_escalation');
  assert.ok(privEscFinding, 'Expected privilege escalation finding');
  assert.equal(privEscFinding?.severity, 'CRITICAL');
  assert.ok(privEscFinding?.privilegeEscalationPath?.includes('roleAssignments/write'));
});

test('detects inactive / dormant accounts (>90 days)', () => {
  const dormantAssignment: RbacAssignment = {
    id: 'assign-4',
    principalId: 'user-4',
    principalName: 'Former Tech Lead',
    principalType: 'User',
    roleDefinitionName: 'Contributor',
    roleDefinitionId: 'b24988ac-6180-42a0-ab88-20f7382dd24c',
    scope: '/subscriptions/1111/resourceGroups/rg-legacy',
    isCustomRole: false,
    actions: ['*'],
    notActions: [],
    dataActions: [],
    lastActiveDays: 140, // Inactive > 90 days!
    mfaEnforced: true,
    isExternalGuest: false,
    assignedDate: '2024-06-01',
  };

  const findings = auditRbacAssignment(dormantAssignment);
  const dormantFinding = findings.find((f) => f.id.includes('DORMANT'));
  assert.ok(dormantFinding, 'Expected dormant role assignment finding');
  assert.equal(dormantFinding?.severity, 'MEDIUM');
});

test('calculates correct posture score and metrics', () => {
  const storages: StorageAccount[] = [
    {
      id: 'stor-1',
      name: 'securestorage',
      resourceGroup: 'rg-prod',
      subscriptionId: 'sub-1',
      location: 'eastus',
      allowBlobPublicAccess: false,
      publicNetworkAccess: 'Disabled',
      defaultAction: 'Deny',
      ipRulesCount: 1,
      virtualNetworkRulesCount: 1,
      privateEndpointConnectionsCount: 1,
      supportsHttpsTrafficOnly: true,
      minimumTlsVersion: 'TLS1_2',
      allowSharedKeyAccess: false,
      infrastructureEncryption: true,
      customerManagedKeyEnabled: true,
      softDeleteEnabled: true,
      blobRetentionDays: 30,
      versioningEnabled: true,
      loggingEnabled: true,
      containers: [
        {
          id: 'c-1',
          name: 'safe-container',
          publicAccess: 'None',
          hasStoredAccessPolicyWithNoExpiry: false,
          sasTokenIssuedWithFullPermissions: false,
          immutabilityPolicyEnabled: true,
        },
      ],
    },
  ];

  const rbac: RbacAssignment[] = [
    {
      id: 'r-1',
      principalId: 'p-1',
      principalName: 'Read-Only Auditor',
      principalType: 'User',
      roleDefinitionName: 'Reader',
      roleDefinitionId: 'acdd72a7-3385-48ef-bd42-f606fba81ae7',
      scope: '/subscriptions/sub-1/resourceGroups/rg-prod',
      isCustomRole: false,
      actions: ['*/read'],
      notActions: [],
      dataActions: [],
      lastActiveDays: 2,
      mfaEnforced: true,
      isExternalGuest: false,
      assignedDate: '2025-01-01',
    },
  ];

  const result = executeFullAudit(storages, rbac);
  assert.equal(result.findings.length, 0);
  assert.equal(result.metrics.postureScore, 100);
  assert.equal(result.metrics.riskGrade, 'A+');
});
