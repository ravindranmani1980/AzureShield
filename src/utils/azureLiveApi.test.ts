/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseAzureStorageAccountsJson,
  parseAzureRoleAssignmentsJson,
} from './azureLiveApi';

test('parses raw az storage account list JSON correctly', () => {
  const rawCliStorage = [
    {
      id: '/subscriptions/1234-5678/resourceGroups/rg-live/providers/Microsoft.Storage/storageAccounts/livestorage99',
      name: 'livestorage99',
      location: 'westeurope',
      resourceGroup: 'rg-live',
      properties: {
        allowBlobPublicAccess: true,
        supportsHttpsTrafficOnly: false,
        minimumTlsVersion: 'TLS1_0',
        publicNetworkAccess: 'Enabled',
        networkAcls: {
          defaultAction: 'Allow',
          ipRules: [],
          virtualNetworkRules: [],
        },
      },
    },
  ];

  const parsed = parseAzureStorageAccountsJson(rawCliStorage);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].name, 'livestorage99');
  assert.equal(parsed[0].allowBlobPublicAccess, true);
  assert.equal(parsed[0].supportsHttpsTrafficOnly, false);
  assert.equal(parsed[0].minimumTlsVersion, 'TLS1_0');
  assert.equal(parsed[0].defaultAction, 'Allow');
});

test('parses raw az role assignment list JSON correctly', () => {
  const rawCliRbac = [
    {
      id: '/subscriptions/1234/providers/Microsoft.Authorization/roleAssignments/assign-99',
      properties: {
        roleDefinitionName: 'Owner',
        principalName: 'partner_dev#EXT#@external.com',
        principalType: 'User',
        scope: '/subscriptions/1234',
        lastActiveDays: 120,
      },
    },
  ];

  const parsed = parseAzureRoleAssignmentsJson(rawCliRbac);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].roleDefinitionName, 'Owner');
  assert.equal(parsed[0].principalType, 'GuestUser');
  assert.equal(parsed[0].isExternalGuest, true);
  assert.equal(parsed[0].lastActiveDays, 120);
});
