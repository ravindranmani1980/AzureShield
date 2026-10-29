/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type VulnerabilityCategory =
  | 'storage'
  | 'rbac'
  | 'privilege_escalation'
  | 'network'
  | 'encryption';

export interface StorageContainer {
  id: string;
  name: string;
  publicAccess: 'None' | 'Blob' | 'Container';
  hasStoredAccessPolicyWithNoExpiry: boolean;
  sasTokenIssuedWithFullPermissions: boolean;
  immutabilityPolicyEnabled: boolean;
  blobCount?: number;
  dataClassification?: 'Confidential' | 'PII/Financial' | 'Internal' | 'Public';
}

export interface StorageAccount {
  id: string;
  name: string;
  resourceGroup: string;
  subscriptionId: string;
  location: string;
  allowBlobPublicAccess: boolean;
  publicNetworkAccess: 'Enabled' | 'Disabled';
  defaultAction: 'Allow' | 'Deny';
  ipRulesCount: number;
  virtualNetworkRulesCount: number;
  privateEndpointConnectionsCount: number;
  supportsHttpsTrafficOnly: boolean;
  minimumTlsVersion: 'TLS1_0' | 'TLS1_1' | 'TLS1_2' | 'TLS1_3';
  allowSharedKeyAccess: boolean;
  infrastructureEncryption: boolean;
  customerManagedKeyEnabled: boolean;
  softDeleteEnabled: boolean;
  blobRetentionDays: number;
  versioningEnabled: boolean;
  loggingEnabled: boolean;
  defenderForStorageEnabled?: boolean;
  crossTenantReplicationRestricted?: boolean;
  containers: StorageContainer[];
}

export interface RbacAssignment {
  id: string;
  principalId: string;
  principalName: string;
  principalEmail?: string;
  principalType: 'User' | 'ServicePrincipal' | 'Group' | 'GuestUser';
  roleDefinitionName: string;
  roleDefinitionId: string;
  scope: string;
  isCustomRole: boolean;
  actions: string[];
  notActions: string[];
  dataActions: string[];
  lastActiveDays: number;
  mfaEnforced: boolean;
  isExternalGuest: boolean;
  assignedDate: string;
}

export interface RemediationGuidance {
  summary: string;
  cliCommand: string;
  portalSteps: string[];
  terraformSnippet: string;
  bicepSnippet?: string;
  impactNotice: string;
}

export interface ComplianceMapping {
  cisAzure?: string;
  cisTitle?: string;
  mcsb?: string;
  nist?: string;
  iso27001?: string;
}

export interface Finding {
  id: string;
  title: string;
  category: VulnerabilityCategory;
  severity: Severity;
  resourceId: string;
  resourceName: string;
  resourceType: 'StorageAccount' | 'StorageContainer' | 'RoleAssignment' | 'RoleDefinition' | 'IAM';
  description: string;
  exploitScenario: string;
  businessImpact: string;
  compliance: ComplianceMapping;
  remediation: RemediationGuidance;
  detectedAt: string;
  isNewAlert?: boolean;
  privilegeEscalationPath?: string;
}

export interface SecurityAlert {
  id: string;
  findingId: string;
  title: string;
  severity: Severity;
  resourceName: string;
  category: VulnerabilityCategory;
  timestamp: string;
  summary: string;
  read: boolean;
}

export interface AuditMetrics {
  totalResources: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  postureScore: number; // 0 to 100
  riskGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  storageFindingCount: number;
  rbacFindingCount: number;
  privilegeEscalationCount: number;
  inactiveRoleCount: number;
  exposedContainerCount: number;
  openBucketCount: number;
  complianceScores: {
    cisAzure: number;
    mcsb: number;
    nist: number;
  };
}

export interface AuditDataset {
  presetName: string;
  description: string;
  subscriptionId: string;
  storageAccounts: StorageAccount[];
  roleAssignments: RbacAssignment[];
}
