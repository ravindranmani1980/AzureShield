/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import {
  Network,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Database,
  Server,
  Globe,
  ChevronRight,
  Lock,
  Unlock,
  KeyRound,
  Filter,
} from 'lucide-react';
import {
  Finding,
  RbacAssignment,
  Severity,
  StorageAccount,
  StorageContainer,
} from '../types/security';

export type GraphNodeType =
  | 'identity'
  | 'anonymous'
  | 'storage_account'
  | 'container';

export interface AccessGraphNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  subLabel: string;
  nodeType: GraphNodeType;
  riskLevel: Severity;
  column: number; // 0 = Identity/Threat, 1 = Storage Account, 2 = Container
  badges: string[];
  findingsCount: number;
  findingIds: string[];
  metadata: {
    principalType?: string;
    roleName?: string;
    scope?: string;
    mfaEnforced?: boolean;
    isExternalGuest?: boolean;
    lastActiveDays?: number;
    resourceGroup?: string;
    location?: string;
    tlsVersion?: string;
    httpsOnly?: boolean;
    publicAccess?: string;
    blobCount?: number;
    dataClassification?: string;
    perpetualSas?: boolean;
    parentAccount?: string;
  };
}

export interface AccessGraphLink
  extends d3.SimulationLinkDatum<AccessGraphNode> {
  id: string;
  source: string | AccessGraphNode;
  target: string | AccessGraphNode;
  relationLabel: string;
  pathCategory:
    | 'anonymous_breach'
    | 'privileged_rbac'
    | 'data_plane'
    | 'container_mount'
    | 'standard_rbac';
  isVulnerable: boolean;
  riskSeverity: Severity;
  description: string;
}

interface StorageAccessGraphD3Props {
  storageAccounts: StorageAccount[];
  roleAssignments: RbacAssignment[];
  findings: Finding[];
  selectedAccountName: string;
  onSelectAccount?: (accountName: string) => void;
  onSelectFinding: (findingId: string) => void;
}

export const StorageAccessGraphD3: React.FC<StorageAccessGraphD3Props> = ({
  storageAccounts,
  roleAssignments,
  findings,
  selectedAccountName,
  onSelectAccount,
  onSelectFinding,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(
    null
  );

  const [scopeMode, setScopeMode] = useState<'all' | 'selected'>('all');
  const [onlyRiskyPaths, setOnlyRiskyPaths] = useState<boolean>(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [simulationTick, setSimulationTick] = useState<number>(0);

  // Build nodes and links from storageAccounts, containers, and roleAssignments
  const { nodes, links, summaryStats } = useMemo(() => {
    const graphNodes: AccessGraphNode[] = [];
    const graphLinks: AccessGraphLink[] = [];

    const activeAccounts =
      scopeMode === 'selected' && selectedAccountName
        ? storageAccounts.filter((a) => a.name === selectedAccountName)
        : storageAccounts;

    const accountsToRender =
      activeAccounts.length > 0 ? activeAccounts : storageAccounts;

    // Track if any container is publicly accessible while its parent account allows public access
    let hasPublicExposure = false;

    // 1. Add Storage Account & Container Nodes
    accountsToRender.forEach((acc) => {
      const accFindings = findings.filter(
        (f) =>
          f.resourceId === acc.id ||
          f.resourceName === acc.name ||
          f.resourceName.startsWith(`${acc.name}/`)
      );

      const hasCritical = accFindings.some((f) => f.severity === 'CRITICAL');
      const hasHigh = accFindings.some((f) => f.severity === 'HIGH');
      const accRisk: Severity = hasCritical
        ? 'CRITICAL'
        : hasHigh
        ? 'HIGH'
        : accFindings.length > 0
        ? 'MEDIUM'
        : 'LOW';

      const accNodeId = `sa:${acc.name}`;
      const accBadges: string[] = [
        acc.minimumTlsVersion.replace('_', ' '),
        acc.supportsHttpsTrafficOnly ? 'HTTPS' : 'HTTP Allowed',
      ];
      if (acc.allowBlobPublicAccess) {
        accBadges.push('Public Blob Enabled');
      }
      if (acc.defaultAction === 'Allow') {
        accBadges.push('Firewall Open');
      } else {
        accBadges.push('Firewall Deny');
      }

      graphNodes.push({
        id: accNodeId,
        label: acc.name,
        subLabel: `Storage Account · ${acc.location}`,
        nodeType: 'storage_account',
        riskLevel: accRisk,
        column: 1,
        badges: accBadges,
        findingsCount: accFindings.length,
        findingIds: accFindings.map((f) => f.id),
        metadata: {
          resourceGroup: acc.resourceGroup,
          location: acc.location,
          tlsVersion: acc.minimumTlsVersion,
          httpsOnly: acc.supportsHttpsTrafficOnly,
          publicAccess: acc.allowBlobPublicAccess ? 'Enabled' : 'Disabled',
        },
      });

      // Add Container Nodes for this Storage Account
      acc.containers.forEach((cont: StorageContainer) => {
        const contNodeId = `cont:${acc.name}/${cont.name}`;
        const contFindings = findings.filter(
          (f) =>
            f.resourceName === `${acc.name}/${cont.name}` ||
            f.resourceId.endsWith(`/containers/${cont.name}`) ||
            f.id.includes(cont.name)
        );

        const isAnonExposed =
          acc.allowBlobPublicAccess && cont.publicAccess !== 'None';
        if (isAnonExposed) {
          hasPublicExposure = true;
        }

        const contRisk: Severity =
          cont.publicAccess === 'Container' && acc.allowBlobPublicAccess
            ? 'CRITICAL'
            : (cont.publicAccess === 'Blob' && acc.allowBlobPublicAccess) ||
              cont.hasStoredAccessPolicyWithNoExpiry
            ? 'HIGH'
            : contFindings.length > 0
            ? 'MEDIUM'
            : 'LOW';

        const contBadges: string[] = [
          cont.publicAccess === 'None'
            ? 'Private'
            : `Public (${cont.publicAccess})`,
        ];
        if (cont.dataClassification) {
          contBadges.push(cont.dataClassification);
        }
        if (cont.hasStoredAccessPolicyWithNoExpiry) {
          contBadges.push('No-Expiry SAS');
        }

        graphNodes.push({
          id: contNodeId,
          label: cont.name,
          subLabel: `${acc.name} · ${(cont.blobCount || 0).toLocaleString()} blobs`,
          nodeType: 'container',
          riskLevel: contRisk,
          column: 2,
          badges: contBadges,
          findingsCount: contFindings.length,
          findingIds: contFindings.map((f) => f.id),
          metadata: {
            parentAccount: acc.name,
            publicAccess: cont.publicAccess,
            blobCount: cont.blobCount || 0,
            dataClassification: cont.dataClassification || 'Internal',
            perpetualSas: cont.hasStoredAccessPolicyWithNoExpiry,
          },
        });

        // Link Storage Account -> Container
        const isLinkVulnerable =
          isAnonExposed || cont.hasStoredAccessPolicyWithNoExpiry;

        graphLinks.push({
          id: `link:${accNodeId}->${contNodeId}`,
          source: accNodeId,
          target: contNodeId,
          relationLabel: isAnonExposed
            ? `PUBLIC ${cont.publicAccess.toUpperCase()}`
            : cont.hasStoredAccessPolicyWithNoExpiry
            ? 'PERPETUAL SAS'
            : 'PRIVATE ACL',
          pathCategory: isAnonExposed ? 'anonymous_breach' : 'container_mount',
          isVulnerable: isLinkVulnerable,
          riskSeverity: contRisk,
          description: isAnonExposed
            ? `Storage account '${acc.name}' permits public blob access and container '${cont.name}' allows anonymous ${cont.publicAccess} reads.`
            : cont.hasStoredAccessPolicyWithNoExpiry
            ? `Container '${cont.name}' has a stored access policy with no expiration timestamp.`
            : `Container '${cont.name}' is private and enforces authenticated access.`,
        });
      });
    });

    // 2. Add Anonymous Threat Node if any container is publicly exposed
    if (hasPublicExposure) {
      const anonNodeId = 'anon:internet';
      const anonFindings = findings.filter(
        (f) => f.id.includes('PUB-ACCESS') || f.id.includes('EXPOSED')
      );

      graphNodes.push({
        id: anonNodeId,
        label: 'Anonymous Internet',
        subLabel: 'Unauthenticated Public Access',
        nodeType: 'anonymous',
        riskLevel: 'CRITICAL',
        column: 0,
        badges: ['No Token Required', 'Public Enumeration'],
        findingsCount: anonFindings.length,
        findingIds: anonFindings.map((f) => f.id),
        metadata: {
          principalType: 'Anonymous Public Internet',
          roleName: 'Anonymous Blob/Container Reader',
          scope: 'Public Endpoint (blob.core.windows.net)',
          mfaEnforced: false,
          isExternalGuest: true,
        },
      });

      accountsToRender.forEach((acc) => {
        const exposedContainers = acc.containers.filter(
          (c) => acc.allowBlobPublicAccess && c.publicAccess !== 'None'
        );
        if (exposedContainers.length > 0) {
          const accNodeId = `sa:${acc.name}`;
          graphLinks.push({
            id: `link:${anonNodeId}->${accNodeId}`,
            source: anonNodeId,
            target: accNodeId,
            relationLabel: 'ANONYMOUS HTTP/S',
            pathCategory: 'anonymous_breach',
            isVulnerable: true,
            riskSeverity: 'CRITICAL',
            description: `Unauthenticated internet traffic can reach '${acc.name}' because allowBlobPublicAccess=true and network defaultAction=${acc.defaultAction}.`,
          });
        }
      });
    }

    // 3. Add RBAC Identity Nodes and compute their access paths to Storage Accounts & Containers
    roleAssignments.forEach((ra) => {
      const rbacNodeId = `rbac:${ra.id}`;
      const rbacFindings = findings.filter(
        (f) =>
          f.resourceId === ra.id ||
          f.resourceName === ra.principalName ||
          f.title.includes(ra.principalName)
      );

      const hasWildcard = ra.actions.includes('*');
      const hasStorageWrite = ra.actions.some(
        (a) =>
          a === '*' ||
          a === 'Microsoft.Storage/*' ||
          a.includes('storageAccounts/blobServices/containers/*') ||
          a.includes('storageAccounts/listKeys')
      );
      const hasDataActions =
        (ra.dataActions && ra.dataActions.length > 0) ||
        ra.roleDefinitionName.toLowerCase().includes('blob data');
      const hasPrivEsc = ra.actions.some(
        (a) =>
          a.includes('roleAssignments/write') ||
          a.includes('roleAssignments/*') ||
          a === 'Microsoft.Authorization/*'
      );

      const isCriticalRbac =
        (ra.isExternalGuest && (hasWildcard || hasStorageWrite)) ||
        hasPrivEsc ||
        (!ra.mfaEnforced && hasWildcard) ||
        rbacFindings.some((f) => f.severity === 'CRITICAL');

      const isHighRbac =
        !ra.mfaEnforced ||
        ra.lastActiveDays > 90 ||
        rbacFindings.some((f) => f.severity === 'HIGH');

      const rbacRisk: Severity = isCriticalRbac
        ? 'CRITICAL'
        : isHighRbac
        ? 'HIGH'
        : rbacFindings.length > 0
        ? 'MEDIUM'
        : 'LOW';

      const scopeShort = ra.scope.includes('/resourceGroups/')
        ? `RG: ${ra.scope.split('/resourceGroups/')[1]?.split('/')[0]}`
        : 'Subscription Scope';

      const identityBadges: string[] = [ra.roleDefinitionName, scopeShort];
      if (ra.isExternalGuest) identityBadges.push('External #EXT#');
      if (!ra.mfaEnforced) identityBadges.push('No MFA');
      if (hasPrivEsc) identityBadges.push('PrivEsc Risk');
      if (ra.lastActiveDays > 90)
        identityBadges.push(`Dormant ${ra.lastActiveDays}d`);

      // Determine which rendered storage accounts this RBAC identity can access
      const accessibleAccounts = accountsToRender.filter((acc) => {
        if (ra.scope.includes('/storageAccounts/')) {
          return ra.scope.endsWith(`/storageAccounts/${acc.name}`);
        }
        if (ra.scope.includes('/resourceGroups/')) {
          const rgName = ra.scope.split('/resourceGroups/')[1]?.split('/')[0];
          return (
            rgName?.toLowerCase() === acc.resourceGroup.toLowerCase() ||
            accountsToRender.length === 1
          );
        }
        // Subscription or Management Group scope applies to all storage accounts in the subscription
        return true;
      });

      if (accessibleAccounts.length === 0) return;

      graphNodes.push({
        id: rbacNodeId,
        label: ra.principalName.split('@')[0],
        subLabel: `${ra.principalType} · ${ra.roleDefinitionName}`,
        nodeType: 'identity',
        riskLevel: rbacRisk,
        column: 0,
        badges: identityBadges,
        findingsCount: rbacFindings.length,
        findingIds: rbacFindings.map((f) => f.id),
        metadata: {
          principalType: ra.principalType,
          roleName: ra.roleDefinitionName,
          scope: ra.scope,
          mfaEnforced: ra.mfaEnforced,
          isExternalGuest: ra.isExternalGuest,
          lastActiveDays: ra.lastActiveDays,
        },
      });

      accessibleAccounts.forEach((acc) => {
        const accNodeId = `sa:${acc.name}`;
        const isVulnerablePath =
          isCriticalRbac || isHighRbac || (hasWildcard && !ra.mfaEnforced);

        let relationLabel = ra.roleDefinitionName;
        if (hasPrivEsc) {
          relationLabel = 'PRIV-ESC + STORAGE*';
        } else if (ra.isExternalGuest && hasWildcard) {
          relationLabel = 'GUEST OWNER (*)';
        } else if (hasDataActions) {
          relationLabel = 'BLOB DATA OWNER';
        } else if (hasWildcard) {
          relationLabel = `${ra.roleDefinitionName.toUpperCase()} (*)`;
        }

        graphLinks.push({
          id: `link:${rbacNodeId}->${accNodeId}`,
          source: rbacNodeId,
          target: accNodeId,
          relationLabel,
          pathCategory: isCriticalRbac
            ? 'privileged_rbac'
            : hasDataActions
            ? 'data_plane'
            : 'standard_rbac',
          isVulnerable: isVulnerablePath,
          riskSeverity: rbacRisk,
          description: `${ra.principalName} (${ra.principalType}) holds '${ra.roleDefinitionName}' at ${scopeShort}, granting ${
            hasWildcard
              ? 'full control/management key access'
              : hasDataActions
              ? 'direct data-plane blob read/write access'
              : 'scoped control-plane access'
          } over '${acc.name}'.`,
        });

        // If this identity has direct data-plane blob permissions or critical guest owner access,
        // also show direct data-plane access paths to high-value containers when focused or when dataActions exist
        if (hasDataActions) {
          acc.containers.forEach((cont) => {
            const contNodeId = `cont:${acc.name}/${cont.name}`;
            graphLinks.push({
              id: `link:${rbacNodeId}->${contNodeId}`,
              source: rbacNodeId,
              target: contNodeId,
              relationLabel: 'DATA-PLANE BLOB R/W',
              pathCategory: 'data_plane',
              isVulnerable: !ra.mfaEnforced || ra.isExternalGuest,
              riskSeverity: rbacRisk,
              description: `${ra.principalName} has dataActions (${
                ra.dataActions[0] || 'containers/blobs/*'
              }) allowing direct blob read/write in container '${cont.name}'${
                !ra.mfaEnforced ? ' without MFA enforcement' : ''
              }.`,
            });
          });
        }
      });
    });

    // Filter if onlyRiskyPaths is enabled
    const filteredLinks = onlyRiskyPaths
      ? graphLinks.filter((l) => l.isVulnerable)
      : graphLinks;

    const connectedNodeIds = new Set<string>();
    filteredLinks.forEach((l) => {
      connectedNodeIds.add(
        typeof l.source === 'string' ? l.source : l.source.id
      );
      connectedNodeIds.add(
        typeof l.target === 'string' ? l.target : l.target.id
      );
    });

    const filteredNodes = onlyRiskyPaths
      ? graphNodes.filter(
          (n) => connectedNodeIds.has(n.id) || n.nodeType === 'storage_account'
        )
      : graphNodes;

    const stats = {
      identitiesCount: filteredNodes.filter(
        (n) => n.nodeType === 'identity' || n.nodeType === 'anonymous'
      ).length,
      storageCount: filteredNodes.filter(
        (n) => n.nodeType === 'storage_account'
      ).length,
      containersCount: filteredNodes.filter((n) => n.nodeType === 'container')
        .length,
      vulnerablePathsCount: filteredLinks.filter((l) => l.isVulnerable).length,
      totalPathsCount: filteredLinks.length,
    };

    return {
      nodes: filteredNodes,
      links: filteredLinks,
      summaryStats: stats,
    };
  }, [
    storageAccounts,
    roleAssignments,
    findings,
    scopeMode,
    selectedAccountName,
    onlyRiskyPaths,
  ]);

  // Select default node when graph updates
  useEffect(() => {
    if (
      !selectedNodeId ||
      !nodes.some((n) => n.id === selectedNodeId)
    ) {
      const targetSa = nodes.find(
        (n) => n.id === `sa:${selectedAccountName}`
      );
      setSelectedNodeId(targetSa?.id || nodes[0]?.id || null);
    }
  }, [nodes, selectedAccountName, selectedNodeId]);

  // Render D3 Force-Directed Layered Node-Link Diagram
  useEffect(() => {
    if (!svgRef.current) return;

    const width = 880;
    const height = 500;

    // Clone nodes and links so D3 can mutate x/y coordinates safely
    const simNodes: AccessGraphNode[] = nodes.map((n) => ({ ...n }));
    const simLinks: AccessGraphLink[] = links.map((l) => ({ ...l }));

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Definitions: Arrow markers & subtle glow filters
    const defs = svg.append('defs');

    const markerConfigs = [
      { id: 'arrow-critical', color: '#ef4444' },
      { id: 'arrow-high', color: '#f97316' },
      { id: 'arrow-data', color: '#38bdf8' },
      { id: 'arrow-secure', color: '#10b981' },
      { id: 'arrow-neutral', color: '#64748b' },
    ];

    markerConfigs.forEach((m) => {
      defs
        .append('marker')
        .attr('id', m.id)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 28)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', m.color);
    });

    // Subtle background column guides
    const bgGroup = svg.append('g').attr('class', 'canvas-guides');
    const colPositions = [
      { col: 0, x: 155, title: 'RBAC IDENTITIES & PRINCIPALS' },
      { col: 1, x: 445, title: 'AZURE STORAGE ACCOUNTS' },
      { col: 2, x: 730, title: 'BLOB CONTAINERS & DATA PLANE' },
    ];

    colPositions.forEach((colInfo) => {
      bgGroup
        .append('rect')
        .attr('x', colInfo.x - 115)
        .attr('y', 14)
        .attr('width', 230)
        .attr('height', height - 28)
        .attr('rx', 14)
        .attr('fill', '#020617')
        .attr('fill-opacity', 0.45)
        .attr('stroke', '#1e293b')
        .attr('stroke-dasharray', '4 4')
        .attr('stroke-width', 1);

      bgGroup
        .append('text')
        .attr('x', colInfo.x)
        .attr('y', 34)
        .attr('text-anchor', 'middle')
        .attr('fill', '#64748b')
        .attr('font-size', '10px')
        .attr('font-weight', '700')
        .attr('letter-spacing', '0.08em')
        .text(colInfo.title);
    });

    // Main zoomable viewport group
    const g = svg.append('g').attr('class', 'graph-viewport');

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.55, 2.4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    zoomBehaviorRef.current = zoom;
    svg.call(zoom);

    // Compute initial vertical spacing per column so layout starts clean and legible
    [0, 1, 2].forEach((colIndex) => {
      const colNodes = simNodes.filter((n) => n.column === colIndex);
      const spacing = (height - 90) / Math.max(1, colNodes.length);
      colNodes.forEach((node, idx) => {
        node.x = colPositions[colIndex].x;
        node.y = 75 + spacing * (idx + 0.5);
      });
    });

    // D3 Force Simulation combining column alignment with organic node-link physics
    const simulation = d3
      .forceSimulation<AccessGraphNode>(simNodes)
      .force(
        'link',
        d3
          .forceLink<AccessGraphNode, AccessGraphLink>(simLinks)
          .id((d) => d.id)
          .distance((link) =>
            link.pathCategory === 'data_plane' ? 260 : 210
          )
          .strength(0.35)
      )
      .force('charge', d3.forceManyBody().strength(-260))
      .force('collide', d3.forceCollide().radius(46).iterations(2))
      .force(
        'x',
        d3
          .forceX<AccessGraphNode>((d) => colPositions[d.column].x)
          .strength(0.88)
      )
      .force(
        'y',
        d3
          .forceY<AccessGraphNode>((d) => d.y || height / 2)
          .strength(0.32)
      );

    // Helper for link colors
    const getLinkColor = (d: AccessGraphLink) => {
      if (d.pathCategory === 'anonymous_breach') return '#ef4444';
      if (d.isVulnerable && d.riskSeverity === 'CRITICAL') return '#ef4444';
      if (d.isVulnerable && d.riskSeverity === 'HIGH') return '#f97316';
      if (d.pathCategory === 'data_plane') return '#38bdf8';
      if (!d.isVulnerable) return '#10b981';
      return '#64748b';
    };

    const getMarkerUrl = (d: AccessGraphLink) => {
      if (
        d.pathCategory === 'anonymous_breach' ||
        (d.isVulnerable && d.riskSeverity === 'CRITICAL')
      ) {
        return 'url(#arrow-critical)';
      }
      if (d.isVulnerable && d.riskSeverity === 'HIGH') {
        return 'url(#arrow-high)';
      }
      if (d.pathCategory === 'data_plane') {
        return 'url(#arrow-data)';
      }
      if (!d.isVulnerable) {
        return 'url(#arrow-secure)';
      }
      return 'url(#arrow-neutral)';
    };

    // Draw Links (Curved cubic bezier paths)
    const linkGroup = g.append('g').attr('class', 'links');

    const linkElements = linkGroup
      .selectAll('path')
      .data(simLinks)
      .join('path')
      .attr('fill', 'none')
      .attr('stroke', (d) => getLinkColor(d))
      .attr('stroke-width', (d) => (d.isVulnerable ? 2.4 : 1.6))
      .attr('stroke-dasharray', (d) =>
        d.pathCategory === 'anonymous_breach'
          ? '6 4'
          : d.pathCategory === 'data_plane'
          ? '3 3'
          : 'none'
      )
      .attr('stroke-opacity', (d) => (d.isVulnerable ? 0.88 : 0.55))
      .attr('marker-end', (d) => getMarkerUrl(d));

    // Link edge labels (pill tags along midpoint)
    const linkLabelGroup = g.append('g').attr('class', 'link-labels');

    const linkLabelElements = linkLabelGroup
      .selectAll('g')
      .data(simLinks)
      .join('g')
      .style('pointer-events', 'none');

    linkLabelElements
      .append('rect')
      .attr('rx', 4)
      .attr('ry', 4)
      .attr('x', -52)
      .attr('y', -8)
      .attr('width', 104)
      .attr('height', 15)
      .attr('fill', '#090d16')
      .attr('fill-opacity', 0.9)
      .attr('stroke', (d) => getLinkColor(d))
      .attr('stroke-opacity', 0.45)
      .attr('stroke-width', 0.8);

    linkLabelElements
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 2.5)
      .attr('fill', (d) =>
        d.isVulnerable
          ? d.riskSeverity === 'CRITICAL'
            ? '#fca5a5'
            : '#fdba74'
          : d.pathCategory === 'data_plane'
          ? '#7dd3fc'
          : '#6ee7b7'
      )
      .attr('font-size', '8.5px')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .attr('font-weight', '600')
      .text((d) =>
        d.relationLabel.length > 18
          ? `${d.relationLabel.slice(0, 16)}..`
          : d.relationLabel
      );

    // Draw Nodes
    const nodeGroup = g.append('g').attr('class', 'nodes');

    const getNodeStroke = (d: AccessGraphNode) => {
      if (d.nodeType === 'anonymous') return '#ef4444';
      if (d.riskLevel === 'CRITICAL') return '#ef4444';
      if (d.riskLevel === 'HIGH') return '#f97316';
      if (d.riskLevel === 'MEDIUM') return '#eab308';
      return '#10b981';
    };

    const getNodeFill = (d: AccessGraphNode) => {
      if (d.nodeType === 'anonymous') return '#450a0a';
      if (d.nodeType === 'storage_account') return '#0f172a';
      if (d.nodeType === 'container') return '#091526';
      return '#111827';
    };

    const nodeElements = nodeGroup
      .selectAll<SVGGElement, AccessGraphNode>('g')
      .data(simNodes)
      .join('g')
      .style('cursor', 'pointer')
      .call(
        d3
          .drag<SVGGElement, AccessGraphNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.25).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on('click', (_event, d) => {
        setSelectedNodeId(d.id);
        if (d.nodeType === 'storage_account' && onSelectAccount) {
          onSelectAccount(d.label);
        } else if (
          d.nodeType === 'container' &&
          d.metadata.parentAccount &&
          onSelectAccount
        ) {
          onSelectAccount(d.metadata.parentAccount);
        }
      })
      .on('mouseenter', (_event, d) => {
        setHoveredNodeId(d.id);
      })
      .on('mouseleave', () => {
        setHoveredNodeId(null);
      });

    // Outer Halo ring for Critical/Selected nodes
    nodeElements
      .append('circle')
      .attr('class', 'node-halo')
      .attr('r', (d) => (d.nodeType === 'storage_account' ? 28 : 23))
      .attr('fill', 'none')
      .attr('stroke', (d) => getNodeStroke(d))
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', (d) =>
        d.riskLevel === 'CRITICAL' ? 0.55 : 0.18
      )
      .attr('stroke-dasharray', (d) =>
        d.riskLevel === 'CRITICAL' ? '3 2' : 'none'
      );

    // Main Node Circle
    nodeElements
      .append('circle')
      .attr('class', 'node-circle')
      .attr('r', (d) => (d.nodeType === 'storage_account' ? 22 : 18))
      .attr('fill', (d) => getNodeFill(d))
      .attr('stroke', (d) => getNodeStroke(d))
      .attr('stroke-width', 2.2);

    // Node Type Glyph inside Circle
    nodeElements
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 4)
      .attr('fill', (d) =>
        d.riskLevel === 'CRITICAL'
          ? '#fca5a5'
          : d.nodeType === 'storage_account'
          ? '#60a5fa'
          : d.nodeType === 'container'
          ? '#38bdf8'
          : '#cbd5e1'
      )
      .attr('font-size', (d) =>
        d.nodeType === 'storage_account' ? '11px' : '9.5px'
      )
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .attr('font-weight', '700')
      .text((d) => {
        if (d.nodeType === 'anonymous') return 'PUB';
        if (d.nodeType === 'storage_account') return 'SA';
        if (d.nodeType === 'container') return 'BLOB';
        if (d.metadata.principalType === 'ServicePrincipal') return 'SP';
        if (d.metadata.principalType === 'GuestUser') return 'EXT';
        if (d.metadata.principalType === 'Group') return 'GRP';
        return 'IAM';
      });

    // Findings Count Badge on top-right of Node Circle
    const badgeNodes = nodeElements.filter((d) => d.findingsCount > 0);

    badgeNodes
      .append('circle')
      .attr('cx', (d) => (d.nodeType === 'storage_account' ? 16 : 13))
      .attr('cy', (d) => (d.nodeType === 'storage_account' ? -16 : -13))
      .attr('r', 8)
      .attr('fill', (d) =>
        d.riskLevel === 'CRITICAL' ? '#dc2626' : '#ea580c'
      )
      .attr('stroke', '#020617')
      .attr('stroke-width', 1.5);

    badgeNodes
      .append('text')
      .attr('x', (d) => (d.nodeType === 'storage_account' ? 16 : 13))
      .attr('y', (d) => (d.nodeType === 'storage_account' ? -13 : -10))
      .attr('text-anchor', 'middle')
      .attr('fill', '#ffffff')
      .attr('font-size', '8.5px')
      .attr('font-weight', '700')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .text((d) => d.findingsCount);

    // Node Primary Label
    nodeElements
      .append('text')
      .attr('y', (d) => (d.nodeType === 'storage_account' ? 36 : 31))
      .attr('text-anchor', 'middle')
      .attr('fill', '#f8fafc')
      .attr('font-size', '11px')
      .attr('font-weight', '700')
      .text((d) =>
        d.label.length > 22 ? `${d.label.slice(0, 20)}…` : d.label
      );

    // Node Sub-Label
    nodeElements
      .append('text')
      .attr('y', (d) => (d.nodeType === 'storage_account' ? 49 : 43))
      .attr('text-anchor', 'middle')
      .attr('fill', '#94a3b8')
      .attr('font-size', '9.5px')
      .text((d) =>
        d.subLabel.length > 28 ? `${d.subLabel.slice(0, 26)}…` : d.subLabel
      );

    // Simulation tick handler
    simulation.on('tick', () => {
      // Constrain nodes inside canvas bounds
      simNodes.forEach((d) => {
        d.x = Math.max(75, Math.min(width - 75, d.x || width / 2));
        d.y = Math.max(60, Math.min(height - 55, d.y || height / 2));
      });

      linkElements.attr('d', (d) => {
        const src = d.source as AccessGraphNode;
        const tgt = d.target as AccessGraphNode;
        const x1 = src.x || 0;
        const y1 = src.y || 0;
        const x2 = tgt.x || 0;
        const y2 = tgt.y || 0;
        const dx = (x2 - x1) * 0.45;
        return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
      });

      linkLabelElements.attr('transform', (d) => {
        const src = d.source as AccessGraphNode;
        const tgt = d.target as AccessGraphNode;
        const mx = ((src.x || 0) + (tgt.x || 0)) / 2;
        const my = ((src.y || 0) + (tgt.y || 0)) / 2;
        return `translate(${mx}, ${my})`;
      });

      nodeElements.attr('transform', (d) => `translate(${d.x || 0}, ${d.y || 0})`);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, links, simulationTick]);

  // Update node/link highlight opacities on hover or selection without resetting simulation
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const activeFocusId = hoveredNodeId || selectedNodeId;

    if (!activeFocusId) {
      svg.selectAll('.nodes g').attr('opacity', 1);
      svg.selectAll('.links path').attr('opacity', 1);
      svg.selectAll('.link-labels g').attr('opacity', 1);
      return;
    }

    const neighborIds = new Set<string>([activeFocusId]);
    links.forEach((l) => {
      const sId = typeof l.source === 'string' ? l.source : l.source.id;
      const tId = typeof l.target === 'string' ? l.target : l.target.id;
      if (sId === activeFocusId) neighborIds.add(tId);
      if (tId === activeFocusId) neighborIds.add(sId);
    });

    svg
      .selectAll<SVGGElement, AccessGraphNode>('.nodes g')
      .attr('opacity', (d) => (neighborIds.has(d.id) ? 1 : 0.25));

    svg
      .selectAll<SVGPathElement, AccessGraphLink>('.links path')
      .attr('opacity', (d) => {
        const sId = typeof d.source === 'string' ? d.source : d.source.id;
        const tId = typeof d.target === 'string' ? d.target : d.target.id;
        return sId === activeFocusId || tId === activeFocusId ? 1 : 0.14;
      });

    svg
      .selectAll<SVGGElement, AccessGraphLink>('.link-labels g')
      .attr('opacity', (d) => {
        const sId = typeof d.source === 'string' ? d.source : d.source.id;
        const tId = typeof d.target === 'string' ? d.target : d.target.id;
        return sId === activeFocusId || tId === activeFocusId ? 1 : 0.12;
      });
  }, [hoveredNodeId, selectedNodeId, links]);

  // Zoom controls
  const handleZoom = (factor: number) => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(200)
      .call(zoomBehaviorRef.current.scaleBy, factor);
  };

  const handleResetView = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(250)
      .call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
    setSimulationTick((t) => t + 1);
  };

  // Selected node details and its connected links/findings
  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) || nodes[0] || null,
    [nodes, selectedNodeId]
  );

  const selectedNodeLinks = useMemo(() => {
    if (!selectedNode) return [];
    return links.filter((l) => {
      const sId = typeof l.source === 'string' ? l.source : l.source.id;
      const tId = typeof l.target === 'string' ? l.target : l.target.id;
      return sId === selectedNode.id || tId === selectedNode.id;
    });
  }, [links, selectedNode]);

  const selectedNodeFindings = useMemo(() => {
    if (!selectedNode) return [];
    return findings.filter((f) => selectedNode.findingIds.includes(f.id));
  }, [findings, selectedNode]);

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
      {/* Top Toolbar */}
      <div className="px-5 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-50">
        <div className="flex items-start space-x-3">
          <div className="p-2.5 rounded-lg bg-[#0E2238] text-[#5FD3BF] border border-[#2BB5A0]/30 mt-0.5">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-serif text-base font-bold text-[#16232F]">
                Interactive Access Path & Blast-Radius Topology (D3 Force Graph)
              </h3>
              <span className="text-xs text-[#546471] font-mono tabular-nums">
                {summaryStats.identitiesCount} Identities ·{' '}
                {summaryStats.storageCount} Storage Accounts ·{' '}
                {summaryStats.containersCount} Containers ·{' '}
                {summaryStats.vulnerablePathsCount} Vulnerable Paths
              </span>
            </div>
            <p className="text-xs text-[#546471] mt-0.5">
              Drag nodes to rearrange, scroll or click controls to zoom, and select any node to inspect effective RBAC permissions and container exposure paths.
            </p>
          </div>
        </div>

        {/* Interactive Graph Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Scope Segmented Control */}
          <div className="flex items-center bg-white p-1 rounded-lg border border-slate-200">
            <button
              type="button"
              onClick={() => setScopeMode('all')}
              className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-colors whitespace-nowrap ${
                scopeMode === 'all'
                  ? 'bg-[#0E2238] text-white'
                  : 'text-[#546471] hover:text-[#16232F]'
              }`}
            >
              All Storage Accounts ({storageAccounts.length})
            </button>
            <button
              type="button"
              onClick={() => setScopeMode('selected')}
              className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-colors whitespace-nowrap ${
                scopeMode === 'selected'
                  ? 'bg-[#0E2238] text-white'
                  : 'text-[#546471] hover:text-[#16232F]'
              }`}
            >
              Focus: {selectedAccountName}
            </button>
          </div>

          {/* Vulnerable Path Filter */}
          <button
            type="button"
            onClick={() => setOnlyRiskyPaths(!onlyRiskyPaths)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors whitespace-nowrap ${
              onlyRiskyPaths
                ? 'bg-red-50 text-red-700 border-red-200'
                : 'bg-white text-[#546471] border-slate-200 hover:bg-slate-100'
            }`}
          >
            <Filter className="w-3.5 h-3.5" />
            <span>{onlyRiskyPaths ? 'Vulnerable Paths Only' : 'All Access Paths'}</span>
          </button>

          {/* Zoom & Reset Buttons */}
          <div className="flex items-center bg-white rounded-lg border border-slate-200 p-0.5">
            <button
              type="button"
              onClick={() => handleZoom(1.25)}
              title="Zoom In"
              className="p-1.5 text-[#546471] hover:text-[#16232F] rounded-md hover:bg-slate-100 transition-colors"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => handleZoom(0.8)}
              title="Zoom Out"
              className="p-1.5 text-[#546471] hover:text-[#16232F] rounded-md hover:bg-slate-100 transition-colors"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={handleResetView}
              title="Reset Layout & Zoom"
              className="p-1.5 text-[#546471] hover:text-[#16232F] rounded-md hover:bg-slate-100 transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Split View: D3 SVG Canvas (Left 8 cols) + Selected Node Access Inspector (Right 4 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12">
        {/* Left: D3 SVG Canvas */}
        <div
          ref={containerRef}
          className="lg:col-span-8 relative bg-[#081420] border-b lg:border-b-0 lg:border-r border-slate-200 flex flex-col justify-between"
        >
          <svg
            ref={svgRef}
            viewBox="0 0 880 500"
            className="w-full h-[440px] sm:h-[480px] select-none"
          />

          {/* Graph Legend Bar */}
          <div className="px-4 py-2.5 bg-[#0D1C2D] border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-[11px] text-[#B7C3CC]">
            <div className="flex flex-wrap items-center gap-4">
              <span className="flex items-center space-x-1.5">
                <span className="w-3 h-0.5 bg-red-500 inline-block" />
                <span>Critical / Anonymous Breach Path</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-3 h-0.5 bg-orange-500 inline-block" />
                <span>High-Risk Overprivileged RBAC</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-3 h-0.5 bg-sky-400 inline-block" />
                <span>Data-Plane Blob Role</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-3 h-0.5 bg-[#2BB5A0] inline-block" />
                <span>Hardened / Least-Privilege Path</span>
              </span>
            </div>
            <span className="font-mono text-[10px] text-[#7D8C99]">
              Click any node to inspect access vectors
            </span>
          </div>
        </div>

        {/* Right: Selected Node & Access Path Inspector */}
        <div className="lg:col-span-4 p-5 bg-white flex flex-col justify-between space-y-4 max-h-[530px] overflow-y-auto">
          {selectedNode ? (
            <div className="space-y-4">
              {/* Selected Node Header */}
              <div className="pb-3 border-b border-slate-200">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[11px] font-mono text-[#546471]">
                    {selectedNode.nodeType === 'storage_account'
                      ? 'Azure Storage Account'
                      : selectedNode.nodeType === 'container'
                      ? 'Azure Blob Container'
                      : selectedNode.nodeType === 'anonymous'
                      ? 'Unauthenticated Threat Vector'
                      : 'Entra ID / RBAC Identity'}
                  </span>
                  <span
                    className={`text-[11px] font-bold font-mono ${
                      selectedNode.riskLevel === 'CRITICAL'
                        ? 'text-red-700'
                        : selectedNode.riskLevel === 'HIGH'
                        ? 'text-orange-700'
                        : selectedNode.riskLevel === 'MEDIUM'
                        ? 'text-amber-700'
                        : 'text-[#1F8A79]'
                    }`}
                  >
                    {selectedNode.riskLevel} RISK
                  </span>
                </div>

                <div className="flex items-center space-x-2.5">
                  {selectedNode.nodeType === 'storage_account' ? (
                    <Server className="w-5 h-5 text-[#1F8A79] flex-shrink-0" />
                  ) : selectedNode.nodeType === 'container' ? (
                    <Database className="w-5 h-5 text-[#2BB5A0] flex-shrink-0" />
                  ) : selectedNode.nodeType === 'anonymous' ? (
                    <Globe className="w-5 h-5 text-red-600 flex-shrink-0" />
                  ) : (
                    <UserCheck className="w-5 h-5 text-[#0E2238] flex-shrink-0" />
                  )}
                  <h4 className="font-serif text-base font-bold text-[#16232F] truncate">
                    {selectedNode.label}
                  </h4>
                </div>
                <p className="text-xs text-[#546471] mt-1">
                  {selectedNode.subLabel}
                </p>

                {/* Unboxed metadata attributes */}
                <div className="mt-2.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-[#546471] font-mono">
                  {selectedNode.badges.map((b, i) => (
                    <React.Fragment key={b}>
                      {i > 0 && (
                        <span className="text-slate-300" aria-hidden="true">
                          ·
                        </span>
                      )}
                      <span>{b}</span>
                    </React.Fragment>
                  ))}
                </div>
              </div>

              {/* Node-Specific Security Properties */}
              <div className="space-y-2 text-xs">
                <div className="text-[#546471] font-semibold">
                  Configuration & Posture Context
                </div>
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5 font-mono text-[11px]">
                  {selectedNode.nodeType === 'identity' ||
                  selectedNode.nodeType === 'anonymous' ? (
                    <>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Role Definition:</span>
                        <span className="text-[#16232F] font-semibold">
                          {selectedNode.metadata.roleName}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Principal Type:</span>
                        <span className="text-[#16232F]">
                          {selectedNode.metadata.principalType}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">MFA Enforcement:</span>
                        <span
                          className={
                            selectedNode.metadata.mfaEnforced
                              ? 'text-[#1F8A79] font-semibold'
                              : 'text-red-700 font-semibold'
                          }
                        >
                          {selectedNode.metadata.mfaEnforced
                            ? 'Enforced'
                            : 'Not Enforced'}
                        </span>
                      </div>
                      {selectedNode.metadata.lastActiveDays !== undefined && (
                        <div className="flex justify-between">
                          <span className="text-[#546471]">Last Activity:</span>
                          <span className="text-[#16232F] tabular-nums">
                            {selectedNode.metadata.lastActiveDays} days ago
                          </span>
                        </div>
                      )}
                    </>
                  ) : selectedNode.nodeType === 'storage_account' ? (
                    <>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Resource Group:</span>
                        <span className="text-[#16232F]">
                          {selectedNode.metadata.resourceGroup}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Public Blob ACL:</span>
                        <span
                          className={
                            selectedNode.metadata.publicAccess === 'Enabled'
                              ? 'text-red-700 font-semibold'
                              : 'text-[#1F8A79] font-semibold'
                          }
                        >
                          {selectedNode.metadata.publicAccess}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Minimum TLS:</span>
                        <span className="text-[#16232F]">
                          {selectedNode.metadata.tlsVersion}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">HTTPS Transfer:</span>
                        <span
                          className={
                            selectedNode.metadata.httpsOnly
                              ? 'text-[#1F8A79] font-semibold'
                              : 'text-red-700 font-semibold'
                          }
                        >
                          {selectedNode.metadata.httpsOnly
                            ? 'Required'
                            : 'HTTP Permitted'}
                        </span>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Parent Account:</span>
                        <span className="text-[#16232F]">
                          {selectedNode.metadata.parentAccount}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Anonymous Access:</span>
                        <span
                          className={
                            selectedNode.metadata.publicAccess !== 'None'
                              ? 'text-red-700 font-semibold'
                              : 'text-[#1F8A79] font-semibold'
                          }
                        >
                          {selectedNode.metadata.publicAccess}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Classification:</span>
                        <span className="text-[#16232F]">
                          {selectedNode.metadata.dataClassification}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#546471]">Stored Blobs:</span>
                        <span className="text-[#16232F] tabular-nums">
                          {selectedNode.metadata.blobCount?.toLocaleString()}
                        </span>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Connected Access Paths (Edges) */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#546471] font-semibold">
                    Connected Access Paths ({selectedNodeLinks.length})
                  </span>
                </div>
                <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                  {selectedNodeLinks.map((link) => {
                    const srcId =
                      typeof link.source === 'string'
                        ? link.source
                        : link.source.id;
                    const tgtId =
                      typeof link.target === 'string'
                        ? link.target
                        : link.target.id;
                    const peerId =
                      srcId === selectedNode.id ? tgtId : srcId;
                    const peerNode = nodes.find((n) => n.id === peerId);

                    return (
                      <button
                        key={link.id}
                        type="button"
                        onClick={() => peerNode && setSelectedNodeId(peerNode.id)}
                        className="w-full text-left p-2.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors space-y-1"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-[#16232F] truncate flex items-center space-x-1.5">
                            {link.isVulnerable ? (
                              <Unlock className="w-3.5 h-3.5 text-red-600 flex-shrink-0" />
                            ) : (
                              <Lock className="w-3.5 h-3.5 text-[#1F8A79] flex-shrink-0" />
                            )}
                            <span className="truncate">
                              {peerNode?.label || peerId}
                            </span>
                          </span>
                          <span
                            className={`text-[10px] font-mono font-semibold ${
                              link.isVulnerable
                                ? 'text-red-700'
                                : 'text-[#1F8A79]'
                            }`}
                          >
                            {link.relationLabel}
                          </span>
                        </div>
                        <p className="text-[11px] text-[#546471] leading-snug">
                          {link.description}
                        </p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Associated Security Findings Drill-Down */}
              <div className="space-y-2">
                <div className="text-xs text-[#546471] font-semibold">
                  Associated Security Findings ({selectedNodeFindings.length})
                </div>
                {selectedNodeFindings.length === 0 ? (
                  <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-[#1F8A79] font-medium flex items-center space-x-2">
                    <ShieldCheck className="w-4 h-4 flex-shrink-0" />
                    <span>No open security findings on this node.</span>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {selectedNodeFindings.slice(0, 3).map((finding) => (
                      <div
                        key={finding.id}
                        className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="flex items-center space-x-1.5 text-[10px] font-mono">
                            <span
                              className={
                                finding.severity === 'CRITICAL'
                                  ? 'text-red-700 font-bold'
                                  : 'text-orange-700 font-bold'
                              }
                            >
                              {finding.severity}
                            </span>
                            {finding.compliance.cisAzure && (
                              <>
                                <span className="text-slate-300">·</span>
                                <span className="text-[#546471]">
                                  CIS {finding.compliance.cisAzure}
                                </span>
                              </>
                            )}
                          </div>
                          <div className="text-xs font-semibold text-[#16232F] truncate">
                            {finding.title}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => onSelectFinding(finding.id)}
                          className="px-2.5 py-1 rounded-md bg-[#0E2238] hover:bg-[#15314E] text-white text-[11px] font-semibold flex items-center space-x-1 whitespace-nowrap shrink-0"
                        >
                          <span>Runbook</span>
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-[#546471] text-xs">
              Select a node in the D3 topology graph to inspect its access paths and security findings.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
