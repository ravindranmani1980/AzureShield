/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { AuditMetrics, Finding } from '../types/security';

/**
 * Creates high-resolution chart images on an off-screen HTML5 canvas
 * to embed directly into the PDF report as visual aids.
 */
export function generateVisualAidsCanvas(
  metrics: AuditMetrics,
  findings: Finding[]
): {
  severityChartDataUrl: string;
  categoryChartDataUrl: string;
} {
  // 1. Severity Distribution Donut / Bar Chart
  const sevCanvas = document.createElement('canvas');
  sevCanvas.width = 700;
  sevCanvas.height = 340;
  const ctx = sevCanvas.getContext('2d');

  if (ctx) {
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, sevCanvas.width, sevCanvas.height);

    // Title
    ctx.fillStyle = '#0F172A';
    ctx.font = 'bold 20px sans-serif';
    ctx.fillText('Finding Severity Distribution', 30, 36);

    const data = [
      { label: 'Critical', count: metrics.criticalCount, color: '#DC2626' },
      { label: 'High', count: metrics.highCount, color: '#EA580C' },
      { label: 'Medium', count: metrics.mediumCount, color: '#D97706' },
      { label: 'Low', count: metrics.lowCount, color: '#2563EB' },
    ];

    const total = Math.max(1, metrics.totalFindings);
    const centerX = 160;
    const centerY = 190;
    const outerRadius = 110;
    const innerRadius = 65;

    let startAngle = -0.5 * Math.PI;

    if (metrics.totalFindings === 0) {
      // Draw 100% clean green circle
      ctx.beginPath();
      ctx.arc(centerX, centerY, outerRadius, 0, 2 * Math.PI);
      ctx.fillStyle = '#10B981';
      ctx.fill();

      ctx.beginPath();
      ctx.arc(centerX, centerY, innerRadius, 0, 2 * Math.PI);
      ctx.fillStyle = '#FFFFFF';
      ctx.fill();

      ctx.fillStyle = '#0F172A';
      ctx.font = 'bold 16px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('CLEAN', centerX, centerY + 6);
    } else {
      data.forEach((item) => {
        if (item.count > 0) {
          const sliceAngle = (item.count / total) * 2 * Math.PI;
          ctx.beginPath();
          ctx.arc(centerX, centerY, outerRadius, startAngle, startAngle + sliceAngle);
          ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
          ctx.closePath();
          ctx.fillStyle = item.color;
          ctx.fill();
          startAngle += sliceAngle;
        }
      });

      // Center score
      ctx.textAlign = 'center';
      ctx.fillStyle = '#0F172A';
      ctx.font = 'bold 26px sans-serif';
      ctx.fillText(`${metrics.postureScore}`, centerX, centerY + 4);
      ctx.fillStyle = '#64748B';
      ctx.font = '12px sans-serif';
      ctx.fillText('/ 100 Posture', centerX, centerY + 22);
    }

    // Legend & breakdown table on right
    ctx.textAlign = 'left';
    let legendY = 95;
    data.forEach((item) => {
      // Swatch
      ctx.fillStyle = item.color;
      ctx.beginPath();
      ctx.roundRect ? ctx.roundRect(340, legendY - 14, 18, 18, 4) : ctx.fillRect(340, legendY - 14, 18, 18);
      ctx.fill();

      // Label & Count
      ctx.fillStyle = '#1E293B';
      ctx.font = 'bold 16px sans-serif';
      ctx.fillText(item.label, 375, legendY);

      const percent = total > 0 ? Math.round((item.count / total) * 100) : 0;
      ctx.fillStyle = '#475569';
      ctx.font = '14px sans-serif';
      ctx.fillText(`${item.count} issues (${percent}%)`, 500, legendY);

      legendY += 50;
    });
  }

  // 2. Misconfiguration Category & Frequency Bar Chart
  const catCanvas = document.createElement('canvas');
  catCanvas.width = 700;
  catCanvas.height = 340;
  const cctx = catCanvas.getContext('2d');

  if (cctx) {
    cctx.fillStyle = '#FFFFFF';
    cctx.fillRect(0, 0, catCanvas.width, catCanvas.height);

    // Title
    cctx.fillStyle = '#0F172A';
    cctx.font = 'bold 20px sans-serif';
    cctx.fillText('Misconfigurations by Domain & Frequency', 30, 36);

    const categories = [
      {
        name: 'Storage Buckets & Containers',
        count: findings.filter((f) => f.category === 'storage').length,
        color: '#0284C7',
      },
      {
        name: 'RBAC & Overly Permissive Roles',
        count: findings.filter((f) => f.category === 'rbac').length,
        color: '#7C3AED',
      },
      {
        name: 'Privilege Escalation Risks',
        count: findings.filter((f) => f.category === 'privilege_escalation').length,
        color: '#DC2626',
      },
      {
        name: 'Network Perimeter & Firewalls',
        count: findings.filter((f) => f.category === 'network').length,
        color: '#F59E0B',
      },
      {
        name: 'Encryption & Deprecated TLS',
        count: findings.filter((f) => f.category === 'encryption').length,
        color: '#0D9488',
      },
    ];

    const maxCount = Math.max(1, ...categories.map((c) => c.count));
    const startY = 75;
    const barHeight = 26;
    const maxBarWidth = 350;

    categories.forEach((cat, idx) => {
      const y = startY + idx * 50;

      // Label
      cctx.fillStyle = '#1E293B';
      cctx.font = '13px sans-serif';
      cctx.textAlign = 'left';
      cctx.fillText(cat.name, 30, y + 17);

      // Bar track
      const barX = 240;
      cctx.fillStyle = '#F1F5F9';
      cctx.beginPath();
      cctx.roundRect ? cctx.roundRect(barX, y, maxBarWidth, barHeight, 6) : cctx.fillRect(barX, y, maxBarWidth, barHeight);
      cctx.fill();

      // Active bar
      const barWidth = Math.max(12, Math.round((cat.count / maxCount) * maxBarWidth));
      if (cat.count > 0) {
        cctx.fillStyle = cat.color;
        cctx.beginPath();
        cctx.roundRect ? cctx.roundRect(barX, y, barWidth, barHeight, 6) : cctx.fillRect(barX, y, barWidth, barHeight);
        cctx.fill();
      }

      // Count badge
      cctx.fillStyle = '#0F172A';
      cctx.font = 'bold 14px sans-serif';
      cctx.textAlign = 'left';
      cctx.fillText(`${cat.count}`, barX + maxBarWidth + 18, y + 18);
    });
  }

  return {
    severityChartDataUrl: sevCanvas.toDataURL('image/png'),
    categoryChartDataUrl: catCanvas.toDataURL('image/png'),
  };
}

export interface PdfReportOptions {
  subscriptionName?: string;
  subscriptionId?: string;
  auditorName?: string;
  website?: string;
  notes?: string;
}

export function generateAzureSecurityPdfReport(
  findings: Finding[],
  metrics: AuditMetrics,
  options: PdfReportOptions = {}
): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const authorName = options.auditorName || 'Mani Ravindran';
  const website = options.website || 'ravidnran.in';

  doc.setProperties({
    title: 'AzureShield Security Audit Report',
    author: `${authorName} (${website})`,
    subject: 'Azure Storage & RBAC Loophole Assessment with Remediation Runbooks',
    keywords: 'Azure, Storage, RBAC, IAM, CSPM, CIS Benchmark, ravidnran.in',
    creator: `${authorName} - https://${website}`,
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const auditDate = new Date().toLocaleString();
  const subId = options.subscriptionId || 'c4b8e219-94fc-4809-b6bb-2a1e8a93ef01';
  const subName = options.subscriptionName || 'Azure Production Workloads (East US)';

  // -------------------------------------------------------------
  // PAGE 1: COVER & EXECUTIVE SUMMARY
  // -------------------------------------------------------------

  // Top Azure Blue Brand Header Bar
  doc.setFillColor(0, 120, 212); // Azure Blue #0078D4
  doc.rect(0, 0, pageWidth, 28, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text('AzureShield — Cloud Security Loophole Assessment', 14, 13);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`Confidential CSPM Audit Report • Author: ${authorName} • https://${website}`, 14, 21);

  // Metadata block
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Assessment Scope & Auditor Information', 14, 38);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105);
  doc.text(`Subscription: ${subName} (${subId})`, 14, 44);
  doc.text(`Lead Auditor / Author: ${authorName} • Website: https://${website}`, 14, 49);
  doc.text(`Audit Timestamp: ${auditDate} • Frameworks: CIS Azure 2.0, MCSB, NIST 800-53`, 14, 54);

  // Posture Score & Metrics Cards
  const scoreBoxY = 60;
  
  // Card 1: Security Posture Score
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(14, scoreBoxY, 55, 32, 3, 3, 'FD');

  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  doc.text('SECURITY POSTURE SCORE', 18, scoreBoxY + 7);

  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  if (metrics.postureScore >= 80) doc.setTextColor(16, 185, 129);
  else if (metrics.postureScore >= 60) doc.setTextColor(245, 158, 11);
  else doc.setTextColor(220, 38, 38);
  doc.text(`${metrics.postureScore}/100`, 18, scoreBoxY + 18);

  doc.setFontSize(9);
  doc.setTextColor(71, 85, 105);
  doc.text(`Risk Grade: ${metrics.riskGrade}`, 18, scoreBoxY + 26);

  // Card 2: Critical / High Loopholes
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(74, scoreBoxY, 55, 32, 3, 3, 'FD');

  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 116, 139);
  doc.text('CRITICAL & HIGH DEFECTS', 78, scoreBoxY + 7);

  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(220, 38, 38);
  doc.text(`${metrics.criticalCount + metrics.highCount}`, 78, scoreBoxY + 18);

  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105);
  doc.text(`${metrics.criticalCount} Critical | ${metrics.highCount} High`, 78, scoreBoxY + 26);

  // Card 3: Storage & RBAC Split
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(134, scoreBoxY, 62, 32, 3, 3, 'FD');

  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 116, 139);
  doc.text('KEY ATTACK VECTORS', 138, scoreBoxY + 7);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text(`Open Storage Buckets: ${metrics.openBucketCount}`, 138, scoreBoxY + 16);
  doc.text(`Privilege Escalations: ${metrics.privilegeEscalationCount}`, 138, scoreBoxY + 22);
  doc.text(`Dormant RBAC Roles: ${metrics.inactiveRoleCount}`, 138, scoreBoxY + 28);

  // Embed Visual Aids Charts
  const visualAids = generateVisualAidsCanvas(metrics, findings);

  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Executive Visual Analytics', 14, 102);

  // Embed Severity Chart (Left/Top)
  doc.addImage(visualAids.severityChartDataUrl, 'PNG', 14, 106, 88, 43);
  // Embed Category Chart (Right/Top)
  doc.addImage(visualAids.categoryChartDataUrl, 'PNG', 106, 106, 90, 43);

  // Compliance Benchmark Scorecards
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Compliance Framework Alignment', 14, 158);

  autoTable(doc, {
    startY: 162,
    head: [['Framework', 'Standard Version', 'Passing Rate', 'Status']],
    body: [
      ['CIS Microsoft Azure Foundations Benchmark', 'v2.0.0', `${metrics.complianceScores.cisAzure}%`, metrics.complianceScores.cisAzure >= 80 ? 'Compliant' : 'Needs Remediation'],
      ['Microsoft Cloud Security Benchmark (MCSB)', 'v1.0', `${metrics.complianceScores.mcsb}%`, metrics.complianceScores.mcsb >= 80 ? 'Compliant' : 'Needs Remediation'],
      ['NIST SP 800-53 Rev. 5 Access Control & Protection', 'Rev 5', `${metrics.complianceScores.nist}%`, metrics.complianceScores.nist >= 80 ? 'Compliant' : 'Action Required'],
    ],
    theme: 'grid',
    headStyles: { fillColor: [0, 120, 212], textColor: 255, fontSize: 8.5 },
    styles: { fontSize: 8, cellPadding: 2.2 },
    columnStyles: {
      2: { fontStyle: 'bold', halign: 'center' },
      3: { fontStyle: 'bold', halign: 'center' },
    },
  });

  // Executive Summary Narrative
  const afterTableY = (doc as any).lastAutoTable?.finalY ? (doc as any).lastAutoTable.finalY + 8 : 195;
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Executive Summary & Risk Assessment', 14, afterTableY);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(51, 65, 85);
  const narrative = [
    `This assessment identified ${metrics.totalFindings} security misconfiguration(s) across storage assets and role-based access control (RBAC).`,
    `Specifically, ${metrics.openBucketCount} storage asset(s) are actively configured with anonymous public access or lack network perimeter restrictions, creating exposure to unauthenticated data exfiltration.`,
    `In the identity domain, ${metrics.rbacFindingCount + metrics.privilegeEscalationCount} finding(s) involve overly permissive role assignments, external guest privilege escalation, or inactive accounts.`,
    `Immediate priority should be given to resolving CRITICAL findings using the attached remediation runbooks.`,
  ];
  doc.text(narrative, 14, afterTableY + 6, { maxWidth: pageWidth - 28, lineHeightFactor: 1.4 });

  // -------------------------------------------------------------
  // PAGE 2: INVENTORY TABLE OF FINDINGS
  // -------------------------------------------------------------
  doc.addPage();

  // Page Header
  doc.setFillColor(241, 245, 249);
  doc.rect(0, 0, pageWidth, 16, 'F');
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text('Findings Inventory Register (Storage & RBAC)', 14, 11);

  const findingsTableRows = findings.map((f) => [
    f.severity,
    f.category.toUpperCase().replace('_', ' '),
    f.resourceName,
    f.title,
    f.compliance.cisAzure ? `CIS ${f.compliance.cisAzure}` : 'MCSB',
  ]);

  autoTable(doc, {
    startY: 22,
    head: [['Severity', 'Category', 'Target Resource', 'Finding Title', 'Benchmark']],
    body: findingsTableRows,
    theme: 'striped',
    headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 8 },
    styles: { fontSize: 7.5, cellPadding: 2 },
    columnStyles: {
      0: { fontStyle: 'bold', halign: 'center', cellWidth: 20 },
      1: { cellWidth: 28 },
      2: { cellWidth: 38 },
      3: { cellWidth: 75 },
      4: { halign: 'center', cellWidth: 20 },
    },
    didParseCell: (data) => {
      if (data.column.index === 0 && data.section === 'body') {
        const text = String(data.cell.raw);
        if (text === 'CRITICAL') {
          data.cell.styles.textColor = [220, 38, 38];
        } else if (text === 'HIGH') {
          data.cell.styles.textColor = [234, 88, 12];
        } else if (text === 'MEDIUM') {
          data.cell.styles.textColor = [217, 119, 6];
        } else {
          data.cell.styles.textColor = [37, 99, 235];
        }
      }
    },
  });

  // -------------------------------------------------------------
  // PAGE 3+: ACTIONABLE REMEDIATION RUNBOOKS
  // -------------------------------------------------------------
  doc.addPage();

  doc.setFillColor(0, 120, 212);
  doc.rect(0, 0, pageWidth, 16, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text('Detailed Actionable Remediation Runbooks', 14, 11);

  let curY = 24;

  findings.forEach((finding, index) => {
    // Check if we need a new page
    if (curY > pageHeight - 65) {
      doc.addPage();
      curY = 20;
    }

    // Header bar for each finding
    const isCrit = finding.severity === 'CRITICAL';
    const isHigh = finding.severity === 'HIGH';

    doc.setFillColor(isCrit ? 254 : isHigh ? 255 : 248, isCrit ? 242 : isHigh ? 247 : 250, isCrit ? 242 : isHigh ? 237 : 252);
    doc.setDrawColor(isCrit ? 252 : isHigh ? 253 : 226, isCrit ? 165 : isHigh ? 186 : 232, isCrit ? 165 : isHigh ? 116 : 240);
    doc.roundedRect(14, curY, pageWidth - 28, 10, 2, 2, 'FD');

    // Severity tag
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(isCrit ? 220 : isHigh ? 234 : 217, isCrit ? 38 : isHigh ? 88 : 119, isCrit ? 38 : isHigh ? 12 : 6);
    doc.text(`[${finding.severity}]`, 18, curY + 6.5);

    // Title
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(`#${index + 1} ${finding.title}`, 38, curY + 6.5);

    curY += 14;

    // Resource & exploit scenario
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    doc.text(`Resource: ${finding.resourceName} (${finding.resourceType}) | Category: ${finding.category.toUpperCase()}`, 16, curY);
    curY += 5;

    doc.setFont('helvetica', 'italic');
    doc.setTextColor(100, 116, 139);
    doc.text(`Threat Mechanics: ${finding.exploitScenario.substring(0, 140)}...`, 16, curY, { maxWidth: pageWidth - 32 });
    curY += 7;

    // Remediation Steps
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text('Actionable Remediation:', 16, curY);
    curY += 4.5;

    // Azure CLI Command in Monospace Box
    doc.setFillColor(15, 23, 42); // Dark terminal background
    const cliHeight = 13;
    doc.roundedRect(16, curY, pageWidth - 32, cliHeight, 2, 2, 'F');

    doc.setTextColor(147, 197, 253); // Light blue terminal text
    doc.setFont('courier', 'normal');
    doc.setFontSize(7);
    const cliLines = doc.splitTextToSize(finding.remediation.cliCommand, pageWidth - 38);
    doc.text(cliLines.slice(0, 2), 20, curY + 5);

    curY += cliHeight + 4;

    // Portal Steps
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    const portalSummary = finding.remediation.portalSteps.slice(0, 2).join(' -> ');
    doc.text(`Portal Walkthrough: ${portalSummary}`, 16, curY, { maxWidth: pageWidth - 32 });
    curY += 6;

    // Impact
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(180, 83, 9);
    doc.text(`Notice: ${finding.remediation.impactNotice}`, 16, curY, { maxWidth: pageWidth - 32 });
    curY += 9;
  });

  // Footer on all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `AzureShield Security Report • Author: ${authorName} (https://${website}) • Confidential • ${auditDate}`,
      14,
      pageHeight - 6
    );
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - 28, pageHeight - 6);
  }

  return doc;
}
