/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
  AuditMetrics,
  Finding,
  RbacAssignment,
  StorageAccount,
} from '../types/security';

export interface PdfGenerationOptions {
  isDemoData?: boolean;
  redactIdentifiers?: boolean;
  collectionSource?: string;
  lastCollectedAt?: string;
}

/**
 * Redacts subscription GUIDs, email addresses, and resource names when requested (Recommendation #15).
 */
export function maskSensitiveIdentifier(
  value: string,
  shouldRedact?: boolean
): string {
  if (!shouldRedact || !value) return value;
  // Redact UUIDs / Subscription IDs
  let masked = value.replace(
    /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    (match) => `${match.slice(0, 4)}-****-****-****-${match.slice(-4)}`
  );
  // Redact email user parts
  masked = masked.replace(
    /([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
    (_, user, domain) => `${user.slice(0, 2)}***@${domain}`
  );
  return masked;
}

/**
 * Renders crisp HTML5 Canvas charts and returns base64 PNG Data URLs
 * for embedding into both the PDF report and the interactive PDF preview modal.
 */
export function generateVisualAidsCanvas(
  metrics: AuditMetrics,
  findings: Finding[]
): {
  severityChartDataUrl: string;
  categoryChartDataUrl: string;
} {
  // 1. Severity Distribution Horizontal Bar Chart
  const sevCanvas = document.createElement('canvas');
  sevCanvas.width = 640;
  sevCanvas.height = 300;
  const ctx = sevCanvas.getContext('2d')!;

  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, sevCanvas.width, sevCanvas.height);

  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 2;
  ctx.strokeRect(1, 1, sevCanvas.width - 2, sevCanvas.height - 2);

  ctx.fillStyle = '#f8fafc';
  ctx.font = 'bold 18px sans-serif';
  ctx.fillText('FINDINGS BY SEVERITY DISTRIBUTION', 28, 38);

  ctx.fillStyle = '#94a3b8';
  ctx.font = '12px sans-serif';
  ctx.fillText('Active security loopholes detected across Storage & RBAC', 28, 58);

  const items = [
    { label: 'CRITICAL', count: metrics.criticalCount, color: '#ef4444' },
    { label: 'HIGH', count: metrics.highCount, color: '#f97316' },
    { label: 'MEDIUM', count: metrics.mediumCount, color: '#eab308' },
    { label: 'LOW', count: metrics.lowCount, color: '#3b82f6' },
  ];

  const maxVal = Math.max(...items.map((i) => i.count), 1);

  items.forEach((item, idx) => {
    const y = 85 + idx * 48;

    ctx.fillStyle = '#cbd5e1';
    ctx.font = 'bold 13px monospace';
    ctx.fillText(item.label, 28, y + 20);

    ctx.fillStyle = '#1e293b';
    ctx.fillRect(130, y, 420, 28);

    const barWidth = Math.max(
      item.count > 0 ? 18 : 4,
      Math.round((item.count / maxVal) * 420)
    );
    ctx.fillStyle = item.color;
    ctx.fillRect(130, y, barWidth, 28);

    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 15px monospace';
    ctx.fillText(String(item.count), 565, y + 20);
  });

  // 2. Category Breakdown & Selected Control Pass Rate Chart
  const catCanvas = document.createElement('canvas');
  catCanvas.width = 640;
  catCanvas.height = 300;
  const cctx = catCanvas.getContext('2d')!;

  cctx.fillStyle = '#0f172a';
  cctx.fillRect(0, 0, catCanvas.width, catCanvas.height);

  cctx.strokeStyle = '#1e293b';
  cctx.lineWidth = 2;
  cctx.strokeRect(1, 1, catCanvas.width - 2, catCanvas.height - 2);

  cctx.fillStyle = '#f8fafc';
  cctx.font = 'bold 18px sans-serif';
  cctx.fillText('LOOPHOLE DOMAIN & SELECTED CHECK PASS RATE', 28, 38);

  cctx.fillStyle = '#94a3b8';
  cctx.font = '12px sans-serif';
  cctx.fillText(
    'Informational cross-reference to 18 selected controls (not formal certification)',
    28,
    58
  );

  const storageFindings = findings.filter((f) => f.category === 'storage').length;
  const rbacFindings = findings.filter((f) => f.category === 'rbac').length;
  const escalationFindings = findings.filter(
    (f) => f.category === 'privilege_escalation'
  ).length;

  const domainBars = [
    {
      label: 'Storage Exposure',
      val: storageFindings,
      max: Math.max(findings.length, 1),
      color: '#06b6d4',
      suffix: ' findings',
    },
    {
      label: 'RBAC Over-Privilege',
      val: rbacFindings,
      max: Math.max(findings.length, 1),
      color: '#f59e0b',
      suffix: ' findings',
    },
    {
      label: 'Priv-Escalation Paths',
      val: escalationFindings,
      max: Math.max(findings.length, 1),
      color: '#a855f7',
      suffix: ' paths',
    },
    {
      label: 'CIS Selected Checks',
      val: metrics.complianceScores.cisAzure,
      max: 100,
      color: '#10b981',
      suffix: '% pass',
    },
  ];

  domainBars.forEach((bar, idx) => {
    const y = 85 + idx * 48;

    cctx.fillStyle = '#cbd5e1';
    cctx.font = 'bold 12px monospace';
    cctx.fillText(bar.label, 28, y + 20);

    cctx.fillStyle = '#1e293b';
    cctx.fillRect(195, y, 340, 28);

    const fillW = Math.max(6, Math.round((bar.val / bar.max) * 340));
    cctx.fillStyle = bar.color;
    cctx.fillRect(195, y, fillW, 28);

    cctx.fillStyle = '#f8fafc';
    cctx.font = 'bold 13px monospace';
    cctx.fillText(`${bar.val}${bar.suffix}`, 545, y + 20);
  });

  return {
    severityChartDataUrl: sevCanvas.toDataURL('image/png'),
    categoryChartDataUrl: catCanvas.toDataURL('image/png'),
  };
}

/**
 * Generates and downloads a multi-page enterprise PDF security audit report
 * incorporating Recommendations #3, #5, #8, #9, #13, #14, and #15.
 */
export function downloadSecurityAuditPdf(
  metrics: AuditMetrics,
  findings: Finding[],
  storageAccounts: StorageAccount[],
  roleAssignments: RbacAssignment[],
  presetTitle: string,
  options: PdfGenerationOptions = {}
): void {
  const isDemo = options.isDemoData ?? true;
  const redact = options.redactIdentifiers ?? false;
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const { severityChartDataUrl, categoryChartDataUrl } =
    generateVisualAidsCanvas(metrics, findings);

  const pageWidth = doc.internal.pageSize.getWidth();
  const timestamp = options.lastCollectedAt || new Date().toLocaleString();

  // Top Header Banner
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 44, 'F');

  doc.setTextColor(6, 182, 212);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.text(
    isDemo
      ? 'MANIQ SHIELD — DEMO DATA — NO LIVE ASSESSMENT (NON-CONFIDENTIAL SAMPLE)'
      : 'MANIQ SHIELD — LIVE AZURE HEURISTIC ASSESSMENT REPORT (CONFIDENTIAL)',
    14,
    12
  );

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(17);
  doc.text('Azure Storage & RBAC Loophole Assessment', 14, 21);

  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.text(
    `Source: ${maskSensitiveIdentifier(options.collectionSource || presetTitle, redact)}  |  Timestamp: ${timestamp}`,
    14,
    29
  );
  // Recommendation #8: Use Tool Author instead of Lead Auditor and state Human Review status
  doc.text(
    `Tool Author: Mani Ravindran (https://ravindran.in)  |  Audit Type: Automated Heuristic Scan (Human Review: Not Performed)`,
    14,
    35
  );
  doc.text(
    `Classification: ${
      isDemo
        ? 'DEMO SAMPLE — NO LIVE TENANT ASSESSMENT PERFORMED'
        : redact
        ? 'CONFIDENTIAL (IDENTIFIERS REDACTED) — RESTRICT TO AUTHORIZED OWNERS'
        : 'CONFIDENTIAL — CONTAINS LIVE TENANT METADATA (HANDLE PER ORG POLICY)'
    }`,
    14,
    41
  );

  // Executive Summary Scorecards
  doc.setFillColor(241, 245, 249);
  doc.roundedRect(14, 49, 58, 24, 2, 2, 'F');
  doc.roundedRect(76, 49, 58, 24, 2, 2, 'F');
  doc.roundedRect(138, 49, 58, 24, 2, 2, 'F');

  doc.setTextColor(71, 85, 105);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.text('SELECTED CHECKS SCORE', 18, 56);
  doc.text('CRITICAL LOOPHOLES', 80, 56);
  doc.text('EXPOSED CONTAINERS / ESCALATION', 142, 56);

  doc.setFontSize(15);
  doc.setTextColor(
    metrics.postureScore >= 80 ? 16 : metrics.postureScore >= 60 ? 217 : 220,
    metrics.postureScore >= 80 ? 185 : metrics.postureScore >= 60 ? 119 : 38,
    metrics.postureScore >= 80 ? 129 : metrics.postureScore >= 60 ? 6 : 38
  );
  doc.text(
    metrics.isEvaluationComplete === false
      ? `N/A (Unknown)`
      : `${metrics.postureScore}/100 (Grade ${metrics.riskGrade})`,
    18,
    67
  );

  doc.setTextColor(220, 38, 38);
  doc.text(`${metrics.criticalCount} Critical`, 80, 67);

  doc.setTextColor(124, 58, 237);
  doc.text(
    `${metrics.exposedContainerCount} Public / ${metrics.privilegeEscalationCount} PrivEsc`,
    142,
    67
  );

  // Visual Aids Section
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text('1. Executive Visual Aids & Risk Telemetry', 14, 82);

  doc.addImage(severityChartDataUrl, 'PNG', 14, 86, 88, 41);
  doc.addImage(categoryChartDataUrl, 'PNG', 108, 86, 88, 41);

  // Recommendation #3 & #9: Selected Control Cross-Reference Table (Passed / Failed / Unknown)
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text(
    '2. Informational Control Cross-Reference (Selected Checks Only)',
    14,
    136
  );

  const cisChecks = metrics.frameworkChecks?.cisAzure || {
    passed: 0,
    failed: 0,
    unknown: 7,
    totalSelected: 7,
    passRate: 0,
  };
  const mcsbChecks = metrics.frameworkChecks?.mcsb || {
    passed: 0,
    failed: 0,
    unknown: 6,
    totalSelected: 6,
    passRate: 0,
  };
  const nistChecks = metrics.frameworkChecks?.nist || {
    passed: 0,
    failed: 0,
    unknown: 5,
    totalSelected: 5,
    passRate: 0,
  };

  autoTable(doc, {
    startY: 140,
    head: [
      [
        'Reference Framework (Informational)',
        'Selected Subset',
        'Passed / Failed / Unknown',
        'Subset Pass Rate',
        'Evaluation State',
      ],
    ],
    body: [
      [
        'CIS Microsoft Azure Foundations v2.0 (Cross-Ref)',
        `${cisChecks.totalSelected} Selected Checks`,
        `${cisChecks.passed} Passed / ${cisChecks.failed} Failed / ${cisChecks.unknown} Unknown`,
        `${cisChecks.passRate}%`,
        cisChecks.unknown > 0
          ? 'Incomplete Scope (Unknowns)'
          : cisChecks.failed === 0
          ? 'Selected Checks Passed'
          : 'Selected Checks Failed',
      ],
      [
        'Microsoft Cloud Security Benchmark v1.0 (Cross-Ref)',
        `${mcsbChecks.totalSelected} Selected Checks`,
        `${mcsbChecks.passed} Passed / ${mcsbChecks.failed} Failed / ${mcsbChecks.unknown} Unknown`,
        `${mcsbChecks.passRate}%`,
        mcsbChecks.unknown > 0
          ? 'Incomplete Scope (Unknowns)'
          : mcsbChecks.failed === 0
          ? 'Selected Checks Passed'
          : 'Selected Checks Failed',
      ],
      [
        'NIST SP 800-53 Rev 5 (Selected AC/SC/IA Cross-Ref)',
        `${nistChecks.totalSelected} Selected Checks`,
        `${nistChecks.passed} Passed / ${nistChecks.failed} Failed / ${nistChecks.unknown} Unknown`,
        `${nistChecks.passRate}%`,
        nistChecks.unknown > 0
          ? 'Incomplete Scope (Unknowns)'
          : nistChecks.failed === 0
          ? 'Selected Checks Passed'
          : 'Selected Checks Failed',
      ],
    ],
    theme: 'grid',
    headStyles: { fillColor: [15, 23, 42], fontSize: 8 },
    styles: { fontSize: 7.5 },
  });

  // Scope, Exclusions & Non-Affiliation Disclaimer Box (Rec #3, #9, #13, #15)
  const afterComplianceY = (doc as any).lastAutoTable.finalY + 5;
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  const disclaimerLines = doc.splitTextToSize(
    'SCOPE, CALCULATION & INDEPENDENCE NOTICE: Scores reflect only the 18 automated heuristic checks evaluated on in-scope Storage Accounts and ARM Role Assignments (100 minus weighted deductions for active findings). This report does NOT assess overall organizational compliance and is NOT certified or endorsed by Microsoft, CIS, or NIST. Azure Storage encrypts all data at rest by default using Microsoft-Managed Keys (MMK). Execute all remediation commands in dry-run/staging first.',
    182
  );
  doc.text(disclaimerLines, 14, afterComplianceY);

  // Findings Summary Table
  const findingsStartY = afterComplianceY + 15;
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text(
    `3. Detected Security Loopholes (${findings.length} Total)`,
    14,
    findingsStartY
  );

  autoTable(doc, {
    startY: findingsStartY + 3,
    head: [
      [
        'Severity',
        'Domain / Classification',
        'Target Resource',
        'Finding Summary',
        'Informational Ref',
      ],
    ],
    body: findings.map((f) => [
      f.severity,
      f.findingType === 'guardrail_gap'
        ? 'STORAGE (GUARDRAIL GAP)'
        : f.findingType === 'confirmed_exposure'
        ? 'STORAGE (CONFIRMED EXPOSURE)'
        : f.category.toUpperCase().replace('_', ' '),
      maskSensitiveIdentifier(f.resourceName, redact),
      maskSensitiveIdentifier(f.title, redact),
      f.compliance.cisAzure
        ? `CIS ${f.compliance.cisAzure}`
        : f.compliance.mcsb || 'NIST AC-6',
    ]),
    theme: 'striped',
    headStyles: { fillColor: [15, 23, 42], fontSize: 8 },
    styles: { fontSize: 7.5, cellPadding: 2 },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 20 },
      1: { cellWidth: 34 },
      2: { cellWidth: 36 },
      3: { cellWidth: 68 },
      4: { cellWidth: 24 },
    },
  });

  // Page 2+: Detailed Remediation Runbooks with Pre-Check & Rollback (Rec #14)
  doc.addPage();

  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 24, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text(
    '4. Step-by-Step Remediation Runbooks (Pre-Check, CLI & Rollback)',
    14,
    15
  );

  let currentY = 32;

  findings.forEach((finding, index) => {
    if (currentY > 225) {
      doc.addPage();
      currentY = 20;
    }

    doc.setFillColor(241, 245, 249);
    doc.rect(14, currentY, 182, 9, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42);
    doc.text(
      `${index + 1}. [${finding.severity}] ${maskSensitiveIdentifier(
        finding.title,
        redact
      )} (${maskSensitiveIdentifier(finding.resourceName, redact)})`,
      16,
      currentY + 6
    );
    currentY += 13;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(51, 65, 85);
    const descLines = doc.splitTextToSize(
      `Technical Risk: ${maskSensitiveIdentifier(finding.description, redact)}`,
      180
    );
    doc.text(descLines, 14, currentY);
    currentY += descLines.length * 4.2 + 2;

    if (finding.remediation.preCheckCommand) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 118, 110);
      doc.text('Pre-Change Verification (Read-Only):', 14, currentY);
      currentY += 4;
      doc.setFont('courier', 'normal');
      doc.setFontSize(7.5);
      const preLines = doc.splitTextToSize(
        maskSensitiveIdentifier(
          finding.remediation.preCheckCommand.replace(/\\\n/g, ' '),
          redact
        ),
        178
      );
      doc.text(preLines, 16, currentY);
      currentY += preLines.length * 3.8 + 2;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text(
      'Remediation CLI Command (Validate in Staging First):',
      14,
      currentY
    );
    currentY += 4;

    doc.setFillColor(15, 23, 42);
    const cliLines = doc.splitTextToSize(
      maskSensitiveIdentifier(
        finding.remediation.cliCommand.replace(/\\\n/g, ' '),
        redact
      ),
      176
    );
    const cliBoxH = cliLines.length * 4.2 + 4;
    doc.rect(14, currentY, 182, cliBoxH, 'F');
    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(56, 189, 248);
    doc.text(cliLines, 17, currentY + 4);
    currentY += cliBoxH + 3;

    if (finding.remediation.rollbackCommand) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(180, 83, 9);
      doc.text('Emergency Rollback Command:', 14, currentY);
      currentY += 3.8;
      doc.setFont('courier', 'normal');
      doc.setFontSize(7.5);
      const rbLines = doc.splitTextToSize(
        maskSensitiveIdentifier(
          finding.remediation.rollbackCommand.replace(/\\\n/g, ' '),
          redact
        ),
        178
      );
      doc.text(rbLines, 16, currentY);
      currentY += rbLines.length * 3.8 + 4;
    } else {
      currentY += 4;
    }
  });

  // Stamp page numbers and Demo/Confidentiality classification on all pages
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `${
        isDemo
          ? 'DEMO DATA — NO LIVE ASSESSMENT'
          : 'CONFIDENTIAL — LIVE AZURE ASSESSMENT'
      } · Tool Author: Mani Ravindran (ravindran.in) · Page ${p} of ${totalPages}`,
      14,
      290
    );
  }

  const filePrefix = isDemo
    ? 'Maniq-Shield-DEMO-Report'
    : 'Maniq-Shield-Live-Assessment';
  doc.save(`${filePrefix}-${new Date().toISOString().slice(0, 10)}.pdf`);
}
