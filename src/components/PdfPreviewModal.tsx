/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  X,
  FileDown,
  FileText,
  BarChart3,
} from 'lucide-react';
import { AuditMetrics, Finding } from '../types/security';
import {
  generateVisualAidsCanvas,
} from '../utils/pdfGenerator';

interface PdfPreviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  findings: Finding[];
  metrics: AuditMetrics;
  onDownloadPdf: () => void;
}

export const PdfPreviewModal: React.FC<PdfPreviewModalProps> = ({
  isOpen,
  onClose,
  findings,
  metrics,
  onDownloadPdf,
}) => {
  const [charts, setCharts] = useState<{
    severityChartDataUrl: string;
    categoryChartDataUrl: string;
  } | null>(null);

  useEffect(() => {
    if (isOpen) {
      const generated = generateVisualAidsCanvas(metrics, findings);
      setCharts(generated);
    }
  }, [isOpen, metrics, findings]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#081420]/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[92vh] flex flex-col bg-white border border-slate-200 rounded-2xl shadow-2xl text-[#16232F] overflow-hidden">
        {/* Top Action Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-[#081420] text-[#F3F5F1]">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-[#2BB5A0]/15 text-[#5FD3BF] border border-[#2BB5A0]/30">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-serif font-bold text-base text-white">
                PDF Audit Report Preview & Visual Aids
              </h3>
              <p className="text-xs text-[#B7C3CC]">
                A4 Executive Audit Document · Charts, Findings Matrix & Actionable Runbooks
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={onDownloadPdf}
              className="xh-btn primary text-xs"
            >
              <FileDown className="w-4 h-4" />
              <span>Download PDF</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-[#B7C3CC] hover:text-white hover:bg-white/10 transition-colors"
              aria-label="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Scrollable Document Simulation */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-[#F3F5F1]">
          {/* Simulated Page 1: Executive Summary & Visual Aids */}
          <div className="bg-white text-[#16232F] rounded-xl shadow-md p-8 max-w-3xl mx-auto border border-slate-200 space-y-6">
            {/* Postrix Top Strip */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-200">
              <div>
                <span className="rm-kicker">
                  MANIQ SHIELD CSPM AUDIT REPORT
                </span>
                <h1 className="font-serif text-xl font-bold text-[#16232F] mt-0.5">
                  Azure Storage & RBAC Loophole Assessment
                </h1>
                <p className="text-xs text-[#546471] mt-0.5">
                  Audit Date: {new Date().toLocaleDateString()} · Lead Auditor: <strong>Mani Ravindran</strong> (
                  <a
                    href="https://ravindran.in"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[#1F8A79] hover:underline"
                  >
                    ravindran.in
                  </a>
                  )
                </p>
              </div>
              <div className="text-right">
                <span className="text-xs px-2.5 py-1 rounded font-mono font-bold bg-slate-100 text-[#16232F] border border-slate-300">
                  CONFIDENTIAL
                </span>
              </div>
            </div>

            {/* Scorecard row */}
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="text-[10px] font-mono uppercase font-bold text-[#546471]">
                  Posture Score
                </div>
                <div
                  className={`font-serif text-2xl font-bold ${
                    metrics.postureScore >= 80
                      ? 'text-[#1F8A79]'
                      : metrics.postureScore >= 60
                      ? 'text-amber-600'
                      : 'text-red-600'
                  }`}
                >
                  {metrics.postureScore}/100
                </div>
                <div className="text-[10px] text-[#546471] font-mono font-semibold">
                  Risk Grade: {metrics.riskGrade}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="text-[10px] font-mono uppercase font-bold text-[#546471]">
                  Critical Loopholes
                </div>
                <div className="font-serif text-2xl font-bold text-red-600">
                  {metrics.criticalCount}
                </div>
                <div className="text-[10px] text-[#546471] font-mono font-semibold">
                  Zero-Barrier Risks
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="text-[10px] font-mono uppercase font-bold text-[#546471]">
                  Escalation & Containers
                </div>
                <div className="font-serif text-2xl font-bold text-[#0E2238]">
                  {(metrics.exposedContainerCount || metrics.openBucketCount) + metrics.privilegeEscalationCount}
                </div>
                <div className="text-[10px] text-[#546471] font-mono font-semibold">
                  High-Impact Paths
                </div>
              </div>
            </div>

            {/* Embedded Visual Aids in PDF Preview */}
            {charts && (
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-[#16232F] uppercase tracking-wider flex items-center space-x-1.5">
                  <BarChart3 className="w-4 h-4 text-[#1F8A79]" />
                  <span>Visual Aids & Risk Distribution (Embedded in PDF)</span>
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-2 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-center">
                    <img
                      src={charts.severityChartDataUrl}
                      alt="Severity Chart"
                      className="w-full h-auto rounded"
                    />
                  </div>
                  <div className="p-2 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-center">
                    <img
                      src={charts.categoryChartDataUrl}
                      alt="Category Chart"
                      className="w-full h-auto rounded"
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Compliance Matrix Preview */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-[#16232F] uppercase tracking-wider">
                Compliance Benchmark Alignment
              </h4>
              <div className="border border-slate-200 rounded-lg overflow-hidden text-xs">
                <table className="w-full text-left">
                  <thead className="bg-slate-100 text-[#16232F] font-bold border-b border-slate-200">
                    <tr>
                      <th className="p-2">Framework</th>
                      <th className="p-2">Version</th>
                      <th className="p-2 text-center">Score</th>
                      <th className="p-2 text-center">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 text-[#546471]">
                    <tr>
                      <td className="p-2 font-medium text-[#16232F]">
                        CIS Microsoft Azure Foundations Benchmark
                      </td>
                      <td className="p-2 font-mono">v2.0.0</td>
                      <td className="p-2 text-center font-mono font-bold text-[#16232F]">
                        {metrics.complianceScores.cisAzure}%
                      </td>
                      <td className="p-2 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            metrics.complianceScores.cisAzure >= 80
                              ? 'bg-emerald-100 text-[#1F8A79]'
                              : 'bg-amber-100 text-amber-800'
                          }`}
                        >
                          {metrics.complianceScores.cisAzure >= 80
                            ? 'Compliant'
                            : 'Needs Remediation'}
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td className="p-2 font-medium text-[#16232F]">
                        Microsoft Cloud Security Benchmark (MCSB)
                      </td>
                      <td className="p-2 font-mono">v1.0</td>
                      <td className="p-2 text-center font-mono font-bold text-[#16232F]">
                        {metrics.complianceScores.mcsb}%
                      </td>
                      <td className="p-2 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            metrics.complianceScores.mcsb >= 80
                              ? 'bg-emerald-100 text-[#1F8A79]'
                              : 'bg-amber-100 text-amber-800'
                          }`}
                        >
                          {metrics.complianceScores.mcsb >= 80
                            ? 'Compliant'
                            : 'Needs Remediation'}
                        </span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Findings Sample Preview */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-[#16232F] uppercase tracking-wider">
                Actionable Remediation Runbooks (Included in PDF)
              </h4>
              <p className="text-xs text-[#546471]">
                The exported PDF report includes dedicated CLI commands, Azure Portal steps, and Terraform code snippets for all {findings.length} findings.
              </p>

              <div className="space-y-2">
                {findings.slice(0, 3).map((finding) => (
                  <div
                    key={finding.id}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50 text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[#16232F]">
                        [{finding.severity}] {finding.title}
                      </span>
                      <span className="text-[10px] font-mono text-[#546471]">
                        {finding.resourceName}
                      </span>
                    </div>
                    <div className="bg-[#081420] text-[#5FD3BF] p-2 rounded text-[10px] font-mono truncate">
                      {finding.remediation.cliCommand.replace(/\\\n/g, ' ')}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-200 bg-white">
          <div className="text-xs text-[#546471]">
            Export includes high-resolution PNG charts and remediation runbooks.
          </div>
          <button
            onClick={onDownloadPdf}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all"
          >
            <FileDown className="w-4 h-4" />
            <span>Generate & Download Complete PDF</span>
          </button>
        </div>
      </div>
    </div>
  );
};
