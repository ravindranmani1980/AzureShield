/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  X,
  FileDown,
  FileText,
  Printer,
  ShieldAlert,
  BarChart3,
  CheckCircle2,
} from 'lucide-react';
import { AuditMetrics, Finding } from '../types/security';
import {
  generateAzureSecurityPdfReport,
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl text-slate-100 overflow-hidden">
        {/* Top Action Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-blue-500/20 text-blue-400 border border-blue-500/30">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white">
                PDF Audit Report Preview & Visual Aids
              </h3>
              <p className="text-xs text-slate-400">
                A4 Executive Audit Document • Charts, Findings Matrix & Actionable Runbooks
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={onDownloadPdf}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/20 transition-all active:scale-95"
            >
              <FileDown className="w-4 h-4" />
              <span>Download PDF</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              aria-label="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Scrollable Document Simulation */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-slate-950/50">
          {/* Simulated Page 1: Executive Summary & Visual Aids */}
          <div className="bg-white text-slate-900 rounded-2xl shadow-xl p-8 max-w-3xl mx-auto border border-slate-200 space-y-6">
            {/* Azure Blue Top Strip */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-200">
              <div>
                <span className="text-[10px] font-black tracking-widest uppercase text-blue-600">
                  AZURESHIELD CSPM AUDIT REPORT
                </span>
                <h1 className="text-xl font-black text-slate-900">
                  Azure Storage & RBAC Loophole Assessment
                </h1>
                <p className="text-xs text-slate-500">
                  Audit Date: {new Date().toLocaleDateString()} • Lead Auditor: <strong>Mani Ravindran</strong> (
                  <a
                    href="https://ravidnran.in"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:underline"
                  >
                    ravidnran.in
                  </a>
                  )
                </p>
              </div>
              <div className="text-right">
                <span className="text-xs px-2.5 py-1 rounded-full font-bold bg-slate-100 text-slate-700 border border-slate-300">
                  CONFIDENTIAL
                </span>
              </div>
            </div>

            {/* Scorecard row */}
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <div className="text-[10px] uppercase font-bold text-slate-500">
                  Posture Score
                </div>
                <div
                  className={`text-2xl font-black ${
                    metrics.postureScore >= 80
                      ? 'text-emerald-600'
                      : metrics.postureScore >= 60
                      ? 'text-amber-600'
                      : 'text-red-600'
                  }`}
                >
                  {metrics.postureScore}/100
                </div>
                <div className="text-[10px] text-slate-500 font-semibold">
                  Risk Grade: {metrics.riskGrade}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <div className="text-[10px] uppercase font-bold text-slate-500">
                  Critical Loopholes
                </div>
                <div className="text-2xl font-black text-red-600">
                  {metrics.criticalCount}
                </div>
                <div className="text-[10px] text-slate-500 font-semibold">
                  Zero-Barrier Risks
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <div className="text-[10px] uppercase font-bold text-slate-500">
                  Escalation & Storage
                </div>
                <div className="text-2xl font-black text-purple-700">
                  {metrics.openBucketCount + metrics.privilegeEscalationCount}
                </div>
                <div className="text-[10px] text-slate-500 font-semibold">
                  High-Impact Paths
                </div>
              </div>
            </div>

            {/* Embedded Visual Aids in PDF Preview */}
            {charts && (
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center space-x-1.5">
                  <BarChart3 className="w-4 h-4 text-blue-600" />
                  <span>Visual Aids & Risk Distribution (Embedded in PDF)</span>
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-2 rounded-xl border border-slate-200 bg-slate-50 flex items-center justify-center">
                    <img
                      src={charts.severityChartDataUrl}
                      alt="Severity Chart"
                      className="w-full h-auto rounded-lg"
                    />
                  </div>
                  <div className="p-2 rounded-xl border border-slate-200 bg-slate-50 flex items-center justify-center">
                    <img
                      src={charts.categoryChartDataUrl}
                      alt="Category Chart"
                      className="w-full h-auto rounded-lg"
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Compliance Matrix Preview */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                Compliance Benchmark Alignment
              </h4>
              <div className="border border-slate-200 rounded-xl overflow-hidden text-xs">
                <table className="w-full text-left">
                  <thead className="bg-slate-100 text-slate-700 font-bold border-b border-slate-200">
                    <tr>
                      <th className="p-2">Framework</th>
                      <th className="p-2">Version</th>
                      <th className="p-2 text-center">Score</th>
                      <th className="p-2 text-center">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 text-slate-600">
                    <tr>
                      <td className="p-2 font-medium text-slate-900">
                        CIS Microsoft Azure Foundations Benchmark
                      </td>
                      <td className="p-2">v2.0.0</td>
                      <td className="p-2 text-center font-bold">
                        {metrics.complianceScores.cisAzure}%
                      </td>
                      <td className="p-2 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            metrics.complianceScores.cisAzure >= 80
                              ? 'bg-emerald-100 text-emerald-800'
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
                      <td className="p-2 font-medium text-slate-900">
                        Microsoft Cloud Security Benchmark (MCSB)
                      </td>
                      <td className="p-2">v1.0</td>
                      <td className="p-2 text-center font-bold">
                        {metrics.complianceScores.mcsb}%
                      </td>
                      <td className="p-2 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            metrics.complianceScores.mcsb >= 80
                              ? 'bg-emerald-100 text-emerald-800'
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
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                Actionable Remediation Runbooks (Included in PDF)
              </h4>
              <p className="text-xs text-slate-500">
                The exported PDF report includes dedicated CLI commands, Azure Portal steps, and Terraform code snippets for all {findings.length} findings.
              </p>

              <div className="space-y-2">
                {findings.slice(0, 3).map((finding) => (
                  <div
                    key={finding.id}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50 text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900">
                        [{finding.severity}] {finding.title}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {finding.resourceName}
                      </span>
                    </div>
                    <div className="bg-slate-900 text-cyan-300 p-2 rounded text-[10px] font-mono truncate">
                      {finding.remediation.cliCommand.replace(/\\\n/g, ' ')}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-800 bg-slate-950/60">
          <div className="text-xs text-slate-400">
            Export includes high-resolution PNG charts and remediation runbooks.
          </div>
          <button
            onClick={onDownloadPdf}
            className="flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-blue-600/20 transition-all active:scale-95"
          >
            <FileDown className="w-4 h-4" />
            <span>Generate & Download Complete PDF</span>
          </button>
        </div>
      </div>
    </div>
  );
};
