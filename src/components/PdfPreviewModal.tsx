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
  EyeOff,
  AlertTriangle,
  ShieldCheck,
} from 'lucide-react';
import { AuditMetrics, Finding } from '../types/security';
import {
  generateVisualAidsCanvas,
  maskSensitiveIdentifier,
} from '../utils/pdfGenerator';

interface PdfPreviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  findings: Finding[];
  metrics: AuditMetrics;
  onDownloadPdf: (redactIdentifiers: boolean) => void;
  isDemoData?: boolean;
  collectionSource?: string;
  lastCollectedAt?: string;
}

export const PdfPreviewModal: React.FC<PdfPreviewModalProps> = ({
  isOpen,
  onClose,
  findings,
  metrics,
  onDownloadPdf,
  isDemoData = true,
  collectionSource = 'Demo Sample Dataset',
  lastCollectedAt,
}) => {
  const [charts, setCharts] = useState<{
    severityChartDataUrl: string;
    categoryChartDataUrl: string;
  } | null>(null);
  const [redactIdentifiers, setRedactIdentifiers] = useState<boolean>(false);

  useEffect(() => {
    if (isOpen) {
      const generated = generateVisualAidsCanvas(metrics, findings);
      setCharts(generated);
    }
  }, [isOpen, metrics, findings]);

  if (!isOpen) return null;

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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#081420]/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[92vh] flex flex-col bg-white border border-slate-200 rounded-2xl shadow-2xl text-[#16232F] overflow-hidden">
        {/* Top Action Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-[#081420] text-[#F3F5F1] flex-wrap gap-3">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-[#2BB5A0]/15 text-[#5FD3BF] border border-[#2BB5A0]/30">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-serif font-bold text-base text-white">
                PDF Assessment Report Preview & Confidentiality Controls
              </h3>
              <p className="text-xs text-[#B7C3CC]">
                {isDemoData
                  ? 'DEMO DATA — NO LIVE ASSESSMENT · Non-Confidential Sample Export'
                  : 'LIVE AZURE SNAPSHOT · Confidential Handling & Identifier Masking Available'}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2.5">
            {/* Recommendation #15: Identifier Redaction Toggle */}
            <label className="flex items-center space-x-1.5 text-xs bg-white/10 px-3 py-1.5 rounded-lg border border-white/15 cursor-pointer text-[#E5ECE9]">
              <input
                type="checkbox"
                checked={redactIdentifiers}
                onChange={(e) => setRedactIdentifiers(e.target.checked)}
                className="rounded accent-[#2BB5A0]"
              />
              <EyeOff className="w-3.5 h-3.5 text-[#5FD3BF]" />
              <span>Redact Subscription &amp; User IDs</span>
            </label>

            <button
              onClick={() => onDownloadPdf(redactIdentifiers)}
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
            {/* Demo vs Live Banner (Rec #5 & #15) */}
            <div
              className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
                isDemoData
                  ? 'bg-amber-50 border-amber-300 text-amber-950'
                  : 'bg-emerald-50 border-emerald-300 text-emerald-950'
              }`}
            >
              <div className="flex items-center space-x-2 font-mono font-bold">
                {isDemoData ? (
                  <>
                    <AlertTriangle className="w-4 h-4 text-amber-700" />
                    <span>DEMO DATA — NO LIVE ASSESSMENT (SAMPLE SCENARIO)</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4 text-[#1F8A79]" />
                    <span>LIVE AZURE ARM ASSESSMENT — HANDLE AS CONFIDENTIAL</span>
                  </>
                )}
              </div>
              <span className="font-mono text-[11px]">
                {redactIdentifiers ? 'Redaction: ENABLED' : 'Redaction: OFF'}
              </span>
            </div>

            {/* Postrix Top Strip (Rec #8: Tool Author & Automated Scan disclosure) */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-200 gap-4">
              <div>
                <span className="rm-kicker">
                  MANIQ SHIELD AUTOMATED HEURISTIC REPORT
                </span>
                <h1 className="font-serif text-xl font-bold text-[#16232F] mt-0.5">
                  Azure Storage & RBAC Loophole Assessment
                </h1>
                <p className="text-xs text-[#546471] mt-1">
                  Collection Time: <strong>{lastCollectedAt || new Date().toLocaleString()}</strong> · Source:{' '}
                  <strong>{maskSensitiveIdentifier(collectionSource, redactIdentifiers)}</strong>
                </p>
                <p className="text-xs text-[#546471] mt-0.5">
                  Tool Author: <strong>Mani Ravindran</strong> (
                  <a
                    href="https://ravindran.in"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[#1F8A79] hover:underline"
                  >
                    ravindran.in
                  </a>
                  ) · Audit Type: <strong>Automated Heuristic Scan (Human Review: Not Performed)</strong>
                </p>
              </div>
              <div className="text-right flex-shrink-0">
                <span
                  className={`text-[10px] px-2.5 py-1 rounded font-mono font-bold border ${
                    isDemoData
                      ? 'bg-amber-100 text-amber-900 border-amber-300'
                      : 'bg-slate-100 text-[#16232F] border-slate-300'
                  }`}
                >
                  {isDemoData ? 'DEMO SAMPLE' : 'CONFIDENTIAL'}
                </span>
              </div>
            </div>

            {/* Scorecard row */}
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="text-[10px] font-mono uppercase font-bold text-[#546471]">
                  Selected Checks Score
                </div>
                <div
                  className={`font-serif text-2xl font-bold ${
                    metrics.isEvaluationComplete === false
                      ? 'text-slate-500'
                      : metrics.postureScore >= 80
                      ? 'text-[#1F8A79]'
                      : metrics.postureScore >= 60
                      ? 'text-amber-600'
                      : 'text-red-600'
                  }`}
                >
                  {metrics.isEvaluationComplete === false
                    ? 'Unknown'
                    : `${metrics.postureScore}/100`}
                </div>
                <div className="text-[10px] text-[#546471] font-mono font-semibold">
                  {metrics.isEvaluationComplete === false
                    ? '0 Resources Evaluated'
                    : `Heuristic Grade: ${metrics.riskGrade}`}
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
                  High-Priority Findings
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="text-[10px] font-mono uppercase font-bold text-[#546471]">
                  Public Containers &amp; PrivEsc
                </div>
                <div className="font-serif text-2xl font-bold text-[#0E2238]">
                  {metrics.exposedContainerCount + metrics.privilegeEscalationCount}
                </div>
                <div className="text-[10px] text-[#546471] font-mono font-semibold">
                  {metrics.exposedContainerCount} Confirmed Public · {metrics.guardrailGapAccountCount || 0} Guardrail Gap
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

            {/* Informational Control Cross-Reference Matrix (Rec #3 & #9) */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-[#16232F] uppercase tracking-wider">
                  Informational Control Cross-Reference (18 Selected Checks)
                </h4>
                <span className="text-[10px] font-mono text-[#546471]">
                  Not a formal compliance certification
                </span>
              </div>
              <div className="border border-slate-200 rounded-lg overflow-hidden text-xs">
                <table className="w-full text-left">
                  <thead className="bg-slate-100 text-[#16232F] font-bold border-b border-slate-200">
                    <tr>
                      <th className="p-2">Reference Benchmark (Informational)</th>
                      <th className="p-2 text-center">Passed / Failed / Unknown</th>
                      <th className="p-2 text-center">Pass Rate</th>
                      <th className="p-2 text-center">Subset Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 text-[#546471]">
                    <tr>
                      <td className="p-2 font-medium text-[#16232F]">
                        CIS Microsoft Azure Foundations v2.0 (7 Selected Checks)
                      </td>
                      <td className="p-2 text-center font-mono text-[11px]">
                        <span className="text-[#1F8A79] font-bold">{cisChecks.passed}P</span> /{' '}
                        <span className="text-red-600 font-bold">{cisChecks.failed}F</span> /{' '}
                        <span className="text-slate-500 font-bold">{cisChecks.unknown}U</span>
                      </td>
                      <td className="p-2 text-center font-mono font-bold text-[#16232F]">
                        {cisChecks.passRate}%
                      </td>
                      <td className="p-2 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            cisChecks.unknown > 0
                              ? 'bg-slate-200 text-slate-700'
                              : cisChecks.failed === 0
                              ? 'bg-emerald-100 text-[#1F8A79]'
                              : 'bg-amber-100 text-amber-800'
                          }`}
                        >
                          {cisChecks.unknown > 0
                            ? 'Incomplete (Unknowns)'
                            : cisChecks.failed === 0
                            ? 'Selected Checks Passed'
                            : `${cisChecks.failed} Check(s) Failed`}
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td className="p-2 font-medium text-[#16232F]">
                        Microsoft Cloud Security Benchmark v1.0 (6 Selected Checks)
                      </td>
                      <td className="p-2 text-center font-mono text-[11px]">
                        <span className="text-[#1F8A79] font-bold">{mcsbChecks.passed}P</span> /{' '}
                        <span className="text-red-600 font-bold">{mcsbChecks.failed}F</span> /{' '}
                        <span className="text-slate-500 font-bold">{mcsbChecks.unknown}U</span>
                      </td>
                      <td className="p-2 text-center font-mono font-bold text-[#16232F]">
                        {mcsbChecks.passRate}%
                      </td>
                      <td className="p-2 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            mcsbChecks.unknown > 0
                              ? 'bg-slate-200 text-slate-700'
                              : mcsbChecks.failed === 0
                              ? 'bg-emerald-100 text-[#1F8A79]'
                              : 'bg-amber-100 text-amber-800'
                          }`}
                        >
                          {mcsbChecks.unknown > 0
                            ? 'Incomplete (Unknowns)'
                            : mcsbChecks.failed === 0
                            ? 'Selected Checks Passed'
                            : `${mcsbChecks.failed} Check(s) Failed`}
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td className="p-2 font-medium text-[#16232F]">
                        NIST SP 800-53 Rev 5 (5 Selected AC/SC/IA Checks)
                      </td>
                      <td className="p-2 text-center font-mono text-[11px]">
                        <span className="text-[#1F8A79] font-bold">{nistChecks.passed}P</span> /{' '}
                        <span className="text-red-600 font-bold">{nistChecks.failed}F</span> /{' '}
                        <span className="text-slate-500 font-bold">{nistChecks.unknown}U</span>
                      </td>
                      <td className="p-2 text-center font-mono font-bold text-[#16232F]">
                        {nistChecks.passRate}%
                      </td>
                      <td className="p-2 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            nistChecks.unknown > 0
                              ? 'bg-slate-200 text-slate-700'
                              : nistChecks.failed === 0
                              ? 'bg-emerald-100 text-[#1F8A79]'
                              : 'bg-amber-100 text-amber-800'
                          }`}
                        >
                          {nistChecks.unknown > 0
                            ? 'Incomplete (Unknowns)'
                            : nistChecks.failed === 0
                            ? 'Selected Checks Passed'
                            : `${nistChecks.failed} Check(s) Failed`}
                        </span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p className="text-[11px] text-[#546471] leading-relaxed">
                <strong>Disclosure (Rec #3, #9, #13):</strong> Mappings are informational cross-references to 18 selected heuristic rules only. Maniq Shield is independent and not affiliated with or certified by CIS, Microsoft, or NIST.
              </p>
            </div>

            {/* Findings Sample Preview */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-[#16232F] uppercase tracking-wider">
                Actionable Remediation Runbooks (Pre-Check, CLI &amp; Rollback Included)
              </h4>
              <p className="text-xs text-[#546471]">
                The exported PDF report includes pre-change verification queries, CLI commands, rollback steps, and Terraform snippets for all {findings.length} findings.
              </p>

              <div className="space-y-2">
                {findings.slice(0, 3).map((finding) => (
                  <div
                    key={finding.id}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50 text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[#16232F]">
                        [{finding.severity}] {maskSensitiveIdentifier(finding.title, redactIdentifiers)}
                      </span>
                      <span className="text-[10px] font-mono text-[#546471]">
                        {maskSensitiveIdentifier(finding.resourceName, redactIdentifiers)}
                      </span>
                    </div>
                    <div className="bg-[#081420] text-[#5FD3BF] p-2 rounded text-[10px] font-mono truncate">
                      {maskSensitiveIdentifier(
                        finding.remediation.cliCommand.replace(/\\\n/g, ' '),
                        redactIdentifiers
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-200 bg-white flex-wrap gap-2">
          <div className="text-xs text-[#546471]">
            {isDemoData
              ? 'Stamped as DEMO DATA — NO LIVE ASSESSMENT.'
              : 'Live assessment report — distribute only to authorized subscription owners.'}
          </div>
          <button
            onClick={() => onDownloadPdf(redactIdentifiers)}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#15314E] text-white transition-all"
          >
            <FileDown className="w-4 h-4" />
            <span>Generate &amp; Download Complete PDF</span>
          </button>
        </div>
      </div>
    </div>
  );
};
