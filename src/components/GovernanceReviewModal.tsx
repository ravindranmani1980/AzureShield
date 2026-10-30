/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  X,
  ShieldCheck,
  Lock,
  Scale,
  FileText,
  CheckCircle2,
  Trash2,
  KeyRound,
  ExternalLink,
  AlertTriangle,
} from 'lucide-react';

interface GovernanceReviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  onOpenLiveSync: () => void;
  onPurgeToken?: () => void;
  isDemoData: boolean;
}

export interface CsvRecommendationItem {
  id: number;
  category: string;
  severity: 'High' | 'Medium';
  issue: string;
  recommendation: string;
  implementedAction: string;
}

export const CSV_RECOMMENDATIONS: CsvRecommendationItem[] = [
  {
    id: 3,
    category: 'Compliance conclusions',
    severity: 'High',
    issue:
      'Framework scores and "Compliant" labels could be read as complete certification or legal compliance.',
    recommendation:
      'Report only selected checks passed/failed/unknown, disclose scope, exclusions, and calculation, and avoid overall compliance conclusions.',
    implementedAction:
      'Replaced "Compliant" badges with Selected Checks (Passed / Failed / Unknown) counters, disclosed the 18-rule subset & penalty formula, and marked 0-resource or unauthenticated scopes as 18 Unknown (Incomplete) instead of 100%.',
  },
  {
    id: 4,
    category: 'Simulated monitoring & history',
    severity: 'High',
    issue:
      'Simulated activity streams, drift alerts, and historical posture curves could be mistaken for live tenant telemetry.',
    recommendation:
      'Separate simulated features from actual observations and display data source, period, and collection timestamp.',
    implementedAction:
      'Relabeled historical curves as "Illustrative 30-Day Baseline (Simulated)" vs. "Current Session Simulation (In-Memory)", labeled sandbox drift streams as Simulated, and added live data source & collection timestamps.',
  },
  {
    id: 5,
    category: 'Demo labeling & breach predictions',
    severity: 'High',
    issue:
      'Sample scenarios and "Breach Imminent" wording could look like real findings or guaranteed outcomes.',
    recommendation:
      'Label all sample views and reports "Demo data — no live assessment" and use neutral risk descriptions.',
    implementedAction:
      'Added prominent "DEMO DATA — NO LIVE ASSESSMENT" banners across the UI and PDF reports, renamed sample presets, and replaced "Breach Imminent" with neutral risk descriptions.',
  },
  {
    id: 6,
    category: 'Remediation status & immutable log',
    severity: 'High',
    issue:
      'UI actions mark findings remediated in memory and call the session log "immutable" without verifying Azure changes.',
    recommendation:
      'Separate simulation/acknowledgment from verified remediation and describe the log as an in-memory session log.',
    implementedAction:
      'Renamed actions to "Simulate Hardening (In-Memory)" / "Acknowledge (Unverified in Azure)" and renamed the log to "Session Activity Log (In-Memory Simulation)".',
  },
  {
    id: 7,
    category: 'Permission scope',
    severity: 'High',
    issue:
      'The app encourages Root Management Group Reader access, Global Administrator elevation, and tenant-wide token scanning.',
    recommendation:
      'Default to the narrowest scope needed, warn against broad elevation, and require explicit confirmation for multi-subscription scans.',
    implementedAction:
      'Removed Root Management Group and Global Administrator elevation guidance; defaulted to single-subscription or Resource Group Reader scope with an explicit confirmation checkbox before multi-subscription scans.',
  },
  {
    id: 8,
    category: 'Human audit representation',
    severity: 'High',
    issue:
      'Reports name a "Lead Auditor," implying a human-led professional audit.',
    recommendation:
      'Use "Tool Author" or "Report Generator" and state whether human review occurred.',
    implementedAction:
      'Replaced "Lead Auditor" with "Tool Author: Mani Ravindran" and added "Audit Type: Automated Heuristic Scan (Human Review: Not Performed)" in the UI and PDF exports.',
  },
  {
    id: 9,
    category: 'CIS licensing & mappings',
    severity: 'Medium',
    issue:
      'CIS Azure Benchmark references may require license review or clearer scope disclaimers.',
    recommendation:
      'Verify CIS reproduction rights or describe mappings as informational cross-references to selected controls.',
    implementedAction:
      'Added explicit disclosures that CIS Azure v2.0, MCSB, and NIST SP 800-53 mappings are informational cross-references to selected controls only and are not CIS/Microsoft certified.',
  },
  {
    id: 10,
    category: 'Anonymous access finding accuracy',
    severity: 'Medium',
    issue:
      'Enabling account-level public access is described as exposing all containers even when containers are private.',
    recommendation:
      'Distinguish account-level guardrail gaps from confirmed container-level anonymous access.',
    implementedAction:
      'Separated account-level allowBlobPublicAccess=true with 0 public containers ("Guardrail Gap") from confirmed public containers ("Confirmed Anonymous Exposure").',
  },
  {
    id: 11,
    category: 'Customer-managed encryption keys',
    severity: 'Medium',
    issue:
      'Lack of CMK is flagged as a compliance risk without noting Azure’s default encryption.',
    recommendation:
      'State that Azure encrypts data at rest by default and assess CMK against organizational policy.',
    implementedAction:
      'Updated Storage findings, Inventory, and Auditor views to state that Azure encrypts all Storage data at rest by default using 256-bit AES Microsoft-Managed Keys (MMK), and that CMK is an organizational policy hardening option.',
  },
  {
    id: 12,
    category: 'Privacy & credential handling',
    severity: 'High',
    issue:
      'Users paste Azure Bearer Tokens and resource metadata without a privacy or token-handling notice.',
    recommendation:
      'Publish how tokens and scan data are processed, transmitted, retained, logged, and cleared.',
    implementedAction:
      'Removed the hardcoded default Bearer Token, published a full Privacy & Token Handling Policy (volatile React memory only, browser-direct HTTPS to management.azure.com, zero backend storage), and added a 1-click "Purge Token" button.',
  },
  {
    id: 13,
    category: 'Authorized use & scope notices',
    severity: 'Medium',
    issue:
      'The app lacks terms for authorized scanning, limitations, and third-party affiliation.',
    recommendation:
      'Add an authorized-use requirement, scope/limitation notice, contact details, and Microsoft/CIS independence notice.',
    implementedAction:
      'Published Authorized Use requirements, 18-check scope & exclusions, contact details (ravindran.in), and independence notices from Microsoft Corporation and CIS.',
  },
  {
    id: 14,
    category: 'Remediation commands & exported scripts',
    severity: 'High',
    issue:
      'Generated CLI commands and scripts can block public access, networks, TLS, or RBAC roles without dry-run or impact checks.',
    recommendation:
      'Include pre-checks, backups, rollback steps, staging validation, and manual approval before live changes.',
    implementedAction:
      'Added Pre-Check and Rollback commands to every finding, and updated exported .sh scripts to default to DRY_RUN=true requiring --apply-live-changes and interactive operator confirmation.',
  },
  {
    id: 15,
    category: 'Report confidentiality',
    severity: 'Medium',
    issue:
      'Exported PDFs are marked "CONFIDENTIAL" even for demo data and may include real subscription or user identifiers.',
    recommendation:
      'Label demo reports clearly, provide confidential-handling guidance, and support masking or redaction.',
    implementedAction:
      'Stamped Demo PDFs with "DEMO DATA — NO LIVE ASSESSMENT (NON-CONFIDENTIAL SAMPLE)", added identifier redaction/masking for Subscription IDs & Principal names, and included confidential-handling guidance.',
  },
];

export const GovernanceReviewModal: React.FC<GovernanceReviewModalProps> = ({
  isOpen,
  onClose,
  onOpenLiveSync,
  onPurgeToken,
  isDemoData,
}) => {
  const [activeSection, setActiveSection] = useState<
    'recommendations' | 'privacy' | 'scope'
  >('recommendations');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#081420]/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[92vh] flex flex-col bg-white border border-slate-200 rounded-2xl shadow-2xl text-[#16232F] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-[#081420] text-[#F3F5F1]">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-lg bg-[#2BB5A0]/20 text-[#5FD3BF] border border-[#2BB5A0]/40">
              <Scale className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="font-serif font-bold text-base text-white">
                  Governance, Privacy & Recommendations Review (IDs 3–15)
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-[#2BB5A0]/20 text-[#5FD3BF] border border-[#2BB5A0]/40">
                  13 / 13 IMPLEMENTED
                </span>
              </div>
              <p className="text-xs text-[#B7C3CC]">
                Maniq-Shield-Recommendations.csv Compliance Matrix · Token Privacy Policy · Scope & Independence Notices
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#B7C3CC] hover:text-white hover:bg-white/10 transition-colors"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Sub-tabs */}
        <div className="flex items-center justify-between px-6 pt-3 border-b border-slate-200 bg-slate-50 flex-wrap gap-2 text-xs">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveSection('recommendations')}
              className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
                activeSection === 'recommendations'
                  ? 'border-[#1F8A79] text-[#16232F]'
                  : 'border-transparent text-[#546471] hover:text-[#16232F]'
              }`}
            >
              <CheckCircle2 className="w-4 h-4 text-[#1F8A79]" />
              <span>CSV Recommendations Review (IDs 3–15)</span>
            </button>
            <button
              onClick={() => setActiveSection('privacy')}
              className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
                activeSection === 'privacy'
                  ? 'border-[#1F8A79] text-[#16232F]'
                  : 'border-transparent text-[#546471] hover:text-[#16232F]'
              }`}
            >
              <Lock className="w-4 h-4 text-[#1F8A79]" />
              <span>Privacy & Bearer Token Handling (ID 12)</span>
            </button>
            <button
              onClick={() => setActiveSection('scope')}
              className={`pb-2.5 px-3 font-semibold border-b-2 transition-all flex items-center space-x-1.5 ${
                activeSection === 'scope'
                  ? 'border-[#1F8A79] text-[#16232F]'
                  : 'border-transparent text-[#546471] hover:text-[#16232F]'
              }`}
            >
              <FileText className="w-4 h-4 text-[#1F8A79]" />
              <span>Authorized Use, Scope & Independence (IDs 3, 9, 13)</span>
            </button>
          </div>

          <div className="pb-2 flex items-center space-x-2">
            <button
              onClick={() => {
                onClose();
                onOpenLiveSync();
              }}
              className="px-3 py-1 rounded-lg bg-[#0E2238] hover:bg-[#15314E] text-white font-semibold text-[11px] flex items-center space-x-1.5"
            >
              <KeyRound className="w-3.5 h-3.5 text-[#5FD3BF]" />
              <span>Enter Azure ARM Bearer Token</span>
            </button>
          </div>
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto flex-1 bg-[#F3F5F1] space-y-4">
          {activeSection === 'recommendations' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-white border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <span className="rm-kicker">CSV AUDIT LOG VERIFICATION</span>
                  <h4 className="font-serif text-base font-bold text-[#16232F]">
                    All 13 Recommendations Reviewed & Enforced
                  </h4>
                  <p className="text-xs text-[#546471] mt-0.5">
                    Additionally, the hardcoded Azure ARM Bearer Access Token has been removed (`DEFAULT_AZURE_ACCESS_TOKEN = &apos;&apos;`) and the application now prompts the operator to enter a fresh token for live assessment.
                  </p>
                </div>
                <span className="px-3 py-1.5 rounded-lg bg-emerald-50 border border-emerald-200 text-[#1F8A79] font-mono text-xs font-bold whitespace-nowrap">
                  STATUS: 100% ADDRESSED
                </span>
              </div>

              <div className="space-y-3">
                {CSV_RECOMMENDATIONS.map((item) => (
                  <div
                    key={item.id}
                    className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded bg-[#081420] text-[#5FD3BF] font-mono text-xs font-bold">
                          ID #{item.id}
                        </span>
                        <span className="font-serif font-bold text-sm text-[#16232F]">
                          {item.category}
                        </span>
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${
                            item.severity === 'High'
                              ? 'bg-red-50 text-red-700 border border-red-200'
                              : 'bg-amber-50 text-amber-800 border border-amber-200'
                          }`}
                        >
                          {item.severity} Priority
                        </span>
                      </div>
                      <span className="text-[11px] font-mono font-bold text-[#1F8A79] flex items-center space-x-1">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Implemented</span>
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs pt-1">
                      <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/80">
                        <div className="font-mono text-[10px] uppercase font-bold text-[#546471] mb-1">
                          Identified Issue
                        </div>
                        <p className="text-[#16232F] leading-relaxed">{item.issue}</p>
                      </div>
                      <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/80">
                        <div className="font-mono text-[10px] uppercase font-bold text-[#546471] mb-1">
                          CSV Recommendation
                        </div>
                        <p className="text-[#16232F] leading-relaxed">
                          {item.recommendation}
                        </p>
                      </div>
                      <div className="p-2.5 rounded-lg bg-emerald-50/60 border border-emerald-200">
                        <div className="font-mono text-[10px] uppercase font-bold text-[#1F8A79] mb-1">
                          Maniq Shield Implementation
                        </div>
                        <p className="text-[#16232F] leading-relaxed">
                          {item.implementedAction}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeSection === 'privacy' && (
            <div className="bg-white rounded-xl border border-slate-200 p-6 space-y-5 text-xs leading-relaxed">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200">
                <div>
                  <span className="rm-kicker">RECOMMENDATION #12 — CREDENTIAL & DATA PRIVACY</span>
                  <h4 className="font-serif text-lg font-bold text-[#16232F] mt-0.5">
                    Azure ARM Bearer Token & Metadata Handling Policy
                  </h4>
                </div>
                {onPurgeToken && (
                  <button
                    onClick={onPurgeToken}
                    className="px-3.5 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-semibold text-xs flex items-center space-x-1.5 transition-all"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Purge Token & Reset to Demo State</span>
                  </button>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                  <h5 className="font-serif font-bold text-sm text-[#16232F] flex items-center space-x-2">
                    <ShieldCheck className="w-4 h-4 text-[#1F8A79]" />
                    <span>1. Zero Default Token & Volatile Memory Only</span>
                  </h5>
                  <p className="text-[#546471]">
                    Maniq Shield does <strong>not</strong> bundle or pre-fill any Azure ARM Bearer Access Token (`DEFAULT_AZURE_ACCESS_TOKEN = &apos;&apos;`). When you paste an OAuth2 Bearer Token, it is held strictly in volatile React component state in your browser tab RAM.
                  </p>
                  <p className="text-[#546471]">
                    Tokens are <strong>never</strong> written to <code>localStorage</code>, <code>sessionStorage</code>, IndexedDB, browser cookies, or application logs.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                  <h5 className="font-serif font-bold text-sm text-[#16232F] flex items-center space-x-2">
                    <Lock className="w-4 h-4 text-[#1F8A79]" />
                    <span>2. Direct Client-to-Azure ARM Transmission</span>
                  </h5>
                  <p className="text-[#546471]">
                    All live API requests execute directly from your browser via HTTPS <code>fetch()</code> to <code>https://management.azure.com</code> using the <code>Authorization: Bearer &lt;token&gt;</code> header.
                  </p>
                  <p className="text-[#546471]">
                    Neither your Bearer Token nor your Azure resource metadata is transmitted to any third-party proxy or backend server.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                  <h5 className="font-serif font-bold text-sm text-[#16232F]">
                    3. Least-Privilege Token Scope Guidance (Rec #7)
                  </h5>
                  <p className="text-[#546471]">
                    Request tokens using an identity assigned built-in <code>Reader</code> on the narrowest target scope required (a specific Resource Group or single Subscription). Do <strong>not</strong> elevate to Global Administrator or assign Root Management Group access solely to run a posture assessment.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                  <h5 className="font-serif font-bold text-sm text-[#16232F]">
                    4. Immediate Credential Clearing & Redaction (Rec #15)
                  </h5>
                  <p className="text-[#546471]">
                    Closing or refreshing the browser tab immediately destroys all in-memory tokens and scan metadata. You can also click <strong>Purge Token</strong> at any time, and enable <strong>Identifier Redaction</strong> when exporting PDF reports.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'scope' && (
            <div className="bg-white rounded-xl border border-slate-200 p-6 space-y-5 text-xs leading-relaxed">
              <div className="pb-4 border-b border-slate-200">
                <span className="rm-kicker">RECOMMENDATIONS #3, #8, #9, #13 — SCOPE & LEGAL NOTICES</span>
                <h4 className="font-serif text-lg font-bold text-[#16232F] mt-0.5">
                  Authorized Use, Selected-Check Calculation & Independence Notice
                </h4>
              </div>

              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-amber-950 space-y-1.5">
                  <div className="font-bold flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 text-amber-700" />
                    <span>Authorized Use Requirement (Rec #13)</span>
                  </div>
                  <p>
                    You must hold explicit authorization from the Azure tenant or subscription owner before scanning any cloud environment or ingesting Azure CLI/ARM metadata into Maniq Shield.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                    <h5 className="font-serif font-bold text-sm text-[#16232F]">
                      Selected-Check Scope, Exclusions & Formula (Rec #3)
                    </h5>
                    <p className="text-[#546471]">
                      Maniq Shield evaluates a curated subset of <strong>18 heuristic checks</strong> across Azure Storage Accounts, Blob Containers, and ARM Role Assignments:
                    </p>
                    <ul className="list-disc pl-5 text-[#546471] space-y-1">
                      <li><strong>CIS Azure v2.0 subset:</strong> 7 selected Storage &amp; IAM rules</li>
                      <li><strong>Microsoft Cloud Security Benchmark (MCSB) subset:</strong> 6 selected rules</li>
                      <li><strong>NIST SP 800-53 Rev 5 subset:</strong> 5 selected AC/SC/IA rules</li>
                    </ul>
                    <p className="text-[#546471]">
                      <strong>Exclusions:</strong> Data-plane blob contents, Azure Policy exemptions, Conditional Access policies, PIM eligible assignments, and non-Storage resource types are not evaluated. If 0 resources are scanned, all 18 checks are reported as <strong>Unknown / Not Evaluated</strong>.
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                    <h5 className="font-serif font-bold text-sm text-[#16232F]">
                      Independence, Licensing & Human Review Notice (Rec #8, #9)
                    </h5>
                    <p className="text-[#546471]">
                      <strong>No Official Endorsement:</strong> Maniq Shield is an independent open-architecture security tool created by Tool Author <strong>Mani Ravindran</strong>. It is not affiliated with, endorsed by, or certified by Microsoft Corporation, the Center for Internet Security (CIS), or NIST.
                    </p>
                    <p className="text-[#546471]">
                      <strong>Informational Cross-References Only:</strong> References to CIS Azure Foundations Benchmark v2.0, MCSB v1.0, and NIST SP 800-53 Rev 5 are provided strictly as informational cross-references to selected technical controls and do not constitute a formal compliance audit or certification.
                    </p>
                    <p className="text-[#546471]">
                      <strong>Human Review Status:</strong> Reports are generated automatically via deterministic client-side heuristics (<em>Human Review: Not Performed</em> unless independently verified by your security team).
                    </p>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-100 border border-slate-200 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[#546471]">
                    Tool Author &amp; Contact: <strong>Mani Ravindran</strong> · Security Architecture &amp; CSPM Engineering
                  </span>
                  <a
                    href="https://ravindran.in"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[#1F8A79] hover:underline font-semibold flex items-center space-x-1"
                  >
                    <span>https://ravindran.in</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-200 bg-white flex items-center justify-between text-xs">
          <span className="text-[#546471] font-mono">
            Dataset Status: {isDemoData ? 'DEMO DATA — NO LIVE ASSESSMENT' : 'LIVE AZURE ARM SNAPSHOT'}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-[#0E2238] hover:bg-[#15314E] text-white font-semibold"
          >
            Close Governance Panel
          </button>
        </div>
      </div>
    </div>
  );
};
