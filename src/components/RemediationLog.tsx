/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  History,
  CheckCircle2,
  Terminal,
  TrendingUp,
  Trash2,
  Database,
  KeyRound,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';
import { RemediationLogEntry } from '../types/security';

interface RemediationLogProps {
  logs: RemediationLogEntry[];
  onClearLogs: () => void;
}

export const RemediationLog: React.FC<RemediationLogProps> = ({
  logs,
  onClearLogs,
}) => {
  return (
    <div className="space-y-6">
      {/* Header Banner (Rec #6: Describe as In-Memory Session Activity Log and separate simulation from verified Azure changes) */}
      <div className="p-5 rounded-xl border border-slate-200/90 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-xs">
        <div>
          <span className="rm-kicker">
            SESSION ACTIVITY LOG (IN-MEMORY SIMULATION &amp; ACKNOWLEDGMENT — REC #6)
          </span>
          <div className="flex items-center space-x-2">
            <History className="w-5 h-5 text-[#1F8A79]" />
            <h2 className="font-serif text-lg font-bold text-[#16232F]">
              In-Memory Remediation Simulation &amp; Acknowledgment Log
            </h2>
          </div>
          <p className="text-xs text-[#546471] mt-1">
            Tracks simulated hardening actions and manual finding acknowledgments during this browser session. Entries below represent <strong>in-memory UI simulations</strong> until you execute the generated CLI commands in Azure and re-sync.
          </p>
        </div>

        {logs.length > 0 && (
          <button
            onClick={onClearLogs}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-red-50 text-[#546471] hover:text-red-700 border border-slate-300 transition-colors self-start sm:self-center"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Session Log</span>
          </button>
        )}
      </div>

      {/* Important Disclosure Banner (Rec #6) */}
      <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-950 text-xs flex items-start space-x-2.5">
        <AlertTriangle className="w-4 h-4 text-amber-700 flex-shrink-0 mt-0.5" />
        <div>
          <strong>Simulation vs. Verified Live Remediation (Rec #6):</strong> This session log is stored in volatile browser memory (not an immutable audit ledger). Clicking <em>Simulate Hardening</em> or <em>Acknowledge</em> updates the in-memory posture model so you can preview score impact; to verify actual remediation, run the CLI runbook against Azure and re-run a live Bearer Token scan.
        </div>
      </div>

      {/* Log Timeline */}
      {logs.length === 0 ? (
        <div className="p-12 rounded-xl border border-slate-200 bg-white text-center space-y-3 shadow-xs">
          <ShieldCheck className="w-12 h-12 text-slate-400 mx-auto" />
          <div className="font-serif text-base font-bold text-[#16232F]">
            No In-Memory Simulations Recorded Yet
          </div>
          <p className="text-xs text-[#546471] max-w-md mx-auto leading-relaxed">
            Click <strong>Simulate Hardening (In-Memory)</strong> on any Storage Account, <strong>Simulate Revoke</strong> on an RBAC Role Assignment, or <strong>Acknowledge</strong> inside a Finding Runbook to preview posture improvements here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {logs.map((entry) => {
            const delta = entry.newScore - entry.previousScore;
            return (
              <div
                key={entry.id}
                className="p-4 rounded-xl border border-slate-200/90 bg-white space-y-3 shadow-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center space-x-2.5">
                    <div className="p-2 rounded-lg bg-emerald-50 text-[#1F8A79] border border-emerald-200">
                      {entry.category === 'storage' ? (
                        <Database className="w-4 h-4" />
                      ) : (
                        <KeyRound className="w-4 h-4" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span className="text-xs font-bold text-[#16232F]">
                          {entry.actionTitle}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-50 text-amber-800 border border-amber-200 flex items-center space-x-1 font-semibold">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>
                            {entry.verificationStatus === 'acknowledged_unverified'
                              ? 'ACKNOWLEDGED IN UI (UNVERIFIED IN AZURE)'
                              : 'IN-MEMORY SIMULATION'}
                          </span>
                        </span>
                      </div>
                      <div className="text-[11px] text-[#546471] font-mono mt-0.5">
                        Resource: <span className="text-[#1F8A79] font-semibold">{entry.resourceName}</span> · Logged at {entry.timestamp}
                      </div>
                    </div>
                  </div>

                  {/* Score Impact Badge */}
                  <div className="flex items-center space-x-2 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 self-start sm:self-center">
                    <TrendingUp className="w-4 h-4 text-[#1F8A79]" />
                    <div className="text-xs font-mono">
                      <span className="text-[#546471]">{entry.previousScore}</span>
                      <span className="mx-1.5 text-slate-400">→</span>
                      <span className="text-[#1F8A79] font-bold">
                        {entry.newScore} pts
                      </span>
                      {delta > 0 && (
                        <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded bg-emerald-50 text-[#1F8A79] font-bold border border-emerald-200">
                          +{delta}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* CLI Reference */}
                <div className="bg-[#081420] p-3 rounded-lg border border-slate-800 flex items-center space-x-2.5 font-mono text-xs text-[#5FD3BF] overflow-x-auto">
                  <Terminal className="w-4 h-4 text-[#2BB5A0] flex-shrink-0" />
                  <span className="truncate">{entry.cliExecuted}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
