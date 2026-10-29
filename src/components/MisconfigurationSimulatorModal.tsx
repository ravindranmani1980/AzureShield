/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  X,
  Flame,
  Unlock,
  Users,
  ShieldAlert,
  Server,
  Lock,
  ArrowRight,
  Radio,
  FileWarning,
} from 'lucide-react';

interface MisconfigurationSimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onInject: (scenarioType: string) => void;
}

export const MisconfigurationSimulatorModal: React.FC<
  MisconfigurationSimulatorModalProps
> = ({ isOpen, onClose, onInject }) => {
  if (!isOpen) return null;

  const scenarios = [
    {
      id: 'open_container',
      title: 'Expose Storage Container to Anonymous Internet',
      category: 'Storage Misconfiguration',
      severity: 'CRITICAL',
      icon: Unlock,
      color: 'text-red-400 bg-red-500/20 border-red-500/30',
      description:
        'Sets public access on container "customer-ssn-vault" to "Blob/Container". Any unauthenticated internet user can browse and download files.',
    },
    {
      id: 'guest_owner',
      title: 'Assign "Owner" Role to External Guest User',
      category: 'RBAC Overprivileged Access',
      severity: 'CRITICAL',
      icon: Users,
      color: 'text-rose-400 bg-rose-500/20 border-rose-500/30',
      description:
        'Grants full Owner authority across the entire subscription to an external partner (#EXT#) without MFA enforcement.',
    },
    {
      id: 'priv_esc',
      title: 'Inject "roleAssignments/write" Privilege Escalation',
      category: 'Privilege Escalation Vulnerability',
      severity: 'CRITICAL',
      icon: Flame,
      color: 'text-purple-400 bg-purple-500/20 border-purple-500/30',
      description:
        'Adds "Microsoft.Authorization/roleAssignments/write" to a junior deployment service principal, allowing self-promotion to Administrator.',
    },
    {
      id: 'insecure_http',
      title: 'Disable "Secure Transfer Required" (Allow HTTP)',
      category: 'Network & Transit Insecurity',
      severity: 'CRITICAL',
      icon: Server,
      color: 'text-amber-400 bg-amber-500/20 border-amber-500/30',
      description:
        'Switches storage transport policy to allow unencrypted plaintext HTTP traffic, exposing data in flight to interception.',
    },
    {
      id: 'legacy_tls',
      title: 'Downgrade Minimum TLS Version to TLS 1.0',
      category: 'Cryptographic Weakness',
      severity: 'HIGH',
      icon: ShieldAlert,
      color: 'text-orange-400 bg-orange-500/20 border-orange-500/30',
      description:
        'Lowers TLS threshold to deprecated TLS 1.0 on the primary production data lake, failing PCI-DSS and CIS benchmarks.',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-150">
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl p-6 text-slate-100 space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          aria-label="Close dialog"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center space-x-3">
          <div className="p-3 rounded-2xl bg-amber-500/20 text-amber-400 border border-amber-500/30">
            <Flame className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h2 className="text-lg sm:text-xl font-extrabold text-white">
              Simulate Live Misconfiguration Injection
            </h2>
            <p className="text-xs text-slate-400">
              Test Maniq Shield's Real-Time Alerting System by injecting a live security loophole into the cloud environment.
            </p>
          </div>
        </div>

        {/* Scenario Cards */}
        <div className="space-y-3 pt-2">
          {scenarios.map((sc) => {
            const Icon = sc.icon;
            return (
              <div
                key={sc.id}
                onClick={() => {
                  onInject(sc.id);
                  onClose();
                }}
                className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800 hover:border-amber-500/50 hover:bg-slate-950 transition-all cursor-pointer flex items-start justify-between gap-3 group"
              >
                <div className="flex items-start space-x-3.5">
                  <div
                    className={`p-2.5 rounded-xl border flex-shrink-0 mt-0.5 ${sc.color}`}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="text-[10px] font-black uppercase px-2 py-0.5 rounded bg-red-600 text-white">
                        {sc.severity}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">
                        {sc.category}
                      </span>
                    </div>
                    <h4 className="text-sm font-bold text-white group-hover:text-amber-300 transition-colors">
                      {sc.title}
                    </h4>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                      {sc.description}
                    </p>
                  </div>
                </div>

                <button className="flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 group-hover:bg-amber-500 group-hover:text-slate-950 transition-all flex-shrink-0 self-center">
                  <span>Trigger Alert</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            );
          })}
        </div>

        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-400 text-center">
          When triggered, the app will dispatch an immediate real-time alert with a direct link to the remediation runbook and update the PDF report.
        </div>
      </div>
    </div>
  );
};
