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
  ArrowRight,
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
      color: 'text-red-700 bg-red-50 border-red-200',
      description:
        'Sets public access on container "customer-ssn-vault" to "Blob/Container". Any unauthenticated internet user can browse and download files.',
    },
    {
      id: 'guest_owner',
      title: 'Assign "Owner" Role to External Guest User',
      category: 'RBAC Overprivileged Access',
      severity: 'CRITICAL',
      icon: Users,
      color: 'text-rose-700 bg-rose-50 border-rose-200',
      description:
        'Grants full Owner authority across the entire subscription to an external partner (#EXT#) without MFA enforcement.',
    },
    {
      id: 'priv_esc',
      title: 'Inject "roleAssignments/write" Privilege Escalation',
      category: 'Privilege Escalation Vulnerability',
      severity: 'CRITICAL',
      icon: Flame,
      color: 'text-purple-700 bg-purple-50 border-purple-200',
      description:
        'Adds "Microsoft.Authorization/roleAssignments/write" to a junior deployment service principal, allowing self-promotion to Administrator.',
    },
    {
      id: 'insecure_http',
      title: 'Disable "Secure Transfer Required" (Allow HTTP)',
      category: 'Network & Transit Insecurity',
      severity: 'CRITICAL',
      icon: Server,
      color: 'text-amber-700 bg-amber-50 border-amber-200',
      description:
        'Switches storage transport policy to allow unencrypted plaintext HTTP traffic, exposing data in flight to interception.',
    },
    {
      id: 'legacy_tls',
      title: 'Downgrade Minimum TLS Version to TLS 1.0',
      category: 'Cryptographic Weakness',
      severity: 'HIGH',
      icon: ShieldAlert,
      color: 'text-orange-700 bg-orange-50 border-orange-200',
      description:
        'Lowers TLS threshold to deprecated TLS 1.0 on the primary production data lake, failing PCI-DSS and CIS benchmarks.',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#081420]/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-white border border-slate-200 rounded-2xl shadow-2xl p-6 text-[#16232F] space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-lg text-[#546471] hover:text-[#16232F] hover:bg-slate-100 transition-colors"
          aria-label="Close dialog"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center space-x-3 pr-10">
          <div className="p-3 rounded-xl bg-amber-50 text-[#D79A45] border border-amber-200">
            <Flame className="w-6 h-6" />
          </div>
          <div>
            <span className="rm-kicker">DRIFT & BREACH SIMULATION</span>
            <h2 className="font-serif text-lg sm:text-xl font-bold text-[#16232F]">
              Simulate Live Misconfiguration Injection
            </h2>
            <p className="text-xs text-[#546471]">
              Test Maniq Shield's Real-Time Alerting System by injecting a live security loophole into the cloud environment.
            </p>
          </div>
        </div>

        {/* Scenario Cards */}
        <div className="space-y-3 pt-1">
          {scenarios.map((sc) => {
            const Icon = sc.icon;
            return (
              <div
                key={sc.id}
                onClick={() => {
                  onInject(sc.id);
                  onClose();
                }}
                className="p-4 rounded-xl bg-slate-50 border border-slate-200 hover:border-[#D79A45] hover:bg-white transition-all cursor-pointer flex items-start justify-between gap-3 group"
              >
                <div className="flex items-start space-x-3.5">
                  <div
                    className={`p-2.5 rounded-lg border flex-shrink-0 mt-0.5 ${sc.color}`}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2 mb-1 font-mono text-[10px]">
                      <span className="font-bold uppercase px-2 py-0.5 rounded bg-red-600 text-white">
                        {sc.severity}
                      </span>
                      <span className="text-[#546471]">
                        {sc.category}
                      </span>
                    </div>
                    <h4 className="font-serif text-sm font-bold text-[#16232F] group-hover:text-[#1F8A79] transition-colors">
                      {sc.title}
                    </h4>
                    <p className="text-xs text-[#546471] mt-1 leading-relaxed">
                      {sc.description}
                    </p>
                  </div>
                </div>

                <button className="flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#0E2238] text-white group-hover:bg-[#2BB5A0] group-hover:text-[#081420] transition-all flex-shrink-0 self-center">
                  <span>Trigger Alert</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            );
          })}
        </div>

        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-[#546471] text-center">
          When triggered, the app will dispatch an immediate real-time alert with a direct link to the remediation runbook and update the PDF report.
        </div>
      </div>
    </div>
  );
};
