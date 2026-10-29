/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { ArrowRight, X, ShieldAlert } from 'lucide-react';
import { SecurityAlert } from '../types/security';

interface AlertNotificationBannerProps {
  activeAlert: SecurityAlert | null;
  onDismiss: () => void;
  onViewRemediation: (findingId: string) => void;
}

export const AlertNotificationBanner: React.FC<AlertNotificationBannerProps> = ({
  activeAlert,
  onDismiss,
  onViewRemediation,
}) => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (activeAlert) {
      setIsVisible(true);
      const timer = setTimeout(() => {
        setIsVisible(false);
        onDismiss();
      }, 14000);
      return () => clearTimeout(timer);
    } else {
      setIsVisible(false);
    }
  }, [activeAlert, onDismiss]);

  if (!activeAlert || !isVisible) return null;

  const isCritical = activeAlert.severity === 'CRITICAL';

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-lg w-full animate-in fade-in slide-in-from-bottom-5 duration-200">
      <div
        className={`relative overflow-hidden rounded-xl p-4 shadow-2xl border bg-[#081420] text-[#F3F5F1] ${
          isCritical ? 'border-red-500/60' : 'border-[#D79A45]/60'
        }`}
      >
        <div className="flex items-start space-x-3.5 relative z-10">
          <div
            className={`p-2.5 rounded-lg flex-shrink-0 flex items-center justify-center border ${
              isCritical
                ? 'bg-red-500/20 text-red-400 border-red-500/30'
                : 'bg-[#D79A45]/20 text-[#EBC385] border-[#D79A45]/30'
            }`}
          >
            <ShieldAlert className="w-5 h-5 animate-pulse" />
          </div>

          <div className="flex-1 min-w-0 pr-6">
            <div className="flex items-center space-x-2 mb-1 font-mono text-[10px]">
              <span
                className={`uppercase tracking-wider font-bold px-2 py-0.5 rounded ${
                  isCritical
                    ? 'bg-red-600 text-white'
                    : 'bg-[#D79A45] text-[#081420]'
                }`}
              >
                REAL-TIME ALERT · {activeAlert.severity}
              </span>
              <span className="text-[#B7C3CC]">
                {activeAlert.timestamp}
              </span>
            </div>

            <h4 className="font-serif text-sm font-bold text-white line-clamp-1 mb-1">
              {activeAlert.title}
            </h4>

            <p className="text-xs text-[#B7C3CC] line-clamp-2 leading-relaxed mb-3">
              {activeAlert.summary}
            </p>

            <div className="flex items-center space-x-2 pt-2 border-t border-white/10">
              <button
                onClick={() => onViewRemediation(activeAlert.findingId)}
                className="xh-btn primary text-xs py-1 px-2.5"
              >
                <span>View Remediation Steps</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              <span className="text-[11px] text-[#B7C3CC] font-mono truncate max-w-[170px]">
                Target: {activeAlert.resourceName}
              </span>
            </div>
          </div>

          {/* Dismiss button */}
          <button
            onClick={() => {
              setIsVisible(false);
              onDismiss();
            }}
            className="absolute top-3 right-3 text-[#B7C3CC] hover:text-white p-1 rounded-md hover:bg-white/10 transition-colors"
            aria-label="Dismiss alert"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
