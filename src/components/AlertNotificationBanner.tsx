/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { AlertCircle, ArrowRight, X, ShieldAlert, Sparkles } from 'lucide-react';
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
      // Auto dismiss after 14 seconds unless dismissed manually
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
        className={`relative overflow-hidden rounded-2xl p-4 shadow-2xl border backdrop-blur-xl ${
          isCritical
            ? 'bg-gradient-to-r from-red-950/95 via-slate-900/95 to-slate-900/95 border-red-500/50 text-white shadow-red-950/50'
            : 'bg-gradient-to-r from-amber-950/95 via-slate-900/95 to-slate-900/95 border-amber-500/50 text-white shadow-amber-950/50'
        }`}
      >
        {/* Glow indicator */}
        <div
          className={`absolute -top-12 -left-12 w-28 h-28 rounded-full blur-2xl pointer-events-none opacity-40 ${
            isCritical ? 'bg-red-500' : 'bg-amber-500'
          }`}
        />

        <div className="flex items-start space-x-3.5 relative z-10">
          <div
            className={`p-2.5 rounded-xl flex-shrink-0 flex items-center justify-center ${
              isCritical
                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
            }`}
          >
            <ShieldAlert className="w-5 h-5 animate-pulse" />
          </div>

          <div className="flex-1 min-w-0 pr-6">
            <div className="flex items-center space-x-2 mb-1">
              <span
                className={`text-[10px] uppercase tracking-wider font-extrabold px-2 py-0.5 rounded-full ${
                  isCritical
                    ? 'bg-red-600 text-white'
                    : 'bg-amber-600 text-white'
                }`}
              >
                REAL-TIME ALERT • {activeAlert.severity}
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                {activeAlert.timestamp}
              </span>
            </div>

            <h4 className="text-sm font-bold text-slate-100 line-clamp-1 mb-1">
              {activeAlert.title}
            </h4>

            <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed mb-3">
              {activeAlert.summary}
            </p>

            <div className="flex items-center space-x-2 pt-1 border-t border-slate-800/80">
              <button
                onClick={() => onViewRemediation(activeAlert.findingId)}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold shadow-md transition-all active:scale-95 ${
                  isCritical
                    ? 'bg-red-600 hover:bg-red-500 text-white'
                    : 'bg-amber-600 hover:bg-amber-500 text-white'
                }`}
              >
                <span>View Remediation Steps</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              <span className="text-[11px] text-slate-400 font-mono truncate max-w-[170px]">
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
            className="absolute top-3 right-3 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
            aria-label="Dismiss alert"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
