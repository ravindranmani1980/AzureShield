/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { X, ShieldAlert, Info } from 'lucide-react';
import { SecurityAlertNotification } from '../types/security';

interface AlertNotificationBannerProps {
  alerts: SecurityAlertNotification[];
  onDismiss: (id: string) => void;
  onClearAll?: () => void;
}

export const AlertNotificationBanner: React.FC<AlertNotificationBannerProps> = ({
  alerts = [],
  onDismiss,
  onClearAll,
}) => {
  if (!alerts || alerts.length === 0) return null;

  const topAlert = alerts[0];
  const isCritical = topAlert.severity === 'CRITICAL';
  const isHigh = topAlert.severity === 'HIGH';

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-md w-full animate-in fade-in slide-in-from-bottom-5 duration-200">
      <div
        className={`relative overflow-hidden rounded-xl p-4 shadow-2xl border bg-[#081420] text-[#F3F5F1] ${
          isCritical
            ? 'border-red-500/60'
            : isHigh
            ? 'border-[#D79A45]/60'
            : 'border-[#2BB5A0]/50'
        }`}
      >
        <div className="flex items-start space-x-3.5 relative z-10">
          <div
            className={`p-2 rounded-lg flex-shrink-0 flex items-center justify-center border ${
              isCritical
                ? 'bg-red-500/20 text-red-400 border-red-500/30'
                : isHigh
                ? 'bg-[#D79A45]/20 text-[#EBC385] border-[#D79A45]/30'
                : 'bg-[#2BB5A0]/20 text-[#5FD3BF] border-[#2BB5A0]/30'
            }`}
          >
            {isCritical || isHigh ? (
              <ShieldAlert className="w-5 h-5" />
            ) : (
              <Info className="w-5 h-5" />
            )}
          </div>

          <div className="flex-1 min-w-0 pr-6">
            <div className="flex items-center space-x-2 mb-1 font-mono text-[10px]">
              <span
                className={`uppercase tracking-wider font-bold px-2 py-0.5 rounded ${
                  isCritical
                    ? 'bg-red-600 text-white'
                    : isHigh
                    ? 'bg-[#D79A45] text-[#081420]'
                    : 'bg-[#2BB5A0] text-[#081420]'
                }`}
              >
                {topAlert.severity}
              </span>
              <span className="text-[#B7C3CC]">{topAlert.timestamp}</span>
              {alerts.length > 1 && onClearAll && (
                <button
                  onClick={onClearAll}
                  className="text-[#5FD3BF] hover:underline ml-auto"
                >
                  Clear All ({alerts.length})
                </button>
              )}
            </div>

            <h4 className="font-serif text-sm font-bold text-white line-clamp-1 mb-1">
              {topAlert.title}
            </h4>

            <p className="text-xs text-[#B7C3CC] line-clamp-2 leading-relaxed">
              {topAlert.message}
            </p>
          </div>

          <button
            onClick={() => onDismiss(topAlert.id)}
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
