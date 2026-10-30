/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useMemo } from 'react';
import {
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Tooltip,
  Legend,
} from 'recharts';
import { ShieldCheck, Info, CheckCircle2, AlertCircle } from 'lucide-react';
import { AuditMetrics } from '../types/security';

interface DashboardWidgetProps {
  metrics: AuditMetrics;
  onOpenGovernance?: () => void;
}

export const DashboardWidget: React.FC<DashboardWidgetProps> = ({
  metrics,
  onOpenGovernance,
}) => {
  const cisChecks = metrics.frameworkChecks?.cisAzure || {
    passed: 0,
    failed: 0,
    unknown: 7,
    totalSelected: 7,
    passRate: metrics.complianceScores.cisAzure || 0,
  };

  const mcsbChecks = metrics.frameworkChecks?.mcsb || {
    passed: 0,
    failed: 0,
    unknown: 6,
    totalSelected: 6,
    passRate: metrics.complianceScores.mcsb || 0,
  };

  const nistChecks = metrics.frameworkChecks?.nist || {
    passed: 0,
    failed: 0,
    unknown: 5,
    totalSelected: 5,
    passRate: metrics.complianceScores.nist || 0,
  };

  const radarData = useMemo(
    () => [
      {
        framework: 'CIS Azure v2.0',
        shortName: 'CIS',
        score: metrics.complianceScores.cisAzure,
        passRate: cisChecks.passRate,
        target: 90,
        passed: cisChecks.passed,
        failed: cisChecks.failed,
        total: cisChecks.totalSelected,
      },
      {
        framework: 'MCSB v1.0',
        shortName: 'MCSB',
        score: metrics.complianceScores.mcsb,
        passRate: mcsbChecks.passRate,
        target: 90,
        passed: mcsbChecks.passed,
        failed: mcsbChecks.failed,
        total: mcsbChecks.totalSelected,
      },
      {
        framework: 'NIST SP 800-53',
        shortName: 'NIST',
        score: metrics.complianceScores.nist,
        passRate: nistChecks.passRate,
        target: 90,
        passed: nistChecks.passed,
        failed: nistChecks.failed,
        total: nistChecks.totalSelected,
      },
    ],
    [
      metrics.complianceScores.cisAzure,
      metrics.complianceScores.mcsb,
      metrics.complianceScores.nist,
      cisChecks,
      mcsbChecks,
      nistChecks,
    ]
  );

  const averageCompliance = Math.round(
    (metrics.complianceScores.cisAzure +
      metrics.complianceScores.mcsb +
      metrics.complianceScores.nist) /
      3
  );

  return (
    <div className="rounded-xl border border-slate-200/90 bg-white p-5 shadow-xs flex flex-col justify-between h-full">
      <div>
        <div className="flex items-start justify-between gap-2 mb-3">
          <div>
            <span className="rm-kicker">COMPARATIVE COMPLIANCE RADAR</span>
            <div className="flex items-center space-x-2 mt-0.5">
              <ShieldCheck className="w-4 h-4 text-[#1F8A79]" />
              <h3 className="font-serif text-base font-bold text-[#16232F]">
                Framework Alignment (CIS · MCSB · NIST)
              </h3>
            </div>
            <p className="text-xs text-[#546471] mt-0.5">
              Comparative posture across 18 selected heuristic controls vs. 90% target benchmark.
            </p>
          </div>

          <div className="flex flex-col items-end">
            <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-[#081420] text-[#5FD3BF] border border-slate-800">
              Avg {averageCompliance}%
            </span>
            {onOpenGovernance && (
              <button
                onClick={onOpenGovernance}
                className="text-[11px] font-semibold text-[#1F8A79] hover:underline flex items-center space-x-1 mt-1"
              >
                <Info className="w-3 h-3" />
                <span>Control Scope</span>
              </button>
            )}
          </div>
        </div>

        <div className="h-60 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart cx="50%" cy="52%" outerRadius="72%" data={radarData}>
              <PolarGrid stroke="#cbd5e1" strokeDasharray="3 3" />
              <PolarAngleAxis
                dataKey="framework"
                tick={{ fill: '#16232F', fontSize: 11, fontWeight: 600 }}
              />
              <PolarRadiusAxis
                angle={30}
                domain={[0, 100]}
                tick={{ fill: '#546471', fontSize: 10 }}
                tickFormatter={(v) => `${v}%`}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#081420',
                  borderColor: '#1e293b',
                  borderRadius: '0.75rem',
                  fontSize: '12px',
                  color: '#F3F5F1',
                }}
                labelStyle={{
                  color: '#5FD3BF',
                  fontWeight: 600,
                  marginBottom: '4px',
                }}
                formatter={(value: any, name: any, props: any) => {
                  if (name === 'Current Score') {
                    return [
                      `${value}% (${props.payload.passed}/${props.payload.total} controls passed)`,
                      'Current Compliance',
                    ];
                  }
                  return [`${value}%`, name];
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: '11px', paddingTop: '4px' }}
              />
              <Radar
                name="Target Benchmark (90%)"
                dataKey="target"
                stroke="#D79A45"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                fill="#D79A45"
                fillOpacity={0.08}
              />
              <Radar
                name="Current Score"
                dataKey="score"
                stroke="#2BB5A0"
                strokeWidth={2.5}
                fill="#2BB5A0"
                fillOpacity={0.32}
                dot={{ r: 4, fill: '#081420', stroke: '#2BB5A0', strokeWidth: 2 }}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Compact Framework Score Pills */}
      <div className="grid grid-cols-3 gap-2 pt-3 border-t border-slate-200/80">
        {radarData.map((item) => {
          const isPassing = item.score >= 80;
          return (
            <div
              key={item.shortName}
              className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/80 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold text-[#16232F]">
                  {item.shortName}
                </span>
                {isPassing ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#1F8A79]" />
                ) : (
                  <AlertCircle className="w-3.5 h-3.5 text-[#D79A45]" />
                )}
              </div>
              <div className="font-serif text-lg font-bold text-[#16232F] mt-0.5">
                {item.score}%
              </div>
              <div className="text-[10px] font-mono text-[#546471]">
                {item.passed}/{item.total} Passed · {item.failed} Fail
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
