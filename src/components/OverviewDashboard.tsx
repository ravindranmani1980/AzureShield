/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  AlertTriangle,
  Info,
  Server,
  Users,
  Unlock,
  FileCheck2,
  ArrowUpRight,
  TrendingUp,
  History,
  Activity,
  CheckCircle2,
  Zap,
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
} from 'recharts';
import { AuditMetrics, Finding, RemediationLogEntry } from '../types/security';
import { RemediationLog } from './RemediationLog';

interface OverviewDashboardProps {
  metrics: AuditMetrics;
  findings: Finding[];
  hardenedFindingsCount?: number;
  totalEvaluatedFindingsCount?: number;
  remediationLog?: RemediationLogEntry[];
  onClearRemediationLog?: () => void;
  onNavigateTab: (
    tab: 'inventory' | 'storage' | 'rbac' | 'findings' | 'remediation_log'
  ) => void;
  onFilterCategory?: (category: string) => void;
  onSelectFinding: (findingId: string) => void;
  onRemediateFinding?: (findingId: string) => void;
  onHardenAll?: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  metrics,
  findings,
  hardenedFindingsCount: hardenedCountProp,
  totalEvaluatedFindingsCount: totalEvaluatedProp,
  remediationLog = [],
  onClearRemediationLog,
  onNavigateTab,
  onSelectFinding,
  onRemediateFinding,
  onHardenAll,
}) => {
  // Local fallback state in case OverviewDashboard is rendered standalone without parent state handlers
  const [localHardenedIds, setLocalHardenedIds] = useState<string[]>([]);
  const [localRemediationLog, setLocalRemediationLog] = useState<RemediationLogEntry[]>([]);

  const createLogEntryFromFinding = (
    finding: Finding,
    method: RemediationLogEntry['remediationMethod'],
    scoreBefore: number,
    scoreAfter: number
  ): RemediationLogEntry => {
    const now = new Date();
    return {
      id: `remed-log-${now.getTime()}-${Math.random().toString(36).slice(2, 7)}`,
      findingId: finding.id,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      resourceId: finding.resourceId,
      resourceName: finding.resourceName,
      resourceType: finding.resourceType,
      remediatedAt: now.toISOString(),
      formattedTimestamp: now.toLocaleString(),
      remediationMethod: method,
      remediationSummary:
        finding.remediation?.summary || 'Applied security hardening configuration.',
      cliCommandExecuted: finding.remediation?.cliCommand || '',
      terraformSnippet: finding.remediation?.terraformSnippet,
      compliance: finding.compliance || {},
      subscriptionId: 'sub-prod-corp-001',
      postureScoreBefore: scoreBefore,
      postureScoreAfter: scoreAfter,
      operator: 'Mani Ravindran (SecOps Admin)',
    };
  };

  const handleQuickHarden = (findingId: string) => {
    if (onRemediateFinding) {
      onRemediateFinding(findingId);
    } else {
      const target = findings.find((f) => f.id === findingId);
      setLocalHardenedIds((prev) =>
        prev.includes(findingId) ? prev : [...prev, findingId]
      );
      if (target) {
        const entry = createLogEntryFromFinding(
          target,
          'Single Remediation',
          realtimePostureScore,
          Math.min(
            100,
            Math.round(
              ((hardenedFindingsCount + 1) / Math.max(1, totalFindingsCount)) * 100
            )
          )
        );
        setLocalRemediationLog((prev) => [entry, ...prev]);
      }
    }
  };

  const handleQuickHardenAll = () => {
    if (onHardenAll) {
      onHardenAll();
    } else {
      const unhardened = findings.filter((f) => !localHardenedIds.includes(f.id));
      setLocalHardenedIds(findings.map((f) => f.id));
      if (unhardened.length > 0) {
        const newEntries = unhardened.map((f, idx) =>
          createLogEntryFromFinding(
            f,
            'Bulk Hardening',
            realtimePostureScore,
            Math.min(
              100,
              Math.round(
                ((hardenedFindingsCount + idx + 1) /
                  Math.max(1, totalFindingsCount)) *
                  100
              )
            )
          )
        );
        setLocalRemediationLog((prev) => [...newEntries, ...prev]);
      }
    }
  };

  const effectiveRemediationLog =
    remediationLog.length > 0 ? remediationLog : localRemediationLog;

  // Count findings explicitly marked hardened in the findings array or via local fallback
  const inlineHardenedCount = findings.filter(
    (f) =>
      f.isHardened ||
      f.status === 'hardened' ||
      f.remediated ||
      localHardenedIds.includes(f.id)
  ).length;

  const activeOpenFindings = findings.filter(
    (f) =>
      !f.isHardened &&
      f.status !== 'hardened' &&
      !f.remediated &&
      !localHardenedIds.includes(f.id)
  );

  const openFindingsCount = activeOpenFindings.length;

  // Calculate real-time Hardened Findings vs. Total Findings ratio
  const baselineHardenedCount =
    typeof hardenedCountProp === 'number'
      ? hardenedCountProp
      : typeof metrics.hardenedFindingsCount === 'number'
      ? metrics.hardenedFindingsCount
      : 0;

  const hardenedFindingsCount = baselineHardenedCount + inlineHardenedCount;

  const totalFindingsCount =
    typeof totalEvaluatedProp === 'number'
      ? totalEvaluatedProp
      : typeof metrics.totalEvaluatedFindings === 'number'
      ? metrics.totalEvaluatedFindings
      : hardenedFindingsCount + openFindingsCount;

  // Real-time Security Posture Score calculated from ratio of hardened findings to total findings
  const realtimePostureScore =
    totalFindingsCount > 0
      ? Math.min(
          100,
          Math.max(0, Math.round((hardenedFindingsCount / totalFindingsCount) * 100))
        )
      : metrics.postureScore ?? 100;

  const dynamicRiskGrade =
    realtimePostureScore >= 95
      ? 'A+'
      : realtimePostureScore >= 85
      ? 'A'
      : realtimePostureScore >= 70
      ? 'B'
      : realtimePostureScore >= 55
      ? 'C'
      : realtimePostureScore >= 40
      ? 'D'
      : 'F';

  // Posture Score color
  const getScoreColor = (score: number) => {
    if (score >= 85) return 'text-emerald-700 stroke-[#2BB5A0]';
    if (score >= 70) return 'text-slate-800 stroke-[#0E2238]';
    if (score >= 55) return 'text-amber-700 stroke-[#D79A45]';
    return 'text-red-600 stroke-red-600';
  };

  const getProgressBarColor = (score: number) => {
    if (score >= 85) return 'bg-[#2BB5A0]';
    if (score >= 70) return 'bg-[#0E2238]';
    if (score >= 55) return 'bg-[#D79A45]';
    return 'bg-red-600';
  };

  const getRiskGradeBg = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      case 'B':
        return 'bg-slate-100 text-slate-800 border-slate-300';
      case 'C':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      default:
        return 'bg-red-50 text-red-700 border-red-200';
    }
  };

  const [timelineScope, setTimelineScope] = useState<'all' | 'session'>('all');
  const [showBenchmarks, setShowBenchmarks] = useState<boolean>(true);

  // Build historical + real-time remediation Compliance Timeline dataset
  const {
    complianceTimelineData,
    initialSessionScore,
    historicalStartScore,
    totalScoreGain,
  } = useMemo(() => {
    const sortedSessionEntries = [...effectiveRemediationLog].sort(
      (a, b) =>
        new Date(a.remediatedAt).getTime() - new Date(b.remediatedAt).getTime()
    );

    const sessionStartScore =
      sortedSessionEntries.length > 0
        ? sortedSessionEntries[0].postureScoreBefore
        : realtimePostureScore;

    const baseHistoricalStart = Math.max(12, sessionStartScore - 18);
    const cisDelta = (metrics.complianceScores?.cisAzure ?? 54) - sessionStartScore;
    const nistDelta = (metrics.complianceScores?.nist ?? 68) - sessionStartScore;

    const clampScore = (val: number) =>
      Math.min(100, Math.max(0, Math.round(val)));

    const historicalPoints = [
      {
        id: 'hist-1',
        label: 'T-30d',
        fullTimestamp: '30 Days Ago · Initial Discovery',
        postureScore: baseHistoricalStart,
        cisScore: clampScore(baseHistoricalStart + cisDelta - 4),
        nistScore: clampScore(baseHistoricalStart + nistDelta - 3),
        scoreDelta: 0,
        remediationCount: 0,
        eventTitle: 'Initial Tenant & ARM Baseline Discovery',
        resourceName: 'Subscription Scope',
        method: 'Automated Audit',
        severity: 'info',
        isLiveSession: false,
      },
      {
        id: 'hist-2',
        label: 'T-21d',
        fullTimestamp: '21 Days Ago · TLS & HTTPS Hardening',
        postureScore: Math.max(baseHistoricalStart + 4, sessionStartScore - 13),
        cisScore: clampScore(
          Math.max(baseHistoricalStart + 4, sessionStartScore - 13) + cisDelta - 2
        ),
        nistScore: clampScore(
          Math.max(baseHistoricalStart + 4, sessionStartScore - 13) + nistDelta - 2
        ),
        scoreDelta:
          Math.max(baseHistoricalStart + 4, sessionStartScore - 13) -
          baseHistoricalStart,
        remediationCount: 1,
        eventTitle: 'Enforced Minimum TLS 1.2 & HTTPS-Only Traffic',
        resourceName: 'stprodcorpdata01',
        method: 'Runbook Execution',
        severity: 'medium',
        isLiveSession: false,
      },
      {
        id: 'hist-3',
        label: 'T-14d',
        fullTimestamp: '14 Days Ago · Soft Delete Retention',
        postureScore: Math.max(baseHistoricalStart + 9, sessionStartScore - 8),
        cisScore: clampScore(
          Math.max(baseHistoricalStart + 9, sessionStartScore - 8) + cisDelta - 1
        ),
        nistScore: clampScore(
          Math.max(baseHistoricalStart + 9, sessionStartScore - 8) + nistDelta - 1
        ),
        scoreDelta:
          Math.max(baseHistoricalStart + 9, sessionStartScore - 8) -
          Math.max(baseHistoricalStart + 4, sessionStartScore - 13),
        remediationCount: 2,
        eventTitle: 'Enabled Blob & Container Soft-Delete Policy (14d)',
        resourceName: 'stfinancelogs02',
        method: 'Single Remediation',
        severity: 'medium',
        isLiveSession: false,
      },
      {
        id: 'hist-4',
        label: 'T-7d',
        fullTimestamp: '7 Days Ago · RBAC Scope Pruning',
        postureScore: Math.max(baseHistoricalStart + 14, sessionStartScore - 4),
        cisScore: clampScore(
          Math.max(baseHistoricalStart + 14, sessionStartScore - 4) + cisDelta
        ),
        nistScore: clampScore(
          Math.max(baseHistoricalStart + 14, sessionStartScore - 4) + nistDelta
        ),
        scoreDelta:
          Math.max(baseHistoricalStart + 14, sessionStartScore - 4) -
          Math.max(baseHistoricalStart + 9, sessionStartScore - 8),
        remediationCount: 3,
        eventTitle: 'Removed Stale Subscription Contributor Assignment',
        resourceName: 'svc-legacy-deploy-sp',
        method: 'Single Remediation',
        severity: 'high',
        isLiveSession: false,
      },
      {
        id: 'session-start',
        label: 'Session Start',
        fullTimestamp: 'Current Session Baseline Scan',
        postureScore: sessionStartScore,
        cisScore: clampScore(sessionStartScore + cisDelta),
        nistScore: clampScore(sessionStartScore + nistDelta),
        scoreDelta:
          sessionStartScore -
          Math.max(baseHistoricalStart + 14, sessionStartScore - 4),
        remediationCount: 3,
        eventTitle: 'Live Session Security Posture Baseline',
        resourceName: `${totalFindingsCount} Evaluated Controls`,
        method: 'Live Telemetry Scan',
        severity: 'info',
        isLiveSession: true,
      },
    ];

    const liveSessionPoints = sortedSessionEntries.map((entry, idx) => {
      const timeLabel = new Date(entry.remediatedAt).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
      const scoreAfter = entry.postureScoreAfter;
      const scoreBefore = entry.postureScoreBefore;
      return {
        id: entry.id,
        label: `Act #${idx + 1} (${timeLabel})`,
        fullTimestamp: `${entry.formattedTimestamp} · Live Remediation #${idx + 1}`,
        postureScore: scoreAfter,
        cisScore: clampScore(scoreAfter + cisDelta * 0.7),
        nistScore: clampScore(scoreAfter + nistDelta * 0.7),
        scoreDelta: Math.max(0, scoreAfter - scoreBefore),
        remediationCount: 3 + idx + 1,
        eventTitle: entry.title,
        resourceName: entry.resourceName,
        method: entry.remediationMethod,
        severity: entry.severity,
        isLiveSession: true,
      };
    });

    const lastRecordedScore =
      liveSessionPoints.length > 0
        ? liveSessionPoints[liveSessionPoints.length - 1].postureScore
        : sessionStartScore;

    if (realtimePostureScore !== lastRecordedScore) {
      liveSessionPoints.push({
        id: 'live-now',
        label: 'Current Now',
        fullTimestamp: 'Real-Time Hardened Posture',
        postureScore: realtimePostureScore,
        cisScore: clampScore(realtimePostureScore + cisDelta * 0.7),
        nistScore: clampScore(realtimePostureScore + nistDelta * 0.7),
        scoreDelta: Math.max(0, realtimePostureScore - lastRecordedScore),
        remediationCount: 3 + liveSessionPoints.length + 1,
        eventTitle: 'Real-Time Control Hardening Applied',
        resourceName: `${hardenedFindingsCount}/${totalFindingsCount} Controls Hardened`,
        method: 'Single Remediation',
        severity: 'high',
        isLiveSession: true,
      });
    }

    const fullSeries = [...historicalPoints, ...liveSessionPoints];
    const scopedSeries =
      timelineScope === 'session'
        ? [historicalPoints[historicalPoints.length - 1], ...liveSessionPoints]
        : fullSeries;

    const referenceStart =
      timelineScope === 'session' ? sessionStartScore : baseHistoricalStart;

    return {
      complianceTimelineData: scopedSeries,
      initialSessionScore: sessionStartScore,
      historicalStartScore: baseHistoricalStart,
      totalScoreGain: Math.max(0, realtimePostureScore - referenceStart),
    };
  }, [
    effectiveRemediationLog,
    realtimePostureScore,
    metrics.complianceScores,
    totalFindingsCount,
    hardenedFindingsCount,
    timelineScope,
  ]);

  const categoryBreakdown = [
    {
      name: 'Storage Accounts & Blobs',
      count: activeOpenFindings.filter((f) => f.category === 'storage').length,
      icon: Server,
      barColor: 'bg-[#0E2238]',
      tab: 'storage' as const,
    },
    {
      name: 'RBAC & Overprivileged Roles',
      count: activeOpenFindings.filter((f) => f.category === 'rbac').length,
      icon: Users,
      barColor: 'bg-[#2BB5A0]',
      tab: 'rbac' as const,
    },
    {
      name: 'Privilege Escalation Risks',
      count: activeOpenFindings.filter((f) => f.category === 'privilege_escalation').length,
      icon: Unlock,
      barColor: 'bg-red-600',
      tab: 'rbac' as const,
    },
    {
      name: 'Network Perimeter & Firewalls',
      count: activeOpenFindings.filter((f) => f.category === 'network').length,
      icon: ShieldAlert,
      barColor: 'bg-[#D79A45]',
      tab: 'storage' as const,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Executive Panel (Postrix .xh-panel signature hero) */}
      <section className="xh-panel space-y-5">
        <div className="xh-kicker">
          <span className="k">
            Maniq Shield · Continuous Cloud Storage &amp; RBAC Posture Audit
          </span>
          <span className="tag">
            {metrics.totalResources} Azure Assets Evaluated · Grade {dynamicRiskGrade}
          </span>
        </div>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[#EEF3F1]">
              Maniq Shield — Storage &amp; RBAC Security Posture
            </h1>
            <p className="text-sm text-[#A9B7BF] leading-relaxed">
              Auditing Azure Storage Accounts for anonymous blob exposure, insecure HTTP transport, deprecated TLS versions, and analyzing Azure Entra ID / RBAC assignments for privilege escalation and excessive credentials.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => onNavigateTab('inventory')}
              className="xh-btn"
            >
              <span>Inspect Asset Inventory</span>
            </button>
            <button
              type="button"
              onClick={() => onNavigateTab('storage')}
              className="xh-btn primary"
            >
              <span>Open Topology &amp; Storage Auditor</span>
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Postrix .xh-metric 4-column grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 pt-1">
          <div
            onClick={() => onNavigateTab('findings')}
            className="xh-metric cursor-pointer hover:border-[#5FD3BF]/60 transition-colors"
          >
            <div className="lbl">
              <span>POSTURE SCORE</span>
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div className="num hi tabular-nums">
              {realtimePostureScore}%
              <span className="text-xs font-normal text-[#A9B7BF] ml-2">
                (Grade {dynamicRiskGrade})
              </span>
            </div>
            <p>
              {hardenedFindingsCount} of {totalFindingsCount} evaluated security controls hardened
            </p>
          </div>

          <div
            onClick={() => onNavigateTab('storage')}
            className="xh-metric cursor-pointer hover:border-[#5FD3BF]/60 transition-colors"
          >
            <div className="lbl">
              <span>EXPOSED CONTAINERS</span>
              <Server className="w-4 h-4" />
            </div>
            <div className="num tabular-nums">
              {metrics.exposedContainerCount || metrics.openBucketCount}
              <span className="text-xs font-normal text-[#A9B7BF] ml-2">
                Containers
              </span>
            </div>
            <p>Anonymous public blob or container read/list exposure</p>
          </div>

          <div
            onClick={() => onNavigateTab('rbac')}
            className="xh-metric cursor-pointer hover:border-[#5FD3BF]/60 transition-colors"
          >
            <div className="lbl">
              <span>ESCALATION PATHS</span>
              <Unlock className="w-4 h-4" />
            </div>
            <div className="num tabular-nums">
              {metrics.privilegeEscalationCount}
              <span className="text-xs font-normal text-[#A9B7BF] ml-2">
                Vectors
              </span>
            </div>
            <p>Wildcard or roleAssignments/write elevation risks</p>
          </div>

          <div
            onClick={() => onNavigateTab('remediation_log')}
            className="xh-metric cursor-pointer hover:border-[#5FD3BF]/60 transition-colors"
          >
            <div className="lbl">
              <span>SESSION REMEDIATIONS</span>
              <History className="w-4 h-4" />
            </div>
            <div className="num hi tabular-nums">
              {effectiveRemediationLog.length}
              <span className="text-xs font-normal text-[#A9B7BF] ml-2">
                Logged
              </span>
            </div>
            <p>{openFindingsCount} open loopholes awaiting remediation</p>
          </div>
        </div>
      </section>

      {/* Main Grid: Posture Meter & Severity Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Posture Meter Card */}
        <div className="lg:col-span-4 bg-white rounded-xl p-6 border border-slate-200 shadow-xs flex flex-col justify-between">
          <div className="flex items-start justify-between mb-2">
            <div>
              <span className="rm-kicker">Posture Ratio</span>
              <h3 className="font-serif font-semibold text-slate-900 text-base">
                Security Posture Score
              </h3>
              <p className="text-xs text-slate-500">
                Real-time Hardened vs. Total Findings Ratio
              </p>
            </div>
            <span
              className={`text-xs px-2.5 py-0.5 rounded font-mono font-semibold border ${getRiskGradeBg(
                dynamicRiskGrade
              )}`}
            >
              Grade {dynamicRiskGrade}
            </span>
          </div>

          {/* Circular Score Gauge */}
          <div className="flex flex-col items-center justify-center my-3">
            <div className="relative w-36 h-36 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  className="stroke-slate-200 fill-none"
                  strokeWidth="8"
                />
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  className={`fill-none transition-all duration-700 ease-out ${getScoreColor(
                    realtimePostureScore
                  )}`}
                  strokeWidth="8"
                  strokeDasharray={264}
                  strokeDashoffset={264 - (264 * realtimePostureScore) / 100}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="text-3xl font-bold font-mono text-slate-900 tracking-tighter tabular-nums">
                  {realtimePostureScore}%
                </span>
                <span className="text-[10px] text-slate-500 font-mono uppercase tracking-wider">
                  {hardenedFindingsCount}/{totalFindingsCount} Hardened
                </span>
              </div>
            </div>

            <p className="text-xs text-center text-slate-600 mt-2 max-w-xs">
              {realtimePostureScore >= 85
                ? 'Hardened posture. Low attack surface across Azure Storage and RBAC.'
                : realtimePostureScore >= 60
                ? 'Moderate posture risk. Harden remaining storage & RBAC findings.'
                : 'CRITICAL EXPOSURE. Public containers or excessive RBAC roles require immediate hardening.'}
            </p>
          </div>

          {/* Real-Time Hardened Findings Ratio Progress Bar */}
          <div className="my-3 p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2.5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-800 flex items-center space-x-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-700" />
                <span>Hardening Progress</span>
              </span>
              <span className="font-mono font-semibold text-slate-900 tabular-nums">
                {hardenedFindingsCount} / {totalFindingsCount} ({realtimePostureScore}%)
              </span>
            </div>

            <div
              role="progressbar"
              aria-label="Security Posture Score"
              aria-valuenow={realtimePostureScore}
              aria-valuemin={0}
              aria-valuemax={100}
              className="relative w-full bg-slate-200 h-2.5 rounded-full overflow-hidden"
            >
              <div
                className={`h-full ${getProgressBarColor(
                  realtimePostureScore
                )} rounded-full transition-all duration-700 ease-out`}
                style={{ width: `${realtimePostureScore}%` }}
              />
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-600 font-mono pt-0.5">
              <span className="flex items-center space-x-1 text-emerald-700 font-semibold">
                <CheckCircle2 className="w-3 h-3" />
                <span>{hardenedFindingsCount} Hardened</span>
              </span>
              <span className="text-amber-700 font-semibold">
                {openFindingsCount} Open
              </span>
              <span>{totalFindingsCount} Total</span>
            </div>

            {openFindingsCount > 0 && (
              <button
                type="button"
                onClick={handleQuickHardenAll}
                className="w-full mt-1 py-2 px-3 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#081420] text-[#EEF3F1] transition-all flex items-center justify-center space-x-1.5 cursor-pointer"
              >
                <Zap className="w-3.5 h-3.5 text-[#5FD3BF]" />
                <span>Harden All Remaining ({openFindingsCount})</span>
              </button>
            )}
          </div>

          {/* Quick Metrics Footer */}
          <div className="pt-3 border-t border-slate-200 grid grid-cols-2 gap-3 text-center">
            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <div className="text-xs text-slate-500">Open Loopholes</div>
              <div className="text-xl font-bold font-mono text-slate-900 tabular-nums">
                {openFindingsCount}
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <div className="text-xs text-slate-500">Hardened Findings</div>
              <div className="text-xl font-bold font-mono text-emerald-700 tabular-nums">
                {hardenedFindingsCount}
              </div>
            </div>
          </div>
        </div>

        {/* Severity Matrix & Visual Analytics */}
        <div className="lg:col-span-8 space-y-6">
          {/* Severity Counters Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-xl bg-white border border-slate-200 hover:border-red-400 cursor-pointer transition-all shadow-xs group"
            >
              <div className="flex items-center justify-between text-red-700 mb-1">
                <span className="text-xs font-mono font-semibold tracking-wider uppercase">
                  Critical
                </span>
                <AlertOctagon className="w-4 h-4" />
              </div>
              <div className="text-2xl font-bold font-mono text-slate-900 group-hover:text-red-700 transition-colors tabular-nums">
                {metrics.criticalCount}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                Zero-barrier exploits
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-xl bg-white border border-slate-200 hover:border-orange-400 cursor-pointer transition-all shadow-xs group"
            >
              <div className="flex items-center justify-between text-orange-700 mb-1">
                <span className="text-xs font-mono font-semibold tracking-wider uppercase">
                  High
                </span>
                <AlertTriangle className="w-4 h-4" />
              </div>
              <div className="text-2xl font-bold font-mono text-slate-900 group-hover:text-orange-700 transition-colors tabular-nums">
                {metrics.highCount}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                Perimeter &amp; token risks
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-xl bg-white border border-slate-200 hover:border-amber-400 cursor-pointer transition-all shadow-xs group"
            >
              <div className="flex items-center justify-between text-amber-700 mb-1">
                <span className="text-xs font-mono font-semibold tracking-wider uppercase">
                  Medium
                </span>
                <Info className="w-4 h-4" />
              </div>
              <div className="text-2xl font-bold font-mono text-slate-900 group-hover:text-amber-700 transition-colors tabular-nums">
                {metrics.mediumCount}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                Governance &amp; logging gaps
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-xl bg-white border border-slate-200 hover:border-emerald-500 cursor-pointer transition-all shadow-xs group"
            >
              <div className="flex items-center justify-between text-emerald-700 mb-1">
                <span className="text-xs font-mono font-semibold tracking-wider uppercase">
                  Low
                </span>
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div className="text-2xl font-bold font-mono text-slate-900 group-hover:text-emerald-700 transition-colors tabular-nums">
                {metrics.lowCount}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                Hardening recommendations
              </div>
            </div>
          </div>

          {/* Visual Aids: Frequency by Category */}
          <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs">
            <div className="flex items-center justify-between mb-4">
              <div>
                <span className="rm-kicker">Domain Distribution</span>
                <h3 className="font-serif font-semibold text-slate-900 text-base">
                  Misconfiguration Frequency by Domain
                </h3>
              </div>
              <span className="text-xs font-mono text-slate-500">
                Visual Analytics (Included in PDF)
              </span>
            </div>

            <div className="space-y-4">
              {categoryBreakdown.map((item) => {
                const max = Math.max(1, metrics.totalFindings);
                const percent = Math.round((item.count / max) * 100);
                const Icon = item.icon;

                return (
                  <div
                    key={item.name}
                    onClick={() => onNavigateTab(item.tab)}
                    className="group cursor-pointer"
                  >
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <div className="flex items-center space-x-2 text-slate-700 group-hover:text-slate-900 font-medium transition-colors">
                        <Icon className="w-4 h-4 text-slate-500 group-hover:text-emerald-700 transition-colors" />
                        <span>{item.name}</span>
                      </div>
                      <div className="flex items-center space-x-2 font-mono tabular-nums">
                        <span className="text-slate-600">
                          {item.count} issues
                        </span>
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-800 border border-slate-200 font-semibold">
                          {percent}%
                        </span>
                      </div>
                    </div>
                    <div className="w-full bg-slate-100 h-2.5 rounded-full overflow-hidden border border-slate-200">
                      <div
                        className={`h-full ${item.barColor} rounded-full transition-all duration-700`}
                        style={{ width: `${Math.max(4, percent)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Framework Scorecards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono font-semibold text-slate-600 uppercase tracking-wider">
              CIS Azure Foundations 2.0
            </span>
            <FileCheck2 className="w-4 h-4 text-emerald-700" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-bold font-mono text-slate-900 tabular-nums">
              {metrics.complianceScores.cisAzure}%
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              Passing benchmark controls
            </div>
          </div>
          <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden border border-slate-200">
            <div
              className={`h-full ${
                metrics.complianceScores.cisAzure >= 80
                  ? 'bg-[#2BB5A0]'
                  : 'bg-[#D79A45]'
              }`}
              style={{ width: `${metrics.complianceScores.cisAzure}%` }}
            />
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono font-semibold text-slate-600 uppercase tracking-wider">
              Microsoft Cloud Security (MCSB)
            </span>
            <FileCheck2 className="w-4 h-4 text-slate-700" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-bold font-mono text-slate-900 tabular-nums">
              {metrics.complianceScores.mcsb}%
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              Data protection &amp; identity baseline
            </div>
          </div>
          <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden border border-slate-200">
            <div
              className={`h-full ${
                metrics.complianceScores.mcsb >= 80
                  ? 'bg-[#2BB5A0]'
                  : 'bg-[#D79A45]'
              }`}
              style={{ width: `${metrics.complianceScores.mcsb}%` }}
            />
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono font-semibold text-slate-600 uppercase tracking-wider">
              NIST SP 800-53 Rev. 5
            </span>
            <FileCheck2 className="w-4 h-4 text-amber-700" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-bold font-mono text-slate-900 tabular-nums">
              {metrics.complianceScores.nist}%
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              Access control (AC) &amp; encryption (SC)
            </div>
          </div>
          <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden border border-slate-200">
            <div
              className={`h-full ${
                metrics.complianceScores.nist >= 80
                  ? 'bg-[#2BB5A0]'
                  : 'bg-[#D79A45]'
              }`}
              style={{ width: `${metrics.complianceScores.nist}%` }}
            />
          </div>
        </div>
      </div>

      {/* Compliance Timeline Section (Recharts LineChart in Postrix Light Skin) */}
      <section className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-6">
          <div className="space-y-1">
            <span className="rm-kicker">Historical Trend &amp; Telemetry</span>
            <div className="flex items-center flex-wrap gap-2.5">
              <h3 className="font-serif font-semibold text-slate-900 text-lg">
                Compliance Timeline &amp; Posture Trajectory
              </h3>
              <span className="px-2 py-0.5 text-[11px] font-mono font-semibold rounded bg-emerald-50 text-emerald-800 border border-emerald-200 tabular-nums whitespace-nowrap shrink-0">
                +{totalScoreGain}% Posture Gain
              </span>
            </div>
            <p className="text-xs text-slate-600">
              Historical security posture score progression and real-time impact of remediation actions across CIS Azure &amp; NIST controls
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setShowBenchmarks((prev) => !prev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all flex items-center space-x-1.5 whitespace-nowrap shrink-0 cursor-pointer ${
                showBenchmarks
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-300'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-slate-900'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>CIS &amp; NIST Overlay</span>
            </button>

            <div className="inline-flex rounded-lg bg-slate-100 p-1 border border-slate-200">
              <button
                type="button"
                onClick={() => setTimelineScope('all')}
                className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-all whitespace-nowrap shrink-0 cursor-pointer ${
                  timelineScope === 'all'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                30d + Live Session
              </button>
              <button
                type="button"
                onClick={() => setTimelineScope('session')}
                className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-all whitespace-nowrap shrink-0 cursor-pointer ${
                  timelineScope === 'session'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Session Only ({effectiveRemediationLog.length})
              </button>
            </div>

            {activeOpenFindings.length > 0 && (
              <button
                type="button"
                onClick={() => handleQuickHarden(activeOpenFindings[0].id)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#0E2238] hover:bg-[#081420] text-[#EEF3F1] transition-all flex items-center space-x-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                title={`Remediate: ${activeOpenFindings[0].title}`}
              >
                <Zap className="w-3.5 h-3.5 text-[#5FD3BF]" />
                <span>Harden Next Finding</span>
              </button>
            )}
          </div>
        </div>

        {/* Summary KPI Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[11px] font-mono font-medium text-slate-500 uppercase tracking-wider">
              {timelineScope === 'session' ? 'Session Start Score' : '30-Day Starting Score'}
            </div>
            <div className="text-xl font-bold text-slate-900 font-mono tabular-nums mt-1">
              {timelineScope === 'session' ? initialSessionScore : historicalStartScore}%
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Pre-remediation baseline
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[11px] font-mono font-medium text-slate-500 uppercase tracking-wider">
              Current Posture Score
            </div>
            <div className="text-xl font-bold text-emerald-700 font-mono tabular-nums mt-1">
              {realtimePostureScore}%
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Grade {dynamicRiskGrade} · Target 85%
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[11px] font-mono font-medium text-slate-500 uppercase tracking-wider">
              Net Posture Improvement
            </div>
            <div className="text-xl font-bold text-[#0E2238] font-mono tabular-nums mt-1">
              +{totalScoreGain}%
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Cumulative hardening delta
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[11px] font-mono font-medium text-slate-500 uppercase tracking-wider">
              Session Remediations
            </div>
            <div className="text-xl font-bold text-amber-700 font-mono tabular-nums mt-1">
              {effectiveRemediationLog.length}
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              {hardenedFindingsCount} of {totalFindingsCount} total hardened
            </div>
          </div>
        </div>

        {/* Recharts LineChart Container */}
        <div className="h-72 w-full bg-[#F3F5F1] rounded-xl border border-slate-200 p-4">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={complianceTimelineData}
              margin={{ top: 12, right: 24, left: 0, bottom: 8 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#d9ddd3"
                vertical={false}
              />
              <XAxis
                dataKey="label"
                stroke="#4b5a66"
                tick={{ fill: '#394a56', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                tickLine={{ stroke: '#c7cdc0' }}
                axisLine={{ stroke: '#c7cdc0' }}
              />
              <YAxis
                domain={[0, 100]}
                tickFormatter={(val) => `${val}%`}
                stroke="#4b5a66"
                tick={{ fill: '#394a56', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                tickLine={{ stroke: '#c7cdc0' }}
                axisLine={{ stroke: '#c7cdc0' }}
                width={44}
              />
              <Tooltip
                content={({ active, payload }) => {
                  if (!active || !payload || !payload.length) return null;
                  const point = payload[0].payload;
                  return (
                    <div className="bg-[#081420] text-[#EEF3F1] border border-[#3E6E86] rounded-xl p-3.5 shadow-xl max-w-xs space-y-2">
                      <div className="flex items-center justify-between gap-3 border-b border-[#3E6E86]/40 pb-2">
                        <span className="text-[11px] font-mono text-[#A9B7BF]">
                          {point.fullTimestamp}
                        </span>
                        <span
                          className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded uppercase ${
                            point.isLiveSession
                              ? 'bg-[#2BB5A0]/20 text-[#5FD3BF] border border-[#5FD3BF]/30'
                              : 'bg-[#102236] text-[#A9B7BF] border border-[#3E6E86]/40'
                          }`}
                        >
                          {point.isLiveSession ? 'Live Session' : 'Historical'}
                        </span>
                      </div>

                      <div>
                        <div className="text-xs font-semibold text-white">
                          {point.eventTitle}
                        </div>
                        <div className="text-[11px] font-mono text-[#A9B7BF] mt-0.5">
                          Target: {point.resourceName} · {point.method}
                        </div>
                      </div>

                      <div className="grid grid-cols-3 gap-2 pt-1 border-t border-[#3E6E86]/40 text-center font-mono">
                        <div>
                          <div className="text-[10px] text-[#A9B7BF]">Posture</div>
                          <div className="text-xs font-bold text-[#5FD3BF] tabular-nums">
                            {point.postureScore}%
                          </div>
                        </div>
                        <div>
                          <div className="text-[10px] text-[#A9B7BF]">Delta</div>
                          <div className="text-xs font-bold text-[#EBC385] tabular-nums">
                            {point.scoreDelta >= 0
                              ? `+${point.scoreDelta}%`
                              : `${point.scoreDelta}%`}
                          </div>
                        </div>
                        <div>
                          <div className="text-[10px] text-[#A9B7BF]">CIS v2.0</div>
                          <div className="text-xs font-bold text-white tabular-nums">
                            {point.cisScore}%
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                }}
              />
              <ReferenceLine
                y={85}
                stroke="#246a65"
                strokeDasharray="4 4"
                strokeOpacity={0.7}
                label={{
                  value: 'Target 85% (Grade A)',
                  position: 'insideTopRight',
                  fill: '#246a65',
                  fontSize: 10,
                  fontFamily: 'IBM Plex Mono',
                }}
              />
              {showBenchmarks && (
                <>
                  <Line
                    type="monotone"
                    dataKey="cisScore"
                    name="CIS Azure v2.0"
                    stroke="#0e2238"
                    strokeWidth={1.75}
                    strokeDasharray="4 4"
                    dot={{ r: 3, fill: '#0e2238', strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: '#0e2238' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="nistScore"
                    name="NIST SP 800-53"
                    stroke="#d79a45"
                    strokeWidth={1.75}
                    strokeDasharray="2 3"
                    dot={{ r: 3, fill: '#d79a45', strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: '#ebc385' }}
                  />
                </>
              )}
              <Line
                type="monotone"
                dataKey="postureScore"
                name="Security Posture Score"
                stroke="#246a65"
                strokeWidth={3}
                dot={{
                  r: 4,
                  fill: '#2bb5a0',
                  stroke: '#16232f',
                  strokeWidth: 1.5,
                }}
                activeDot={{
                  r: 6,
                  fill: '#2bb5a0',
                  stroke: '#081420',
                  strokeWidth: 2,
                }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Chart Legend & Live Event Feed Footer */}
        <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-slate-200 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center space-x-2">
              <span className="w-3 h-1 rounded-full bg-[#246a65] inline-block" />
              <span className="text-slate-800 font-medium">
                Overall Security Posture Score
              </span>
            </div>
            {showBenchmarks && (
              <>
                <div className="flex items-center space-x-2">
                  <span className="w-3 h-0.5 bg-[#0e2238] inline-block" />
                  <span className="text-slate-600">CIS Azure v2.0 Benchmark</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="w-3 h-0.5 bg-[#d79a45] inline-block" />
                  <span className="text-slate-600">NIST SP 800-53 Rev. 5</span>
                </div>
              </>
            )}
            <div className="flex items-center space-x-2">
              <span className="w-3 h-0.5 border-b border-dashed border-emerald-700 inline-block" />
              <span className="text-slate-600">85% Target Threshold</span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => onNavigateTab('remediation_log')}
            className="text-xs font-semibold text-emerald-700 hover:text-emerald-900 flex items-center space-x-1 self-start sm:self-auto whitespace-nowrap shrink-0 cursor-pointer"
          >
            <History className="w-3.5 h-3.5" />
            <span>Inspect Full Remediation Audit Trail</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </section>

      {/* Critical Action Items List */}
      <section className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <div>
            <span className="rm-kicker">Priority Queue</span>
            <h3 className="font-serif font-semibold text-slate-900 text-lg">
              Immediate Action Items (Priority Remediation)
            </h3>
            <p className="text-xs text-slate-600">
              Harden vulnerabilities directly to improve your real-time Security Posture Score
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigateTab('findings')}
            className="text-xs font-semibold text-emerald-700 hover:underline flex items-center space-x-1 cursor-pointer"
          >
            <span>View All ({activeOpenFindings.length})</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {activeOpenFindings.length === 0 ? (
          <div className="p-6 rounded-xl bg-emerald-50 border border-emerald-200 text-center space-y-2">
            <ShieldCheck className="w-8 h-8 text-emerald-700 mx-auto" />
            <div className="text-sm font-bold text-emerald-900">
              100% Hardened Security Posture Achieved
            </div>
            <p className="text-xs text-slate-600 max-w-md mx-auto">
              All {totalFindingsCount} evaluated security findings across Azure Storage Accounts, Blob Containers, and RBAC assignments are hardened.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {activeOpenFindings.slice(0, 4).map((finding) => (
              <div
                key={finding.id}
                onClick={() => onSelectFinding(finding.id)}
                className="p-4 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-400 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
              >
                <div className="flex items-start space-x-3">
                  <div className="p-2 rounded-lg bg-red-50 text-red-700 border border-red-200 flex-shrink-0 mt-0.5">
                    <AlertOctagon className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-slate-900 group-hover:text-red-700 transition-colors">
                        {finding.title}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-700 font-mono">
                        {finding.category.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 line-clamp-1 mt-0.5">
                      {finding.description}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-2 self-end sm:self-center flex-shrink-0">
                  <span className="text-xs font-mono text-slate-500 hidden md:inline">
                    {finding.resourceName}
                  </span>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleQuickHarden(finding.id);
                    }}
                    className="px-3 py-1.5 rounded-md text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200 hover:bg-[#2BB5A0] hover:text-[#04211B] transition-all flex items-center space-x-1 cursor-pointer"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Harden</span>
                  </button>
                  <button
                    type="button"
                    className="px-3 py-1.5 rounded-md text-xs font-semibold bg-[#0E2238] text-[#EEF3F1] hover:bg-[#081420] transition-all cursor-pointer"
                  >
                    Runbook
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Live Session Remediation Log Panel */}
      <RemediationLog
        entries={effectiveRemediationLog}
        onClearLog={
          onClearRemediationLog || (() => setLocalRemediationLog([]))
        }
        compact={true}
        onViewAllClick={() => onNavigateTab('remediation_log')}
      />
    </div>
  );
};
