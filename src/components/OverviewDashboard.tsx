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
  KeyRound,
  FileCheck2,
  ArrowUpRight,
  TrendingDown,
  TrendingUp,
  History,
  Activity,
  Sparkles,
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
  onFilterCategory,
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
    if (score >= 85) return 'text-emerald-400 stroke-emerald-500';
    if (score >= 70) return 'text-blue-400 stroke-blue-500';
    if (score >= 55) return 'text-amber-400 stroke-amber-500';
    return 'text-red-400 stroke-red-500';
  };

  const getProgressBarGradient = (score: number) => {
    if (score >= 85) return 'from-emerald-600 via-emerald-500 to-teal-400';
    if (score >= 70) return 'from-blue-600 via-cyan-500 to-emerald-400';
    if (score >= 55) return 'from-amber-600 via-amber-500 to-yellow-400';
    return 'from-red-600 via-orange-500 to-amber-500';
  };

  const getRiskGradeBg = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
      case 'B':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'C':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default:
        return 'bg-red-500/20 text-red-400 border-red-500/30';
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

    // If findings were hardened outside the log array, append a current state sync point
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
      color: 'from-blue-600 to-cyan-500',
      tab: 'storage' as const,
    },
    {
      name: 'RBAC & Overprivileged Roles',
      count: activeOpenFindings.filter((f) => f.category === 'rbac').length,
      icon: Users,
      color: 'from-purple-600 to-indigo-500',
      tab: 'rbac' as const,
    },
    {
      name: 'Privilege Escalation Risks',
      count: activeOpenFindings.filter((f) => f.category === 'privilege_escalation').length,
      icon: Unlock,
      color: 'from-rose-600 to-red-500',
      tab: 'rbac' as const,
    },
    {
      name: 'Network Perimeter & Firewalls',
      count: activeOpenFindings.filter((f) => f.category === 'network').length,
      icon: ShieldAlert,
      color: 'from-amber-600 to-orange-500',
      tab: 'storage' as const,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner / Summary */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 p-6 border border-slate-700/80 shadow-xl">
        <div className="absolute top-0 right-0 -mt-10 -mr-10 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30 flex items-center space-x-1">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Maniq Shield • Continuous Cloud Posture Audit</span>
              </span>
              <span className="text-xs text-slate-400">
                • {metrics.totalResources} Azure Assets Evaluated
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Maniq Shield — Storage & RBAC Security Posture
            </h1>
            <p className="text-sm text-slate-300 max-w-2xl mt-1 leading-relaxed">
              Auditing Azure Storage Accounts for anonymous blob exposure, insecure HTTP transport, deprecated TLS versions, and analyzing Azure Entra ID / RBAC assignments for privilege escalation and excessive credentials.
            </p>
          </div>

          {/* Quick Metrics Badges */}
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={() => onNavigateTab('storage')}
              className="flex items-center space-x-3 px-4 py-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-700/80 transition-all text-left group"
            >
              <div className="p-2.5 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30">
                <Server className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs text-slate-400">Exposed Containers</div>
                <div className="text-lg font-bold text-white group-hover:text-blue-400 transition-colors flex items-center space-x-1">
                  <span>{metrics.exposedContainerCount || metrics.openBucketCount} Containers</span>
                  <ArrowUpRight className="w-4 h-4 opacity-50 group-hover:opacity-100" />
                </div>
              </div>
            </button>

            <button
              onClick={() => onNavigateTab('rbac')}
              className="flex items-center space-x-3 px-4 py-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-700/80 transition-all text-left group"
            >
              <div className="p-2.5 rounded-lg bg-purple-500/20 text-purple-400 border border-purple-500/30">
                <Unlock className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs text-slate-400">Escalation Risks</div>
                <div className="text-lg font-bold text-white group-hover:text-purple-400 transition-colors flex items-center space-x-1">
                  <span>{metrics.privilegeEscalationCount} Paths</span>
                  <ArrowUpRight className="w-4 h-4 opacity-50 group-hover:opacity-100" />
                </div>
              </div>
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Posture Meter & Severity Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Posture Meter Card */}
        <div className="lg:col-span-4 bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="font-bold text-slate-100 text-sm tracking-wide">
                SECURITY POSTURE SCORE
              </h3>
              <p className="text-[11px] text-slate-400">
                Real-time Hardened vs. Total Findings Ratio
              </p>
            </div>
            <span
              className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${getRiskGradeBg(
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
                {/* Background Track */}
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  className="stroke-slate-800 fill-none"
                  strokeWidth="8"
                />
                {/* Animated Value Arc */}
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
                <span className="text-3xl font-extrabold text-white tracking-tighter">
                  {realtimePostureScore}%
                </span>
                <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
                  {hardenedFindingsCount}/{totalFindingsCount} Hardened
                </span>
              </div>
            </div>

            <p className="text-xs text-center text-slate-400 mt-2 max-w-xs">
              {realtimePostureScore >= 85
                ? 'Hardened posture. Low attack surface across Azure Storage and RBAC.'
                : realtimePostureScore >= 60
                ? 'Moderate posture risk. Harden remaining storage & RBAC findings.'
                : 'CRITICAL EXPOSURE. Public containers or excessive RBAC roles require immediate hardening.'}
            </p>
          </div>

          {/* Real-Time Hardened Findings Ratio Progress Bar */}
          <div className="my-3 p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 space-y-2.5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-300 flex items-center space-x-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Hardening Progress</span>
              </span>
              <span className="font-mono font-bold text-slate-200">
                {hardenedFindingsCount} / {totalFindingsCount} ({realtimePostureScore}%)
              </span>
            </div>

            {/* Progress Bar Track */}
            <div
              role="progressbar"
              aria-label="Security Posture Score"
              aria-valuenow={realtimePostureScore}
              aria-valuemin={0}
              aria-valuemax={100}
              className="relative w-full bg-slate-900 h-3 rounded-full overflow-hidden border border-slate-800"
            >
              <div
                className={`h-full bg-gradient-to-r ${getProgressBarGradient(
                  realtimePostureScore
                )} rounded-full transition-all duration-700 ease-out`}
                style={{ width: `${realtimePostureScore}%` }}
              />
            </div>

            {/* Ratio Breakdown Pills */}
            <div className="flex items-center justify-between text-[11px] text-slate-400 pt-0.5">
              <span className="flex items-center space-x-1 text-emerald-400 font-medium">
                <CheckCircle2 className="w-3 h-3" />
                <span>{hardenedFindingsCount} Hardened</span>
              </span>
              <span className="text-amber-400 font-medium">
                {openFindingsCount} Open
              </span>
              <span>{totalFindingsCount} Total</span>
            </div>

            {openFindingsCount > 0 && (
              <button
                onClick={handleQuickHardenAll}
                className="w-full mt-1 py-1.5 px-3 rounded-lg text-xs font-semibold bg-emerald-600/20 hover:bg-emerald-600 text-emerald-300 hover:text-white border border-emerald-500/30 transition-all flex items-center justify-center space-x-1.5"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Harden All Remaining ({openFindingsCount})</span>
              </button>
            )}
          </div>

          {/* Quick Metrics Footer */}
          <div className="pt-3 border-t border-slate-800 grid grid-cols-2 gap-3 text-center">
            <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80">
              <div className="text-xs text-slate-400">Open Loopholes</div>
              <div className="text-xl font-bold text-white">
                {openFindingsCount}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80">
              <div className="text-xs text-slate-400">Hardened Findings</div>
              <div className="text-xl font-bold text-emerald-400">
                {hardenedFindingsCount}
              </div>
            </div>
          </div>
        </div>

        {/* Severity Matrix & Visual Analytics */}
        <div className="lg:col-span-8 space-y-6">
          {/* Severity Counters Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-2xl bg-red-950/30 border border-red-500/30 hover:border-red-500/50 cursor-pointer transition-all shadow-sm group"
            >
              <div className="flex items-center justify-between text-red-400 mb-1">
                <span className="text-xs font-bold tracking-wider uppercase">
                  Critical
                </span>
                <AlertOctagon className="w-4 h-4" />
              </div>
              <div className="text-2xl font-black text-white group-hover:text-red-400 transition-colors">
                {metrics.criticalCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Zero-barrier exploits
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-2xl bg-orange-950/30 border border-orange-500/30 hover:border-orange-500/50 cursor-pointer transition-all shadow-sm group"
            >
              <div className="flex items-center justify-between text-orange-400 mb-1">
                <span className="text-xs font-bold tracking-wider uppercase">
                  High
                </span>
                <AlertTriangle className="w-4 h-4" />
              </div>
              <div className="text-2xl font-black text-white group-hover:text-orange-400 transition-colors">
                {metrics.highCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Perimeter & token risks
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-2xl bg-amber-950/30 border border-amber-500/30 hover:border-amber-500/50 cursor-pointer transition-all shadow-sm group"
            >
              <div className="flex items-center justify-between text-amber-400 mb-1">
                <span className="text-xs font-bold tracking-wider uppercase">
                  Medium
                </span>
                <Info className="w-4 h-4" />
              </div>
              <div className="text-2xl font-black text-white group-hover:text-amber-400 transition-colors">
                {metrics.mediumCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Governance & logging gaps
              </div>
            </div>

            <div
              onClick={() => onNavigateTab('findings')}
              className="p-4 rounded-2xl bg-blue-950/30 border border-blue-500/30 hover:border-blue-500/50 cursor-pointer transition-all shadow-sm group"
            >
              <div className="flex items-center justify-between text-blue-400 mb-1">
                <span className="text-xs font-bold tracking-wider uppercase">
                  Low
                </span>
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div className="text-2xl font-black text-white group-hover:text-blue-400 transition-colors">
                {metrics.lowCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Hardening recommendations
              </div>
            </div>
          </div>

          {/* Visual Aids: Frequency by Category */}
          <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-lg">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-slate-100 text-sm tracking-wide">
                MISCONFIGURATION FREQUENCY BY DOMAIN
              </h3>
              <span className="text-xs text-slate-400">
                Visual Analytics (Included in PDF)
              </span>
            </div>

            <div className="space-y-3.5">
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
                      <div className="flex items-center space-x-2 text-slate-300 group-hover:text-white font-medium transition-colors">
                        <Icon className="w-4 h-4 text-slate-400 group-hover:text-blue-400 transition-colors" />
                        <span>{item.name}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-slate-400">
                          {item.count} issues
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-bold">
                          {percent}%
                        </span>
                      </div>
                    </div>
                    {/* Track */}
                    <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800/80">
                      <div
                        className={`h-full bg-gradient-to-r ${item.color} rounded-full transition-all duration-700`}
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
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-400 tracking-wider uppercase">
              CIS Azure Foundations 2.0
            </span>
            <FileCheck2 className="w-4 h-4 text-blue-400" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-black text-white">
              {metrics.complianceScores.cisAzure}%
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Passing benchmark controls
            </div>
          </div>
          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full ${
                metrics.complianceScores.cisAzure >= 80
                  ? 'bg-emerald-500'
                  : 'bg-amber-500'
              }`}
              style={{ width: `${metrics.complianceScores.cisAzure}%` }}
            />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-400 tracking-wider uppercase">
              Microsoft Cloud Security (MCSB)
            </span>
            <FileCheck2 className="w-4 h-4 text-purple-400" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-black text-white">
              {metrics.complianceScores.mcsb}%
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Data protection & identity baseline
            </div>
          </div>
          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full ${
                metrics.complianceScores.mcsb >= 80
                  ? 'bg-emerald-500'
                  : 'bg-amber-500'
              }`}
              style={{ width: `${metrics.complianceScores.mcsb}%` }}
            />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-400 tracking-wider uppercase">
              NIST SP 800-53 Rev. 5
            </span>
            <FileCheck2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="my-2">
            <div className="text-2xl font-black text-white">
              {metrics.complianceScores.nist}%
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Access control (AC) & encryption (SC)
            </div>
          </div>
          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full ${
                metrics.complianceScores.nist >= 80
                  ? 'bg-emerald-500'
                  : 'bg-amber-500'
              }`}
              style={{ width: `${metrics.complianceScores.nist}%` }}
            />
          </div>
        </div>
      </div>

      {/* Compliance Timeline Section (Recharts LineChart) */}
      <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-6">
          <div className="space-y-1">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <TrendingUp className="w-4 h-4" />
              </div>
              <h3 className="font-bold text-slate-100 text-sm tracking-wide uppercase">
                Compliance Timeline & Posture Trajectory
              </h3>
              <span className="px-2 py-0.5 text-[11px] font-mono font-semibold rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 tabular-nums whitespace-nowrap shrink-0">
                +{totalScoreGain}% Posture Gain
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Historical security posture score progression and real-time impact of remediation actions across CIS Azure & NIST controls
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Benchmark Overlay Toggle */}
            <button
              onClick={() => setShowBenchmarks((prev) => !prev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all flex items-center space-x-1.5 whitespace-nowrap shrink-0 ${
                showBenchmarks
                  ? 'bg-blue-500/15 text-blue-300 border-blue-500/30'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>CIS & NIST Overlay</span>
            </button>

            {/* Timeframe Scope Toggle */}
            <div className="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800">
              <button
                onClick={() => setTimelineScope('all')}
                className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-all whitespace-nowrap shrink-0 ${
                  timelineScope === 'all'
                    ? 'bg-slate-800 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                30d + Live Session
              </button>
              <button
                onClick={() => setTimelineScope('session')}
                className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-all whitespace-nowrap shrink-0 ${
                  timelineScope === 'session'
                    ? 'bg-slate-800 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Session Only ({effectiveRemediationLog.length})
              </button>
            </div>

            {activeOpenFindings.length > 0 && (
              <button
                onClick={() => handleQuickHarden(activeOpenFindings[0].id)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600/20 hover:bg-emerald-600 text-emerald-300 hover:text-white border border-emerald-500/30 transition-all flex items-center space-x-1.5 whitespace-nowrap shrink-0"
                title={`Remediate: ${activeOpenFindings[0].title}`}
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Harden Next Finding</span>
              </button>
            )}
          </div>
        </div>

        {/* Summary KPI Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
            <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
              {timelineScope === 'session' ? 'Session Start Score' : '30-Day Starting Score'}
            </div>
            <div className="text-xl font-black text-slate-200 font-mono tabular-nums mt-1">
              {timelineScope === 'session' ? initialSessionScore : historicalStartScore}%
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Pre-remediation baseline
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
            <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
              Current Posture Score
            </div>
            <div className="text-xl font-black text-emerald-400 font-mono tabular-nums mt-1">
              {realtimePostureScore}%
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Grade {dynamicRiskGrade} · Target 85%
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
            <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
              Net Posture Improvement
            </div>
            <div className="text-xl font-black text-cyan-400 font-mono tabular-nums mt-1">
              +{totalScoreGain}%
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Cumulative hardening delta
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
            <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
              Session Remediations
            </div>
            <div className="text-xl font-black text-blue-400 font-mono tabular-nums mt-1">
              {effectiveRemediationLog.length}
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              {hardenedFindingsCount} of {totalFindingsCount} total hardened
            </div>
          </div>
        </div>

        {/* Recharts LineChart Container */}
        <div className="h-72 w-full bg-slate-950/50 rounded-xl border border-slate-800/80 p-4">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={complianceTimelineData}
              margin={{ top: 12, right: 24, left: 0, bottom: 8 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#1e293b"
                vertical={false}
              />
              <XAxis
                dataKey="label"
                stroke="#64748b"
                tick={{ fill: '#94a3b8', fontSize: 11 }}
                tickLine={{ stroke: '#334155' }}
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis
                domain={[0, 100]}
                tickFormatter={(val) => `${val}%`}
                stroke="#64748b"
                tick={{ fill: '#94a3b8', fontSize: 11 }}
                tickLine={{ stroke: '#334155' }}
                axisLine={{ stroke: '#334155' }}
                width={44}
              />
              <Tooltip
                content={({ active, payload }) => {
                  if (!active || !payload || !payload.length) return null;
                  const point = payload[0].payload;
                  return (
                    <div className="bg-slate-950/95 border border-slate-700 rounded-xl p-3.5 shadow-2xl max-w-xs space-y-2 backdrop-blur-md">
                      <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-2">
                        <span className="text-[11px] font-mono text-slate-400">
                          {point.fullTimestamp}
                        </span>
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                            point.isLiveSession
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : 'bg-slate-800 text-slate-300 border border-slate-700'
                          }`}
                        >
                          {point.isLiveSession ? 'Live Session' : 'Historical'}
                        </span>
                      </div>

                      <div>
                        <div className="text-xs font-bold text-white leading-snug">
                          {point.eventTitle}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                          Resource: {point.resourceName} · {point.method}
                        </div>
                      </div>

                      <div className="grid grid-cols-3 gap-2 pt-1 border-t border-slate-800/80 text-center">
                        <div className="bg-slate-900/90 rounded-lg p-1.5 border border-slate-800">
                          <div className="text-[10px] text-slate-400">Posture</div>
                          <div className="text-xs font-bold font-mono text-emerald-400 tabular-nums">
                            {point.postureScore}%
                            {point.scoreDelta > 0 && (
                              <span className="text-[10px] text-emerald-300 ml-1">
                                (+{point.scoreDelta}%)
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="bg-slate-900/90 rounded-lg p-1.5 border border-slate-800">
                          <div className="text-[10px] text-slate-400">CIS v2.0</div>
                          <div className="text-xs font-bold font-mono text-blue-400 tabular-nums">
                            {point.cisScore}%
                          </div>
                        </div>
                        <div className="bg-slate-900/90 rounded-lg p-1.5 border border-slate-800">
                          <div className="text-[10px] text-slate-400">NIST 800-53</div>
                          <div className="text-xs font-bold font-mono text-purple-400 tabular-nums">
                            {point.nistScore}%
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                }}
              />
              <ReferenceLine
                y={85}
                stroke="#10b981"
                strokeDasharray="4 4"
                strokeOpacity={0.6}
                label={{
                  value: '85% Hardened Target',
                  position: 'insideTopRight',
                  fill: '#34d399',
                  fontSize: 10,
                }}
              />
              {showBenchmarks && (
                <>
                  <Line
                    type="monotone"
                    dataKey="cisScore"
                    name="CIS Azure v2.0"
                    stroke="#3b82f6"
                    strokeWidth={1.75}
                    strokeDasharray="4 4"
                    dot={{ r: 3, fill: '#3b82f6', strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: '#60a5fa' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="nistScore"
                    name="NIST SP 800-53"
                    stroke="#a855f7"
                    strokeWidth={1.75}
                    strokeDasharray="2 3"
                    dot={{ r: 3, fill: '#a855f7', strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: '#c084fc' }}
                  />
                </>
              )}
              <Line
                type="monotone"
                dataKey="postureScore"
                name="Security Posture Score"
                stroke="#10b981"
                strokeWidth={3}
                dot={{
                  r: 4,
                  fill: '#059669',
                  stroke: '#34d399',
                  strokeWidth: 2,
                }}
                activeDot={{
                  r: 6,
                  fill: '#10b981',
                  stroke: '#ecfdf5',
                  strokeWidth: 2,
                }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Chart Legend & Live Event Feed Footer */}
        <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-slate-800/80 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center space-x-2">
              <span className="w-3 h-1 rounded-full bg-emerald-500 inline-block" />
              <span className="text-slate-300 font-medium">
                Overall Security Posture Score
              </span>
            </div>
            {showBenchmarks && (
              <>
                <div className="flex items-center space-x-2">
                  <span className="w-3 h-0.5 bg-blue-500 inline-block" />
                  <span className="text-slate-400">CIS Azure v2.0 Benchmark</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="w-3 h-0.5 bg-purple-500 inline-block" />
                  <span className="text-slate-400">NIST SP 800-53 Rev. 5</span>
                </div>
              </>
            )}
            <div className="flex items-center space-x-2">
              <span className="w-3 h-0.5 border-b border-dashed border-emerald-400 inline-block" />
              <span className="text-slate-400">85% Target Threshold</span>
            </div>
          </div>

          <button
            onClick={() => onNavigateTab('remediation_log')}
            className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center space-x-1 self-start sm:self-auto whitespace-nowrap shrink-0"
          >
            <History className="w-3.5 h-3.5" />
            <span>Inspect Full Remediation Audit Trail</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Critical Action Items List */}
      <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="font-bold text-slate-100 text-sm tracking-wide">
              IMMEDIATE ACTION ITEMS (PRIORITY REMEDIATION)
            </h3>
            <p className="text-xs text-slate-400">
              Harden vulnerabilities directly to improve your real-time Security Posture Score
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('findings')}
            className="text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center space-x-1"
          >
            <span>View All ({activeOpenFindings.length})</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {activeOpenFindings.length === 0 ? (
          <div className="p-6 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-center space-y-2">
            <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
            <div className="text-sm font-bold text-emerald-300">
              100% Hardened Security Posture Achieved
            </div>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              All {totalFindingsCount} evaluated security findings across Azure Storage Accounts, Blob Containers, and RBAC assignments are hardened.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {activeOpenFindings
              .slice(0, 4)
              .map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => onSelectFinding(finding.id)}
                  className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-red-500/40 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
                >
                  <div className="flex items-start space-x-3">
                    <div className="p-2 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30 flex-shrink-0 mt-0.5">
                      <AlertOctagon className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold text-white group-hover:text-red-300 transition-colors">
                          {finding.title}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                          {finding.category.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">
                        {finding.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 self-end sm:self-center flex-shrink-0">
                    <span className="text-xs font-mono text-slate-400 hidden md:inline">
                      {finding.resourceName}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleQuickHarden(finding.id);
                      }}
                      className="px-3 py-1 rounded-lg text-xs font-semibold bg-emerald-600/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-600 hover:text-white transition-all flex items-center space-x-1"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Harden</span>
                    </button>
                    <button className="px-3 py-1 rounded-lg text-xs font-semibold bg-red-600/20 text-red-300 border border-red-500/30 group-hover:bg-red-600 group-hover:text-white transition-all">
                      Runbook
                    </button>
                  </div>
                </div>
              ))}
          </div>
        )}
      </div>

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
