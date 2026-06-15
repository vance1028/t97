'use strict';

const DEFAULT_WORK_HOURS = {
  startHour: 9,
  endHour: 18,
  workDays: [1, 2, 3, 4, 5],
};

const DEFAULT_RULES = [
  {
    id: 'MASS_DELETE_SHORT_WINDOW',
    name: '短时间大量删除',
    description: '在指定时间窗口内删除操作超过阈值',
    enabled: true,
    params: { windowMinutes: 10, threshold: 5 },
  },
  {
    id: 'BATCH_STATUS_OFF_HOURS',
    name: '非工作时段批量状态变更',
    description: '在非工作时段内的批量状态更新操作',
    enabled: true,
    params: { windowMinutes: 30, threshold: 3, fieldName: 'status' },
  },
  {
    id: 'OBJECT_PINGPONG',
    name: '同一对象反复来回改动',
    description: '同一对象在短时间内被反复更新多次',
    enabled: true,
    params: { windowMinutes: 60, threshold: 4 },
  },
  {
    id: 'ACCOUNT_SPIKE',
    name: '账号操作频率突增',
    description: '某个账号在短时间内操作次数相比基线突增',
    enabled: true,
    params: { windowMinutes: 15, threshold: 20, baselineWindowHours: 24, spikeRatio: 3 },
  },
];

function loadRules(customRules) {
  if (Array.isArray(customRules)) {
    return customRules.map(r => ({
      ...r, enabled: r.enabled !== false,
    }));
  }
  return JSON.parse(JSON.stringify(DEFAULT_RULES));
}

function isWorkingHours(dt, workHours = DEFAULT_WORK_HOURS) {
  const day = dt.getDay();
  const hour = dt.getHours();
  if (!workHours.workDays.includes(day)) return false;
  return hour >= workHours.startHour && hour < workHours.endHour;
}

function formatAlert(rule, details, matchedRecords, extra = {}) {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    description: rule.description,
    severity: rule.severity || 'warning',
    matchedRecordIds: matchedRecords.map(r => r.id),
    matchedCount: matchedRecords.length,
    details,
    ...extra,
  };
}

function checkMassDelete(records, rule) {
  if (!rule.enabled) return [];
  const { windowMinutes = 10, threshold = 5 } = rule.params;
  const deletes = records.filter(r => r.actionType === 'delete');
  if (deletes.length < threshold) return [];

  const alerts = [];
  const sorted = [...deletes].sort((a, b) => new Date(a.actionTime) - new Date(b.actionTime));

  for (let i = 0; i < sorted.length; i++) {
    const windowStart = new Date(sorted[i].actionTime);
    windowStart.setMinutes(windowStart.getMinutes() - windowMinutes);
    const windowEnd = new Date(sorted[i].actionTime);
    windowEnd.setMinutes(windowEnd.getMinutes() + windowMinutes);

    const windowRecords = sorted.filter(r => {
      const t = new Date(r.actionTime);
      return t >= windowStart && t <= windowEnd;
    });

    if (windowRecords.length >= threshold) {
      const matched = windowRecords.slice(0, 20);
      alerts.push(formatAlert(rule, {
        windowStart: windowStart.toISOString(),
        windowEnd: windowEnd.toISOString(),
        deleteCount: windowRecords.length,
        threshold,
        windowMinutes,
      }, matched));
      i += windowRecords.length - 1;
    }
  }
  return alerts;
}

function checkOffHoursBatchStatus(records, rule, workHours) {
  if (!rule.enabled) return [];
  const { windowMinutes = 30, threshold = 3, fieldName = 'status' } = rule.params;

  const updates = records.filter(r => {
    if (r.actionType !== 'update') return false;
    if (!r.diff || !r.diff.changes) return false;
    return r.diff.changes.some(c => c.path === fieldName || c.path.endsWith(`.${fieldName}`));
  });

  if (updates.length < threshold) return [];

  const offHoursUpdates = updates.filter(r => !isWorkingHours(new Date(r.actionTime), workHours));
  if (offHoursUpdates.length < threshold) return [];

  const alerts = [];
  const sorted = [...offHoursUpdates].sort((a, b) => new Date(a.actionTime) - new Date(b.actionTime));

  for (let i = 0; i < sorted.length; i++) {
    const windowStart = new Date(sorted[i].actionTime);
    windowStart.setMinutes(windowStart.getMinutes() - windowMinutes);
    const windowEnd = new Date(sorted[i].actionTime);
    windowEnd.setMinutes(windowEnd.getMinutes() + windowMinutes);

    const windowRecords = sorted.filter(r => {
      const t = new Date(r.actionTime);
      return t >= windowStart && t <= windowEnd;
    });

    if (windowRecords.length >= threshold) {
      alerts.push(formatAlert(rule, {
        fieldName,
        windowStart: windowStart.toISOString(),
        windowEnd: windowEnd.toISOString(),
        count: windowRecords.length,
        threshold,
      }, windowRecords.slice(0, 20)));
      i += windowRecords.length - 1;
    }
  }
  return alerts;
}

function checkObjectPingpong(records, rule) {
  if (!rule.enabled) return [];
  const { windowMinutes = 60, threshold = 4 } = rule.params;

  const byEntity = new Map();
  for (const r of records) {
    const key = `${r.entityType}:${r.entityId}`;
    if (!byEntity.has(key)) byEntity.set(key, []);
    byEntity.get(key).push(r);
  }

  const alerts = [];
  for (const [entityKey, recs] of byEntity) {
    if (recs.length < threshold) continue;
    const sorted = [...recs].sort((a, b) => new Date(a.actionTime) - new Date(b.actionTime));
    const updates = sorted.filter(r => r.actionType === 'update');
    if (updates.length < threshold) continue;

    for (let i = 0; i < updates.length; i++) {
      const windowStart = new Date(updates[i].actionTime);
      windowStart.setMinutes(windowStart.getMinutes() - windowMinutes);
      const windowEnd = new Date(updates[i].actionTime);
      windowEnd.setMinutes(windowEnd.getMinutes() + windowMinutes);

      const windowRecords = updates.filter(r => {
        const t = new Date(r.actionTime);
        return t >= windowStart && t <= windowEnd;
      });

      if (windowRecords.length >= threshold) {
        const [etype, eid] = entityKey.split(':');
        alerts.push(formatAlert(rule, {
          entityType: etype,
          entityId: Number(eid),
          windowStart: windowStart.toISOString(),
          windowEnd: windowEnd.toISOString(),
          updateCount: windowRecords.length,
          threshold,
        }, windowRecords.slice(0, 20)));
        break;
      }
    }
  }
  return alerts;
}

function checkAccountSpike(records, rule) {
  if (!rule.enabled) return [];
  const { windowMinutes = 15, threshold = 20, baselineWindowHours = 24, spikeRatio = 3 } = rule.params;

  if (records.length === 0) return [];

  const latestTime = new Date(Math.max(...records.map(r => new Date(r.actionTime).getTime())));
  const spikeWindowStart = new Date(latestTime);
  spikeWindowStart.setMinutes(spikeWindowStart.getMinutes() - windowMinutes);
  const baselineStart = new Date(latestTime);
  baselineStart.setHours(baselineStart.getHours() - baselineWindowHours);

  const byOperator = new Map();
  for (const r of records) {
    const key = r.operatorId;
    if (!byOperator.has(key)) byOperator.set(key, { spike: [], baseline: [] });
    const t = new Date(r.actionTime);
    if (t >= spikeWindowStart) byOperator.get(key).spike.push(r);
    if (t >= baselineStart && t < spikeWindowStart) byOperator.get(key).baseline.push(r);
  }

  const alerts = [];
  for (const [opId, { spike, baseline }] of byOperator) {
    if (spike.length < threshold) continue;

    const baselineMinutes = baselineWindowHours * 60;
    const baselineRatePerWindow = baseline.length * (windowMinutes / baselineMinutes);
    const ratio = baselineRatePerWindow > 0 ? spike.length / baselineRatePerWindow : spike.length;

    if (ratio >= spikeRatio) {
      const sample = spike.slice(0, 20);
      const op = spike[0];
      alerts.push(formatAlert(rule, {
        operatorId: op.operatorId,
        operatorUsername: op.operatorUsername,
        spikeCount: spike.length,
        baselineAvgPerWindow: Number(baselineRatePerWindow.toFixed(2)),
        ratio: Number(ratio.toFixed(2)),
        threshold,
        spikeRatio,
      }, sample, { severity: ratio >= spikeRatio * 2 ? 'high' : 'warning' }));
    }
  }
  return alerts;
}

function runSuspiciousCheck(records, { customRules, workHours } = {}) {
  const rules = loadRules(customRules);
  const wh = workHours || DEFAULT_WORK_HOURS;
  const alerts = [];

  for (const rule of rules) {
    try {
      switch (rule.id) {
        case 'MASS_DELETE_SHORT_WINDOW':
          alerts.push(...checkMassDelete(records, rule));
          break;
        case 'BATCH_STATUS_OFF_HOURS':
          alerts.push(...checkOffHoursBatchStatus(records, rule, wh));
          break;
        case 'OBJECT_PINGPONG':
          alerts.push(...checkObjectPingpong(records, rule));
          break;
        case 'ACCOUNT_SPIKE':
          alerts.push(...checkAccountSpike(records, rule));
          break;
        default:
          break;
      }
    } catch (e) {
      alerts.push({
        ruleId: rule.id,
        ruleName: rule.name,
        description: rule.description,
        severity: 'error',
        error: e.message,
        matchedRecordIds: [],
        matchedCount: 0,
        details: { error: 'rule_execution_failed', message: e.message },
      });
    }
  }

  return {
    alerts,
    totalAlerts: alerts.length,
    recordsScanned: records.length,
    highSeverity: alerts.filter(a => a.severity === 'high').length,
  };
}

function getDefaultRules() {
  return JSON.parse(JSON.stringify(DEFAULT_RULES));
}

module.exports = {
  runSuspiciousCheck,
  getDefaultRules,
  loadRules,
  DEFAULT_RULES,
  DEFAULT_WORK_HOURS,
};
