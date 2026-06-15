'use strict';

const express = require('express');
const store = require('../data/store');
const { authRequired, requireRole } = require('../auth');
const { runSuspiciousCheck, getDefaultRules } = require('../audit/suspicious-rules');
const {
  sendData,
  sendError,
  parseEnum,
  parseId,
  parseNumber,
  optionalString,
  HttpError,
} = require('../utils/http');

const router = express.Router();

router.use(authRequired);

const ENTITY_TYPES = ['user', 'pipe', 'station'];
const ACTION_TYPES = ['create', 'update', 'delete', 'restore'];

/** GET /api/audit —— 审计记录查询，支持分页、过滤。 */
router.get('/', (req, res) => {
  try {
    const page = Math.max(1, parseNumber(req.query, 'page', { min: 1, integer: true }) || 1);
    const pageSize = Math.min(200, Math.max(1, parseNumber(req.query, 'pageSize', { min: 1, integer: true }) || 50));
    const operatorId = req.query.operatorId !== undefined ? parseNumber(req.query, 'operatorId', { integer: true }) : undefined;
    const entityType = req.query.entityType ? parseEnum(req.query, 'entityType', ENTITY_TYPES, { required: true }) : undefined;
    const entityId = req.query.entityId !== undefined ? parseNumber(req.query, 'entityId', { integer: true, min: 1 }) : undefined;
    const actionType = req.query.actionType ? parseEnum(req.query, 'actionType', ACTION_TYPES, { required: true }) : undefined;
    const fromTime = req.query.fromTime ? optionalString(req.query, 'fromTime') : undefined;
    const toTime = req.query.toTime ? optionalString(req.query, 'toTime') : undefined;

    const result = store.listAuditLogs({
      operatorId, entityType, entityId, actionType, fromTime, toTime, page, pageSize,
    });
    return sendData(res, 200, result.items, {
      total: result.total,
      page: result.page,
      pageSize: result.pageSize,
    });
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

/** GET /api/audit/:id —— 单条审计记录详情。 */
router.get('/:id', (req, res) => {
  try {
    const id = parseId(req.params.id);
    const log = store.getAuditLogById(id);
    if (!log) return sendError(res, 404, '审计记录不存在');
    return sendData(res, 200, log);
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

/** GET /api/audit/chain/verify —— 完整校验哈希链。 */
router.get('/chain/verify', requireRole('admin'), (req, res) => {
  try {
    const result = store.verifyAuditChain();
    return sendData(res, 200, result);
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

/** GET /api/audit/chain/verify/:id —— 校验单条审计记录哈希。 */
router.get('/chain/verify/:id', requireRole('admin'), (req, res) => {
  try {
    const id = parseId(req.params.id);
    const result = store.verifySingleAuditRecord(id);
    if (result.reason === 'not_found') return sendError(res, 404, '审计记录不存在');
    return sendData(res, 200, result);
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

/** GET /api/audit/timeline/:entityType/:entityId —— 某对象完整变更时间线。 */
router.get('/timeline/:entityType/:entityId', (req, res) => {
  try {
    const entityType = parseEnum(req.params, 'entityType', ENTITY_TYPES, { required: true });
    const entityId = parseId(req.params.entityId);
    const timeline = store.getEntityTimeline(entityType, entityId);
    return sendData(res, 200, timeline, { total: timeline.length });
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

/** GET /api/audit/reconstruct/:entityType/:entityId/:auditLogId —— 时间旅行：重建某历史时刻状态。 */
router.get('/reconstruct/:entityType/:entityId/:auditLogId', (req, res) => {
  try {
    const entityType = parseEnum(req.params, 'entityType', ENTITY_TYPES, { required: true });
    const entityId = parseId(req.params.entityId);
    const auditLogId = parseId(req.params.auditLogId);

    const timeline = store.getEntityTimeline(entityType, entityId);
    if (timeline.length === 0) {
      return sendError(res, 404, '该对象不存在任何审计记录，无法重建');
    }

    const firstLogTime = timeline[0].actionTime;
    if (auditLogId < timeline[0].id) {
      return sendData(res, 200, {
        ok: false,
        error: 'BEFORE_CREATION',
        message: `目标时间点早于对象诞生。对象诞生时间（审计记录 #${timeline[0].id}）：${firstLogTime}`,
        firstRecordId: timeline[0].id,
        firstRecordTime: firstLogTime,
      });
    }

    const result = store.reconstructEntityAt(entityType, entityId, auditLogId);
    return sendData(res, 200, result);
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

/** POST /api/audit/restore/:entityType/:entityId/:auditLogId —— 还原对象到某历史状态。 */
router.post('/restore/:entityType/:entityId/:auditLogId', requireRole('admin', 'operator'), (req, res) => {
  try {
    const entityType = parseEnum(req.params, 'entityType', ENTITY_TYPES, { required: true });
    const entityId = parseId(req.params.entityId);
    const auditLogId = parseId(req.params.auditLogId);

    const sourceIp = req.ip || req.socket.remoteAddress || null;
    const ctx = {
      operatorId: req.user.id,
      operatorUsername: req.user.username,
      sourceIp,
    };

    let restored;
    try {
      restored = store.restoreEntityToVersion(entityType, entityId, auditLogId, ctx);
    } catch (e) {
      const code = e.message;
      switch (code) {
        case 'NO_TIMELINE':
          return sendError(res, 404, '该对象不存在审计记录，无法还原');
        case 'TARGET_NOT_IN_TIMELINE':
          return sendError(res, 400, '目标审计记录不在该对象时间线上');
        case 'TARGET_STATE_DELETED':
          return sendError(res, 400, '目标时刻对象已被删除，请选择一个非删除状态的记录作为还原目标');
        case 'DIFF_MISSING':
        case 'DIFF_CORRUPTED':
        case 'APPLY_DIFF_FAILED':
        case 'RECONSTRUCT_NULL':
          return sendError(res, 500, `审计链数据损坏，无法还原。错误码：${code}`, { errorCode: code });
        default:
          throw e;
      }
    }
    return sendData(res, 200, restored, { restoredFromAuditLogId: auditLogId });
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

/** GET /api/audit/suspicious/rules —— 获取默认可疑规则定义。 */
router.get('/suspicious/rules', requireRole('admin'), (req, res) => {
  try {
    const rules = getDefaultRules();
    return sendData(res, 200, rules);
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

/** POST /api/audit/suspicious/scan —— 扫描审计流识别可疑操作。 */
router.post('/suspicious/scan', requireRole('admin'), (req, res) => {
  try {
    const fromTime = req.body && req.body.fromTime ? String(req.body.fromTime) : undefined;
    const toTime = req.body && req.body.toTime ? String(req.body.toTime) : undefined;
    const customRules = req.body && Array.isArray(req.body.rules) ? req.body.rules : undefined;
    const workHours = req.body && req.body.workHours ? req.body.workHours : undefined;

    const all = store.listAuditLogs({
      fromTime, toTime, page: 1, pageSize: 10000,
    });

    const result = runSuspiciousCheck(all.items, { customRules, workHours });
    return sendData(res, 200, result);
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.status, err.message, err.details);
    throw err;
  }
});

module.exports = router;
