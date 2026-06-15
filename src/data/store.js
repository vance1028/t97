'use strict';

const { getDb } = require('../db');
const { hashPassword } = require('../utils/password');
const { computeRecordHash, getGenesisPrevHash, verifyChain, verifyRecordHash } = require('../audit/hash-chain');
const { diffCreate, diffUpdate, diffDelete, diffRestore, SENSITIVE_MARKER } = require('../audit/deep-diff');

/**
 * 数据仓储层：所有 SQL 都集中在这里，路由层只调用这些方法。
 * 对外返回的对象统一用 camelCase 字段，便于前端消费。
 */

/* ----------------------------- 行 -> API 映射 ----------------------------- */

function mapUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    name: row.name,
    role: row.role,
    active: !!row.active,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapPipe(row) {
  if (!row) return null;
  return {
    id: row.id,
    code: row.code,
    district: row.district,
    type: row.type,
    material: row.material,
    diameterMm: row.diameter_mm,
    lengthM: row.length_m,
    status: row.status,
    installedAt: row.installed_at,
    remark: row.remark,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapStation(row) {
  if (!row) return null;
  return {
    id: row.id,
    code: row.code,
    name: row.name,
    district: row.district,
    capacityM3h: row.capacity_m3h,
    pumpCount: row.pump_count,
    status: row.status,
    location: row.location,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/* --------------------------------- 用户 --------------------------------- */

function getUserByUsername(username) {
  return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function getUserById(id) {
  return mapUser(getDb().prepare('SELECT * FROM users WHERE id = ?').get(id));
}

/** 内部使用：返回包含 password_hash 的原始行。 */
function getRawUserById(id) {
  return getDb().prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function listUsers() {
  return getDb()
    .prepare('SELECT * FROM users ORDER BY id ASC')
    .all()
    .map(mapUser);
}

function createUser({ username, password, name, role = 'viewer', active = true }) {
  const info = getDb()
    .prepare(
      `INSERT INTO users (username, password_hash, name, role, active)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .run(username, hashPassword(password), name, role, active ? 1 : 0);
  return getUserById(info.lastInsertRowid);
}

function updateUser(id, fields) {
  const sets = [];
  const params = [];
  if (fields.name !== undefined) { sets.push('name = ?'); params.push(fields.name); }
  if (fields.role !== undefined) { sets.push('role = ?'); params.push(fields.role); }
  if (fields.active !== undefined) { sets.push('active = ?'); params.push(fields.active ? 1 : 0); }
  if (fields.password !== undefined) { sets.push('password_hash = ?'); params.push(hashPassword(fields.password)); }
  if (sets.length === 0) return getUserById(id);
  sets.push("updated_at = datetime('now')");
  params.push(id);
  getDb().prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  return getUserById(id);
}

function deleteUser(id) {
  return getDb().prepare('DELETE FROM users WHERE id = ?').run(id).changes > 0;
}

/* ------------------------------- 排水管段 ------------------------------- */

function listPipes({ district, type, status, keyword } = {}) {
  const where = [];
  const params = [];
  if (district) { where.push('district = ?'); params.push(district); }
  if (type) { where.push('type = ?'); params.push(type); }
  if (status) { where.push('status = ?'); params.push(status); }
  if (keyword) {
    where.push('(code LIKE ? OR remark LIKE ?)');
    params.push(`%${keyword}%`, `%${keyword}%`);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  return getDb()
    .prepare(`SELECT * FROM pipe_segments ${clause} ORDER BY id DESC`)
    .all(...params)
    .map(mapPipe);
}

function getPipeById(id) {
  return mapPipe(getDb().prepare('SELECT * FROM pipe_segments WHERE id = ?').get(id));
}

function getPipeByCode(code) {
  return mapPipe(getDb().prepare('SELECT * FROM pipe_segments WHERE code = ?').get(code));
}

function createPipe(data) {
  const info = getDb()
    .prepare(
      `INSERT INTO pipe_segments
        (code, district, type, material, diameter_mm, length_m, status, installed_at, remark)
       VALUES (@code, @district, @type, @material, @diameterMm, @lengthM, @status, @installedAt, @remark)`,
    )
    .run({
      code: data.code,
      district: data.district,
      type: data.type,
      material: data.material,
      diameterMm: data.diameterMm,
      lengthM: data.lengthM,
      status: data.status,
      installedAt: data.installedAt,
      remark: data.remark,
    });
  return getPipeById(info.lastInsertRowid);
}

function updatePipe(id, data) {
  const allowed = {
    district: 'district',
    type: 'type',
    material: 'material',
    diameterMm: 'diameter_mm',
    lengthM: 'length_m',
    status: 'status',
    installedAt: 'installed_at',
    remark: 'remark',
  };
  const sets = [];
  const params = [];
  for (const [key, col] of Object.entries(allowed)) {
    if (data[key] !== undefined) { sets.push(`${col} = ?`); params.push(data[key]); }
  }
  if (sets.length === 0) return getPipeById(id);
  sets.push("updated_at = datetime('now')");
  params.push(id);
  getDb().prepare(`UPDATE pipe_segments SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  return getPipeById(id);
}

function deletePipe(id) {
  return getDb().prepare('DELETE FROM pipe_segments WHERE id = ?').run(id).changes > 0;
}

/* -------------------------------- 泵站 -------------------------------- */

function listStations({ district, status, keyword } = {}) {
  const where = [];
  const params = [];
  if (district) { where.push('district = ?'); params.push(district); }
  if (status) { where.push('status = ?'); params.push(status); }
  if (keyword) {
    where.push('(code LIKE ? OR name LIKE ?)');
    params.push(`%${keyword}%`, `%${keyword}%`);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  return getDb()
    .prepare(`SELECT * FROM pump_stations ${clause} ORDER BY id DESC`)
    .all(...params)
    .map(mapStation);
}

function getStationById(id) {
  return mapStation(getDb().prepare('SELECT * FROM pump_stations WHERE id = ?').get(id));
}

function getStationByCode(code) {
  return mapStation(getDb().prepare('SELECT * FROM pump_stations WHERE code = ?').get(code));
}

function createStation(data) {
  const info = getDb()
    .prepare(
      `INSERT INTO pump_stations
        (code, name, district, capacity_m3h, pump_count, status, location)
       VALUES (@code, @name, @district, @capacityM3h, @pumpCount, @status, @location)`,
    )
    .run({
      code: data.code,
      name: data.name,
      district: data.district,
      capacityM3h: data.capacityM3h,
      pumpCount: data.pumpCount,
      status: data.status,
      location: data.location,
    });
  return getStationById(info.lastInsertRowid);
}

function updateStation(id, data) {
  const allowed = {
    name: 'name',
    district: 'district',
    capacityM3h: 'capacity_m3h',
    pumpCount: 'pump_count',
    status: 'status',
    location: 'location',
  };
  const sets = [];
  const params = [];
  for (const [key, col] of Object.entries(allowed)) {
    if (data[key] !== undefined) { sets.push(`${col} = ?`); params.push(data[key]); }
  }
  if (sets.length === 0) return getStationById(id);
  sets.push("updated_at = datetime('now')");
  params.push(id);
  getDb().prepare(`UPDATE pump_stations SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  return getStationById(id);
}

function deleteStation(id) {
  return getDb().prepare('DELETE FROM pump_stations WHERE id = ?').run(id).changes > 0;
}

/* -------------------------------- 计数 -------------------------------- */

function countUsers() {
  return getDb().prepare('SELECT COUNT(*) AS n FROM users').get().n;
}

/* ------------------------------ 审计相关 ------------------------------ */

const ENTITY_TYPE_MAP = {
  user: {
    table: 'users',
    getById: (id) => getRawUserById(id),
    mapRow: mapUser,
    idCol: 'id',
  },
  pipe: {
    table: 'pipe_segments',
    getById: (id) => getDb().prepare('SELECT * FROM pipe_segments WHERE id = ?').get(id),
    mapRow: mapPipe,
    idCol: 'id',
  },
  station: {
    table: 'pump_stations',
    getById: (id) => getDb().prepare('SELECT * FROM pump_stations WHERE id = ?').get(id),
    mapRow: mapStation,
    idCol: 'id',
  },
};

function getEntityConfig(entityType) {
  const cfg = ENTITY_TYPE_MAP[entityType];
  if (!cfg) throw new Error(`未知的 entityType: ${entityType}`);
  return cfg;
}

function getRawEntitySnapshot(entityType, id) {
  const cfg = getEntityConfig(entityType);
  const row = cfg.getById(id);
  if (!row) return null;
  return row;
}

function getMappedEntitySnapshot(entityType, id) {
  const cfg = getEntityConfig(entityType);
  const row = cfg.getById(id);
  if (!row) return null;
  return cfg.mapRow(row);
}

function mapAuditLog(row) {
  if (!row) return null;
  let diffData;
  try {
    diffData = typeof row.diff_data === 'string' ? JSON.parse(row.diff_data) : row.diff_data;
  } catch {
    diffData = { _raw: row.diff_data, _parseError: true };
  }
  return {
    id: row.id,
    operatorId: row.operator_id,
    operatorUsername: row.operator_username,
    actionTime: row.action_time,
    actionType: row.action_type,
    entityType: row.entity_type,
    entityId: row.entity_id,
    sourceIp: row.source_ip,
    diff: diffData,
    prevHash: row.prev_hash,
    currentHash: row.current_hash,
  };
}

function _getLastAuditHash(conn) {
  const row = conn.prepare('SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1').get();
  return row ? row.current_hash : getGenesisPrevHash();
}

function appendAuditLog(conn, { operatorId, operatorUsername, actionType, entityType, entityId, sourceIp, diffData }) {
  if (!conn) conn = getDb();

  const prevHash = _getLastAuditHash(conn);
  const diffDataStr = typeof diffData === 'string' ? diffData : JSON.stringify(diffData);

  const now = new Date().toISOString();
  const payload = {
    operatorId,
    operatorUsername,
    actionTime: now,
    actionType,
    entityType,
    entityId,
    sourceIp,
    diffData: diffDataStr,
  };

  const currentHash = computeRecordHash(prevHash, payload);

  const info = conn
    .prepare(
      `INSERT INTO audit_logs
        (operator_id, operator_username, action_time, action_type, entity_type, entity_id, source_ip, diff_data, prev_hash, current_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      Number(operatorId),
      String(operatorUsername),
      now,
      String(actionType),
      String(entityType),
      Number(entityId),
      sourceIp ? String(sourceIp) : null,
      diffDataStr,
      prevHash,
      currentHash,
    );

  return { id: info.lastInsertRowid, prevHash, currentHash, actionTime: now };
}

function getAuditLogById(id) {
  const row = getDb().prepare('SELECT * FROM audit_logs WHERE id = ?').get(Number(id));
  return mapAuditLog(row);
}

function listAuditLogs({ operatorId, entityType, entityId, actionType, fromTime, toTime, page = 1, pageSize = 50 } = {}) {
  const where = [];
  const params = [];
  if (operatorId !== undefined) { where.push('operator_id = ?'); params.push(Number(operatorId)); }
  if (entityType) { where.push('entity_type = ?'); params.push(String(entityType)); }
  if (entityId !== undefined) { where.push('entity_id = ?'); params.push(Number(entityId)); }
  if (actionType) { where.push('action_type = ?'); params.push(String(actionType)); }
  if (fromTime) { where.push('action_time >= ?'); params.push(String(fromTime)); }
  if (toTime) { where.push('action_time <= ?'); params.push(String(toTime)); }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const countRow = getDb().prepare(`SELECT COUNT(*) AS n FROM audit_logs ${whereClause}`).get(...params);
  const total = countRow.n;

  const safePage = Math.max(1, Number(page) || 1);
  const safeSize = Math.min(200, Math.max(1, Number(pageSize) || 50));
  const offset = (safePage - 1) * safeSize;

  const rows = getDb()
    .prepare(`SELECT * FROM audit_logs ${whereClause} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .all(...params, safeSize, offset);

  return {
    items: rows.map(mapAuditLog),
    total,
    page: safePage,
    pageSize: safeSize,
  };
}

function getEntityTimeline(entityType, entityId) {
  const rows = getDb()
    .prepare('SELECT * FROM audit_logs WHERE entity_type = ? AND entity_id = ? ORDER BY id ASC')
    .all(String(entityType), Number(entityId));
  return rows.map(mapAuditLog);
}

function getAllAuditRecordsForVerify() {
  return getDb()
    .prepare('SELECT * FROM audit_logs ORDER BY id ASC')
    .all();
}

function verifyAuditChain() {
  const records = getAllAuditRecordsForVerify();
  return verifyChain(records);
}

function verifySingleAuditRecord(id) {
  const row = getDb().prepare('SELECT * FROM audit_logs WHERE id = ?').get(Number(id));
  if (!row) return { ok: false, reason: 'not_found' };
  return verifyRecordHash(row);
}

/* ------------ 事务封装：业务写 + 审计写入在同一事务内 ------------ */

function _txDb() {
  return getDb();
}

function _injectSensitivePasswordMarker(diffObj) {
  if (diffObj && Array.isArray(diffObj.changes)) {
    const hasPwd = diffObj.changes.some(c => c.path === 'password' || c.type === 'sensitive');
    if (!hasPwd) {
      diffObj.changes.push({
        path: 'password',
        type: 'sensitive',
        before: undefined,
        after: SENSITIVE_MARKER,
      });
    }
    const createChange = diffObj.changes.find(c => c.type === 'create');
    if (createChange && createChange.after && typeof createChange.after === 'object') {
      if (!Object.prototype.hasOwnProperty.call(createChange.after, 'password')) {
        createChange.after.password = SENSITIVE_MARKER;
      }
    }
    if (diffObj.snapshot && typeof diffObj.snapshot === 'object' && !Object.prototype.hasOwnProperty.call(diffObj.snapshot, 'password')) {
      diffObj.snapshot.password = SENSITIVE_MARKER;
    }
  }
  if (diffObj && diffObj.action === 'create' && diffObj.snapshot && typeof diffObj.snapshot === 'object') {
    if (!Object.prototype.hasOwnProperty.call(diffObj.snapshot, 'password')) {
      diffObj.snapshot.password = SENSITIVE_MARKER;
    }
  }
  return diffObj;
}

function createAuditedUser(data, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(data.username);
    if (existing) throw new Error('USER_EXISTS');
    const info = db
      .prepare(
        `INSERT INTO users (username, password_hash, name, role, active)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(data.username, hashPassword(data.password), data.name, data.role || 'viewer', data.active ? 1 : 0);
    const id = info.lastInsertRowid;
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    const mapped = mapUser(row);
    const diff = _injectSensitivePasswordMarker(diffCreate(mapped));
    appendAuditLog(db, {
      operatorId: ctx.operatorId,
      operatorUsername: ctx.operatorUsername,
      actionType: 'create',
      entityType: 'user',
      entityId: id,
      sourceIp: ctx.sourceIp,
      diffData: diff,
    });
    return mapped;
  });
  return tx();
}

function updateAuditedUser(id, fields, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const oldRow = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!oldRow) throw new Error('NOT_FOUND');
    const oldMapped = mapUser(oldRow);

    const sets = [];
    const params = [];
    if (fields.name !== undefined) { sets.push('name = ?'); params.push(fields.name); }
    if (fields.role !== undefined) { sets.push('role = ?'); params.push(fields.role); }
    if (fields.active !== undefined) { sets.push('active = ?'); params.push(fields.active ? 1 : 0); }
    if (fields.password !== undefined) { sets.push('password_hash = ?'); params.push(hashPassword(fields.password)); }
    if (sets.length === 0) return oldMapped;
    sets.push("updated_at = datetime('now')");
    params.push(id);
    db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...params);

    const newRow = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    const newMapped = mapUser(newRow);
    let diff = diffUpdate(oldMapped, newMapped);
    if (fields.password !== undefined) {
      if (!Array.isArray(diff.changes)) diff.changes = [];
      diff.changes.push({
        path: 'password',
        type: 'sensitive',
        before: SENSITIVE_MARKER,
        after: SENSITIVE_MARKER,
      });
    }
    appendAuditLog(db, {
      operatorId: ctx.operatorId,
      operatorUsername: ctx.operatorUsername,
      actionType: 'update',
      entityType: 'user',
      entityId: id,
      sourceIp: ctx.sourceIp,
      diffData: diff,
    });
    return newMapped;
  });
  return tx();
}

function deleteAuditedUser(id, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const oldRow = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!oldRow) return false;
    const oldMapped = mapUser(oldRow);
    const diff = diffDelete(oldMapped);
    appendAuditLog(db, {
      operatorId: ctx.operatorId,
      operatorUsername: ctx.operatorUsername,
      actionType: 'delete',
      entityType: 'user',
      entityId: id,
      sourceIp: ctx.sourceIp,
      diffData: diff,
    });
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    return true;
  });
  return tx();
}

function createAuditedPipe(data, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const existing = db.prepare('SELECT id FROM pipe_segments WHERE code = ?').get(data.code);
    if (existing) throw new Error('CODE_EXISTS');
    const info = db
      .prepare(
        `INSERT INTO pipe_segments
          (code, district, type, material, diameter_mm, length_m, status, installed_at, remark)
         VALUES (@code, @district, @type, @material, @diameterMm, @lengthM, @status, @installedAt, @remark)`,
      )
      .run({
        code: data.code, district: data.district, type: data.type,
        material: data.material, diameterMm: data.diameterMm, lengthM: data.lengthM,
        status: data.status, installedAt: data.installedAt, remark: data.remark,
      });
    const id = info.lastInsertRowid;
    const row = db.prepare('SELECT * FROM pipe_segments WHERE id = ?').get(id);
    const mapped = mapPipe(row);
    const diff = diffCreate(mapped);
    appendAuditLog(db, {
      operatorId: ctx.operatorId, operatorUsername: ctx.operatorUsername,
      actionType: 'create', entityType: 'pipe', entityId: id,
      sourceIp: ctx.sourceIp, diffData: diff,
    });
    return mapped;
  });
  return tx();
}

function updateAuditedPipe(id, data, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const oldRow = db.prepare('SELECT * FROM pipe_segments WHERE id = ?').get(id);
    if (!oldRow) throw new Error('NOT_FOUND');
    const oldMapped = mapPipe(oldRow);
    const allowed = {
      district: 'district', type: 'type', material: 'material',
      diameterMm: 'diameter_mm', lengthM: 'length_m', status: 'status',
      installedAt: 'installed_at', remark: 'remark',
    };
    const sets = [];
    const params = [];
    for (const [key, col] of Object.entries(allowed)) {
      if (data[key] !== undefined) { sets.push(`${col} = ?`); params.push(data[key]); }
    }
    if (sets.length === 0) return oldMapped;
    sets.push("updated_at = datetime('now')");
    params.push(id);
    db.prepare(`UPDATE pipe_segments SET ${sets.join(', ')} WHERE id = ?`).run(...params);
    const newRow = db.prepare('SELECT * FROM pipe_segments WHERE id = ?').get(id);
    const newMapped = mapPipe(newRow);
    const diff = diffUpdate(oldMapped, newMapped);
    appendAuditLog(db, {
      operatorId: ctx.operatorId, operatorUsername: ctx.operatorUsername,
      actionType: 'update', entityType: 'pipe', entityId: id,
      sourceIp: ctx.sourceIp, diffData: diff,
    });
    return newMapped;
  });
  return tx();
}

function deleteAuditedPipe(id, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const oldRow = db.prepare('SELECT * FROM pipe_segments WHERE id = ?').get(id);
    if (!oldRow) return false;
    const oldMapped = mapPipe(oldRow);
    const diff = diffDelete(oldMapped);
    appendAuditLog(db, {
      operatorId: ctx.operatorId, operatorUsername: ctx.operatorUsername,
      actionType: 'delete', entityType: 'pipe', entityId: id,
      sourceIp: ctx.sourceIp, diffData: diff,
    });
    db.prepare('DELETE FROM pipe_segments WHERE id = ?').run(id);
    return true;
  });
  return tx();
}

function createAuditedStation(data, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const existing = db.prepare('SELECT id FROM pump_stations WHERE code = ?').get(data.code);
    if (existing) throw new Error('CODE_EXISTS');
    const info = db
      .prepare(
        `INSERT INTO pump_stations
          (code, name, district, capacity_m3h, pump_count, status, location)
         VALUES (@code, @name, @district, @capacityM3h, @pumpCount, @status, @location)`,
      )
      .run({
        code: data.code, name: data.name, district: data.district,
        capacityM3h: data.capacityM3h, pumpCount: data.pumpCount,
        status: data.status, location: data.location,
      });
    const id = info.lastInsertRowid;
    const row = db.prepare('SELECT * FROM pump_stations WHERE id = ?').get(id);
    const mapped = mapStation(row);
    const diff = diffCreate(mapped);
    appendAuditLog(db, {
      operatorId: ctx.operatorId, operatorUsername: ctx.operatorUsername,
      actionType: 'create', entityType: 'station', entityId: id,
      sourceIp: ctx.sourceIp, diffData: diff,
    });
    return mapped;
  });
  return tx();
}

function updateAuditedStation(id, data, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const oldRow = db.prepare('SELECT * FROM pump_stations WHERE id = ?').get(id);
    if (!oldRow) throw new Error('NOT_FOUND');
    const oldMapped = mapStation(oldRow);
    const allowed = {
      name: 'name', district: 'district', capacityM3h: 'capacity_m3h',
      pumpCount: 'pump_count', status: 'status', location: 'location',
    };
    const sets = [];
    const params = [];
    for (const [key, col] of Object.entries(allowed)) {
      if (data[key] !== undefined) { sets.push(`${col} = ?`); params.push(data[key]); }
    }
    if (sets.length === 0) return oldMapped;
    sets.push("updated_at = datetime('now')");
    params.push(id);
    db.prepare(`UPDATE pump_stations SET ${sets.join(', ')} WHERE id = ?`).run(...params);
    const newRow = db.prepare('SELECT * FROM pump_stations WHERE id = ?').get(id);
    const newMapped = mapStation(newRow);
    const diff = diffUpdate(oldMapped, newMapped);
    appendAuditLog(db, {
      operatorId: ctx.operatorId, operatorUsername: ctx.operatorUsername,
      actionType: 'update', entityType: 'station', entityId: id,
      sourceIp: ctx.sourceIp, diffData: diff,
    });
    return newMapped;
  });
  return tx();
}

function deleteAuditedStation(id, ctx) {
  const db = getDb();
  const tx = db.transaction(() => {
    const oldRow = db.prepare('SELECT * FROM pump_stations WHERE id = ?').get(id);
    if (!oldRow) return false;
    const oldMapped = mapStation(oldRow);
    const diff = diffDelete(oldMapped);
    appendAuditLog(db, {
      operatorId: ctx.operatorId, operatorUsername: ctx.operatorUsername,
      actionType: 'delete', entityType: 'station', entityId: id,
      sourceIp: ctx.sourceIp, diffData: diff,
    });
    db.prepare('DELETE FROM pump_stations WHERE id = ?').run(id);
    return true;
  });
  return tx();
}

function reconstructEntityAt(entityType, entityId, targetAuditLogId) {
  const timeline = getEntityTimeline(entityType, entityId);
  if (timeline.length === 0) {
    return { ok: false, error: 'NO_TIMELINE', message: '该对象不存在任何审计记录' };
  }

  const numericTarget = Number(targetAuditLogId);
  const targetIdx = timeline.findIndex(l => l.id === numericTarget);
  if (targetIdx === -1) {
    const allIds = timeline.map(l => l.id);
    return { ok: false, error: 'TARGET_NOT_IN_TIMELINE', message: `目标审计记录不在该对象的时间线上，可用记录ID: ${allIds.join(', ')}` };
  }

  let reconstructed = null;
  for (let i = 0; i <= targetIdx; i++) {
    const log = timeline[i];
    if (!log.diff) {
      return { ok: false, error: 'DIFF_MISSING', brokenAt: log.id, message: `审计记录 #${log.id} 的 diff 数据缺失` };
    }
    if (log.diff._parseError) {
      return { ok: false, error: 'DIFF_CORRUPTED', brokenAt: log.id, message: `审计记录 #${log.id} 的 diff 数据损坏无法解析` };
    }
    try {
      reconstructed = applyAuditDiff(reconstructed, log);
    } catch (e) {
      return { ok: false, error: 'APPLY_DIFF_FAILED', brokenAt: log.id, message: `应用审计记录 #${log.id} 的 diff 时出错: ${e.message}` };
    }
    if (reconstructed === null && log.actionType !== 'delete') {
      return { ok: false, error: 'RECONSTRUCT_NULL', brokenAt: log.id, message: `应用审计记录 #${log.id} 后状态为空，但该操作不是 delete` };
    }
  }

  const targetLog = timeline[targetIdx];
  if (reconstructed === null) {
    return {
      ok: true,
      state: null,
      note: '该时间点对象已被删除',
      asOf: targetLog.actionTime,
      asOfAuditLogId: targetLog.id,
    };
  }
  return {
    ok: true,
    state: reconstructed,
    asOf: targetLog.actionTime,
    asOfAuditLogId: targetLog.id,
    actionType: targetLog.actionType,
  };
}

function restoreEntityToVersion(entityType, entityId, targetAuditLogId, ctx) {
  const reconResult = reconstructEntityAt(entityType, entityId, targetAuditLogId);
  if (!reconResult.ok) {
    throw new Error(reconResult.error);
  }
  if (reconResult.state === null) {
    throw new Error('TARGET_STATE_DELETED');
  }

  const reconstructed = reconResult.state;
  const db = getDb();
  const tx = db.transaction(() => {
    const oldRow = ENTITY_TYPE_MAP[entityType].getById(entityId);
    const oldMapped = oldRow ? ENTITY_TYPE_MAP[entityType].mapRow(oldRow) : {};
    const diff = diffRestore(oldMapped, reconstructed);

    const cfg = ENTITY_TYPE_MAP[entityType];
    const idCol = cfg.idCol;
    const table = cfg.table;
    const snapshot = reconstructed;
    const nonAuditCols = Object.keys(snapshot).filter(k => !['createdAt', 'updatedAt', 'id'].includes(k));
    const colMapping = getColumnMappingForEntity(entityType);

    const sets = [];
    const params = [];
    for (const camelKey of nonAuditCols) {
      const col = colMapping[camelKey];
      if (!col) continue;
      sets.push(`${col} = ?`);
      let val = snapshot[camelKey];
      if (camelKey === 'active') val = val ? 1 : 0;
      params.push(val);
    }
    if (sets.length === 0) {
      return oldRow ? cfg.mapRow(oldRow) : null;
    }
    sets.push("updated_at = datetime('now')");
    params.push(entityId);

    const updateSql = `UPDATE ${table} SET ${sets.join(', ')} WHERE ${idCol} = ?`;
    db.prepare(updateSql).run(...params);

    appendAuditLog(db, {
      operatorId: ctx.operatorId, operatorUsername: ctx.operatorUsername,
      actionType: 'restore', entityType, entityId,
      sourceIp: ctx.sourceIp, diffData: diff,
    });

    const newRow = cfg.getById(entityId);
    return cfg.mapRow(newRow);
  });
  return tx();
}

function getColumnMappingForEntity(entityType) {
  const maps = {
    user: { username: 'username', name: 'name', role: 'role', active: 'active' },
    pipe: {
      code: 'code', district: 'district', type: 'type', material: 'material',
      diameterMm: 'diameter_mm', lengthM: 'length_m', status: 'status',
      installedAt: 'installed_at', remark: 'remark',
    },
    station: {
      code: 'code', name: 'name', district: 'district',
      capacityM3h: 'capacity_m3h', pumpCount: 'pump_count',
      status: 'status', location: 'location',
    },
  };
  return maps[entityType] || {};
}

function applyAuditDiff(currentState, auditLog) {
  const { actionType, diff } = auditLog;

  if (actionType === 'create') {
    if (!diff || !diff.changes || diff.changes.length === 0) return currentState;
    const createChange = diff.changes.find(c => c.type === 'create');
    return createChange ? deepClone(createChange.after) : currentState;
  }

  if (actionType === 'delete') {
    return null;
  }

  if (actionType === 'update' || actionType === 'restore') {
    if (!diff || !diff.changes) return currentState;
    let result = currentState ? deepClone(currentState) : {};
    for (const change of diff.changes) {
      try {
        result = applySingleChange(result, change);
      } catch {
        continue;
      }
    }
    return result;
  }

  return currentState;
}

function applySingleChange(obj, change) {
  const { path, type, before, after } = change;

  if (type === 'sensitive') {
    if (path === '') return obj;
    return obj;
  }

  if (path === '') {
    if (type === 'array-replace') return deepClone(after);
    if (type === 'scalar' || type === 'type-change') return deepClone(after);
    return obj;
  }

  const parts = path.split('.');
  const last = parts[parts.length - 1];
  const parentPath = parts.slice(0, -1);
  let parent = obj;
  for (const p of parentPath) {
    if (parent === null || parent === undefined) return obj;
    if (typeof parent !== 'object') return obj;
    if (!Object.prototype.hasOwnProperty.call(parent, p)) {
      parent[p] = {};
    }
    parent = parent[p];
  }

  if (parent === null || parent === undefined || typeof parent !== 'object') return obj;

  switch (type) {
    case 'added':
    case 'scalar':
    case 'type-change':
    case 'array-replace':
      parent[last] = deepClone(after);
      break;
    case 'removed':
      if (Array.isArray(parent) && Number.isInteger(Number(last))) {
        parent.splice(Number(last), 1);
      } else {
        delete parent[last];
      }
      break;
  }

  return obj;
}

function deepClone(v) {
  if (v === null || v === undefined) return v;
  if (typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(deepClone);
  const result = {};
  for (const [k, val] of Object.entries(v)) {
    result[k] = deepClone(val);
  }
  return result;
}

module.exports = {
  mapUser,
  getUserByUsername,
  getUserById,
  getRawUserById,
  listUsers,
  createUser,
  updateUser,
  deleteUser,
  countUsers,
  listPipes,
  getPipeById,
  getPipeByCode,
  createPipe,
  updatePipe,
  deletePipe,
  listStations,
  getStationById,
  getStationByCode,
  createStation,
  updateStation,
  deleteStation,
  // 审计只读查询
  getAuditLogById,
  listAuditLogs,
  getEntityTimeline,
  verifyAuditChain,
  verifySingleAuditRecord,
  getAllAuditRecordsForVerify,
  // 审计 + 事务封装的写操作
  createAuditedUser,
  updateAuditedUser,
  deleteAuditedUser,
  createAuditedPipe,
  updateAuditedPipe,
  deleteAuditedPipe,
  createAuditedStation,
  updateAuditedStation,
  deleteAuditedStation,
  appendAuditLog,
  getRawEntitySnapshot,
  getMappedEntitySnapshot,
  getEntityConfig,
  restoreEntityToVersion,
  reconstructEntityAt,
  applyAuditDiff,
  deepClone,
  ENTITY_TYPE_MAP,
};
