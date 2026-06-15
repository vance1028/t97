'use strict';

const crypto = require('crypto');

const GENESIS_PREV_HASH = '0'.repeat(64);
const HASH_ALGO = 'sha256';

function computeHash(data) {
  const serialized = typeof data === 'string' ? data : JSON.stringify(data);
  return crypto.createHash(HASH_ALGO).update(serialized).digest('hex');
}

function buildAuditPayload({ operatorId, operatorUsername, actionTime, actionType, entityType, entityId, sourceIp, diffData }) {
  return {
    operatorId: Number(operatorId),
    operatorUsername: String(operatorUsername),
    actionTime: String(actionTime),
    actionType: String(actionType),
    entityType: String(entityType),
    entityId: Number(entityId),
    sourceIp: sourceIp ? String(sourceIp) : null,
    diffData: typeof diffData === 'string' ? diffData : JSON.stringify(diffData),
  };
}

function computeRecordHash(prevHash, payload) {
  const hashInput = {
    prevHash: String(prevHash),
    ...buildAuditPayload(payload),
  };
  return computeHash(JSON.stringify(hashInput, Object.keys(hashInput).sort()));
}

function verifyRecordHash(record) {
  if (!record || typeof record !== 'object') return { ok: false, reason: 'record_not_object' };
  if (typeof record.prev_hash !== 'string') return { ok: false, reason: 'prev_hash_missing' };
  if (typeof record.current_hash !== 'string') return { ok: false, reason: 'current_hash_missing' };

  let diffData;
  try {
    diffData = typeof record.diff_data === 'string' ? record.diff_data : JSON.stringify(record.diff_data);
  } catch {
    return { ok: false, reason: 'diff_data_invalid' };
  }

  const payload = {
    operatorId: record.operator_id,
    operatorUsername: record.operator_username,
    actionTime: record.action_time,
    actionType: record.action_type,
    entityType: record.entity_type,
    entityId: record.entity_id,
    sourceIp: record.source_ip,
    diffData,
  };

  const expected = computeRecordHash(record.prev_hash, payload);
  if (expected !== record.current_hash) {
    return { ok: false, reason: 'hash_mismatch', expected, actual: record.current_hash };
  }

  return { ok: true };
}

function verifyChain(records) {
  if (!Array.isArray(records)) return { ok: false, reason: 'records_not_array' };
  if (records.length === 0) return { ok: true, count: 0, message: 'empty_chain' };

  const sorted = [...records].sort((a, b) => Number(a.id) - Number(b.id));

  const first = sorted[0];
  if (first.prev_hash !== GENESIS_PREV_HASH) {
    return {
      ok: false,
      brokenAt: Number(first.id),
      reason: 'genesis_prev_hash_invalid',
      expected: GENESIS_PREV_HASH,
      actual: first.prev_hash,
    };
  }

  for (let i = 0; i < sorted.length; i++) {
    const rec = sorted[i];
    const hashCheck = verifyRecordHash(rec);
    if (!hashCheck.ok) {
      return {
        ok: false,
        brokenAt: Number(rec.id),
        reason: `record_hash_invalid: ${hashCheck.reason}`,
        details: hashCheck,
      };
    }

    if (i > 0) {
      const prev = sorted[i - 1];
      if (rec.prev_hash !== prev.current_hash) {
        return {
          ok: false,
          brokenAt: Number(rec.id),
          reason: 'chain_link_broken',
          prevRecordId: Number(prev.id),
          expectedPrevHash: prev.current_hash,
          actualPrevHash: rec.prev_hash,
        };
      }
    }
  }

  return {
    ok: true,
    count: sorted.length,
    lastId: Number(sorted[sorted.length - 1].id),
    lastHash: sorted[sorted.length - 1].current_hash,
  };
}

function getGenesisPrevHash() {
  return GENESIS_PREV_HASH;
}

module.exports = {
  computeHash,
  buildAuditPayload,
  computeRecordHash,
  verifyRecordHash,
  verifyChain,
  getGenesisPrevHash,
  GENESIS_PREV_HASH,
  HASH_ALGO,
};
