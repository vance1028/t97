'use strict';

const SENSITIVE_FIELDS = new Set(['password', 'password_hash', 'passwordHash', 'token', 'secret', 'api_key', 'apiKey']);
const SENSITIVE_MARKER = '[REDACTED]';

function isSensitiveField(path) {
  for (const segment of path) {
    if (SENSITIVE_FIELDS.has(String(segment).toLowerCase())) return true;
    if (SENSITIVE_FIELDS.has(String(segment))) return true;
  }
  return false;
}

function getType(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function buildPath(base, key) {
  return base === '' ? String(key) : `${base}.${key}`;
}

function diffValues(oldVal, newVal, path = '', changes = []) {
  const pathArr = path === '' ? [] : path.split('.');

  if (isSensitiveField(pathArr)) {
    const oldChanged = oldVal !== undefined;
    const newChanged = newVal !== undefined;
    if (oldChanged || newChanged) {
      changes.push({
        path,
        type: 'sensitive',
        before: oldChanged ? SENSITIVE_MARKER : undefined,
        after: newChanged ? SENSITIVE_MARKER : undefined,
      });
    }
    return changes;
  }

  const oldType = getType(oldVal);
  const newType = getType(newVal);

  if (oldType !== newType) {
    changes.push({
      path,
      type: 'type-change',
      before: serializeForDiff(oldVal, pathArr),
      after: serializeForDiff(newVal, pathArr),
      beforeType: oldType,
      afterType: newType,
    });
    return changes;
  }

  if (oldType === 'array') {
    return diffArrays(oldVal, newVal, path, changes);
  }

  if (oldType === 'object') {
    return diffObjects(oldVal, newVal, path, changes);
  }

  if (oldVal !== newVal) {
    if (oldType === 'number' && Number.isNaN(oldVal) && Number.isNaN(newVal)) {
      return changes;
    }
    changes.push({
      path,
      type: 'scalar',
      before: oldVal,
      after: newVal,
    });
  }

  return changes;
}

function diffObjects(oldObj, newObj, path = '', changes = []) {
  const oldKeys = Object.keys(oldObj || {});
  const newKeys = Object.keys(newObj || {});
  const allKeys = new Set([...oldKeys, ...newKeys]);

  for (const key of allKeys) {
    const keyPath = buildPath(path, key);
    const pathArr = keyPath === '' ? [] : keyPath.split('.');
    const inOld = oldObj && Object.prototype.hasOwnProperty.call(oldObj, key);
    const inNew = newObj && Object.prototype.hasOwnProperty.call(newObj, key);

    if (isSensitiveField(pathArr)) {
      if (inOld || inNew) {
        changes.push({
          path: keyPath,
          type: 'sensitive',
          before: inOld ? SENSITIVE_MARKER : undefined,
          after: inNew ? SENSITIVE_MARKER : undefined,
        });
      }
      continue;
    }

    if (inOld && !inNew) {
      changes.push({
        path: keyPath,
        type: 'removed',
        before: serializeForDiff(oldObj[key], pathArr),
      });
    } else if (!inOld && inNew) {
      changes.push({
        path: keyPath,
        type: 'added',
        after: serializeForDiff(newObj[key], pathArr),
      });
    } else {
      diffValues(oldObj[key], newObj[key], keyPath, changes);
    }
  }

  return changes;
}

function diffArrays(oldArr, newArr, path = '', changes = []) {
  const maxLen = Math.max(oldArr.length, newArr.length);
  let hasDifference = false;

  if (oldArr.length !== newArr.length) {
    hasDifference = true;
  } else {
    for (let i = 0; i < oldArr.length; i++) {
      const itemPath = buildPath(path, i);
      const itemChanges = [];
      diffValues(oldArr[i], newArr[i], itemPath, itemChanges);
      if (itemChanges.length > 0) {
        hasDifference = true;
        break;
      }
    }
  }

  if (hasDifference) {
    changes.push({
      path,
      type: 'array-replace',
      before: serializeForDiff(oldArr, path === '' ? [] : path.split('.')),
      after: serializeForDiff(newArr, path === '' ? [] : path.split('.')),
      lengthBefore: oldArr.length,
      lengthAfter: newArr.length,
    });
  }

  return changes;
}

function serializeForDiff(val, pathArr) {
  if (val === null || val === undefined) return val;

  if (isSensitiveField(pathArr)) {
    return SENSITIVE_MARKER;
  }

  const t = getType(val);

  if (t === 'array') {
    return val.map((item, i) => serializeForDiff(item, [...pathArr, i]));
  }

  if (t === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(val)) {
      const newPath = [...pathArr, k];
      if (isSensitiveField(newPath)) {
        result[k] = SENSITIVE_MARKER;
      } else {
        result[k] = serializeForDiff(v, newPath);
      }
    }
    return result;
  }

  return val;
}

function diffCreate(newVal) {
  const fullSnapshot = serializeForDiff(newVal, []);
  return {
    action: 'create',
    changes: [{
      path: '',
      type: 'create',
      after: fullSnapshot,
    }],
    snapshot: fullSnapshot,
  };
}

function diffUpdate(oldVal, newVal) {
  const changes = diffValues(oldVal, newVal, '', []);
  return {
    action: 'update',
    changes,
    beforeSnapshot: serializeForDiff(oldVal, []),
    afterSnapshot: serializeForDiff(newVal, []),
  };
}

function diffDelete(oldVal) {
  const fullSnapshot = serializeForDiff(oldVal, []);
  return {
    action: 'delete',
    changes: [{
      path: '',
      type: 'delete',
      before: fullSnapshot,
    }],
    snapshot: fullSnapshot,
  };
}

function diffRestore(oldVal, newVal) {
  const result = diffUpdate(oldVal, newVal);
  result.action = 'restore';
  return result;
}

module.exports = {
  diffCreate,
  diffUpdate,
  diffDelete,
  diffRestore,
  SENSITIVE_MARKER,
  SENSITIVE_FIELDS,
};
