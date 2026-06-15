'use strict';

process.env.DB_FILE = ':memory:';
process.env.SEED_ON_START = 'false';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { createApp } = require('../src/app');
const { getDb, resetAll } = require('../src/db');
const { seed } = require('../src/seed');
const store = require('../src/data/store');
const { diffCreate, diffUpdate, diffDelete, SENSITIVE_MARKER } = require('../src/audit/deep-diff');
const { verifyChain, computeRecordHash, GENESIS_PREV_HASH } = require('../src/audit/hash-chain');
const { runSuspiciousCheck, getDefaultRules } = require('../src/audit/suspicious-rules');

getDb();
const app = createApp();

async function login(username, password) {
  const res = await request(app).post('/api/auth/login').send({ username, password });
  assert.equal(res.status, 200, `登录应成功: ${username}`);
  return res.body.data.token;
}

function authHeader(token) {
  return { Authorization: `Bearer ${token}` };
}

test.beforeEach(() => {
  resetAll();
  seed({ force: true });
});

/* ============================= 单元测试 ============================= */

test('deep-diff: 标量字段变更正确记录 before/after', () => {
  const old = { a: 1, b: 'x', c: true };
  const now = { a: 2, b: 'x', c: false };
  const r = diffUpdate(old, now);
  assert.equal(r.changes.length, 2);
  const a = r.changes.find(c => c.path === 'a');
  assert.ok(a);
  assert.equal(a.type, 'scalar');
  assert.equal(a.before, 1);
  assert.equal(a.after, 2);
  const c = r.changes.find(c => c.path === 'c');
  assert.ok(c);
  assert.equal(c.before, true);
  assert.equal(c.after, false);
});

test('deep-diff: 嵌套对象逐层比较', () => {
  const old = { meta: { x: { y: 1 } }, arr: [1, 2, 3] };
  const now = { meta: { x: { y: 2, z: 3 } }, arr: [1, 2, 4] };
  const r = diffUpdate(old, now);
  assert.ok(r.changes.some(c => c.path === 'meta.x.y' && c.before === 1 && c.after === 2));
  assert.ok(r.changes.some(c => c.path === 'meta.x.z' && c.type === 'added' && c.after === 3));
  assert.ok(r.changes.some(c => c.path === 'arr' && c.type === 'array-replace'));
});

test('deep-diff: 敏感字段（password）只显示 [REDACTED]，不落明文', () => {
  const old = { username: 'alice', password: 'old-pass-123', extra: { token: 'abc' } };
  const now = { username: 'alice', password: 'new-pass-456', extra: { token: 'xyz' } };
  const r = diffUpdate(old, now);
  const pwdChange = r.changes.find(c => c.path === 'password');
  assert.ok(pwdChange, '应记录 password 字段变更');
  assert.equal(pwdChange.type, 'sensitive');
  assert.equal(pwdChange.before, SENSITIVE_MARKER);
  assert.equal(pwdChange.after, SENSITIVE_MARKER);
  assert.notEqual(JSON.stringify(r).includes('old-pass'), true);
  assert.notEqual(JSON.stringify(r).includes('new-pass'), true);
  const tokenChange = r.changes.find(c => c.path === 'extra.token');
  assert.ok(tokenChange);
  assert.equal(tokenChange.before, SENSITIVE_MARKER);
  assert.equal(tokenChange.after, SENSITIVE_MARKER);
});

test('deep-diff: create 记录全量新值，delete 记录全量旧值', () => {
  const obj = { id: 5, name: 'test', status: 'ok' };
  const c = diffCreate(obj);
  assert.equal(c.changes[0].type, 'create');
  assert.equal(c.changes[0].after.id, 5);
  const d = diffDelete(obj);
  assert.equal(d.changes[0].type, 'delete');
  assert.equal(d.changes[0].before.name, 'test');
});

test('hash-chain: 空链校验通过', () => {
  const r = verifyChain([]);
  assert.equal(r.ok, true);
  assert.equal(r.count, 0);
});

test('hash-chain: 第一条记录 prev_hash 必须是 GENESIS', () => {
  const fake = [{ id: 1, prev_hash: 'xxxx', current_hash: 'yyy' }];
  const r = verifyChain(fake);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'genesis_prev_hash_invalid');
  assert.equal(r.brokenAt, 1);
});

/* ============================= 集成测试 ============================= */

test('写操作自动留痕：新建管段 → 审计表新增 create 记录，哈希链连贯', async () => {
  const adminToken = await login('admin', 'admin123');
  const create = await request(app)
    .post('/api/pipes')
    .set(authHeader(adminToken))
    .send({ code: 'AUDIT-TEST-001', district: '测试区', type: 'rain' });
  assert.equal(create.status, 201);
  const pipeId = create.body.data.id;

  const audits = store.listAuditLogs({ entityType: 'pipe', entityId: pipeId });
  assert.equal(audits.total, 1);
  const log = audits.items[0];
  assert.equal(log.entityType, 'pipe');
  assert.equal(log.entityId, pipeId);
  assert.equal(log.actionType, 'create');
  assert.equal(log.operatorUsername, 'admin');
  assert.ok(log.sourceIp);
  assert.ok(log.diff);
  assert.equal(log.diff.changes[0].type, 'create');
  assert.equal(log.diff.changes[0].after.code, 'AUDIT-TEST-001');

  assert.equal(log.prevHash, GENESIS_PREV_HASH, '首条记录 prev_hash 应为 GENESIS');
  assert.equal(typeof log.currentHash, 'string');
  assert.equal(log.currentHash.length, 64, '哈希长度应为 64');

  const verify = store.verifyAuditChain();
  assert.equal(verify.ok, true, `哈希链应完整：${JSON.stringify(verify)}`);
});

test('更新管段：diff 正确记录每个字段的前后差异', async () => {
  const token = await login('operator', 'operator123');
  const beforeStatus = 'normal';
  const create = await request(app)
    .post('/api/pipes')
    .set(authHeader(token))
    .send({ code: 'DIFF-TEST-1', district: 'D1', type: 'rain', status: beforeStatus });
  assert.equal(create.status, 201);
  const pipeId = create.body.data.id;

  const afterRemark = 'updated remark content';
  const afterStatus = beforeStatus === 'normal' ? 'maintenance' : 'normal';
  const put = await request(app)
    .put(`/api/pipes/${pipeId}`)
    .set(authHeader(token))
    .send({ status: afterStatus, remark: afterRemark });
  assert.equal(put.status, 200);

  const timeline = store.getEntityTimeline('pipe', pipeId);
  assert.ok(timeline.length >= 2, '至少应有初始创建 + 本次更新');

  const updateLog = timeline[timeline.length - 1];
  assert.equal(updateLog.actionType, 'update');
  assert.ok(updateLog.diff.changes.length >= 1);
  const statusChange = updateLog.diff.changes.find(c => c.path === 'status');
  assert.ok(statusChange, '应包含 status 字段变更');
  assert.equal(statusChange.before, beforeStatus);
  assert.equal(statusChange.after, afterStatus);
  const remarkChange = updateLog.diff.changes.find(c => c.path === 'remark');
  assert.ok(remarkChange, '应包含 remark 字段变更');
  assert.equal(remarkChange.after, afterRemark);

  const verify = store.verifyAuditChain();
  assert.equal(verify.ok, true);
});

test('删除管段 + 哈希链校验：删除后仍可从审计还原完整状态', async () => {
  const token = await login('admin', 'admin123');
  const list = await request(app).get('/api/pipes').set(authHeader(token));
  const pipe = list.body.data[0];

  const del = await request(app)
    .delete(`/api/pipes/${pipe.id}`)
    .set(authHeader(token));
  assert.equal(del.status, 200);

  const timeline = store.getEntityTimeline('pipe', pipe.id);
  const deleteLog = timeline[timeline.length - 1];
  assert.equal(deleteLog.actionType, 'delete');
  assert.equal(deleteLog.diff.changes[0].before.code, pipe.code);
  assert.equal(deleteLog.diff.changes[0].before.district, pipe.district);

  const verify = store.verifyAuditChain();
  assert.equal(verify.ok, true);
});

test('审计对外只读：没有 DELETE/PUT 审计表的路由入口', async () => {
  const auditRoutes = app._router && app._router.stack
    ? app._router.stack
        .filter(l => l && l.route)
        .map(l => ({ path: l.route.path, methods: Object.keys(l.route.methods) }))
    : [];
  const auditModifying = auditRoutes.filter(r =>
    r.path.startsWith('/api/audit') && (r.methods.includes('put') || r.methods.includes('delete'))
  );
  assert.equal(auditModifying.length, 0, '审计路由不应有 PUT/DELETE 方法');
});

test('事务一致性：如果管段创建冲突（CODE_EXISTS），审计表不应残留孤记录', async () => {
  const token = await login('operator', 'operator123');

  const existing = await request(app).get('/api/pipes').set(authHeader(token));
  const dupCode = existing.body.data[0].code;

  const countBefore = store.listAuditLogs({}).total;

  const create = await request(app)
    .post('/api/pipes')
    .set(authHeader(token))
    .send({ code: dupCode, district: '测试区', type: 'rain' });
  assert.equal(create.status, 409, '重复编号应冲突');

  const countAfter = store.listAuditLogs({}).total;
  assert.equal(countAfter, countBefore, '冲突回滚后，审计记录数不应增加');

  const verify = store.verifyAuditChain();
  assert.equal(verify.ok, true);
});

test('时间线 API：对象从诞生到现在完整串起来', async () => {
  const token = await login('operator', 'operator123');
  const create = await request(app)
    .post('/api/pipes')
    .set(authHeader(token))
    .send({ code: 'TIMELINE-1', district: 'D1', type: 'rain' });
  const pipeId = create.body.data.id;
  await request(app).put(`/api/pipes/${pipeId}`).set(authHeader(token)).send({ status: 'warning' });
  await request(app).put(`/api/pipes/${pipeId}`).set(authHeader(token)).send({ status: 'maintenance', remark: 'R1' });

  const res = await request(app)
    .get(`/api/audit/timeline/pipe/${pipeId}`)
    .set(authHeader(token));
  assert.equal(res.status, 200);
  assert.equal(res.body.total, 3);
  assert.equal(res.body.data[0].actionType, 'create');
  assert.equal(res.body.data[1].actionType, 'update');
  assert.equal(res.body.data[2].actionType, 'update');
});

test('时间旅行：重建某时刻对象状态（早于对象诞生时给出明确提示）', async () => {
  const token = await login('operator', 'operator123');
  const create = await request(app)
    .post('/api/pipes')
    .set(authHeader(token))
    .send({ code: 'TT-0', district: 'D0', type: 'rain', status: 'normal' });
  const pipeId = create.body.data.id;

  const timeline1 = store.getEntityTimeline('pipe', pipeId);
  const createAuditId = timeline1[timeline1.length - 1].id;

  await request(app)
    .put(`/api/pipes/${pipeId}`)
    .set(authHeader(token))
    .send({ status: 'warning', remark: 'first change' });
  const timeline2 = store.getEntityTimeline('pipe', pipeId);
  const update1Id = timeline2[timeline2.length - 1].id;

  await request(app)
    .put(`/api/pipes/${pipeId}`)
    .set(authHeader(token))
    .send({ status: 'maintenance', remark: 'second change' });

  const reconAtCreate = await request(app)
    .get(`/api/audit/reconstruct/pipe/${pipeId}/${createAuditId}`)
    .set(authHeader(token));
  assert.equal(reconAtCreate.status, 200);
  assert.equal(reconAtCreate.body.data.ok, true);
  assert.equal(reconAtCreate.body.data.state.status, 'normal');
  assert.equal(reconAtCreate.body.data.state.remark, null);

  const reconAtUpd1 = await request(app)
    .get(`/api/audit/reconstruct/pipe/${pipeId}/${update1Id}`)
    .set(authHeader(token));
  assert.equal(reconAtUpd1.status, 200);
  assert.equal(reconAtUpd1.body.data.state.status, 'warning');
  assert.equal(reconAtUpd1.body.data.state.remark, 'first change');
});

test('还原 API：一键还原并产生 restore 类型审计记录', async () => {
  const token = await login('admin', 'admin123');
  const create = await request(app)
    .post('/api/pipes')
    .set(authHeader(token))
    .send({ code: 'RESTORE-1', district: 'D', type: 'rain', status: 'normal', remark: 'original' });
  const pipeId = create.body.data.id;

  const timeline1 = store.getEntityTimeline('pipe', pipeId);
  const targetAuditId = timeline1[0].id;

  await request(app)
    .put(`/api/pipes/${pipeId}`)
    .set(authHeader(token))
    .send({ status: 'abandoned', remark: '被误改成废弃了' });

  const restore = await request(app)
    .post(`/api/audit/restore/pipe/${pipeId}/${targetAuditId}`)
    .set(authHeader(token));
  assert.equal(restore.status, 200, JSON.stringify(restore.body));
  assert.equal(restore.body.data.status, 'normal');
  assert.equal(restore.body.data.remark, 'original');

  const timeline2 = store.getEntityTimeline('pipe', pipeId);
  const lastLog = timeline2[timeline2.length - 1];
  assert.equal(lastLog.actionType, 'restore', '还原操作本身也应被审计');
  assert.equal(lastLog.operatorUsername, 'admin');

  const verify = store.verifyAuditChain();
  assert.equal(verify.ok, true);
});

test('哈希链防篡改：偷偷改审计表某条记录后，校验能指出断点', async () => {
  const token = await login('operator', 'operator123');
  await request(app).post('/api/pipes').set(authHeader(token)).send({ code: 'CHAIN-1', district: 'D1', type: 'rain' });
  await request(app).post('/api/pipes').set(authHeader(token)).send({ code: 'CHAIN-2', district: 'D2', type: 'rain' });
  await request(app).post('/api/pipes').set(authHeader(token)).send({ code: 'CHAIN-3', district: 'D3', type: 'rain' });

  let v1 = store.verifyAuditChain();
  assert.equal(v1.ok, true);

  const db = getDb();
  const all = db.prepare('SELECT * FROM audit_logs ORDER BY id ASC').all();
  const victim = all[1];
  db.prepare('UPDATE audit_logs SET operator_username = ? WHERE id = ?').run('hacker-x', victim.id);

  const v2 = store.verifyAuditChain();
  assert.equal(v2.ok, false, '篡改后校验应失败');
  assert.equal(v2.brokenAt, victim.id, '应指出被篡改记录的 id');
  assert.ok(v2.reason.includes('hash_mismatch') || v2.reason.includes('record_hash_invalid'));
});

test('审计查询过滤 + 分页：按操作人/动作/时间范围正确过滤', async () => {
  const adminToken = await login('admin', 'admin123');
  const opToken = await login('operator', 'operator123');

  await request(app).post('/api/pipes').set(authHeader(adminToken)).send({ code: 'ADM-P', district: 'D', type: 'rain' });
  await request(app).post('/api/stations').set(authHeader(opToken)).send({ code: 'OP-S', name: 'N', district: 'D' });

  const adminLogs = await request(app)
    .get('/api/audit')
    .query({ operatorId: 1, pageSize: 100 })
    .set(authHeader(adminToken));
  assert.equal(adminLogs.status, 200);
  assert.ok(adminLogs.body.data.every(l => l.operatorId === 1));

  const createLogs = await request(app)
    .get('/api/audit')
    .query({ actionType: 'create', pageSize: 100 })
    .set(authHeader(adminToken));
  assert.equal(createLogs.status, 200);
  assert.ok(createLogs.body.data.every(l => l.actionType === 'create'));
});

test('敏感字段（用户密码）：审计中只能看到 [REDACTED]，绝不落明文', async () => {
  const adminToken = await login('admin', 'admin123');
  const create = await request(app)
    .post('/api/users')
    .set(authHeader(adminToken))
    .send({ username: 'audit-user-1', password: 'super-secret-password-123', name: 'U', role: 'viewer' });
  assert.equal(create.status, 201);
  const userId = create.body.data.id;

  const timeline = store.getEntityTimeline('user', userId);
  const log = timeline[0];
  const serialized = JSON.stringify(log.diff);

  assert.notEqual(serialized.includes('super-secret-password-123'), true, '密码明文绝不能出现在审计里');
  assert.equal(serialized.includes(SENSITIVE_MARKER), true, '密码应被标记为 REDACTED');

  await request(app)
    .put(`/api/users/${userId}`)
    .set(authHeader(adminToken))
    .send({ password: 'another-secret-xyz' });

  const timeline2 = store.getEntityTimeline('user', userId);
  const upd = timeline2[timeline2.length - 1];
  const updJson = JSON.stringify(upd.diff);
  assert.notEqual(updJson.includes('another-secret-xyz'), true, '更新密码同样不能落明文');
  assert.equal(updJson.includes(SENSITIVE_MARKER), true);
});

test('可疑操作识别：短时间大量删除触发告警', () => {
  const now = Date.now();
  const records = [];
  for (let i = 0; i < 6; i++) {
    records.push({
      id: 100 + i,
      actionType: 'delete',
      entityType: 'pipe',
      entityId: i + 1,
      actionTime: new Date(now + i * 1000).toISOString(),
      operatorId: 99,
      operatorUsername: 'bad-guy',
    });
  }
  const r = runSuspiciousCheck(records);
  assert.ok(r.alerts.some(a => a.ruleId === 'MASS_DELETE_SHORT_WINDOW'));
  assert.ok(r.totalAlerts >= 1);
});

test('可疑操作识别：同一对象短时间内反复更新触发 pingpong 告警', () => {
  const now = Date.now();
  const records = [];
  for (let i = 0; i < 5; i++) {
    records.push({
      id: 200 + i,
      actionType: 'update',
      entityType: 'pipe',
      entityId: 42,
      actionTime: new Date(now + i * 60 * 1000).toISOString(),
      operatorId: 5,
      operatorUsername: 'flip-flopper',
      diff: { changes: [{ path: 'status' }] },
    });
  }
  const r = runSuspiciousCheck(records);
  const pingpong = r.alerts.find(a => a.ruleId === 'OBJECT_PINGPONG');
  assert.ok(pingpong, '应触发 pingpong 规则，实际：' + JSON.stringify(r.alerts.map(x => x.ruleId)));
  assert.equal(pingpong.details.entityId, 42);
});

test('异常情况安全处理：指定审计记录 ID 不在时间线上时不崩', async () => {
  const token = await login('operator', 'operator123');
  const create = await request(app)
    .post('/api/pipes')
    .set(authHeader(token))
    .send({ code: 'ERRCASE-1', district: 'D', type: 'rain' });
  const pipeId = create.body.data.id;

  const res = await request(app)
    .get(`/api/audit/reconstruct/pipe/${pipeId}/999999`)
    .set(authHeader(token));
  assert.equal(res.status, 200);
  assert.equal(res.body.data.ok, false);
  assert.ok(res.body.data.message);
});

test('异常情况安全处理：还原目标已被删除时给出明确错误', async () => {
  const token = await login('admin', 'admin123');
  const create = await request(app)
    .post('/api/pipes')
    .set(authHeader(token))
    .send({ code: 'DEL-RESTORE', district: 'D', type: 'rain' });
  const pipeId = create.body.data.id;

  await request(app).delete(`/api/pipes/${pipeId}`).set(authHeader(token));

  const timeline = store.getEntityTimeline('pipe', pipeId);
  const delAuditId = timeline[timeline.length - 1].id;

  const restore = await request(app)
    .post(`/api/audit/restore/pipe/${pipeId}/${delAuditId}`)
    .set(authHeader(token));
  assert.equal(restore.status, 400);
  assert.ok(restore.body.error && restore.body.error.message);
});

test('哈希链校验接口：admin 可访问，viewer 禁止', async () => {
  const adminT = await login('admin', 'admin123');
  const viewerT = await login('viewer', 'viewer123');
  const ok = await request(app).get('/api/audit/chain/verify').set(authHeader(adminT));
  assert.equal(ok.status, 200);
  assert.equal(ok.body.data.ok, true);
  const forbid = await request(app).get('/api/audit/chain/verify').set(authHeader(viewerT));
  assert.equal(forbid.status, 403);
});
