// ym-cf-panel v4.0.13 KV 导出/回导定向测试（node tests/kvio-backup.mjs）
// 覆盖：导出升级为规整备份信封（format/version/exportedAt/entries）+
// 回导先校验版本（不对拒绝且零写入）+ 只写文件内条目不动其他键 +
// 成功/失败条数（含分批部分失败、无键名条目计失败）+ 旧裸数组兼容。
// 全部假数据：PANEL_KV 用内存替身，被管账号的 KV 命名空间用 fetch
// 替身模拟 Cloudflare 官方接口（keys 列表 / bulk get / bulk PUT）。
import { createSession } from '../functions/_auth.js';
import { onRequestGet as kvExport, onRequestPost as kvImport, KV_EXPORT_FORMAT, KV_EXPORT_VERSION } from '../functions/api/kvio.js';

class KV {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.has(k) ? this.m.get(k) : null; }
  async put(k, v) { this.m.set(k, String(v)); }
  async delete(k) { this.m.delete(k); }
}
let pass = 0, failN = 0;
const chk = (name, cond, extra = '') => { if (cond) { pass++; console.log('PASS', name); } else { failN++; console.log('FAIL', name, extra); } };

// ---- 假 Cloudflare KV 命名空间（fetch 替身） ----
const realFetch = globalThis.fetch;
let fakeNs;        // Map<key, value>：被管命名空间的内容
let putCalls;      // bulk PUT 调用次数
let fetchMethods;  // 记录所有 fetch 方法（验导入绝不发 DELETE）
let failSecondBatch; // 注入：第二批 bulk PUT 失败
function installFetchMock() {
  fakeNs = new Map();
  putCalls = 0;
  fetchMethods = [];
  failSecondBatch = false;
  globalThis.fetch = async (url, opts = {}) => {
    const u = new URL(String(url));
    const method = (opts.method || 'GET').toUpperCase();
    fetchMethods.push(method);
    const ok = (result, result_info) => new Response(JSON.stringify({ success: true, result, ...(result_info ? { result_info } : {}) }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    const err = (status, message) => new Response(JSON.stringify({ success: false, errors: [{ message }] }), { status, headers: { 'Content-Type': 'application/json' } });
    if (u.pathname.endsWith('/keys')) {
      return ok([...fakeNs.keys()].map((name) => ({ name })), { cursor: '' });
    }
    if (u.pathname.endsWith('/bulk/get')) {
      const body = JSON.parse(opts.body);
      const result = {};
      for (const k of body.keys) if (fakeNs.has(k)) result[k] = fakeNs.get(k);
      return ok(result);
    }
    if (u.pathname.endsWith('/bulk') && method === 'PUT') {
      putCalls++;
      const batch = JSON.parse(opts.body);
      if (failSecondBatch && putCalls === 2) return err(500, '注入的批量写失败');
      for (const p of batch) fakeNs.set(p.key, p.value);
      return ok(null);
    }
    throw new Error('unexpected fetch ' + method + ' ' + u.pathname);
  };
}

async function makeCtx() {
  const kv = new KV();
  const env = { PANEL_KV: kv };
  await kv.put('admin', JSON.stringify({ user: 'boss', salt: 's', hash: 'h', sv: 1 }));
  await kv.put('accounts', JSON.stringify([{ id: 'a1', name: '假账号', accountId: 'accfake123', token: 'fake-token-for-test' }]));
  const tok = await createSession(env, 'boss', 1);
  const req = (path, opts = {}) => new Request('https://panel.test' + path, { headers: { cookie: `ymcfp=${tok}`, 'content-type': 'application/json' }, ...opts });
  return { env, req };
}
const post = (req, env, body) => kvImport({ request: req('/api/kvio', { method: 'POST', body: JSON.stringify(body) }), env });

// ---- 1) 导出信封形状 + 内容与假数据一致 ----
installFetchMock();
{
  const { env, req } = await makeCtx();
  fakeNs.set('accounts', '[{"id":"x","token":"fake-token-value"}]');
  fakeNs.set('settings', '{"panelName":"假面板"}');
  fakeNs.set('greeting', '你好，世界');
  const r = await kvExport({ request: req('/api/kvio?account=a1&ns=ns-test-1'), env });
  const j = await r.json();
  chk('导出 200', r.status === 200, 'status=' + r.status + ' ' + JSON.stringify(j).slice(0, 120));
  chk('导出带 format 标记', j.format === KV_EXPORT_FORMAT && j.format === 'ym-cf-panel-kv-export', String(j.format));
  chk('导出带 version=1', j.version === KV_EXPORT_VERSION && j.version === 1, String(j.version));
  chk('导出带 exportedAt 时间', typeof j.exportedAt === 'string' && !Number.isNaN(Date.parse(j.exportedAt)), String(j.exportedAt));
  chk('导出 entries/total 正确', j.total === 3 && Array.isArray(j.entries) && j.entries.length === 3, JSON.stringify(j).slice(0, 120));
  const byName = Object.fromEntries((j.entries || []).map((e) => [e.name, e.value]));
  chk('导出值逐条与原数据一致', byName.accounts === '[{"id":"x","token":"fake-token-value"}]' && byName.settings === '{"panelName":"假面板"}' && byName.greeting === '你好，世界');
  chk('导出保留 truncated 字段', j.truncated === false);

  // ---- 2) 全程：导出 → 清空 → 回导 → 逐条一致；且不碰文件外的键 ----
  const backup = j;
  fakeNs.clear();
  fakeNs.set('outside', '文件外的值，不许动');
  const putsBefore = putCalls;
  const r2 = await post(req, env, { account: 'a1', ns: 'ns-test-1', backup });
  const j2 = await r2.json();
  chk('回导 200 且 ok', r2.status === 200 && j2.ok === true, 'status=' + r2.status + ' ' + JSON.stringify(j2));
  chk('回导报数 succeeded=3 failed=0（written 兼容）', j2.succeeded === 3 && j2.failed === 0 && j2.written === 3, JSON.stringify(j2));
  chk('回导后逐条数据一致', fakeNs.get('accounts') === byName.accounts && fakeNs.get('settings') === byName.settings && fakeNs.get('greeting') === byName.greeting);
  chk('回导没动文件外的键', fakeNs.get('outside') === '文件外的值，不许动' && fakeNs.size === 4, 'size=' + fakeNs.size);
  chk('回导全程没有任何 DELETE 请求', !fetchMethods.includes('DELETE'), fetchMethods.join(','));
  chk('回导确实发了 bulk PUT', putCalls > putsBefore);
}

// ---- 3) 版本不对 → 拒绝且零写入 ----
installFetchMock();
{
  const { env, req } = await makeCtx();
  fakeNs.set('keep', '原样');
  const bad = { format: KV_EXPORT_FORMAT, version: 999, exportedAt: new Date().toISOString(), entries: [{ name: 'a', value: '1' }] };
  const r = await post(req, env, { account: 'a1', ns: 'ns-test-1', backup: bad });
  const j = await r.json();
  chk('版本 999 被拒绝（400）', r.status === 400 && /版本不对/.test(j.error || ''), 'status=' + r.status + ' ' + JSON.stringify(j));
  chk('版本不对时零写入', putCalls === 0 && fakeNs.size === 1 && fakeNs.get('keep') === '原样', 'puts=' + putCalls);
  // format 对不上同样拒绝
  const bad2 = { format: 'some-other-file', version: 1, entries: [{ name: 'a', value: '1' }] };
  const r2 = await post(req, env, { account: 'a1', ns: 'ns-test-1', backup: bad2 });
  chk('format 对不上被拒绝且零写入', r2.status === 400 && putCalls === 0, 'status=' + r2.status);
  // 信封缺 version 同样拒绝
  const bad3 = { format: KV_EXPORT_FORMAT, entries: [{ name: 'a', value: '1' }] };
  const r3 = await post(req, env, { account: 'a1', ns: 'ns-test-1', backup: bad3 });
  chk('缺 version 被拒绝且零写入', r3.status === 400 && putCalls === 0, 'status=' + r3.status);
  // 摊平写法（format/version 与 entries 同层）版本不对同样拒绝
  const r4 = await post(req, env, { account: 'a1', ns: 'ns-test-1', format: KV_EXPORT_FORMAT, version: 2, entries: [{ name: 'a', value: '1' }] });
  chk('摊平信封版本不对被拒绝且零写入', r4.status === 400 && putCalls === 0, 'status=' + r4.status);
}

// ---- 4) 旧格式裸条目仍可导入（老备份不作废） ----
installFetchMock();
{
  const { env, req } = await makeCtx();
  const r = await post(req, env, { account: 'a1', ns: 'ns-test-1', entries: [{ name: 'old1', value: 'v1' }, { key: 'old2', value: 'v2' }] });
  const j = await r.json();
  chk('旧裸条目导入成功', r.status === 200 && j.ok === true && j.succeeded === 2 && fakeNs.get('old1') === 'v1' && fakeNs.get('old2') === 'v2', JSON.stringify(j));
}

// ---- 5) 成功/失败条数：无效条目计失败、分批部分失败如实报数 ----
installFetchMock();
{
  const { env, req } = await makeCtx();
  const r = await post(req, env, { account: 'a1', ns: 'ns-test-1', entries: [{ name: '', value: 'x' }, { name: 'ok', value: 'v' }, { name: 'bad', value: { nested: 1 } }] });
  const j = await r.json();
  chk('无效条目计失败（成功1/失败2）', r.status === 200 && j.succeeded === 1 && j.failed === 2 && fakeNs.get('ok') === 'v' && !fakeNs.has('bad'), JSON.stringify(j));

  installFetchMock();
  failSecondBatch = true;
  const many = Array.from({ length: 150 }, (_, i) => ({ name: 'k' + String(i).padStart(3, '0'), value: 'v' + i }));
  const r2 = await post(req, env, { account: 'a1', ns: 'ns-test-1', backup: { format: KV_EXPORT_FORMAT, version: 1, exportedAt: new Date().toISOString(), entries: many } });
  const j2 = await r2.json();
  chk('第二批失败时报数成功100/失败50', r2.status === 200 && j2.ok === false && j2.succeeded === 100 && j2.failed === 50, 'status=' + r2.status + ' ' + JSON.stringify(j2));
  chk('第一批已落库、第二批没落库', fakeNs.get('k000') === 'v0' && !fakeNs.has('k100'), 'size=' + fakeNs.size);
}

// ---- 6) 未登录不可用 ----
installFetchMock();
{
  const { env } = await makeCtx();
  const r = await kvExport({ request: new Request('https://panel.test/api/kvio?account=a1&ns=ns-test-1'), env });
  chk('未登录导出被拒（401）', r.status === 401, 'status=' + r.status);
  const r2 = await kvImport({ request: new Request('https://panel.test/api/kvio', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ account: 'a1', ns: 'ns-test-1', backup: { format: KV_EXPORT_FORMAT, version: 1, entries: [{ name: 'a', value: '1' }] } }) }), env });
  chk('未登录回导被拒（401）且零写入', r2.status === 401 && putCalls === 0, 'status=' + r2.status);
}

globalThis.fetch = realFetch;
console.log(`\nTOTAL pass=${pass} fail=${failN}`);
process.exit(failN ? 1 : 0);
