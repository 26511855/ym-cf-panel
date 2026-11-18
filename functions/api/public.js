import { json, getAdmin, getSession } from '../_auth.js';
import { getAccounts, getSettings } from '../_store.js';

// Public aggregate (only when the admin enables it in settings).
// Contains totals only — never tokens, never per-resource detail.
export async function onRequestGet({ request, env }) {
  const settings = await getSettings(env);
  if (!settings.publicSummary) return json({ enabled: false });
  const cacheKey = 'cache:public:today';
  // 【C-26 修复】缓存刷新只许发生在管理员请求里：这个键此前只有本接口
  // 自己在写，匿名访客在缓存过期后反复打就能稳定消耗写额度。现匿名侧
  // 只读已有缓存、永不触发写（过期也返回旧缓存）；带有效管理员会话
  // 的请求（站长打开面板时）才允许现算并回写刷新，口径与 state 的
  // sv 比对一致。取舍：站长长期不打开面板时，公开汇总会停在旧值——
  // 它本来就是 5 分钟级的展示汇总，慢更新可接受，写额度优先。
  let authed = false;
  try {
    const admin = await getAdmin(env);
    const sess = await getSession(env, request);
    authed = !!(admin && sess && (sess.sv || 1) === (admin.sv || 1));
  } catch { authed = false; }
  const raw = await env.PANEL_KV.get(cacheKey);
  if (raw) {
    try {
      const c = JSON.parse(raw);
      if (!authed || Date.now() - c.at < 300000) return json({ enabled: true, ...c.data, cachedAt: c.at });
      // 管理员请求 + 缓存已过期：落到下方现算并回写刷新
    } catch { /* 缓存损坏：落到下方现算（写与否仍只看 authed） */ }
  }
  const list = await getAccounts(env);
  const tot = { accounts: list.length, workersRequests: 0, workersErrors: 0, kvReads: 0, kvWrites: 0, d1RowsRead: 0, d1RowsWritten: 0, r2Ops: 0, httpRequests: 0, httpBytes: 0 };
  // 只读管理员打开用量页时写下的 per-account 缓存（cache:<id>:today），
  // 不再由匿名请求现场触发全账号拉取：此前缓存一过期，任何匿名访客的
  // 一个请求就会串行跑完所有账号的 getUsage（约 45 次子请求贴着免费版
  // 50 上限），并发进来还会各拉一遍。没有缓存的账号跳过并如实标注。
  let covered = 0, stalest = null;
  for (const acct of list) {
    try {
      const raw = await env.PANEL_KV.get(`cache:${acct.id}:today`);
      if (!raw) continue;
      const c = JSON.parse(raw);
      const u = (c.data && c.data.usage) || {};
      if (u.workers && u.workers.ok) { tot.workersRequests += u.workers.data.requests; tot.workersErrors += u.workers.data.errors; }
      if (u.kv && u.kv.ok) { tot.kvReads += u.kv.data.read; tot.kvWrites += u.kv.data.write; }
      if (u.d1 && u.d1.ok) { tot.d1RowsRead += u.d1.data.rowsRead; tot.d1RowsWritten += u.d1.data.rowsWritten; }
      if (u.r2 && u.r2.ok) { tot.r2Ops += u.r2.data.classA + u.r2.data.classB; }
      if (u.http && u.http.ok) { tot.httpRequests += u.http.data.requests; tot.httpBytes += u.http.data.bytes; }
      covered++;
      if (stalest === null || c.at < stalest) stalest = c.at;
    } catch { /* skip broken account */ }
  }
  const data = { panelName: settings.panelName, range: 'today', totals: tot, accountsCovered: covered, usageCachedAt: stalest };
  // 【C-26】落盘刷新只在管理员请求时发生；匿名现算只返回、不落盘。
  if (authed) {
    await env.PANEL_KV.put(cacheKey, JSON.stringify({ at: Date.now(), data }), { expirationTtl: 3600 });
    return json({ enabled: true, ...data, cachedAt: Date.now() });
  }
  return json({ enabled: true, ...data, cachedAt: stalest });
}
