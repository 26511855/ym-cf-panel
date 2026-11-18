// ym-cf-panel 登录限流定向测试（node tests/login-ratelimit.mjs）
// 覆盖对抗复读 C-4 / C-5 / C-26 / C-29：
//   C-4 登录失败计数改内存版：500 次不同 IP 失败登录，KV put 总数 ≤ 20
//       （改前每失败写 2 笔 = 1000 笔）；同 IP 第 5 次失败后锁定行为不变；
//       全局失败攒高后的渐进延迟行为不变。
//   C-5 /api/state 必须比对会话 sv：sv 对不上的旧会话按未登录返回
//       （authed:false 的现有返回形状不变），sv 对上的照常 authed:true。
//   C-26 /api/public 匿名侧永不写 KV：有过期缓存也只返回旧缓存、不回写。
//   C-29 用户名不对时也要跑一遍口令哈希拉平耗时（以 PBKDF2 耗时下限粗测）。
import { sha256hex, hashPassword, createSession } from '../functions/_auth.js';
import { onRequestPost as login } from '../functions/api/login.js';
import { onRequestGet as state } from '../functions/api/state.js';
import { onRequestGet as pub } from '../functions/api/public.js';

class KV {
  constructor() { this.m = new Map(); this.puts = 0; this.putKeys = []; }
  async get(k) { return this.m.has(k) ? this.m.get(k) : null; }
  async put(k, v) { this.puts++; this.putKeys.push(k); this.m.set(k, String(v)); }
  async delete(k) { this.m.delete(k); }
}
let pass = 0, failN = 0;
const chk = (name, cond, extra = '') => { if (cond) { pass++; console.log('PASS', name); } else { failN++; console.log('FAIL', name, extra); } };

const legacyAdmin = async () => ({ user: 'boss', salt: 'salt1', hash: await sha256hex('salt1:right-pw'), sv: 1 });
const loginReq = (ip, user, password) => new Request('https://panel.test/api/login', {
  method: 'POST',
  headers: { 'cf-connecting-ip': ip, 'content-type': 'application/json' },
  body: JSON.stringify({ user, password }),
});

// ---- C-4 场景 B（先跑，全局计数还低、无延迟）：同 IP 锁定语义 ----
// 注意 login.js 的限流状态是模块级内存，整个测试进程共享，下面顺序经过设计。
{
  const env = { PANEL_KV: new KV() };
  await env.PANEL_KV.put('admin', JSON.stringify(await legacyAdmin()));
  env.PANEL_KV.puts = 0;
  let last;
  for (let i = 0; i < 5; i++) last = await login({ request: loginReq('9.9.9.9', 'boss', 'wrong'), env });
  chk('C-4 同 IP 前 5 次失败仍是 401', last.status === 401, 'status=' + last.status);
  const sixth = await login({ request: loginReq('9.9.9.9', 'boss', 'wrong'), env });
  chk('C-4 同 IP 第 6 次尝试被锁 429', sixth.status === 429, 'status=' + sixth.status);
}

// ---- C-4 场景 A：500 次不同 IP 失败登录的 KV 写量（并发跑，避开全局延迟串行等待） ----
{
  const env = { PANEL_KV: new KV() };
  await env.PANEL_KV.put('admin', JSON.stringify(await legacyAdmin()));
  env.PANEL_KV.puts = 0; env.PANEL_KV.putKeys = [];
  const reqs = [];
  for (let i = 0; i < 500; i++) {
    reqs.push(login({ request: loginReq(`10.${(i >> 8) & 255}.${i & 255}.7`, 'boss', 'wrong'), env }));
  }
  const res = await Promise.all(reqs);
  chk('C-4 500 次失败全是 401', res.every(r => r.status === 401));
  chk('C-4 500 次不同 IP 失败登录 KV put ≤ 20', env.PANEL_KV.puts <= 20, `puts=${env.PANEL_KV.puts}`);
  // ---- C-4 场景 C：全局失败已攒高 → 新尝试带渐进延迟（≥1s，语义与改前一致） ----
  const t0 = Date.now();
  await login({ request: loginReq('8.8.8.8', 'boss', 'wrong'), env });
  const elapsed = Date.now() - t0;
  chk('C-4 全局失败攒高后有渐进延迟（≥1000ms）', elapsed >= 1000, `elapsed=${elapsed}ms`);
}

// ---- C-29：用户名不对也要跑哈希（PBKDF2 管理员，错用户名+对密码应明显耗时） ----
{
  const env = { PANEL_KV: new KV() };
  const { salt, hash } = await hashPassword('right-pw');
  await env.PANEL_KV.put('admin', JSON.stringify({ user: 'boss', salt, hash, sv: 1 }));
  const t0 = Date.now();
  const r = await login({ request: loginReq('7.7.7.7', 'not-boss', 'right-pw'), env });
  const elapsed = Date.now() - t0;
  chk('C-29 错用户名+对密码仍是 401', r.status === 401, 'status=' + r.status);
  chk('C-29 错用户名也跑了口令哈希（≥10ms）', elapsed >= 10, `elapsed=${elapsed}ms`);
}

// ---- C-5：/api/state 比对 sv ----
{
  const env = { PANEL_KV: new KV() };
  await env.PANEL_KV.put('admin', JSON.stringify({ user: 'boss', salt: 's', hash: 'h', sv: 2 }));
  const staleTok = await createSession(env, 'boss', 1); // sv=1，管理员已是 sv=2（改过密码）
  const reqStale = new Request('https://panel.test/api/state', { headers: { cookie: `ymcfp=${staleTok}` } });
  const jStale = await (await state({ request: reqStale, env })).json();
  chk('C-5 sv 对不上的会话按未登录（authed:false）', jStale.authed === false && jStale.needsSetup === false, JSON.stringify(jStale));
  const goodTok = await createSession(env, 'boss', 2);
  const reqGood = new Request('https://panel.test/api/state', { headers: { cookie: `ymcfp=${goodTok}` } });
  const jGood = await (await state({ request: reqGood, env })).json();
  chk('C-5 sv 对上的会话照常 authed:true', jGood.authed === true && jGood.user === 'boss', JSON.stringify(jGood));
}

// ---- C-26：/api/public 匿名永不写 ----
{
  const env = { PANEL_KV: new KV() };
  await env.PANEL_KV.put('settings', JSON.stringify({ panelName: 'P', publicSummary: true }));
  await env.PANEL_KV.put('accounts', JSON.stringify([]));
  const staleAt = Date.now() - 10 * 60 * 1000; // 已过期 10 分钟
  await env.PANEL_KV.put('cache:public:today', JSON.stringify({ at: staleAt, data: { panelName: 'P', range: 'today', totals: { accounts: 0 }, accountsCovered: 0, usageCachedAt: null } }));
  env.PANEL_KV.puts = 0;
  const j = await (await pub({ request: new Request('https://panel.test/api/public'), env })).json();
  chk('C-26 过期缓存也返回（不 500、不现算覆盖）', j.enabled === true && j.cachedAt === staleAt, JSON.stringify(j));
  chk('C-26 匿名请求零 KV 写', env.PANEL_KV.puts === 0, `puts=${env.PANEL_KV.puts}`);
  // 无任何缓存时：可以现算返回，但仍不许写
  const env2 = { PANEL_KV: new KV() };
  await env2.PANEL_KV.put('settings', JSON.stringify({ panelName: 'P', publicSummary: true }));
  await env2.PANEL_KV.put('accounts', JSON.stringify([]));
  env2.PANEL_KV.puts = 0;
  const j2 = await (await pub({ request: new Request('https://panel.test/api/public'), env: env2 })).json();
  chk('C-26 无缓存时现算返回且零 KV 写', j2.enabled === true && env2.PANEL_KV.puts === 0, `puts=${env2.PANEL_KV.puts} ${JSON.stringify(j2)}`);
  // 管理员请求 + 过期缓存 → 允许现算并回写刷新（刷新只在管理员路径发生）
  const env3 = { PANEL_KV: new KV() };
  await env3.PANEL_KV.put('settings', JSON.stringify({ panelName: 'P', publicSummary: true }));
  await env3.PANEL_KV.put('accounts', JSON.stringify([]));
  await env3.PANEL_KV.put('admin', JSON.stringify({ user: 'boss', salt: 's', hash: 'h', sv: 1 }));
  await env3.PANEL_KV.put('cache:public:today', JSON.stringify({ at: staleAt, data: { panelName: 'P', range: 'today', totals: { accounts: 99 }, accountsCovered: 0, usageCachedAt: null } }));
  const tok = await createSession(env3, 'boss', 1);
  env3.PANEL_KV.puts = 0;
  const reqA = new Request('https://panel.test/api/public', { headers: { cookie: `ymcfp=${tok}` } });
  const j3 = await (await pub({ request: reqA, env: env3 })).json();
  chk('C-26 管理员请求刷新过期缓存', j3.enabled === true && j3.cachedAt !== staleAt && j3.totals.accounts === 0 && env3.PANEL_KV.puts === 1,
    `puts=${env3.PANEL_KV.puts} ${JSON.stringify(j3)}`);
}

console.log(`\nTOTAL pass=${pass} fail=${failN}`);
process.exit(failN ? 1 : 0);
