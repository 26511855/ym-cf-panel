// ym-cf-panel 落盘加密（M26）+ 会话键哈希定向测试（node tests/secrets.mjs）
// 覆盖：
//   ① 明文旧数据（无 DATA_KEK）读得到，行为与加密改造前一致；
//   ② 有 KEK 时写出 enc:v1: 密文（不含令牌明文）、读回一致；
//   ③ 无 KEK 时写读仍是明文 JSON（代码先上线、钥匙后配，中间不降级也不损坏）；
//   ④ KEK 给错时读显式报错，且 KV 里的原数据一字未动（不许覆盖坏数据）；
//   ⑤ 有密文却没配 KEK → 显式报错；
//   ⑥ mutateAccounts 在有 KEK 时正常（落盘密文、读回一致）；
//   ⑦ 会话键改 sess:<sha256(token)>：落盘不含原文、Cookie 照常鉴权、退出删键。
import { randomBytes, createHash } from 'node:crypto';
import { getAccounts, saveAccounts, mutateAccounts } from '../functions/_store.js';
import { createSession, getSession, requireAuth } from '../functions/_auth.js';
import { onRequestPost as logout } from '../functions/api/logout.js';

class KV {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.has(k) ? this.m.get(k) : null; }
  async put(k, v) { this.m.set(k, String(v)); }
  async delete(k) { this.m.delete(k); }
}

let pass = 0, failN = 0;
const chk = (name, cond, extra = '') => { if (cond) { pass++; console.log('PASS', name); } else { failN++; console.log('FAIL', name, extra); } };

const KEK_A = randomBytes(32).toString('base64');
const KEK_B = randomBytes(32).toString('base64');
const LIST = [{ id: 'a1', name: '主账号', accountId: 'f86488d8e8df5d7db666c0a498292af6', token: 'cfut-secret-token-1234567890' }];

// ① 明文旧数据读得到
{
  const kv = new KV();
  kv.m.set('accounts', JSON.stringify(LIST));
  const got = await getAccounts({ PANEL_KV: kv });
  chk('① 明文旧数据读得到', JSON.stringify(got) === JSON.stringify(LIST));
}

// ② 有 KEK：密文落盘 + 读回一致
{
  const kv = new KV();
  const env = { PANEL_KV: kv, DATA_KEK: KEK_A };
  await saveAccounts(env, LIST);
  const stored = kv.m.get('accounts');
  chk('② 落盘是 enc:v1: 密文', typeof stored === 'string' && stored.startsWith('enc:v1:'), String(stored).slice(0, 40));
  chk('② 密文不含令牌明文', !stored.includes('cfut-secret-token'));
  const got = await getAccounts(env);
  chk('② 读回与原文一致', JSON.stringify(got) === JSON.stringify(LIST));
}

// ③ 无 KEK：明文写读（与改前一致）
{
  const kv = new KV();
  const env = { PANEL_KV: kv };
  await saveAccounts(env, LIST);
  chk('③ 无 KEK 时落盘仍是明文 JSON', kv.m.get('accounts') === JSON.stringify(LIST));
  const got = await getAccounts(env);
  chk('③ 无 KEK 时读回一致', JSON.stringify(got) === JSON.stringify(LIST));
}

// ④ KEK 给错：显式报错 + 原数据不动
{
  const kv = new KV();
  await saveAccounts({ PANEL_KV: kv, DATA_KEK: KEK_A }, LIST);
  const before = kv.m.get('accounts');
  let err = null;
  try { await getAccounts({ PANEL_KV: kv, DATA_KEK: KEK_B }); } catch (e) { err = e; }
  chk('④ 错 KEK 读显式报错', !!err && /解密失败/.test(err.message), err?.message);
  chk('④ 报错后 KV 原数据一字未动', kv.m.get('accounts') === before);
}

// ⑤ 有密文、没配 KEK：显式报错
{
  const kv = new KV();
  await saveAccounts({ PANEL_KV: kv, DATA_KEK: KEK_A }, LIST);
  let err = null;
  try { await getAccounts({ PANEL_KV: kv }); } catch (e) { err = e; }
  chk('⑤ 密文 + 无 KEK 显式报错', !!err && /DATA_KEK 没配/.test(err.message), err?.message);
}

// ⑥ mutateAccounts + KEK
{
  const kv = new KV();
  const env = { PANEL_KV: kv, DATA_KEK: KEK_A };
  const r = await mutateAccounts(env, (list) => ({ list: [...list, LIST[0]] }));
  chk('⑥ mutate 成功', r.ok === true);
  chk('⑥ mutate 落盘是密文', (kv.m.get('accounts') || '').startsWith('enc:v1:'));
  const got = await getAccounts(env);
  chk('⑥ mutate 读回一致', got.length === 1 && got[0].token === LIST[0].token);
}

// ⑦ 会话键哈希 + 登录全路径
{
  const kv = new KV();
  const env = { PANEL_KV: kv };
  kv.m.set('admin', JSON.stringify({ username: 'boss', salt: 's', hash: 'x', sv: 1 }));
  const token = await createSession(env, 'boss', 1);
  const expectKey = 'sess:' + createHash('sha256').update(token).digest('hex');
  chk('⑦ 会话以哈希键落库', kv.m.has(expectKey), [...kv.m.keys()].join(','));
  chk('⑦ KV 键里不含令牌原文', ![...kv.m.keys()].some(k => k.includes(token)));
  const req = new Request('https://cf.test/api/state', { headers: { Cookie: `ymcfp=${token}` } });
  const sess = await getSession(env, req);
  chk('⑦ Cookie 原文读回会话', !!sess && sess.user === 'boss');
  const auth = await requireAuth(env, req);
  chk('⑦ requireAuth 全路径通过', !auth.error && auth.sess.user === 'boss', auth.error ? 'error' : '');
  await logout({ request: req, env });
  chk('⑦ 退出后哈希键已删', !kv.m.has(expectKey));
  const sess2 = await getSession(env, req);
  chk('⑦ 退出后会话失效', sess2 === null);
}

console.log(`\nTOTAL pass=${pass} fail=${failN}`);
process.exit(failN ? 1 : 0);
