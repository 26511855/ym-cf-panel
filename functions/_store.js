// KV-backed storage for panel accounts + settings.
// accounts 整份文档经 _secrets.js 兼容层落盘：配了 DATA_KEK 时是
// AES-GCM 密文（enc:v1:），没配时与旧版一样明文 JSON；读时自动分流，
// 存量明文零迁移可读、会在下次正常保存时顺带升级（M26）。
import { sealValue, openValue } from './_secrets.js';

export async function getAccounts(env) {
  const raw = await env.PANEL_KV.get('accounts');
  return raw ? JSON.parse(await openValue(env, raw)) : [];
}

export async function saveAccounts(env, list) {
  await env.PANEL_KV.put('accounts', await sealValue(env, JSON.stringify(list)));
}

// ── 整文档读改写的版本校验 + 冲突重试（2026-11-17 审计核验 #13） ──
// accounts 是一份 JSON 文档：旧流程「读 → 改 → 整份写回」在两个写操作
// 并发时后写者会把先写者的改动整份覆盖（丢更新）。KV 没有 CAS，做不到
// 真原子，这里用内容指纹做写前复核：读时记下指纹，写前重读比对，指纹
// 变了就重读、把修改重新应用到新内容上再写（最多 3 轮）；存储格式不变
// （仍是原来的 JSON 数组），无需迁移，老数据直接兼容。
function hashOf(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return (h >>> 0).toString(16) + ':' + str.length;
}

// fn(list) 返回 { list } 表示新列表，或 { error, status } 表示业务错误（不重试）。
// 成功返回 { ok: true, list }；重试耗尽返回 { error: 'conflict' }。
export async function mutateAccounts(env, fn, retries = 3) {
  for (let i = 0; i < retries; i++) {
    const raw = await env.PANEL_KV.get('accounts');
    const list = raw ? JSON.parse(await openValue(env, raw)) : [];
    const ver = hashOf(raw || ''); // 指纹仍按落盘原文算（明文/密文都适用）
    const r = fn(list);
    if (r && r.error) return r;
    const next = r && r.list ? r.list : list;
    const nowRaw = await env.PANEL_KV.get('accounts');
    if (hashOf(nowRaw || '') !== ver) continue; // 已被别人改过：重读重试
    await env.PANEL_KV.put('accounts', await sealValue(env, JSON.stringify(next)));
    return { ok: true, list: next };
  }
  return { error: 'conflict' };
}

export function maskAccount(a) {
  return {
    id: a.id, name: a.name, accountId: a.accountId,
    tokenMasked: a.token ? '••••••••' + a.token.slice(-4) : '',
    createdAt: a.createdAt || null,
  };
}

// Panel-local audit log of management actions (last 100). Never stores tokens
// or secret values — action name + a short human detail only.
export async function addAudit(env, user, action, detail) {
  try {
    // 同 #13：审计也是整份读改写，并发时后写会吞掉先写的条目。改为写后
    // 复核 + 重试：每条带随机 nonce，重试时先查 nonce 是否已在（防重复），
    // 复核不一致就重读、把本条重新补到最新列表头上（最多 3 轮）。
    const entry = { at: Date.now(), user: user || '', action, detail: String(detail || '').slice(0, 200), n: Math.random().toString(36).slice(2, 10) };
    for (let i = 0; i < 3; i++) {
      const raw = await env.PANEL_KV.get('audit');
      const list = raw ? JSON.parse(raw) : [];
      if (list.some((e) => e.n === entry.n)) return;
      list.unshift(entry);
      const intended = JSON.stringify(list.slice(0, 100));
      await env.PANEL_KV.put('audit', intended);
      const back = await env.PANEL_KV.get('audit');
      if (back === intended) return;
    }
  } catch { /* auditing must never break the action itself */ }
}

export async function getAudit(env) {
  const raw = await env.PANEL_KV.get('audit');
  return raw ? JSON.parse(raw) : [];
}

export async function getSettings(env) {
  const raw = await env.PANEL_KV.get('settings');
  const s = raw ? JSON.parse(raw) : {};
  return { panelName: 'YM CF 面板', publicSummary: false, ...s };
}

export async function saveSettings(env, s) {
  await env.PANEL_KV.put('settings', JSON.stringify(s));
}
