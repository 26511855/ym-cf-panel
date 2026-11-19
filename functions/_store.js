// KV-backed storage for panel accounts + settings.
// accounts 整份文档经 _secrets.js 兼容层落盘：配了 DATA_KEK 时是
// AES-GCM 密文（enc:v1:），没配时与旧版一样明文 JSON；读时自动分流，
// 存量明文零迁移可读、会在下次正常保存时顺带升级（M26）。
import { sealValue, openValue } from './_secrets.js';

export async function getAccounts(env) {
  const raw = await env.PANEL_KV.get('accounts');
  if (!raw) return [];
  try { return JSON.parse(await openValue(env, raw)); }
  catch (e) {
    // 解密失败（钥匙问题）必须原样上抛，不能降级成空列表把真数据盖掉；
    // 纯 JSON 损坏才降级为空列表并留日志，避免一处损坏拖垮全站读取。
    if (e && /DATA_KEK|解密|加密/.test(String(e.message || e))) throw e;
    console.error('accounts 文档 JSON 损坏，按空列表降级：', String(e.message || e));
    return [];
  }
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
  return sha256Sync(str) + ':' + str.length;
}
// 同步纯 JS SHA-256（FIPS 180-4）：hashOf 原是同步函数且调用方在写前复核
// 的热路径上，WebCrypto 只有异步接口、改异步会牵动整个 mutate 流程，故用
// 同步实现换掉 32 位 FNV-1a，消除指纹碰撞一说。输入按 UTF-8 编码；指纹只在
// 单次请求内做前后比对、不落盘，换算法无需迁移存量数据。
function sha256Sync(str) {
  const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const bytes = new TextEncoder().encode(str);
  const bitLen = bytes.length * 8;
  const total = (((bytes.length + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(total);
  buf.set(bytes); buf[bytes.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 4, bitLen >>> 0); dv.setUint32(total - 8, Math.floor(bitLen / 4294967296));
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = new Int32Array(64);
  const rotr = (x,n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h=g; g=f; f=e; e=(d + t1) | 0; d=c; c=b; b=a; a=(t1 + t2) | 0;
    }
    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
  }
  return [h0,h1,h2,h3,h4,h5,h6,h7].map((x) => (x >>> 0).toString(16).padStart(8, '0')).join('');
}


// fn(list) 返回 { list } 表示新列表，或 { error, status } 表示业务错误（不重试）。
// 成功返回 { ok: true, list }；重试耗尽返回 { error: 'conflict' }。
export async function mutateAccounts(env, fn, retries = 3) {
  for (let i = 0; i < retries; i++) {
    const raw = await env.PANEL_KV.get('accounts');
    let list;
    if (!raw) list = [];
    else {
      try { list = JSON.parse(await openValue(env, raw)); }
      catch { return { error: 'accounts 文档损坏或无法解密，已中止写入（原数据未动）', status: 500 }; }
    }
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
      let list = [];
      try { list = raw ? JSON.parse(raw) : []; } catch { list = []; } // 审计损坏不拖垮主操作：从空列表重建
      if (!Array.isArray(list)) list = [];
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
  if (!raw) return [];
  try { const v = JSON.parse(raw); return Array.isArray(v) ? v : []; } catch { return []; }
}

export async function getSettings(env) {
  const raw = await env.PANEL_KV.get('settings');
  let s = {};
  try { s = raw ? JSON.parse(raw) : {}; } catch { s = {}; } // 设置损坏回默认，不拖垮全站
  if (!s || typeof s !== 'object') s = {};
  return { panelName: 'YM CF 面板', publicSummary: false, ...s };
}

export async function saveSettings(env, s) {
  await env.PANEL_KV.put('settings', JSON.stringify(s));
}
