import { requireAuth, json, readBody } from '../_auth.js';
import { resolveAccount, cfApi, fail } from '../_manage.js';
import { addAudit } from '../_store.js';

// KV bulk export (all keys+values of a namespace as JSON) + bulk import.
// Needs Workers KV Storage Edit for import; export uses the same data APIs.
const MAX_KEYS = 1000; // import cap: enforced with an explicit 400 error below, not silent
// Export guard: values are read with the KV bulk-get endpoint (100 keys
// per subrequest). 4000 keys ≈ 40 bulk calls + a few list pages, which
// stays inside the free plan's 50-subrequest budget; the old per-key
// fetch died around key #44 and made export unusable for any real
// namespace. Excess is flagged via `truncated`, never silent.
const MAX_EXPORT_KEYS = 4000;

// ── 规整备份格式（v4.0.13） ──────────────────────────────────────────
// 导出文件是一个带信封的 JSON 对象，不再是裸条目数组：
//   { format, version, exportedAt, namespace, total, truncated,
//     entries: [{ name, value }, ...] }
// 回导（导入备份文件）前先校验 format 与 version：对不上、缺失一律
// 拒绝且一条都不写——拿错文件/新版文件往旧面板里灌时不会写一半才发现。
// 只动导出/回导这一头：KV 里数据的存法（键名、值、accounts 的加密
// 兼容层）一概不碰，导出的 value 就是 KV 里的原始值、原样写回。
export const KV_EXPORT_FORMAT = 'ym-cf-panel-kv-export';
export const KV_EXPORT_VERSION = 1;

// 校验一个备份信封：返回 null 表示合格，否则返回拒绝原因。
// 合格条件：format 完全一致、version 是当前支持的版本号（数字）。
function checkEnvelope(envObj) {
  if (!envObj || typeof envObj !== 'object' || Array.isArray(envObj)) return '备份文件格式不对：不是面板导出的备份文件';
  if (envObj.format !== KV_EXPORT_FORMAT) return '备份文件格式不对：不是面板导出的备份文件（format 对不上），已拒绝导入，未写入任何数据';
  if (envObj.version !== KV_EXPORT_VERSION) return `备份文件版本不对（文件是 ${envObj.version === undefined ? '缺失' : 'v' + String(envObj.version)}，本面板只支持 v${KV_EXPORT_VERSION}），已拒绝导入，未写入任何数据`;
  if (!Array.isArray(envObj.entries)) return '备份文件格式不对：缺少 entries 条目清单，已拒绝导入，未写入任何数据';
  return null;
}

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request); if (a.error) return a.error;
  try {
    const url = new URL(request.url);
    const acct = await resolveAccount(env, url.searchParams.get('account'));
    const ns = url.searchParams.get('ns');
    const base = `/accounts/${acct.accountId}/storage/kv/namespaces/${encodeURIComponent(ns)}`;
    const names = [];
    let cursor = '';
    let exportTruncated = false;
    while (true) {
      const d = await cfApi(acct, `${base}/keys?limit=1000${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
      for (const k of d.result || []) names.push(k.name);
      cursor = (d.result_info && d.result_info.cursor) || '';
      if (!cursor) break;
      if (names.length >= MAX_EXPORT_KEYS) { exportTruncated = true; break; }
    }
    if (exportTruncated) names.length = MAX_EXPORT_KEYS;
    const entries = [];
    let bytes = 0;
    // Bulk get: up to 100 keys per call. Same loud-failure contract as
    // before: any batch failure or a listed key missing from the result
    // aborts the whole export with a 502 — a failed read must NEVER be
    // exported as an empty value (restoring it would wipe the real one).
    for (let i = 0; i < names.length; i += 100) {
      const chunk = names.slice(i, i + 100);
      let d;
      try {
        d = await cfApi(acct, `${base}/bulk/get`, { method: 'POST', body: JSON.stringify({ keys: chunk }) });
      } catch (e) {
        return json({ error: `批量读取键值失败（${String(e.message || e).slice(0, 120)}），导出已终止：这份备份不完整，请勿使用` }, 502);
      }
      const map = d.result || {};
      for (const name of chunk) {
        const value = map[name];
        if (value === undefined || value === null) {
          return json({ error: `读取键「${name}」失败，导出已终止：这份备份不完整，请勿使用` }, 502);
        }
        const v = String(value);
        bytes += v.length;
        if (bytes > 4 * 1024 * 1024) return json({ error: '数据总量超过 4MB，请分批处理' }, 413);
        entries.push({ name, value: v });
      }
    }
    // 规整信封 + 旧字段（entries/total/truncated）保留：老调用方照常能读，
    // 新的前端下载的是整个信封对象、能直接回导。
    return json({
      format: KV_EXPORT_FORMAT,
      version: KV_EXPORT_VERSION,
      exportedAt: new Date().toISOString(),
      namespace: ns,
      entries, total: names.length, truncated: exportTruncated,
    });
  } catch (e) { return fail(e); }
}

export async function onRequestPost({ request, env }) {
  const a = await requireAuth(env, request); if (a.error) return a.error;
  try {
    const b = await readBody(request);
    // ── 先定条目来源并校验（任何校验失败都发生在写入之前，一条都不写）──
    // 1) b.backup 是对象 → 按「备份文件回导」处理：必须过信封校验。
    // 2) b 自带 format/version 字段（前端摊平的信封）→ 同样必须过校验。
    // 3) 只有 b.entries（无任何格式声明）→ 旧格式直通条目（v4.0.13 之前
    //    导出的裸数组文件经前端解析后走这条），保持旧行为可恢复，不因
    //    升级把站长手里的老备份变成废纸。
    let entries;
    if (b.backup !== undefined) {
      const bad = checkEnvelope(b.backup);
      if (bad) return json({ error: bad }, 400);
      entries = b.backup.entries;
    } else if (b.format !== undefined || b.version !== undefined) {
      const bad = checkEnvelope(b);
      if (bad) return json({ error: bad }, 400);
      entries = b.entries;
    } else {
      entries = Array.isArray(b.entries) ? b.entries : [];
    }
    if (!b.ns) return json({ error: '缺少命名空间' }, 400);
    if (!entries.length) return json({ error: '没有可导入的条目' }, 400);
    if (entries.length > MAX_KEYS) return json({ error: `一次最多导入 ${MAX_KEYS} 条` }, 400);
    const acct = await resolveAccount(env, b.account);
    // 条目规整：键名为空、值是对象/数组的条目算无效（计入失败数），
    // 不再像旧版那样静默丢弃或把对象写成 "[object Object]" 坏数据。
    const pairs = [];
    let invalid = 0;
    for (const e of entries) {
      if (!e || typeof e !== 'object') { invalid++; continue; }
      const key = String(e.name ?? e.key ?? '');
      const rawVal = e.value ?? '';
      if (!key || (typeof rawVal === 'object')) { invalid++; continue; }
      pairs.push({ key, value: String(rawVal) });
    }
    if (!pairs.length) return json({ error: `没有可导入的条目（${invalid} 条无效：键名为空或值不是文本）` }, 400);
    // ── 只写文件里包含的条目：全程只有 bulk PUT、没有任何删除动作，
    //    文件之外的键一律不碰（同名键按 KV 语义被新值覆盖）。──
    // 分批写：某批失败只把该批计入失败、其余批继续，最后如实报数，
    // 不再像旧版那样一批失败整单报错、已写好的也说不清写了多少。
    let succeeded = 0;
    let failed = invalid;
    let firstErr = '';
    for (let i = 0; i < pairs.length; i += 100) {
      const batch = pairs.slice(i, i + 100);
      try {
        await cfApi(acct, `/accounts/${acct.accountId}/storage/kv/namespaces/${encodeURIComponent(b.ns)}/bulk`, { method: 'PUT', body: JSON.stringify(batch) });
        succeeded += batch.length;
      } catch (e) {
        failed += batch.length;
        if (!firstErr) firstErr = String(e.message || e).slice(0, 120);
      }
    }
    await addAudit(env, a.sess.user, 'kv.import', `${acct.name} · 导入成功 ${succeeded} 条${failed ? `、失败 ${failed} 条` : ''}`);
    const counts = { written: succeeded, succeeded, failed, total: entries.length };
    if (failed === 0) return json({ ok: true, ...counts });
    const msg = `导入未全部成功：成功 ${succeeded} 条，失败 ${failed} 条${firstErr ? `（首个错误：${firstErr}）` : ''}`;
    // 至少写成一部分 → 200 带 ok:false 与计数，前端能把数字亮给站长看；
    // 一条都没写成 → 502，错误信息里同样带计数。
    if (succeeded > 0) return json({ ok: false, error: msg, ...counts });
    return json({ ok: false, error: msg, ...counts }, 502);
  } catch (e) { return fail(e); }
}
