import { requireAuth, json, readBody } from '../_auth.js';
import { resolveAccount, cfApi, fail } from '../_manage.js';
import { addAudit } from '../_store.js';

// Cloudflare Registrar: registered domains, auto-renew and lock toggles.
// No purchases here — registering/transferring costs money and always goes
// through the official checkout with the owner's confirmation.
const A = (acct) => `/accounts/${acct.accountId}/registrar/domains`;

// ---- Registrar list fetching (NOT the shared cfApiAll, on purpose) --------
// This endpoint's paging metadata is unreliable and it hard-errors with
// "Page bigger than the number of pages" when asked for a page past the
// end, instead of returning an empty page:
//   - an account with no registrar domains reports total_pages 0, which
//     can make even page=1 trip the error;
//   - the first page may carry no result_info at all;
//   - result_info can claim a next page that the endpoint then refuses.
// The shared cfApiAll trusts that metadata and surfaces the raw error, so
// the whole 注册商域名 section died with an English API complaint
// (2026-11-18 button-walk finding). This fetcher instead: clamps the walk
// to the totals the first response itself reports, treats the overflow
// error on a later page as end-of-list (keeping the pages already
// fetched), and retries page 1 without paging params before giving up —
// an overflow there means the list is empty.
export function isPageOverflowError(e) {
  return /page bigger than the number of pages/i.test(String((e && e.message) || e));
}

const REG_PER_PAGE = 100;
const REG_MAX_PAGES = 50; // same anti-runaway guard as cfApiAll

export async function fetchRegistrarDomains(acct) {
  const getPage = (page) => cfApi(acct, `${A(acct)}?per_page=${REG_PER_PAGE}&page=${page}`);
  let first;
  try {
    first = await getPage(1);
  } catch (e) {
    if (!isPageOverflowError(e)) throw e;
    try { first = await cfApi(acct, A(acct)); }
    catch (e2) {
      if (!isPageOverflowError(e2)) throw e2;
      return { result: [], result_info: { total_count: 0, truncated: false } };
    }
  }
  const rows = Array.isArray(first.result) ? [...first.result] : [];
  const info = first.result_info || {};
  const total = typeof info.total_count === 'number' ? info.total_count : null;
  // Clamp: never knowingly ask past the page range the first response
  // reported. With no metadata at all, walk on but stop at the first
  // short page (or at the overflow error, handled below).
  let walkCap = REG_MAX_PAGES;
  if (typeof info.total_pages === 'number' && info.total_pages > 0) walkCap = Math.min(info.total_pages, REG_MAX_PAGES);
  else if (total !== null) walkCap = Math.min(Math.max(1, Math.ceil(total / REG_PER_PAGE)), REG_MAX_PAGES);
  let hitOverflow = false;
  for (let page = 2; page <= walkCap; page++) {
    if (total !== null && rows.length >= total) break;
    let d;
    try { d = await getPage(page); }
    catch (e) {
      if (!isPageOverflowError(e)) throw e;
      hitOverflow = true; break; // fall back to the pages already fetched
    }
    const part = Array.isArray(d.result) ? d.result : [];
    if (!part.length) break;
    rows.push(...part);
    if (typeof info.total_pages !== 'number' && total === null && part.length < REG_PER_PAGE) break;
  }
  return {
    result: rows,
    result_info: {
      total_count: total !== null ? total : rows.length,
      truncated: hitOverflow || (total !== null && rows.length < total),
    },
  };
}

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request); if (a.error) return a.error;
  try {
    const url = new URL(request.url);
    const acct = await resolveAccount(env, url.searchParams.get('account'));
    const d = await fetchRegistrarDomains(acct);
    return json({
      total: d.result_info ? d.result_info.total_count : (d.result || []).length, truncated: !!(d.result_info && d.result_info.truncated),
      domains: (d.result || []).map((x) => ({
        name: x.name || x.id, expires: x.expires_at, autoRenew: x.auto_renew, locked: x.locked,
        privacy: x.privacy_redaction && x.privacy_redaction.enabled,
      })),
    });
  } catch (e) { return fail(e); }
}

export async function onRequestPost({ request, env }) {
  const a = await requireAuth(env, request); if (a.error) return a.error;
  try {
    const b = await readBody(request);
    const acct = await resolveAccount(env, b.account);
    const patch = {};
    if (typeof b.autoRenew === 'boolean') patch.auto_renew = b.autoRenew;
    if (typeof b.locked === 'boolean') patch.locked = b.locked;
    if (!Object.keys(patch).length) return json({ error: '没有要改的项' }, 400);
    await cfApi(acct, `${A(acct)}/${encodeURIComponent(b.domain)}`, { method: 'PUT', body: JSON.stringify(patch) });
    await addAudit(env, a.sess.user, 'registrar.update', `${acct.name} · ${b.domain} ${JSON.stringify(patch)}`);
    return json({ ok: true });
  } catch (e) { return fail(e); }
}
