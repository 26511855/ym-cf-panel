import { cookieOf, clearCookie, json, sha256hex } from '../_auth.js';

export async function onRequestPost({ request, env }) {
  const token = cookieOf(request);
  if (token) await env.PANEL_KV.delete('sess:' + (await sha256hex(token)));
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}
