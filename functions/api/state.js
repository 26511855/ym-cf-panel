import { getAdmin, getSession, json } from '../_auth.js';
import { getAccounts, getSettings, maskAccount } from '../_store.js';

export async function onRequestGet({ request, env }) {
  const admin = await getAdmin(env);
  const settings = await getSettings(env);
  if (!admin) return json({ needsSetup: true, authed: false, settings: { panelName: settings.panelName, publicSummary: settings.publicSummary } });
  const sess = await getSession(env, request);
  // 【C-5 修复】与全仓 requireAuth 口径一致地比对会话版本 sv：改密码会
  // 把 admin.sv +1，旧会话（含别的设备上的）必须立即失效。此前这里只
  // 看会话存不存在，改密后旧会话仍能从开机接口拿到全量账号列表。
  // 未登录/失效的返回形状保持不变（authed:false），前端开机流程无感。
  if (!sess || (sess.sv || 1) !== (admin.sv || 1)) return json({ needsSetup: false, authed: false, settings: { panelName: settings.panelName, publicSummary: settings.publicSummary } });
  const accounts = await getAccounts(env);
  return json({ needsSetup: false, authed: true, user: sess.user, settings, accounts: accounts.map(maskAccount) });
}
