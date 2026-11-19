import { requireAuth, json, readBody, getAdmin, verifyPassword, hashPassword, createSession, sessionCookie } from '../_auth.js';
import { getSettings, saveSettings, addAudit } from '../_store.js';

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request);
  if (a.error) return a.error;
  return json({ settings: await getSettings(env) });
}

export async function onRequestPost({ request, env }) {
  const a = await requireAuth(env, request);
  if (a.error) return a.error;
  let body; try { body = await readBody(request); } catch (e) { return json({ error: e.message }, e.status || 400); }
  // 先验后存：以前是先保存设置、再验原密码，密码不对时设置已经落盘，
  // 出现"报错但其实改了"的半成功状态。改密校验全部通过后才统一落盘。
  let newAdmin = null;
  if (body.newPassword) {
    const admin = await getAdmin(env);
    if (!(await verifyPassword(String(body.oldPassword || ''), admin))) return json({ error: '原密码不对' }, 400);
    if (String(body.newPassword).length < 10) return json({ error: '新密码至少 10 位' }, 400);
    const { salt, hash } = await hashPassword(String(body.newPassword));
    // sv+1：所有旧会话立即失效；本会话在下方换发新令牌，无感续登
    newAdmin = { ...admin, salt, hash, sv: (admin.sv || 1) + 1 };
  }
  const prevSettings = await getSettings(env);
  const s = { ...prevSettings };
  if (typeof body.panelName === 'string' && body.panelName.trim()) s.panelName = body.panelName.trim().slice(0, 40);
  if (typeof body.publicSummary === 'boolean') s.publicSummary = body.publicSummary;
  await saveSettings(env, s);
  const headers = {};
  if (newAdmin) {
    try {
      await env.PANEL_KV.put('admin', JSON.stringify(newAdmin));
    } catch (e) {
      // 两步落盘的顺序保护：第二步（admin）失败时把第一步（settings）
      // 回滚到旧值再报错，避免「报错了但设置其实改了」的半成功状态
      try { await saveSettings(env, prevSettings); } catch { /* 回滚失败只能留日志 */ }
      return json({ error: '保存管理员信息失败，设置已回滚，请重试' }, 500);
    }
    const token = await createSession(env, newAdmin.user, newAdmin.sv);
    headers['Set-Cookie'] = sessionCookie(token);
    await addAudit(env, a.sess.user, 'settings.password', '修改管理员密码（全部会话已失效）');
  }
  await addAudit(env, a.sess.user, 'settings.update', '保存设置');
  return json({ ok: true, settings: s }, 200, headers);
}
