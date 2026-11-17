// ym-cf-panel _store 并发测试（node tests/store-concurrency.mjs）
// 验 #13 安全子集：accounts 整份读改写的版本校验+冲突重试、audit 的写后复核+重试。
// KV 替身可注入「对手写」：在指定时机插入一次并发修改，模拟两个写操作交错。
import { getAccounts, mutateAccounts, addAudit, getAudit } from '../functions/_store.js';

class KV {
  constructor() { this.m = new Map(); this.rival = null; }
  async get(k) {
    const v = this.m.has(k) ? this.m.get(k) : null;
    if (this.rival && this.rival.key === k && this.rival.onGet) { const r = this.rival; this.rival = null; r.fn(this); }
    return v;
  }
  async put(k, v) {
    this.m.set(k, String(v));
    if (this.rival && this.rival.key === k && !this.rival.onGet) { const r = this.rival; this.rival = null; r.fn(this); }
  }
}

let pass = 0, failN = 0;
const chk = (name, cond, extra = '') => { if (cond) { pass++; console.log('PASS', name); } else { failN++; console.log('FAIL', name, extra); } };

// 1) 无并发：mutateAccounts 正常增删
{
  const kv = new KV();
  const env = { PANEL_KV: kv };
  let r = await mutateAccounts(env, (list) => ({ list: [...list, { id: 'a1', name: '甲' }] }));
  chk('mutate 无并发添加成功', r.ok === true);
  r = await mutateAccounts(env, (list) => ({ list: [...list, { id: 'a2', name: '乙' }] }));
  const list = await getAccounts(env);
  chk('mutate 两次添加都在', r.ok === true && list.length === 2 && list[1].id === 'a2');
  r = await mutateAccounts(env, () => ({ error: '业务错误', status: 409 }));
  chk('mutate 业务错误原样返回不重试', r.error === '业务错误' && r.status === 409);
}

// 2) 写前复核撞上对手写：应重试并把双方改动都保住
{
  const kv = new KV();
  const env = { PANEL_KV: kv };
  kv.m.set('accounts', JSON.stringify([{ id: 'base', name: '原有' }]));
  // 对手：在我方第一次「写前复核读」时插入它自己的账号（模拟并发添加已落库）
  let gets = 0;
  kv.rival = null;
  const origGet = kv.get.bind(kv);
  kv.get = async (k) => {
    const v = await origGet(k);
    if (k === 'accounts') {
      gets++;
      if (gets === 2) { // 第 2 次 get = 写前复核：此刻对手刚写完
        kv.m.set('accounts', JSON.stringify([{ id: 'base', name: '原有' }, { id: 'rival', name: '对手' }]));
        return kv.m.get('accounts');
      }
    }
    return v;
  };
  const r = await mutateAccounts(env, (list) => ({ list: [...list, { id: 'mine', name: '我方' }] }));
  const list = JSON.parse(kv.m.get('accounts'));
  const ids = list.map(x => x.id).sort().join(',');
  chk('mutate 撞版本后重试成功', r.ok === true, JSON.stringify(r));
  chk('mutate 双方改动都保住（base,mine,rival）', ids === 'base,mine,rival', ids);
}

// 3) addAudit 并发覆盖：对手在我方 put 后立刻写入它的条目 → 我方复核发现不一致、重试补上，两条都在且不重复
{
  const kv = new KV();
  const env = { PANEL_KV: kv };
  kv.rival = {
    key: 'audit', onGet: false,
    fn: (store) => {
      const cur = JSON.parse(store.m.get('audit') || '[]');
      cur.unshift({ at: Date.now(), user: 'rival', action: 'rival.act', detail: '', n: 'rivalnonce' });
      store.m.set('audit', JSON.stringify(cur));
    },
  };
  await addAudit(env, 'me', 'my.act', 'detail');
  const list = await getAudit(env);
  const mine = list.filter(e => e.action === 'my.act');
  const rival = list.filter(e => e.action === 'rival.act');
  chk('audit 对手条目保住', rival.length === 1, JSON.stringify(list.map(e => e.action)));
  chk('audit 我方条目补上且只一份', mine.length === 1, JSON.stringify(list.map(e => e.action)));
}

// 4) addAudit 无并发：一条落库
{
  const kv = new KV();
  const env = { PANEL_KV: kv };
  await addAudit(env, 'me', 'solo.act', 'x');
  const list = await getAudit(env);
  chk('audit 无并发正常落库', list.length === 1 && list[0].action === 'solo.act');
}

console.log(`\nTOTAL pass=${pass} fail=${failN}`);
process.exit(failN ? 1 : 0);
