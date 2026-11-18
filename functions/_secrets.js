// _secrets.js — KV 落盘加密兼容层（M26，2026-11-18 Peter 拍板）
//
// 面板代持的凭证（accounts 里的 CF 令牌、r2s3:* 的 S3 密钥）原来明文存
// KV：任何 KV 读面（同命名空间的其他 Worker、后台、导出）都能直接拿走。
// 现加一层 AES-GCM 信封加密：
//   格式：enc:v1:<base64(iv)>:<base64(密文)>（iv 每写随机 12 字节）
//   钥匙（KEK）：环境变量 secret DATA_KEK，值为 base64 的 32 字节。
//     代码里不出现钥匙的值；钥匙只存在于 Pages 项目的环境变量里。
// 兼容与上线顺序（红线：任何时刻行为不比明文时代差、绝不弄坏现有数据）：
//   - 读：带 enc:v1: 前缀才解密；其余一律按明文原样返回（存量数据零迁移可读）。
//   - 写：环境里配了 DATA_KEK 才加密写；没配就照旧明文写。代码先上线、
//     钥匙后配，配上之后老明文在下一次正常保存时顺带升级为密文（懒升级，
//     不写批量迁移脚本、不碰线上数据）。
//   - 解密失败（没配钥匙却读到密文、钥匙不对、数据损坏）一律显式抛错，
//     绝不把密文当数据返回、更不许把坏数据覆盖回去。

const PREFIX = 'enc:v1:';

function b64encode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// 返回 { key } 或 { none: true }（没配钥匙）；配了但格式不对 → 抛错，
// 不许悄悄降级成明文写（那会让站长以为加密了、其实没有）。
async function loadKek(env) {
  const raw = env && env.DATA_KEK ? String(env.DATA_KEK).trim() : '';
  if (!raw) return { none: true };
  let bytes;
  try { bytes = b64decode(raw); } catch {
    throw new Error('DATA_KEK 不是合法的 base64：请按 README「出事了怎么办」第 9 条处理');
  }
  if (bytes.length !== 32) {
    throw new Error(`DATA_KEK 长度不对（解码后 ${bytes.length} 字节，应为 32 字节）：请按 README「出事了怎么办」第 9 条处理`);
  }
  const key = await crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return { key };
}

export function isSealed(stored) {
  return typeof stored === 'string' && stored.startsWith(PREFIX);
}

// 写路径：配了钥匙 → 密文；没配 → 原样明文（与旧行为一致）。
export async function sealValue(env, plaintext) {
  const { key, none } = await loadKek(env);
  if (none) return plaintext;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return PREFIX + b64encode(iv) + ':' + b64encode(new Uint8Array(ct));
}

// 读路径：明文原样返回；密文必须解开，解不开显式抛错。
export async function openValue(env, stored) {
  if (!isSealed(stored)) return stored;
  const { key, none } = await loadKek(env);
  if (none) {
    throw new Error('KV 里的数据是加密存的，但环境变量 DATA_KEK 没配：请按 README「出事了怎么办」第 9 条配置钥匙后重试（数据没动过）');
  }
  const parts = stored.slice(PREFIX.length).split(':');
  if (parts.length !== 2) throw new Error('加密数据格式损坏（enc:v1 段数不对）：数据没动过，请按 README「出事了怎么办」第 9 条处理');
  let plain;
  try {
    const iv = b64decode(parts[0]);
    const ct = b64decode(parts[1]);
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  } catch {
    throw new Error('解密失败：DATA_KEK 与数据不匹配或数据已损坏。数据没动过；请确认钥匙是否配对，或按 README「出事了怎么办」第 9 条处理');
  }
  return new TextDecoder().decode(plain);
}
