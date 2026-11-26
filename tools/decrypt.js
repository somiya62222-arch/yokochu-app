// 公開中の index.html から data.json と salt.txt を取り出す
// node tools/decrypt.js <index.html> <パスワード> <出力フォルダ>
const fs = require('fs'), path = require('path');
const [, , file, pw, out] = process.argv;
(async () => {
  const s = fs.readFileSync(file, 'utf8');
  const raw = Buffer.from(JSON.parse(s.match(/const ENC=("[^"]+")/)[1]), 'base64');
  const salt = raw.subarray(0, 16), iv = raw.subarray(16, 28), ct = raw.subarray(28);
  const { subtle } = globalThis.crypto;
  const base = await subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const data = JSON.parse(new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)));
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'data.json'), JSON.stringify(data, null, 1));
  fs.writeFileSync(path.join(out, 'salt.txt'), Buffer.from(salt).toString('base64'));
  console.log('ok', Object.keys(data).map(k => `${k}:${Array.isArray(data[k]) ? data[k].length : 'obj'}`).join(' '));
})();
