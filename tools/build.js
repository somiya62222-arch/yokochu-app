// 横浜中央教会アプリ ビルド
// node tools/build.js <作業フォルダ> <パスワード>
// 入力: data.json, index.tpl.html, salt.txt(任意), pages/<id>/*.jpg
// 出力: out/index.html, out/files/<id>.json（pages/ にある号だけ作り直す）
// パスワードを変えるときは salt.txt を消してから、全号の画像を pages/ に置いて実行する
const fs = require('fs'), path = require('path');
const dir = process.argv[2], pw = process.argv[3];
if (!dir || !pw) { console.error('usage: node build.js <dir> <password>'); process.exit(1); }
const P = f => path.join(dir, f);
(async () => {
  const { subtle } = globalThis.crypto;
  const data = JSON.parse(fs.readFileSync(P('data.json'), 'utf8'));
  let salt;
  if (fs.existsSync(P('salt.txt'))) salt = Buffer.from(fs.readFileSync(P('salt.txt'), 'utf8').trim(), 'base64');
  else { salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16))); fs.writeFileSync(P('salt.txt'), salt.toString('base64')); }
  const base = await subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const enc = async bytes => { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes)); return { iv: Buffer.from(iv), ct: Buffer.from(ct) }; };
  fs.mkdirSync(P('out/files'), { recursive: true });
  const pdir = P('pages'); const built = [];
  if (fs.existsSync(pdir)) for (const id of fs.readdirSync(pdir)) {
    const imgs = fs.readdirSync(path.join(pdir, id)).filter(f => /\.jpe?g$/i.test(f)).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    if (!imgs.length) continue;
    const arr = imgs.map(f => fs.readFileSync(path.join(pdir, id, f)).toString('base64'));
    const r = await enc(new TextEncoder().encode(JSON.stringify(arr)));
    fs.writeFileSync(P(`out/files/${id}.json`), JSON.stringify({ iv: r.iv.toString('base64'), ct: r.ct.toString('base64') }));
    built.push(`${id}(${imgs.length})`);
  }
  const r = await enc(new TextEncoder().encode(JSON.stringify(data)));
  const all = Buffer.concat([salt, r.iv, r.ct]).toString('base64');
  const t = fs.readFileSync(P('index.tpl.html'), 'utf8');
  if (!t.includes('"__ENC__"')) throw new Error('template marker missing');
  fs.writeFileSync(P('out/index.html'), t.replace('"__ENC__"', JSON.stringify(all)));
  console.log('built index', all.length, 'files:', built.join(' ') || 'none');
})();
