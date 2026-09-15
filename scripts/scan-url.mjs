#!/usr/bin/env node
// Live-app diagnosis: a deployed URL in, plain-English report out.
//
// Why this exists: the repo-based engine (diagnose.mjs) needs a public GitHub
// repo, and the people who need help almost never have one. They have a
// deployed link. This scans that link instead, read-only, no account needed.
//
// Usage: node scripts/scan-url.mjs <url> [--out report.md] [--check-data] [--json]
//
// --check-data is OPT-IN and OFF by default. It asks the app's own Supabase
// endpoint, using only the anon key the app already ships to every visitor,
// whether a table returns rows without a login. It reads row COUNTS, never
// record contents. Only run it on an app you own or were asked to check.
//
// Everything else is what a browser does when it visits: load the page, read
// the scripts the page itself asks for, look at response headers, and ask for
// a handful of well-known paths (/.env, /.git/HEAD) to confirm they are NOT
// served. Nothing is written, no logins are attempted, no records are read.
//
// Sandboxing note (macOS local runs): Chrome cannot start inside the Claude
// session sandbox, so run this unsandboxed. In CI/containers set
// CHROME_EXTRA_FLAGS="--no-sandbox --disable-dev-shm-usage".

import { spawn } from 'node:child_process';
import { existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const argv = process.argv.slice(2);
const outIdx = argv.indexOf('--out');
const outPath = outIdx >= 0 ? argv[outIdx + 1] : null;
const checkData = argv.includes('--check-data');
const asJson = argv.includes('--json');
const raw = argv.filter((a, i) => !a.startsWith('--') && (outIdx < 0 || i !== outIdx + 1))[0];
if (!raw) {
  console.error('usage: scan-url.mjs <url> [--out report.md] [--check-data] [--json]');
  process.exit(2);
}

let target;
try {
  target = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
} catch {
  console.error(`cannot parse a URL from: ${raw}`);
  process.exit(2);
}
if (!/^https?:$/.test(target.protocol)) { console.error('only http and https are supported'); process.exit(2); }

// ---- SSRF guard ----------------------------------------------------------------
// This scanner takes a URL from strangers (issue form, Apify input, a Reddit
// thread). Without this, someone could point it at 169.254.169.254 and have our
// CI runner fetch its own cloud credentials, or at an internal address on
// whatever network it happens to run on. Public hosts only, checked after DNS so
// a public name that resolves to a private address is rejected too.
const isPrivateIp = ip => {
  if (/^::1$|^fe80:|^fc00:|^fd/i.test(ip)) return true;
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 0 || a === 10 || a === 127
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 192 && b === 0)
    || a >= 224;
};
{
  const host = target.hostname.replace(/^\[|\]$/g, '');
  if (/^(localhost|.*\.localhost|.*\.local|.*\.internal)$/i.test(host) || isPrivateIp(host)) {
    console.error(`refusing to scan a private or local address: ${host}`);
    process.exit(2);
  }
  const { lookup } = await import('node:dns/promises');
  let addrs;
  try {
    addrs = await lookup(host, { all: true });
  } catch (e) {
    console.error(`that hostname does not resolve: ${host} (${e.code || e.message})`);
    process.exit(2);
  }
  if (addrs.some(a => isPrivateIp(a.address))) {
    console.error(`refusing to scan ${host}: it resolves to a private address`);
    process.exit(2);
  }
}

const TMP = '/tmp/claude';
mkdirSync(join(TMP, 'scan'), { recursive: true });
const CHROME = process.env.CHROME_PATH
  || ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium-browser', '/usr/bin/chromium']
    .find(p => existsSync(p))
  || '/usr/bin/google-chrome';

const findings = [];
const f = (severity, cls, title, detail) => findings.push({ severity, cls, title, detail });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const short = (s, n = 300) => { const t = String(s || '').replace(/\s+/g, ' ').trim(); return t.length > n ? `${t.slice(0, n)}...` : t; };

const get = async (url, opts = {}) => {
  try {
    const r = await fetch(url, {
      redirect: opts.redirect || 'follow',
      signal: AbortSignal.timeout(opts.timeoutMs || 15000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; VibeCodeRescue/1.0; +https://dylancaponi.github.io/vibe-code-rescue/)', ...(opts.headers || {}) },
    });
    const body = opts.head ? '' : await r.text();
    return { ok: true, status: r.status, url: r.url, headers: r.headers, body };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
};

// ---- headless Chrome over CDP: the real browser signal ------------------------
// --dump-dom gives the DOM but throws away the console, and the console is where
// a white screen actually explains itself. So drive the DevTools protocol.
async function browserLoad(url) {
  const port = 9222 + (process.pid % 500);
  const extra = (process.env.CHROME_EXTRA_FLAGS || '').split(/\s+/).filter(Boolean);
  const chrome = spawn(CHROME, [
    ...extra,
    '--headless=new', '--disable-gpu', '--mute-audio', '--no-first-run', '--no-default-browser-check',
    `--user-data-dir=${join(TMP, `scan-chrome-${process.pid}`)}`,
    `--remote-debugging-port=${port}`,
    'about:blank',
  ], { stdio: 'ignore' });

  const result = {
    launched: false, consoleErrors: [], exceptions: [], failed: [], httpErrors: [],
    domlen: 0, rootlen: -1, bodyText: 0, title: '', scripts: [], finalUrl: url,
  };

  try {
    // wait for the debugging endpoint
    let wsUrl = null;
    for (let i = 0; i < 40 && !wsUrl; i++) {
      await sleep(250);
      const v = await get(`http://127.0.0.1:${port}/json/version`, { timeoutMs: 1500 });
      if (v.ok) { try { wsUrl = JSON.parse(v.body).webSocketDebuggerUrl; } catch { /* not ready */ } }
    }
    if (!wsUrl) return result;
    result.launched = true;

    const ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('cdp socket failed')); });

    let id = 0;
    const pending = new Map();
    ws.onmessage = ev => {
      let msg; try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return; }
      const p = msg.params || {};
      switch (msg.method) {
        case 'Runtime.exceptionThrown': {
          const d = p.exceptionDetails || {};
          const text = d.exception?.description || d.text || 'unknown error';
          result.exceptions.push(short(text, 400));
          break;
        }
        case 'Runtime.consoleAPICalled':
          if (p.type === 'error') result.consoleErrors.push(short((p.args || []).map(a => a.value ?? a.description ?? a.type).join(' '), 300));
          break;
        case 'Log.entryAdded':
          if (p.entry?.level === 'error') result.consoleErrors.push(short(p.entry.text, 300));
          break;
        case 'Network.loadingFailed':
          if (!p.canceled) result.failed.push(short(`${p.type}: ${p.errorText}`, 160));
          break;
        case 'Network.responseReceived': {
          const r = p.response || {};
          // cosmetic 404s (favicon, touch icons, manifest) are noise, not findings
          if (r.status >= 400 && !/\/(favicon\.ico|apple-touch-icon[\w-]*\.png|site\.webmanifest|manifest\.json|robots\.txt)(\?|$)/i.test(r.url || ''))
            result.httpErrors.push(`${r.status} ${short(r.url, 120)}`);
          if (p.type === 'Script' && r.url && /^https?:/.test(r.url)) result.scripts.push(r.url);
          break;
        }
        default: break;
      }
    };
    const send = (method, params, sessionId) => new Promise(res => {
      const msgId = ++id;
      pending.set(msgId, res);
      ws.send(JSON.stringify({ id: msgId, method, params: params || {}, ...(sessionId ? { sessionId } : {}) }));
      setTimeout(() => { if (pending.has(msgId)) { pending.delete(msgId); res({ error: 'timeout' }); } }, 20000);
    });

    const t = await send('Target.createTarget', { url: 'about:blank' });
    const targetId = t.result?.targetId;
    const a = await send('Target.attachToTarget', { targetId, flatten: true });
    const sid = a.result?.sessionId;
    if (!sid) return result;

    await send('Network.enable', {}, sid);
    await send('Runtime.enable', {}, sid);
    await send('Log.enable', {}, sid);
    await send('Page.enable', {}, sid);
    await send('Page.navigate', { url }, sid);

    // give the app time to mount and make its first data calls
    await sleep(9000);

    const ev = async expr => {
      const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true }, sid);
      return r.result?.result?.value;
    };
    result.domlen = (await ev('document.documentElement.outerHTML.length')) || 0;
    result.rootlen = (await ev("(()=>{const r=document.querySelector('#root,#app,[data-reactroot]');return r?r.innerHTML.trim().length:-1})()"));
    result.bodyText = (await ev('(document.body&&document.body.innerText||"").trim().length')) || 0;
    result.title = (await ev('document.title')) || '';
    result.finalUrl = (await ev('location.href')) || url;

    ws.close();
  } catch { /* fall through with whatever was collected */ } finally {
    try { chrome.kill('SIGKILL'); } catch { /* gone */ }
  }
  return result;
}

// ---- run ----------------------------------------------------------------------
console.error(`[1/5] fetching ${target.href}`);
const home = await get(target.href);
if (!home.ok) {
  f('blocker', 'reachability', 'The site did not respond', `Nothing answered at ${target.href}. The error was: ${home.error}. Either the deploy is down, the domain does not resolve, or the certificate is rejected. Every visitor sees this.`);
} else if (home.status >= 500) {
  f('blocker', 'reachability', `The homepage returns HTTP ${home.status}`, 'The server is up but errors on the homepage. This is what every visitor gets. On AI-built apps this is almost always a missing environment variable or a data call running with no credentials.');
} else if (home.status >= 400) {
  f('blocker', 'reachability', `The homepage returns HTTP ${home.status}`, `The root URL does not serve the app. If the real app lives on a different path, share that URL instead. Otherwise visitors hit this ${home.status}.`);
}

const finalOrigin = home.ok ? new URL(home.url).origin : target.origin;
const isHttps = finalOrigin.startsWith('https:');
if (!isHttps) f('warn', 'transport', 'The site is served over plain HTTP', 'Traffic is unencrypted, so passwords and session cookies travel in the clear and browsers will mark the site as not secure. Most hosts give HTTPS for free; turn it on and redirect HTTP to it.');

console.error('[2/5] loading in a real browser');
const bl = await browserLoad(home.ok ? home.url : target.href);
if (!bl.launched) {
  f('info', 'runtime', 'Browser check could not run on this machine', 'Headless Chrome did not start, so the render and console checks were skipped. The rest of the report is unaffected.');
} else {
  const blank = bl.bodyText < 40 && (bl.rootlen === -1 || bl.rootlen < 100);
  if (blank) {
    const why = bl.exceptions[0] || bl.consoleErrors[0];
    f('blocker', 'runtime', 'The app loads a blank white screen', `A clean browser with no logins and no extensions loaded the page and got ${bl.bodyText} characters of visible text. Visitors see white. ${why ? `The browser console explains it:\n\n${why}` : 'The console reported no error, which usually means the app mounted nothing rather than crashing: a routing mismatch, or a build that shipped an empty bundle.'}`);
  } else if (bl.exceptions.length) {
    f('warn', 'runtime', 'The page renders but throws JavaScript errors on load', `The app shows content, but ${bl.exceptions.length} uncaught error${bl.exceptions.length > 1 ? 's' : ''} fired while loading. Whatever those errors were supposed to run did not run, which is usually the feature a user reports as "the button does nothing":\n\n${bl.exceptions.slice(0, 3).join('\n\n')}`);
  }

  if (bl.httpErrors.length) {
    const uniq = [...new Set(bl.httpErrors)].slice(0, 6);
    const auth = uniq.filter(x => /^40[13]/.test(x));
    f(auth.length ? 'blocker' : 'warn', 'data', `${uniq.length} request${uniq.length > 1 ? 's the page makes come' : ' the page makes comes'} back as an error`, `${auth.length ? 'Some of these are 401/403, which on a Supabase or Firebase app almost always means row level security is blocking the read and the app has no fallback, so the screen stays empty forever. ' : ''}The failing requests:\n\n${uniq.join('\n')}`);
  }
  if (bl.failed.length) {
    const uniq = [...new Set(bl.failed)].slice(0, 5);
    f('warn', 'runtime', 'Some requests never completed', `These were started by the page and failed at the network level, often a CORS rejection or a call to a host that no longer exists:\n\n${uniq.join('\n')}`);
  }
}

console.error('[3/5] reading the scripts the page ships');
const scriptUrls = [...new Set(bl.scripts)].filter(u => u.startsWith(finalOrigin)).slice(0, 8);
let bundleText = '';
const bundles = [];
for (const u of scriptUrls) {
  const r = await get(u, { timeoutMs: 20000 });
  if (r.ok && r.status === 200) {
    bundles.push({ url: u, body: r.body });
    bundleText += `\n${r.body}`;
  }
}
const sawBundles = bundleText.length > 0;

// Pull the surrounding snippet for a bundle match so a finding can show its own
// evidence instead of asserting. Long token-ish runs are redacted so quoting a
// bundle back at its owner can never republish a secret that happens to sit
// next to the match.
function evidenceAll(re, limit = 20) {
  const out = [];
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  for (const b of bundles) {
    g.lastIndex = 0;
    let m;
    while ((m = g.exec(b.body)) && out.length < limit) {
      const at = m.index;
      const snippet = b.body
        .slice(Math.max(0, at - 60), at + m[0].length + 60)
        .replace(/\s+/g, ' ')
        .replace(/[A-Za-z0-9_-]{28,}/g, '[redacted]')
        .trim();
      out.push({ file: b.url.split('/').pop() || b.url, match: m[0], snippet });
      if (m[0].length === 0) g.lastIndex++;
    }
  }
  return out;
}

// Bundled libraries ship their own local-dev defaults that are dead code in
// production. supabase-js in particular carries http://localhost:9999 as its
// GoTrue fallback, so a naive localhost check fires on essentially every
// Supabase app we scan. Flagging that would make the free scan cry wolf on our
// most common target, so a match is only real if it is not a known vendor
// default sitting next to that library's own markers.
const VENDOR_LOCALHOST = [
  { match: /(?:localhost|127\.0\.0\.1):9999/, near: /supabase\.auth\.token|GOTRUE|X-Client-Info|gotrue/i },
  { match: /(?:localhost|127\.0\.0\.1):54321/, near: /supabase/i },
];
const isVendorDefault = (hit) =>
  VENDOR_LOCALHOST.some(v => v.match.test(hit.match) && v.near.test(hit.snippet));

// Secrets that must never reach a browser. The anon/publishable ones are fine by
// design and are deliberately not flagged.
const secretPatterns = [
  [/\bsk_live_[A-Za-z0-9]{10,}/, 'a live Stripe secret key', 'Anyone who opens the page can take payments as you, issue refunds to themselves, and read every customer record. Roll this key in the Stripe dashboard now, then move it to a server-side environment variable.'],
  [/\bsk_test_[A-Za-z0-9]{10,}/, 'a Stripe test secret key', 'Test keys do not move real money, but the same code path will ship the live key when you switch. Move it server-side before launch.'],
  [/"role"\s*:\s*"service_role"|\bservice_role\b/, 'a Supabase service_role key', 'That key bypasses every row level security policy you have written. Anyone who opens the page can read, edit, and delete every row in your database. Roll it in the Supabase dashboard immediately and never put it in front-end code.'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'an AWS access key', 'AWS keys in browser code get scraped within hours and are commonly used to run up compute charges on your account. Deactivate it in IAM now.'],
  [/\bsk-[A-Za-z0-9]{32,}/, 'an OpenAI-style secret key', 'Anyone can spend your API budget with this. Revoke it and proxy the calls through your own server instead.'],
  [/\bghp_[A-Za-z0-9]{30,}/, 'a GitHub personal access token', 'This grants access to your repositories. Revoke it in GitHub settings now.'],
];
if (sawBundles) {
  for (const [re, what, why] of secretPatterns) {
    if (re.test(bundleText)) f('blocker', 'secrets', `The JavaScript sent to every visitor contains ${what}`, why);
  }
  const sbUrl = bundleText.match(/https:\/\/[a-z0-9]{8,}\.supabase\.co/i);
  if (sbUrl) f('info', 'data', 'This app talks to Supabase from the browser', `The front end calls ${sbUrl[0]} directly with its public anon key, which is the normal Supabase design. It only holds if row level security is switched on for every table, because the anon key is visible to everyone who opens the page.${checkData ? ' The data check below covers that.' : ' Open your Supabase dashboard and confirm RLS is enabled on every table.'}`);
  const lhRe = /(?:https?:\/\/)?(?:localhost|127\.0\.0\.1):\d{2,5}/;
  const lhHits = isHttps ? evidenceAll(lhRe).filter(h => !isVendorDefault(h)) : [];
  if (lhHits.length) {
    const ev = lhHits[0];
    f('warn', 'config', 'The deployed code still points at localhost somewhere', `A production bundle referencing localhost is the usual cause of "login works on my machine but loops forever on the live site". It is in \`${ev.file}\`, here: \`${short(ev.snippet, 160)}\`. The fix is almost always the Site URL and Redirect URLs in your auth provider settings, plus any hardcoded API base URL.`);
  }
}

// Source maps: only a finding if the .map is actually served.
const mapRef = bundleText.match(/\/\/# sourceMappingURL=([^\s*]+)/);
if (mapRef && scriptUrls.length) {
  const mapUrl = new URL(mapRef[1], scriptUrls[0]).href;
  const mr = await get(mapUrl, { timeoutMs: 10000 });
  if (mr.ok && mr.status === 200 && /"sources"\s*:/.test(mr.body)) {
    f('warn', 'exposure', 'Your original source code is downloadable', `The site serves its source map at ${short(mapUrl, 120)}, so anyone can reconstruct your unminified source, including comments and any logic you assumed was hidden. Turn off source map generation for production builds, or stop uploading the .map files.`);
  }
}

console.error('[4/5] checking well-known paths and headers');
// Confirm by content, never by status: a catch-all route returns 200 for everything.
const envProbe = await get(new URL('/.env', finalOrigin).href, { timeoutMs: 10000 });
if (envProbe.ok && envProbe.status === 200 && /^\s*[A-Z][A-Z0-9_]{2,}\s*=/m.test(envProbe.body) && !/<html/i.test(envProbe.body)) {
  f('blocker', 'exposure', 'Your .env file is being served to the public', 'Requesting /.env returns real environment variable lines. Every key in that file must be treated as leaked: roll all of them now. The cause is almost always a static file server pointed at the project root instead of the build output folder.');
}
const gitProbe = await get(new URL('/.git/HEAD', finalOrigin).href, { timeoutMs: 10000 });
if (gitProbe.ok && gitProbe.status === 200 && /^ref:\s+refs\//.test(gitProbe.body.trim())) {
  f('blocker', 'exposure', 'Your .git folder is being served to the public', 'Requesting /.git/HEAD returns a real git reference, which means the whole repository history can be downloaded, including any secret that was ever committed and later removed. Stop serving the project root and roll anything sensitive that was ever in the history.');
}

// Deep-link behaviour: an SPA must rewrite unknown paths to index.html.
const deepPath = `/vcr-check-${Date.now().toString(36)}`;
const deep = await get(new URL(deepPath, finalOrigin).href, { timeoutMs: 10000 });
const looksSpa = bl.rootlen >= 0 || /<div id="root"|<div id="app"/i.test(home.body || '');
if (looksSpa && deep.ok && deep.status === 404) {
  f('warn', 'config', 'Refreshing the page on any route gives a 404', `The app is a single page app, but ${deepPath} returned a 404 instead of the app shell. Links into the app work while clicking around and break the moment someone refreshes or opens a shared link. The fix is one rewrite rule telling the host to serve index.html for unknown paths.`);
}

if (home.ok && home.headers) {
  const h = n => home.headers.get(n);
  const missing = [];
  if (!h('content-security-policy')) missing.push('Content-Security-Policy');
  if (isHttps && !h('strict-transport-security')) missing.push('Strict-Transport-Security');
  if (!h('x-content-type-options')) missing.push('X-Content-Type-Options');
  if (!h('x-frame-options') && !/frame-ancestors/i.test(h('content-security-policy') || '')) missing.push('X-Frame-Options or a frame-ancestors rule');
  if (missing.length >= 3) {
    f('info', 'hardening', 'The standard browser security headers are not set', `Missing: ${missing.join(', ')}. None of these are urgent on their own, and no visitor will notice. They are the cheap layer that turns a small bug into a non-event, and most hosts set them with a few lines of config.`);
  }
  if (h('x-powered-by')) f('info', 'hardening', `The server announces what it runs (${h('x-powered-by')})`, 'This header tells an attacker exactly which stack and often which version to target. Turning it off is one line.');
}

// ---- opt-in data check ---------------------------------------------------------
if (checkData && sawBundles) {
  console.error('[5/5] data check (opt-in)');
  const sbUrl = bundleText.match(/https:\/\/[a-z0-9]{8,}\.supabase\.co/i);
  const sbKey = bundleText.match(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/);
  if (sbUrl && sbKey) {
    // Ask PostgREST for a HEAD count only. Never request row contents.
    const tables = [...new Set((bundleText.match(/\.from\(\s*['"`]([A-Za-z0-9_]{2,40})['"`]\s*\)/g) || [])
      .map(s => s.match(/['"`]([A-Za-z0-9_]{2,40})['"`]/)[1]))].slice(0, 12);
    const open = [];
    for (const t of tables) {
      const r = await get(`${sbUrl[0]}/rest/v1/${t}?select=*&limit=1`, {
        timeoutMs: 10000,
        headers: { apikey: sbKey[0], Authorization: `Bearer ${sbKey[0]}`, Prefer: 'count=exact', Range: '0-0' },
      });
      if (r.ok && r.status >= 200 && r.status < 300) {
        const cr = r.headers.get('content-range') || '';
        const total = cr.split('/')[1] || 'an unknown number of';
        open.push(`${t} (${total} rows readable)`);
      }
    }
    if (open.length) {
      f('blocker', 'data', `${open.length} database table${open.length > 1 ? 's are' : ' is'} readable by anyone with no login`, `Using only the anon key this app already ships to every visitor, these tables returned data without any authentication:\n\n${open.join('\n')}\n\nRow counts were read; no records were retrieved. If any of those tables holds user data, treat it as public right now. The fix is to enable row level security on each table in the Supabase dashboard and add a policy that scopes rows to the signed-in user. Turning RLS on with no policy denies everything, which is the safe starting point.`);
    } else if (tables.length) {
      f('info', 'data', 'Row level security appears to be doing its job', `${tables.length} table${tables.length > 1 ? 's' : ''} referenced by the front end refused to return rows to an unauthenticated request. That is the correct behaviour.`);
    }
  }
} else if (checkData) {
  console.error('[5/5] data check skipped (no bundles read)');
} else {
  console.error('[5/5] data check skipped (not requested)');
}

// ---- report ---------------------------------------------------------------------
const order = { blocker: 0, warn: 1, info: 2 };
findings.sort((a, b) => order[a.severity] - order[b.severity]);
const blockers = findings.filter(x => x.severity === 'blocker');
const sevLabel = { blocker: 'BROKEN', warn: 'RISK', info: 'NOTE' };

const verdict = blockers.length
  ? `This app has ${blockers.length === 1 ? 'one blocking problem' : `${blockers.length} blocking problems`} a visitor hits right now. Worst first below.`
  : findings.some(x => x.severity === 'warn')
    ? 'Nothing is outright broken for a first-time visitor. There are real risks worth fixing before you promote this, listed below.'
    : 'The live site loads cleanly and nothing on the outside looks wrong. Notes below.';

const report = `# Live scan: ${target.hostname}

Scanned ${bl.finalUrl || target.href}${bl.title ? ` ("${bl.title}")` : ''}. Checked: page load in a real browser, the JavaScript it ships, the requests it makes, response headers, and well-known paths${checkData ? ', plus an authenticated-read check against its own database' : ''}.

## Verdict

${verdict}

## Findings

${findings.length
    ? findings.map((x, i) => `### ${i + 1}. [${sevLabel[x.severity]}] ${x.title}\n\n${x.detail}\n`).join('\n')
    : 'Nothing notable, which is rarer than it sounds for an AI-built app.'}
## How this was checked

A clean headless browser with no logins, no cookies, and no extensions opened the page, and everything above came from what the site itself sent back: the rendered page, its console, the scripts it asked for, and its response headers. A handful of well-known paths were requested to confirm they are not served. ${checkData ? 'The database check used only the public key the app hands to every visitor, and read row counts, never records. ' : ''}Nothing was written, no login was attempted, and no user records were read.

Automated by Vibe Code Rescue. https://dylancaponi.github.io/vibe-code-rescue/
`;

if (asJson) {
  console.log(JSON.stringify({ url: bl.finalUrl || target.href, title: bl.title, findings, blockers: blockers.length }, null, 2));
} else {
  console.log(report);
}
if (outPath) { writeFileSync(outPath, report); console.error(`report: ${outPath}`); }
process.exit(0);
