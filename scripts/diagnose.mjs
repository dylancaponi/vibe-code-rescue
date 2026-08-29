#!/usr/bin/env node
// One-shot vibe-code diagnosis: repo URL in, plain-English report out.
// Composes the rescue-sweep + runtime-check pipeline with static checks from
// playbooks/rescue-playbook.md failure classes. Untrusted-code protocol applies:
// --ignore-scripts always, package.json risk skim before install, clone in TMPDIR.
//
// Usage: node scripts/diagnose.mjs <github-url-or-owner/repo> [--out report.md] [--keep]
//        node scripts/diagnose.mjs <owner/repo> --runtime-only   (phase 2, see below)
// Exit 0 = report written (even if the app is broken; broken IS the product).
//
// Sandboxing note (macOS local runs): install/build MUST run inside the session
// sandbox (untrusted code). Headless Chrome cannot start in that sandbox
// (ProcessSingleton/mach denials), so the render check degrades gracefully.
// To complete it, run phase 1 with --keep, then a SEPARATE unsandboxed call:
//   node scripts/diagnose.mjs <owner/repo> --runtime-only
// which only serves the already-built dist/ to Chrome (repo code executes solely
// inside Chrome's own sandbox) and appends the finding to the report.

import { execFileSync, spawnSync, spawn } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';

const argv = process.argv.slice(2);
const keep = argv.includes('--keep');
const runtimeOnly = argv.includes('--runtime-only');
const outIdx = argv.indexOf('--out');
const outPath = outIdx >= 0 ? argv[outIdx + 1] : null;
const target = argv.filter((a, i) => !a.startsWith('--') && (outIdx < 0 || i !== outIdx + 1))[0];
if (!target) { console.error('usage: diagnose.mjs <github-url-or-owner/repo> [--out report.md] [--keep]'); process.exit(2); }

const m = target.match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git|\/.*)?$/);
if (!m) { console.error(`cannot parse repo from: ${target}`); process.exit(2); }
const repo = `${m[1]}/${m[2]}`;
// /tmp/claude is writable both inside and outside the session sandbox, and is
// the SAME path in both contexts (TMPDIR differs), so phase 2 can find phase 1's clone.
import { mkdirSync } from 'node:fs';
const TMP = '/tmp/claude';
mkdirSync(join(TMP, 'diagnose'), { recursive: true });
const dir = join(TMP, 'diagnose', repo.replace('/', '__'));
const env = { ...process.env, npm_config_cache: join(TMP, 'npm-cache') };

const findings = []; // {severity: 'blocker'|'warn'|'info', cls, title, detail}
const f = (severity, cls, title, detail) => findings.push({ severity, cls, title, detail });
const sh = (cmd, args, opts = {}) =>
  spawnSync(cmd, args, { encoding: 'utf8', env, timeout: (opts.timeoutSec ?? 300) * 1000, cwd: opts.cwd, maxBuffer: 32 * 1024 * 1024 });
const head = (s, n = 6) => (s || '').split('\n').filter(l => l.trim()).slice(0, n).join('\n');
const CHROME = process.env.CHROME_PATH
  || ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium-browser', '/usr/bin/chromium']
    .find(p => existsSync(p))
  || '/usr/bin/google-chrome';
const reportPath = () => outPath || join(TMP, 'diagnose', `${repo.replace('/', '__')}.report.md`);
const findDist = d => ['dist', 'build', 'out'].map(x => join(d, x)).find(x => existsSync(x) && statSync(x).isDirectory()) || null;

// serve dist to headless Chrome, measure what mounts inside #root
async function renderCheck(dd) {
  const port = 4199;
  const srv = spawn('python3', ['-m', 'http.server', String(port)], { cwd: dd, stdio: 'ignore', env });
  await new Promise(r => setTimeout(r, 1200));
  // Chrome prints the DOM then lingers; the timeout reaps it and stdout is kept
  const rend = sh(CHROME, ['--headless=new', '--disable-gpu', `--user-data-dir=${join(TMP, 'diagnose-chrome-profile')}`, '--virtual-time-budget=8000', '--dump-dom', `http://127.0.0.1:${port}/`], { timeoutSec: 30 });
  srv.kill();
  const dom = rend.stdout || '';
  const rm2 = dom.match(/<div id="root"[^>]*>([\s\S]*?)<\/div>\s*(?:<script|<\/body)/);
  return { domlen: dom.length, rootlen: rm2 ? rm2[1].trim().length : -1, stderr: head(rend.stderr, 3) };
}
const runtimeVerdict = r =>
  r.domlen === 0 ? null
    : r.rootlen >= 0 && r.rootlen < 100
      ? { severity: 'blocker', cls: 'runtime', title: 'App builds but renders a blank white screen', detail: `Headless Chrome loaded the production build; the React root stayed empty (${r.rootlen} chars rendered). The build pipeline is fine and the failure is at runtime, almost always missing env config or a crash before React mounts. Browser console on the deployed site will show the real error.` }
      : r.rootlen >= 100
        ? { severity: 'info', cls: 'runtime', title: `Production build renders (${r.rootlen} chars of UI)`, detail: 'The app mounts in a clean browser with no env vars beyond defaults. Failures users see are likely config, auth, or data-layer issues rather than the build.' }
        : { severity: 'info', cls: 'runtime', title: 'Rendered, but no #root div found to measure', detail: 'The page is not a standard Vite/React mount; manual review of the served output needed.' };

// ---- phase 2: runtime-only (run unsandboxed after a --keep phase-1 run) -------
if (runtimeOnly) {
  if (!existsSync(dir)) { console.error(`no kept clone at ${dir}; run phase 1 with --keep first`); process.exit(1); }
  const dd = findDist(dir);
  if (!dd) { console.error('no dist/build/out dir in kept clone (build failed or not run)'); process.exit(1); }
  const r = await renderCheck(dd);
  if (r.domlen === 0) { console.error(`chrome produced no DOM. stderr:\n${r.stderr}`); process.exit(1); }
  const v = runtimeVerdict(r);
  const section = `\n## Runtime render check (phase 2)\n\n**${v.title}**\n\n${v.detail}\n`;
  const dest = reportPath();
  if (existsSync(dest)) {
    const cur = readFileSync(dest, 'utf8');
    writeFileSync(dest, cur.replace(/\n## Runtime render check \(phase 2\)[\s\S]*?(?=\n## |$)/, '') + section);
  } else writeFileSync(dest, `# Diagnosis: ${repo}\n${section}`);
  console.error(`rootlen=${r.rootlen} report updated: ${dest}`);
  console.log(section);
  process.exit(0);
}

console.error(`[1/6] clone ${repo}`);
rmSync(dir, { recursive: true, force: true });
const clone = sh('git', ['clone', '--depth', '1', '--template=', `https://github.com/${repo}.git`, dir], { timeoutSec: 120 });
if (clone.status !== 0) { console.error(`clone failed:\n${head(clone.stderr)}`); process.exit(1); }

// ---- static pass: package.json risk skim + stack detection --------------------
console.error('[2/6] static checks');
if (!existsSync(join(dir, 'package.json'))) {
  f('blocker', 'unsupported', 'Not a Node/JavaScript project', 'No package.json at the repo root. This tool currently diagnoses JS/TS app repos (Lovable, Bolt, v0, Vite, Next.js).');
}
let pkg = {};
try { pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')); } catch { /* covered above */ }
const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

const riskHooks = ['preinstall', 'postinstall', 'prepare'].filter(k => pkg.scripts?.[k]);
if (riskHooks.length) f('warn', 'security', `package.json has ${riskHooks.join('/')} lifecycle scripts`,
  `Scripts: ${riskHooks.map(k => `${k}: "${pkg.scripts[k]}"`).join('; ')}. We install with --ignore-scripts so these never ran here, but review them before anyone runs a bare npm install.`);
const offRegistry = Object.entries(deps).filter(([, v]) => /^(git|http|file):|github:|^[^\d^~*]+\//.test(String(v)));
if (offRegistry.length) f('warn', 'security', 'Dependencies not pinned to the npm registry',
  offRegistry.map(([k, v]) => `${k}: ${v}`).join(', ') + '. Off-registry deps are a supply-chain risk and often break installs for anyone but the original author.');

const isNext = !!deps.next;
const isVite = !!deps.vite;
const isLovable = !!deps['lovable-tagger'] || (existsSync(join(dir, 'components.json')) && existsSync(join(dir, 'supabase')));
const usesSupabase = !!deps['@supabase/supabase-js'];
const stack = isNext ? 'Next.js' : isVite ? (isLovable ? 'Lovable (Vite + React + Supabase)' : 'Vite SPA') : 'Node';

// env-var references vs .env.example (playbook failure class 3)
const grep = sh('grep', ['-rhoE', '(import\\.meta\\.env|process\\.env)\\.[A-Z_0-9]+', 'src', 'app', 'lib', '--include=*.ts', '--include=*.tsx', '--include=*.js', '--include=*.jsx'], { cwd: dir, timeoutSec: 30 });
const envRefs = [...new Set((grep.stdout || '').split('\n').map(l => l.replace(/^(import\.meta\.env|process\.env)\./, '').trim()).filter(v => v && !['NODE_ENV', 'MODE', 'DEV', 'PROD', 'BASE_URL', 'SSR'].includes(v)))];
const hasEnvExample = ['.env.example', '.env.sample', '.env.template'].some(n => existsSync(join(dir, n)));
if (envRefs.length && !hasEnvExample)
  f('warn', 'env', `App needs ${envRefs.length} environment variable(s) but ships no .env.example`,
    `Referenced in code: ${envRefs.join(', ')}. Anyone cloning this repo (including your own deploys and collaborators) starts broken with no hint why. This is the #1 cause of "works in the AI tool, blank page everywhere else".`);

// module-level throw on missing env (the campus-link-dash class)
const throwGrep = sh('grep', ['-rlE', 'throw new Error', 'src/lib', 'src/integrations', 'lib'], { cwd: dir, timeoutSec: 15 });
const throwFiles = (throwGrep.stdout || '').split('\n').filter(Boolean).filter(p => /supabase|client|config|env/i.test(p));
if (throwFiles.length && envRefs.length)
  f('info', 'env', 'Config module throws at import time if env vars are missing',
    `${throwFiles.join(', ')}: a throw during module import runs before React mounts, so users see a silent white screen instead of an error message.`);

// hardcoded secrets skim (service_role JWTs, sk- keys); anon keys are public by design
const secGrep = sh('grep', ['-rnE', '(service_role|sk-[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]+)', 'src', 'app', 'lib', '--include=*.ts', '--include=*.tsx', '--include=*.js'], { cwd: dir, timeoutSec: 15 });
if ((secGrep.stdout || '').trim())
  f('blocker', 'security', 'Possible secret key committed in client code',
    head(secGrep.stdout, 3) + '\nService-role or sk- keys in frontend code are readable by every visitor. Rotate them and move server-side.');

// SPA deep-link routing (playbook class 7)
if (isVite && (deps['react-router-dom'] || deps['react-router'])) {
  const hasRedirects = existsSync(join(dir, 'public/_redirects')) || existsSync(join(dir, 'vercel.json')) || existsSync(join(dir, 'netlify.toml'));
  if (!hasRedirects) f('warn', 'deploy', 'Client-side routing without SPA rewrite config',
    'react-router with no _redirects/vercel.json/netlify.toml: page refresh or direct links on any route other than / will 404 on Netlify/Vercel static hosting.');
}

// ---- install ------------------------------------------------------------------
console.error('[3/6] npm install --ignore-scripts');
let installOk = false, buildOk = false, distDir = null;
const inst = sh('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel=error'], { cwd: dir, timeoutSec: 300 });
if (inst.status !== 0) {
  const out = (inst.stdout || '') + (inst.stderr || '');
  const eresolve = /ERESOLVE/.test(out);
  f('blocker', 'install', eresolve ? 'npm install fails with an ERESOLVE dependency conflict' : 'npm install fails',
    head(out.split('\n').filter(l => /ERR|error|ERESOLVE|peer/.test(l)).join('\n'), 8) +
    (eresolve ? '\nThe AI tool pinned package versions that contradict each other. Fix is correcting the conflicting version ranges in package.json, not --force (which hides the problem and breaks later).' : ''));
} else {
  installOk = true;
  // ---- build ------------------------------------------------------------------
  console.error('[4/6] npm run build');
  if (!pkg.scripts?.build) {
    f('info', 'build', 'No build script defined', 'package.json has no "build" script; skipped build and runtime checks.');
  } else {
    const build = sh('npm', ['run', 'build'], { cwd: dir, timeoutSec: 300 });
    const bout = (build.stdout || '') + (build.stderr || '');
    if (build.status !== 0) {
      const lines = bout.split('\n').filter(l => /error|Error|ERR|Cannot find/.test(l));
      const missing = bout.match(/Cannot find (?:module|package) '([^']+)'/);
      f('blocker', 'build', missing ? `Build fails: cannot find module "${missing[1]}"` : 'npm run build fails',
        head(lines.join('\n'), 8) + (missing ? `\n"${missing[1]}" is imported but missing from package.json dependencies. The AI tool used it without declaring it.` : ''));
    } else {
      buildOk = true;
      distDir = findDist(dir);
    }
  }
}

// ---- runtime white-screen check (Vite SPA output only) ------------------------
let runtimePending = false, runtimeDone = false;
if (buildOk && distDir && !isNext && existsSync(CHROME) && existsSync(join(distDir, 'index.html'))) {
  console.error('[5/6] runtime render check (headless Chrome)');
  const r = await renderCheck(distDir);
  console.error(`  dom=${r.domlen} rootlen=${r.rootlen}`);
  if (r.domlen === 0) {
    runtimePending = true;
    console.error(`  chrome could not start here (sandbox); complete with: node scripts/diagnose.mjs ${repo} --runtime-only`);
    if (keep) f('info', 'runtime', 'Runtime render check pending', 'The build succeeded but the headless-browser render check could not run in this environment. It runs as a separate phase 2 step.');
  } else {
    runtimeDone = true;
    const v = runtimeVerdict(r);
    f(v.severity, v.cls, v.title, v.detail);
  }
} else { console.error('[5/6] runtime check skipped'); }

// ---- report -------------------------------------------------------------------
console.error('[6/6] report');
const order = { blocker: 0, warn: 1, info: 2 };
findings.sort((a, b) => order[a.severity] - order[b.severity]);
const blockers = findings.filter(x => x.severity === 'blocker');
const sevLabel = { blocker: 'BROKEN', warn: 'RISK', info: 'NOTE' };

const verdict = blockers.length
  ? `This app is broken at the ${blockers[0].cls} stage. ${blockers.length === 1 ? 'One blocking problem found.' : blockers.length + ' blocking problems found.'} Details below, worst first.`
  : installOk && buildOk
    ? 'Good news: this app installs, builds, and renders in a clean environment. The problems users hit are most likely in configuration, auth, or the data layer rather than the code pipeline. Notes below.'
    : 'No hard blockers found in the stages we could run. See notes below.';

const report = `# Diagnosis: ${repo}

Stack: ${stack}${usesSupabase ? ' with Supabase' : ''}. Checked: install, build${runtimeDone ? ', runtime render' : ''}, plus static review.

## Verdict

${verdict}

## Findings

${findings.length ? findings.map((x, i) => `### ${i + 1}. [${sevLabel[x.severity]}] ${x.title}

${x.detail}
`).join('\n') : 'Nothing notable. The repo is in better shape than most AI-generated apps we see.'}
## How this was checked

Fresh clone, dependencies installed with lifecycle scripts disabled, production build attempted${runtimeDone ? ', and the built app rendered in a clean headless browser with no stored logins or env vars' : ''}. That isolation is the point: it reproduces what a new user, a new deploy, or a collaborator hits, instead of what works on the machine that grew the app.

Automated diagnosis by Vibe Code Rescue. A fix for anything above is usually a small, reviewed change. https://dylancaponi.github.io/vibe-code-rescue/
`;

const dest = reportPath();
writeFileSync(dest, report);
if (!keep) rmSync(dir, { recursive: true, force: true });
console.error(`report: ${dest}`);
console.log(report);
