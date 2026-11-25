// Packs both packages into ./dist-pkg as <name>-<version>.tgz (the file names
// served from https://sso.moonl.cloud/sdk/npm/). The top-level README is
// shipped inside each package.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'dist-pkg');
mkdirSync(out, { recursive: true });
// Prefer running npm's JS entry point directly (no shell); fall back to the npm binary.
const npmCli = process.env.npm_execpath;
const runNpm = (args, cwd) =>
  npmCli && npmCli.endsWith('.js')
    ? execFileSync(process.execPath, [npmCli, ...args], { cwd, stdio: 'inherit' })
    : execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, { cwd, stdio: 'inherit', shell: process.platform === 'win32' });
for (const pkg of ['packages/browser', 'packages/node']) {
  const dir = join(root, pkg);
  const readme = join(dir, 'README.md');
  copyFileSync(join(root, 'README.md'), readme);
  try {
    runNpm(['pack', '--pack-destination', out], dir);
  } finally {
    rmSync(readme, { force: true });
  }
}
console.log(readdirSync(out).filter((f) => f.endsWith('.tgz')).map((f) => join(out, f)).join('\n'));
