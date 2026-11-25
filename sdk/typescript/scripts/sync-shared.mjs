// Copies the environment-neutral core in ../shared into each package's
// src/shared directory so that every package compiles (with plain tsc) into a
// self-contained ESM build without runtime dependencies.
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'shared');
const targets = ['packages/browser/src/shared', 'packages/node/src/shared'];
const files = readdirSync(src).filter((f) => f.endsWith('.ts'));

for (const t of targets) {
  const dir = join(root, t);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  for (const f of files) {
    const body = readFileSync(join(src, f), 'utf8');
    writeFileSync(join(dir, f), `// Generated from sdk/typescript/shared/${f} by scripts/sync-shared.mjs. Edit the original.\n${body}`);
  }
}
console.log(`synced ${files.length} shared modules into ${targets.length} packages`);
