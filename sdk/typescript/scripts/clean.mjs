// Removes build output and generated shared sources.
import { rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
for (const p of [
  'packages/browser/dist',
  'packages/node/dist',
  'packages/browser/src/shared',
  'packages/node/src/shared',
  'packages/browser/tsconfig.tsbuildinfo',
  'packages/node/tsconfig.tsbuildinfo',
  'dist-test',
]) {
  rmSync(join(root, p), { recursive: true, force: true });
}
console.log('clean');
