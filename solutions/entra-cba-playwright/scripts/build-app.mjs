import { cp, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const labRoot = path.resolve(scriptDirectory, '..');
const appDirectory = path.join(labRoot, 'app');
const outputDirectory = path.join(labRoot, 'dist');
const publicPkiDirectory = path.join(labRoot, '.lab-secrets', 'public');

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

await build({
  bundle: true,
  entryPoints: [path.join(appDirectory, 'main.ts')],
  format: 'esm',
  minify: true,
  outfile: path.join(outputDirectory, 'app.js'),
  sourcemap: false,
  target: ['es2022'],
});

await Promise.all([
  cp(path.join(appDirectory, 'index.html'), path.join(outputDirectory, 'index.html')),
  cp(path.join(appDirectory, 'styles.css'), path.join(outputDirectory, 'styles.css')),
  cp(path.join(appDirectory, 'config.template.js'), path.join(outputDirectory, 'config.js')),
  cp(
    path.join(appDirectory, 'staticwebapp.config.json'),
    path.join(outputDirectory, 'staticwebapp.config.json'),
  ),
]);

try {
  await cp(publicPkiDirectory, path.join(outputDirectory, 'crl'), { recursive: true });
} catch (error) {
  if (error?.code !== 'ENOENT') {
    throw error;
  }
}
