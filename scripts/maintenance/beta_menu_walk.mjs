import { spawn } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, writeFile } from 'node:fs/promises';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--results') {
  console.error('Usage: npm run beta:menu-walk -- --results <directory>');
  process.exit(2);
}
const results = resolve(args[1]);
const dotnet = process.env.DOTNET_HOST_PATH || 'dotnet';
// Do not inherit an operator's connection or runtime configuration.
const testEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  !/^(ADLOG_|SLI_|ASPNETCORE_|ConnectionStrings[:_]|Kestrel[:_]|PG)/i.test(key)
  && !['DATABASE_URL', 'CREDENTIALS_DIRECTORY', 'DOTNET_STARTUP_HOOKS', 'DOTNET_ADDITIONAL_DEPS'].includes(key)));
Object.assign(testEnv, {
  DOTNET_ENVIRONMENT: 'Testing', ASPNETCORE_ENVIRONMENT: 'Testing',
  ADLOG_DISABLE_SCHEDULER: '1', ADLOG_DISABLE_COLLECTION: '1',
  ADLOG_DB_BACKEND: 'postgres', ADLOG_PG_DSN: 'host=sli-tests.invalid dbname=sli_test_unreachable user=sli_test',
  ConnectionStrings__Sli: 'Host=sli-tests.invalid;Database=sli_test_unreachable;Username=sli_test',
  SLI_MENU_WALK_RESULTS: results,
});
if (process.env.SLI_MENU_WALK_ONLY) testEnv.SLI_MENU_WALK_ONLY = process.env.SLI_MENU_WALK_ONLY;
if (process.env.SLI_TEST_CHROMIUM_EXECUTABLE_PATH) testEnv.SLI_TEST_CHROMIUM_EXECUTABLE_PATH = process.env.SLI_TEST_CHROMIUM_EXECUTABLE_PATH;
async function run(command, argv, env = process.env) {
  await new Promise((ok, fail) => {
    const child = spawn(command, argv, { cwd: root, env, stdio: 'inherit', windowsHide: true });
    child.once('error', fail);
    child.once('exit', code => code === 0 ? ok() : fail(new Error(`Command failed (${code})`)));
  });
}
try {
  await mkdir(results, { recursive: true });
  if (!testEnv.SLI_MENU_WALK_ONLY) await writeFile(resolve(results, 'menu-walk.md'), 'Обход не завершён: подготовка тестовой сборки и базы.\n');
  if (!testEnv.SLI_MENU_WALK_ONLY) await writeFile(resolve(results, 'menu-walk.json'), '[]\n');
  await run(process.execPath, ['frontend/node_modules/typescript/bin/tsc', '-b', 'frontend']);
  await run(process.execPath, ['frontend/node_modules/vite/bin/vite.js', 'build', 'frontend', '--config', 'frontend/vite.config.ts']);
  await run(dotnet, ['build', 'server-dotnet/Sli.Server.slnx']);
  await run(dotnet, ['run', '--project', 'server-dotnet/tests/Sli.Server.Tests', '--no-build', '--',
    '-class', 'Sli.Server.Tests.Workspace.BetaMenuWalkTests'], testEnv);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
