import { access, cp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const functionNames = ['api/verify.func', 'api/execute.func'];
const ddkPackages = ['ddk-ts', 'ddk-ts-linux-x64-gnu'];

async function mustRealpath(packageName) {
  const packagePath = path.join(rootDir, 'node_modules/@bennyblader', packageName);
  await access(packagePath);
  return realpath(packagePath);
}

const ddkSources = await Promise.all(
  ddkPackages.map(async (packageName) => ({
    packageName,
    source: await mustRealpath(packageName),
  })),
);

for (const functionName of functionNames) {
  const functionDir = path.join(rootDir, '.vercel/output/functions', functionName);
  const configPath = path.join(functionDir, '.vc-config.json');

  const config = JSON.parse(await readFile(configPath, 'utf8'));
  config.architecture = 'x86_64';
  if (config.filePathMap) {
    for (const key of Object.keys(config.filePathMap)) {
      const value = config.filePathMap[key];
      if (key.includes('@bennyblader/ddk-ts') || String(value).includes('@bennyblader/ddk-ts')) {
        delete config.filePathMap[key];
      }
    }
  }
  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`);

  const copiedDdk = [];
  for (const { packageName, source } of ddkSources) {
    const ddkTarget = path.join(functionDir, 'node_modules/@bennyblader', packageName);
    await rm(ddkTarget, { recursive: true, force: true });
    await mkdir(path.dirname(ddkTarget), { recursive: true });
    await cp(source, ddkTarget, { recursive: true, force: true, dereference: true });
    copiedDdk.push(path.relative(rootDir, ddkTarget));
  }

  console.log(
    JSON.stringify(
      {
        patchedFunction: path.relative(rootDir, functionDir),
        architecture: config.architecture,
        copiedDdk,
      },
      null,
      2,
    ),
  );
}
