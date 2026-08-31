/**
 * Propagates the package.json version to every other place in the repo that
 * carries it. The npm version lifecycle runs this after bumping package.json
 * and before committing, so the synced files land in the release commit.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const packageJsonPath = new URL('../package.json', import.meta.url);
const cargoTomlPath = new URL('../Cargo.toml', import.meta.url);

const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
const version = packageJson.version;

/**
 * Pin the platform packages to the root version. napi prepublish rewrites
 * these again at publish time, and syncing them here keeps the committed
 * manifest identical to what ships.
 */
for (const name of Object.keys(packageJson.optionalDependencies)) {
  packageJson.optionalDependencies[name] = version;
}

writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n');

/**
 * The anchored match only hits the [package] version line, because the
 * dependency versions in this manifest are either inline table fields or
 * plain string values that do not start the line with "version".
 */
const cargoToml = readFileSync(cargoTomlPath, 'utf8');

if (!/^version = ".+"$/m.test(cargoToml)) {
  throw new Error('Could not find the version line in Cargo.toml');
}

writeFileSync(cargoTomlPath, cargoToml.replace(/^version = ".+"$/m, `version = "${version}"`));

console.log(`Synced Cargo.toml and optionalDependencies to ${version}`);
