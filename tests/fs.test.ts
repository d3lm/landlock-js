import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import * as vitest from 'vitest';
import { fsAccessFromAbi, getAbiVersion, isLandlockSupported, type FsAccess } from '../dist/index.mjs';

const isSupported = isLandlockSupported();
const abi = getAbiVersion();

const supportedAccess = isSupported ? fsAccessFromAbi(abi) : [];

test('read_file');
test('write_file');
test('execute');
test('read_dir');
test('make_dir');
test('make_reg');
test('make_sym');
test('make_sock');
test('make_fifo');
test('make_char');
test('make_block');
test('remove_file');
test('remove_dir');
test('refer');
test('truncate');
test('ioctl_dev');

// scenario tests cover cross-cutting behavior such as ruleset layering
testScenario('layers');
testScenario('unhandled_access');

function runFixture(name: string) {
  const runner = path.resolve(import.meta.dirname, 'fixtures/fs.ts');

  const result = spawnSync(process.execPath, ['--experimental-strip-types', runner, name], {
    stdio: 'pipe',
    env: process.env,
  });

  vitest.expect(result.stderr.toString()).toBe('');
  vitest.expect(result.status).toBe(0);
}

function test(access: FsAccess) {
  if (!isSupported) {
    vitest.test.skip(`${access} (Landlock not supported)`, () => {
      runFixture(access);
    });
  } else if (!supportedAccess.includes(access)) {
    vitest.test.skip(`${access} (ABI v${abi} does not support ${access})`, () => {
      runFixture(access);
    });
  } else {
    vitest.test(access, () => {
      runFixture(access);
    });
  }
}

function testScenario(name: string) {
  if (!isSupported) {
    vitest.test.skip(`${name} (Landlock not supported)`, () => {
      runFixture(name);
    });
  } else {
    vitest.test(name, () => {
      runFixture(name);
    });
  }
}
