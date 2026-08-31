import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import * as vitest from 'vitest';
import { LandlockRuleset, fsAccessFromAbi, getAbiVersion, isLandlockSupported, type FsAccess } from '../dist/index.mjs';

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
test('resolve_unix');

// scenario tests cover cross-cutting behavior such as ruleset layering
testScenario('layers');
testScenario('unhandled_access');

vitest.describe.skipIf(!isSupported)('rule validation', () => {
  // mirrors the unknown access checks of the upstream `mini` net fixture for fs rights
  vitest.test('rejects unknown access rights', () => {
    const invalid = ['bogus'] as unknown as FsAccess[];

    vitest.expect(() => new LandlockRuleset().handleFsAccess(invalid)).toThrow(/Unknown fs access/);

    const ruleset = new LandlockRuleset();

    ruleset.handleFsAccess(['read_file']);
    ruleset.create();

    vitest.expect(() => ruleset.addPathRule('/', invalid)).toThrow(/Unknown fs access/);
  });

  const hasResolveUnix = supportedAccess.includes('resolve_unix');

  /**
   * Building rulesets is safe in-process because only restrictSelf() changes
   * the process, so the compatibility behavior of the ABI 9 right can be
   * probed directly.
   */
  vitest.test.skipIf(hasResolveUnix)('handles resolve_unix gracefully below ABI 9', () => {
    // best effort silently drops the right and still creates the ruleset
    const dropped = new LandlockRuleset();

    dropped.handleFsAccess(['resolve_unix']);
    dropped.create();

    // a hard requirement turns the missing kernel support into an error
    const strict = new LandlockRuleset();

    strict.setCompatibility('hard_requirement');

    vitest.expect(() => strict.handleFsAccess(['resolve_unix'])).toThrow(/Failed to handle fs access/);
  });

  vitest.test.skipIf(!hasResolveUnix)('accepts resolve_unix rules on ABI 9 kernels', () => {
    const ruleset = new LandlockRuleset();

    ruleset.setCompatibility('hard_requirement');
    ruleset.handleFsAccess(['resolve_unix']);
    ruleset.create();
    ruleset.addPathRule('/', ['resolve_unix']);
  });
});

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
