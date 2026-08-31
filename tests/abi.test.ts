/**
 * This suite guards CI against silent skips. The fs, net and scope suites
 * skip whatever the running kernel does not support, so a broken build that
 * reports Landlock as unavailable would otherwise turn a whole run green
 * without executing a single test. CI sets LANDLOCK_TEST_MIN_ABI to the ABI
 * version the kernel under test is known to provide, and this suite fails
 * loudly when the bindings report anything less. The suite is skipped when
 * the variable is unset, which keeps local runs on arbitrary machines
 * unaffected.
 */

import * as vitest from 'vitest';
import { getAbiVersion, isLandlockSupported } from '../dist/index.mjs';

const rawMinAbi = process.env.LANDLOCK_TEST_MIN_ABI;
const minAbi = Number(rawMinAbi);

vitest.describe.skipIf(!rawMinAbi)(`expected Landlock ABI (v${minAbi} or newer)`, () => {
  vitest.test('Landlock is supported', () => {
    vitest.expect(isLandlockSupported()).toBe(true);
  });

  vitest.test(`the kernel provides at least ABI v${minAbi}`, () => {
    vitest.expect(getAbiVersion()).toBeGreaterThanOrEqual(minAbi);
  });
});
