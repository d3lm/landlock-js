/**
 * Landlock restrict-self flag tests (audit log control since ABI v7,
 * enforcement across all threads since ABI v8) plus the errata query and the
 * pure feature helpers.
 *
 * These tests mirror the upstream kernel selftests
 * (tools/testing/selftests/landlock/audit_test.c, the TSYNC variants of
 * base_test.c and the restrict_self checks in base_test.c) as closely as
 * possible using only Node.js APIs (node:fs, node:worker_threads and
 * node:child_process). Every test that enforces a ruleset or applies flags
 * runs in a subprocess (fixtures/restrict.ts) because restrictSelf() and
 * applyRestrictSelfFlags() change the calling process irreversibly.
 *
 * The covered upstream behavior maps to fixture cases as follows.
 *
 * - `default_status` checks the documented kernel defaults that
 *   `audit.default_flags` relies on (same-exec logging on, new-exec logging
 *   off, subdomain logging on, single thread enforcement).
 * - `logging_flags` mirrors the flag plumbing of the `audit` fixtures
 *   (`flags.log_same_exec_off`, `flags.log_new_exec_on` and
 *   `flags.log_subdomains_off`). The upstream tests then read audit records
 *   through an AF_NETLINK audit socket, which Node.js does not expose, so
 *   the assertions stop at the flags reported back by the kernel.
 * - `all_threads` mirrors the TSYNC selftests. Upstream uses raw pthreads,
 *   and worker threads stand in here. A thread created before the
 *   restriction must be confined when all_threads is requested.
 * - `all_threads_dropped` proves the inverse on kernels below ABI 8, where
 *   best effort drops the flag and pre-existing threads stay unrestricted,
 *   matching the per thread semantics that scope.test.ts covers.
 * - `flags_dropped_best_effort`, `flags_soft_requirement`,
 *   `log_flags_hard_requirement` and `all_threads_hard_requirement` cover
 *   the compatibility behavior for kernels that predate the flags. The
 *   kernel rejects unknown restrict_self flags with EINVAL, and the bindings
 *   surface the incompatibility before the syscall.
 * - `no_new_privs_opt_out` mirrors the `restrict_self` checks in
 *   base_test.c, where enforcement without no_new_privs fails with EPERM
 *   unless the process holds CAP_SYS_ADMIN in its namespace.
 * - The `apply_flags_*` cases mirror the ruleset-less
 *   landlock_restrict_self(2) calls with a -1 file descriptor that upstream
 *   exercises for subdomain log muting, including the TSYNC combination.
 *   The kernel accepts that combination only since Linux 7.1 (ABI 9), so
 *   `apply_flags_all_threads` needs ABI 9, and
 *   `apply_flags_all_threads_unsupported` proves the EBADF rejection on
 *   ABI 8 kernels, which already support TSYNC itself.
 * - The in-process "errata" suite below mirrors the errata queries in
 *   base_test.c (`errata` and `errata_abi`). The exact bitmask depends on
 *   the running kernel, so the assertions are structural.
 *
 * The following upstream behavior needs kernel interfaces Node.js does not
 * expose, and cannot be reproduced here.
 *
 * - Reading audit records (every `audit` variant beyond flag plumbing) needs
 *   an AF_NETLINK audit socket and CAP_AUDIT_* capabilities.
 * - The quiet rule flag and the quiet_* ruleset attributes (ABI 10) and the
 *   LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS flag (ABI 11) are not exposed by the
 *   landlock crate yet, so this library cannot exercise them.
 * - Upstream TSYNC tests target single pthreads with pthread_kill(3) and
 *   per-thread seccomp interactions, which Node.js cannot express.
 */

import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import * as vitest from 'vitest';
import {
  applyRestrictSelfFlags,
  fsAccessFromAbi,
  getAbiVersion,
  getErrata,
  isLandlockSupported,
  netAccessFromAbi,
  restrictFlagsFromAbi,
  scopesFromAbi,
} from '../dist/index.mjs';

const isSupported = isLandlockSupported();
const abi = getAbiVersion();

interface CaseRange {
  /**
   * Lowest Landlock ABI version the case needs.
   */
  minAbi?: number;

  /**
   * Highest Landlock ABI version the case is meaningful for, used by the
   * cases that prove the graceful degradation on older kernels.
   */
  maxAbi?: number;
}

test('default_status');
test('flags_dropped_best_effort', { maxAbi: 6 });
test('flags_soft_requirement', { maxAbi: 6 });
test('log_flags_hard_requirement', { maxAbi: 6 });
test('all_threads_hard_requirement', { maxAbi: 7 });
test('logging_flags', { minAbi: 7 });
test('all_threads', { minAbi: 8 });
test('all_threads_dropped', { maxAbi: 7 });
test('no_new_privs_opt_out');
test('apply_flags_defaults');
test('apply_flags_unsupported', { maxAbi: 6 });
test('apply_flags_subdomains', { minAbi: 7 });
test('apply_flags_all_threads_unsupported', { minAbi: 8, maxAbi: 8 });
test('apply_flags_all_threads', { minAbi: 9 });

vitest.describe('errata', () => {
  vitest.test('returns a non-negative bitmask', () => {
    const errata = getErrata();

    vitest.expect(Number.isInteger(errata)).toBe(true);
    vitest.expect(errata).toBeGreaterThanOrEqual(0);
  });

  vitest.test.skipIf(isSupported)('reports no fixed errata without Landlock', () => {
    vitest.expect(getErrata()).toBe(0);
  });
});

vitest.describe('feature helpers', () => {
  vitest.test('maps restrict flags to their ABI versions', () => {
    vitest.expect(restrictFlagsFromAbi(6)).toEqual([]);
    vitest.expect(restrictFlagsFromAbi(7)).toEqual(['log_same_exec', 'log_new_exec', 'log_subdomains']);
    vitest.expect(restrictFlagsFromAbi(8)).toEqual(['log_same_exec', 'log_new_exec', 'log_subdomains', 'all_threads']);
    vitest.expect(restrictFlagsFromAbi(11)).toContain('all_threads');
  });

  vitest.test('maps resolve_unix to ABI 9', () => {
    vitest.expect(fsAccessFromAbi(8)).not.toContain('resolve_unix');
    vitest.expect(fsAccessFromAbi(9)).toContain('resolve_unix');
    vitest.expect(fsAccessFromAbi(1)).toHaveLength(13);
    vitest.expect(fsAccessFromAbi(9)).toHaveLength(17);
  });

  vitest.test('exposes no UDP rights below the crate support', () => {
    // the landlock crate does not support the ABI 10 UDP rights yet
    vitest.expect(netAccessFromAbi(11)).toEqual(['bind_tcp', 'connect_tcp']);
    vitest.expect(scopesFromAbi(11)).toEqual(['signal', 'abstract_unix_socket']);
  });
});

vitest.describe.skipIf(!isSupported)('flag validation', () => {
  vitest.test('rejects unknown compatibility levels', () => {
    // the level is parsed before any flag or prctl side effect
    vitest
      .expect(() => applyRestrictSelfFlags({ log_subdomains: false, compatibility: 'bogus' as never }))
      .toThrow(/Unknown compatibility level/);
  });
});

function test(name: string, range: CaseRange = {}) {
  const wrappedFunction = () => {
    const runner = path.resolve(import.meta.dirname, 'fixtures/restrict.ts');

    const result = spawnSync(process.execPath, ['--experimental-strip-types', runner, name], {
      stdio: 'pipe',
      env: process.env,
    });

    vitest.expect(result.stderr.toString()).toBe('');
    vitest.expect(result.status).toBe(0);
  };

  if (!isSupported) {
    vitest.test.skip(`${name} (Landlock not supported)`, wrappedFunction);
  } else if (range.minAbi !== undefined && abi < range.minAbi) {
    vitest.test.skip(`${name} (needs ABI v${range.minAbi}, kernel has v${abi})`, wrappedFunction);
  } else if (range.maxAbi !== undefined && abi > range.maxAbi) {
    vitest.test.skip(`${name} (only meaningful up to ABI v${range.maxAbi}, kernel has v${abi})`, wrappedFunction);
  } else {
    vitest.test(name, wrappedFunction, 30_000);
  }
}
