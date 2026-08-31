/**
 * Landlock restrict-self flags test runner (audit log control since ABI v7,
 * enforcement across all threads since ABI v8). Each invocation runs a single
 * test case in a fresh process, because an enforced Landlock ruleset cannot
 * be removed again. The test harness in tests/restrict.test.ts spawns this
 * file once per test case.
 *
 * See tests/restrict.test.ts for the mapping to the upstream kernel selftests
 * and for the list of upstream tests that need low level syscall access.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import { Worker } from 'node:worker_threads';
import { expect } from 'vitest';
import {
  type CompatibilityLevel,
  type RestrictSelfOptions,
  LandlockRuleset,
  applyRestrictSelfFlags,
  isLandlockSupported,
} from '../../dist/index.mjs';

const caseName = process.argv[2];

/**
 * Source of a worker thread that probes directory listing on request. The
 * worker runs plain CommonJS because it is evaluated from a string.
 */
const READDIR_PROBE_WORKER = `
  const { parentPort } = require('node:worker_threads');
  const fs = require('node:fs');

  parentPort.on('message', (dir) => {
    let code = 'ok';

    try {
      fs.readdirSync(dir);
    } catch (error) {
      code = error.code;
    }

    parentPort.postMessage(code);
  });
`;

const testCases: Partial<Record<string, () => Promise<void> | void>> = {
  /**
   * Verifies the kernel defaults reported by restrictSelf() without any
   * options. Denials are logged for the same executable, not after execve(2),
   * subdomain logging stays on, and only the calling thread is restricted.
   */
  default_status() {
    const status = restrict();

    expect(status).toEqual({
      ruleset: 'fully_enforced',
      no_new_privs: true,
      log_same_exec: true,
      log_new_exec: false,
      log_subdomains: true,
      all_threads: false,
    });

    // the ruleset denies read_dir everywhere, which proves the enforcement
    expect(() => fs.readdirSync(os.tmpdir())).toThrow(/EACCES/);
  },

  /**
   * On a kernel without restrict-self flags, best effort silently drops every
   * requested flag. The status downgrades to partially_enforced and reports
   * the kernel defaults, so callers can detect the weaker guarantee.
   */
  flags_dropped_best_effort() {
    const status = restrict({
      log_same_exec: false,
      log_new_exec: true,
      log_subdomains: false,
      all_threads: true,
    });

    expect(status).toEqual({
      ruleset: 'partially_enforced',
      no_new_privs: true,
      log_same_exec: true,
      log_new_exec: false,
      log_subdomains: true,
      all_threads: false,
    });

    // the ruleset itself is still enforced
    expect(() => fs.readdirSync(os.tmpdir())).toThrow(/EACCES/);
  },

  /**
   * Under a soft requirement, an unsupported flag disables the whole ruleset
   * instead of being dropped, and restrictSelf() reports not_enforced.
   */
  flags_soft_requirement() {
    const status = restrict({ log_same_exec: false }, 'soft_requirement');

    expect(status.ruleset).toBe('not_enforced');

    // no_new_privs is applied even when the ruleset is disabled
    expect(status.no_new_privs).toBe(true);

    // nothing is restricted
    fs.readdirSync(os.tmpdir());
  },

  /**
   * Under a hard requirement, requesting a logging flag on a kernel below
   * ABI 7 fails at restrictSelf() time instead of degrading silently.
   */
  log_flags_hard_requirement() {
    const ruleset = new LandlockRuleset();

    ruleset.setCompatibility('hard_requirement');
    ruleset.handleFsAccess(['read_dir']);
    ruleset.create();

    expect(() => ruleset.restrictSelf({ log_same_exec: false })).toThrow(/Failed to set log_same_exec/);

    // the failed call left the process unrestricted
    fs.readdirSync(os.tmpdir());
  },

  /**
   * Under a hard requirement, requesting all_threads on a kernel below ABI 8
   * fails instead of restricting only the calling thread.
   */
  all_threads_hard_requirement() {
    const ruleset = new LandlockRuleset();

    ruleset.setCompatibility('hard_requirement');
    ruleset.handleFsAccess(['read_dir']);
    ruleset.create();

    expect(() => ruleset.restrictSelf({ all_threads: true })).toThrow(/Failed to set all_threads/);

    fs.readdirSync(os.tmpdir());
  },

  /**
   * On an ABI 7 kernel the three logging flags are accepted and the returned
   * status reflects the requested configuration. The audit records themselves
   * are only reachable over an AF_NETLINK audit socket, which Node.js does
   * not expose, so this stops at the flag plumbing.
   */
  logging_flags() {
    const status = restrict(
      {
        log_same_exec: false,
        log_new_exec: true,
        log_subdomains: false,
      },
      'hard_requirement',
    );

    expect(status).toEqual({
      ruleset: 'fully_enforced',
      no_new_privs: true,
      log_same_exec: false,
      log_new_exec: true,
      log_subdomains: false,
      all_threads: false,
    });

    expect(() => fs.readdirSync(os.tmpdir())).toThrow(/EACCES/);
  },

  /**
   * On an ABI 8 kernel, all_threads enforces the ruleset atomically on every
   * thread of the process. A worker thread created before the restriction is
   * confined as well, unlike the default per thread behavior.
   */
  async all_threads() {
    const worker = new Worker(READDIR_PROBE_WORKER, { eval: true });

    // the probe both syncs on the worker being live and takes a baseline
    expect(await askWorker(worker, os.tmpdir())).toBe('ok');

    const status = restrict({ all_threads: true }, 'hard_requirement');

    expect(status.ruleset).toBe('fully_enforced');
    expect(status.all_threads).toBe(true);

    // the calling thread is restricted
    expect(() => fs.readdirSync(os.tmpdir())).toThrow(/EACCES/);

    // the worker thread that existed before the restriction is restricted too
    expect(await askWorker(worker, os.tmpdir())).toBe('EACCES');

    await worker.terminate();
  },

  /**
   * On a kernel below ABI 8, best effort drops all_threads and only the
   * calling thread is restricted. A worker thread created before the
   * restriction keeps its full access, which mirrors the per thread
   * semantics that the scope suite proves for domains without the flag.
   */
  async all_threads_dropped() {
    const worker = new Worker(READDIR_PROBE_WORKER, { eval: true });

    expect(await askWorker(worker, os.tmpdir())).toBe('ok');

    const status = restrict({ all_threads: true });

    expect(status.ruleset).toBe('partially_enforced');
    expect(status.all_threads).toBe(false);

    expect(() => fs.readdirSync(os.tmpdir())).toThrow(/EACCES/);

    // the pre-existing worker stays unrestricted because the flag was dropped
    expect(await askWorker(worker, os.tmpdir())).toBe('ok');

    await worker.terminate();
  },

  /**
   * Mirrors the enforcement checks of the upstream base tests. The kernel
   * requires either no_new_privs or CAP_SYS_ADMIN to enforce a ruleset, so
   * opting out of no_new_privs either fails with EPERM or succeeds because
   * the process holds the capability in its namespace.
   */
  no_new_privs_opt_out() {
    const ruleset = new LandlockRuleset();

    ruleset.handleFsAccess(['read_dir']);
    ruleset.create();

    let status;

    try {
      status = ruleset.restrictSelf({ no_new_privs: false });
    } catch (error) {
      // without the capability the kernel refuses the enforcement
      expect((error as Error).message).toMatch(/not permitted/i);

      // the failed call left the process unrestricted
      fs.readdirSync(os.tmpdir());

      return;
    }

    // with CAP_SYS_ADMIN the ruleset is enforced without setting no_new_privs
    expect(status.ruleset).toBe('fully_enforced');
    expect(status.no_new_privs).toBe(false);
    expect(() => fs.readdirSync(os.tmpdir())).toThrow(/EACCES/);
  },

  /**
   * Calling applyRestrictSelfFlags() without options skips the restrict
   * syscall and reports the kernel defaults. It still sets no_new_privs, and
   * it never creates a Landlock domain.
   */
  apply_flags_defaults() {
    const status = applyRestrictSelfFlags();

    expect(status).toEqual({
      no_new_privs: true,
      log_subdomains: true,
      all_threads: false,
    });

    // no domain was created, so nothing is restricted
    fs.readdirSync(os.tmpdir());
  },

  /**
   * On a kernel below ABI 7, a hard requirement rejects muting subdomain
   * logs, while best effort drops the flag and reports the kernel default.
   */
  apply_flags_unsupported() {
    expect(() => applyRestrictSelfFlags({ log_subdomains: false, compatibility: 'hard_requirement' })).toThrow(
      /Failed to set log_subdomains/,
    );

    const status = applyRestrictSelfFlags({ log_subdomains: false, no_new_privs: false });

    expect(status).toEqual({
      no_new_privs: false,
      log_subdomains: true,
      all_threads: false,
    });
  },

  /**
   * On an ABI 7 kernel, subdomain logging can be muted without creating a
   * Landlock domain, which maps to landlock_restrict_self(2) with a ruleset
   * file descriptor of -1.
   */
  apply_flags_subdomains() {
    const status = applyRestrictSelfFlags({ log_subdomains: false, compatibility: 'hard_requirement' });

    expect(status).toEqual({
      no_new_privs: true,
      log_subdomains: false,
      all_threads: false,
    });

    // muting logs creates no domain, so nothing is restricted
    fs.readdirSync(os.tmpdir());
  },

  /**
   * On an ABI 8 kernel, the muted subdomain logging can be propagated to all
   * threads of the process. The kernel only accepts all_threads on this
   * ruleset-less path together with muting subdomain logs.
   */
  apply_flags_all_threads() {
    const status = applyRestrictSelfFlags({
      log_subdomains: false,
      all_threads: true,
      compatibility: 'hard_requirement',
    });

    expect(status).toEqual({
      no_new_privs: true,
      log_subdomains: false,
      all_threads: true,
    });

    fs.readdirSync(os.tmpdir());
  },
};

if (!isLandlockSupported()) {
  process.exit(1);
}

const fn = testCases[caseName];

if (!fn) {
  throw new Error(`Unknown restrict test case: ${caseName}`);
}

await fn();

process.exit(0);

/**
 * Handles read_dir with no rules and restricts the current process with the
 * given options, so every directory listing is denied once the ruleset is
 * enforced.
 */
function restrict(options?: RestrictSelfOptions, compatibility: CompatibilityLevel = 'best_effort') {
  const ruleset = new LandlockRuleset();

  ruleset.setCompatibility(compatibility);
  ruleset.handleFsAccess(['read_dir']);
  ruleset.create();

  return ruleset.restrictSelf(options);
}

/**
 * Asks the readdir probe worker to list the given directory and returns "ok"
 * or the reported error code.
 */
function askWorker(worker: Worker, dir: string): Promise<unknown> {
  return new Promise((resolve) => {
    worker.once('message', resolve);
    worker.postMessage(dir);
  });
}
