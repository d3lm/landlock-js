/**
 * Landlock scope restriction tests (signal and abstract unix socket scoping,
 * available since Landlock ABI v6).
 *
 * These tests mirror the upstream kernel selftests
 * (tools/testing/selftests/landlock/scoped_signal_test.c and
 * scoped_abstract_unix_test.c, together with the variant tables in
 * scoped_base_variants.h and scoped_multiple_domain_variants.h) as closely as
 * possible using only Node.js APIs (node:child_process, node:net and
 * node:worker_threads). Every test that enforces a ruleset runs in a
 * subprocess (fixtures/scope.ts) because restrictSelf() irreversibly
 * restricts the calling process. Node.js reaches abstract unix sockets by
 * prefixing the socket path with a NUL byte, and both process.kill() and
 * socket connections surface the EPERM a scoped domain injects.
 *
 * The covered upstream tests map to fixture cases as follows.
 *
 * - `signal_send_to_parent` mirrors `scoping_signals.send_sig_to_parent` for
 *   all four upstream signal variants (SIGTRAP, SIGURG, SIGHUP and SIGTSTP).
 *   A child signals its parent before scoping, is denied with EPERM after
 *   scoping, and can still signal itself.
 * - `signal_domains_*` mirror `scoped_domains.check_access_signal` across all
 *   eight parent and child domain permutations from scoped_base_variants.h,
 *   probing both directions with the null signal like upstream.
 * - `signal_worker_threads` covers the per thread semantics behind
 *   `signal_scoping_thread_before` and `signal_scoping_thread_after`.
 *   restrictSelf() only restricts the calling thread, so a worker thread
 *   created before the restriction can still signal outside the domain while
 *   a worker created afterwards inherits it.
 * - `unix_domains_*` mirror the SOCK_STREAM halves of
 *   `scoped_domains.connect_to_parent` and `scoped_domains.connect_to_child`
 *   across the same eight domain permutations.
 * - `unix_tree_*` mirror `scoped_vs_unscoped.unix_scoping` across all seven
 *   three process permutations from scoped_multiple_domain_variants.h. A
 *   file system only Landlock domain stands in for OTHER_SANDBOX and proves
 *   that unrelated domains do not scope abstract sockets.
 * - `unix_sockets_*` mirror the stream parts of
 *   `various_address_sockets.scoped_pathname_sockets`. Pathname sockets, the
 *   inherited IPC socketpair (an unnamed socketpair, as upstream uses) and
 *   connections established before the restriction keep working, while new
 *   abstract connections are denied only inside a scoped domain. This also
 *   covers the connected socket allowance that `datagram_sockets` checks,
 *   stream flavored.
 * - `unix_self_connect` mirrors the intent of `self_connect`. The listening
 *   socket itself is passed to the scoped child over the IPC channel (which
 *   uses SCM_RIGHTS underneath), and holding it still does not permit
 *   connecting to its abstract address.
 * - `both_scopes` mirrors the combined scoped ruleset attribute used by the
 *   `scoped_audit` variants. A single ruleset handles both scopes and
 *   enforces them at the same time.
 * - The in-process "scope validation" suite below mirrors the ruleset
 *   attribute checks. The kernel rejects unknown scope bits with EINVAL, and
 *   the bindings reject unknown scope strings before the syscall. Scopes have
 *   no rule type, so unlike the fs and net suites there are no rule level
 *   checks.
 *
 * The following upstream tests need low level syscall access, or kernel
 * interfaces Node.js does not expose, and cannot be reproduced with pure
 * Node.js APIs.
 *
 * - Every SOCK_DGRAM variant of the abstract socket tests, because node:dgram
 *   only supports UDP and has no AF_UNIX support. This drops the datagram
 *   halves of `connect_to_parent`, `connect_to_child` and `unix_scoping`, the
 *   `datagram_sockets` checks for connected versus unconnected sends, the
 *   whole of `self_connect` (its stream analog is covered by
 *   `unix_self_connect`), and the datagram sends of
 *   `various_address_sockets`.
 * - `outside_socket.socket_with_different_domain` creates a socket with
 *   socket(2) in one domain and binds it in another, passing the bare file
 *   descriptor over SCM_RIGHTS at chosen lifecycle points. Node.js can only
 *   transfer sockets that are already listening, so the cases where socket
 *   creation and bind happen in different domains are out of reach.
 * - `fown.sigurg_socket`, `sigio_to_pgid_members` and `sigio_to_pgid_self`
 *   need fcntl(2) with F_SETOWN, F_SETSIG and O_ASYNC, out of band data with
 *   MSG_OOB, setpgid(2) and sandboxing a single pthread, none of which
 *   Node.js exposes.
 * - `signal_scoping_thread_before` and `signal_scoping_thread_after` call
 *   pthread_kill(3) to target one specific thread. Node.js cannot signal a
 *   thread, so `signal_worker_threads` asserts the underlying per thread
 *   domain semantics instead.
 * - `signal_scoping_thread_setuid` coordinates the setuid(2) credential
 *   synchronization of libc with CAP_SETUID toggling across threads.
 * - The `scoped_audit` fixtures read records from an AF_NETLINK audit socket
 *   and use the quiet_scoped ruleset attribute, which neither the landlock
 *   crate nor this library exposes.
 * - The `trace_signal`, `trace_unix` and `trace_fown` tests attach to tracefs
 *   events and need CAP_SYS_ADMIN plus a private mount namespace.
 * - The kernel selftests assert raw errno values from the syscall return.
 *   Node.js surfaces the same information through error codes, so these
 *   tests assert the string form (EPERM) instead.
 */

import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import * as vitest from 'vitest';
import { LandlockRuleset, getAbiVersion, isLandlockSupported, scopesFromAbi, type Scope } from '../dist/index.mjs';

const isSupported = isLandlockSupported();
const abi = getAbiVersion();

const supportedScopes = isSupported ? scopesFromAbi(abi) : [];
const hasScopeSupport = supportedScopes.includes('signal') && supportedScopes.includes('abstract_unix_socket');

// the eight parent and child domain permutations from scoped_base_variants.h
const domainVariants = [
  'without_domain',
  'child_domain',
  'parent_domain',
  'sibling_domain',
  'inherited_domain',
  'nested_domain',
  'nested_and_parent_domain',
  'forked_domains',
];

// the seven three process permutations from scoped_multiple_domain_variants.h
const treeVariants = [
  'deny_scoped',
  'all_scoped',
  'allow_with_other_domain',
  'allow_with_one_domain',
  'allow_with_grand_parent_scoped',
  'allow_with_parents_domain',
  'deny_with_self_and_grandparent_domain',
];

test('signal_send_to_parent');

for (const variant of domainVariants) {
  test(`signal_domains_${variant}`);
}

test('signal_worker_threads');

for (const variant of domainVariants) {
  test(`unix_domains_${variant}`);
}

for (const variant of treeVariants) {
  test(`unix_tree_${variant}`);
}

test('unix_sockets_scoped');
test('unix_sockets_other_domain');
test('unix_sockets_no_domain');
test('unix_self_connect');
test('both_scopes');

vitest.describe.skipIf(!hasScopeSupport)('scope validation', () => {
  /**
   * Every scope can be handled and used to create a ruleset, alone and
   * combined. Consecutive calls are ORed together.
   */
  vitest.test('accepts every supported scope', () => {
    const combinations: Scope[][] = [['signal'], ['abstract_unix_socket'], ['signal', 'abstract_unix_socket']];

    for (const scopes of combinations) {
      const ruleset = new LandlockRuleset();

      ruleset.setCompatibility('hard_requirement');
      ruleset.handleScopes(scopes);
      ruleset.create();
    }

    const merged = new LandlockRuleset();

    merged.setCompatibility('hard_requirement');
    merged.handleScopes(['signal']);
    merged.handleScopes(['abstract_unix_socket']);
    merged.create();
  });

  // the kernel rejects unknown scope bits with EINVAL before any rule exists
  vitest.test('rejects unknown scopes', () => {
    const invalid = ['bogus'] as unknown as Scope[];

    vitest.expect(() => new LandlockRuleset().handleScopes(invalid)).toThrow(/Unknown scope/);
  });

  // covers the wrapper lifecycle guards around scopes
  vitest.test('enforces the create() lifecycle', () => {
    const ruleset = new LandlockRuleset();

    ruleset.handleScopes(['signal']);
    ruleset.create();

    vitest.expect(() => ruleset.handleScopes(['abstract_unix_socket'])).toThrow(/after creation/);
  });
});

function test(name: string) {
  const wrappedFunction = () => {
    const runner = path.resolve(import.meta.dirname, 'fixtures/scope.ts');

    const result = spawnSync(process.execPath, ['--experimental-strip-types', runner, name], {
      stdio: 'pipe',
      env: process.env,
    });

    vitest.expect(result.stderr.toString()).toBe('');
    vitest.expect(result.status).toBe(0);
  };

  if (!isSupported) {
    vitest.test.skip(`${name} (Landlock not supported)`, wrappedFunction);
  } else if (!hasScopeSupport) {
    vitest.test.skip(`${name} (ABI v${abi} does not support scopes)`, wrappedFunction);
  } else {
    vitest.test(name, wrappedFunction, 30_000);
  }
}
