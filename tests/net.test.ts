/**
 * Landlock TCP network restriction tests.
 *
 * These tests mirror the upstream kernel selftests
 * (tools/testing/selftests/landlock/net_test.c) as closely as possible using
 * only Node.js APIs (node:net, node:dgram, node:fs and node:child_process).
 * Every test that enforces a ruleset runs in a subprocess (fixtures/net.ts)
 * because restrictSelf() irreversibly restricts the calling process.
 *
 * The covered upstream tests map to fixture cases as follows.
 *
 * - `bind` mirrors the TCP variants of `protocol.bind`, including denied
 *   ephemeral binds and the ECONNREFUSED case that proves Landlock allowed
 *   the connect.
 * - `connect` mirrors the TCP variants of `protocol.connect`, including a
 *   denied connect to a port with a listening server.
 * - `ipv6` re-runs the bind and connect checks against the IPv6 loopback and
 *   verifies that port rules are address family agnostic.
 * - `unaffected_protocols` mirrors the UDP and unix socket variants of the
 *   `protocol` fixture, which expect a TCP sandbox to leave other protocols
 *   alone.
 * - `ruleset_overlap` mirrors `tcp_layers.ruleset_overlap` (rules for the
 *   same port are unioned within a layer, layers are intersected).
 * - `ruleset_expand` mirrors `tcp_layers.ruleset_expand` (later layers can
 *   handle more accesses but never regain what an earlier layer denied).
 * - `bind_connect_zero` mirrors `port_specific.bind_connect_zero` (a port 0
 *   rule allows ephemeral binds and nothing else).
 * - `port_endianness` mirrors `ipv4_tcp.port_endianness` from the JavaScript
 *   side by checking that rule ports are interpreted in host byte order end
 *   to end.
 * - `with_fs` mirrors `ipv4_tcp.with_fs` (one ruleset can enforce file system
 *   and network rules at the same time).
 * - `already_connected` mirrors the pre-restriction connection checks in
 *   `protocol.connect_unspec` and `protocol.sendmsg_dgram`.
 * - `inherited` mirrors the fork based child checks used throughout the
 *   kernel suite, using child processes instead of fork(2).
 * - The in-process "rule validation" suite below mirrors the `mini` fixture
 *   (`network_access_rights`, `ruleset_with_unknown_access`,
 *   `rule_with_unknown_access`, `rule_with_unhandled_access`, `inval` and
 *   `tcp_port_overflow`).
 *
 * The following upstream tests need low level syscall access, or kernel
 * features this library does not expose, and cannot be reproduced with pure
 * Node.js APIs.
 *
 * - `protocol.bind_unspec` and `protocol.connect_unspec` build AF_UNSPEC
 *   sockaddr structures by hand to disconnect sockets and to probe
 *   INADDR_ANY, and they pass truncated addrlen values to trigger EINVAL.
 *   Node.js always builds well formed sockaddr structures internally.
 * - `protocol.tcp_fastopen` calls sendto(2) with MSG_FASTOPEN on a TCP
 *   socket, which Node.js does not expose.
 * - `protocol.sendmsg_stream`, `protocol.sendmsg_dgram` and
 *   `protocol.sendmsg_unspec` call sendto(2) with explicit destination
 *   addresses on connected sockets. Node.js stream sockets have no sendto
 *   equivalent, and the UDP parts additionally depend on the bind_udp and
 *   connect_send_udp rights (kernel ABI v10), which neither the landlock
 *   crate nor this library exposes yet.
 * - The MPTCP protocol variants need socket(2) with IPPROTO_MPTCP, which
 *   Node.js does not support.
 * - `ipv4.from_unix_to_inet` calls bind(2) and connect(2) on a socket with a
 *   mismatched address family.
 * - `port_specific.bind_connect_1023` toggles CAP_NET_BIND_SERVICE to bind
 *   privileged ports, which needs root and libcap.
 * - The `mini` tests assert exact errno values (EINVAL, ENOMSG) returned by
 *   landlock_add_rule(2) for raw access bit patterns. The bindings validate
 *   access strings before they reach the kernel, so the rule validation
 *   suite below asserts on the binding errors instead.
 * - The `audit` tests read audit records through an AF_NETLINK audit socket
 *   and the `trace_net` tests attach eBPF programs. Neither is reachable
 *   from Node.js.
 */

import { spawnSync } from 'node:child_process';
import * as os from 'node:os';
import * as path from 'node:path';
import * as vitest from 'vitest';
import {
  LandlockRuleset,
  getAbiVersion,
  isLandlockSupported,
  netAccessFromAbi,
  type NetAccess,
} from '../dist/index.mjs';

const isSupported = isLandlockSupported();
const abi = getAbiVersion();

const supportedAccess = isSupported ? netAccessFromAbi(abi) : [];
const hasNetSupport = supportedAccess.includes('bind_tcp') && supportedAccess.includes('connect_tcp');

const hasIpv6Loopback = Object.values(os.networkInterfaces())
  .flat()
  .some((iface) => iface?.address === '::1');

test('bind');
test('connect');
test('ipv6', hasIpv6Loopback, 'IPv6 loopback unavailable');
test('unaffected_protocols');
test('ruleset_overlap');
test('ruleset_expand');
test('bind_connect_zero');
test('port_endianness');
test('with_fs');
test('already_connected');
test('inherited');

vitest.describe.skipIf(!hasNetSupport)('rule validation', () => {
  /**
   * Mirrors `mini.network_access_rights`. Every access right can be handled
   * and used in a rule, alone and combined, across the whole port range.
   */
  vitest.test('accepts every supported access right', () => {
    const combinations: NetAccess[][] = [['bind_tcp'], ['connect_tcp'], ['bind_tcp', 'connect_tcp']];

    for (const access of combinations) {
      const ruleset = new LandlockRuleset();

      ruleset.setCompatibility('hard_requirement');
      ruleset.handleNetAccess(access);
      ruleset.create();
      ruleset.addNetPortRule(1, access);
      ruleset.addNetPortRule(65_535, access);
    }
  });

  // mirrors `mini.ruleset_with_unknown_access` and `mini.rule_with_unknown_access`
  vitest.test('rejects unknown access rights', () => {
    const invalid = ['bogus'] as unknown as NetAccess[];

    vitest.expect(() => new LandlockRuleset().handleNetAccess(invalid)).toThrow(/Unknown net access/);

    const ruleset = new LandlockRuleset();

    ruleset.handleNetAccess(['bind_tcp', 'connect_tcp']);
    ruleset.create();

    vitest.expect(() => ruleset.addNetPortRule(4000, invalid)).toThrow(/Unknown net access/);
  });

  // mirrors `mini.rule_with_unhandled_access`, which the kernel rejects with EINVAL
  vitest.test('rejects rules with unhandled access rights', () => {
    const ruleset = new LandlockRuleset();

    ruleset.setCompatibility('hard_requirement');
    ruleset.handleNetAccess(['bind_tcp']);
    ruleset.create();

    vitest.expect(() => ruleset.addNetPortRule(4000, ['connect_tcp'])).toThrow(/not handled/);
  });

  // mirrors the zero access check in `mini.inval`, which the kernel rejects with ENOMSG
  vitest.test('rejects rules with empty access', () => {
    const ruleset = new LandlockRuleset();

    ruleset.setCompatibility('hard_requirement');
    ruleset.handleNetAccess(['bind_tcp', 'connect_tcp']);
    ruleset.create();

    vitest.expect(() => ruleset.addNetPortRule(4000, [])).toThrow(/empty access/);
  });

  // mirrors `mini.tcp_port_overflow`
  vitest.test('rejects ports outside the 16 bit unsigned range', () => {
    const ruleset = new LandlockRuleset();

    ruleset.setCompatibility('hard_requirement');
    ruleset.handleNetAccess(['bind_tcp']);
    ruleset.create();

    ruleset.addNetPortRule(65_535, ['bind_tcp']);

    vitest.expect(() => ruleset.addNetPortRule(65_536, ['bind_tcp'])).toThrow(/u16/);
    vitest.expect(() => ruleset.addNetPortRule(-1, ['bind_tcp'])).toThrow(/u16/);

    // interleaving valid and invalid rules keeps the ruleset usable, as in the kernel test
    ruleset.addNetPortRule(1024, ['bind_tcp']);
  });

  // covers the wrapper lifecycle guards around net rules
  vitest.test('enforces the create() lifecycle', () => {
    const ruleset = new LandlockRuleset();

    ruleset.handleNetAccess(['bind_tcp']);

    vitest.expect(() => ruleset.addNetPortRule(4000, ['bind_tcp'])).toThrow(/not created/);

    ruleset.create();

    vitest.expect(() => ruleset.handleNetAccess(['connect_tcp'])).toThrow(/after creation/);
  });
});

function test(name: string, condition = true, skipReason = '') {
  const wrappedFunction = () => {
    const runner = path.resolve(import.meta.dirname, 'fixtures/net.ts');

    const result = spawnSync(process.execPath, ['--experimental-strip-types', runner, name], {
      stdio: 'pipe',
      env: process.env,
    });

    vitest.expect(result.stderr.toString()).toBe('');
    vitest.expect(result.status).toBe(0);
  };

  if (!isSupported) {
    vitest.test.skip(`${name} (Landlock not supported)`, wrappedFunction);
  } else if (!hasNetSupport) {
    vitest.test.skip(`${name} (ABI v${abi} does not support network rules)`, wrappedFunction);
  } else if (!condition) {
    vitest.test.skip(`${name} (${skipReason})`, wrappedFunction);
  } else {
    vitest.test(name, wrappedFunction, 30_000);
  }
}
