/**
 * Landlock scope restriction test runner. Each invocation runs a single
 * test case in a fresh process, because an enforced Landlock ruleset cannot
 * be removed again. The test harness in tests/scope.test.ts spawns this file
 * once per test case.
 *
 * Scoped domains restrict interactions between processes, so most cases here
 * fork this file again with a role argument (child or grandchild) and use the
 * IPC channel for synchronization. The IPC channel itself is an unnamed unix
 * socketpair, which the abstract unix socket scope never restricts, so it is
 * safe to use from inside a scoped domain. Abstract socket addresses travel
 * through argv without their leading NUL byte, because argv cannot carry NUL
 * bytes, and the byte is prepended again on use.
 *
 * See tests/scope.test.ts for the mapping to the upstream kernel selftests
 * and for the list of upstream tests that need low level syscall access.
 */

import { fork, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { Worker } from 'node:worker_threads';
import { expect } from 'vitest';
import { LandlockRuleset, getAbiVersion, isLandlockSupported, scopesFromAbi, type Scope } from '../../dist/index.mjs';

const caseName = process.argv[2];
const role = process.argv[3] ?? 'main';
const roleArgs = process.argv.slice(4);

/**
 * The four signals exercised by the upstream scoping_signals fixture. All of
 * them can be caught from JavaScript, so raising them is observable.
 */
const SCOPED_SIGNALS: NodeJS.Signals[] = ['SIGTRAP', 'SIGURG', 'SIGHUP', 'SIGTSTP'];

/**
 * Source of a worker thread that probes signal delivery on request.
 * The worker runs plain CommonJS because it is evaluated from a string.
 */
const KILL_PROBE_WORKER = `
  const { parentPort } = require('node:worker_threads');

  parentPort.on('message', (pid) => {
    let code = 'ok';

    try {
      process.kill(pid, 0);
    } catch (error) {
      code = error.code;
    }

    parentPort.postMessage(code);
  });
`;

interface DomainVariant {
  /**
   * Creates the scoped domain before forking, so parent and child share it.
   */
  both: boolean;

  /**
   * Puts the parent in its own scoped domain right after forking.
   */
  parent: boolean;

  /**
   * Puts the child in its own scoped domain.
   */
  child: boolean;
}

/**
 * Mirrors the eight parent and child domain permutations from the upstream
 * scoped_base_variants.h.
 */
const domainVariants: Record<string, DomainVariant> = {
  without_domain: { both: false, parent: false, child: false },
  child_domain: { both: false, parent: false, child: true },
  parent_domain: { both: false, parent: true, child: false },
  sibling_domain: { both: false, parent: true, child: true },
  inherited_domain: { both: true, parent: false, child: false },
  nested_domain: { both: true, parent: false, child: true },
  nested_and_parent_domain: { both: true, parent: true, child: false },
  forked_domains: { both: true, parent: true, child: true },
};

/**
 * A sandbox kind from the upstream scoped_multiple_domain_variants.h, where
 * "other" is a Landlock domain that handles no scope at all.
 */
type SandboxKind = 'none' | 'scope' | 'other';

interface TreeVariant {
  /**
   * Applied by the top process before forking, so all three processes share it.
   */
  all: SandboxKind;

  /**
   * Applied by the top process after forking the middle process.
   */
  parent: SandboxKind;

  /**
   * Applied by the middle process before forking the grandchild, so the
   * middle process and the grandchild share it.
   */
  children: SandboxKind;

  /**
   * Applied by the middle process after forking the grandchild.
   */
  child: SandboxKind;

  /**
   * Applied by the grandchild itself.
   */
  grandChild: SandboxKind;
}

/**
 * Mirrors the seven three process permutations from the upstream
 * scoped_multiple_domain_variants.h.
 */
const treeVariants: Record<string, TreeVariant> = {
  deny_scoped: { all: 'other', parent: 'none', children: 'scope', child: 'none', grandChild: 'none' },
  all_scoped: { all: 'scope', parent: 'none', children: 'scope', child: 'none', grandChild: 'none' },
  allow_with_other_domain: { all: 'other', parent: 'none', children: 'other', child: 'none', grandChild: 'none' },
  allow_with_one_domain: { all: 'none', parent: 'other', children: 'none', child: 'scope', grandChild: 'none' },
  allow_with_grand_parent_scoped: {
    all: 'none',
    parent: 'scope',
    children: 'none',
    child: 'other',
    grandChild: 'none',
  },
  allow_with_parents_domain: { all: 'none', parent: 'scope', children: 'none', child: 'scope', grandChild: 'none' },
  deny_with_self_and_grandparent_domain: {
    all: 'none',
    parent: 'scope',
    children: 'none',
    child: 'none',
    grandChild: 'scope',
  },
};

type Role = 'main' | 'child' | 'grandchild';

const testCases: Partial<Record<string, Partial<Record<Role, () => Promise<void>>>>> = {
  /**
   * Mirrors `scoping_signals.send_sig_to_parent`, looping over all four
   * upstream signal variants with a fresh child per signal.
   */
  signal_send_to_parent: {
    async main() {
      for (const signal of SCOPED_SIGNALS) {
        const waiter = signalWaiter(signal);
        const child = forkSelf('child', [signal]);
        const inbox = createInbox(child);

        // the child can signal the parent while its domain is not scoped
        await waiter.first;

        child.send('signaled');

        await inbox.expectNext({ denied: 'EPERM' });

        expect(await waitForExit(child)).toBe(0);

        // the signal sent after scoping never arrived
        expect(waiter.count()).toBe(1);

        waiter.dispose();
      }
    },

    async child() {
      const signal = roleArgs[0] as NodeJS.Signals;
      const inbox = createInbox(process);

      process.kill(process.ppid, signal);

      // waits until the parent confirms the delivery
      await inbox.expectNext('signaled');

      scopeSelf(['signal']);

      // the child cannot signal the parent anymore
      const denied = killCode(process.ppid, signal);

      // no matter the domain, a process can always signal itself
      const selfWaiter = signalWaiter(signal);

      process.kill(process.pid, signal);

      await selfWaiter.first;
      await sendToParent({ denied });
    },
  },

  /**
   * Covers the per thread semantics behind `signal_scoping_thread_before` and
   * `signal_scoping_thread_after`. restrictSelf() only restricts the calling
   * thread, so threads created before the restriction stay unrestricted while
   * threads created afterwards inherit the domain.
   */
  signal_worker_threads: {
    async main() {
      // the test runner that spawned this fixture is outside any scoped domain
      const outsidePid = process.ppid;

      const before = new Worker(KILL_PROBE_WORKER, { eval: true });

      expect(await askWorker(before, outsidePid)).toBe('ok');

      scopeSelf(['signal']);

      // the main thread is scoped now
      expect(killCode(outsidePid, 0)).toBe('EPERM');

      // the worker that already existed can still signal outside the domain
      expect(await askWorker(before, outsidePid)).toBe('ok');

      // a worker created after the restriction inherits the domain
      const after = new Worker(KILL_PROBE_WORKER, { eval: true });

      expect(await askWorker(after, outsidePid)).toBe('EPERM');

      // signaling the own process is always allowed
      expect(killCode(process.pid, 0)).toBe('ok');

      await before.terminate();
      await after.terminate();
    },
  },

  /**
   * Mirrors the stream parts of `various_address_sockets` for a scoped child.
   * Pathname sockets, the inherited IPC socketpair and connections that were
   * established before the restriction keep working, while new abstract
   * connections are denied.
   */
  unix_sockets_scoped: {
    main: () => unixSocketsMain(),
    child: () => unixSocketsChild('scope'),
  },

  /**
   * Mirrors `various_address_sockets.pathname_socket_other_domain`. A Landlock
   * domain without any handled scope restricts nothing here.
   */
  unix_sockets_other_domain: {
    main: () => unixSocketsMain(),
    child: () => unixSocketsChild('other'),
  },

  // mirrors `various_address_sockets.pathname_socket_no_domain`
  unix_sockets_no_domain: {
    main: () => unixSocketsMain(),
    child: () => unixSocketsChild('none'),
  },

  /**
   * Mirrors the intent of `self_connect`. The listening socket itself is
   * transferred to the child over IPC, and holding it still does not permit
   * connecting to its abstract address from inside a scoped domain.
   */
  unix_self_connect: {
    async main() {
      const name = abstractName('self');
      const server = await listenUnix(toAbstract(name));
      const child = forkSelf('child', [name]);

      child.send('server', server);

      expect(await waitForExit(child)).toBe(0);

      await closeServer(server);
    },

    async child() {
      const [name] = roleArgs;

      const server = await new Promise<net.Server>((resolve) => {
        process.once('message', (_message, handle) => {
          resolve(handle as net.Server);
        });
      });

      expect(server).toBeInstanceOf(net.Server);

      scopeSelf(['abstract_unix_socket']);

      // holding the listening socket does not permit connecting to its address
      expect(await connectCode(toAbstract(name))).toBe('EPERM');

      server.close();
    },
  },

  /**
   * Mirrors the combined scoped attribute used by the upstream `scoped_audit`
   * variants. A single ruleset handles both scopes and enforces them at the
   * same time.
   */
  both_scopes: {
    async main() {
      const name = abstractName('both');
      const waiter = signalWaiter('SIGURG');
      const server = await listenUnix(toAbstract(name));
      const child = forkSelf('child', [name]);
      const inbox = createInbox(child);

      await waiter.first;

      child.send('signaled');

      await inbox.expectNext({ signal: 'EPERM', connect: 'EPERM' });

      expect(await waitForExit(child)).toBe(0);
      expect(waiter.count()).toBe(1);

      waiter.dispose();
      await closeServer(server);
    },

    async child() {
      const [name] = roleArgs;
      const inbox = createInbox(process);

      // both actions work before the restriction
      process.kill(process.ppid, 'SIGURG');

      await inbox.expectNext('signaled');

      const socket = await connectUnix(toAbstract(name));

      socket.destroy();

      scopeSelf(['signal', 'abstract_unix_socket']);

      // both scopes are enforced by the single ruleset
      const signal = killCode(process.ppid, 'SIGURG');
      const connect = await connectCode(toAbstract(name));

      await sendToParent({ signal, connect });
    },
  },
};

for (const [name, variant] of Object.entries(domainVariants)) {
  /**
   * Mirrors `scoped_domains.check_access_signal` for this variant. Both
   * directions are checked with the null signal, exactly like upstream.
   */
  testCases[`signal_domains_${name}`] = {
    async main() {
      if (variant.both) {
        scopeSelf(['signal']);
      }

      const child = forkSelf('child');
      const inbox = createInbox(child);

      if (variant.parent) {
        scopeSelf(['signal']);
      }

      await inbox.expectNext('ready');

      // the parent can signal the child unless the parent is in its own domain
      checkKill(pidOf(child), !variant.parent);

      // a process can always signal itself
      expect(killCode(process.pid, 0)).toBe('ok');

      child.send('go');

      expect(await waitForExit(child)).toBe(0);
    },

    async child() {
      const inbox = createInbox(process);

      if (variant.child) {
        scopeSelf(['signal']);
      }

      await sendToParent('ready');
      await inbox.expectNext('go');

      // the child can signal the parent unless the child is in its own domain
      checkKill(process.ppid, !variant.child);

      expect(killCode(process.pid, 0)).toBe('ok');
    },
  };

  /**
   * Mirrors the SOCK_STREAM halves of `scoped_domains.connect_to_parent` and
   * `scoped_domains.connect_to_child` for this variant. Both processes bind an
   * abstract socket and connect to the socket of the other one.
   */
  testCases[`unix_domains_${name}`] = {
    async main() {
      const parentName = abstractName('parent');
      const childName = abstractName('child');

      if (variant.both) {
        scopeSelf(['abstract_unix_socket']);
      }

      const child = forkSelf('child', [parentName, childName]);
      const inbox = createInbox(child);

      if (variant.parent) {
        scopeSelf(['abstract_unix_socket']);
      }

      const server = await listenUnix(toAbstract(parentName));

      child.send('parent_ready');

      await inbox.expectNext('child_ready');

      // the parent reaches the child socket unless the parent is in its own domain
      await checkConnect(toAbstract(childName), !variant.parent);

      child.send('go');

      expect(await waitForExit(child)).toBe(0);

      await closeServer(server);
    },

    async child() {
      const [parentName, childName] = roleArgs;
      const inbox = createInbox(process);

      if (variant.child) {
        scopeSelf(['abstract_unix_socket']);
      }

      // binding an abstract socket is never restricted, only reaching it is
      const server = await listenUnix(toAbstract(childName));

      await sendToParent('child_ready');
      await inbox.expectNext('parent_ready');
      await inbox.expectNext('go');

      // the child reaches the parent socket unless the child is in its own domain
      await checkConnect(toAbstract(parentName), !variant.child);

      await closeServer(server);
    },
  };
}

for (const [name, variant] of Object.entries(treeVariants)) {
  /**
   * Mirrors `scoped_vs_unscoped.unix_scoping` for this variant. A grandchild
   * connects to the abstract sockets of its parent and grandparent while the
   * three processes carry the domain layout of the variant.
   */
  testCases[`unix_tree_${name}`] = {
    async main() {
      const parentName = abstractName('tree-parent');
      const childName = abstractName('tree-child');

      applyDomain(variant.all);

      const child = forkSelf('child', [parentName, childName]);

      applyDomain(variant.parent);

      const server = await listenUnix(toAbstract(parentName));

      child.send('parent_ready');

      expect(await waitForExit(child)).toBe(0);

      await closeServer(server);
    },

    async child() {
      const [parentName, childName] = roleArgs;
      const inbox = createInbox(process);

      applyDomain(variant.children);

      const grandChild = forkSelf('grandchild', [parentName, childName]);

      applyDomain(variant.child);

      const server = await listenUnix(toAbstract(childName));

      grandChild.send('child_ready');

      // relays the notification that the grandparent socket is listening
      await inbox.expectNext('parent_ready');
      grandChild.send('parent_ready');

      expect(await waitForExit(grandChild)).toBe(0);

      await closeServer(server);
    },

    async grandchild() {
      const [parentName, childName] = roleArgs;
      const inbox = createInbox(process);

      applyDomain(variant.grandChild);

      /**
       * A scoped grandchild reaches nothing outside its own domain. An
       * unscoped grandchild reaches its parent unless the parent bound the
       * socket inside a scope that excludes the grandchild, which happens
       * when the middle process scoped itself before forking.
       */
      const canConnectToChild = variant.grandChild !== 'scope';
      const canConnectToParent = canConnectToChild && variant.children !== 'scope';

      await inbox.expectNext('child_ready');
      await checkConnect(toAbstract(childName), canConnectToChild);

      await inbox.expectNext('parent_ready');
      await checkConnect(toAbstract(parentName), canConnectToParent);
    },
  };
}

if (!isLandlockSupported()) {
  process.exit(1);
}

const supportedScopes = scopesFromAbi(getAbiVersion());

if (!supportedScopes.includes('signal') || !supportedScopes.includes('abstract_unix_socket')) {
  process.exit(1);
}

const testCase = testCases[caseName];
const fn = testCase?.[role as Role];

if (!fn) {
  throw new Error(`Unknown scope test case: ${caseName} (role ${role})`);
}

await fn();

process.exit(0);

/**
 * Shared main logic for the unix_sockets_* cases. The parent stays
 * unrestricted, serves a pathname socket and an abstract socket, and waits for
 * the child to finish its checks.
 */
async function unixSocketsMain(): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'landlock-scope-'));
  const sockPath = path.join(dir, 'pathname.sock');
  const name = abstractName('various');

  const pathServer = await listenUnix(sockPath);
  const abstractServer = await listenUnix(toAbstract(name));

  const child = forkSelf('child', [sockPath, name]);
  const inbox = createInbox(child);

  // the inherited IPC socketpair still transmits from inside the domain
  await inbox.expectNext('done');

  expect(await waitForExit(child)).toBe(0);

  await closeServer(pathServer);
  await closeServer(abstractServer);

  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Shared child logic for the unix_sockets_* cases. The child enters the given
 * sandbox and checks which address families stay reachable.
 */
async function unixSocketsChild(kind: SandboxKind): Promise<void> {
  const [sockPath, name] = roleArgs;

  // connects before any restriction so the established stream can be checked later
  const held = await connectUnix(toAbstract(name));

  held.on('error', () => {});

  applyDomain(kind);

  // pathname sockets are not covered by the abstract unix socket scope
  const pathSocket = await connectUnix(sockPath);

  await echoByte(pathSocket);
  pathSocket.destroy();

  // new abstract connections are denied only inside a scoped domain
  if (kind === 'scope') {
    expect(await connectCode(toAbstract(name))).toBe('EPERM');
  } else {
    const socket = await connectUnix(toAbstract(name));

    await echoByte(socket);
    socket.destroy();
  }

  // data still flows on the abstract connection established before the domain
  await echoByte(held);
  held.destroy();

  await sendToParent('done');
}

/**
 * Handles the given scopes with a single ruleset and restricts the current
 * process.
 */
function scopeSelf(scopes: Scope[]): void {
  const ruleset = new LandlockRuleset();

  ruleset.setCompatibility('hard_requirement');
  ruleset.handleScopes(scopes);
  ruleset.create();

  const status = ruleset.restrictSelf();

  expect(status.ruleset).toBe('fully_enforced');
  expect(status.no_new_privs).toBe(true);
}

/**
 * Puts the current process in a Landlock domain that handles no scope at all,
 * mirroring create_fs_domain() from the upstream tests. Such a domain must
 * not restrict signals or abstract unix sockets.
 */
function restrictFsOnly(): void {
  const ruleset = new LandlockRuleset();

  ruleset.setCompatibility('hard_requirement');
  ruleset.handleFsAccess(['read_dir']);
  ruleset.create();

  const status = ruleset.restrictSelf();

  expect(status.ruleset).toBe('fully_enforced');
}

/**
 * Applies the sandbox kind of a variant to the current process.
 */
function applyDomain(kind: SandboxKind): void {
  if (kind === 'scope') {
    scopeSelf(['abstract_unix_socket']);
  } else if (kind === 'other') {
    restrictFsOnly();
  }
}

/**
 * Forks this fixture again with the same case name and the given role.
 */
function forkSelf(childRole: Role, args: string[] = []): ChildProcess {
  return fork(import.meta.filename, [caseName, childRole, ...args]);
}

/**
 * Waits until the given child process exits and returns its exit code.
 */
function waitForExit(child: ChildProcess): Promise<number | null> {
  return new Promise((resolve) =>
    child.once('exit', (code) => {
      resolve(code);
    }),
  );
}

/**
 * Returns the pid of a forked child process.
 */
function pidOf(child: ChildProcess): number {
  if (child.pid === undefined) {
    throw new Error('Child process has no pid');
  }

  return child.pid;
}

/**
 * Sends an IPC message to the parent process and waits until it is flushed,
 * so exiting right afterwards cannot lose it.
 */
function sendToParent(message: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    process.send?.(message, (error: Error | null) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

/**
 * Buffers IPC messages from the given emitter so they can be awaited in order
 * without racing the message events.
 */
function createInbox(source: NodeJS.EventEmitter) {
  const queue: unknown[] = [];
  const waiters: ((message: unknown) => void)[] = [];

  source.on('message', (message: unknown) => {
    const waiter = waiters.shift();

    if (waiter) {
      waiter(message);
    } else {
      queue.push(message);
    }
  });

  return {
    next(): Promise<unknown> {
      if (queue.length > 0) {
        return Promise.resolve(queue.shift());
      }

      return new Promise((resolve) => waiters.push(resolve));
    },

    async expectNext(expected: unknown): Promise<void> {
      expect(await this.next()).toEqual(expected);
    },
  };
}

/**
 * Returns a unique abstract socket name without its leading NUL byte, so it
 * can travel through argv.
 */
function abstractName(tag: string): string {
  return `landlock-scope-${process.pid}-${tag}`;
}

/**
 * Prepends the NUL byte that marks a unix socket address as abstract.
 */
function toAbstract(name: string): string {
  return `\0${name}`;
}

/**
 * Creates a unix stream server on the given address that echoes all data back.
 */
function listenUnix(address: string): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.on('error', () => {});
      socket.on('data', (data) => socket.write(data));
    });

    server.once('error', reject);

    server.listen(address, () => {
      resolve(server);
    });
  });
}

/**
 * Opens a unix stream connection to the given address.
 */
function connectUnix(address: string): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(address);

    socket.once('connect', () => {
      resolve(socket);
    });

    socket.once('error', reject);
  });
}

/**
 * Attempts to connect to the given unix socket address and returns "ok" or
 * the error code of the failure.
 */
async function connectCode(address: string): Promise<string> {
  try {
    const socket = await connectUnix(address);

    socket.destroy();

    return 'ok';
  } catch (error) {
    return (error as NodeJS.ErrnoException).code ?? 'unknown';
  }
}

/**
 * Expects a connection to the given unix socket address to either succeed or
 * be denied by Landlock with EPERM.
 */
async function checkConnect(address: string, allowed: boolean): Promise<void> {
  expect(await connectCode(address)).toBe(allowed ? 'ok' : 'EPERM');
}

/**
 * Writes one byte to the socket and waits for the echo.
 */
function echoByte(socket: net.Socket): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.once('data', (data) => {
      expect(data.toString()).toBe('.');
      resolve();
    });

    socket.once('error', reject);
    socket.write('.');
  });
}

/**
 * Closes a server and waits until it is fully closed.
 */
function closeServer(server: net.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

/**
 * Sends the given signal to the given pid and returns "ok" or the error code
 * of the failure.
 */
function killCode(pid: number, signal: number | NodeJS.Signals): string {
  try {
    process.kill(pid, signal);

    return 'ok';
  } catch (error) {
    return (error as NodeJS.ErrnoException).code ?? 'unknown';
  }
}

/**
 * Expects the null signal to the given pid to either be deliverable or be
 * denied by Landlock with EPERM.
 */
function checkKill(pid: number, allowed: boolean): void {
  expect(killCode(pid, 0)).toBe(allowed ? 'ok' : 'EPERM');
}

/**
 * Installs a handler for the given signal and exposes a promise for the first
 * delivery plus a counter for later assertions.
 */
function signalWaiter(signal: NodeJS.Signals) {
  let count = 0;

  const { promise: first, resolve: resolveFirst }: PromiseWithResolvers<void> = Promise.withResolvers();

  const handler = () => {
    count += 1;
    resolveFirst();
  };

  process.on(signal, handler);

  return {
    first,
    count: () => count,
    dispose: () => process.removeListener(signal, handler),
  };
}

/**
 * Asks a kill probe worker to send the null signal to the given pid and
 * returns "ok" or the reported error code.
 */
function askWorker(worker: Worker, pid: number): Promise<unknown> {
  return new Promise((resolve) => {
    worker.once('message', resolve);
    worker.postMessage(pid);
  });
}
