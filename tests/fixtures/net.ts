import { spawnSync } from 'node:child_process';
import * as dgram from 'node:dgram';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'vitest';
import {
  LandlockRuleset,
  getAbiVersion,
  isLandlockSupported,
  netAccessFromAbi,
  type NetPortRule,
} from '../../dist/index.mjs';

const IPV4 = '127.0.0.1';
const IPV6 = '::1';

const caseName = process.argv[2];

const testCases: Partial<Record<string, () => Promise<void>>> = {
  /**
   * Mirrors `protocol.bind` from the kernel selftests. The first port allows
   * bind and connect, the second port only allows connect, and the third port
   * has no rule at all.
   */
  async bind() {
    const [p0, p1, p2] = await freePorts(3);

    restrictNet([
      { port: p0, access: ['bind_tcp', 'connect_tcp'] },
      { port: p1, access: ['connect_tcp'] },
    ]);

    // bind and connect both work on the first port
    await checkRoundTrip(p0);

    // bind is denied on the second port because its rule only grants connect
    await expectErrorCode(listenOn(p1), 'EACCES');

    /**
     * Connect is allowed on the second port, so the failure comes from TCP
     * (nothing is listening) instead of Landlock.
     */
    await expectErrorCode(connectTo(p1), 'ECONNREFUSED');

    // everything is denied on the third port because it has no rule
    await expectErrorCode(listenOn(p2), 'EACCES');
    await expectErrorCode(connectTo(p2), 'EACCES');

    // binding an ephemeral port is denied because there is no rule for port 0
    await expectErrorCode(listenOn(0), 'EACCES');
  },

  /**
   * Mirrors `protocol.connect` from the kernel selftests. The first port
   * allows bind and connect, the second port only allows bind, and the third
   * port has no rule at all.
   */
  async connect() {
    const [p0, p1, p2] = await freePorts(3);

    restrictNet([
      { port: p0, access: ['bind_tcp', 'connect_tcp'] },
      { port: p1, access: ['bind_tcp'] },
    ]);

    await checkRoundTrip(p0);

    /**
     * Connect is denied on the second port even though a server is actually
     * listening, which proves the denial comes from Landlock and not from TCP.
     */
    const server = await listenOn(p1);

    await expectErrorCode(connectTo(p1), 'EACCES');
    await closeServer(server);

    await expectErrorCode(connectTo(p2), 'EACCES');
  },

  /**
   * Re-runs the bind and connect checks against the IPv6 loopback, mirroring
   * the ipv6 variants of `protocol.bind` and `protocol.connect`. Net port
   * rules apply to a port regardless of the address family.
   */
  async ipv6() {
    const [p0, p1, p2] = await freePortsDual(3);

    restrictNet([
      { port: p0, access: ['bind_tcp', 'connect_tcp'] },
      { port: p1, access: ['bind_tcp'] },
    ]);

    // bind and connect both work on the first port over IPv6
    await checkRoundTrip(p0, IPV6);

    // the same rule also covers IPv4 because rules are per port, not per address family
    await checkRoundTrip(p0, IPV4);

    // connect is denied on the second port even with a listening server
    const server = await listenOn(p1, IPV6);

    await expectErrorCode(connectTo(p1, IPV6), 'EACCES');
    await closeServer(server);

    // everything is denied on the third port
    await expectErrorCode(listenOn(p2, IPV6), 'EACCES');
    await expectErrorCode(connectTo(p2, IPV6), 'EACCES');
  },

  /**
   * Mirrors the UDP and unix socket variants of the `protocol` fixture. A
   * sandbox that only handles TCP rights must leave other protocols alone.
   */
  async unaffected_protocols() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'landlock-net-'));
    const sockPath = path.join(dir, 'test.sock');

    // handling both TCP rights with no rules denies all TCP bind and connect
    restrictNet([]);

    // a TCP bind is denied, which proves that the sandbox is enforced
    await expectErrorCode(listenOn(0), 'EACCES');

    // UDP sockets are unaffected because only TCP rights are handled
    const sender = dgram.createSocket('udp4');
    const receiver = dgram.createSocket('udp4');

    await new Promise<void>((resolve) => sender.bind(0, IPV4, resolve));
    await new Promise<void>((resolve) => receiver.bind(0, IPV4, resolve));

    const message = new Promise<Buffer>((resolve) => receiver.once('message', resolve));

    await new Promise<void>((resolve, reject) => {
      sender.send('U', receiver.address().port, IPV4, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });

    const datagram = await message;

    expect(datagram.toString()).toBe('U');

    // connected UDP sockets are unaffected as well
    await new Promise<void>((resolve, reject) => {
      sender.once('error', reject);
      sender.connect(receiver.address().port, IPV4, resolve);
    });

    sender.close();
    receiver.close();

    // unix domain sockets are unaffected
    const server = net.createServer((socket) => socket.end('.'));

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(sockPath, resolve);
    });

    const data = await new Promise<Buffer>((resolve, reject) => {
      const client = net.createConnection(sockPath);

      client.once('data', resolve);
      client.once('error', reject);
    });

    expect(data.toString()).toBe('.');

    await closeServer(server);

    fs.rmSync(dir, { recursive: true, force: true });
  },

  /**
   * Mirrors `tcp_layers.ruleset_overlap`. Rules for the same port within one
   * layer are unioned, while stacked layers are intersected.
   */
  async ruleset_overlap() {
    const [p0] = await freePorts(1);

    // the first layer adds two overlapping rules for the same port
    const layer1 = new LandlockRuleset();

    layer1.setCompatibility('hard_requirement');
    layer1.handleNetAccess(['bind_tcp', 'connect_tcp']);
    layer1.create();
    layer1.addNetPortRule(p0, ['bind_tcp']);
    layer1.addNetPortRule(p0, ['bind_tcp', 'connect_tcp']);
    layer1.restrictSelf();

    // both rules are unioned within the layer, so bind and connect work
    await checkRoundTrip(p0);

    // the second layer only allows bind on the same port
    const layer2 = new LandlockRuleset();

    layer2.setCompatibility('hard_requirement');
    layer2.handleNetAccess(['bind_tcp', 'connect_tcp']);
    layer2.create();
    layer2.addNetPortRule(p0, ['bind_tcp']);
    layer2.restrictSelf();

    // layers are intersected, so bind still works while connect is now denied
    const server = await listenOn(p0);

    await expectErrorCode(connectTo(p0), 'EACCES');
    await closeServer(server);
  },

  /**
   * Mirrors `tcp_layers.ruleset_expand`. A new layer can handle more access
   * rights than the previous ones, but it can never regain an access that an
   * earlier layer already denied.
   */
  async ruleset_expand() {
    const [p0, p1] = await freePorts(2);

    // the first layer only handles bind and allows it on the first port
    const layer1 = new LandlockRuleset();

    layer1.setCompatibility('hard_requirement');
    layer1.handleNetAccess(['bind_tcp']);
    layer1.create();
    layer1.addNetPortRule(p0, ['bind_tcp']);
    layer1.restrictSelf();

    // bind works on the first port and connect is not restricted at all yet
    await checkRoundTrip(p0);

    // bind is denied on the second port
    await expectErrorCode(listenOn(p1), 'EACCES');

    // the second layer expands the handled accesses with connect
    const layer2 = new LandlockRuleset();

    layer2.setCompatibility('hard_requirement');
    layer2.handleNetAccess(['bind_tcp', 'connect_tcp']);
    layer2.create();
    layer2.addNetPortRule(p0, ['bind_tcp', 'connect_tcp']);
    layer2.addNetPortRule(p1, ['bind_tcp']);
    layer2.restrictSelf();

    // bind and connect keep working on the first port
    await checkRoundTrip(p0);

    // bind on the second port stays denied because the first layer never allowed it
    await expectErrorCode(listenOn(p1), 'EACCES');

    /**
     * Connect on the second port is denied by the second layer. Landlock
     * checks run before TCP, so the error is EACCES and not ECONNREFUSED.
     */
    await expectErrorCode(connectTo(p1), 'EACCES');

    // the third layer handles both rights but only allows bind on the first port
    const layer3 = new LandlockRuleset();

    layer3.setCompatibility('hard_requirement');
    layer3.handleNetAccess(['bind_tcp', 'connect_tcp']);
    layer3.create();
    layer3.addNetPortRule(p0, ['bind_tcp']);
    layer3.restrictSelf();

    // bind still works on the first port while connect is now denied
    const server = await listenOn(p0);

    await expectErrorCode(connectTo(p0), 'EACCES');
    await closeServer(server);
  },

  /**
   * Mirrors `port_specific.bind_connect_zero`. A rule for port 0 allows
   * binding to a kernel assigned ephemeral port, and nothing else.
   */
  async bind_connect_zero() {
    const [p1] = await freePorts(1);

    restrictNet([{ port: 0, access: ['bind_tcp', 'connect_tcp'] }]);

    // binding port 0 is allowed and the kernel assigns an ephemeral port
    const server = await listenOn(0);
    const assigned = serverPort(server);

    expect(assigned).toBeGreaterThan(0);

    // the port 0 rule does not cover the assigned port, so connecting to it is denied
    await expectErrorCode(connectTo(assigned), 'EACCES');

    // the port 0 rule covers ephemeral binds only, not explicit ports
    await expectErrorCode(listenOn(p1), 'EACCES');

    await closeServer(server);
  },

  /**
   * Mirrors `ipv4_tcp.port_endianness` from the JavaScript side. Rule ports
   * must be interpreted in host byte order end to end, so a rule for the byte
   * swapped value of a port must not cover the port itself.
   */
  async port_endianness() {
    let port = 0;
    let swapped = 0;

    /**
     * Picks an ephemeral port whose byte swapped value is itself a free,
     * unprivileged port.
     */
    for (let attempt = 0; port === 0 && attempt < 50; attempt++) {
      const candidateServer = await listenOn(0);
      const candidate = serverPort(candidateServer);
      const candidateSwapped = ((candidate & 0xff) << 8) | ((candidate >> 8) & 0xff);

      if (candidateSwapped !== candidate && candidateSwapped >= 1024) {
        try {
          const swappedServer = await listenOn(candidateSwapped);

          await closeServer(swappedServer);

          port = candidate;
          swapped = candidateSwapped;
        } catch {
          // the swapped port is taken, so another candidate is tried
        }
      }

      await closeServer(candidateServer);
    }

    expect(port).toBeGreaterThan(0);

    restrictNet([{ port: swapped, access: ['bind_tcp'] }]);

    /**
     * If any layer mistakenly swapped bytes (like htons() would), the
     * original port would become bindable here.
     */
    await expectErrorCode(listenOn(port), 'EACCES');

    // the rule covers exactly the numeric port value that was passed in
    const server = await listenOn(swapped);

    await closeServer(server);
  },

  /**
   * Mirrors `ipv4_tcp.with_fs`. A single ruleset can handle file system and
   * network access rights at the same time, and both are enforced.
   */
  async with_fs() {
    const [p0, p1] = await freePorts(2);
    const allowedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'landlock-net-fs-'));

    fs.writeFileSync(path.join(allowedDir, 'file.txt'), 'content');

    const ruleset = new LandlockRuleset();

    ruleset.setCompatibility('hard_requirement');
    ruleset.handleFsAccess(['read_dir']);
    ruleset.handleNetAccess(['bind_tcp']);
    ruleset.create();
    ruleset.addPathRule(allowedDir, ['read_dir']);
    ruleset.addNetPortRule(p0, ['bind_tcp']);

    const status = ruleset.restrictSelf();

    expect(status.ruleset).toBe('fully_enforced');

    // listing the allowed directory works while other directories are denied
    expect(fs.readdirSync(allowedDir)).toEqual(['file.txt']);
    expect(() => fs.readdirSync(os.tmpdir())).toThrow(/EACCES/);

    /**
     * Bind is allowed on the first port only. Connect stays unrestricted
     * because it is not handled, so the round trip works.
     */
    await checkRoundTrip(p0);
    await expectErrorCode(listenOn(p1), 'EACCES');

    fs.rmSync(allowedDir, { recursive: true, force: true });
  },

  /**
   * Mirrors the pre-restriction connection checks in `protocol.connect_unspec`
   * and `protocol.sendmsg_dgram`. Sockets that were connected before the
   * restriction keep working, and only new bind and connect calls are denied.
   */
  async already_connected() {
    const [p0, p1] = await freePorts(2);

    const server = await listenOn(p0);
    const serverConnection = new Promise<net.Socket>((resolve) => server.once('connection', resolve));
    const client = await connectTo(p0);
    const peer = await serverConnection;

    // denies all TCP bind and connect from now on
    restrictNet([]);

    // the connection that was established before the restriction still works
    const receiving = new Promise<Buffer>((resolve) => peer.once('data', resolve));

    client.write('.');

    const received = await receiving;

    expect(received.toString()).toBe('.');

    const echoing = new Promise<Buffer>((resolve) => client.once('data', resolve));

    peer.write(',');

    const echoed = await echoing;

    expect(echoed.toString()).toBe(',');

    // new connections are denied even though the server is still listening
    await expectErrorCode(connectTo(p0), 'EACCES');

    // new servers are denied as well
    await expectErrorCode(listenOn(p1), 'EACCES');

    client.destroy();
    peer.destroy();

    await closeServer(server);
  },

  /**
   * Landlock restrictions are inherited by child processes, mirroring the
   * fork based checks used throughout the kernel suite.
   */
  async inherited() {
    const [p0, p1] = await freePorts(2);

    restrictNet([{ port: p0, access: ['bind_tcp'] }]);

    const script = [
      "const net = require('node:net');",
      'const server = net.createServer();',
      "server.once('error', (error) => console.log('LISTEN_' + error.code));",
      "server.listen(Number(process.argv[1]), '127.0.0.1', () => {",
      "  console.log('LISTEN_OK');",
      '  server.close();',
      '});',
    ].join('\n');

    const allowed = spawnSync(process.execPath, ['-e', script, String(p0)], { stdio: 'pipe' });

    expect(allowed.stdout.toString().trim()).toBe('LISTEN_OK');
    expect(allowed.status).toBe(0);

    const denied = spawnSync(process.execPath, ['-e', script, String(p1)], { stdio: 'pipe' });

    expect(denied.stdout.toString().trim()).toBe('LISTEN_EACCES');
    expect(denied.status).toBe(0);
  },
};

if (!isLandlockSupported()) {
  process.exit(1);
}

const supportedAccess = netAccessFromAbi(getAbiVersion());

if (!supportedAccess.includes('bind_tcp') || !supportedAccess.includes('connect_tcp')) {
  process.exit(1);
}

const fn = testCases[caseName];

if (!fn) {
  throw new Error(`Unknown network test case: ${caseName}`);
}

await fn();

process.exit(0);

/**
 * Handles both TCP access rights, allows the given port rules, and restricts
 * the current process. Handled rights without a matching rule are denied.
 */
function restrictNet(rules: NetPortRule[]) {
  const ruleset = new LandlockRuleset();

  ruleset.setCompatibility('hard_requirement');
  ruleset.handleNetAccess(['bind_tcp', 'connect_tcp']);
  ruleset.create();
  ruleset.addNetPortRules(rules);

  const status = ruleset.restrictSelf();

  expect(status.ruleset).toBe('fully_enforced');
  expect(status.no_new_privs).toBe(true);

  return status;
}

/**
 * Creates a TCP server listening on the given port and host.
 */
function listenOn(port: number, host: string = IPV4): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();

    server.once('error', reject);

    server.listen(port, host, () => {
      resolve(server);
    });
  });
}

/**
 * Opens a TCP connection to the given port and host.
 */
function connectTo(port: number, host: string = IPV4): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port, host });

    socket.once('connect', () => {
      resolve(socket);
    });

    socket.once('error', reject);
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
 * Returns the port a server is bound to.
 */
function serverPort(server: net.Server): number {
  return (server.address() as net.AddressInfo).port;
}

/**
 * Reserves distinct free ports by binding them all at once before closing
 * them again. This must run before the process is restricted.
 */
async function freePorts(count: number, host: string = IPV4): Promise<number[]> {
  const servers = await Promise.all(Array.from({ length: count }, () => listenOn(0, host)));
  const ports = servers.map((server) => serverPort(server));

  await Promise.all(servers.map((server) => closeServer(server)));

  return ports;
}

/**
 * Finds ports that are free on both the IPv4 and the IPv6 loopback. All
 * reserved servers are kept open until the last port is found so that the
 * same port is not handed out twice.
 */
async function freePortsDual(count: number): Promise<number[]> {
  const ports: number[] = [];
  const holds: net.Server[] = [];

  while (ports.length < count) {
    const v6Server = await listenOn(0, IPV6);
    const port = serverPort(v6Server);

    try {
      const v4Server = await listenOn(port, IPV4);

      holds.push(v4Server, v6Server);
      ports.push(port);
    } catch {
      await closeServer(v6Server);
    }
  }

  await Promise.all(holds.map((server) => closeServer(server)));

  return ports;
}

/**
 * Awaits the given action and expects it to fail with the given syscall
 * error code.
 */
async function expectErrorCode(action: Promise<unknown>, code: string): Promise<void> {
  let failure: unknown;

  try {
    await action;
  } catch (error) {
    failure = error;
  }

  expect((failure as NodeJS.ErrnoException | undefined)?.code).toBe(code);
}

/**
 * Binds a server to the given port, connects a client to it, and verifies
 * that a byte can be echoed back. This exercises both the bind_tcp and the
 * connect_tcp access rights, mirroring the data exchange the kernel
 * selftests perform in test_bind_and_connect().
 */
async function checkRoundTrip(port: number, host: string = IPV4): Promise<void> {
  const server = await listenOn(port, host);

  server.on('connection', (socket) => {
    socket.on('data', (data) => socket.end(data));
  });

  const client = await connectTo(port, host);

  const echoing = new Promise<Buffer>((resolve, reject) => {
    client.once('data', resolve);
    client.once('error', reject);
  });

  client.write('.');

  const echoed = await echoing;

  expect(echoed.toString()).toBe('.');

  client.destroy();
  await closeServer(server);
}
