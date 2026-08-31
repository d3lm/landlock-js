import { doesNotThrow, rejects } from 'node:assert';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { LandlockRuleset, getAbiVersion, isLandlockSupported, netAccessFromAbi } from '../dist/index.mjs';

const __filename = new URL(import.meta.url).pathname;
const __dirname = path.dirname(__filename);

console.log(__dirname);

// check if Landlock is supported
if (!isLandlockSupported()) {
  console.error('Landlock is not supported on this system!');
  console.error('Make sure you are running Linux kernel 5.13 or later.');
  process.exit(1);
}

// get ABI version supported by the kernel
const abi = getAbiVersion();

console.log(`Landlock ABI version: ${abi}`);

// create a ruleset builder
const ruleset = new LandlockRuleset();

ruleset.setCompatibility('hard_requirement');

// set network access rights that are supported by the ABI
ruleset.handleNetAccess(netAccessFromAbi(abi));

ruleset.create();

ruleset.addNetPortRule(8080, ['bind_tcp']);

const status = ruleset.restrictSelf();

console.log(status);

doesNotThrow(async () => {
  await new Promise<void>((resolve, reject) => {
    const server = http.createServer((request, response) => {
      response.end('Hello from restricted server!');
    });

    server.listen(8080);

    server.on('listening', () => {
      server.close();
      resolve();
    });

    server.on('error', reject);
  });
});

rejects(async () => {
  await new Promise<void>((resolve, reject) => {
    const server = http.createServer((request, response) => {
      response.end('Hello from restricted server!');
    });

    server.listen(8081);

    server.on('listening', () => {
      resolve();
    });

    server.on('error', reject);
  });
}, /EACCES: permission denied 0.0.0.0:8081/);

rejects(
  async () => {
    const client = net.createConnection({ port: 443, host: 'google.com' });

    await new Promise<void>((resolve, reject) => {
      client.on('connect', () => {
        client.end();
        resolve();
      });

      client.on('error', reject);
    });
  },
  (error: unknown) => {
    console.log(error instanceof AggregateError ? error.errors : error);

    return true;
  },
);
