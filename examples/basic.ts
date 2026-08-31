import { doesNotThrow, throws } from 'node:assert';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { LandlockRuleset, fsAccessFromAbi, getAbiVersion, isLandlockSupported } from '../dist/index.mjs';

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

// set file system access rights that are supported by the ABI
ruleset.handleFsAccess(fsAccessFromAbi(abi));

ruleset.create();

ruleset.addPathRule(__dirname, ['read_file']);

const status = ruleset.restrictSelf();

console.log(status);

doesNotThrow(() => {
  readFileSync(__filename, 'utf8');
});

throws(() => {
  readFileSync(path.join(__dirname, '../package.json'), 'utf8');
}, /EACCES: permission denied, open/);

throws(() => {
  mkdirSync(path.join(__dirname, 'foo'));
}, /EACCES: permission denied, mkdir/);
