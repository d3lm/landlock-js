import { familySync, MUSL } from 'detect-libc';
import { createRequire } from 'node:module';
import { _featuresfromAbi, FS_ACCESS, NET_ACCESS, RESTRICT_FLAGS, SCOPES } from './features';
import {
  ABI,
  CompatibilityLevel,
  FsAccess,
  NativeLandlockRuleset,
  NetAccess,
  NetPortRule,
  PathRule,
  RestrictionStatus,
  RestrictSelfFlagsOptions,
  RestrictSelfFlagsStatus,
  RestrictSelfOptions,
  Scope,
  type NativeBinding,
} from './types';

// re-export types
export * from './types';

const require = createRequire(import.meta.url);

const loadErrors: Error[] = [];

function tryRequire(id: string): NativeBinding | undefined {
  try {
    return require(id) as NativeBinding;
  } catch (error) {
    loadErrors.push(error instanceof Error ? error : new Error(String(error)));
    return undefined;
  }
}

function requireNative(): NativeBinding | undefined {
  if (process.platform !== 'linux') {
    return undefined;
  }

  const family = familySync();
  const isMusl = family === MUSL;

  if (process.arch === 'x64') {
    if (isMusl) {
      return tryRequire('./landlock-js.linux-x64-musl.node') ?? tryRequire('@landlock/landlock-js-linux-x64-musl');
    }

    return tryRequire('./landlock-js.linux-x64-gnu.node') ?? tryRequire('@landlock/landlock-js-linux-x64-gnu');
  }

  if (process.arch === 'arm64') {
    if (isMusl) {
      return tryRequire('./landlock-js.linux-arm64-musl.node') ?? tryRequire('@landlock/landlock-js-linux-arm64-musl');
    }

    return tryRequire('./landlock-js.linux-arm64-gnu.node') ?? tryRequire('@landlock/landlock-js-linux-arm64-gnu');
  }

  loadErrors.push(new Error(`Unsupported OS: ${process.platform}, architecture: ${process.arch}`));

  return undefined;
}

const _nativeBinding = requireNative();

if (!_nativeBinding) {
  if (loadErrors.length > 0) {
    let cause = loadErrors[0];

    for (const error of loadErrors.slice(1)) {
      error.cause = cause;
      cause = error;
    }

    throw new Error(
      `Cannot find native binding. ` +
        `npm has a bug related to optional dependencies (https://github.com/npm/cli/issues/4828). ` +
        'Please try `npm i` again after removing both package-lock.json and node_modules directory.',
      { cause },
    );
  }

  throw new Error('Failed to load native binding');
}

const nativeBinding = _nativeBinding;

/**
 * Landlock ruleset builder for creating security sandboxes.
 */
export class LandlockRuleset {
  #native: NativeLandlockRuleset;
  #created = false;
  #restricted = false;

  constructor() {
    this.#native = new nativeBinding.LandlockRuleset();
  }

  /**
   * Attempts to add a set of file system access rights that will be supported
   * by this ruleset. By default, all actions requiring these access rights will
   * be denied. Consecutive calls to `handleFsAccess()` will be interpreted as
   * logical ORs with the previous handled accesses.
   */
  handleFsAccess(access: FsAccess[]): this {
    if (this.#created) {
      throw new Error('Cannot modify ruleset after creation');
    }

    this.#native.handleFsAccess(access);

    return this;
  }

  /**
   * Attemps to add a set the network access rights that will be supported
   * by this ruleset. By default, all actions requiring these access rights will
   * be denied. Consecutive calls to `handleNetAccess()` will be interpreted as
   * logical ORs with the previous handled accesses.
   */
  handleNetAccess(access: NetAccess[]): this {
    if (this.#created) {
      throw new Error('Cannot modify ruleset after creation');
    }

    this.#native.handleNetAccess(access);

    return this;
  }

  /**
   * Attemps to add a set the scope access rights that will be supported
   * by this ruleset. By default, all actions requiring these access rights will
   * be denied. Consecutive calls to `handleScopes()` will be interpreted as logical
   * ORs with the previous handled accesses.
   */
  handleScopes(scopes: Scope[]) {
    if (this.#created) {
      throw new Error('Cannot modify ruleset after creation');
    }

    this.#native.handleScopes(scopes);

    return this;
  }

  /**
   * Add a path rule to allow specific access rights for a file or directory.
   */
  addPathRule(path: string, access: FsAccess[]): this {
    if (!this.#created) {
      throw new Error('Ruleset not created yet');
    }

    this.#native.addPathRule(path, access);

    return this;
  }

  /**
   * Add multiple path rules at once.
   */
  addPathRules(rules: PathRule[]): this {
    for (const rule of rules) {
      this.addPathRule(rule.path, rule.access);
    }

    return this;
  }

  /**
   * Add a network port rule to allow specific access rights for a port.
   */
  addNetPortRule(port: number, access: NetAccess[]): this {
    if (!this.#created) {
      throw new Error('Ruleset not created yet');
    }

    this.#native.addNetPortRule(port, access);

    return this;
  }

  /**
   * Add multiple network port rules at once.
   */
  addNetPortRules(rules: NetPortRule[]): this {
    for (const rule of rules) {
      this.addNetPortRule(rule.port, rule.access);
    }

    return this;
  }

  /**
   * Set the compatibility level for handling unsupported Landlock features.
   */
  setCompatibility(level: CompatibilityLevel): this {
    if (this.#created) {
      throw new Error('Cannot modify ruleset after creation');
    }

    this.#native.setCompatibility(level);

    return this;
  }

  /**
   * Create the ruleset. This must be called before `restrictSelf()`.
   */
  create(): this {
    if (this.#created) {
      throw new Error('Ruleset already created');
    }

    this.#native.create();

    this.#created = true;

    return this;
  }

  /**
   * Apply the ruleset restrictions to the current process. By default only
   * the calling thread is restricted, denied accesses are logged for code
   * running the same executable, and `PR_SET_NO_NEW_PRIVS` is set. All of
   * this can be changed through the options, subject to the kernel supporting
   * the matching restrict-self flag and to the compatibility level of the
   * ruleset.
   */
  restrictSelf(options?: RestrictSelfOptions): RestrictionStatus {
    if (!this.#created) {
      throw new Error('Ruleset must be created before restricting');
    }

    if (this.#restricted) {
      throw new Error('Process already restricted');
    }

    const status = this.#native.restrictSelf(options);

    this.#restricted = true;

    return status;
  }
}

/**
 * Returns the Landlock ABI version supported by the running kernel.
 */
export function getAbiVersion(): ABI {
  return nativeBinding.getAbiVersion() as ABI;
}

/**
 * Returns the bitmask of Landlock errata fixed in the running kernel, where
 * bit N-1 set means erratum N is fixed. Returns `0` when the kernel does not
 * support the errata query or Landlock is unavailable. Most applications
 * should not check errata, because disabling a feature over an unfixed
 * erratum usually leaves the system less secure than Landlock's best-effort
 * protection.
 *
 * @see https://docs.kernel.org/userspace-api/landlock.html#landlock-errata
 */
export function getErrata(): number {
  return nativeBinding.getErrata();
}

/**
 * Checks if Landlock is supported on the current system.
 */
export function isLandlockSupported(): boolean {
  return nativeBinding.isLandlockSupported();
}

/**
 * Applies restrict-self flags to the current process without enforcing a
 * ruleset, which maps to `landlock_restrict_self(2)` with a ruleset file
 * descriptor of -1. The kernel accepts `log_subdomains: false` on this path,
 * optionally combined with `all_threads: true` to propagate the logging
 * configuration to every thread of the process. This is useful for runtimes
 * that launch programs which create their own Landlock domains and would
 * otherwise flood the audit log.
 *
 * When no effective flag remains, for example because the kernel predates
 * ABI 7 and the default `'best_effort'` level dropped them, the syscall is
 * skipped and the returned status reports the kernel defaults.
 */
export function applyRestrictSelfFlags(options?: RestrictSelfFlagsOptions): RestrictSelfFlagsStatus {
  return nativeBinding.applyRestrictSelfFlags(options);
}

/**
 * Returns the file system access rights supported by the given Landlock ABI version.
 */
export function fsAccessFromAbi(abi: ABI) {
  return _featuresfromAbi(abi, FS_ACCESS);
}

/**
 * Returns the network access rights supported by the given Landlock ABI version.
 */
export function netAccessFromAbi(abi: ABI) {
  return _featuresfromAbi(abi, NET_ACCESS);
}

/**
 * Returns the scope access rights supported by the given Landlock ABI version.
 */
export function scopesFromAbi(abi: ABI) {
  return _featuresfromAbi(abi, SCOPES);
}

/**
 * Returns the restrict-self flags supported by the given Landlock ABI version.
 */
export function restrictFlagsFromAbi(abi: ABI) {
  return _featuresfromAbi(abi, RESTRICT_FLAGS);
}
