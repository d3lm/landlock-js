/**
 * Landlock ABI version.
 */
export type ABI = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11;

/**
 * File system access rights.
 *
 * @see https://man7.org/linux/man-pages/man7/landlock.7.html
 */
export type FsAccess =
  | 'execute'
  | 'write_file'
  | 'read_file'
  | 'read_dir'
  | 'remove_dir'
  | 'remove_file'
  | 'make_char'
  | 'make_dir'
  | 'make_reg'
  | 'make_sock'
  | 'make_fifo'
  | 'make_block'
  | 'make_sym'
  | 'refer'
  | 'truncate'
  | 'ioctl_dev'
  | 'resolve_unix';

/**
 * Network access rights.
 *
 * @see https://man7.org/linux/man-pages/man7/landlock.7.html
 */
export type NetAccess = 'bind_tcp' | 'connect_tcp';

/**
 * Scope access rights.
 *
 * @see https://man7.org/linux/man-pages/man7/landlock.7.html
 */
export type Scope = 'signal' | 'abstract_unix_socket';

/**
 * Compatibility level for Landlock features.
 *
 * `best_effort`: Takes into account the build requests if they are supported by the running system,
 * or silently ignores them otherwise. Never returns a compatibility error.
 *
 * `soft_requirement`: Takes into account the build requests if they are supported by the running system,
 * or silently ignores the whole build object otherwise. Never returns a compatibility error. If not
 * supported, the call to `restrictSelf()` will return a `not_enforced` status.
 *
 * `hard_requirement`: Takes into account the build requests if they are supported by the running system,
 * or returns a compatibility error otherwise.
 */
export type CompatibilityLevel = 'best_effort' | 'soft_requirement' | 'hard_requirement';

/**
 * Flags accepted by `restrictSelf()`, grouped by the ABI version that
 * introduced them. The three logging flags arrived with ABI 7 and
 * `all_threads` arrived with ABI 8.
 *
 * @see https://man7.org/linux/man-pages/man2/landlock_restrict_self.2.html
 */
export type RestrictFlag = 'log_same_exec' | 'log_new_exec' | 'log_subdomains' | 'all_threads';

/**
 * Status of ruleset enforcement.
 *
 * `fully_enforced`: All requested restrictions are enforced.
 *
 * `partially_enforced`: Some requested restrictions are enforced, following a best-effort approach.
 *
 * `not_enforced`: The running system doesn’t support Landlock or a subset of the requested Landlock features.
 */
export type RulesetStatus = 'not_enforced' | 'partially_enforced' | 'fully_enforced';

/**
 * Result of restricting the process.
 */
export interface RestrictionStatus {
  /**
   * Status of the Landlock ruleset enforcement.
   */
  ruleset: RulesetStatus;

  /**
   * Status of `prctl(2)`'s `PR_SET_NO_NEW_PRIVS` enforcement.
   */
  no_new_privs: boolean;

  /**
   * Reports whether denied accesses from the restricted thread and its
   * children are logged while they run the same executable.
   */
  log_same_exec: boolean;

  /**
   * Reports whether denied accesses are logged after an `execve(2)` call.
   */
  log_new_exec: boolean;

  /**
   * Reports whether denied accesses from nested Landlock domains are logged.
   */
  log_subdomains: boolean;

  /**
   * Reports whether the ruleset was enforced on all threads of the process
   * instead of only the calling thread.
   */
  all_threads: boolean;
}

/**
 * Options for `restrictSelf()`. Every option that maps to a kernel flag is
 * subject to the compatibility level of the ruleset, so requesting a
 * non-default value on a kernel that lacks the flag is silently ignored under
 * `best_effort` and throws under `hard_requirement`.
 */
export interface RestrictSelfOptions {
  /**
   * Logs denied accesses from the restricted thread and its children while
   * they run the same executable. Enabled by default. Disabling it requires
   * Landlock ABI 7 and is intended for programs that execute unknown code
   * without an `execve(2)` call, such as script interpreters.
   */
  log_same_exec?: boolean;

  /**
   * Logs denied accesses after an `execve(2)` call. Disabled by default.
   * Enabling it requires Landlock ABI 7.
   */
  log_new_exec?: boolean;

  /**
   * Logs denied accesses from nested Landlock domains created by the
   * restricted process or its descendants. Enabled by default. Disabling it
   * requires Landlock ABI 7.
   */
  log_subdomains?: boolean;

  /**
   * Enforces the ruleset atomically on all threads of the process instead of
   * only the calling thread. Disabled by default. Enabling it requires
   * Landlock ABI 8. Without it, threads that already exist when
   * `restrictSelf()` is called stay unrestricted.
   */
  all_threads?: boolean;

  /**
   * Sets `PR_SET_NO_NEW_PRIVS` as part of enforcement. Enabled by default.
   * The kernel requires either this attribute or `CAP_SYS_ADMIN` to enforce
   * a ruleset, so opting out in an unprivileged process makes
   * `restrictSelf()` fail with `EPERM`.
   */
  no_new_privs?: boolean;
}

/**
 * Options for `applyRestrictSelfFlags()`.
 */
export interface RestrictSelfFlagsOptions {
  /**
   * Logs denied accesses from nested Landlock domains. Enabled by default.
   * Disabling it requires Landlock ABI 7.
   */
  log_subdomains?: boolean;

  /**
   * Applies the logging configuration to all threads of the process. Disabled
   * by default. The kernel only accepts it on this ruleset-less path together
   * with `log_subdomains: false`, and only since Landlock ABI 9 (Linux 7.1).
   * On an ABI 8 kernel the flag itself passes the compatibility check, so no
   * level drops it, and the call throws with `EBADF` instead.
   */
  all_threads?: boolean;

  /**
   * Sets `PR_SET_NO_NEW_PRIVS` before applying the flags. Enabled by default.
   */
  no_new_privs?: boolean;

  /**
   * Sets how unsupported flags are treated, mirroring
   * `LandlockRuleset.setCompatibility()`. The default is `'best_effort'`.
   */
  compatibility?: CompatibilityLevel;
}

/**
 * Result of `applyRestrictSelfFlags()`. Every field reports the effective
 * state, so a flag that was dropped on an older kernel keeps its default
 * value here.
 */
export interface RestrictSelfFlagsStatus {
  /**
   * Status of `prctl(2)`'s `PR_SET_NO_NEW_PRIVS` enforcement.
   */
  no_new_privs: boolean;

  /**
   * Reports whether denied accesses from nested Landlock domains are logged.
   */
  log_subdomains: boolean;

  /**
   * Reports whether the configuration was applied to all threads.
   */
  all_threads: boolean;
}

/**
 * Path rule configuration.
 */
export interface PathRule {
  /**
   * Path to be restricted.
   */
  path: string;

  /**
   * File system access rights to be restricted.
   */
  access: FsAccess[];
}

/**
 * Network port rule configuration.
 */
export interface NetPortRule {
  /**
   * Port to be restricted.
   */
  port: number;

  /**
   * Network access rights to be restricted.
   */
  access: NetAccess[];
}

export interface NativeBinding {
  LandlockRuleset: new () => NativeLandlockRuleset;

  getAbiVersion(): number;
  getErrata(): number;
  isLandlockSupported(): boolean;
  applyRestrictSelfFlags(options?: RestrictSelfFlagsOptions): RestrictSelfFlagsStatus;
}

export interface NativeLandlockRuleset {
  handleFsAccess(access: string[]): void;
  handleNetAccess(access: string[]): void;
  handleScopes(scopes: Scope[]): void;
  addPathRule(path: string, access: string[]): void;
  addNetPortRule(port: number, access: string[]): void;
  setCompatibility(level: string): void;
  create(): void;
  restrictSelf(options?: RestrictSelfOptions): RestrictionStatus;
}
