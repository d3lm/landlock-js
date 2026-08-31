/**
 * Landlock ABI version.
 */
export type ABI = 0 | 1 | 2 | 3 | 4 | 5 | 6;

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
  | 'ioctl_dev';

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
  isLandlockSupported(): boolean;
}

export interface NativeLandlockRuleset {
  handleFsAccess(access: string[]): void;
  handleNetAccess(access: string[]): void;
  handleScopes(scopes: Scope[]): void;
  addPathRule(path: string, access: string[]): void;
  addNetPortRule(port: number, access: string[]): void;
  setCompatibility(level: string): void;
  create(): void;
  restrictSelf(): RestrictionStatus;
}
