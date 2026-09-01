# landlock-js

Node.js bindings for [Linux Landlock](https://docs.kernel.org/userspace-api/landlock.html), built on the official [landlock Rust crate](https://crates.io/crates/landlock) via [napi-rs](https://github.com/napi-rs/napi-rs).

Landlock lets an unprivileged process lock itself down. With this library a Node.js process can restrict which paths it may read, write, or execute, which TCP ports it may bind or connect to, and which processes it may signal or reach over UNIX sockets. It can also control how the kernel logs denied accesses and enforce a ruleset across all threads at once. The restrictions apply to the process and everything it spawns afterwards, and they can never be lifted again.

This is a practical hardening layer for AI agents, plugin hosts, CI runners, and other code you do not fully trust. It is not a complete sandbox on its own. Read [What Landlock Does Not Cover](#what-landlock-does-not-cover) before relying on it.

## Platform Support

This package works only on Linux. Importing it on macOS, Windows, or an architecture without a prebuilt binary throws immediately. It does not degrade gracefully and it does not build from source as a fallback. If your application also runs on other platforms, guard the import.

```typescript
if (process.platform === 'linux') {
  const { LandlockRuleset } = await import('landlock-js');
}
```

Prebuilt binaries are published for x64 and arm64, each in glibc and musl (Alpine) variants.

## Requirements

- Node.js 22 or later.
- A Linux kernel with Landlock enabled. Kernel 5.13 is the floor, but each feature group has its own minimum ABI version.

| Landlock ABI | Kernel | Features exposed by this library                                                  |
| ------------ | ------ | --------------------------------------------------------------------------------- |
| 1            | 5.13   | The base filesystem rights.                                                       |
| 2            | 5.19   | `refer` (reparenting files across directories).                                   |
| 3            | 6.2    | `truncate`.                                                                       |
| 4            | 6.7    | TCP network rules (`bind_tcp`, `connect_tcp`).                                    |
| 5            | 6.10   | `ioctl_dev`.                                                                      |
| 6            | 6.12   | Scopes (`signal`, `abstract_unix_socket`).                                        |
| 7            | 6.15   | Audit log control (`log_same_exec`, `log_new_exec`, `log_subdomains`) and errata. |
| 8            | 7.0    | Enforcement on threads that already exist (`all_threads`).                        |
| 9            | 7.1    | `resolve_unix` (pathname UNIX socket rules).                                      |

The newest ABI features (UDP rules and quiet log suppression in ABI 10, the atomic `no_new_privs` flag in ABI 11) are not exposed yet, because the [landlock crate](https://crates.io/crates/landlock) this library builds on does not support them so far.

Kernel support alone is not enough. Landlock must also be in the kernel's active LSM list. Most current distributions enable it, but you can verify by checking that `cat /sys/kernel/security/lsm` contains `landlock`, or by calling `isLandlockSupported()` at runtime.

## Installation

```bash
npm install landlock-js
```

The matching native binary is pulled in through optional dependencies. Note that npm has a [long-standing bug](https://github.com/npm/cli/issues/4828) around optional dependencies. If the import fails after switching platforms, remove `node_modules` and the lockfile and install again.

## Quick Start

Landlock uses a three step model:

1. Handle access rights. Every right you handle becomes deny-by-default.
2. Create the ruleset, then add rules that grant handled rights back for specific paths or ports.
3. Call `restrictSelf()`. Rights you never handled remain completely unrestricted.

```typescript
import { LandlockRuleset, fsAccessFromAbi, getAbiVersion, isLandlockSupported } from 'landlock-js';

if (!isLandlockSupported()) {
  throw new Error('Landlock is required but not supported on this system');
}

const ruleset = new LandlockRuleset();

// deny every filesystem right the running kernel knows about
ruleset.handleFsAccess(fsAccessFromAbi(getAbiVersion()));

ruleset.create();

// grant specific rights back for specific paths
ruleset.addPathRule('/app/data', ['read_file', 'write_file', 'truncate']);
ruleset.addPathRule('/app/config', ['read_file']);

const status = ruleset.restrictSelf();

console.log(status.ruleset); // 'fully_enforced'
```

### TCP Network Rules

```typescript
const ruleset = new LandlockRuleset();

ruleset.handleNetAccess(['bind_tcp', 'connect_tcp']);
ruleset.create();

// the process may bind port 8080 and connect to port 443, all other TCP binds and connects are denied
ruleset.addNetPortRule(8080, ['bind_tcp']);
ruleset.addNetPortRule(443, ['connect_tcp']);

ruleset.restrictSelf();
```

### Scopes

Scopes take no rules. Handling them confines the process to its own Landlock domain for the given interaction.

```typescript
const ruleset = new LandlockRuleset();

/**
 * Deny sending signals to, and connecting to abstract UNIX sockets of,
 * any process outside this Landlock domain.
 */
ruleset.handleScopes(['signal', 'abstract_unix_socket']);
ruleset.create();
ruleset.restrictSelf();
```

After restriction, denied operations surface as ordinary `EACCES` or `EPERM` errors from the Node.js APIs you already use.

## API Reference

### Functions

| Function                          | Description                                                                                      |
| --------------------------------- | ------------------------------------------------------------------------------------------------ |
| `isLandlockSupported()`           | Returns `true` when the kernel can create and enforce a basic ruleset.                           |
| `getAbiVersion()`                 | Returns the Landlock ABI version of the running kernel, or `0` when Landlock is unavailable.     |
| `getErrata()`                     | Returns the bitmask of fixed Landlock errata, or `0` when the kernel predates the query (ABI 7). |
| `applyRestrictSelfFlags(options)` | Applies restrict-self flags without enforcing a ruleset (see [Audit Logging](#audit-logging)).   |
| `fsAccessFromAbi(abi)`            | Returns every filesystem access right available at the given ABI version.                        |
| `netAccessFromAbi(abi)`           | Returns every network access right available at the given ABI version.                           |
| `scopesFromAbi(abi)`              | Returns every scope available at the given ABI version.                                          |
| `restrictFlagsFromAbi(abi)`       | Returns every restrict-self flag available at the given ABI version.                             |

Combine the `*FromAbi` helpers with `getAbiVersion()` to handle everything the running kernel supports.

### `LandlockRuleset`

All configuration methods return `this` for chaining. The lifecycle is enforced, so calling a method at the wrong time throws.

These methods configure the ruleset and must be called before `create()`:

- `handleFsAccess(access)` adds filesystem rights that the ruleset will deny by default. Consecutive calls are ORed together.
- `handleNetAccess(access)` does the same for TCP network rights.
- `handleScopes(scopes)` does the same for IPC scopes.
- `setCompatibility(level)` sets how unsupported features are treated (see below). The default is `'best_effort'`.

These methods require the ruleset to have been created with `create()`:

- `addPathRule(path, access)` grants the given rights beneath the given path. The path must exist and be openable at rule time.
- `addPathRules(rules)` adds multiple path rules at once.
- `addNetPortRule(port, access)` grants the given rights on the given TCP port.
- `addNetPortRules(rules)` adds multiple port rules at once.
- `restrictSelf(options?)` enforces the ruleset and returns a `RestrictionStatus`. This is irreversible and can be called once per instance. By default only the calling thread is restricted, denied accesses are logged for code running the same executable, and `PR_SET_NO_NEW_PRIVS` is set. The options change this, subject to kernel support and the compatibility level:
  - `all_threads` (ABI 8) enforces the ruleset on every thread of the process at once, including threads that already exist (see [Threads](#threads)).
  - `log_same_exec`, `log_new_exec`, and `log_subdomains` (ABI 7) control which denials the kernel emits as audit events (see [Audit Logging](#audit-logging)).
  - `no_new_privs: false` skips setting `PR_SET_NO_NEW_PRIVS`, which then requires the process to hold `CAP_SYS_ADMIN` in its namespace.

### Compatibility Levels

| Level                | Behavior                                                                                                                                                                                  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `'best_effort'`      | Applies every requested feature the kernel supports and silently ignores the rest. This never produces a compatibility error, which means an old kernel enforces less than you asked for. |
| `'soft_requirement'` | Silently disables the whole ruleset if any requested feature is unsupported. `restrictSelf()` then reports `'not_enforced'`.                                                              |
| `'hard_requirement'` | Makes any unsupported feature an error. Use this when the sandbox is security critical, and check for it in tests.                                                                        |

### `RestrictionStatus`

`restrictSelf()` returns an object describing what was actually enforced. `ruleset` is one of `'fully_enforced'`, `'partially_enforced'`, or `'not_enforced'`. Treat anything other than `'fully_enforced'` as a red flag in security critical code. `no_new_privs` reports whether `PR_SET_NO_NEW_PRIVS` was set, which `restrictSelf()` does as part of enforcement. A side effect worth knowing is that setuid binaries (like `sudo` or `ping`) spawned afterwards will not gain privileges. The remaining fields (`log_same_exec`, `log_new_exec`, `log_subdomains`, `all_threads`) report the effective state of each restrict-self flag, so on old kernels you can detect that a requested flag was dropped by `'best_effort'`.

### Audit Logging

On ABI 7+ kernels, denied accesses are logged as audit events. By default the kernel logs denials for code running the same executable, stops logging after `execve(2)`, and does not log denials from nested domains. Three flags on `restrictSelf()` tune this: `log_same_exec: false` quiets same-executable denials, `log_new_exec: true` keeps logging across `execve(2)`, and `log_subdomains: true` also logs denials from Landlock domains created by child processes.

A runtime that launches sandboxed programs, but creates no domain itself, can suppress subdomain logging without enforcing anything by calling `applyRestrictSelfFlags({ log_subdomains: false })`. This maps to `landlock_restrict_self(2)` with a ruleset file descriptor of `-1`, which the kernel accepts for exactly this flag. Since ABI 9 (Linux 7.1) it can be combined with `all_threads: true`, while ABI 8 kernels reject that pairing with `EBADF` because they support `all_threads` only together with a ruleset. Both functions take a `compatibility` level with the same semantics as the ruleset levels above. With the default `'best_effort'`, unsupported flags are dropped silently and the returned status shows what actually applied, but the `EBADF` rejection on ABI 8 is not a compatibility drop and throws under every level.

### Threads

A Landlock domain is attached to the credentials of a thread, not to the process. `restrictSelf()` therefore restricts the thread that calls it. Every thread and child process created afterwards starts out with a copy of those credentials and inherits the domain, so spawning a new thread after the call is not a way out of the sandbox on any kernel version.

Threads that already exist when `restrictSelf()` is called are a different matter. They keep their old, unrestricted credentials, and nothing the calling thread does afterwards can reach them. On kernels below ABI 8 this leaves a hole that can only be avoided by ordering, which means calling `restrictSelf()` before any other thread exists. In a Node.js process the threads that matter are worker threads and the libuv thread pool, both covered in [Node.js Specific Caveats](#nodejs-specific-caveats).

On ABI 8+ kernels, `restrictSelf({ all_threads: true })` enforces the ruleset on every thread of the process atomically, including the ones that already exist, which removes the ordering constraint. On older kernels `'best_effort'` drops the flag silently and confines only the calling thread, so check `all_threads` in the returned status or use `'hard_requirement'` when you depend on it.

### Filesystem Access Rights

| Right          | ABI | What a rule grants                                                                                                            |
| -------------- | --- | ----------------------------------------------------------------------------------------------------------------------------- |
| `execute`      | 1   | Execute a file.                                                                                                               |
| `write_file`   | 1   | Open a file with write access. Pair it with `truncate`, because overwriting usually truncates.                                |
| `read_file`    | 1   | Open a file with read access.                                                                                                 |
| `read_dir`     | 1   | Open a directory or list its content.                                                                                         |
| `remove_dir`   | 1   | Remove an empty directory or rename one.                                                                                      |
| `remove_file`  | 1   | Unlink or rename a file.                                                                                                      |
| `make_char`    | 1   | Create, rename, or link a character device.                                                                                   |
| `make_dir`     | 1   | Create or rename a directory.                                                                                                 |
| `make_reg`     | 1   | Create, rename, or link a regular file.                                                                                       |
| `make_sock`    | 1   | Create, rename, or link a UNIX domain socket.                                                                                 |
| `make_fifo`    | 1   | Create, rename, or link a named pipe.                                                                                         |
| `make_block`   | 1   | Create, rename, or link a block device.                                                                                       |
| `make_sym`     | 1   | Create, rename, or link a symbolic link.                                                                                      |
| `refer`        | 2   | Link or rename a file from one directory into another. On ABI 1 kernels, sandboxed processes can never reparent files at all. |
| `truncate`     | 3   | Truncate a file with `truncate(2)`, `ftruncate(2)`, `creat(2)`, or `open(2)` with `O_TRUNC`.                                  |
| `ioctl_dev`    | 5   | Invoke `ioctl(2)` commands on device files opened after sandboxing.                                                           |
| `resolve_unix` | 9   | Connect or send datagrams to a pathname UNIX socket. Like scopes, this only affects sockets created outside the domain.       |

### Network Access Rights

| Right         | ABI | What a rule grants                             |
| ------------- | --- | ---------------------------------------------- |
| `bind_tcp`    | 4   | Bind a TCP socket to the given local port.     |
| `connect_tcp` | 4   | Connect a TCP socket to the given remote port. |

A rule for port `0` allows binding to an ephemeral port. `server.listen(0)` and `server.listen()` need such a rule when `bind_tcp` is handled. Outbound connections need `connect_tcp` on the destination port only, never `bind_tcp`.

### Scopes

| Scope                  | ABI | What handling it denies                                                          |
| ---------------------- | --- | -------------------------------------------------------------------------------- |
| `signal`               | 6   | Sending signals to processes outside the same or a nested Landlock domain.       |
| `abstract_unix_socket` | 6   | Connecting to abstract UNIX sockets created outside the same or a nested domain. |

## Node.js Specific Caveats

These follow from how Landlock and the Node.js runtime interact:

- **Restrict as early as possible.** Without `all_threads`, `restrictSelf()` confines only the calling thread and whatever is created after it (see [Threads](#threads)). Worker threads started before the call bypass the sandbox entirely (the test suite proves this). The same goes for the libuv thread pool, which services async `fs`, `dns.lookup`, and some `crypto` and `zlib` calls. The pool spawns lazily on the first such call and its threads then live for the rest of the process. If any async I/O ran before `restrictSelf()`, every later async `fs` call from JavaScript is serviced by unrestricted threads, so `fs.readdirSync('/etc')` fails with `EACCES` while `fs.promises.readdir('/etc')` succeeds. Call `restrictSelf()` before starting workers and before any async I/O. On ABI 8+ kernels, `restrictSelf({ all_threads: true })` closes this gap by restricting every existing thread atomically.
- **Module loading needs read access.** `require()` and dynamic `import()` after restriction are ordinary file reads. If you handle `read_file` and `read_dir`, grant them on your application code and `node_modules`, or lazy loading will fail with `EACCES`.
- **Child processes are confined too.** Anything spawned after restriction inherits the domain and cannot escape it. This is usually what you want, but remember it when shelling out to system tools.
- **DNS keeps working.** Landlock mediates only TCP `bind(2)` and `connect(2)`. Typical DNS runs over UDP and is unaffected even when every TCP connect is denied. Do not mistake a successful lookup for network access.

## What Landlock Does Not Cover

Landlock is a solid kernel primitive with a deliberately narrow scope. A Landlock ruleset alone is not a sandbox. These are the gaps:

- **Unmediated syscalls.** Landlock has no access rights for `stat(2)` and friends, `access(2)`, `chdir(2)`, `chmod(2)`, `chown(2)`, `setxattr(2)`, file locking, or timestamp changes. A sandboxed process can still probe which paths exist, walk directories, and change metadata on anything regular DAC permissions allow.
- **Pre-existing file descriptors.** Enforcement happens at open time. Any FD opened before `restrictSelf()`, including `stdin`, `stdout`, `stderr`, and inherited or passed sockets, keeps its capabilities forever. An already-connected TCP socket can exchange data freely regardless of network rules.
- **Non-TCP networking.** UDP, ICMP, raw sockets, and traffic on allowed connections are untouched. There is no packet or payload filtering. (ABI 10 kernels can restrict UDP, but this library does not expose that yet.)
- **Resource exhaustion.** There are no limits on processes, memory, CPU, or file descriptors. Fork bombs and memory exhaustion need rlimits and cgroups.
- **Memory safety.** Landlock limits what compromised code can reach, not whether the code can be compromised in the first place.
- **Special filesystems.** Files reachable through `/proc/<pid>/fd/*` and kernel filesystems like nsfs cannot be explicitly restricted, although Landlock's ptrace rules confine the most sensitive `/proc` entries to the domain hierarchy.

Rulesets stack up to 16 layers per thread, and each layer can only remove rights. Restrict once and deliberately rather than incrementally.

Landlock is also not a replacement for [seccomp-bpf](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html), which it is often mentioned alongside. seccomp filters which syscalls a process may invoke, and it can only inspect syscall numbers and raw argument values, so it cannot tell which file a path refers to. Landlock does not care which syscall is used and instead controls which kernel objects (file hierarchies, TCP ports) the process can reach through them. Use seccomp-bpf to shrink the kernel's attack surface and Landlock to scope file and network access. The two compose without interfering.

Do not rely on Landlock alone for executing hostile code or for multi-tenant isolation. For serious containment, combine it with seccomp-bpf, namespaces, cgroups, rlimits, and dropped capabilities.

## Test Coverage

The test suites are direct ports of the kernel's own Landlock selftests (`tools/testing/selftests/landlock/`), reproduced as faithfully as pure Node.js APIs allow.

- `tests/fs.test.ts` mirrors `fs_test.c`. Every one of the 17 filesystem access rights has a dedicated enforcement test, including `resolve_unix` against pathname UNIX sockets, plus scenarios for ruleset layering and for unhandled rights staying unrestricted.
- `tests/net.test.ts` mirrors `net_test.c`, covering bind and connect enforcement, IPv6, UDP and UNIX sockets staying unaffected, ruleset overlap and expansion across layers, ephemeral port rules, port endianness, combined filesystem and network rulesets, pre-connected sockets, inheritance by child processes, and rule validation errors.
- `tests/scope.test.ts` mirrors `scoped_signal_test.c` and `scoped_abstract_unix_test.c`, including all eight parent and child domain permutations, all seven three-process tree permutations, and the per-thread semantics of worker threads created before and after restriction.
- `tests/restrict.test.ts` covers the restrict-self flags following `audit_test.c` where Node.js allows: status reporting and best-effort dropping of the logging flags, `all_threads` confining pre-existing worker threads, the domain-less `applyRestrictSelfFlags()` path, `no_new_privs` opt-out, compatibility level handling per flag, and the errata query.
- `tests/abi.test.ts` guards CI against silent skips. The suites skip whatever the running kernel cannot do, so CI pins the expected ABI per kernel and fails loudly if the bindings report less.

Every test that enforces a ruleset runs in a fresh subprocess, because enforcement is irreversible.

CI boots real mainline kernels with [virtme-ng](https://github.com/arighi/virtme-ng) and runs the full suite once per ABI tier, on Linux 5.15, 6.1, 6.2, 6.7, 6.10, 6.12, 6.15, 7.0, and 7.1 (Landlock ABI 1 through 9). Additional jobs run the suite on Alpine (musl) for x64 and arm64 and on arm64 glibc, so every published binary target is exercised.

Some upstream selftests cannot be reproduced from Node.js because they need raw syscall access, for example `renameat2(2)` with `RENAME_EXCHANGE`, `O_PATH` opens, mount topology changes, FD passing over `SCM_RIGHTS`, `MSG_FASTOPEN`, MPTCP, and datagram UNIX sockets. Each test file documents exactly which upstream cases it covers and which it cannot.

## Development

```bash
pnpm install

pnpm build

pnpm test

pnpm lint
```

The examples in `examples/` import from `dist/` and can be run directly after a build.

```bash
node --experimental-strip-types examples/basic.ts
node --experimental-strip-types examples/network.ts
```

## License

`landlock-js` is licensed under the [MIT License](LICENSE).
