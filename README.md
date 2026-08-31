# landlock-js

Node.js bindings for [Linux Landlock](https://docs.kernel.org/userspace-api/landlock.html), built on the official [landlock Rust crate](https://crates.io/crates/landlock) via [napi-rs](https://github.com/napi-rs/napi-rs).

Landlock lets an unprivileged process lock itself down. With this library a Node.js process can restrict which paths it may read, write, or execute, which TCP ports it may bind or connect to, and which processes it may signal or reach over abstract UNIX sockets. The restrictions apply to the process and everything it spawns afterwards, and they can never be lifted again.

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

| Landlock ABI | Kernel | Features exposed by this library                |
| ------------ | ------ | ----------------------------------------------- |
| 1            | 5.13   | The base filesystem rights.                     |
| 2            | 5.19   | `refer` (reparenting files across directories). |
| 3            | 6.2    | `truncate`.                                     |
| 4            | 6.7    | TCP network rules (`bind_tcp`, `connect_tcp`).  |
| 5            | 6.10   | `ioctl_dev`.                                    |
| 6            | 6.12   | Scopes (`signal`, `abstract_unix_socket`).      |

Newer ABI features (audit log control in ABI 7, ruleset enforcement across all threads in ABI 8, pathname UNIX socket and UDP rules in ABI 9 and 10) are not exposed by this library yet.

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

console.log(status); // { ruleset: 'fully_enforced', no_new_privs: true }
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

| Function                | Description                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------- |
| `isLandlockSupported()` | Returns `true` when the kernel can create and enforce a basic ruleset.                       |
| `getAbiVersion()`       | Returns the Landlock ABI version of the running kernel, or `0` when Landlock is unavailable. |
| `fsAccessFromAbi(abi)`  | Returns every filesystem access right available at the given ABI version.                    |
| `netAccessFromAbi(abi)` | Returns every network access right available at the given ABI version.                       |
| `scopesFromAbi(abi)`    | Returns every scope available at the given ABI version.                                      |

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
- `restrictSelf()` enforces the ruleset on the calling thread and returns a `RestrictionStatus`. This is irreversible and can be called once per instance.

### Compatibility Levels

| Level                | Behavior                                                                                                                                                                                  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `'best_effort'`      | Applies every requested feature the kernel supports and silently ignores the rest. This never produces a compatibility error, which means an old kernel enforces less than you asked for. |
| `'soft_requirement'` | Silently disables the whole ruleset if any requested feature is unsupported. `restrictSelf()` then reports `'not_enforced'`.                                                              |
| `'hard_requirement'` | Makes any unsupported feature an error. Use this when the sandbox is security critical, and check for it in tests.                                                                        |

### `RestrictionStatus`

`restrictSelf()` returns an object with two fields. `ruleset` is one of `'fully_enforced'`, `'partially_enforced'`, or `'not_enforced'`. Treat anything other than `'fully_enforced'` as a red flag in security critical code. `no_new_privs` reports whether `PR_SET_NO_NEW_PRIVS` was set, which `restrictSelf()` does as part of enforcement. A side effect worth knowing is that setuid binaries (like `sudo` or `ping`) spawned afterwards will not gain privileges.

### Filesystem Access Rights

| Right         | ABI | What a rule grants                                                                                                            |
| ------------- | --- | ----------------------------------------------------------------------------------------------------------------------------- |
| `execute`     | 1   | Execute a file.                                                                                                               |
| `write_file`  | 1   | Open a file with write access. Pair it with `truncate`, because overwriting usually truncates.                                |
| `read_file`   | 1   | Open a file with read access.                                                                                                 |
| `read_dir`    | 1   | Open a directory or list its content.                                                                                         |
| `remove_dir`  | 1   | Remove an empty directory or rename one.                                                                                      |
| `remove_file` | 1   | Unlink or rename a file.                                                                                                      |
| `make_char`   | 1   | Create, rename, or link a character device.                                                                                   |
| `make_dir`    | 1   | Create or rename a directory.                                                                                                 |
| `make_reg`    | 1   | Create, rename, or link a regular file.                                                                                       |
| `make_sock`   | 1   | Create, rename, or link a UNIX domain socket.                                                                                 |
| `make_fifo`   | 1   | Create, rename, or link a named pipe.                                                                                         |
| `make_block`  | 1   | Create, rename, or link a block device.                                                                                       |
| `make_sym`    | 1   | Create, rename, or link a symbolic link.                                                                                      |
| `refer`       | 2   | Link or rename a file from one directory into another. On ABI 1 kernels, sandboxed processes can never reparent files at all. |
| `truncate`    | 3   | Truncate a file with `truncate(2)`, `ftruncate(2)`, `creat(2)`, or `open(2)` with `O_TRUNC`.                                  |
| `ioctl_dev`   | 5   | Invoke `ioctl(2)` commands on device files opened after sandboxing.                                                           |

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

- **Restrict as early as possible.** `restrictSelf()` restricts the calling thread. Threads created afterwards inherit the domain, but threads that already exist do not. Worker threads created before the call can bypass the sandbox entirely (the test suite proves this), and the libuv thread pool, which services async `fs`, `dns.lookup`, and some `crypto` calls, spawns lazily on first use. Call `restrictSelf()` before starting workers and before any async I/O, or their operations will not be confined.
- **Module loading needs read access.** `require()` and dynamic `import()` after restriction are ordinary file reads. If you handle `read_file` and `read_dir`, grant them on your application code and `node_modules`, or lazy loading will fail with `EACCES`.
- **Child processes are confined too.** Anything spawned after restriction inherits the domain and cannot escape it. This is usually what you want, but remember it when shelling out to system tools.
- **DNS keeps working.** Landlock mediates only TCP `bind(2)` and `connect(2)`. Typical DNS runs over UDP and is unaffected even when every TCP connect is denied. Do not mistake a successful lookup for network access.

## What Landlock Does Not Cover

Landlock is a solid kernel primitive with a deliberately narrow scope. A Landlock ruleset alone is not a sandbox. These are the gaps:

- **Unmediated syscalls.** Landlock has no access rights for `stat(2)` and friends, `access(2)`, `chdir(2)`, `chmod(2)`, `chown(2)`, `setxattr(2)`, file locking, or timestamp changes. A sandboxed process can still probe which paths exist, walk directories, and change metadata on anything regular DAC permissions allow.
- **Pre-existing file descriptors.** Enforcement happens at open time. Any FD opened before `restrictSelf()`, including `stdin`, `stdout`, `stderr`, and inherited or passed sockets, keeps its capabilities forever. An already-connected TCP socket can exchange data freely regardless of network rules.
- **Non-TCP networking.** UDP, ICMP, raw sockets, and traffic on allowed connections are untouched. There is no packet or payload filtering.
- **Resource exhaustion.** There are no limits on processes, memory, CPU, or file descriptors. Fork bombs and memory exhaustion need rlimits and cgroups.
- **Memory safety.** Landlock limits what compromised code can reach, not whether the code can be compromised in the first place.
- **Special filesystems.** Files reachable through `/proc/<pid>/fd/*` and kernel filesystems like nsfs cannot be explicitly restricted, although Landlock's ptrace rules confine the most sensitive `/proc` entries to the domain hierarchy.

Rulesets stack up to 16 layers per thread, and each layer can only remove rights. Restrict once and deliberately rather than incrementally.

Landlock is also not a replacement for [seccomp-bpf](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html), which it is often mentioned alongside. seccomp filters which syscalls a process may invoke, and it can only inspect syscall numbers and raw argument values, so it cannot tell which file a path refers to. Landlock does not care which syscall is used and instead controls which kernel objects (file hierarchies, TCP ports) the process can reach through them. Use seccomp-bpf to shrink the kernel's attack surface and Landlock to scope file and network access. The two compose without interfering.

Do not rely on Landlock alone for executing hostile code or for multi-tenant isolation. For serious containment, combine it with seccomp-bpf, namespaces, cgroups, rlimits, and dropped capabilities.

## Test Coverage

The test suites are direct ports of the kernel's own Landlock selftests (`tools/testing/selftests/landlock/`), reproduced as faithfully as pure Node.js APIs allow.

- `tests/fs.test.ts` mirrors `fs_test.c`. Every one of the 16 filesystem access rights has a dedicated enforcement test, plus scenarios for ruleset layering and for unhandled rights staying unrestricted.
- `tests/net.test.ts` mirrors `net_test.c`, covering bind and connect enforcement, IPv6, UDP and UNIX sockets staying unaffected, ruleset overlap and expansion across layers, ephemeral port rules, port endianness, combined filesystem and network rulesets, pre-connected sockets, inheritance by child processes, and rule validation errors.
- `tests/scope.test.ts` mirrors `scoped_signal_test.c` and `scoped_abstract_unix_test.c`, including all eight parent and child domain permutations, all seven three-process tree permutations, and the per-thread semantics of worker threads created before and after restriction.
- `tests/abi.test.ts` guards CI against silent skips. The suites skip whatever the running kernel cannot do, so CI pins the expected ABI per kernel and fails loudly if the bindings report less.

Every test that enforces a ruleset runs in a fresh subprocess, because enforcement is irreversible.

CI boots real mainline kernels with [virtme-ng](https://github.com/arighi/virtme-ng) and runs the full suite once per ABI tier, on Linux 5.15, 6.1, 6.2, 6.7, 6.10, 6.12, and 6.15 (Landlock ABI 1 through 7). Additional jobs run the suite on Alpine (musl) for x64 and arm64 and on arm64 glibc, so every published binary target is exercised.

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
