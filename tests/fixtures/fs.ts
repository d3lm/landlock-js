/**
 * Landlock file system test runner. Each invocation runs a single test case in
 * a fresh process, because an enforced Landlock ruleset cannot be removed again.
 * The test harness in tests/fs.test.ts spawns this file once per test case.
 *
 * The scenarios mirror the kernel selftests in
 * tools/testing/selftests/landlock/fs_test.c as closely as pure Node.js APIs
 * allow. Covered upstream behavior includes the per-access-right checks
 * (read_file, write_file, execute, the make_* family, remove_*, read_dir,
 * truncate, refer and ioctl_dev), rules attached to single files, rename and
 * link operations being guarded by the make_* and remove_* rights, the
 * EACCES-over-EXDEV precedence for reparenting, truncate rights attaching to
 * file descriptors at open time, ruleset layering, and unhandled access rights
 * staying unrestricted.
 *
 * The following upstream scenarios need low level syscall access (a native
 * helper or FFI binding) and cannot be reproduced with pure Node.js APIs.
 *
 * - renameat2(2) with RENAME_EXCHANGE or RENAME_WHITEOUT. Node.js only exposes
 *   plain rename(2), so the exchange and whiteout variants of the upstream
 *   rename tests are out of reach. Whiteout creation being guarded by make_reg
 *   is also untestable.
 * - truncate(2) by path. Node.js implements fs.truncateSync as open(2) with
 *   O_RDWR followed by ftruncate(2), so path-based truncation of files that
 *   only carry the truncate right cannot be exercised. Truncation without
 *   write access is still covered through open(2) with O_RDONLY | O_TRUNC.
 * - mknod(2) and mkfifo(3) have no Node.js API. The device and FIFO tests
 *   shell out to the mknod and mkfifo binaries instead, which works because
 *   child processes inherit the Landlock domain. Creating real device nodes
 *   additionally requires CAP_MKNOD, so those tests degrade gracefully when
 *   run without that capability.
 * - ioctl(2) with chosen commands. The upstream tests exercise FIONREAD,
 *   FS_IOC_GETFLAGS and the blanket-permitted commands such as FIOCLEX and
 *   FIONBIO, and they verify that FIFOs and UNIX sockets are exempt from
 *   ioctl_dev. Node.js cannot issue arbitrary ioctls. The ioctl_dev test here
 *   triggers TCGETS indirectly through isatty(3) via tty.isatty() on a pty
 *   device instead.
 * - open(2) with O_PATH or O_TMPFILE, which upstream uses to verify EBADF
 *   behavior and anonymous file handling.
 * - Mount topology changes. Bind mounts, OverlayFS layouts, open_tree(2),
 *   move_mount(2), umount(2), pivot_root(2) and chroot(2) back the layout*,
 *   disconnected-path and mount propagation tests.
 * - memfd_create(2), which upstream uses to show that anonymous files are not
 *   subject to path-based rules.
 * - File descriptor passing over UNIX sockets with SCM_RIGHTS, which upstream
 *   uses to show that fd-attached rights survive crossing process boundaries.
 * - Dropping and raising capabilities such as CAP_MKNOD or CAP_SYS_ADMIN,
 *   which upstream uses to separate EPERM from EACCES cases.
 * - The Landlock audit and tracing tests, which need the audit netlink API.
 * - The *at() syscall family with real directory file descriptors, for example
 *   openat(2) relative to a dirfd that outlives a rename.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import * as tty from 'node:tty';
import { expect } from 'vitest';
import {
  type FsAccess,
  type PathRule,
  LandlockRuleset,
  fsAccessFromAbi,
  getAbiVersion,
  isLandlockSupported,
} from '../../dist/index.mjs';

/**
 * Scenario tests exercise cross-cutting Landlock behavior that is
 * not tied to a single file system access right.
 */
type ScenarioTest = 'layers' | 'unhandled_access';

type TestName = FsAccess | ScenarioTest;

const testName = process.argv[2] as TestName;

const testCases: Partial<Record<TestName, (dir: string) => void | Promise<void>>> = {
  read_file(dir) {
    const outerFile = path.join(dir, 'outer.txt');
    const fileWithRule = path.join(dir, 'direct-rule.txt');
    const nestedDir = path.join(dir, 'nested');
    const nestedFile = path.join(nestedDir, 'nested.txt');

    fs.mkdirSync(nestedDir);
    fs.writeFileSync(outerFile, 'outer');
    fs.writeFileSync(fileWithRule, 'direct rule');
    fs.writeFileSync(nestedFile, 'nested');

    enforce(fsAccessFromAbi(getAbiVersion()), [
      { path: nestedDir, access: ['read_file'] },
      // rules can target a single file instead of a directory hierarchy
      { path: fileWithRule, access: ['read_file'] },
    ]);

    expect(fs.readFileSync(nestedFile, 'utf8')).toBe('nested');
    expect(fs.readFileSync(fileWithRule, 'utf8')).toBe('direct rule');

    expect(() => fs.readFileSync(outerFile, 'utf8')).toThrow(/EACCES/);

    // granting read_file does not grant writing
    expect(() => {
      fs.writeFileSync(nestedFile, 'denied', { flag: 'a' });
    }).toThrow(/EACCES/);
  },

  write_file(dir) {
    const outerFile = path.join(dir, 'outer.txt');
    const nestedDir = path.join(dir, 'nested');
    const nestedFile = path.join(nestedDir, 'nested.txt');

    fs.mkdirSync(nestedDir);
    fs.writeFileSync(outerFile, 'outer');
    fs.writeFileSync(nestedFile, 'nested');

    restrictDir(nestedDir, ['write_file']);

    // appending works because it avoids O_TRUNC, which would need the truncate right
    fs.writeFileSync(nestedFile, 'updated', { flag: 'a' });

    /**
     * Overwriting an existing file with the default 'w' flag implies O_TRUNC.
     * On kernels that handle the truncate right (ABI 3 and newer) the open is
     * denied because the rule only grants write_file. Older kernels do not
     * mediate truncation at all, so the same overwrite goes through there.
     */
    if (supportedAccess.includes('truncate')) {
      expect(() => {
        fs.writeFileSync(nestedFile, 'clobber');
      }).toThrow(/EACCES/);
    } else {
      fs.writeFileSync(nestedFile, 'clobber');
    }

    // granting write_file does not grant reading
    expect(() => fs.readFileSync(nestedFile, 'utf8')).toThrow(/EACCES/);

    // creating a new file needs the make_reg right
    expect(() => {
      fs.writeFileSync(path.join(nestedDir, 'new.txt'), 'new file');
    }).toThrow(/EACCES/);

    expect(() => {
      fs.writeFileSync(outerFile, 'denied', { flag: 'a' });
    }).toThrow(/EACCES/);
  },

  execute(dir) {
    const nestedDir = path.join(dir, 'nested');
    const script = path.join(nestedDir, 'script.sh');

    fs.mkdirSync(nestedDir);
    fs.writeFileSync(script, '#!/bin/sh\necho "Hello from script"');
    fs.chmodSync(script, 0o755);

    let trueBinary = '/usr/bin/true';
    let falseBinary = '/usr/bin/false';

    if (!fs.existsSync(trueBinary)) {
      trueBinary = '/bin/true';
    }

    if (!fs.existsSync(falseBinary)) {
      falseBinary = '/bin/false';
    }

    if (!fs.existsSync(trueBinary) || !fs.existsSync(falseBinary)) {
      throw new Error('Cannot find true/false binaries for execute test');
    }

    enforce(
      ['execute'],
      [
        // executing dynamically linked binaries needs execute access to the loader and libraries
        { path: '/lib', access: ['execute'] },
        { path: trueBinary, access: ['execute'] },
      ],
    );

    execFileSync(trueBinary);

    /**
     * On busybox systems such as Alpine, true and false are symlinks to the
     * same multi-call binary, so the execute grant on the true binary implicitly
     * covers the false binary as well. The node binary is always a different file,
     * so it stands in as the denied executable there.
     */
    const deniedBinary = fs.realpathSync(falseBinary) === fs.realpathSync(trueBinary) ? process.execPath : falseBinary;

    expect(() => execFileSync(deniedBinary)).toThrow(/EACCES/);
    expect(() => execFileSync(script)).toThrow(/EACCES/);
  },

  make_dir(dir) {
    const outerDir = path.join(dir, 'outer-dir');
    const nestedDir = path.join(dir, 'nested');
    const newDir = path.join(nestedDir, 'new-dir');

    fs.mkdirSync(nestedDir);
    fs.mkdirSync(outerDir);

    restrictDir(nestedDir, ['make_dir']);

    // creating a directory in the allowed hierarchy works
    fs.mkdirSync(newDir);

    expect(fs.existsSync(newDir)).toBe(true);

    // creating nested directories also works
    const deepDir = path.join(nestedDir, 'deep', 'nested', 'dir');

    fs.mkdirSync(deepDir, { recursive: true });

    expect(fs.existsSync(deepDir)).toBe(true);

    // creating a directory in a sibling directory is denied
    const badDir = path.join(outerDir, 'new-dir');

    expect(() => {
      fs.mkdirSync(badDir);
    }).toThrow(/EACCES/);

    // creating a directory in the parent directory is denied
    const parentDir = path.join(dir, 'parent-new');

    expect(() => {
      fs.mkdirSync(parentDir);
    }).toThrow(/EACCES/);
  },

  make_reg(dir) {
    const nestedDir = path.join(dir, 'nested');
    const outerDir = path.join(dir, 'outer');
    const subDir = path.join(nestedDir, 'subdir');

    fs.mkdirSync(nestedDir);
    fs.mkdirSync(outerDir);
    fs.mkdirSync(subDir);

    // create a file before the restriction to test O_CREAT on an existing file
    const existingFile = path.join(nestedDir, 'existing.txt');

    fs.writeFileSync(existingFile, 'existing content');

    /**
     * Creating a file also requires the read_file right here because the file
     * descriptor must be opened (in read-only mode) as part of the creation.
     */
    restrictDir(nestedDir, ['make_reg', 'read_file']);

    const newFile1 = path.join(nestedDir, 'new1.txt');

    // writeFileSync fails because it needs the write_file right
    expect(() => {
      fs.writeFileSync(newFile1, 'content');
    }).toThrow(/EACCES/);

    {
      // opening with O_CREAT | O_RDONLY succeeds because it only needs make_reg and read_file
      const fd = fs.openSync(newFile1, fs.constants.O_CREAT | fs.constants.O_RDONLY, 0o666);

      fs.closeSync(fd);
    }

    expect(fs.existsSync(newFile1)).toBe(true);

    // writing to the created file stays denied without the write_file right
    expect(() => {
      fs.writeFileSync(newFile1, 'content');
    }).toThrow(/EACCES/);

    /**
     * Opening an existing file with O_CREAT works without make_reg because no
     * new file is actually created.
     */
    {
      const fd = fs.openSync(existingFile, fs.constants.O_CREAT | fs.constants.O_RDONLY, 0o666);

      fs.closeSync(fd);
    }

    expect(fs.existsSync(existingFile)).toBe(true);

    // file creation works in subdirectories of the allowed hierarchy
    const subFile = path.join(subDir, 'subfile.txt');

    {
      const fd = fs.openSync(subFile, fs.constants.O_CREAT | fs.constants.O_RDONLY, 0o666);

      fs.closeSync(fd);
    }

    expect(fs.existsSync(subFile)).toBe(true);

    // file creation outside the allowed directory fails
    const outerFile = path.join(outerDir, 'outer.txt');

    expect(() => {
      const fd = fs.openSync(outerFile, fs.constants.O_CREAT | fs.constants.O_RDONLY, 0o666);

      fs.closeSync(fd);
    }).toThrow(/EACCES/);

    // file creation in the parent directory fails
    const parentFile = path.join(dir, 'parent.txt');

    expect(() => {
      const fd = fs.openSync(parentFile, fs.constants.O_CREAT | fs.constants.O_RDONLY, 0o666);

      fs.closeSync(fd);
    }).toThrow(/EACCES/);

    // O_CREAT | O_EXCL tests exclusive creation of a new file
    const exclusiveFile = path.join(nestedDir, 'exclusive.txt');

    {
      const fd = fs.openSync(exclusiveFile, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDONLY, 0o666);

      fs.closeSync(fd);
    }

    expect(fs.existsSync(exclusiveFile)).toBe(true);

    // O_EXCL on an existing file fails with EEXIST rather than EACCES
    expect(() => {
      fs.openSync(exclusiveFile, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDONLY, 0o666);
    }).toThrow(/EEXIST/);

    // multiple file creations keep working
    for (let i = 0; i < 3; i++) {
      const multiFile = path.join(nestedDir, `file_${i}.txt`);

      const fd = fs.openSync(multiFile, fs.constants.O_CREAT | fs.constants.O_RDONLY, 0o666);

      fs.closeSync(fd);

      expect(fs.existsSync(multiFile)).toBe(true);
    }
  },

  read_dir(dir) {
    const nestedDir = path.join(dir, 'nested');
    const subDir = path.join(nestedDir, 'sub');
    const file1 = path.join(nestedDir, 'file1.txt');
    const file2 = path.join(nestedDir, 'file2.txt');
    const outerFile = path.join(dir, 'outer.txt');

    fs.mkdirSync(nestedDir);
    fs.mkdirSync(subDir);
    fs.writeFileSync(file1, 'content1');
    fs.writeFileSync(file2, 'content2');
    fs.writeFileSync(outerFile, 'outer');

    restrictDir(nestedDir, ['read_dir'], ['read_dir', 'read_file']);

    // listing the allowed directory works
    const entries = fs.readdirSync(nestedDir);

    expect(entries.toSorted()).toEqual(['file1.txt', 'file2.txt', 'sub']);

    // listing a subdirectory works too
    expect(fs.readdirSync(subDir)).toEqual([]);

    // the withFileTypes variant goes through the same getdents64(2) path
    const entriesWithTypes = fs.readdirSync(nestedDir, { withFileTypes: true });

    expect(entriesWithTypes.length).toBe(3);
    expect(entriesWithTypes.find((entry) => entry.name === 'sub')?.isDirectory()).toBe(true);

    // granting read_dir does not grant read_file on the files inside
    expect(() => fs.readFileSync(file1, 'utf8')).toThrow(/EACCES/);

    // landlock cannot restrict stat(2), so metadata stays readable everywhere
    expect(fs.statSync(nestedDir).isDirectory()).toBe(true);
    expect(fs.statSync(dir).isDirectory()).toBe(true);

    // listing the parent directory is denied
    expect(() => fs.readdirSync(dir)).toThrow(/EACCES/);
  },

  remove_file(dir) {
    const nestedDir = path.join(dir, 'nested');
    const file1 = path.join(nestedDir, 'file1.txt');
    const file2 = path.join(nestedDir, 'file2.txt');
    const file3 = path.join(nestedDir, 'file3.txt');
    const file4 = path.join(nestedDir, 'file4.txt');
    const file5 = path.join(nestedDir, 'file5.txt');
    const symlink = path.join(nestedDir, 'link.txt');
    const outerFile = path.join(dir, 'outer.txt');

    fs.mkdirSync(nestedDir);
    fs.writeFileSync(file1, 'content1');
    fs.writeFileSync(file2, 'content2');
    fs.writeFileSync(file3, 'content3');
    fs.writeFileSync(file4, 'content4');
    fs.writeFileSync(file5, 'content5');
    fs.writeFileSync(outerFile, 'outer');
    fs.symlinkSync(file1, symlink);

    restrictDir(nestedDir, ['remove_file'], ['remove_file']);

    // removing a regular file works
    fs.unlinkSync(file1);
    expect(fs.existsSync(file1)).toBe(false);

    // removing a symlink works and only removes the link, not the target
    fs.unlinkSync(symlink);
    expect(fs.existsSync(symlink)).toBe(false);

    // rmSync goes through the same unlink(2) path
    fs.rmSync(file2);
    expect(fs.existsSync(file2)).toBe(false);

    /**
     * Renaming a file unlinks the source name, so remove_file is required on
     * the source parent directory even for same-directory renames.
     */
    fs.renameSync(file3, path.join(nestedDir, 'file3-renamed.txt'));

    // replacing an existing file through rename requires remove_file for the replaced destination
    fs.renameSync(file4, file5);
    expect(fs.readFileSync(file5, 'utf8')).toBe('content4');

    // removing a file in the parent directory is denied
    expect(() => {
      fs.unlinkSync(outerFile);
    }).toThrow(/EACCES/);

    // renaming a file in the parent directory is denied for the same reason
    expect(() => {
      fs.renameSync(outerFile, path.join(dir, 'outer-renamed.txt'));
    }).toThrow(/EACCES/);
  },

  remove_dir(dir) {
    const nestedDir = path.join(dir, 'nested');
    const emptyDir = path.join(nestedDir, 'empty');
    const nonEmptyDir = path.join(nestedDir, 'nonempty');
    const fileInDir = path.join(nonEmptyDir, 'file.txt');
    const outerDir = path.join(dir, 'outer');

    fs.mkdirSync(nestedDir);
    fs.mkdirSync(emptyDir);
    fs.mkdirSync(nonEmptyDir);
    fs.writeFileSync(fileInDir, 'content');
    fs.mkdirSync(outerDir);

    restrictDir(nestedDir, ['remove_dir', 'remove_file'], ['remove_dir', 'remove_file']);

    // removing an empty directory works
    fs.rmdirSync(emptyDir);
    expect(fs.existsSync(emptyDir)).toBe(false);

    // rmdir(2) on a non-empty directory fails on its own, not because of landlock
    expect(() => {
      fs.rmdirSync(nonEmptyDir);
    }).toThrow(/ENOTEMPTY/);

    // recursive removal works because remove_file is granted and read_dir is unhandled
    fs.rmSync(nonEmptyDir, { recursive: true });
    expect(fs.existsSync(nonEmptyDir)).toBe(false);

    // removing a directory in the parent directory is denied
    expect(() => {
      fs.rmdirSync(outerDir);
    }).toThrow(/EACCES/);

    /**
     * The remove_dir right applies to the content of the allowed directory and
     * not to the directory itself, so removing it stays denied.
     */
    expect(() => {
      fs.rmdirSync(nestedDir);
    }).toThrow(/EACCES/);
  },

  make_sym(dir) {
    const nestedDir = path.join(dir, 'nested');
    const targetFile = path.join(nestedDir, 'target.txt');
    const targetDir = path.join(nestedDir, 'targetdir');
    const link1 = path.join(nestedDir, 'link1');
    const link2 = path.join(nestedDir, 'link2');
    const outerLink = path.join(dir, 'outer-link');
    const preExistingLink = path.join(dir, 'pre-existing-link');

    fs.mkdirSync(nestedDir);
    fs.writeFileSync(targetFile, 'target content');
    fs.mkdirSync(targetDir);
    fs.symlinkSync(targetFile, preExistingLink);

    restrictDir(nestedDir, ['make_sym'], ['make_sym']);

    // creating a symlink to a file works
    fs.symlinkSync(targetFile, link1);
    expect(fs.lstatSync(link1).isSymbolicLink()).toBe(true);
    expect(fs.readlinkSync(link1)).toBe(targetFile);

    // creating a symlink to a directory works
    fs.symlinkSync(targetDir, link2);
    expect(fs.lstatSync(link2).isSymbolicLink()).toBe(true);

    // creating a symlink to a non-existent target also works
    const deadLink = path.join(nestedDir, 'deadlink');

    fs.symlinkSync('/nonexistent/path', deadLink);
    expect(fs.lstatSync(deadLink).isSymbolicLink()).toBe(true);

    /**
     * Renaming a symlink within the same directory is guarded by make_sym on
     * the destination side. The source side needs remove_file, which is not
     * handled by this ruleset and therefore stays unrestricted.
     */
    const renamedLink = path.join(nestedDir, 'link1-renamed');

    fs.renameSync(link1, renamedLink);
    expect(fs.lstatSync(renamedLink).isSymbolicLink()).toBe(true);

    // hard-linking a symlink creates a new symlink name, which make_sym also guards
    const hardLink = path.join(nestedDir, 'hardlink-to-symlink');

    fs.linkSync(renamedLink, hardLink);
    expect(fs.lstatSync(hardLink).isSymbolicLink()).toBe(true);

    // creating a symlink in the parent directory is denied
    expect(() => {
      fs.symlinkSync(targetFile, outerLink);
    }).toThrow(/EACCES/);

    // renaming a symlink in the parent directory is denied on the destination side
    expect(() => {
      fs.renameSync(preExistingLink, path.join(dir, 'pre-existing-renamed'));
    }).toThrow(/EACCES/);
  },

  async make_sock(dir) {
    const nestedDir = path.join(dir, 'nested');
    const sockPath = path.join(nestedDir, 'test.sock');
    const renamedSockPath = path.join(nestedDir, 'renamed.sock');
    const outerSockPath = path.join(dir, 'outer.sock');

    fs.mkdirSync(nestedDir);

    restrictDir(nestedDir, ['make_sock'], ['make_sock']);

    // bind(2) on a pathname UNIX socket creates the socket file, which make_sock guards
    const server = net.createServer();

    expect(await listenOnPath(server, sockPath)).toBeUndefined();
    expect(fs.statSync(sockPath).isSocket()).toBe(true);

    // renaming a socket file within the same directory is also guarded by make_sock
    fs.renameSync(sockPath, renamedSockPath);
    expect(fs.statSync(renamedSockPath).isSocket()).toBe(true);

    await closeServer(server);

    // creating a socket file in the parent directory is denied
    const outerServer = net.createServer();
    const error = await listenOnPath(outerServer, outerSockPath);

    expect(error?.code).toBe('EACCES');
  },

  make_fifo(dir) {
    const nestedDir = path.join(dir, 'nested');
    const fifoPath = path.join(nestedDir, 'test.fifo');
    const fifo2Path = path.join(nestedDir, 'test2.fifo');
    const outerFifoPath = path.join(dir, 'outer.fifo');

    fs.mkdirSync(nestedDir);

    /**
     * Only handle make_fifo so that executing the mkfifo binary in a child
     * process stays unrestricted. The child inherits the Landlock domain.
     */
    restrictDir(nestedDir, ['make_fifo'], ['make_fifo']);

    // creating a FIFO in the allowed directory works
    let result = runCommand('mkfifo', [fifoPath]);

    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(fs.statSync(fifoPath).isFIFO()).toBe(true);

    // creating a FIFO with a specific mode works too
    result = runCommand('mkfifo', ['-m', '0600', fifo2Path]);

    expect(result.status).toBe(0);
    expect(fs.statSync(fifo2Path).isFIFO()).toBe(true);

    // renaming and hard-linking a FIFO are guarded by make_fifo on the destination side
    fs.renameSync(fifo2Path, path.join(nestedDir, 'test2-renamed.fifo'));
    fs.linkSync(fifoPath, path.join(nestedDir, 'fifo.link'));

    // creating a FIFO in the parent directory is denied
    result = runCommand('mkfifo', [outerFifoPath]);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/Permission denied/);
  },

  make_char(dir) {
    // a character device with major 1 and minor 3 is /dev/null
    testMakeDevice(dir, 'make_char', 'c', '1', '3', (stats) => stats.isCharacterDevice());
  },

  make_block(dir) {
    // a block device with major 7 and minor 0 is /dev/loop0
    testMakeDevice(dir, 'make_block', 'b', '7', '0', (stats) => stats.isBlockDevice());
  },

  truncate(dir) {
    const fileRwt = path.join(dir, 'file-rwt.txt');
    const fileRw = path.join(dir, 'file-rw.txt');
    const fileRt = path.join(dir, 'file-rt.txt');
    const fileT = path.join(dir, 'file-t.txt');
    const fileNone = path.join(dir, 'file-none.txt');
    const dirT = path.join(dir, 'dir-t');
    const fileInDirT = path.join(dirT, 'file.txt');
    const dirW = path.join(dir, 'dir-w');
    const fileInDirW = path.join(dirW, 'file.txt');

    fs.writeFileSync(fileRwt, 'This is a long content that will be truncated');
    fs.writeFileSync(fileRw, 'content');
    fs.writeFileSync(fileRt, 'short');
    fs.writeFileSync(fileT, 'content');
    fs.writeFileSync(fileNone, 'content');
    fs.mkdirSync(dirT);
    fs.writeFileSync(fileInDirT, 'content');
    fs.mkdirSync(dirW);
    fs.writeFileSync(fileInDirW, 'content');

    // rights are attached to file descriptors at open time, so this fd stays unrestricted
    const fdBefore = fs.openSync(fileNone, 'r+');

    enforce(
      ['read_file', 'write_file', 'truncate'],
      [
        { path: fileRwt, access: ['read_file', 'write_file', 'truncate'] },
        { path: fileRw, access: ['read_file', 'write_file'] },
        { path: fileRt, access: ['read_file', 'truncate'] },
        { path: fileT, access: ['truncate'] },
        { path: dirT, access: ['read_file', 'write_file', 'truncate'] },
        { path: dirW, access: ['write_file'] },
      ],
    );

    /**
     * Node.js implements fs.truncateSync as open(2) with O_RDWR followed by
     * ftruncate(2), so it needs the read, write and truncate rights together.
     */
    fs.truncateSync(fileRwt, 10);
    expect(fs.readFileSync(fileRwt, 'utf8')).toBe('This is a ');

    // extending a file also counts as truncation and pads with null bytes
    fs.truncateSync(fileRwt, 20);

    const content = fs.readFileSync(fileRwt);

    expect(content.length).toBe(20);
    expect(content.subarray(10).every((byte) => byte === 0)).toBe(true);

    // without the write right the internal O_RDWR open is denied
    expect(truncateErrorCode(fileRt)).toBe('EACCES');
    expect(truncateErrorCode(fileT)).toBe('EACCES');

    // opening works here, but the fd is created without the truncate right
    expect(truncateErrorCode(fileRw)).toBe('EACCES');

    expect(truncateErrorCode(fileNone)).toBe('EACCES');

    // a rule on a directory covers the files beneath it
    fs.truncateSync(fileInDirT, 1);

    // opening with O_TRUNC needs the truncate right along with the matching read or write right
    const { O_RDONLY, O_WRONLY, O_TRUNC } = fs.constants;

    expect(openErrorCode(fileRwt, O_RDONLY | O_TRUNC)).toBeUndefined();
    expect(openErrorCode(fileRwt, O_WRONLY | O_TRUNC)).toBeUndefined();

    // files can get truncated through open(2) even without any write right
    expect(openErrorCode(fileRt, O_RDONLY | O_TRUNC)).toBeUndefined();
    expect(openErrorCode(fileRt, O_WRONLY | O_TRUNC)).toBe('EACCES');
    expect(openErrorCode(fileRw, O_RDONLY | O_TRUNC)).toBe('EACCES');
    expect(openErrorCode(fileRw, O_WRONLY | O_TRUNC)).toBe('EACCES');
    expect(openErrorCode(fileT, O_RDONLY | O_TRUNC)).toBe('EACCES');
    expect(openErrorCode(fileT, O_WRONLY | O_TRUNC)).toBe('EACCES');

    /**
     * Overwriting an existing file with writeFileSync uses O_CREAT | O_TRUNC,
     * so it needs the truncate right in addition to write_file.
     */
    expect(() => {
      fs.writeFileSync(fileInDirW, 'overwrite');
    }).toThrow(/EACCES/);

    // unlinking is unrestricted because remove_file is not handled by this ruleset
    fs.unlinkSync(fileInDirW);

    // creating a new file does not truncate anything, so write_file alone is enough
    fs.writeFileSync(fileInDirW, 'new content');

    // the fd opened before enforcement can still be truncated
    fs.ftruncateSync(fdBefore, 3);
    fs.closeSync(fdBefore);

    // an fd opened now on a file without the truncate right cannot be truncated
    const fdRw = fs.openSync(fileRw, 'r+');

    expect(ftruncateErrorCode(fdRw)).toBe('EACCES');
    fs.closeSync(fdRw);

    // an fd opened now on a file with the truncate right can be truncated
    const fdRwt = fs.openSync(fileRwt, 'r+');

    fs.ftruncateSync(fdRwt, 2);
    fs.closeSync(fdRwt);
  },

  refer(dir) {
    const dir1 = path.join(dir, 'dir1');
    const dir2 = path.join(dir, 'dir2');
    const dir3 = path.join(dir, 'dir3');
    const sourceFile = path.join(dir1, 'file.txt');
    const linkSource = path.join(dir1, 'link-source.txt');
    const sameDirFile = path.join(dir1, 'same.txt');

    fs.mkdirSync(dir1);
    fs.mkdirSync(dir2);
    fs.mkdirSync(dir3);
    fs.writeFileSync(sourceFile, 'content');
    fs.writeFileSync(linkSource, 'link content');
    fs.writeFileSync(sameDirFile, 'same dir');

    /**
     * Reparenting a file needs the refer right on both parent directories, the
     * matching make_* right on the destination and, for renames, the matching
     * remove_* right on the source. The file must also not gain access rights
     * through the move. dir3 gets make_reg but no refer so that reparenting
     * into it fails with EXDEV and nothing else.
     */
    enforce(
      ['refer', 'make_reg', 'remove_file'],
      [
        { path: dir1, access: ['refer', 'make_reg', 'remove_file'] },
        { path: dir2, access: ['refer', 'make_reg'] },
        { path: dir3, access: ['make_reg'] },
      ],
    );

    /**
     * Linking across directories needs refer on both sides and make_reg on the
     * destination, but no removal right.
     */
    const linked = path.join(dir2, 'linked.txt');

    fs.linkSync(linkSource, linked);
    expect(fs.readFileSync(linked, 'utf8')).toBe('link content');

    // renaming across directories additionally needs remove_file on the source parent
    const renamed = path.join(dir2, 'renamed.txt');

    fs.renameSync(sourceFile, renamed);
    expect(fs.existsSync(renamed)).toBe(true);
    expect(fs.existsSync(sourceFile)).toBe(false);

    /**
     * Moving the file back is denied. The source parent dir2 lacks remove_file
     * (an EACCES error) and the file would also gain the remove_file right in
     * dir1 (an EXDEV error). EACCES takes precedence over EXDEV.
     */
    expect(() => {
      fs.renameSync(renamed, path.join(dir1, 'back.txt'));
    }).toThrow(/EACCES/);

    // dir3 lacks the refer right, and only that, so reparenting into it fails with EXDEV
    expect(() => {
      fs.renameSync(linkSource, path.join(dir3, 'moved.txt'));
    }).toThrow(/EXDEV/);

    expect(() => {
      fs.linkSync(linkSource, path.join(dir3, 'linked.txt'));
    }).toThrow(/EXDEV/);

    // renames within the same directory do not involve the refer right
    const sameDirRenamed = path.join(dir1, 'same-renamed.txt');

    fs.renameSync(sameDirFile, sameDirRenamed);
    expect(fs.existsSync(sameDirRenamed)).toBe(true);

    /**
     * The refer right is denied by default in every ruleset, even when it is
     * not handled. Enforcing another layer without refer therefore denies all
     * cross-directory renames, including the previously allowed direction.
     */
    enforce(['read_file'], [{ path: dir, access: ['read_file'] }]);

    expect(() => {
      fs.renameSync(sameDirRenamed, path.join(dir2, 'blocked.txt'));
    }).toThrow(/EXDEV/);

    // renames within the same directory keep working
    fs.renameSync(sameDirRenamed, sameDirFile);
    expect(fs.existsSync(sameDirFile)).toBe(true);
  },

  ioctl_dev() {
    const ptmxPath = '/dev/ptmx';

    /**
     * Node.js cannot issue arbitrary ioctls, but tty.isatty() calls isatty(3),
     * which issues a TCGETS ioctl. Opening /dev/ptmx yields a pty master, a
     * character device for which isatty(3) normally returns true, so a false
     * result proves that Landlock blocked the ioctl with EACCES.
     */
    let probeFd: number;

    try {
      probeFd = fs.openSync(ptmxPath, 'r+');
    } catch {
      // minimal environments such as containers may not provide a pty device
      console.log('Skipping the ioctl_dev test because /dev/ptmx is not available.');
      return;
    }

    if (!tty.isatty(probeFd)) {
      fs.closeSync(probeFd);
      console.log('Skipping the ioctl_dev test because /dev/ptmx is not a tty.');
      return;
    }

    // the first layer grants ioctl_dev below /dev, so device ioctls keep working
    enforce(['ioctl_dev'], [{ path: '/dev', access: ['ioctl_dev'] }]);

    const allowedFd = fs.openSync(ptmxPath, 'r+');

    expect(tty.isatty(allowedFd)).toBe(true);

    // the second layer handles ioctl_dev without granting it anywhere
    enforce(['ioctl_dev'], []);

    /**
     * Opening the device still works because read_file and write_file are not
     * handled, but ioctls on the new fd are now denied.
     */
    const deniedFd = fs.openSync(ptmxPath, 'r+');

    expect(tty.isatty(deniedFd)).toBe(false);

    // the ioctl_dev right attaches to file descriptors at open time, so older fds keep it
    expect(tty.isatty(allowedFd)).toBe(true);
    expect(tty.isatty(probeFd)).toBe(true);

    fs.closeSync(deniedFd);
    fs.closeSync(allowedFd);
    fs.closeSync(probeFd);
  },

  layers(dir) {
    const nestedDir = path.join(dir, 'nested');
    const subDir = path.join(nestedDir, 'sub');
    const nestedFile = path.join(nestedDir, 'nested.txt');
    const subFile = path.join(subDir, 'sub.txt');
    const outerFile = path.join(dir, 'outer.txt');

    fs.mkdirSync(nestedDir);
    fs.mkdirSync(subDir);
    fs.writeFileSync(nestedFile, 'nested');
    fs.writeFileSync(subFile, 'sub');
    fs.writeFileSync(outerFile, 'outer');

    // the first layer allows reading and writing below nestedDir
    enforce(['read_file', 'write_file'], [{ path: nestedDir, access: ['read_file', 'write_file'] }]);

    expect(fs.readFileSync(nestedFile, 'utf8')).toBe('nested');
    fs.writeFileSync(nestedFile, 'updated');
    fs.writeFileSync(subFile, 'sub updated');
    expect(() => fs.readFileSync(outerFile, 'utf8')).toThrow(/EACCES/);

    /**
     * The second layer only allows writing below subDir. An access is granted
     * only when every enforced layer grants it, so a new layer can tighten the
     * policy but never widen it.
     */
    enforce(['write_file'], [{ path: subDir, access: ['write_file'] }]);

    // reads are unaffected because the second layer does not handle read_file
    expect(fs.readFileSync(nestedFile, 'utf8')).toBe('updated');

    // writes outside subDir are now denied even though the first layer allows them
    expect(() => {
      fs.writeFileSync(nestedFile, 'blocked');
    }).toThrow(/EACCES/);

    // writes below subDir stay allowed by both layers
    fs.writeFileSync(subFile, 'still writable');

    // writes denied by the first layer stay denied
    expect(() => {
      fs.writeFileSync(outerFile, 'blocked');
    }).toThrow(/EACCES/);
  },

  unhandled_access(dir) {
    const nestedDir = path.join(dir, 'nested');
    const nestedFile = path.join(nestedDir, 'nested.txt');
    const outerFile = path.join(dir, 'outer.txt');

    fs.mkdirSync(nestedDir);
    fs.writeFileSync(nestedFile, 'nested');
    fs.writeFileSync(outerFile, 'outer');

    // only read_file is handled, so only read accesses are restricted at all
    enforce(['read_file'], [{ path: nestedDir, access: ['read_file'] }]);

    expect(fs.readFileSync(nestedFile, 'utf8')).toBe('nested');
    expect(() => fs.readFileSync(outerFile, 'utf8')).toThrow(/EACCES/);

    // unhandled access rights stay unrestricted everywhere, even outside all rules
    fs.writeFileSync(outerFile, 'outer updated', { flag: 'a' });
    fs.mkdirSync(path.join(dir, 'new-dir'));
    fs.writeFileSync(path.join(dir, 'new-file.txt'), 'created');
    expect(fs.existsSync(path.join(dir, 'new-file.txt'))).toBe(true);
  },
};

const SCENARIO_TESTS: ReadonlySet<string> = new Set(['layers', 'unhandled_access'] satisfies ScenarioTest[]);

if (!isLandlockSupported()) {
  process.exit(1);
}

const abi = getAbiVersion();
const supportedAccess: string[] = fsAccessFromAbi(abi);

if (!SCENARIO_TESTS.has(testName) && !supportedAccess.includes(testName)) {
  process.exit(1);
}

await withTemporaryDir(async (dir) => {
  const fn = testCases[testName];

  if (!fn) {
    throw new Error(`Unknown test case: ${testName}`);
  }

  await fn(dir);
});

async function withTemporaryDir(fn: (dir: string) => void | Promise<void>) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'landlock-test-'));

  try {
    await fn(dir);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // the cleanup is usually blocked by the enforced ruleset itself
    }
  }
}

/**
 * Creates and enforces a ruleset that handles the given access rights and
 * allows the given path rules. Everything else covered by the handled rights
 * is denied, while unhandled rights stay unrestricted.
 */
function enforce(handled: FsAccess[], rules: PathRule[]) {
  const ruleset = new LandlockRuleset();

  ruleset.setCompatibility('hard_requirement');
  ruleset.handleFsAccess(handled);
  ruleset.create();
  ruleset.addPathRules(rules);

  return ruleset.restrictSelf();
}

/**
 * Restricts the process to the given access rights below the given directory.
 * By default all access rights supported by the running kernel are handled, so
 * everything not explicitly allowed is denied. Pass an explicit handled set to
 * leave the other access rights unrestricted, which mirrors how the kernel
 * selftests only handle the rights under test.
 */
function restrictDir(dir: string, access: FsAccess[], handled: FsAccess[] = fsAccessFromAbi(getAbiVersion())) {
  return enforce(handled, [{ path: dir, access }]);
}

/**
 * Runs a binary with a C locale so that error message assertions are stable.
 */
function runCommand(command: string, args: string[]) {
  return spawnSync(command, args, {
    stdio: 'pipe',
    encoding: 'utf8',
    env: { ...process.env, LC_ALL: 'C' },
  });
}

/**
 * Shared implementation for the make_char and make_block tests. Device nodes
 * can only be created through mknod(2), which Node.js does not expose, so this
 * shells out to the mknod binary. The child process inherits the Landlock
 * domain. Creating real device nodes also requires CAP_MKNOD, so without that
 * capability the test only verifies that the failure is consistent.
 */
function testMakeDevice(
  dir: string,
  access: 'make_char' | 'make_block',
  deviceType: string,
  major: string,
  minor: string,
  isExpectedDeviceType: (stats: fs.Stats) => boolean,
) {
  const nestedDir = path.join(dir, 'nested');
  const innerDevice = path.join(nestedDir, 'device');
  const outerDevice = path.join(dir, 'device');

  fs.mkdirSync(nestedDir);

  restrictDir(nestedDir, [access], [access]);

  const inner = runCommand('mknod', [innerDevice, deviceType, major, minor]);
  const outer = runCommand('mknod', [outerDevice, deviceType, major, minor]);

  if (inner.status !== 0 && inner.stderr.includes('Operation not permitted')) {
    // without CAP_MKNOD the kernel returns EPERM before landlock is consulted
    expect(outer.status).not.toBe(0);
    return;
  }

  // creating the device in the allowed directory works
  expect(inner.stderr).toBe('');
  expect(inner.status).toBe(0);
  expect(isExpectedDeviceType(fs.lstatSync(innerDevice))).toBe(true);

  // renaming the device within the same directory is guarded by the same make right
  fs.renameSync(innerDevice, path.join(nestedDir, 'device-renamed'));

  // creating the device in the parent directory is denied by landlock
  expect(outer.status).not.toBe(0);
  expect(outer.stderr).toMatch(/Permission denied/);
}

/**
 * Starts listening on the given UNIX socket path and resolves with the listen
 * error, or with undefined when listening succeeded.
 */
function listenOnPath(server: net.Server, socketPath: string): Promise<NodeJS.ErrnoException | undefined> {
  return new Promise((resolve) => {
    const onError = (error: Error) => {
      resolve(error);
    };

    server.once('error', onError);

    server.listen(socketPath, () => {
      server.off('error', onError);
      resolve(undefined);
    });
  });
}

function closeServer(server: net.Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => {
      resolve();
    });
  });
}

/**
 * Returns the error code of a failed open(2) with the given flags, or
 * undefined when opening succeeded.
 */
function openErrorCode(file: string, flags: number): string | undefined {
  try {
    fs.closeSync(fs.openSync(file, flags));
    return undefined;
  } catch (error) {
    return errnoCode(error);
  }
}

/**
 * Returns the error code of a failed truncate(2), or undefined on success.
 */
function truncateErrorCode(file: string): string | undefined {
  try {
    fs.truncateSync(file, 4);
    return undefined;
  } catch (error) {
    return errnoCode(error);
  }
}

/**
 * Returns the error code of a failed ftruncate(2), or undefined on success.
 */
function ftruncateErrorCode(fd: number): string | undefined {
  try {
    fs.ftruncateSync(fd, 4);
    return undefined;
  } catch (error) {
    return errnoCode(error);
  }
}

function errnoCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException).code;
}
