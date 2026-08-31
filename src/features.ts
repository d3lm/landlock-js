import { ABI, FsAccess, NetAccess, Scope } from './types';

export const FS_ACCESS: Partial<Record<ABI, FsAccess[]>> = {
  1: [
    'execute',
    'write_file',
    'read_file',
    'read_dir',
    'remove_dir',
    'remove_file',
    'make_char',
    'make_dir',
    'make_reg',
    'make_sock',
    'make_fifo',
    'make_block',
    'make_sym',
  ],
  2: ['refer'],
  3: ['truncate'],
  5: ['ioctl_dev'],
};

export const NET_ACCESS: Partial<Record<ABI, NetAccess[]>> = {
  4: ['bind_tcp', 'connect_tcp'],
};

export const SCOPES: Partial<Record<ABI, Scope[]>> = {
  6: ['signal', 'abstract_unix_socket'],
};

export function _featuresfromAbi<T>(abi: ABI, featureMap: Partial<Record<ABI, T>>): T {
  return Object.entries(featureMap)
    .flatMap(([key, value]) => {
      if (Number(key) > abi) {
        return [];
      }

      return value;
    })
    .flat() as T;
}
