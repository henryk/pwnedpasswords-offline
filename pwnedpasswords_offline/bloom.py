import struct
from collections import deque
from hashlib import sha1
from pathlib import Path
from typing import Deque, Tuple

from pwnedpasswords_offline.helper import MmapHelper

SIZE_BITS = 2 ** 32
SIZE_BYTE = SIZE_BITS // 8
FULL_HASH_LENGTH = 160  # SHA-1
NUM_HASHES = 5
HASH_LENGTH_BITS = 32
HASH_LENGTH_BYTES = HASH_LENGTH_BITS // 8

assert FULL_HASH_LENGTH == HASH_LENGTH_BITS * NUM_HASHES
assert SIZE_BITS == 2 ** HASH_LENGTH_BITS


class PwnedBloomFilter:
    """Special cased optimized Bloom filter with fixed parameters:
       * Filter size 512MiB (2**32 bits)
       * 5 hashes, of 32 bits each (5 parts of a 160-bit SHA-1 hash)
    These params lead to p = 0.034661226 (1 in 29) https://hur.st/bloomfilter/?n=613584246&p=&m=512MiB&k=
    """

    def __init__(self, data_path: Path, readonly: bool = False):
        self._mh = MmapHelper(data_path, fixed_size=SIZE_BYTE, write=not readonly)
        self._readonly = readonly

    def open(self):
        self._mh.open()

    def close(self):
        self._mh.close()

    def __enter__(self):
        self._mh.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._mh.__exit__(exc_type, exc_val, exc_tb)

    @staticmethod
    def _calc_hashes(value: bytes) -> Deque[Tuple[int, int]]:
        full_hash = sha1(value).digest()
        retval = deque()

        for i in range(NUM_HASHES):
            h = struct.unpack(
                "<I", full_hash[i * HASH_LENGTH_BYTES : (i + 1) * HASH_LENGTH_BYTES]
            )[0]
            retval.append((h >> 3, 1 << (h & 0x7)))

        return retval

    def add(self, value: bytes):
        if self._readonly:
            raise PermissionError("Bloom filter instance is read-only")

        for index, mask in self._calc_hashes(value):
            self._mh.data[index] |= mask

    def contains(self, value: bytes) -> bool:
        retval = True

        for index, mask in self._calc_hashes(value):
            retval = retval and bool(self._mh.data[index] & mask)

        return retval
