from contextlib import suppress
from hashlib import sha1
from pathlib import Path
from typing import Union

from .bloom import PwnedBloomFilter
from .helper import MmapHelper

BLOOM_FILTER_AUTOMATIC = object()


class PwnedPasswordsOfflineChecker:
    def __init__(
        self,
        data_file: Union[Path, str],
        bloom_file: Union[Path, str, object, None] = BLOOM_FILTER_AUTOMATIC,
    ):
        if not isinstance(data_file, Path):
            data_file = Path(data_file)

        self._mh = MmapHelper(
            data_file, default_file_name="pwned-passwords-sha1-ordered-by-hash-v7.txt"
        )
        self._bf = None

        if bloom_file is not None:
            if bloom_file is BLOOM_FILTER_AUTOMATIC:
                with suppress(OSError, ValueError):
                    self._bf = PwnedBloomFilter(
                        data_file
                        if data_file.is_dir()
                        else data_file.parent
                        / "pwned-passwords-sha1-ordered-by-hash-v7.bloom",
                        readonly=True,
                    )
            else:
                self._bf = PwnedBloomFilter(bloom_file, readonly=True)

    def open(self):
        self._mh.open()
        try:
            if self._bf:
                self._bf.open()
        except Exception as e:
            self._mh.close()
            raise e

    def close(self):
        try:
            self._mh.close()
        finally:
            if self._bf:
                self._bf.close()

    def __enter__(self):
        self._mh.__enter__()
        try:
            if self._bf:
                self._bf.__enter__()
        except Exception as e:
            self._mh.__exit__(None, None, None)
            raise e
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self._mh.__exit__(exc_type, exc_val, exc_tb)
        finally:
            if self._bf:
                self._bf.__exit__(exc_type, exc_val, exc_tb)

    def lookup_hash(self, hash: Union[str, bytes]):
        if not self._mh.is_open():
            with self:
                return self.lookup_hash(hash)

        targeth = hash.upper()[:40]
        if isinstance(targeth, str):
            targeth = targeth.encode("us-ascii")

        if self._bf and not self._bf.contains(targeth):
            return False

        lowp = 0
        highp = self._mh.data.rfind(b"\x0a", 0, self._mh.data.size()) + 1

        found = None
        lastp = (None, None)

        while (lowp, highp) != lastp:
            lastp = (lowp, highp)

            midp = (lowp + highp) // 2 + 20
            midp = self._mh.data.rfind(b"\x0a", 0, midp) + 1

            midh = self._mh.data[midp : (midp + 40)]

            if targeth < midh:
                highp = midp
            elif targeth > midh:
                lowp = midp
            else:
                found = midp
                break

        if found is None:
            return False
        else:
            return True

    def lookup_raw_password(self, password: str, encoding="utf-8"):
        return self.lookup_hash(
            sha1(password.encode(encoding, errors="strict")).hexdigest().upper()
        )
