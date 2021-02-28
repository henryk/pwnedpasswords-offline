from hashlib import sha1
from pathlib import Path
from typing import Optional, Union

from .helper import MmapHelper


class PwnedPasswordsOfflineChecker:
    def __init__(self, data_file: Union[Path, str]):
        self._mh = MmapHelper(data_file, default_file_name="pwned-passwords-sha1-ordered-by-hash-v7.txt")

    def open(self):
        self._mh.open()

    def close(self):
        self._mh.close()

    def __enter__(self):
        self._mh.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._mh.__exit__(exc_type, exc_val, exc_tb)

    def lookup_hash(self, hash: Union[str, bytes]):
        if not self._mh.is_open():
            with self:
                return self.lookup_hash(hash)

        targeth = hash.upper()[:40]
        if isinstance(targeth, str):
            targeth = targeth.encode("us-ascii")

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
