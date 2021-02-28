import mmap
import os
from hashlib import sha1
from pathlib import Path
from typing import Optional, Union

__version__ = "1.0.1"


class PwnedPasswordsOfflineChecker:
    def __init__(self, data_file: Union[Path, str]):
        if not isinstance(data_file, Path):
            data_file = Path(data_file)

        if data_file.is_dir():
            data_file = data_file / "pwned-passwords-sha1-ordered-by-hash-v7.txt"

        if not (data_file.exists() and data_file.is_file()):
            raise ValueError(
                "Must specify path or directory to data file "
                "(should be pwned-passwords-sha1-ordered-by-hash-v7.txt)"
            )

        self._data_file_path: Path = data_file
        self._opened: int = 0
        self._data: Optional[mmap.mmap] = None
        self._fd: Optional[int] = None

    def _open(self):
        self._fd = os.open(
            self._data_file_path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
        self._data = mmap.mmap(self._fd, 0, access=mmap.ACCESS_READ)

    def _close(self):
        self._data.close()
        os.close(self._fd)

        self._fd = self._data = None

    def open(self):
        if not self._opened:
            self._open()
        self._opened += 1

    def close(self):
        if self._opened:
            self._close()
        self._opened = 0

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._opened == 1:
            self._close()
        if self._opened > 0:
            self._opened -= 1

    def lookup_hash(self, hash: Union[str, bytes]):
        if not self._opened:
            with self:
                return self.lookup_hash(hash)

        targeth = hash.upper()[:40]
        if isinstance(targeth, str):
            targeth = targeth.encode("us-ascii")

        lowp = 0
        highp = self._data.rfind(b"\x0a", 0, self._data.size()) + 1

        found = None
        lastp = (None, None)

        while (lowp, highp) != lastp:
            lastp = (lowp, highp)

            midp = (lowp + highp) // 2 + 20
            midp = self._data.rfind(b"\x0a", 0, midp) + 1

            midh = self._data[midp : (midp + 40)]

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
