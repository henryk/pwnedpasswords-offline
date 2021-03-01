import mmap
import os
from pathlib import Path
from typing import Optional, Union


class MmapHelper:
    def __init__(
        self,
        data_file: Union[Path, str],
        default_file_name: Optional[str] = None,
        fixed_size: Optional[int] = None,
        write: bool = False,
    ):
        if not isinstance(data_file, Path):
            data_file = Path(data_file)

        if data_file.is_dir():
            if default_file_name is not None:
                data_file = data_file / default_file_name
            else:
                raise ValueError(
                    "Cannot open dir as data file when no default name is given"
                )

        if not (data_file.exists() and data_file.is_file()) and not write:
            raise ValueError(
                "Must specify path or directory to data file"
                + (
                    f" (should be {default_file_name})"
                    if default_file_name is not None
                    else ""
                )
            )

        self._data_file_path: Path = data_file
        self._opened: int = 0
        self._fd: Optional[int] = None
        self._fixed_size = fixed_size
        self._write = write
        self.data: Optional[mmap.mmap] = None

    def _open(self):
        if self._write:
            self._fd = os.open(
                self._data_file_path,
                os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0),
            )
            if self._fixed_size:
                os.ftruncate(self._fd, self._fixed_size)
            self.data = mmap.mmap(
                self._fd, self._fixed_size or 0, access=mmap.ACCESS_WRITE
            )
        else:
            self._fd = os.open(
                self._data_file_path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            self.data = mmap.mmap(
                self._fd, self._fixed_size or 0, access=mmap.ACCESS_READ
            )

    def _close(self):
        self.data.close()
        os.close(self._fd)

        self._fd = self.data = None

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

    def is_open(self):
        return self._opened > 0
