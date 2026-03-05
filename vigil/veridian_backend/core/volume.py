from __future__ import annotations

import os
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Optional

from utils.helpers import get_logger

log = get_logger(__name__)


@dataclass
class VolumeInfo:
    path: str
    bytes_per_sector: int = 512
    sectors_per_cluster: int = 8
    mft_cluster_number: int = 0
    mft_mirror_cluster_number: int = 0
    oem_id: str = "NTFS    "


class VolumeHandle(AbstractContextManager["VolumeHandle"]):
    """
    Thin abstraction over a raw NTFS volume or disk image.

    For the MVP this implements a minimal interface with regular file
    I/O while preserving the shape required for later Win32 API calls.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh: Optional[os.FileIO] = None
        self.info = VolumeInfo(path=path)

    # Context manager ----------------------------------------------------
    def __enter__(self) -> "VolumeHandle":
        # For safety in the MVP we open in binary read-only mode. A
        # future Windows-specific implementation can replace this with
        # CreateFile / DeviceIoControl calls as described in the prompt.
        log.info("Opening volume/image: %s", self.path)
        self._fh = open(self.path, "rb")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh:
            log.info("Closing volume/image: %s", self.path)
            self._fh.close()
            self._fh = None

    # Raw access ---------------------------------------------------------
    def read_aligned(self, offset: int, length: int) -> bytes:
        """
        Read raw bytes from the underlying handle with simple 512‑byte
        alignment checks, as required by the design.
        """
        if offset % 512 != 0 or length % 512 != 0:
            raise ValueError("offset and length must be multiples of 512 bytes")
        if not self._fh:
            raise RuntimeError("Volume not opened")
        self._fh.seek(offset)
        return self._fh.read(length)

