from __future__ import annotations

from typing import Dict, List

from detection.types import LogRecord
from utils.helpers import get_logger

log = get_logger(__name__)


class LogFileParser:
    """
    $LogFile parser.

    The full design parses restart pages and RCRD pages, builds an LSN
    index, and validates LSN chains. The MVP provides a stubbed index
    to satisfy higher levels of the pipeline.
    """

    def __init__(self, volume) -> None:
        self.volume = volume
        self.lsn_index: Dict[int, LogRecord] = {}

    def build_indexes(self) -> None:
        log.info("$LogFile parsing is not yet implemented.")

