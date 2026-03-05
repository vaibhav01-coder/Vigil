from __future__ import annotations

from typing import Dict, Iterable, List

from core.metadata import USNRecordV2
from detection.types import USNRecord
from utils.helpers import get_logger

log = get_logger(__name__)


class USNJournalParser:
    """
    USN Journal parser.

    The full implementation requires FSCTL_QUERY_USN_JOURNAL and
    FSCTL_READ_USN_JOURNAL. For the MVP we only define the interface
    and data structures so the rest of the pipeline can be wired up.
    """

    def __init__(self, volume) -> None:
        self.volume = volume
        self.index: Dict[int, List[USNRecord]] = {}

    def build_index(self) -> None:
        log.info("USN journal parsing is not yet implemented.")

    def get_records_for_file(self, file_reference: int) -> List[USNRecord]:
        return self.index.get(file_reference, [])

