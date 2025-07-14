"""base parser class for coverage formats"""

from abc import ABC, abstractmethod
from ..logging import log_info, log_debug
from ..coverage_types import CoverageTrace


class CoverageParser(ABC):
    """base class for all coverage format parsers"""

    def __init__(self, bv, filepath):
        self.bv = bv
        self.filepath = filepath

    @property
    @abstractmethod
    def format_name(self):
        """return the format name (e.g., 'DrCovTrace', 'AddressTrace', etc.)"""
        pass

    @abstractmethod
    def can_parse(self):
        """check if this parser can handle the file"""
        pass

    @abstractmethod
    def parse(self) -> CoverageTrace:
        """parse the file and return coverage trace"""
        pass

    def log_stats(self, trace: CoverageTrace):
        """log parsing statistics"""
        total_blocks = trace.total_blocks()
        total_hits = trace.total_hits()
        log_info(
            self.bv,
            f"parsed {self.format_name}: {total_blocks} blocks, {total_hits} total hits",
        )
