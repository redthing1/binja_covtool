"""base parser class for coverage formats"""

from abc import ABC, abstractmethod
from ..logging import log_info, log_debug


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
    def parse(self):
        """parse the file and return coverage dict"""
        pass

    def log_stats(self, coverage):
        """log parsing statistics"""
        unique_addrs = len(coverage)
        total_hits = sum(coverage.values())
        log_info(
            self.bv,
            f"parsed {self.format_name}: {unique_addrs} unique addresses, {total_hits} total hits",
        )
