"""coverage data types and structures"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class TraceFormat(Enum):
    """coverage trace format types"""
    BLOCKS = "blocks"        # block traces (drcov)
    ADDRESSES = "addresses"  # address traces (single instructions)


@dataclass
class CoverageBlock:
    """represents a covered block or single instruction"""
    address: int      # block start address
    size: int         # size in bytes (1 for single instructions)
    hitcount: int     # number of times hit
    module_id: Optional[int] = None  # for drcov traces
    
    def __hash__(self):
        """make blocks hashable for set operations"""
        return hash((self.address, self.size))
    
    def __eq__(self, other):
        """equality based on address and size"""
        if not isinstance(other, CoverageBlock):
            return False
        return self.address == other.address and self.size == other.size
    
    def contains_address(self, addr: int) -> bool:
        """check if an address falls within this block"""
        return self.address <= addr < (self.address + self.size)
    
    def end_address(self) -> int:
        """get the end address of the block"""
        return self.address + self.size


@dataclass  
class ModuleInfo:
    """module information from coverage traces"""
    id: int
    base: int
    end: int
    path: str
    
    def contains_address(self, addr: int) -> bool:
        """check if an address falls within this module"""
        return self.base <= addr < self.end
    
    def size(self) -> int:
        """get module size"""
        return self.end - self.base


@dataclass
class CoverageTrace:
    """complete coverage trace with metadata"""
    format: TraceFormat
    blocks: List[CoverageBlock] = field(default_factory=list)
    modules: Optional[Dict[int, ModuleInfo]] = None  # for drcov
    source_file: Optional[str] = None  # original trace file path
    
    def total_blocks(self) -> int:
        """get total number of blocks"""
        return len(self.blocks)
    
    def total_coverage_size(self) -> int:
        """get total size of all covered blocks"""
        return sum(block.size for block in self.blocks)
    
    def total_hits(self) -> int:
        """get total hit count across all blocks"""
        return sum(block.hitcount for block in self.blocks)
    
    def unique_addresses(self) -> int:
        """get number of unique covered addresses"""
        if self.format == TraceFormat.ADDRESSES:
            return len(self.blocks)  # each block is size 1
        else:
            # for block traces, calculate actual instruction count
            return self.total_coverage_size()  # approximation
    
    def get_blocks_for_module(self, module_id: int) -> List[CoverageBlock]:
        """get all blocks belonging to a specific module"""
        return [b for b in self.blocks if b.module_id == module_id]
    
    def get_hottest_blocks(self, count: int = 10) -> List[CoverageBlock]:
        """get the N most frequently hit blocks"""
        return sorted(self.blocks, key=lambda b: b.hitcount, reverse=True)[:count]
    
    def filter_by_hitcount(self, min_hits: Optional[int] = None, 
                          max_hits: Optional[int] = None) -> List[CoverageBlock]:
        """filter blocks by hit count range"""
        filtered = self.blocks
        if min_hits is not None:
            filtered = [b for b in filtered if b.hitcount >= min_hits]
        if max_hits is not None:
            filtered = [b for b in filtered if b.hitcount <= max_hits]
        return filtered