from binaryninja import *
import binaryninja._binaryninjacore as core

# cache BNGetInstructionLength for performance
BNGetInstructionLength = core.BNGetInstructionLength


class CoverageDB:
    """central coverage database for a single coverage file"""

    def __init__(self, bv):
        self.bv = bv
        self.coverage_file = None  # path to current coverage file
        self.covered_addrs = set()  # set of covered instruction addresses
        self.hitcounts = {}  # addr -> hitcount mapping
        self._block_cache = {}  # cache for block -> instructions mapping

    def load_coverage(self, filepath, coverage_data):
        """load coverage from parsed data (replaces any existing coverage)"""
        # coverage_data: Dict[addr, hitcount] or Set[addr]
        self.clear()
        self.coverage_file = filepath

        # if coverage_data is block-level, convert to instruction-level
        if isinstance(coverage_data, dict):
            for addr, hitcount in coverage_data.items():
                self._add_block_coverage(addr, hitcount)
        else:
            # it's a set
            for addr in coverage_data:
                self._add_block_coverage(addr, 1)

    def _add_block_coverage(self, block_addr, hitcount):
        """convert block coverage to instruction coverage"""
        instructions = self._get_block_instructions(block_addr)
        for inst_addr in instructions:
            self.covered_addrs.add(inst_addr)
            self.hitcounts[inst_addr] = self.hitcounts.get(inst_addr, 0) + hitcount

    def _get_block_instructions(self, block_addr):
        """get all instruction addresses in a block (with caching)"""
        if block_addr in self._block_cache:
            return self._block_cache[block_addr]

        instructions = []
        # use fast BNGetInstructionLength approach
        bh = self.bv.handle
        ah = self.bv.arch.handle

        # find containing block
        blocks = self.bv.get_basic_blocks_starting_at(block_addr)
        if not blocks:
            # single instruction case or address is an instruction within a block
            # try to find the containing block
            func_containing = self.bv.get_functions_containing(block_addr)
            if func_containing:
                for func in func_containing:
                    for block in func.basic_blocks:
                        if block.start <= block_addr < block.end:
                            # found the containing block, process from block_addr to end
                            current_addr = block_addr
                            while current_addr < block.end:
                                instructions.append(current_addr)
                                inst_len = BNGetInstructionLength(bh, ah, current_addr)
                                if not inst_len:
                                    inst_len = 1  # fallback
                                current_addr += inst_len
                            self._block_cache[block_addr] = instructions
                            return instructions

            # if we still haven't found it, treat as single instruction
            instructions = [block_addr]
            self._block_cache[block_addr] = instructions
            return instructions

        block = blocks[0]
        current_addr = block.start

        while current_addr < block.end:
            instructions.append(current_addr)
            inst_len = BNGetInstructionLength(bh, ah, current_addr)
            if not inst_len:
                inst_len = 1  # fallback
            current_addr += inst_len

        self._block_cache[block_addr] = instructions
        return instructions

    def is_covered(self, addr):
        """check if an instruction address is covered"""
        return addr in self.covered_addrs

    def get_hitcount(self, addr):
        """get hitcount for an instruction address"""
        return self.hitcounts.get(addr, 0)

    def get_coverage_stats(self):
        """get coverage statistics"""
        return {
            "file": self.coverage_file,
            "total_covered": len(self.covered_addrs),
            "unique_blocks": len(self._block_cache),
            "max_hitcount": max(self.hitcounts.values()) if self.hitcounts else 0,
        }

    def filter_by_hitcount(self, hitcount, mode="minimum"):
        """return addresses filtered by hitcount based on mode"""
        if hitcount <= 0 or mode == "disabled":
            return self.covered_addrs

        if mode == "minimum":
            return {addr for addr, count in self.hitcounts.items() if count >= hitcount}
        elif mode == "maximum":
            return {addr for addr, count in self.hitcounts.items() if count <= hitcount}
        elif mode == "exact":
            return {addr for addr, count in self.hitcounts.items() if count == hitcount}
        else:
            return self.covered_addrs

    def clear(self):
        """clear all coverage data"""
        self.coverage_file = None
        self.covered_addrs.clear()
        self.hitcounts.clear()
        self._block_cache.clear()
