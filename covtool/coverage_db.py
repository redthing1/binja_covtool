from binaryninja import *
import binaryninja._binaryninjacore as core

# cache BNGetInstructionLength for performance
BNGetInstructionLength = core.BNGetInstructionLength

# maximum reasonable instruction length
MAX_INSTRUCTION_LENGTH = 16


class CoverageDB:
    """central coverage database for a single coverage file"""

    def __init__(self, bv):
        self.bv = bv
        self.coverage_file = None  # path to current coverage file
        self.hitcounts = {}  # addr -> hitcount mapping
        self._block_cache = {}  # cache for block -> instructions mapping

    def load_coverage(self, filepath, coverage_data):
        """load coverage from parsed data (replaces any existing coverage)"""
        # coverage_data: Dict[addr, hitcount] or Set[addr]
        self.clear()
        self.coverage_file = filepath

        # always convert to instruction-level coverage
        # because tracer blocks don't match binary ninja blocks
        if isinstance(coverage_data, dict):
            for addr, hitcount in coverage_data.items():
                self._add_address_coverage(addr, hitcount)
        else:
            # it's a set
            for addr in coverage_data:
                self._add_address_coverage(addr, 1)

    def _add_address_coverage(self, addr, hitcount):
        """add coverage for an address (might be block start or instruction)"""
        # check if this is a block start
        blocks = self.bv.get_basic_blocks_starting_at(addr)
        if blocks:
            # it's a block start, enumerate all instructions in the block
            instructions = self._get_block_instructions(addr)
            for inst_addr in instructions:
                self.hitcounts[inst_addr] = self.hitcounts.get(inst_addr, 0) + hitcount
        else:
            # it's an individual instruction address
            self.hitcounts[addr] = self.hitcounts.get(addr, 0) + hitcount

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
                            # this shouldn't happen - block_addr should be a block start
                            # but if it does, we've been given an instruction in the middle
                            # just return that single instruction
                            instructions = [block_addr]
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
            if not inst_len or inst_len <= 0:
                inst_len = 1  # fallback for invalid instruction
            # bounds check to prevent infinite loop
            if inst_len > MAX_INSTRUCTION_LENGTH:
                inst_len = 1
            current_addr += inst_len

        self._block_cache[block_addr] = instructions
        return instructions

    def is_covered(self, addr):
        """check if an instruction address is covered"""
        return addr in self.hitcounts

    def get_hitcount(self, addr):
        """get hitcount for an instruction address"""
        return self.hitcounts.get(addr, 0)

    def get_coverage_stats(self):
        """get coverage statistics"""
        return {
            "file": self.coverage_file,
            "total_covered": len(self.hitcounts),
            "unique_blocks": len(self._block_cache),
            "max_hitcount": max(self.hitcounts.values()) if self.hitcounts else 0,
        }

    def filter_by_hitcount(self, hitcount, mode="minimum"):
        """return addresses filtered by hitcount based on mode"""
        if hitcount <= 0 or mode == "disabled":
            return set(self.hitcounts.keys())

        if mode == "minimum":
            return {addr for addr, count in self.hitcounts.items() if count >= hitcount}
        elif mode == "maximum":
            return {addr for addr, count in self.hitcounts.items() if count <= hitcount}
        elif mode == "exact":
            return {addr for addr, count in self.hitcounts.items() if count == hitcount}
        else:
            return set(self.hitcounts.keys())

    def clear(self):
        """clear all coverage data"""
        self.coverage_file = None
        self.hitcounts.clear()
        self._block_cache.clear()
