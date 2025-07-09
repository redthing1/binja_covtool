from binaryninja import *
import binaryninja._binaryninjacore as core
from .logging import log_info, log_warn, log_debug

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
        self.invalid_addrs = {}  # track invalid addresses and their counts

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

        # log statistics about invalid addresses
        if self.invalid_addrs:
            total_invalid = len(self.invalid_addrs)
            total_invalid_hits = sum(self.invalid_addrs.values())
            log_warn(
                self.bv,
                f"found {total_invalid} invalid addresses with {total_invalid_hits} total hits",
            )
            # log a few examples
            examples = list(self.invalid_addrs.items())[:5]
            for addr, count in examples:
                log_debug(self.bv, f"  invalid: 0x{addr:x} (hits: {count})")
            if total_invalid > 5:
                log_debug(self.bv, f"  ... and {total_invalid - 5} more")

    def _add_address_coverage(self, addr, hitcount):
        """add coverage for an address (might be block start or instruction)"""
        # first check if address is within binary view bounds
        if addr < self.bv.start or addr >= self.bv.end:
            self.invalid_addrs[addr] = self.invalid_addrs.get(addr, 0) + hitcount
            return

        # check if this is a block start
        blocks = self.bv.get_basic_blocks_starting_at(addr)
        if blocks:
            # it's a block start, enumerate all instructions in the block
            instructions = self._get_block_instructions(addr)
            for inst_addr in instructions:
                self.hitcounts[inst_addr] = self.hitcounts.get(inst_addr, 0) + hitcount
        else:
            # check if it's a valid instruction address
            if self._is_valid_instruction(addr):
                self.hitcounts[addr] = self.hitcounts.get(addr, 0) + hitcount
            else:
                self.invalid_addrs[addr] = self.invalid_addrs.get(addr, 0) + hitcount

    def _is_valid_instruction(self, addr):
        """check if address points to a valid instruction"""
        # check if any function contains this address
        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return False

        # verify it's at an instruction boundary
        for func in funcs:
            # check if it's at the start of any instruction in the function
            for block in func.basic_blocks:
                if block.start <= addr < block.end:
                    # walk instructions to see if addr is at instruction start
                    current = block.start
                    while current < block.end:
                        if current == addr:
                            return True
                        inst_len = BNGetInstructionLength(
                            self.bv.handle, self.bv.arch.handle, current
                        )
                        if not inst_len or inst_len <= 0:
                            break
                        current += inst_len
                    break
        return False

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
            "invalid_addresses": len(self.invalid_addrs),
            "invalid_hits": sum(self.invalid_addrs.values()),
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
        self.invalid_addrs.clear()
