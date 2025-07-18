"""address trace format parser"""

from .base import CoverageParser
from ..logging import log_debug
from ..coverage_types import CoverageTrace, CoverageBlock, TraceFormat


class AddressTraceParser(CoverageParser):
    """parser for newline-separated hex addresses"""

    @property
    def format_name(self):
        return "AddressTrace"

    def can_parse(self):
        """check if file looks like address trace (hex addresses on each line)"""
        try:
            with open(self.filepath, "r") as f:
                # check first few non-empty lines
                valid_lines = 0
                for i, line in enumerate(f):
                    if i >= 10:  # check first 10 lines max
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # try to parse as hex
                    try:
                        int(line, 16)
                        valid_lines += 1
                    except ValueError:
                        # check for space - might be AddressHitTrace format
                        if " " in line:
                            return False
                        # not a valid hex line
                        return False
                return valid_lines > 0
        except:
            return False

    def parse(self) -> CoverageTrace:
        """parse newline-separated hex addresses"""
        log_debug(self.bv, f"parsing {self.filepath} as AddressTrace")

        # use dict to accumulate hitcounts per address
        address_hits = {}
        line_count = 0
        error_count = 0

        with open(self.filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                line_count += 1

                # parse hex address (with or without 0x)
                try:
                    if line.startswith("0x") or line.startswith("0X"):
                        addr = int(line, 16)
                    else:
                        addr = int(line, 16)
                except ValueError:
                    error_count += 1
                    if error_count <= 5:  # log first few errors
                        log_debug(
                            self.bv,
                            f"skipping invalid address on line {line_num}: {line}",
                        )
                    continue

                # increment hitcount for this address
                address_hits[addr] = address_hits.get(addr, 0) + 1

        if error_count > 5:
            log_debug(self.bv, f"skipped {error_count} total invalid lines")

        # convert to CoverageBlock list (size=1 for each address)
        blocks = []
        for addr, hitcount in address_hits.items():
            blocks.append(CoverageBlock(
                address=addr,
                size=1,  # single instruction
                hitcount=hitcount,
                module_id=None
            ))

        # create the trace
        trace = CoverageTrace(
            format=TraceFormat.ADDRESSES,
            blocks=blocks,
            modules=None,
            source_file=self.filepath
        )

        self.log_stats(trace)
        return trace
