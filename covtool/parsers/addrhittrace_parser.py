"""address hit trace format parser"""

from .base import CoverageParser
from ..logging import log_debug, log_warn
from ..coverage_types import CoverageTrace, CoverageBlock, TraceFormat


class AddressHitTraceParser(CoverageParser):
    """parser for address hit trace format: <hex_address> <hit_count>"""

    @property
    def format_name(self):
        return "AddressHitTrace"

    def can_parse(self):
        """check if file looks like address hit trace (hex address + hitcount)"""
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

                    # should have exactly one space
                    parts = line.split()
                    if len(parts) != 2:
                        return False

                    # first part should be hex, second should be number
                    try:
                        int(parts[0], 16)  # hex address
                        int(parts[1])  # hit count
                        valid_lines += 1
                    except ValueError:
                        return False

                return valid_lines > 0
        except:
            return False

    def parse(self) -> CoverageTrace:
        """parse address hit trace format"""
        log_debug(self.bv, f"parsing {self.filepath} as AddressHitTrace")

        # use dict to accumulate hitcounts per address
        address_hits = {}
        line_count = 0
        error_count = 0
        max_hitcount = 0

        with open(self.filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                line_count += 1

                # split into address and hitcount
                parts = line.split()
                if len(parts) != 2:
                    error_count += 1
                    if error_count <= 5:
                        log_debug(self.bv, f"skipping invalid line {line_num}: {line}")
                    continue

                # parse hex address and hitcount
                try:
                    # address can have 0x prefix or not
                    if parts[0].startswith("0x") or parts[0].startswith("0X"):
                        addr = int(parts[0], 16)
                    else:
                        addr = int(parts[0], 16)

                    hitcount = int(parts[1])

                    if hitcount < 0:
                        log_warn(
                            self.bv,
                            f"negative hitcount {hitcount} on line {line_num}, treating as 0",
                        )
                        hitcount = 0

                except ValueError:
                    error_count += 1
                    if error_count <= 5:
                        log_debug(
                            self.bv,
                            f"skipping invalid address/hitcount on line {line_num}: {line}",
                        )
                    continue

                # store or accumulate hitcount
                if addr in address_hits:
                    log_debug(
                        self.bv,
                        f"duplicate address 0x{addr:x} on line {line_num}, accumulating hitcounts",
                    )
                    address_hits[addr] += hitcount
                else:
                    address_hits[addr] = hitcount

                if hitcount > max_hitcount:
                    max_hitcount = hitcount

        if error_count > 5:
            log_debug(self.bv, f"skipped {error_count} total invalid lines")

        # log additional stats for this format
        log_debug(self.bv, f"max hitcount: {max_hitcount}")

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
