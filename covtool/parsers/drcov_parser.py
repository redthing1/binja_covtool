"""drcov format parser"""

import os
import sys

# add the formats directory to the path to import the existing drcov module
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "formats"))
import drcov as drcov_lib

from .base import CoverageParser
from ..logging import log_info, log_warn, log_debug


class DrCovParser(CoverageParser):
    """parser for drcov format files"""

    @property
    def format_name(self):
        return "DrCovTrace"

    def can_parse(self):
        """check if file has drcov magic header"""
        try:
            with open(self.filepath, "rb") as f:
                header = f.read(16)
            return header.startswith(b"DRCOV")
        except:
            return False

    def parse(self):
        """parse drcov file and return coverage dict"""
        log_debug(self.bv, f"parsing {self.filepath} as DrCovTrace")

        # use the existing drcov library to parse the file
        coverage_data = drcov_lib.read(self.filepath)

        # find the module that matches our binary
        target_filename = os.path.basename(self.bv.file.original_filename)
        target_module = None

        for module in coverage_data.modules:
            module_filename = os.path.basename(module.path)
            if module_filename == target_filename:
                target_module = module
                break

        if not target_module:
            # try partial match
            for module in coverage_data.modules:
                if target_filename in module.path:
                    target_module = module
                    break

        if not target_module:
            raise ValueError(
                f"could not find module matching {target_filename} in coverage data"
            )

        log_info(self.bv, f"found matching module: {target_module.path}")

        # convert basic blocks to absolute addresses with hitcounts
        coverage = {}

        # check if we have hit counts
        if coverage_data.has_hit_counts():
            # use hit counts from the file
            for i, bb in enumerate(coverage_data.basic_blocks):
                if bb.module_id == target_module.id:
                    # convert module offset to absolute address in BinaryView
                    abs_addr = self.bv.start + bb.start
                    hitcount = coverage_data.get_hit_count(i)
                    coverage[abs_addr] = coverage.get(abs_addr, 0) + hitcount
        else:
            # no hit counts, treat each block as hit once
            for bb in coverage_data.basic_blocks:
                if bb.module_id == target_module.id:
                    # convert module offset to absolute address in BinaryView
                    abs_addr = self.bv.start + bb.start
                    coverage[abs_addr] = coverage.get(abs_addr, 0) + 1

        self.log_stats(coverage)
        return coverage
