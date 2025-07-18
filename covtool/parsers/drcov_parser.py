"""drcov format parser"""

import os
import sys
import traceback

# add the formats directory to the path to import the existing drcov module
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "formats"))
import drcov as drcov_lib

from .base import CoverageParser
from ..logging import log_info, log_warn, log_debug, log_error
from ..coverage_types import CoverageTrace, CoverageBlock, ModuleInfo, TraceFormat


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

    def parse(self) -> CoverageTrace:
        """parse drcov file and return coverage trace"""
        log_debug(self.bv, f"parsing {self.filepath} as DrCovTrace")

        # 1. load coverage data
        coverage_data = drcov_lib.read(self.filepath)

        # 2. find all matching modules
        matching_modules = self._find_matching_modules(coverage_data)

        # 3. validate modules and get their status
        validated_modules = self._validate_modules(matching_modules)

        # 4. create coverage trace from all modules (valid + warned)
        trace = self._create_coverage_trace(coverage_data, validated_modules)

        self.log_stats(trace)
        return trace

    def _find_matching_modules(self, coverage_data):
        """find all modules that match the target binary filename"""
        target_filename = os.path.basename(self.bv.file.original_filename)
        matching_modules = []

        # first pass: exact filename matches
        for module in coverage_data.modules:
            module_filename = os.path.basename(module.path)
            if module_filename == target_filename:
                matching_modules.append(module)

        # second pass: partial matches if no exact matches found
        if not matching_modules:
            for module in coverage_data.modules:
                if target_filename in module.path:
                    matching_modules.append(module)

        if not matching_modules:
            # generate detailed error message
            available_modules = [
                os.path.basename(m.path) for m in coverage_data.modules
            ]
            error_msg = (
                f"could not find module matching '{target_filename}' in coverage data\n"
                f"available modules in coverage file: {', '.join(available_modules)}\n"
                f"this usually means the coverage file was generated for a different binary"
            )
            raise ValueError(error_msg)

        log_info(
            self.bv,
            f"found {len(matching_modules)} matching module(s): {[m.path for m in matching_modules]}",
        )
        return matching_modules

    def _validate_modules(self, modules):
        """validate modules against binary sections and categorize them"""
        if not self.bv:
            # can't validate without binary view, accept all modules
            return {"valid": modules, "warned": [], "rejected": []}

        # get binary layout info
        try:
            # self.bv.sections is a dict, need to iterate over values
            sections = [(s.name, s.start, s.end) for s in self.bv.sections.values()]
            segments = [(s.start, s.end) for s in self.bv.segments]

            log_debug(
                self.bv, f"found {len(sections)} sections and {len(segments)} segments"
            )
        except Exception as e:
            log_error(self.bv, f"error accessing binary sections/segments: {e}")
            log_error(self.bv, f"full traceback:\n{traceback.format_exc()}")
            # fallback to accepting all modules if we can't validate
            return {"valid": modules, "warned": [], "rejected": []}

        valid_modules = []
        warned_modules = []
        rejected_modules = []

        for module in modules:
            base = module.base

            # check if base matches any segment start (primary validation for runtime addresses)
            segment_matches = [s for s in segments if s[0] == base]
            # check if base matches any section start (secondary validation)
            section_matches = [s for s in sections if s[1] == base]

            if segment_matches:
                valid_modules.append(module)
                log_debug(
                    self.bv,
                    f"module {module.path} base 0x{base:x} matches segment start",
                )
            elif section_matches:
                valid_modules.append(module)
                log_debug(
                    self.bv,
                    f"module {module.path} base 0x{base:x} matches section: {section_matches[0][0]}",
                )
            else:
                # module base doesn't match exactly - check if it's within any segment/section
                in_segment = any(s[0] <= base < s[1] for s in segments)
                in_section = any(s[1] <= base < s[2] for s in sections)

                if in_segment or in_section:
                    warned_modules.append(module)
                    location = "segment" if in_segment else "section"
                    log_warn(
                        self.bv,
                        f"module {module.path} base 0x{base:x} is within binary {location} but doesn't match start",
                    )
                else:
                    rejected_modules.append(module)
                    log_warn(
                        self.bv,
                        f"module {module.path} base 0x{base:x} is outside binary range - rejecting",
                    )

        # log summary
        total_used = len(valid_modules) + len(warned_modules)
        if total_used > 0:
            log_info(
                self.bv,
                f"using {total_used} module(s): {len(valid_modules)} valid, {len(warned_modules)} warned, {len(rejected_modules)} rejected",
            )

        if rejected_modules:
            rejected_bases = [f"0x{m.base:x}" for m in rejected_modules]
            log_warn(self.bv, f"rejected module bases: {', '.join(rejected_bases)}")

        return {
            "valid": valid_modules,
            "warned": warned_modules,
            "rejected": rejected_modules,
        }

    def _create_coverage_trace(self, coverage_data, validated_modules) -> CoverageTrace:
        """create coverage trace from all valid and warned modules"""
        # combine valid and warned modules for coverage aggregation
        all_modules = validated_modules["valid"] + validated_modules["warned"]

        if not all_modules:
            raise ValueError("no valid modules found to create coverage trace from")

        # create module ID lookup map
        module_id_map = {module.id: module for module in all_modules}

        log_info(self.bv, f"creating coverage trace from {len(all_modules)} module(s)")

        # convert drcov modules to our ModuleInfo format
        modules_dict = {}
        for module in all_modules:
            modules_dict[module.id] = ModuleInfo(
                id=module.id,
                base=module.base,
                end=module.end,
                path=module.path
            )

        # convert basic blocks to CoverageBlock format
        blocks = []
        if coverage_data.has_hit_counts():
            # use hit counts from the file
            for i, bb in enumerate(coverage_data.basic_blocks):
                if bb.module_id in module_id_map:
                    module = module_id_map[bb.module_id]
                    abs_addr = module.base + bb.start
                    hitcount = coverage_data.get_hit_count(i)
                    blocks.append(CoverageBlock(
                        address=abs_addr,
                        size=bb.size,
                        hitcount=hitcount,
                        module_id=bb.module_id
                    ))
        else:
            # no hit counts, treat each block as hit once
            for bb in coverage_data.basic_blocks:
                if bb.module_id in module_id_map:
                    module = module_id_map[bb.module_id]
                    abs_addr = module.base + bb.start
                    blocks.append(CoverageBlock(
                        address=abs_addr,
                        size=bb.size,
                        hitcount=1,
                        module_id=bb.module_id
                    ))

        # create the trace
        trace = CoverageTrace(
            format=TraceFormat.BLOCKS,
            blocks=blocks,
            modules=modules_dict,
            source_file=self.filepath
        )

        return trace
