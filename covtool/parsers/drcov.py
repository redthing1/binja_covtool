import os
import sys

# add the formats directory to the path to import the existing drcov module
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "formats"))
import drcov as drcov_lib


def parse_drcov(bv, filepath):
    """parse drcov file and return coverage dict"""
    # use the existing drcov library to parse the file
    coverage_data = drcov_lib.read(filepath)

    # find the module that matches our binary
    target_filename = os.path.basename(bv.file.original_filename)
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

    # convert basic blocks to absolute addresses with hitcounts
    coverage = {}

    # check if we have hit counts
    if coverage_data.has_hit_counts():
        # use hit counts from the file
        for i, bb in enumerate(coverage_data.basic_blocks):
            if bb.module_id == target_module.id:
                # convert module offset to absolute address in BinaryView
                abs_addr = bv.start + bb.start
                hitcount = coverage_data.get_hit_count(i)
                coverage[abs_addr] = coverage.get(abs_addr, 0) + hitcount
    else:
        # no hit counts, treat each block as hit once
        for bb in coverage_data.basic_blocks:
            if bb.module_id == target_module.id:
                # convert module offset to absolute address in BinaryView
                abs_addr = bv.start + bb.start
                coverage[abs_addr] = coverage.get(abs_addr, 0) + 1

    return coverage
