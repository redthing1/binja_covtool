from binaryninja import *
from binaryninja.interaction import (
    get_open_filename_input,
    get_form_input,
    IntegerField,
    show_message_box,
    ChoiceField,
)
from binaryninja.enums import HighlightStandardColor
from binaryninja.highlight import HighlightColor

import binaryninja._binaryninjacore as core

from .context import get_context
from .parsers import detect_and_parse
from .settings import my_settings

# cache BNGetInstructionLength for performance
BNGetInstructionLength = core.BNGetInstructionLength


def import_coverage(bv):
    """import a coverage file"""
    filepath = get_open_filename_input("Select coverage file")
    if not filepath:
        return

    ctx = get_context(bv)

    # parse coverage file
    try:
        coverage_data = detect_and_parse(bv, filepath)
    except Exception as e:
        show_message_box("error", f"failed to parse coverage file: {e}")
        return

    # load into database
    ctx.covdb.load_coverage(filepath, coverage_data)

    # apply current filter and paint
    if ctx.filter_mode != "disabled" and ctx.filter_hitcount > 0:
        filtered_addrs = ctx.covdb.filter_by_hitcount(
            ctx.filter_hitcount, ctx.filter_mode
        )
        ctx.painter.paint_coverage(filtered_addrs)
    else:
        ctx.painter.paint_coverage()

    # show stats if enabled
    if my_settings.get_bool("covtool.showStatsInLog"):
        stats = ctx.covdb.get_coverage_stats()
        log_info(
            f"loaded coverage: {stats['total_covered']} instructions from {stats['unique_blocks']} blocks"
        )


def filter_coverage(bv):
    """open filter dialog"""
    ctx = get_context(bv)

    # create form fields
    mode_field = ChoiceField("filter mode", ["disabled", "minimum", "maximum", "exact"])

    # set default selection based on current mode
    mode_map = {"disabled": 0, "minimum": 1, "maximum": 2, "exact": 3}
    mode_field.result = mode_map.get(ctx.filter_mode, 0)

    hitcount_field = IntegerField("hitcount value")
    hitcount_field.result = ctx.filter_hitcount if ctx.filter_hitcount > 0 else 1

    form = get_form_input([mode_field, hitcount_field], "filter coverage")

    if form:
        # map choice back to mode string
        mode_names = ["disabled", "minimum", "maximum", "exact"]
        ctx.filter_mode = mode_names[mode_field.result]
        ctx.filter_hitcount = hitcount_field.result

        # repaint with filter
        if ctx.covdb.coverage_file:
            if ctx.filter_mode != "disabled" and ctx.filter_hitcount > 0:
                filtered_addrs = ctx.covdb.filter_by_hitcount(
                    ctx.filter_hitcount, ctx.filter_mode
                )
                ctx.painter.paint_coverage(filtered_addrs)
            else:
                ctx.painter.paint_coverage()


def clear_coverage(bv):
    """clear all coverage data and highlights"""
    ctx = get_context(bv)
    ctx.painter.clear_highlights()
    ctx.covdb.clear()
    ctx.filter_hitcount = 0
    ctx.filter_mode = "disabled"
    log_info("coverage cleared")


def toggle_heatmap(bv):
    """toggle between solid color and heatmap visualization"""
    ctx = get_context(bv)

    if not ctx.covdb.coverage_file:
        show_message_box("no coverage", "no coverage file loaded")
        return

    # for now, just switch to heatmap
    # later could track state and toggle
    if ctx.filter_mode != "disabled" and ctx.filter_hitcount > 0:
        filtered_addrs = ctx.covdb.filter_by_hitcount(
            ctx.filter_hitcount, ctx.filter_mode
        )
        ctx.painter.paint_heatmap(filtered_addrs)
    else:
        ctx.painter.paint_heatmap()


# register plugin commands
PluginCommand.register(
    "CovTool\\Import Coverage",
    "Import a coverage file (drcov or address trace)",
    import_coverage,
)

PluginCommand.register(
    "CovTool\\Filter Coverage", "Filter coverage by minimum hitcount", filter_coverage
)

PluginCommand.register(
    "CovTool\\Clear Coverage", "Clear all coverage data and highlights", clear_coverage
)

PluginCommand.register(
    "CovTool\\Toggle Heatmap", "Toggle heatmap visualization", toggle_heatmap
)
