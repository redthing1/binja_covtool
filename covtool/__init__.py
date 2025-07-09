from binaryninja import *
from binaryninja.interaction import (
    get_open_filename_input,
    get_form_input,
    IntegerField,
    show_message_box,
    ChoiceField,
)

from .context import get_context
from .parsers import detect_and_parse
from .settings import my_settings
from .tasks import CoverageImportTask


def import_coverage(bv):
    """import a coverage file"""
    filepath = get_open_filename_input("Select coverage file")
    if not filepath:
        return

    # create and start background task
    task = CoverageImportTask(bv, filepath)
    task.start()


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
        ctx.filter_hitcount = max(0, hitcount_field.result)  # ensure non-negative

        # repaint with filter
        _repaint_coverage(ctx)


def clear_coverage(bv):
    """clear all coverage data and highlights"""
    ctx = get_context(bv)
    ctx.painter.clear_highlights()
    ctx.covdb.clear()
    ctx.filter_hitcount = 0
    ctx.filter_mode = "disabled"
    ctx.heatmap_enabled = False
    log_info("coverage cleared")


def _repaint_coverage(ctx):
    """helper to repaint coverage with current settings"""
    if not ctx.covdb.coverage_file:
        return

    # get filtered addresses if filter is active
    coverage_addrs = None
    if ctx.filter_mode != "disabled" and ctx.filter_hitcount > 0:
        coverage_addrs = ctx.covdb.filter_by_hitcount(
            ctx.filter_hitcount, ctx.filter_mode
        )

    # paint with appropriate method
    if ctx.heatmap_enabled:
        ctx.painter.paint_heatmap(coverage_addrs)
    else:
        ctx.painter.paint_coverage(coverage_addrs)


def toggle_heatmap(bv):
    """toggle between solid color and heatmap visualization"""
    ctx = get_context(bv)

    if not ctx.covdb.coverage_file:
        show_message_box("no coverage", "no coverage file loaded")
        return

    # toggle state
    ctx.heatmap_enabled = not ctx.heatmap_enabled

    # repaint with new state
    _repaint_coverage(ctx)

    # log the change
    mode = "heatmap" if ctx.heatmap_enabled else "solid color"
    log_info(f"switched to {mode} visualization")


# register plugin commands
PluginCommand.register(
    "CovTool\\Import Coverage",
    "Import a coverage file (drcov or address trace)",
    import_coverage,
)

PluginCommand.register(
    "CovTool\\Filter Coverage", "Filter coverage by hitcount", filter_coverage
)

PluginCommand.register(
    "CovTool\\Clear Coverage", "Clear all coverage data and highlights", clear_coverage
)

PluginCommand.register(
    "CovTool\\Toggle Heatmap", "Toggle heatmap visualization", toggle_heatmap
)
