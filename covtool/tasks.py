from binaryninja import BackgroundTaskThread
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

from .context import get_context
from .parsers import detect_and_parse
from .settings import my_settings
from .logging import log_info, log_error
from .coverage_types import CoverageTrace


class CoverageImportTask(BackgroundTaskThread):
    """background task for importing coverage files"""

    def __init__(self, bv, filepath):
        super().__init__("Importing coverage...", can_cancel=True)
        self.bv = bv
        self.filepath = filepath
        self.coverage_data = None
        self.error = None

    def run(self):
        """run the import task"""
        try:
            # phase 1: parse coverage file
            import os

            filename = os.path.basename(self.filepath)
            self.progress = f"Parsing {filename}..."
            if self.cancelled:
                return

            self.coverage_trace = detect_and_parse(self.bv, self.filepath)
            if self.cancelled:
                return

            # get initial stats
            total_blocks = self.coverage_trace.total_blocks()
            total_hits = self.coverage_trace.total_hits()
            self.progress = (
                f"Parsed {total_blocks:,} blocks with {total_hits:,} total hits"
            )

            # phase 2: load into database
            self.progress = "Loading into database..."
            ctx = get_context(self.bv)

            # load coverage trace into database
            if self.coverage_trace.total_blocks() > 1000:
                # large dataset, show progress during loading
                self.progress = f"Loading {self.coverage_trace.total_blocks():,} blocks into database..."

            ctx.covdb.load_coverage_trace(self.coverage_trace)

            if self.cancelled:
                ctx.covdb.clear()  # rollback on cancel
                return

            # phase 3: apply filter and paint
            stats = ctx.covdb.get_coverage_stats()
            valid_count = stats["total_covered"]
            invalid_count = stats["invalid_addresses"]

            if invalid_count > 0:
                self.progress = (
                    f"Validated {valid_count:,} addresses ({invalid_count:,} invalid)"
                )
            else:
                self.progress = f"Validated {valid_count:,} addresses"

            # determine what to paint
            coverage_addrs = None
            if ctx.filter_mode != "disabled" and ctx.filter_hitcount > 0:
                coverage_addrs = ctx.covdb.filter_by_hitcount(
                    ctx.filter_hitcount, ctx.filter_mode
                )
                filtered_count = len(coverage_addrs) if coverage_addrs else 0
                self.progress = (
                    f"Applying filter ({filtered_count:,}/{valid_count:,} addresses)..."
                )
            else:
                self.progress = f"Highlighting {valid_count:,} addresses..."

            # paint with appropriate method
            if ctx.heatmap_enabled:
                ctx.painter.paint_heatmap(coverage_addrs)
            else:
                ctx.painter.paint_coverage(coverage_addrs)

            if self.cancelled:
                # if cancelled during painting, clear highlights
                ctx.painter.clear_highlights()
                ctx.covdb.clear()
                return

            # final progress update
            mode = "heatmap" if ctx.heatmap_enabled else "coverage"
            self.progress = f"Coverage imported: {valid_count:,} addresses highlighted"

            # show stats if enabled
            if my_settings.get_bool("covtool.showStatsInLog"):
                stats = ctx.covdb.get_coverage_stats()
                msg = f"loaded coverage: {stats['total_covered']} instructions from {stats['unique_blocks']} blocks"
                if stats["invalid_addresses"] > 0:
                    msg += f" ({stats['invalid_addresses']} invalid addresses ignored)"
                log_info(self.bv, msg)

            # mark task as finished
            self.finish()

        except Exception as e:
            self.error = str(e)
            log_error(self.bv, f"coverage import failed: {e}")
            self.cancel()

    def _show_error_dialog(self):
        """Show appropriate error dialog based on error type"""
        error_lower = self.error.lower()

        if "could not find module matching" in error_lower:
            # Module matching error - show detailed error popup
            title = "Module Matching Error"
            icon = MessageBoxIcon.ErrorIcon
            show_message_box(
                title,
                f"Coverage Import Failed\n\n{self.error}",
                MessageBoxButtonSet.OKButtonSet,
                icon,
            )
        elif "module base" in error_lower and "doesn't match" in error_lower:
            # Module base validation warning
            title = "Module Base Mismatch Warning"
            icon = MessageBoxIcon.WarningIcon
            show_message_box(
                title,
                f"Coverage Import Warning\n\n{self.error}\n\nThe coverage data may not be accurate.",
                MessageBoxButtonSet.OKButtonSet,
                icon,
            )
        else:
            # Generic error
            show_message_box(
                "Coverage Import Error",
                f"Failed to import coverage: {self.error}",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon,
            )
