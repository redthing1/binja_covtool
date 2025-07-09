from binaryninja import BackgroundTaskThread
from binaryninja.interaction import show_message_box

from .context import get_context
from .parsers import detect_and_parse
from .settings import my_settings
from .logging import log_info, log_error


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
            self.progress = "Parsing coverage file..."
            if self.cancelled:
                return

            self.coverage_data = detect_and_parse(self.bv, self.filepath)
            if self.cancelled:
                return

            # phase 2: load into database
            self.progress = "Loading into database..."
            ctx = get_context(self.bv)

            # if the coverage data is large, show progress during loading
            if isinstance(self.coverage_data, dict) and len(self.coverage_data) > 1000:
                # load in chunks with progress updates
                total = len(self.coverage_data)
                processed = 0
                chunk_size = max(100, total // 20)  # 5% chunks

                # clear existing coverage first
                ctx.covdb.clear()
                ctx.covdb.coverage_file = self.filepath

                items = list(self.coverage_data.items())
                for i in range(0, len(items), chunk_size):
                    if self.cancelled:
                        ctx.covdb.clear()  # rollback on cancel
                        return

                    chunk = items[i : i + chunk_size]
                    for addr, hitcount in chunk:
                        ctx.covdb._add_address_coverage(addr, hitcount)

                    processed += len(chunk)
                    percent = int((processed / total) * 100)
                    self.progress = f"Loading coverage data... {percent}%"
            else:
                # small dataset, load normally
                ctx.covdb.load_coverage(self.filepath, self.coverage_data)

            if self.cancelled:
                ctx.covdb.clear()  # rollback on cancel
                return

            # phase 3: apply filter and paint
            self.progress = "Applying coverage highlights..."

            # determine what to paint
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

            if self.cancelled:
                # if cancelled during painting, clear highlights
                ctx.painter.clear_highlights()
                ctx.covdb.clear()
                return

            # show stats if enabled
            if my_settings.get_bool("covtool.showStatsInLog"):
                stats = ctx.covdb.get_coverage_stats()
                msg = f"loaded coverage: {stats['total_covered']} instructions from {stats['unique_blocks']} blocks"
                if stats["invalid_addresses"] > 0:
                    msg += f" ({stats['invalid_addresses']} invalid addresses ignored)"
                log_info(self.bv, msg)

        except Exception as e:
            self.error = str(e)
            log_error(self.bv, f"coverage import failed: {e}")

    def finish(self):
        """called when task completes"""
        if self.cancelled:
            log_info(self.bv, "coverage import cancelled")
        elif self.error:
            show_message_box("Error", f"Failed to import coverage: {self.error}")
        else:
            # success - nothing to do, stats already logged if enabled
            pass
