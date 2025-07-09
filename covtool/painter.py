import math
from binaryninja import *
from binaryninja.enums import HighlightStandardColor
from binaryninja.highlight import HighlightColor
from .settings import my_settings


class CoveragePainter:
    """handles coverage visualization"""

    def __init__(self, bv, covdb):
        self.bv = bv
        self.covdb = covdb
        self.highlighted_addrs = set()

    def paint_coverage(self, coverage_addrs=None, color=None):
        """paint coverage with specified color"""
        # clear only our existing highlights
        self.clear_highlights()

        # use all covered addrs if none specified
        if coverage_addrs is None:
            coverage_addrs = set(self.covdb.hitcounts.keys())

        # default to configured color
        if color is None:
            color_name = my_settings.get_string("covtool.defaultHighlightColor")
            color_map = {
                "orange": HighlightStandardColor.OrangeHighlightColor,
                "cyan": HighlightStandardColor.CyanHighlightColor,
                "red": HighlightStandardColor.RedHighlightColor,
                "blue": HighlightStandardColor.BlueHighlightColor,
                "green": HighlightStandardColor.GreenHighlightColor,
                "magenta": HighlightStandardColor.MagentaHighlightColor,
                "yellow": HighlightStandardColor.YellowHighlightColor,
            }
            color = color_map.get(
                color_name, HighlightStandardColor.OrangeHighlightColor
            )

        # highlight instructions
        for addr in coverage_addrs:
            funcs = self.bv.get_functions_containing(addr)
            for func in funcs:
                func.set_auto_instr_highlight(addr, color)
                self.highlighted_addrs.add((func, addr))

    def paint_heatmap(self, coverage_addrs=None):
        """paint coverage as heatmap based on hitcounts"""
        self.clear_highlights()

        if coverage_addrs is None:
            coverage_addrs = set(self.covdb.hitcounts.keys())

        # calculate hitcount distribution
        hitcounts = [self.covdb.get_hitcount(addr) for addr in coverage_addrs]
        if not hitcounts:
            return

        # sort to find percentiles
        sorted_counts = sorted(hitcounts)

        # get percentile cap from settings
        percentile_cap = my_settings.get_integer("covtool.heatmapPercentileCap")

        # calculate percentile for outlier capping
        percentile_idx = int(len(sorted_counts) * (percentile_cap / 100.0))
        if percentile_idx >= len(sorted_counts):
            percentile_idx = len(sorted_counts) - 1
        cap_value = sorted_counts[percentile_idx]

        # use log scale with capped values
        min_count = min(hitcounts)

        # check if we should use log scale
        use_log_scale = my_settings.get_bool("covtool.heatmapLogScale")

        if use_log_scale:
            # apply log transformation with capping
            # add 1 to avoid log(0), and to make log(1) = 0
            log_min = math.log(min_count + 1)
            log_cap = math.log(cap_value + 1)

        # paint with gradient
        for addr in coverage_addrs:
            hitcount = self.covdb.get_hitcount(addr)
            # cap at configured percentile
            capped_count = min(hitcount, cap_value)

            if use_log_scale:
                color = self._compute_heatmap_color_log(
                    capped_count, min_count, cap_value, log_min, log_cap
                )
            else:
                color = self._compute_heatmap_color(capped_count, min_count, cap_value)

            funcs = self.bv.get_functions_containing(addr)
            for func in funcs:
                func.set_auto_instr_highlight(addr, color)
                self.highlighted_addrs.add((func, addr))

    def _compute_heatmap_color(self, hitcount, min_count, max_count):
        """compute color on spectrum from blue (cold) to red (hot)"""
        if max_count == min_count:
            # all same hitcount, use middle color
            return HighlightColor(red=128, green=0, blue=128)

        # normalize to 0-1 range
        normalized = (hitcount - min_count) / (max_count - min_count)

        # interpolate between blue and red
        blue = int(255 * (1 - normalized))
        red = int(255 * normalized)

        return HighlightColor(red=red, green=0, blue=blue)

    def _compute_heatmap_color_log(
        self, hitcount, min_count, cap_value, log_min, log_cap
    ):
        """compute color on spectrum using logarithmic scale"""
        if cap_value == min_count:
            # all same hitcount, use middle color
            return HighlightColor(red=128, green=0, blue=128)

        # apply log transformation
        log_count = math.log(hitcount + 1)

        # normalize to 0-1 range using log scale
        if log_cap == log_min:
            normalized = 0.5
        else:
            normalized = (log_count - log_min) / (log_cap - log_min)

        # ensure normalized is in [0, 1]
        normalized = max(0, min(1, normalized))

        # interpolate between blue and red
        blue = int(255 * (1 - normalized))
        red = int(255 * normalized)

        return HighlightColor(red=red, green=0, blue=blue)

    def clear_highlights(self):
        """clear only our tracked highlights"""
        # create a copy to avoid modification during iteration
        addrs_to_clear = list(self.highlighted_addrs)
        for func, addr in addrs_to_clear:
            func.set_auto_instr_highlight(addr, HighlightStandardColor.NoHighlightColor)
        self.highlighted_addrs.clear()
