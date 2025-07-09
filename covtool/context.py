from dataclasses import dataclass
from .coverage_db import CoverageDB
from .painter import CoveragePainter


@dataclass
class CovToolContext:
    """per-BinaryView plugin state"""

    covdb: CoverageDB
    painter: CoveragePainter
    filter_hitcount: int = 0  # current filter setting
    filter_mode: str = "disabled"  # "disabled", "minimum", "maximum", "exact"
    heatmap_enabled: bool = False  # track heatmap visualization state


def get_context(bv) -> CovToolContext:
    """get or create context for BinaryView"""
    if "covtool" not in bv.session_data:
        covdb = CoverageDB(bv)
        painter = CoveragePainter(bv, covdb)
        ctx = CovToolContext(covdb=covdb, painter=painter)
        bv.session_data["covtool"] = ctx
    return bv.session_data["covtool"]
