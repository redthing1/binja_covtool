from .drcov import parse_drcov
from .addrtrace import parse_addrtrace


def detect_and_parse(bv, filepath):
    """auto-detect format and parse coverage file"""
    with open(filepath, "rb") as f:
        header = f.read(16)

    # check for drcov magic
    if header.startswith(b"DRCOV"):
        return parse_drcov(bv, filepath)

    # otherwise assume address trace
    return parse_addrtrace(bv, filepath)
