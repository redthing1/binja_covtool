"""coverage file parsers"""

from .drcov_parser import DrCovParser
from .addrtrace_parser import AddressTraceParser
from .addrhittrace_parser import AddressHitTraceParser
from ..logging import log_info, log_error

# list of parsers in order of priority
PARSERS = [
    DrCovParser,  # check drcov first (has magic header)
    AddressHitTraceParser,  # check address+hit before plain address
    AddressTraceParser,  # fallback to plain address trace
]


def detect_and_parse(bv, filepath):
    """auto-detect format and parse coverage file"""
    # try each parser in order
    last_error = None
    detected_format = None

    for parser_class in PARSERS:
        parser = parser_class(bv, filepath)
        if parser.can_parse():
            log_info(bv, f"detected format: {parser.format_name}")
            detected_format = parser.format_name
            try:
                coverage = parser.parse()
                return coverage
            except Exception as e:
                last_error = e
                log_error(bv, f"failed to parse as {parser.format_name}: {e}")
                # continue to next parser

    # no parser could handle the file
    if detected_format and last_error:
        # we detected a format but failed to parse it - this is a parsing error, not unsupported format
        raise ValueError(f"failed to parse {detected_format} format: {last_error}")
    else:
        # no format was detected - this is truly unsupported
        raise ValueError("unsupported coverage file format")


def get_supported_formats():
    """get list of supported format names"""
    return [parser_class(None, None).format_name for parser_class in PARSERS]
