"""logging utilities for covtool"""

_logger = None


def get_logger(bv):
    """get or create the covtool logger"""
    global _logger
    if _logger is None:
        _logger = bv.create_logger("CovTool")
    return _logger


def log_info(bv, message):
    """log info message"""
    logger = get_logger(bv)
    logger.log_info(message)


def log_error(bv, message):
    """log error message"""
    logger = get_logger(bv)
    logger.log_error(message)


def log_warn(bv, message):
    """log warning message"""
    logger = get_logger(bv)
    logger.log_warn(message)


def log_debug(bv, message):
    """log debug message"""
    logger = get_logger(bv)
    logger.log_debug(message)
