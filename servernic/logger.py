"""Logging setup for ServerNIC."""

import logging


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure and return the ServerNIC logger."""
    logger = logging.getLogger("servernic")
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(handler)

    return logger
