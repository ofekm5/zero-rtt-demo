"""Unit tests for logger.py"""

import pytest
import logging

from clientnic.logger import setup_logging


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_returns_logger(self):
        """Test function returns a logger instance."""
        logger = setup_logging()
        assert isinstance(logger, logging.Logger)

    def test_logger_name(self):
        """Test logger has correct name."""
        logger = setup_logging()
        assert logger.name == "clientnic"

    def test_default_level(self):
        """Test default log level is INFO."""
        logger = setup_logging()
        assert logger.level == logging.INFO

    def test_custom_level(self):
        """Test custom log level is applied."""
        logger = setup_logging(level=logging.DEBUG)
        assert logger.level == logging.DEBUG

    def test_has_handler(self):
        """Test logger has at least one handler."""
        logger = setup_logging()
        assert len(logger.handlers) >= 1

    def test_handler_is_stream_handler(self):
        """Test handler is a StreamHandler."""
        # Clear existing handlers first
        logger = logging.getLogger("clientnic")
        logger.handlers.clear()

        logger = setup_logging()

        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)

    def test_no_duplicate_handlers(self):
        """Test calling setup_logging multiple times doesn't add duplicate handlers."""
        # Clear existing handlers
        logger = logging.getLogger("clientnic")
        logger.handlers.clear()

        setup_logging()
        initial_count = len(logging.getLogger("clientnic").handlers)

        setup_logging()
        final_count = len(logging.getLogger("clientnic").handlers)

        assert final_count == initial_count

    def test_formatter_format(self):
        """Test handler has correct format."""
        # Clear existing handlers
        logger = logging.getLogger("clientnic")
        logger.handlers.clear()

        logger = setup_logging()

        handler = logger.handlers[0]
        # Check format contains expected components
        assert handler.formatter._fmt == "[%(levelname)s] %(name)s: %(message)s"
