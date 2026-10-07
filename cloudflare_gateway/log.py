"""Logging helpers.

A tiny wrapper around :mod:`logging` that prefixes each line with a level icon.
Icons are plain Unicode instead of ANSI colors so output stays readable in
CI dashboards and when piped to a file.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import NoReturn

logger = logging.getLogger("cloudflare_gateway")


class IconFormatter(logging.Formatter):
    """Format records as ``<icon> <timestamp> | <message>``."""

    LEVEL_ICONS = {
        logging.DEBUG: "🐞",
        logging.INFO: "ℹ️ ",
        logging.WARNING: "⚠️ ",
        logging.ERROR: "❌",
        logging.CRITICAL: "🔥",
    }

    def format(self, record: logging.LogRecord) -> str:
        icon = self.LEVEL_ICONS.get(record.levelno, "•")
        timestamp = datetime.fromtimestamp(record.created).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]
        message = f"{icon} {timestamp} | {record.getMessage()}"
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        return message


def _configure_logger() -> logging.Logger:
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(IconFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


_configure_logger()


def info(message: str) -> None:
    """Log an informational message."""
    logger.info(message)


def warn(message: str) -> None:
    """Log a non-fatal warning."""
    logger.warning(message)


def error(message: str) -> None:
    """Log an error without aborting."""
    logger.error(message)


def fatal(message: str) -> NoReturn:
    """Log an error and terminate the process with a non-zero exit code."""
    logger.error(message)
    raise SystemExit(1)
