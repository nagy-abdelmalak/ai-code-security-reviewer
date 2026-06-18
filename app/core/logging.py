import logging
import sys
from typing import Any

import structlog

from app.core.config import settings


def configure_logging() -> None:
    """
    Configure structured logging for the whole application.

    - In development: human-friendly colored output to stdout.
    - In production: structured JSON output to stdout (12-Factor App).
    - Uses structlog as the API layer; bridges stdlib `logging` so that
      third-party libraries (uvicorn, sqlalchemy) also produce structured output.
    """
    # Shared processors that run for every log entry, before rendering
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,   # adds bound context (request_id, etc.)
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Choose the final renderer based on environment
    if settings.ENVIRONMENT == "development":
        renderer: Any = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer()

    # Configure structlog itself
    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.LOG_LEVEL.upper())
        ),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Bridge stdlib logging → structlog
    # So that uvicorn, sqlalchemy, etc., also flow through the same pipeline.
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=shared_processors,
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                renderer,
            ],
        )
    )

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(settings.LOG_LEVEL.upper())

    # Tune noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Convenience function — use this in every module instead of importing structlog directly."""
    return structlog.get_logger(name)