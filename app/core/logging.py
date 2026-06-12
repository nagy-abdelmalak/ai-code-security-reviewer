import logging.config
import Logging
from datetime import datetime

settings = get_settings()
LOG_DIR = settings.LOG_DIR

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

config_dict = {
    "version": 1,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": settings.LOG_LEVEL,
            "formatter": "default"
        },
        "file": {
            "class": "logging.FileHandler",
            "level": settings.LOG_LEVEL,
            "formatter": "default",
            "filename": f"{LOG_DIR}/{logger_name}_{timestamp}.log"
        }
    },
    "root": {
        "handlers": ["console", "file"],
        "level": settings.LOG_LEVEL,
    },
    "loggers": {
        "app": {
            "handlers": ["console", "file"],
            "level": settings.LOG_LEVEL,
            "propagate": False,
        },
        "fastapi": {
            "handlers": ["console", "file"],
            "level": settings.LOG_LEVEL,
            "propagate": False,
        },
        "database": {
            "handlers": ["console", "file"],
            "level": settings.LOG_LEVEL,
            "propagate": False,
        },
    }
}

logging.config.dictConfig(config_dict)

logger = logging.getLogger("app")
logger.info("Logging configured")