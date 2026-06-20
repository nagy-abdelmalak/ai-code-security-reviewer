import os
import uuid
from pathlib import Path

from app.core.logging import get_logger

logger = get_logger(__name__)

ANALYSIS_DIR = Path("/tmp/aicsr-analysis")

def create_temp_file(code: str, suffix: str = ".py") -> str:
    """"
    Write code to a secure temporary file. ADR-007 Layer 3.

    - Dedicated directory (not /tmp root)
    - UUID filename (no path traversal)
    - Mode 0600 (owner read/write only)
    """
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

    filename = f"{uuid.uuid4()}{suffix}"
    file_path = ANALYSIS_DIR / filename

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(file_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(code)

    logger.info("temp_file_created", path=str(file_path))

    return str(file_path)

def delete_temp_file(filepath: str) -> None:
    """Delete a temporary file created by create_temp_file"""
    try:
        filepath.unlink(missing_ok=True)
        logger.info("temp_file_deleted", path=str(filepath))
    except OSError as e:
        logger.warning("temp_file_not_found", path=str(filepath), error=str(e))