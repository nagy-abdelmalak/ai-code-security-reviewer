import asyncio
from contextlib import asynccontextmanager
from app.core.logging import get_logger
from app.core.config import settings

logger = get_logger(__name__)

@asynccontextmanager
async def safe_subprocess(process: asyncio.subprocess.Process):
    """Guarantess process cleanup and reaps the PID to prevent zombie processes leakage"""
    try:
        yield process
    finally:
        if process.returncode is None:
            try:
                process.kill()
                await process.wait()
            except OSError:
                pass

async def run_subprocess(
    args: list[str],
    tool_name: str,
    timeout: int = settings.TIMEOT_SECONDS,
    success_exit_codes: tuple[int, ...] = (0, 1),
) -> tuple[str, str, int] | None:
    """
    Run a CLI tool safely as a subprocess.

    Uses safe_subprocess to guarantee process cleanup and prevent
    zombie process leakage even on timeout or exception.

    Returns (stdout, stderr, returncode) if exit code is in success_exit_codes.
    Returns None on timeout or binary not found — caller decides how to handle.
    """

    # --- Step 1: Spawn the process ---
    try:
        process = await asyncio.create_subprocess_exec(
            *args,                              # unpack list into positional args
            stdout=asyncio.subprocess.PIPE,     # capture stdout for JSON parsing
            stderr=asyncio.subprocess.PIPE,     # capture stderr for error messages
        )
    except FileNotFoundError:
        # The binary (e.g. "semgrep") is not on PATH — tool not installed
        logger.error(f"{tool_name}_not_installed", command=args[0])
        return None

    # --- Step 2: Enter safe context ---
    async with safe_subprocess(process):
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),          # read stdout + stderr, wait for exit
                timeout=timeout,                # raise TimeoutError if exceeded
            )
        except asyncio.TimeoutError:
            logger.warning(f"{tool_name}_timeout", timeout=timeout)
            return None

    # --- Step 3: Check exit code ---
    if process.returncode not in success_exit_codes:
        logger.error(
            f"{tool_name}_execution_failed",
            code=process.returncode,
            error=stderr.decode("utf-8", errors="replace")[:300],
        )
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            process.returncode,
        )

    # --- Step 4: Return decoded output ---
    return (
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
        process.returncode,
    )