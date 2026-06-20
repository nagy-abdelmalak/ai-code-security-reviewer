import asyncio
from contextlib import asynccontextmanager

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