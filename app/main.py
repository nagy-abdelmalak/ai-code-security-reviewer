from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from pydantic import BaseModel
import uuid
import structlog

from app.core.config import settings
import app.models
from app.db.session import init_db
from app.core.logging import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

class CodeRequest(BaseModel):
    code: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up")
    init_db()
    logger.info("Database initialized")
    # bootstrap_admin()
    # logger.info("Admin bootstrap complete")
    yield
    logger.info("Shutting down")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    description="Security review of code using a SAST tool and LLM",
    # docs_url="/docs",
    # redoc_url="/redoc",
    # openapi_url="/openapi.json",
    lifespan=lifespan,
    # dependencies=[Depends(get_session)],
)

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

@app.get("/")
def root():
    return {"message": "Welcome to AI CODE SECURITY REVIEWER!"}

@app.get("/health")
def health():
    return {
        "status": "OK",
        "environment": settings.ENVIRONMENT
    }

# @app.post("/review")
# def analyze(request: CodeRequest):
#     with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
#         tmp.write(request.code.encode())
#         tmp_path = tmp.name

#     try:
#         result = subprocess.run(
#             ["bandit", "-f", "json", tmp_path], 
#             capture_output=True, 
#             text=True
#         )
#         return result.stdout

#     except subprocess.CalledProcessError as e:
#         return {
#             "message": "Error running bandit",
#             "error": str(e)
#         }
    # if "eval(" in request.code:
    #     return {
    #         "vulnerabilities": [
    #             {   "type": "Code Injection",
    #                 "description": "The request contains a code injection vulnerability.",
    #                 "severity": "High",
    #                 "line_number": 10,
    #                 "file_name": "main.py",
    #                 "suggestions": "Use a safer function instead of eval.",
    #             }
    #         ]
    #     }
    # return {"message": "No vulnerabilities found."}