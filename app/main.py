from fastapi import FastAPI, Depends
from pydantic import BaseModel
import tempfile
import subprocess
from app.core.config import get_settings
from app.db.session import get_session

settings = get_settings()

class CodeRequest(BaseModel):
    code: str

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    description="Security review of code using a SAST tool and LLM",
    # docs_url="/docs",
    # redoc_url="/redoc",
    # openapi_url="/openapi.json",
    # lifespan=lifespan,
    dependencies=[Depends(get_session)],
)

@app.get("/")
def root():
    return {"message": "Welcome to AI CODE SECURITY REVIEWER!"}

@app.get("/health")
def health():
    return {
        "status": "OK",
        "environment": settings.ENVIRONMENT,
        # "database": "Connected" if get_session().exec("SELECT 1").fetchone() else "Disconnected"
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