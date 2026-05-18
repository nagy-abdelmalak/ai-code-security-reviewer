from fastapi import FastAPI
from pydantic import BaseModel

class CodeRequest(BaseModel):
    code: str

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Welcome to AI CODE SECURITY REVIEWER!"}

@app.post("/review")
def analyze(request: CodeRequest):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
        tmp.write(request.code.encode())
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["bandit", "-f", "json", tmp_path], 
            capture_output=True, 
            text=True
        )
        return result.stdout

    except subprocess.CalledProcessError as e:
        return {
            "message": "Error running bandit",
            "error": str(e)
        }
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