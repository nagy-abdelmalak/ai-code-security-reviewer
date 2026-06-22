from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.core.logging import get_logger
from app.core.templates import templates
from app.core.security import decode_token
from app.models import User, Submission, Analysis, Finding
from app.api.deps import get_analysis_service
from app.db.session import get_session
from app.services.auth_service import AuthService, EmailAlreadyRegistered

logger = get_logger(__name__)

router = APIRouter(prefix="/web", tags=["web"])

def _get_token(request: Request) -> str | None:
    """Read JWT from cookie"""
    return request.cookies.get("access_token")

def _set_token(response: Response, token: str) -> None:
        """Store JWT in httpOnly cookie."""
        response.set_cookie(
            key="access_token",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=1800,  # 30 min
        )

# ---- Auth pages ----
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request, "login.html", 
        {"request": request, "token": None}
    )

@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session)
):
    service = AuthService(session)
    user = service.authenticate(email=email, password=password)
    if not user:
        return templates.TemplateResponse(
            request, "login.html",
            {"request": request, 
            "error": "Invalid email or password",
            "token": None
            }
        )

    tokens = service.issue_tokens(user)
    response = RedirectResponse(
        url="/web/submit", 
        status_code=status.HTTP_303_SEE_OTHER
    )
    _set_token(response=response, token=tokens.access_token)
    return response

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
     return templates.TemplateResponse(
        request, "register.html",
        {"request": request, "token": None}    
    )

@router.post("/register", response_class=HTMLResponse)
async def register_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session)
):
    service = AuthService(session)
    try:
        service.register(
            type("Req", (), {"email": email, "password": password})
        )
    except EmailAlreadyRegistered:
        return templates.TemplateResponse(
            request, "register.html",
            {"request": request, "error": "Email already registered", "token": None}
        )
    except Exception as e:
        return templates.TemplateResponse(
            request, "register.html",
            {"request": request, "error": str(e), "token": None}
        )
    
    return templates.TemplateResponse(
        request, "register.html",
        {
            "request": request,
            "success": "Account created! You can now log in.",
            "token": None,
        },
    )

@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/web/login", status_code=303)
    response.delete_cookie("access_token")
    return response

# ----- Protected pages -----
def _get_current_user_from_cookie(request: Request, session: Session):
    """Decode JWT from cookie, return user or None"""
    token = _get_token(request)
    if not token:
        return None
    
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id or payload.get("type") != "access":
            return None
        user = session.get(User, UUID(user_id))
        return user if user and user.is_active else None
    except Exception:
        return None

@router.get("/submit", response_class=HTMLResponse)
async def submit_page(
    request: Request,
    session: Session = Depends(get_session)
):
    user = _get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(
            url="/web/login", status_code=status.HTTP_303_SEE_OTHER
        )

    return templates.TemplateResponse(
        request, "submit.html",
        {"request": request, "token": True}
    )

@router.post("/submit", response_class=HTMLResponse)
async def submit_code(
    request: Request,
    code: str = Form(...),
    run_llm_str: str = Form(default=""),
    explanation_enabled_str: str = Form(default=""),
    session: Session = Depends(get_session)
):
    user = _get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(
            url="/web/login", status_code=status.HTTP_303_SEE_OTHER
        )
    
    run_llm = run_llm_str == "true"
    explanation_enabled = explanation_enabled_str == "true"

    service = get_analysis_service(session=session, run_llm=run_llm)
    try:
        submission, _ = await service.create_and_analyze(
            code=code,
            language="python",
            user=user,
            run_llm=run_llm,
            explanation_enabled=explanation_enabled
        )
        return RedirectResponse(
            url=f"/web/results/{submission.id}",
            status_code=303,
        )
    except Exception as e:
        logger.exception("web_submit_error")
        return templates.TemplateResponse(
            request, "submit.html",
            {"request": request, "token": True, "error": str(e), "code": code},
        )

@router.get("/results/{submission_id}", response_class=HTMLResponse)
async def results_page(
    request: Request,
    submission_id: UUID,
    session: Session = Depends(get_session),
):
    user = _get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(url="/web/login", status_code=303)

    submission = session.get(Submission, submission_id)
    if not submission:
        return templates.TemplateResponse(
            request, "base.html",
            {"request": request, "token": True, "error": "Submission not found"},
        )

    analyses_raw = session.exec(
        select(Analysis).where(Analysis.submission_id == submission_id)
    ).all()

    analyses = []
    for a in analyses_raw:
        findings = session.exec(
            select(Finding).where(Finding.analysis_id == a.id)
        ).all()
        analyses.append({
            "analyzer_type": a.analyzer_type.value,
            "status": a.status.value,
            "duration_ms": (
                int((a.completed_at - a.started_at).total_seconds() * 1000)
                if a.completed_at and a.started_at
                else None
            ),
            "error_message": a.error_message,
            "findings": [
                {
                    "id": str(f.id),
                    "severity": f.severity.value,
                    "line_number": f.line_number,
                    "rule_id": f.rule_id,
                    "message": f.message,
                    "explanation": f.explanation,
                    "status": f.status.value,
                }
                for f in findings
            ],
        })

    return templates.TemplateResponse(
        request, "results.html",
        {
            "request": request,
            "token": True,
            "submission": {
                "id": str(submission.id),
                "language": submission.language,
                "created_at": submission.created_at.isoformat(),
            },
            "analyses": analyses,
        },
    )

@router.get("/history", response_class=HTMLResponse)
async def history_page(
    request: Request,
    session: Session = Depends(get_session),
):
    user = _get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(url="/web/login", status_code=303)

    submissions = session.exec(
        select(Submission)
        .where(Submission.user_id == user.id)
        .order_by(Submission.created_at.desc())
    ).all()

    return templates.TemplateResponse(
        request, "history.html",
        {
            "request": request,
            "token": True,
            "submissions": [
                {
                    "id": str(s.id),
                    "language": s.language,
                    "source_mode": s.source_mode,
                    "created_at": s.created_at.isoformat(),
                }
                for s in submissions
            ],
        },
    )

@router.get("/", response_class=HTMLResponse)
async def home(request: Request, session: Session = Depends(get_session)):
    user = _get_current_user_from_cookie(request, session)
    if user:
        return RedirectResponse(url="/web/submit", status_code=303)
    return RedirectResponse(url="/web/login", status_code=303)