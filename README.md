# AI Code Security Reviewer

AI Code Security Reviewer is a web application that analyzes source code for security vulnerabilities by combining deterministic SAST with LLM-powered review.

The project is designed as a comparison tool between automated analysis (Semgrep/Bandit) and AI review, with a web UI, REST API, and role-based workflows for developers, auditors, and admins.

## Key features

- Python code analysis with Semgrep and Bandit
- LLM-based review support via LangChain
- Web interface for submitting source code and viewing results
- REST API with JWT authentication
- RBAC roles: `developer`, `auditor`, `admin`
- JSON export of submissions, analyses, and reviews
- Automatic initial admin bootstrap on startup

## Tech stack

- Python 3.12
- FastAPI
- SQLModel + PostgreSQL
- Semgrep
- Bandit
- LangChain
- Jinja2
- Uvicorn
- Docker / Docker Compose

## Prerequisites

- Python 3.12
- PostgreSQL (or Docker Compose)
- `uv` package manager (`pip install uv` if not already installed)
- `.env` file with environment settings and LLM API keys

## Local setup

1. Clone the repository:

   ```bash
   git clone https://github.com/<your-username>/ai-code-security-reviewer.git
   cd ai-code-security-reviewer
   ```

2. Copy the example env file and configure variables:

   ```bash
   cp .env.example .env
   ```

3. Install dependencies and sync the environment:

   ```bash
   uv sync --no-dev
   ```

4. Start the app in development mode:

   ```bash
   uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

5. Open the browser:

   - UI: `http://localhost:8000/web/`
   - API docs: `http://localhost:8000/docs`

## Docker Compose

Use `docker-compose.yml` to start the app with PostgreSQL:

```bash
docker compose up --build
```

The application will be available at `http://localhost:8000`.

## Configuration

Copy `.env.example` to `.env` and set at minimum:

- `DATABASE_URL`
- `JWT_SECRET_KEY`
- `INITIAL_ADMIN_EMAIL`
- `INITIAL_ADMIN_PASSWORD`
- LLM keys: `OPENROUTER_API_KEY`, `GROQ_API_KEY`, `GOOGLE_API_KEY`

Other useful variables:

- `ENVIRONMENT`
- `ENABLED_SAST_ANALYZERS` (for example `semgrep,bandit`)
- `SEMGREP_RULESET`
- `BANDIT_SEVERITY`
- `BANDIT_CONFIDENCE`

## Roles and permissions

- `developer`: submit code and view own submissions
- `auditor`: review findings and add review comments
- `admin`: administrative management and initial bootstrap

## Main API endpoints

- `POST /auth/register` - user registration
- `POST /auth/login` - login and obtain JWT tokens
- `GET /auth/me` - fetch current user info
- `POST /submissions/` - submit code for analysis
- `GET /submissions/` - list user submissions
- `GET /submissions/{submission_id}` - get submission details with analyses
- `POST /findings/{finding_id}/reviews` - create a review (auditor only)
- `GET /findings/{finding_id}/reviews` - list reviews for a finding
- `GET /export/{submission_id}/json` - export submission and analysis to JSON

## Testing

Run the test suite with:

```bash
uv run python -m pytest tests
```

## Useful scripts

- `scripts/benchmark_analyzers.py` - benchmark and compare analyzers
- `scripts/debug_analyzers.py` - debug analyzer output
- `scripts/test_scanners.py` - local Semgrep/Bandit scanner tests

## Notes

- The app mounts the code at startup and bootstraps an initial admin if none exists.
- For production use, set strong secret keys and use `ENVIRONMENT=production`.
- Use `http://localhost:8000/docs` to explore the automatically generated OpenAPI documentation.
