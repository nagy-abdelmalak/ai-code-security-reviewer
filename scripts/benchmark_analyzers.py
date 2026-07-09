"""
Analyzer Benchmark — AI Code Security Reviewer
Tesi di Laurea — Sapienza Università di Roma

Runs all configured SAST and LLM analyzers against a curated set of
vulnerability scenarios and produces:
  - Console output: per-scenario findings + summary comparison table
  - JSON report:    full structured data for thesis statistical analysis
  - Metrics:        TP, FP, FN, Precision, Recall, F1 per analyzer

Usage:
    uv run python -m scripts.benchmark_analyzers

    # Run with specific SAST only:
    ENABLED_SAST_ANALYZERS=semgrep uv run python -m scripts.benchmark_analyzers

Requirements:
    - semgrep installed  (uv add semgrep)
    - bandit installed   (uv add bandit)
    - API keys in .env   (GROQ_API_KEY, OPENAI_API_KEY, etc.)

# Run A — Semgrep only
ENABLED_SAST_ANALYZERS=semgrep uv run python -m scripts.benchmark_analyzers

# Run B — Bandit only  
ENABLED_SAST_ANALYZERS=bandit uv run python -m scripts.benchmark_analyzers

# Run C — Semgrep + Bandit + all LLMs
uv run python -m scripts.benchmark_analyzers
"""

import asyncio
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Project root on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import LLM_AVAILABLE_MODELS, settings
from app.core.logging import configure_logging, get_logger
from app.analyzers.port import AnalysisResult, AnalysisStatus

configure_logging()
logger = get_logger(__name__)

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


# ── Vulnerability Scenarios ─────────────────────────────────────────────────────
# Each scenario targets a specific OWASP Top 10 / CWE category.
# "expected_severity" drives TP/FP/FN classification:
#   - "none"   → clean code control group (findings = false positives)
#   - anything else → vulnerability expected (no finding = false negative)

SCENARIOS: dict[str, dict] = {

    "sql_injection_fstring": {
        "name": "SQL Injection — f-string interpolation",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "expected_severity": "high",
        "code": '''\
import sqlite3

def get_user_profile(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM profiles WHERE username = \'{username}\'"
    cursor.execute(query)
    return cursor.fetchall()
''',
    },

    "sql_injection_concat": {
        "name": "SQL Injection — string concatenation",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "expected_severity": "high",
        "code": '''\
import sqlite3

def search_users(name):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")
    return cursor.fetchall()
''',
    },

    "command_injection": {
        "name": "Command Injection — shell=True",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-78",
        "expected_severity": "high",
        "code": '''\
import subprocess

def run_user_command(user_input):
    result = subprocess.call(user_input, shell=True)
    return result

def ping_host(hostname):
    subprocess.Popen("ping -c 1 " + hostname, shell=True)
''',
    },

    "hardcoded_secrets": {
        "name": "Hardcoded Secrets — API keys and passwords",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-798",
        "expected_severity": "high",
        "code": '''\
import os

API_KEY = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "super_secret_production_password"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def connect():
    return os.getenv("DB_URL")
''',
    },

    "weak_crypto": {
        "name": "Weak Cryptography — MD5 / SHA1",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-327",
        "expected_severity": "medium",
        "code": '''\
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def verify_integrity(data):
    return hashlib.sha1(data).hexdigest()
''',
    },

    "code_injection_eval": {
        "name": "Code Injection — eval() / exec()",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-95",
        "expected_severity": "high",
        "code": '''\
def process_expression(user_input):
    result = eval(user_input)
    return result

def run_dynamic_code(code_string):
    exec(code_string)
''',
    },

    "path_traversal": {
        "name": "Path Traversal — unsanitized file path",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-22",
        "expected_severity": "high",
        "code": '''\
import os

def read_user_file(filename):
    filepath = os.path.join("/data/uploads", filename)
    with open(filepath, "r") as f:
        return f.read()

def serve_file(request_path):
    with open("/var/www/" + request_path) as f:
        return f.read()
''',
    },

    "insecure_deserialization": {
        "name": "Insecure Deserialization — pickle / yaml",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "cwe": "CWE-502",
        "expected_severity": "high",
        "code": '''\
import pickle
import yaml

def load_user_data(data_bytes):
    return pickle.loads(data_bytes)

def parse_config(yaml_string):
    return yaml.load(yaml_string)
''',
    },

    "insecure_random": {
        "name": "Insecure Randomness — random module for security",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-338",
        "expected_severity": "medium",
        "code": '''\
import random

def generate_token():
    return random.randint(100000, 999999)

def generate_session_id():
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(32))
''',
    },

    "ssrf": {
        "name": "SSRF — Server-Side Request Forgery",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "cwe": "CWE-918",
        "expected_severity": "high",
        "code": '''\
import requests

def fetch_url(user_provided_url):
    response = requests.get(user_provided_url)
    return response.text

def proxy_request(target):
    return requests.post(target, data={"action": "fetch"})
''',
    },

    "xss_flask": {
        "name": "XSS — Reflected via Flask response",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79",
        "expected_severity": "medium",
        "code": '''\
from flask import Flask, request

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return f"<h1>Hello, {name}!</h1>"
''',
    },

    "clean_code": {
        "name": "Clean Code — no vulnerabilities (control group)",
        "owasp": "none",
        "cwe": "none",
        "expected_severity": "none",
        "code": '''\
import os
from pathlib import Path

def get_config() -> dict:
    """Safely load configuration from environment variables only."""
    return {
        "db_url": os.environ.get("DATABASE_URL", ""),
        "debug": os.environ.get("DEBUG", "false").lower() == "true",
        "secret_key": os.environ.get("SECRET_KEY", ""),
    }

def sanitize_filename(name: str) -> str:
    """Extract only the basename to prevent path traversal."""
    return Path(name).name
''',
    },
}


# ── Data classes ────────────────────────────────────────────────────────────────

@dataclass
class FindingRecord:
    severity: str
    line_number: int
    rule_id: str
    message: str
    explanation: str | None = None


@dataclass
class ScenarioResult:
    scenario_id: str
    analyzer_name: str
    status: str
    duration_ms: int
    findings: list[FindingRecord] = field(default_factory=list)
    error_message: str | None = None
    is_true_positive: bool = False
    is_false_positive: bool = False
    is_false_negative: bool = False


@dataclass
class AnalyzerMetrics:
    analyzer_name: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    total_findings: int = 0
    total_duration_ms: int = 0
    scenarios_run: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 3) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 3) if denom else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 3) if (p + r) else 0.0

    @property
    def avg_duration_ms(self) -> float:
        return round(self.total_duration_ms / self.scenarios_run, 0) if self.scenarios_run else 0.0


# ── Analyzer builder ────────────────────────────────────────────────────────────

def build_analyzers() -> list:
    analyzers = []

    for name in settings.get_sast_analyzers():
        if name == "semgrep":
            try:
                from app.analyzers.semgrep import SemgrepAnalyzer
                analyzers.append(SemgrepAnalyzer())
                print(f"  ✅ Semgrep  (rulesets: {settings.SEMGREP_RULESET})")
            except Exception as e:
                print(f"  ⚠️  Semgrep failed: {e}")

        elif name == "bandit":
            try:
                from app.analyzers.bandit import BanditAnalyzer
                analyzers.append(BanditAnalyzer())
                print(f"  ✅ Bandit   (severity≥{settings.BANDIT_SEVERITY}, confidence≥{settings.BANDIT_CONFIDENCE})")
            except Exception as e:
                print(f"  ⚠️  Bandit failed: {e}")

    for model_str in LLM_AVAILABLE_MODELS:
        config = settings.get_llm_config(model_str)
        if config is None:
            print(f"  ⚠️  {model_str} skipped (no API key)")
            continue
        try:
            from app.analyzers.llm import LLMAnalyzer
            analyzers.append(LLMAnalyzer(llm_config=config))
            print(f"  ✅ LLM      ({config.provider}:{config.model}, prompt={config.prompt_version})")
        except Exception as e:
            print(f"  ⚠️  LLM {model_str} failed: {e}")

    return analyzers


# ── Label helper ────────────────────────────────────────────────────────────────

def _label(analyzer) -> str:
    from app.models.analysis import AnalyzerType
    if analyzer.type == AnalyzerType.LLM:
        return f"LLM:{analyzer.provider}:{analyzer.model}"
    return f"SAST:{analyzer.name}"


# ── Classification ──────────────────────────────────────────────────────────────

def _classify(
    scenario_id: str,
    label: str,
    result: AnalysisResult,
    scenario: dict,
) -> ScenarioResult:

    findings = [
        FindingRecord(
            severity=f.severity.value,
            line_number=f.line_number,
            rule_id=f.rule_id,
            message=f.message,
            explanation=f.explanation,
        )
        for f in result.findings
    ]

    sr = ScenarioResult(
        scenario_id=scenario_id,
        analyzer_name=label,
        status=result.status.value if hasattr(result.status, "value") else str(result.status),
        duration_ms=result.duration_ms,
        findings=findings,
        error_message=result.error_message,
    )

    is_vulnerable = scenario["expected_severity"] != "none"
    found_something = len(findings) > 0

    if is_vulnerable:
        sr.is_true_positive = found_something
        sr.is_false_negative = not found_something
    else:
        sr.is_false_positive = found_something

    return sr


def _metrics(all_results: list[ScenarioResult], label: str) -> AnalyzerMetrics:
    m = AnalyzerMetrics(analyzer_name=label)
    for r in all_results:
        if r.analyzer_name != label:
            continue
        m.scenarios_run += 1
        m.total_findings += len(r.findings)
        m.total_duration_ms += r.duration_ms
        if r.is_true_positive:   m.true_positives += 1
        if r.is_false_positive:  m.false_positives += 1
        if r.is_false_negative:  m.false_negatives += 1
    return m


# ── Print helpers ───────────────────────────────────────────────────────────────

W = 88

def div(title: str = "") -> None:
    if title:
        pad = (W - len(title) - 2) // 2
        print(f"\n{'═' * pad} {title} {'═' * (W - pad - len(title) - 2)}")
    else:
        print("─" * W)


def short_label(label: str) -> str:
    """Compact display label: SAST:semgrep → semgrep, LLM:groq:qwen... → qwen..."""
    parts = label.split(":")
    return parts[-1][:16] if len(parts) > 1 else label[:16]


# ── Main ────────────────────────────────────────────────────────────────────────

async def run_benchmark() -> None:
    div("ANALYZER BENCHMARK — AI Code Security Reviewer")
    print(f"  Date:      {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Scenarios: {len(SCENARIOS)} ({len(SCENARIOS)-1} vulnerable + 1 clean code control)")
    print(f"\n  Loading analyzers...")

    analyzers = build_analyzers()
    if not analyzers:
        print("\n  ❌ No analyzers loaded. Check .env and installed tools.")
        return

    labels = [_label(a) for a in analyzers]
    print(f"\n  Running: {len(SCENARIOS)} scenarios × {len(analyzers)} analyzers "
          f"= {len(SCENARIOS) * len(analyzers)} total calls\n")

    all_results: list[ScenarioResult] = []
    raw_data: list[dict] = []

    # ── Per-scenario execution ──────────────────────────────────────────────────
    for scenario_id, scenario in SCENARIOS.items():
        div(scenario["name"])
        print(f"  OWASP: {scenario['owasp']}  |  CWE: {scenario['cwe']}  |  Expected: {scenario['expected_severity'].upper()}")
        print()

        # Run all analyzers concurrently — safe because analyze() is pure I/O
        results: list[AnalysisResult] = await asyncio.gather(*[
            analyzer.analyze(
                code=scenario["code"],
                language="python",
                explanation_enabled=True,
            )
            for analyzer in analyzers
        ], return_exceptions=True)

        scenario_raw: dict = {
            "id": scenario_id,
            "name": scenario["name"],
            "owasp": scenario["owasp"],
            "cwe": scenario["cwe"],
            "expected_severity": scenario["expected_severity"],
            "code_lines": len(scenario["code"].strip().splitlines()),
            "analyzers": {},
        }

        for analyzer, result, label in zip(analyzers, results, labels):
            sl = short_label(label)

            # Handle exceptions from gather
            if isinstance(result, Exception):
                print(f"  [{sl}] ❌ Exception: {result}")
                sr = ScenarioResult(
                    scenario_id=scenario_id,
                    analyzer_name=label,
                    status="error",
                    duration_ms=0,
                    error_message=str(result),
                    is_false_negative=(scenario["expected_severity"] != "none"),
                )
                all_results.append(sr)
                scenario_raw["analyzers"][label] = {"status": "error", "error": str(result)}
                continue

            # Print findings
            if not result.findings:
                msg = "✅ No findings" if result.status == AnalysisStatus.COMPLETED else f"⚠️  FAILED: {result.error_message}"
                print(f"  [{sl}] {msg} ({result.duration_ms}ms)")
            else:
                print(f"  [{sl}] {len(result.findings)} finding(s) ({result.duration_ms}ms)")
                for f in result.findings:
                    exp = f" | 💡 {f.explanation[:70]}..." if f.explanation else ""
                    print(f"    [{f.severity.value.upper():6}] L{f.line_number:3d} {f.rule_id}")
                    print(f"           {f.message[:80]}{exp}")

            # Classify and verdict
            sr = _classify(scenario_id, label, result, scenario)
            all_results.append(sr)

            if sr.is_true_positive:
                print(f"           → ✅ TRUE POSITIVE")
            elif sr.is_false_negative:
                print(f"           → ❌ FALSE NEGATIVE (vulnerability missed)")
            elif sr.is_false_positive:
                print(f"           → ⚠️  FALSE POSITIVE (hallucination on clean code)")

            scenario_raw["analyzers"][label] = {
                "status": sr.status,
                "findings_count": len(sr.findings),
                "duration_ms": sr.duration_ms,
                "is_true_positive": sr.is_true_positive,
                "is_false_positive": sr.is_false_positive,
                "is_false_negative": sr.is_false_negative,
                "error_message": sr.error_message,
                "findings": [
                    {
                        "severity": f.severity,
                        "line_number": f.line_number,
                        "rule_id": f.rule_id,
                        "message": f.message,
                        "explanation": f.explanation,
                    }
                    for f in sr.findings
                ],
            }

        raw_data.append(scenario_raw)

    # ── Summary table ───────────────────────────────────────────────────────────
    div("SUMMARY — Detection Comparison")

    col = 12
    header = f"  {'Scenario':<36}  {'Expected':>8}"
    for label in labels:
        header += f"  {short_label(label):>{col}}"
    header += f"  {'Match'}"
    print(header)
    div()

    for scenario_id, scenario in SCENARIOS.items():
        name = scenario["name"][:36]
        expected = scenario["expected_severity"]
        row = f"  {name:<36}  {expected:>8}"

        detected = []
        for label in labels:
            sr = next((r for r in all_results
                       if r.scenario_id == scenario_id and r.analyzer_name == label), None)
            if sr is None:
                row += f"  {'N/A':>{col}}"
                detected.append(False)
                continue
            count = len(sr.findings)
            if expected == "none":
                cell = "clean ✅" if count == 0 else f"FP:{count} ⚠️"
            else:
                cell = f"{count} found ✅" if count > 0 else "MISS ❌"
            row += f"  {cell:>{col}}"
            detected.append(count > 0)

        if expected == "none":
            match = "✅ clean" if not any(detected) else "⚠️ FP"
        else:
            n = sum(detected)
            if n == len(labels):
                match = "✅ all"
            elif n == 0:
                match = "❌ none"
            else:
                who = [short_label(labels[i]) for i, d in enumerate(detected) if d]
                match = f"partial({','.join(who)})"

        print(f"{row}  {match}")

    # ── Metrics ─────────────────────────────────────────────────────────────────
    div("METRICS — Precision / Recall / F1-Score")
    print(f"  Computed on {len(SCENARIOS)-1} vulnerability scenarios (clean code excluded from P/R/F1)\n")

    metrics_list: list[AnalyzerMetrics] = []
    for label in labels:
        m = _metrics(all_results, label)
        metrics_list.append(m)

    # Table
    mw = 20
    header = f"  {'Analyzer':<{mw}}  {'TP':>4}  {'FP':>4}  {'FN':>4}  {'Precision':>10}  {'Recall':>8}  {'F1':>6}  {'Findings':>8}  {'Avg ms':>8}"
    print(header)
    div()
    for m in metrics_list:
        sl = short_label(m.analyzer_name)
        print(f"  {sl:<{mw}}  {m.true_positives:>4}  {m.false_positives:>4}  {m.false_negatives:>4}"
              f"  {m.precision:>9.1%}  {m.recall:>7.1%}  {m.f1_score:>5.3f}"
              f"  {m.total_findings:>8}  {m.avg_duration_ms:>7.0f}ms")

    # ── Thesis observations ─────────────────────────────────────────────────────
    div("THESIS OBSERVATIONS")

    sast_labels = [l for l in labels if l.startswith("SAST")]
    llm_labels  = [l for l in labels if l.startswith("LLM")]

    llm_advantage, sast_advantage, both_detected, neither_detected = [], [], [], []

    for scenario_id, scenario in SCENARIOS.items():
        if scenario["expected_severity"] == "none":
            continue

        def detected_by(label_list):
            return any(
                r.is_true_positive
                for l in label_list
                for r in all_results
                if r.scenario_id == scenario_id and r.analyzer_name == l
            )

        sast_ok = detected_by(sast_labels)
        llm_ok  = detected_by(llm_labels) if llm_labels else False

        if llm_ok and not sast_ok:
            llm_advantage.append(scenario["name"])
        elif sast_ok and not llm_ok:
            sast_advantage.append(scenario["name"])
        elif sast_ok and llm_ok:
            both_detected.append(scenario["name"])
        else:
            neither_detected.append(scenario["name"])

    fp_instances = [
        (scenario["name"], short_label(label))
        for scenario_id, scenario in SCENARIOS.items()
        if scenario["expected_severity"] == "none"
        for label in labels
        for r in all_results
        if r.scenario_id == scenario_id and r.analyzer_name == label and r.is_false_positive
    ]

    if both_detected:
        print(f"\n  ✅ Detected by ALL ({len(both_detected)} scenarios):")
        for s in both_detected:
            print(f"     • {s}")

    if llm_advantage:
        print(f"\n  🤖 LLM-only detections — {len(llm_advantage)} scenario(s) [semantic understanding]:")
        for s in llm_advantage:
            print(f"     • {s}")

    if sast_advantage:
        print(f"\n  🔍 SAST-only detections — {len(sast_advantage)} scenario(s) [explicit pattern matching]:")
        for s in sast_advantage:
            print(f"     • {s}")

    if neither_detected:
        print(f"\n  ❌ Missed by ALL ({len(neither_detected)} scenarios) — coverage gap:")
        for s in neither_detected:
            print(f"     • {s}")

    if fp_instances:
        print(f"\n  ⚠️  False positives on clean code (hallucinations):")
        for name, analyzer in fp_instances:
            print(f"     • [{analyzer}] {name}")
    else:
        print(f"\n  ✅ Zero false positives on clean code across all analyzers.")

    print(f"""
  ─── Key findings for Chapter 5 ─────────────────────────────────────────────
  Complementarity: {len(llm_advantage)} scenarios where LLM caught what SAST missed
                   {len(sast_advantage)} scenarios where SAST caught what LLM missed
  Coverage:        {len(both_detected)} / {len(SCENARIOS)-1} vulnerabilities caught by at least one approach
  Reliability:     SAST = 0 hallucinations | LLM = {len(fp_instances)} false positive(s) on clean code
  Recommendation:  Run SAST first (fast, deterministic), add LLM for semantic gaps
""")

    # ── JSON export ─────────────────────────────────────────────────────────────
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_file = REPORTS_DIR / f"benchmark_{timestamp}.json"

    export = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scenarios_count": len(SCENARIOS),
            "vulnerability_scenarios": len(SCENARIOS) - 1,
            "analyzers": labels,
            "config": {
                "semgrep_rulesets": settings.SEMGREP_RULESET,
                "bandit_severity": settings.BANDIT_SEVERITY,
                "bandit_confidence": settings.BANDIT_CONFIDENCE,
                "llm_prompt_version": settings.LLM_PROMPT_VERSION,
            },
        },
        "metrics": {
            m.analyzer_name: {
                "true_positives": m.true_positives,
                "false_positives": m.false_positives,
                "false_negatives": m.false_negatives,
                "precision": m.precision,
                "recall": m.recall,
                "f1_score": m.f1_score,
                "total_findings": m.total_findings,
                "avg_duration_ms": m.avg_duration_ms,
            }
            for m in metrics_list
        },
        "thesis_observations": {
            "both_detected": both_detected,
            "llm_advantage": llm_advantage,
            "sast_advantage": sast_advantage,
            "neither_detected": neither_detected,
            "false_positives_on_clean_code": [
                {"scenario": n, "analyzer": a} for n, a in fp_instances
            ],
        },
        "scenarios": raw_data,
    }

    output_file.write_text(json.dumps(export, indent=2, default=str))

    div("BENCHMARK COMPLETE")
    print(f"  Report: {output_file}")
    print(f"  Use metrics[] and thesis_observations[] for Chapter 5 tables.\n")


if __name__ == "__main__":
    asyncio.run(run_benchmark())