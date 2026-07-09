import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Set

# Paste your SCENARIOS dictionary here
SCENARIOS = {
    "sql_injection_fstring": {
        "name": "SQL Injection (f-string)",
        "category": "injection",
        "expected_severity": "high",
        "code": """
import sqlite3

def get_user_profile(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM profiles WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
""",
    },
    "sql_injection_concatenation": {
        "name": "SQL Injection (string concat)",
        "category": "injection",
        "expected_severity": "high",
        "code": """
import sqlite3

def search_users(name):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchall()
""",
    },
    "command_injection": {
        "name": "Command Injection (shell=True)",
        "category": "injection",
        "expected_severity": "high",
        "code": """
import subprocess

def run_user_command(user_input):
    result = subprocess.call(user_input, shell=True)
    return result

def ping_host(hostname):
    subprocess.Popen("ping -c 1 " + hostname, shell=True)
""",
    },
    "hardcoded_secret": {
        "name": "Hardcoded Secrets",
        "category": "secrets",
        "expected_severity": "high",
        "code": """
import os

API_KEY = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "super_secret_production_password"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def connect():
    return os.getenv("DB_URL")
""",
    },
    "weak_crypto": {
        "name": "Weak Cryptography (MD5/SHA1)",
        "category": "crypto",
        "expected_severity": "medium",
        "code": """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def verify_integrity(data):
    return hashlib.sha1(data).hexdigest()
""",
    },
    "eval_usage": {
        "name": "Code Injection (eval/exec)",
        "category": "injection",
        "expected_severity": "high",
        "code": """
def process_expression(user_input):
    result = eval(user_input)
    return result

def run_dynamic_code(code_string):
    exec(code_string)
""",
    },
    "path_traversal": {
        "name": "Path Traversal",
        "category": "injection",
        "expected_severity": "high",
        "code": """
import os

def read_user_file(filename):
    filepath = os.path.join("/data/uploads", filename)
    with open(filepath, "r") as f:
        return f.read()

def serve_file(request_path):
    with open("/var/www/" + request_path) as f:
        return f.read()
""",
    },
    "insecure_deserialization": {
        "name": "Insecure Deserialization (pickle)",
        "category": "deserialization",
        "expected_severity": "high",
        "code": """
import pickle
import yaml

def load_user_data(data_bytes):
    return pickle.loads(data_bytes)

def parse_config(yaml_string):
    return yaml.load(yaml_string)
""",
    },
    "insecure_random": {
        "name": "Insecure Randomness",
        "category": "crypto",
        "expected_severity": "medium",
        "code": """
import random

def generate_token():
    return random.randint(100000, 999999)

def generate_session_id():
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(32))
""",
    },
    "ssrf_potential": {
        "name": "SSRF (Server-Side Request Forgery)",
        "category": "injection",
        "expected_severity": "high",
        "code": """
import requests

def fetch_url(user_provided_url):
    response = requests.get(user_provided_url)
    return response.text

def proxy_request(target):
    return requests.post(target, data={"action": "fetch"})
""",
    },
    "xss_template": {
        "name": "XSS via string formatting",
        "category": "injection",
        "expected_severity": "medium",
        "code": """
from flask import Flask, request

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return f"<h1>Hello, {name}!</h1>"
""",
    },
    "clean_code": {
        "name": "Clean Code (no vulnerabilities)",
        "category": "none",
        "expected_severity": "none",
        "code": """
import os
from pathlib import Path

def get_config():
    \"\"\"Safely load configuration from environment variables.\"\"\"
    return {
        "db_url": os.environ.get("DATABASE_URL", ""),
        "debug": os.environ.get("DEBUG", "false").lower() == "true",
    }

def sanitize_filename(name: str) -> str:
    \"\"\"Remove unsafe characters from a filename.\"\"\"
    return Path(name).name
""",
    },
}


SEMGREP_CONFIGS = [
    ("auto", "Semgrep auto"),
    ("p/python", "Semgrep p/python"),
    ("p/security-audit,p/sql-injection,p/python", "Semgrep security-audit+sql-injection+python"),
    ("semgrep-custom-rules.yml", "Semgrep custom rules"),
]


def run_bandit(file_path: str) -> dict:
    """Runs Bandit on a file or directory and returns parsed JSON output."""
    try:
        cmd = ["bandit", "-f", "json", "-q"]
        if os.path.isdir(file_path):
            cmd.extend(["-r", file_path])
        else:
            cmd.append(file_path)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ.copy(),
        )
        if result.stderr:
            print(f"Bandit stderr: {result.stderr.strip()}")
        return json.loads(result.stdout if result.stdout else "{}")
    except FileNotFoundError:
        print("Error running Bandit: bandit executable not found")
        return {}
    except subprocess.TimeoutExpired:
        print("Error running Bandit: command timed out (>30s)")
        return {}
    except Exception as e:
        print(f"Error running Bandit: {e}")
        return {}


# def run_opengrep(file_path: str) -> bool:
#     """Runs OpenGrep on a file using auto rules and returns True if vulnerabilities are found."""
#     try:
#         # Run opengrep scan directly; let OS search PATH
#         # opengrep scan outputs json format natively when requested
#         result = subprocess.run(
#             ["opengrep", "scan", "--config=p/python", "--json", file_path],
#             capture_output=True,
#             text=True,
#             timeout=60,
#             env=os.environ.copy(),
#         )
#         data = json.loads(result.stdout)
#         return len(data.get("results", [])) > 0
#     except FileNotFoundError:
#         print("Error running OpenGrep: opengrep executable not found")
#         return False
#     except subprocess.TimeoutExpired:
#         print("Error running OpenGrep: command timed out (>60s)")
#         return False
#     except Exception as e:
#         print(f"Error running OpenGrep: {e}")
#         return False

def run_semgrep(file_path: str, config: str) -> dict:
    """Runs Semgrep on a file or directory using the given config and returns the parsed JSON result."""
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", config, "--json", file_path],
            capture_output=True,
            text=True,
            timeout=60,
            env=os.environ.copy(),
        )
        if result.stderr:
            print(f"Semgrep stderr for config {config}: {result.stderr.strip()}")
        return json.loads(result.stdout if result.stdout else "{}")
    except FileNotFoundError:
        print("Error running Semgrep: semgrep executable not found")
        return {}
    except subprocess.TimeoutExpired:
        print(f"Error running Semgrep: command timed out (>60s) for config {config}")
        return {}
    except Exception as e:
        print(f"Error running Semgrep: {e}")
        return {}


def evaluate_scanners():
    results = {
        "Bandit": {"detected": [], "missed": [], "false_positives": 0},
        **{
            label: {"detected": [], "missed": [], "false_positives": 0}
            for _, label in SEMGREP_CONFIGS
        },
    }

    print("=== Starting Vulnerability Discovery Benchmark ===\n")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        for key, scenario in SCENARIOS.items():
            file_path = tmp_path / f"{key}.py"
            file_path.write_text(scenario["code"].strip(), encoding="utf-8")

        bandit_result = run_bandit(str(tmp_path))
        bandit_detected = {
            Path(issue.get("filename", "")).stem
            for issue in bandit_result.get("results", [])
            if issue.get("filename")
        }

        for key, scenario in SCENARIOS.items():
            is_clean = scenario["category"] == "none"
            if key in bandit_detected:
                if is_clean:
                    results["Bandit"]["false_positives"] += 1
                else:
                    results["Bandit"]["detected"].append(scenario["name"])
            else:
                if not is_clean:
                    results["Bandit"]["missed"].append(scenario["name"])

        for config, label in SEMGREP_CONFIGS:
            semgrep_result = run_semgrep(str(tmp_path), config)
            semgrep_detected = {
                Path(item.get("path", "")).stem
                for item in semgrep_result.get("results", [])
                if item.get("path")
            }
            print(f"[{label}] found {len(semgrep_detected)} scenario files")

            for key, scenario in SCENARIOS.items():
                is_clean = scenario["category"] == "none"
                if key in semgrep_detected:
                    if is_clean:
                        results[label]["false_positives"] += 1
                    else:
                        results[label]["detected"].append(scenario["name"])
                else:
                    if not is_clean:
                        results[label]["missed"].append(scenario["name"])

    total_vulns = len([s for s in SCENARIOS.values() if s["category"] != "none"])

    for tool in ["Bandit"] + [label for _, label in SEMGREP_CONFIGS]:
        detected_count = len(results[tool]["detected"])
        missed_count = len(results[tool]["missed"])
        fp_count = results[tool]["false_positives"]
        detection_rate = (
            (detected_count / total_vulns) * 100 if total_vulns > 0 else 0
        )

        print(f"📊 Results for {tool}:")
        print(f"  - Detection Rate: {detection_rate:.1f}%")
        print(f"  - Vulnerabilities Found ({detected_count}/{total_vulns})")
        for item in results[tool]["detected"]:
            print(f"    ✅ {item}")

        if missed_count > 0:
            print(f"  - Vulnerabilities Missed ({missed_count}/{total_vulns})")
            for item in results[tool]["missed"]:
                print(f"    ❌ {item}")

        print(f"  - False Positives (Flagging clean code): {fp_count}")
        print("-" * 50)


if __name__ == "__main__":
    evaluate_scanners()
