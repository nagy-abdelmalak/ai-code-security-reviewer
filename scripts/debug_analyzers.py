"""Quick debug to see raw analyzer output."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings
from app.core.sandbox import create_temp_file, delete_temp_file

TEST_CODE = '''
import subprocess
import sqlite3

DB_PASSWORD = "super_secret_123"

def run(user_input):
    subprocess.call(user_input, shell=True)

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM profiles WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
'''


async def debug_semgrep():
    print("=" * 60)
    print("SEMGREP RAW OUTPUT")
    print("=" * 60)

    filepath = create_temp_file(TEST_CODE)
    try:
        args = ["semgrep", "scan", "--no-git-ignore"]
        for ruleset in settings.SEMGREP_RULESET.split(","):
            args.extend(["--config", ruleset.strip()])
        args.extend(["--json", "--quiet", str(filepath)])

        print(f"Command: {' '.join(args)}\n")

        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        print(f"Exit code: {process.returncode}")
        print(f"Stderr: {stderr.decode()[:500]}")
        print(f"\nStdout (raw JSON):")

        raw = stdout.decode()
        print(raw[:2000])

        # Try to parse
        try:
            data = json.loads(raw)
            results = data.get("results", [])
            print(f"\nParsed 'results' key: {len(results)} items")
            if results:
                print(f"First result keys: {list(results[0].keys())}")
                print(f"First result: {json.dumps(results[0], indent=2)[:500]}")
            else:
                print(f"Available top-level keys: {list(data.keys())}")
                # Show what IS in the output
                for key in data:
                    val = data[key]
                    if isinstance(val, list):
                        print(f"  {key}: list with {len(val)} items")
                    elif isinstance(val, dict):
                        print(f"  {key}: dict with keys {list(val.keys())[:5]}")
                    else:
                        print(f"  {key}: {str(val)[:100]}")
        except json.JSONDecodeError as e:
            print(f"\nJSON parse error: {e}")
    finally:
        delete_temp_file(filepath)


async def debug_llm():
    print("\n" + "=" * 60)
    print("LLM RAW OUTPUT")
    print("=" * 60)

    if not settings.GROQ_API_KEY:
        print("Skipped — no LLM_API_KEY")
        return

    from app.analyzers.llm import LLMAnalyzer

    analyzer = LLMAnalyzer()

    # Monkey-patch to see raw response
    original_parse = analyzer._parse_response

    def debug_parse(raw_text, explanation_enabled):
        print(f"\nRaw LLM response ({len(raw_text)} chars):")
        print(raw_text[:2000])
        print("\n--- Attempting parse ---")
        result = original_parse(raw_text, explanation_enabled)
        print(f"Parsed {len(result)} findings")
        return result

    analyzer._parse_response = debug_parse

    result = await analyzer.analyze(
        code=TEST_CODE,
        language="python",
        explanation_enabled=True,
    )

    print(f"\nFinal result: status={result.status}, findings={len(result.findings)}")


async def main():
    await debug_semgrep()
    await debug_llm()


if __name__ == "__main__":
    asyncio.run(main())