"""Assignment item 33: ask the AI five questions with known answers and compare.

Run:  python evaluate.py
Needs LLM_API_KEY in .env. Writes the results table into QUESTIONS.md (under "## Results").
The questions and expected answers mirror the table in QUESTIONS.md.
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path

from app import build_agent, build_capture_service
from netdash.agent import QuestionAgent
from netdash.config import load_settings
from netdash.core import Answer, LlmError

ROOT = Path(__file__).parent
CAPTURE = ROOT / "pcap-files" / "hasnafa (1).pcapng"
QUESTIONS_FILE = ROOT / "QUESTIONS.md"


@dataclass(frozen=True)
class Case:
    question: str
    facts: list[list[str]]  # each fact = alternative spellings; one must appear in the answer
    frames: set[int]        # frames the answer must cite


CASES = [
    Case("Which HTTP request was the slowest, and how long did it take?",
         [["forms/post"], ["157", "156.6", "156.5", "0.157"]], {2530, 2578}),
    Case("How many requests were sent to httpbin.org?", [["2", "two"]], {2530, 4788}),
    Case("Which status codes were returned?", [["200"]], {2578, 4900}),
    Case("What happened in the POST request?",
         [["post"], ["/post"], ["200"], ["152", "0.152"]], {4788, 4900}),
    Case("What are the Content-Type and Content-Length of the response to GET /forms/post?",
         [["text/html"], ["1397"]], {2578}),
]


def judge(case: Case, answer: Answer) -> list[str]:
    """Return the problems found (empty list = pass)."""
    text = answer.text.lower()
    problems = [f"missing {' / '.join(f)}" for f in case.facts if not any(a in text for a in f)]
    problems += [f"frame {f} not cited" for f in sorted(case.frames - set(answer.evidence_frames))]
    problems += [f"invented frame {f}" for f in answer.unverified_frames]
    return problems


def ask_with_retry(agent: QuestionAgent, question: str, report, tries: int = 4, wait: float = 20.0) -> Answer:
    """Ask once; on a quota error wait and retry (free tiers limit requests per minute)."""
    for attempt in range(1, tries + 1):
        try:
            return agent.ask(question, report)
        except LlmError as error:
            if "quota" not in str(error) or attempt == tries:
                raise
            print(f"  quota hit, waiting {wait:.0f}s (attempt {attempt}/{tries})")
            time.sleep(wait)


def write_results(rows: list[str], model: str) -> None:
    """Replace everything under '## Results' in QUESTIONS.md with the new table."""
    text = QUESTIONS_FILE.read_text(encoding="utf-8")
    head = text.split("## Results")[0]
    table = ["| # | AI answer | Cited frames | Result |", "|---|---|---|---|", *rows]
    stamp = time.strftime("%Y-%m-%d %H:%M")
    QUESTIONS_FILE.write_text(
        f"{head}## Results\n\nRun {stamp} with `{model}` on `{CAPTURE.name}` (`python evaluate.py`).\n\n"
        + "\n".join(table) + "\n", encoding="utf-8")


def main() -> int:
    agent = build_agent()
    if not isinstance(agent, QuestionAgent):
        print("AI is not available: set LLM_API_KEY in .env (see .env.example).")
        return 1
    report = build_capture_service().analyze(CAPTURE)
    rows, passed = [], 0
    for number, case in enumerate(CASES, 1):
        try:
            answer = ask_with_retry(agent, case.question, report)
        except LlmError as error:
            print(f"Q{number}: ERROR {error}")
            rows.append(f"| {number} | (error: {error}) | - | ERROR |")
            continue
        problems = judge(case, answer)
        passed += not problems
        verdict = "PASS" if not problems else "FAIL: " + "; ".join(problems)
        print(f"Q{number}: {verdict}\n  {answer.text}\n  frames {answer.evidence_frames}")
        shown = answer.text.replace("\n", " ").replace("|", "/")
        rows.append(f"| {number} | {shown} | {', '.join(map(str, answer.evidence_frames)) or '-'} | {verdict} |")
        time.sleep(1)  # stay well under the free-tier requests-per-minute limit
    write_results(rows, load_settings(ROOT / ".env").model)
    print(f"\n{passed}/{len(CASES)} passed. Results written to {QUESTIONS_FILE.name}")
    return 0 if passed == len(CASES) else 2


if __name__ == "__main__":
    sys.exit(main())
