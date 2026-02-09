import argparse
import json
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

import requests

from config import DEFAULT_OUTPUT_DIR, DEFAULT_TIMEOUT_SECONDS, DEFAULT_USER_AGENT
from core.analyzer import AnalysisResult, analyze_cookies
from core.cookie_utils import extract_cookies


def normalize_targets(raw_targets: List[str]) -> List[str]:
    targets = []
    for target in raw_targets:
        clean = target.strip()
        if not clean:
            continue
        if not urlparse(clean).scheme:
            clean = f"https://{clean}"
        targets.append(clean)
    return targets


def load_targets_from_file(file_path: str) -> List[str]:
    content = Path(file_path).read_text(encoding="utf-8")
    return normalize_targets(content.splitlines())


def fetch_cookies(target: str) -> List:
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    session.get(target, timeout=DEFAULT_TIMEOUT_SECONDS, allow_redirects=True)
    return list(session.cookies)


def ai_interpretation(result: AnalysisResult) -> Dict[str, str]:
    if not result.findings:
        return {
            "executive_summary": "No authentication cookie weaknesses were detected in the sampled response.",
            "recommendations": "Continue to enforce secure cookie attributes and rotate session tokens regularly.",
            "business_risk": "Low",
        }
    issues = {finding.issue for finding in result.findings}
    recommendations = []
    if "Missing Secure flag" in issues:
        recommendations.append("Enforce Secure on all authentication cookies to prevent downgrade risks.")
    if "Missing HttpOnly flag" in issues:
        recommendations.append("Set HttpOnly to reduce exposure to XSS.")
    if "Missing SameSite attribute" in issues:
        recommendations.append("Apply SameSite=Lax or Strict to mitigate CSRF.")
    if "Short session token" in issues or "Low session token entropy" in issues:
        recommendations.append("Increase session token length and randomness using a cryptographically secure RNG.")
    risk = "High" if any(f.severity in {"High", "Critical"} for f in result.findings) else "Medium"
    return {
        "executive_summary": (
            "Authentication cookie weaknesses were detected. The findings indicate potential session "
            "hijacking risks if attackers can capture or predict tokens."
        ),
        "recommendations": " ".join(recommendations),
        "business_risk": risk,
    }


def format_text_report(result: AnalysisResult, ai_summary: Dict[str, str]) -> str:
    lines = [f"Target: {result.target}", f"Total findings: {result.summary['total_findings']}"]
    for finding in result.findings:
        lines.append(f"- [{finding.severity}] {finding.cookie_name}: {finding.issue}")
        lines.append(f"  Details: {finding.details}")
    lines.append("")
    lines.append("Executive Summary")
    lines.append(ai_summary["executive_summary"])
    lines.append("")
    lines.append("Business Risk")
    lines.append(ai_summary["business_risk"])
    lines.append("")
    lines.append("Recommendations")
    lines.append(ai_summary["recommendations"])
    return "\n".join(lines)


def write_reports(output_dir: Path, result: AnalysisResult, ai_summary: Dict[str, str]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_target = result.target.replace("://", "_").replace("/", "_")
    json_path = output_dir / f"{safe_target}.json"
    text_path = output_dir / f"{safe_target}.txt"
    json_path.write_text(
        json.dumps(
            {
                "target": result.target,
                "summary": result.summary,
                "findings": [finding.__dict__ for finding in result.findings],
                "ai_summary": ai_summary,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    text_path.write_text(format_text_report(result, ai_summary), encoding="utf-8")


def run_scan(targets: List[str], output_dir: str) -> List[AnalysisResult]:
    results = []
    for target in targets:
        cookies = fetch_cookies(target)
        observations = extract_cookies(cookies)
        analysis = analyze_cookies(target, observations)
        ai_summary = ai_interpretation(analysis)
        write_reports(Path(output_dir), analysis, ai_summary)
        results.append(analysis)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="AI-assisted broken authentication cookie scanner.")
    parser.add_argument("--target", action="append", help="Target URL (can be used multiple times).")
    parser.add_argument("--target-file", help="Path to a text file containing target URLs.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for reports.")
    args = parser.parse_args()

    targets: List[str] = []
    if args.target:
        targets.extend(normalize_targets(args.target))
    if args.target_file:
        targets.extend(load_targets_from_file(args.target_file))
    if not targets:
        parser.error("Provide at least one --target or --target-file.")

    run_scan(targets, args.output_dir)


if __name__ == "__main__":
    main()
