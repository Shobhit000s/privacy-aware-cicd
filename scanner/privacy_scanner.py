#!/usr/bin/env python3
"""
scanner/privacy_scanner.py

A custom, dependency-free privacy/PII scanner that complements Gitleaks.
Gitleaks is tuned for credential-shaped secrets (API keys, tokens, private
keys). This scanner is tuned for personal-data-shaped content that a
credential scanner typically won't flag: government IDs, phone numbers,
certificates, and structured identifiers relevant to Indian data-privacy
compliance (Aadhaar, PAN) as well as generic PII.

Design notes:
- Every rule includes a checksum/format validator where one exists (Aadhaar
  Verhoeff checksum, PAN structural format) to cut false positives — a scanner
  that just regex-matches "12 digits" is useless in a codebase full of IDs,
  timestamps, and phone-adjacent numbers.
- Findings are redacted in output (only first/last few chars shown) so the
  scan report itself doesn't become a new leak.
- Exit code 1 if any HIGH/CRITICAL severity finding exists, for CI gating.

Usage:
    python scanner/privacy_scanner.py --path .
    python scanner/privacy_scanner.py --path . --format json --out report.json
    python scanner/privacy_scanner.py --demo
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, asdict


# --------------------------------------------------------------------------
# Rule definitions
# --------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
PHONE_IN_RE = re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)")
PHONE_INTL_RE = re.compile(
    r"(?<!\d)\+\d{1,3}[-\s]?\(?\d{2,4}\)?[-\s]?\d{3,4}[-\s]?\d{3,4}(?!\d)"
)
AADHAAR_RE = re.compile(r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)
CERT_RE = re.compile(
    r"-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|PUBLIC KEY)-----"
)
PASSWORD_ASSIGN_RE = re.compile(
    r"""(?i)\b(password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{4,}['"]"""
)
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
IP_ADDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


SEVERITY = {
    "aadhaar": "CRITICAL",
    "pan": "CRITICAL",
    "credit_card": "CRITICAL",
    "certificate_or_key": "CRITICAL",
    "password_assignment": "HIGH",
    "jwt": "HIGH",
    "phone_number": "MEDIUM",
    "email": "LOW",
    "ip_address": "LOW",
}


DEFAULT_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".pytest_cache",
}

DEFAULT_IGNORE_GLOBS = [
    "*.lock",
    "*.min.js",
    "*package-lock.json*",
    "*synthetic_*.csv",
    "*privacy_scanner.py",
    "*.joblib",
]


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    redacted_match: str


def verhoeff_checksum_valid(number: str) -> bool:
    """Validate an Aadhaar-like 12-digit number using the Verhoeff algorithm,
    which real Aadhaar numbers satisfy. Cuts false positives from arbitrary
    12-digit strings (order IDs, timestamps, etc.).
    """

    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]

    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]

    digits = [int(c) for c in number][::-1]
    c = 0

    for i, digit in enumerate(digits):
        c = d[c][p[i % 8][digit]]

    return c == 0


def pan_format_valid(value: str) -> bool:
    # PAN structure: 5 letters, 4 digits, 1 letter;
    # 4th letter encodes holder type.
    return bool(
        re.fullmatch(
            r"[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]",
            value,
        )
    )


def redact(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)

    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def iter_files(root: str, ignore_dirs: set, ignore_globs: list):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in ignore_dirs
        ]

        for fn in filenames:
            full = os.path.join(dirpath, fn)

            if any(
                fnmatch.fnmatch(full, pat)
                for pat in ignore_globs
            ):
                continue

            yield full


def scan_file(path: str) -> list[Finding]:
    findings = []

    try:
        if os.path.getsize(path) > 3_000_000:
            return findings

        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()

    except OSError:
        return findings

    for lineno, line in enumerate(lines, start=1):

        # Email
        for m in EMAIL_RE.finditer(line):
            findings.append(
                Finding(
                    "email",
                    SEVERITY["email"],
                    path,
                    lineno,
                    redact(m.group()),
                )
            )

        # Indian phone number
        for m in PHONE_IN_RE.finditer(line):
            findings.append(
                Finding(
                    "phone_number",
                    SEVERITY["phone_number"],
                    path,
                    lineno,
                    redact(m.group()),
                )
            )

        # Aadhaar
        for m in AADHAAR_RE.finditer(line):
            digits = re.sub(r"\s", "", m.group())

            if len(digits) == 12 and verhoeff_checksum_valid(digits):
                findings.append(
                    Finding(
                        "aadhaar",
                        SEVERITY["aadhaar"],
                        path,
                        lineno,
                        redact(digits),
                    )
                )

        # PAN
        for m in PAN_RE.finditer(line):
            if pan_format_valid(m.group()):
                findings.append(
                    Finding(
                        "pan",
                        SEVERITY["pan"],
                        path,
                        lineno,
                        redact(m.group()),
                    )
                )

        # JWT
        for m in JWT_RE.finditer(line):
            findings.append(
                Finding(
                    "jwt",
                    SEVERITY["jwt"],
                    path,
                    lineno,
                    redact(m.group()),
                )
            )

        # Certificates / private keys
        for m in CERT_RE.finditer(line):
            findings.append(
                Finding(
                    "certificate_or_key",
                    SEVERITY["certificate_or_key"],
                    path,
                    lineno,
                    m.group(),
                )
            )

        # Password assignment
        for m in PASSWORD_ASSIGN_RE.finditer(line):
            findings.append(
                Finding(
                    "password_assignment",
                    SEVERITY["password_assignment"],
                    path,
                    lineno,
                    redact(m.group()),
                )
            )

        # Credit card
        for m in CREDIT_CARD_RE.finditer(line):
            digits = re.sub(r"[ -]", "", m.group())

            if luhn_valid(digits):
                findings.append(
                    Finding(
                        "credit_card",
                        SEVERITY["credit_card"],
                        path,
                        lineno,
                        redact(digits),
                    )
                )

    return findings


def luhn_valid(number: str) -> bool:
    if not number.isdigit() or not (13 <= len(number) <= 19):
        return False

    total = 0
    alt = False

    for ch in reversed(number):
        d = int(ch)

        if alt:
            d *= 2

            if d > 9:
                d -= 9

        total += d
        alt = not alt

    return total % 10 == 0


def scan_path(
    root: str,
    ignore_dirs=None,
    ignore_globs=None,
) -> list[Finding]:

    ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
    ignore_globs = ignore_globs or DEFAULT_IGNORE_GLOBS

    all_findings = []

    for f in iter_files(
        root,
        ignore_dirs,
        ignore_globs,
    ):
        all_findings.extend(
            scan_file(f)
        )

    return all_findings


def summarize(findings: list[Finding]) -> dict:
    by_severity = {}
    by_rule = {}

    for f in findings:
        by_severity[f.severity] = (
            by_severity.get(f.severity, 0) + 1
        )

        by_rule[f.rule] = (
            by_rule.get(f.rule, 0) + 1
        )

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_rule": by_rule,
    }


def main():

    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--path",
        default=".",
    )

    ap.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
    )

    ap.add_argument(
        "--out",
        default=None,
    )

    ap.add_argument(
        "--demo",
        action="store_true",
    )

    ap.add_argument(
        "--fail-on",
        choices=[
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            "none",
        ],
        default="HIGH",
    )

    args = ap.parse_args()

    if args.demo:

        os.makedirs(
            "/tmp/privacy_scan_demo",
            exist_ok=True,
        )

        demo_file = "/tmp/privacy_scan_demo/sample.py"

        with open(
            demo_file,
            "w",
            encoding="utf-8",
        ) as f:

            f.write(
                "user_email = 'jane.doe@example.com'\n"
                "aadhaar = '234123412346'\n"
                "pan_number = 'ABCPD1234E'\n"
                "password = 'Sup3r' + 'Secret!'\n"
                "token = 'demo-header' + '.' + 'demo-payload' + '.' + 'demo-signature'\n"
            )

        findings = scan_path(
            "/tmp/privacy_scan_demo"
        )

    else:
        findings = scan_path(
            args.path
        )

    summary = summarize(findings)

    severity_order = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    if args.format == "json":

        report = {
            "summary": summary,
            "findings": [
                asdict(f)
                for f in findings
            ],
        }

        output = json.dumps(
            report,
            indent=2,
        )

    else:

        lines = [
            f"Privacy scan: {summary['total']} finding(s) "
            f"across "
            f"{len(set(f.file for f in findings))} file(s)"
        ]

        for f in findings:

            lines.append(
                f"  [{f.severity:8s}] "
                f"{f.rule:20s} "
                f"{f.file}:{f.line}  "
                f"{f.redacted_match}"
            )

        lines.append("")

        lines.append(
            f"By severity: "
            f"{summary['by_severity']}"
        )

        output = "\n".join(lines)

    if args.out:

        with open(
            args.out,
            "w",
            encoding="utf-8",
        ) as f:
            f.write(output)

    print(output)

    if args.fail_on != "none":

        threshold_idx = severity_order.index(
            args.fail_on
        )

        blocking = [
            f
            for f in findings
            if severity_order.index(f.severity)
            >= threshold_idx
        ]

        if blocking:

            print(
                f"\n❌ {len(blocking)} finding(s) "
                f"at or above {args.fail_on} severity. "
                f"Failing.",
                file=sys.stderr,
            )

            sys.exit(1)


if __name__ == "__main__":
    main()