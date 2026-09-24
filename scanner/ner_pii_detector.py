#!/usr/bin/env python3
"""
scanner/ner_pii_detector.py

Machine-learning-based PII detector, complementing the regex/checksum rules
in privacy_scanner.py. This module exists because of a specific, documented
limitation in the literature (Mishra, Pagare & Sharma, 2025 — see
docs/VERIFICATION_LOG.md / literature review): regex-only PII detection
fails on *unstructured* identifiers — names, addresses — that have no fixed
format or checksum to validate against. A person's name is valid PII no
matter what string it is; there is no regex for "a name."

This uses spaCy's pretrained statistical NER model (a genuine trained
neural network — a transition-based dependency-parsing architecture with
a CNN/tok2vec token-embedding layer, not a hand-written rule) to detect
PERSON and GPE/LOC (geopolitical/location) entities in source code, config
files, comments, and log statements, where such entities are a strong
indicator of hardcoded personal data (e.g., a test fixture with a real
employee's name, or a log statement interpolating a customer's address).

This is a *separate, distinct* ML technique from the Gradient Boosting risk
model in ml/risk_predictor/: that model does tabular regression over
structural features; this one does sequence labeling over natural-language
and code text. Using both is intentional — they solve different problems
and neither substitutes for the other.

Usage:
    python scanner/ner_pii_detector.py --path .
    python scanner/ner_pii_detector.py --demo
"""
import argparse
import fnmatch
import json
import os
import sys
from dataclasses import dataclass, asdict

DEFAULT_IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache"}
DEFAULT_IGNORE_GLOBS = ["*.lock", "*.min.js", "*package-lock.json*", "*.png", "*.jpg", "*.pdf", "*.joblib"]
TEXT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".yaml", ".yml", ".json", ".md", ".txt", ".rego", ".toml", ".cfg", ".ini", ".log"}

# Confidence-relevant entity labels: PERSON (names) and GPE/LOC (addresses,
# cities, countries) are the two spaCy categories that correspond to
# unstructured PII a regex cannot express.
PII_ENTITY_LABELS = {"PERSON", "GPE", "LOC"}

SEVERITY_BY_LABEL = {
    "PERSON": "HIGH",
    "GPE": "MEDIUM",
    "LOC": "MEDIUM",
}


@dataclass
class NERFinding:
    entity_type: str
    file: str
    line: int
    redacted_text: str
    confidence_note: str


def redact(value: str) -> str:
    if len(value) <= 4:
        return value[0] + "*" * (len(value) - 1)
    return value[:2] + "*" * (len(value) - 3) + value[-1]


_nlp = None


def get_model():
    """Lazy-load the spaCy model once per process; loading is the expensive
    part (~30-60ms), inference on already-loaded model is fast per line."""
    global _nlp
    if _nlp is None:
        import spacy
        try:
            _nlp = spacy.load("en_core_web_sm", disable=["lemmatizer", "attribute_ruler"])
        except OSError as e:
            raise RuntimeError(
                "spaCy model 'en_core_web_sm' not installed. Run:\n"
                "  pip install spacy\n"
                "  pip install https://github.com/explosion/spacy-models/releases/download/"
                "en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"
            ) from e
    return _nlp


def iter_files(root: str, ignore_dirs: set, ignore_globs: list):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for fn in filenames:
            _, ext = os.path.splitext(fn)
            if ext not in TEXT_EXTENSIONS:
                continue
            full = os.path.join(dirpath, fn)
            if any(fnmatch.fnmatch(full, pat) for pat in ignore_globs):
                continue
            yield full


def scan_file(path: str, nlp) -> list[NERFinding]:
    findings = []
    try:
        if os.path.getsize(path) > 500_000:  # NER is expensive; cap file size
            return findings
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Skip lines unlikely to contain natural-language PII: pure code
        # syntax, import statements, and very short lines waste inference
        # time and produce noise (e.g., spaCy tagging a variable name as
        # a PERSON entity in isolation).
        if not stripped or len(stripped) < 8:
            continue
        if stripped.startswith(("import ", "from ", "#!/", "//", "/*")):
            continue

        doc = nlp(stripped)
        for ent in doc.ents:
            if ent.label_ in PII_ENTITY_LABELS and len(ent.text.strip()) >= 3:
                findings.append(NERFinding(
                    entity_type=ent.label_,
                    file=path,
                    line=lineno,
                    redacted_text=redact(ent.text.strip()),
                    confidence_note=f"spaCy NER ({ent.label_}); verify manually, statistical model may false-positive on identifiers/class names",
                ))
    return findings


def scan_path(root: str, ignore_dirs=None, ignore_globs=None) -> list[NERFinding]:
    ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
    ignore_globs = ignore_globs or DEFAULT_IGNORE_GLOBS
    nlp = get_model()
    all_findings = []
    for f in iter_files(root, ignore_dirs, ignore_globs):
        all_findings.extend(scan_file(f, nlp))
    return all_findings


def summarize(findings: list[NERFinding]) -> dict:
    by_label = {}
    for f in findings:
        by_label[f.entity_type] = by_label.get(f.entity_type, 0) + 1
    return {"total": len(findings), "by_entity_type": by_label}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--path", default=".")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--out", default=None)
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    if args.demo:
        os.makedirs("/tmp/ner_pii_demo", exist_ok=True)
        with open("/tmp/ner_pii_demo/sample_config.py", "w") as f:
            f.write(
                "# Test fixture — DO NOT use real customer data here\n"
                "test_customer_name = 'Rohan Malhotra'\n"
                "shipping_address = 'Flat 402, MG Road, Bangalore, Karnataka'\n"
                "# ticket assigned to Priya Sharma for review\n"
                "MAX_RETRIES = 3\n"
                "def calculate_total(items): return sum(i.price for i in items)\n"
            )
        findings = scan_path("/tmp/ner_pii_demo")
    else:
        findings = scan_path(args.path)

    summary = summarize(findings)

    if args.format == "json":
        report = {"summary": summary, "findings": [asdict(f) for f in findings]}
        output = json.dumps(report, indent=2)
    else:
        lines = [f"NER-based PII scan: {summary['total']} unstructured-PII candidate(s) found"]
        for f in findings:
            lines.append(f"  [{f.entity_type:8s}] {f.file}:{f.line}  {f.redacted_text}  ({f.confidence_note})")
        lines.append("")
        lines.append(f"By entity type: {summary['by_entity_type']}")
        lines.append("")
        lines.append("NOTE: unlike the checksum-validated scanner (privacy_scanner.py), NER")
        lines.append("output is probabilistic and intended for human triage, not hard CI blocking —")
        lines.append("see docs/ARCHITECTURE.md for why this stage does not fail the build by default.")
        output = "\n".join(lines)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
    print(output)


if __name__ == "__main__":
    main()
