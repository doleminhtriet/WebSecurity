#!/usr/bin/env python3
# scripts/eml_to_csv.py
#
# Convert .eml files to CSV with columns: subject, body, label.
# Supports three ways to set labels:
#   1) --labels-csv labels.csv (columns: filename,label)
#   2) --default-label 0|1     (same label for all files)
#   3) --infer-from-name       (filename contains 'phish' -> 1, 'ham'/'legit' -> 0)
#
# Usage examples:
#   python scripts/eml_to_csv.py samples/ out.csv --labels-csv labels.csv
#   python scripts/eml_to_csv.py samples/ out.csv --default-label 1
#   python scripts/eml_to_csv.py samples/ out.csv --infer-from-name --recursive
#
from __future__ import annotations
import argparse
import csv
import html as htmlmod
import re
from pathlib import Path
from typing import Dict, Optional, Tuple
from email import policy
from email.parser import BytesParser

TAG_RE = re.compile(r"<[^>]+>")  # simple HTML tag stripper


def strip_html(s: str) -> str:
    s = htmlmod.unescape(s or "")
    s = TAG_RE.sub(" ", s)
    s = re.sub(r"[ \t]+", " ", s)
    return s.strip()


def extract_subject_body(eml_path: Path) -> Tuple[str, str]:
    """Parse an .eml and return (subject, body). Prefer text/plain; fallback text/html (stripped)."""
    with eml_path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = (msg.get("subject") or "").strip()

    def is_attachment(part) -> bool:
        disp = (part.get("Content-Disposition") or "").lower()
        return "attachment" in disp

    # Prefer text/plain
    body_text: Optional[str] = None
    if msg.is_multipart():
        # first try text/plain parts
        for part in msg.walk():
            if part.get_content_maintype() == "text" and part.get_content_subtype() == "plain" and not is_attachment(part):
                try:
                    body_text = part.get_content()
                    if body_text:
                        break
                except Exception:
                    pass
        # fallback to text/html
        if not body_text:
            for part in msg.walk():
                if part.get_content_maintype() == "text" and part.get_content_subtype() == "html" and not is_attachment(part):
                    try:
                        body_text = strip_html(part.get_content())
                        if body_text:
                            break
                    except Exception:
                        pass
    else:
        # singlepart message
        try:
            if msg.get_content_subtype() == "html":
                body_text = strip_html(msg.get_content())
            else:
                body_text = msg.get_content()
        except Exception:
            body_text = ""

    # Normalize newlines and whitespace
    body = (body_text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    return subject, body


def load_label_mapping(labels_csv: Path) -> Dict[str, int]:
    mapping: Dict[str, int] = {}
    with labels_csv.open(newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        if "filename" not in r.fieldnames or "label" not in r.fieldnames:
            raise ValueError("labels.csv must have columns: filename,label")
        for row in r:
            fname = (row["filename"] or "").strip()
            lab = int(row["label"])
            if lab not in (0, 1):
                raise ValueError(f"Invalid label for {fname}: {lab} (must be 0 or 1)")
            mapping[fname] = lab
    return mapping


def infer_label_from_name(name: str) -> Optional[int]:
    n = name.lower()
    if "phish" in n or "scam" in n or "mal" in n:
        return 1
    if "ham" in n or "legit" in n or "normal" in n:
        return 0
    return None


def main():
    ap = argparse.ArgumentParser(description="Convert .eml files to CSV (subject,body,label).")
    ap.add_argument("eml_dir", type=str, help="Directory containing .eml files")
    ap.add_argument("out_csv", type=str, help="Output CSV path")
    ap.add_argument("--labels-csv", type=str, help="CSV with columns: filename,label")
    ap.add_argument("--default-label", type=int, choices=[0, 1], help="Use this label for all files (if no labels-csv)")
    ap.add_argument("--infer-from-name", action="store_true", help="Infer label from filename keywords (phish/ham/legit)")
    ap.add_argument("--recursive", action="store_true", help="Recurse into subdirectories")
    args = ap.parse_args()

    eml_dir = Path(args.eml_dir)
    if not eml_dir.exists() or not eml_dir.is_dir():
        raise SystemExit(f"Not a directory: {eml_dir}")

    if not any([args.labels_csv, args.default_label is not None, args.infer_from_name]):
        raise SystemExit("You must specify one of: --labels-csv, --default-label, or --infer-from-name")

    label_map: Dict[str, int] = {}
    if args.labels_csv:
        label_map = load_label_mapping(Path(args.labels_csv))

    # Collect .eml files
    pattern = "**/*.eml" if args.recursive else "*.eml"
    files = sorted(eml_dir.glob(pattern))
    if not files:
        raise SystemExit(f"No .eml files found in {eml_dir} (recursive={args.recursive})")

    out_path = Path(args.out_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows_written = 0
    skipped = 0

    with out_path.open("w", newline="", encoding="utf-8") as g:
        w = csv.DictWriter(g, fieldnames=["subject", "body", "label"])
        w.writeheader()

        for p in files:
            try:
                subject, body = extract_subject_body(p)
            except Exception as e:
                print(f"[WARN] Failed to parse {p.name}: {e}")
                skipped += 1
                continue

            # Determine label
            label: Optional[int] = None
            if args.labels_csv:
                # use mapping by basename
                label = label_map.get(p.name)
            if label is None and args.infer_from_name:
                label = infer_label_from_name(p.name)
            if label is None and args.default_label is not None:
                label = args.default_label

            if label not in (0, 1):
                print(f"[WARN] No label for {p.name}; skipping (provide --labels-csv or --default-label or --infer-from-name)")
                skipped += 1
                continue

            # Write row
            w.writerow({
                "subject": subject,
                "body": body,
                "label": int(label),
            })
            rows_written += 1

    print(f"Done. Wrote {rows_written} rows to {out_path} (skipped {skipped}).")


if __name__ == "__main__":
    main()
