"""RAGSHIELD detection engine - standard library only.

A corpus is a list of document dicts. The canonical on-disk form is JSONL
where each line is an object with at least:
    {"id": "...", "text": "..."}
and optionally:
    {"embedding": [float, ...]}

All detectors return a list of Finding objects. scan_corpus aggregates them
into a ScanResult with a severity-weighted risk score.
"""
from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --- severity ranking -------------------------------------------------------
_SEVERITY_WEIGHT = {"info": 1, "low": 2, "medium": 5, "high": 9, "critical": 15}


@dataclass
class Finding:
    detector: str
    severity: str  # info|low|medium|high|critical
    doc_id: str
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    doc_count: int = 0
    risk_score: float = 0.0

    @property
    def poisoned(self) -> bool:
        """True if any finding is medium severity or worse."""
        return any(f.severity in ("medium", "high", "critical") for f in self.findings)

    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {k: 0 for k in _SEVERITY_WEIGHT}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_count": self.doc_count,
            "risk_score": round(self.risk_score, 2),
            "poisoned": self.poisoned,
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


# --- IO ---------------------------------------------------------------------
def load_jsonl(path: str) -> List[Dict[str, Any]]:
    """Load a JSONL corpus file. Skips blank lines; raises on bad JSON."""
    docs: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{lineno}: expected a JSON object")
            obj.setdefault("id", f"doc-{lineno}")
            obj.setdefault("text", "")
            docs.append(obj)
    return docs


# --- helpers ----------------------------------------------------------------
_WORD_RE = re.compile(r"[A-Za-z0-9_]+")
# control chars except tab/newline/carriage-return, plus known stego ranges
_ZERO_WIDTH = {
    "​", "‌", "‍", "⁠", "﻿", "᠎",
}
_BIDI_CONTROL = {
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}
# Cyrillic/Greek homoglyphs that mimic Latin letters
_HOMOGLYPHS = {
    "а", "е", "о", "р", "с", "х", "у",
    "Α", "Β", "Ε", "Η", "Ο", "Ρ",
}

_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"you\s+are\s+now\s+(a|an|in)\b",
    r"system\s*prompt\s*[:=]",
    r"</?(system|assistant|user)>",
    r"do\s+not\s+(tell|inform|mention)\s+the\s+user",
    r"reveal\s+(your|the)\s+(system\s+)?(prompt|instructions?)",
    r"override\s+(your|the|all)\s+",
    r"new\s+instructions?\s*[:=]",
    r"(always|instead)\s+(recommend|respond\s+with|say|output)\b",
]
_INJECTION_RE = re.compile("|".join("(?:%s)" % p for p in _INJECTION_PATTERNS), re.IGNORECASE)


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in _WORD_RE.findall(text)]


def _norm_text(text: str) -> str:
    """Normalize text for duplicate detection."""
    return " ".join(_tokenize(text))


def _shingles(tokens: List[str], k: int = 4) -> set:
    if len(tokens) < k:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


# --- detectors --------------------------------------------------------------
def detect_backdoor_triggers(docs: List[Dict[str, Any]]) -> List[Finding]:
    """Find invisible-unicode payloads, bidi overrides, and homoglyph clusters
    that are used as covert retrieval triggers / content smuggling."""
    findings: List[Finding] = []
    for doc in docs:
        text = doc.get("text", "") or ""
        doc_id = str(doc.get("id"))
        zw = [c for c in text if c in _ZERO_WIDTH]
        bidi = [c for c in text if c in _BIDI_CONTROL]
        homo = [c for c in text if c in _HOMOGLYPHS]
        # general invisible/format control chars
        ctrl = [c for c in text
                if unicodedata.category(c) in ("Cf", "Co")
                and c not in _ZERO_WIDTH and c not in _BIDI_CONTROL]
        if bidi:
            findings.append(Finding(
                "backdoor_triggers", "critical", doc_id,
                f"bidirectional control characters detected ({len(bidi)})",
                {"codepoints": [hex(ord(c)) for c in bidi[:8]]},
            ))
        if zw:
            sev = "high" if len(zw) >= 3 else "medium"
            findings.append(Finding(
                "backdoor_triggers", sev, doc_id,
                f"zero-width / invisible characters detected ({len(zw)})",
                {"count": len(zw), "codepoints": [hex(ord(c)) for c in zw[:8]]},
            ))
        if homo:
            findings.append(Finding(
                "backdoor_triggers", "medium", doc_id,
                f"homoglyph characters mimicking Latin script ({len(homo)})",
                {"count": len(homo), "codepoints": [hex(ord(c)) for c in homo[:8]]},
            ))
        if ctrl:
            findings.append(Finding(
                "backdoor_triggers", "medium", doc_id,
                f"unexpected format/control characters ({len(ctrl)})",
                {"count": len(ctrl), "codepoints": [hex(ord(c)) for c in ctrl[:8]]},
            ))
    # rare-repeated-token trigger: a low-frequency token repeated many times in
    # a single doc (e.g. "cf-trigger cf-trigger cf-trigger") used as a backdoor key.
    df: Dict[str, int] = {}
    for doc in docs:
        for tok in set(_tokenize(doc.get("text", "") or "")):
            df[tok] = df.get(tok, 0) + 1
    n = len(docs) or 1
    for doc in docs:
        toks = _tokenize(doc.get("text", "") or "")
        counts: Dict[str, int] = {}
        for t in toks:
            counts[t] = counts.get(t, 0) + 1
        for tok, c in counts.items():
            # globally rare (appears in <=10% of docs) but locally hammered
            if c >= 5 and df.get(tok, 0) <= max(1, n // 10) and len(tok) >= 3:
                findings.append(Finding(
                    "backdoor_triggers", "high", str(doc.get("id")),
                    f"rare token '{tok}' repeated {c}x (possible retrieval trigger)",
                    {"token": tok, "repeat": c, "corpus_doc_frequency": df.get(tok, 0)},
                ))
    return findings


def detect_instruction_injection(docs: List[Dict[str, Any]]) -> List[Finding]:
    """Find prompt-injection / instruction-override payloads in retrievable text."""
    findings: List[Finding] = []
    for doc in docs:
        text = doc.get("text", "") or ""
        doc_id = str(doc.get("id"))
        hits = []
        for m in _INJECTION_RE.finditer(text):
            snippet = m.group(0).strip()
            if snippet:
                hits.append(snippet)
        if hits:
            sev = "critical" if len(hits) > 1 else "high"
            findings.append(Finding(
                "instruction_injection", sev, doc_id,
                f"prompt-injection style instruction detected ({len(hits)} match(es))",
                {"matches": hits[:5]},
            ))
    return findings


def detect_embedding_anomalies(docs: List[Dict[str, Any]]) -> List[Finding]:
    """Flag precomputed embedding vectors that are statistical outliers.

    Two signals:
      * abnormal L2 norm vs the corpus (robust z-score on norms) - a vector
        pushed far out so it is retrieved for almost any query.
      * per-vector mean per-dimension robust z deviation - a vector that is an
        outlier across many dimensions simultaneously.
    Docs without an 'embedding' field are skipped.
    """
    findings: List[Finding] = []
    vecs: List[Tuple[str, List[float]]] = []
    dim: Optional[int] = None
    for doc in docs:
        emb = doc.get("embedding")
        if not isinstance(emb, list) or not emb:
            continue
        try:
            fv = [float(x) for x in emb]
        except (TypeError, ValueError):
            findings.append(Finding(
                "embedding_anomalies", "low", str(doc.get("id")),
                "embedding contains non-numeric values", {},
            ))
            continue
        if dim is None:
            dim = len(fv)
        elif len(fv) != dim:
            findings.append(Finding(
                "embedding_anomalies", "medium", str(doc.get("id")),
                f"embedding dimension {len(fv)} != corpus dimension {dim}", {},
            ))
            continue
        vecs.append((str(doc.get("id")), fv))

    if len(vecs) < 4 or dim is None:
        return findings

    # --- norm outliers via robust z (median / MAD) ---
    norms = [math.sqrt(sum(x * x for x in v)) for _, v in vecs]
    med = _median(norms)
    mad = _median([abs(x - med) for x in norms]) or 1e-9
    for (doc_id, _), norm in zip(vecs, norms):
        rz = 0.6745 * (norm - med) / mad
        if abs(rz) >= 3.5:
            sev = "high" if abs(rz) >= 6 else "medium"
            findings.append(Finding(
                "embedding_anomalies", sev, doc_id,
                f"embedding norm outlier (robust z={rz:.1f}, norm={norm:.3f}, median={med:.3f})",
                {"robust_z": round(rz, 2), "norm": round(norm, 4)},
            ))

    # --- per-dimension robust stats, then per-vector outlier fraction ---
    col_med = []
    col_mad = []
    for d in range(dim):
        col = [v[d] for _, v in vecs]
        m = _median(col)
        mad_d = _median([abs(x - m) for x in col]) or 1e-9
        col_med.append(m)
        col_mad.append(mad_d)
    for doc_id, v in vecs:
        outlier_dims = 0
        for d in range(dim):
            rz = 0.6745 * (v[d] - col_med[d]) / col_mad[d]
            if abs(rz) >= 4.0:
                outlier_dims += 1
        frac = outlier_dims / dim
        if frac >= 0.30:
            findings.append(Finding(
                "embedding_anomalies", "high", doc_id,
                f"embedding is a multi-dimensional outlier ({outlier_dims}/{dim} dims off)",
                {"outlier_dims": outlier_dims, "dims": dim, "fraction": round(frac, 3)},
            ))
    return findings


def detect_duplication(docs: List[Dict[str, Any]], threshold: float = 0.9) -> List[Finding]:
    """Flag duplication flooding: clusters of near-identical documents.

    Exact normalized duplicates are reported; near-duplicates use Jaccard
    similarity over 4-token shingles. Many copies of one payload bias
    retrieval toward the attacker's text.
    """
    findings: List[Finding] = []

    # exact normalized duplicates
    groups: Dict[str, List[str]] = {}
    for doc in docs:
        norm = _norm_text(doc.get("text", "") or "")
        if not norm:
            continue
        groups.setdefault(norm, []).append(str(doc.get("id")))
    flagged_exact = set()
    for norm, ids in groups.items():
        if len(ids) >= 3:
            for i in ids:
                flagged_exact.add(i)
            sev = "high" if len(ids) >= 5 else "medium"
            findings.append(Finding(
                "duplication", sev, ids[0],
                f"{len(ids)} exact-duplicate documents (corpus flooding)",
                {"duplicate_ids": ids[:20], "count": len(ids)},
            ))

    # near-duplicate clustering (skip docs already in an exact-dup group)
    items = []
    for doc in docs:
        doc_id = str(doc.get("id"))
        if doc_id in flagged_exact:
            continue
        toks = _tokenize(doc.get("text", "") or "")
        if len(toks) < 4:
            continue
        items.append((doc_id, _shingles(toks)))
    used = set()
    for i in range(len(items)):
        if items[i][0] in used:
            continue
        cluster = [items[i][0]]
        for j in range(i + 1, len(items)):
            if items[j][0] in used:
                continue
            if _jaccard(items[i][1], items[j][1]) >= threshold:
                cluster.append(items[j][0])
                used.add(items[j][0])
        if len(cluster) >= 3:
            used.add(items[i][0])
            findings.append(Finding(
                "duplication", "medium", cluster[0],
                f"{len(cluster)} near-duplicate documents (>= {threshold:.0%} similar)",
                {"cluster_ids": cluster[:20], "count": len(cluster), "threshold": threshold},
            ))
    return findings


# --- orchestrator -----------------------------------------------------------
def scan_corpus(docs: List[Dict[str, Any]], dup_threshold: float = 0.9) -> ScanResult:
    """Run all detectors over a loaded corpus and aggregate a risk score."""
    findings: List[Finding] = []
    findings += detect_backdoor_triggers(docs)
    findings += detect_instruction_injection(docs)
    findings += detect_embedding_anomalies(docs)
    findings += detect_duplication(docs, threshold=dup_threshold)

    # stable sort: worst severity first, then detector, then doc id
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_order.get(f.severity, 9), f.detector, f.doc_id))

    risk = float(sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings))
    return ScanResult(findings=findings, doc_count=len(docs), risk_score=risk)
