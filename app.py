from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Tuple
import os
import json
import re
from datetime import datetime
from pathlib import Path

app = FastAPI(
    title="ATC Mitigator — SELECT SINGLE not unique (offline JSON key-catalog)",
    version="1.0.3"
)

# =========================
# Catalog (default + loader)
# =========================

DEFAULT_CATALOG: Dict[str, Any] = {
    "schema_version": "1.0",
    "sap_release": "S4HANA_2023",
    "generated_from": "embedded_default",
    "generated_at": "2025-09-14T00:00:00Z",
    "tables": {
        "BKPF": {
            "entity_type": "table",
            "primary_key": ["BUKRS", "BELNR", "GJAHR"],
            "unique_indexes": [],
            "implicit_client_field": True
        },
        "BSEG": {
            "entity_type": "compat_view",
            "maps_to": "ACDOCA",
            "primary_key": ["BUKRS", "BELNR", "GJAHR", "BUZEI"],
            "unique_indexes": [],
            "implicit_client_field": True
        },
        "ACDOCA": {
            "entity_type": "table",
            "primary_key": ["RCLNT", "RLDNR", "RYEAR", "DOCNR", "DOCIT"],
            "unique_indexes": [],
            "implicit_client_field": True
        },
        "VBRK": {
            "entity_type": "view_or_table",
            "primary_key": ["VBELN"],
            "unique_indexes": [],
            "implicit_client_field": True
        },
        "VBRP": {
            "entity_type": "view_or_table",
            "primary_key": ["VBELN", "POSNR"],
            "unique_indexes": [["AUBEL", "AUPOS"], ["VGBEL", "VGPOS"]],
            "implicit_client_field": True
        }
    },
    "synonyms": {
        "BSID": "ACDOCA",
        "BSAD": "ACDOCA",
        "BSIK": "ACDOCA",
        "BSAK": "ACDOCA",
        "GLT0": "ACDOCA",
        "FAGLFLEXA": "ACDOCA",
        "FAGLFLEXT": "ACDOCA"
    }
}


class CatalogTable(BaseModel):
    entity_type: str
    primary_key: List[str]
    unique_indexes: List[List[str]] = Field(default_factory=list)
    implicit_client_field: bool = True
    maps_to: Optional[str] = None


class Catalog(BaseModel):
    schema_version: str
    sap_release: Optional[str] = None
    generated_from: Optional[str] = None
    generated_at: Optional[str] = None
    tables: Dict[str, CatalogTable]
    synonyms: Dict[str, str] = Field(default_factory=dict)


def _uppercase_catalog(cat: Dict[str, Any]) -> Dict[str, Any]:
    out = json.loads(json.dumps(cat))
    out["tables"] = {t.upper(): v for t, v in out.get("tables", {}).items()}
    for t, meta in out["tables"].items():
        meta["primary_key"] = [f.upper() for f in meta.get("primary_key", [])]
        meta["unique_indexes"] = [[f.upper() for f in idx] for idx in meta.get("unique_indexes", [])]
        if "maps_to" in meta and meta["maps_to"]:
            meta["maps_to"] = meta["maps_to"].upper()
    out["synonyms"] = {k.upper(): v.upper() for k, v in out.get("synonyms", {}).items()}
    return out


def load_catalog() -> Catalog:
    """
    Load catalog with this precedence:
      1) env var KEYS_JSON_PATH
      2) /mnt/data/keys_catalog.json
      3) ./ddic.json                 (same folder as this app.py)
      4) ./keys_catalog.json         (same folder as this app.py)
      5) embedded DEFAULT_CATALOG
    """
    candidates: List[Path] = []
    env_path = os.environ.get("KEYS_JSON_PATH")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("/mnt/data/keys_catalog.json"))

    script_dir = Path(__file__).resolve().parent
    candidates.append(script_dir / "ddic.json")
    candidates.append(script_dir / "keys_catalog.json")

    for p in candidates:
        try:
            if p.exists():
                with p.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                data = _uppercase_catalog(data)
                cat = Catalog.model_validate(data)
                return cat
        except Exception:
            pass

    data = _uppercase_catalog(DEFAULT_CATALOG)
    return Catalog.model_validate(data)


CATALOG = load_catalog()

# =========================
# Input / Output models
# =========================

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    code: Optional[str] = ""


class Finding(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: str
    class_implementation: str
    line: int
    issue_type: str
    severity: str
    table: Optional[str] = None
    alias: Optional[str] = None
    is_unique: Optional[bool] = None
    unique_basis: Optional[str] = None
    missing_key_fields: Optional[List[str]] = None
    message: str
    original_snippet: str
    remediated_snippet: Optional[str] = None
    meta: Dict[str, Any] = {}

# =========================
# ABAP parsing helpers
# =========================

# We deliberately do NOT capture alias in the regex to avoid false-positives (e.g., 'WHERE' as alias).
SELECT_BLOCK_RE = re.compile(
    r"""(?P<full>
        SELECT\s+(?P<single>SINGLE\s+)?(?P<fields>.+?)\s+
        FROM\s+(?P<table>\w+)
        (?P<after_from>.*?)
    )\.
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)

RE_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)
RE_ORDER = re.compile(r"\bORDER\s+BY\b", re.IGNORECASE)
RE_INTO  = re.compile(r"\bINTO\b", re.IGNORECASE)
RE_UPTO  = re.compile(r"\bUP\s+TO\s+\d+\s+ROWS\b", re.IGNORECASE)
RE_JOIN  = re.compile(r"\bJOIN\b", re.IGNORECASE)

# Equality predicate collector
EQUALITY_FIELD_RE = re.compile(
    r"""(?:
            (?:(?P<q1>\w+)\s*~\s*(?P<f1>\w+))
          | (?:(?P<f2>\w+))
        )
        \s*=\s*
        (?!\()
        [^,\n]+
    """,
    re.IGNORECASE | re.VERBOSE
)

NEGATIVE_OP_RE = re.compile(r"\b(IN|BETWEEN|LIKE|IS\s+NULL|IS\s+NOT\s+NULL)\b", re.IGNORECASE)

CLAUSE_KEYWORDS = {
    "WHERE", "INTO", "ORDER", "GROUP", "HAVING", "FOR", "UP", "JOIN",
    "INNER", "LEFT", "RIGHT", "CROSS", "CLIENT", "USING"
}

def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 80)
    e = min(len(text), end + 80)
    return text[s:e]

def normalize_table_name(name: Optional[str]) -> str:
    if not name:
        return ""
    t = name.upper()
    return CATALOG.synonyms.get(t, t)

def catalog_entry(table: str) -> Optional[CatalogTable]:
    t = normalize_table_name(table)
    return CATALOG.tables.get(t)

def _where_segment(full_select: str, after_from: str) -> Tuple[str, int, int]:
    mw = RE_WHERE.search(after_from)
    if not mw:
        return "", -1, -1
    end_candidates = []
    for rex in (RE_INTO, RE_ORDER, RE_UPTO, re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
                re.compile(r"\bHAVING\b", re.IGNORECASE)):
        m = rex.search(after_from, mw.end())
        if m:
            end_candidates.append(m.start())
    where_end = min(end_candidates) if end_candidates else len(after_from)
    where_text = after_from[mw.end():where_end]
    start_in_full = full_select.upper().find("WHERE", 0)
    end_in_full = start_in_full + 5 + len(where_text) if start_in_full >= 0 else -1
    return where_text, start_in_full, end_in_full

def has_joins(after_from: str) -> bool:
    return RE_JOIN.search(after_from) is not None

def parse_safe_alias(after_from: str) -> Optional[str]:
    """
    Accepts alias only if it is 'AS <alias>' or bare '<alias>' and that token
    is not a clause keyword.
    """
    s = after_from.lstrip()

    # AS <alias>
    m = re.match(r"^AS\s+([A-Za-z]\w+)\b", s, flags=re.IGNORECASE)
    if m:
        token = m.group(1).upper()
        if token not in CLAUSE_KEYWORDS:
            return token

    # bare <alias>
    m = re.match(r"^([A-Za-z]\w+)\b", s)
    if m:
        token = m.group(1).upper()
        if token not in CLAUSE_KEYWORDS:
            return token

    return None

def collect_equal_fields(where_text: str, main_alias: Optional[str]) -> List[str]:
    out: List[str] = []
    for m in EQUALITY_FIELD_RE.finditer(where_text or ""):
        q1 = m.group("q1")
        f1 = m.group("f1")
        f2 = m.group("f2")
        if f1:
            if main_alias and q1 and q1.upper() == main_alias.upper():
                out.append(f1.upper())
            elif not main_alias:
                out.append(f1.upper())
        else:
            out.append(f2.upper())
    # dedup preserve order
    seen = set()
    res = []
    for f in out:
        if f not in seen:
            seen.add(f)
            res.append(f)
    return res

def is_unique_by_catalog(table: str, equal_fields: List[str]) -> Tuple[bool, str, List[str]]:
    meta = catalog_entry(table)
    if not meta:
        return False, "", []
    pk = [f.upper() for f in meta.primary_key]
    if meta.implicit_client_field:
        pk_wo_client = [f for f in pk if f not in ("MANDT", "RCLNT", "CLIENT")]
    else:
        pk_wo_client = pk
    eqset = set(f.upper() for f in equal_fields)

    missing = [f for f in pk_wo_client if f not in eqset]
    if not missing and pk_wo_client:
        return True, "primary_key", []

    for idx in meta.unique_indexes or []:
        idx_wo_client = [f for f in idx if f not in ("MANDT", "RCLNT", "CLIENT")]
        if idx_wo_client and all(f in eqset for f in idx_wo_client):
            return True, "unique_index", []
    return False, "", missing

# ---------- NEW: generator in your requested format ----------
def build_remediated_select(full: str,
                            is_single: bool,
                            fields: str,
                            table: str,
                            alias: Optional[str],
                            after_from: str) -> Optional[str]:
    """
    Emit:
      SELECT <fields>
      FROM <table> [AS <alias>]
      [INTO ...]
      UP TO 1 ROWS
      [WHERE ...].
      ENDSELECT.
    Drops existing ORDER BY to match requested layout.
    """

    # WHERE slice (verbatim with 'WHERE ' prefix if present)
    where_text, _, _ = _where_segment(full, after_from)
    where_line = ""
    if where_text:
        # Capture exact 'WHERE ...' token range from after_from
        mw = RE_WHERE.search(after_from)
        end_candidates = []
        for rex in (RE_INTO, RE_ORDER, RE_UPTO,
                    re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
                    re.compile(r"\bHAVING\b", re.IGNORECASE)):
            m = rex.search(after_from, mw.end())
            if m:
                end_candidates.append(m.start())
        where_end = min(end_candidates) if end_candidates else len(after_from)
        where_line = after_from[mw.start():where_end].strip()

    # INTO slice (verbatim, but not swallowing WHERE/UP TO/ORDER)
    into_line = ""
    m_into = RE_INTO.search(after_from)
    if m_into:
        start = m_into.start()
        # Cut at next clause start (WHERE, UP TO, ORDER, GROUP, HAVING) or end
        end_candidates = []
        for rex in (RE_WHERE, RE_UPTO, RE_ORDER,
                    re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
                    re.compile(r"\bHAVING\b", re.IGNORECASE)):
            m = rex.search(after_from, start + 4)
            if m:
                end_candidates.append(m.start())
        into_end = min(end_candidates) if end_candidates else len(after_from)
        into_line = after_from[start:into_end].strip()

    # UP TO n ROWS: keep original if present, else UP TO 1 ROWS
    m_upto = RE_UPTO.search(after_from)
    if m_upto:
        upto_line = after_from[m_upto.start():m_upto.end()].strip()
    else:
        upto_line = "UP TO 1 ROWS"

    # Header lines
    head_lines = [f"SELECT {fields.strip()}",
                  f"FROM {table}" + (f" AS {alias}" if alias else "")]

    out_lines = head_lines
    if into_line:
        out_lines.append(into_line)
    out_lines.append(upto_line)
    if where_line:
        out_lines.append(where_line + ".")
    else:
        out_lines[-1] = out_lines[-1] + "."  # put period on UP TO line if no WHERE

    out_lines.append("ENDSELECT.")

    # Join with newlines and normalize spaces
    remediated = "\n".join(l.strip() for l in out_lines)
    remediated = re.sub(r"[ \t]{2,}", " ", remediated)
    return remediated

# =========================
# Scanner
# =========================

def analyze_unit(u: Unit) -> Dict[str, Any]:
    code = u.code or ""
    findings: List[Finding] = []

    for m in SELECT_BLOCK_RE.finditer(code):
        full = m.group("full")
        start_off, _ = m.span("full")
        is_single = bool(m.group("single"))
        fields = m.group("fields") or ""
        table = (m.group("table") or "").upper()
        after_from = m.group("after_from") or ""

        # Only mitigate SELECT SINGLE
        if not is_single:
            continue

        # Robust alias detection (prevents alias='WHERE')
        alias = parse_safe_alias(after_from)

        # JOINs — we still flag, but we cannot prove uniqueness by single-table keys
        joined = has_joins(after_from)
        where_text, _, _ = _where_segment(full, after_from)

        cat = catalog_entry(table)
        equal_fields = collect_equal_fields(where_text, alias)

        is_unique, basis, missing = (False, "", [])
        if not joined and cat:
            is_unique, basis, missing = is_unique_by_catalog(table, equal_fields)
        if is_unique:
            continue

        remediated = build_remediated_select(
            full=full,
            is_single=is_single,
            fields=fields,
            table=table,
            alias=alias,
            after_from=after_from
        )

        message_parts = []
        if joined:
            message_parts.append("SELECT SINGLE with JOIN cannot be proven unique by a single table key.")
        if not cat:
            message_parts.append(f"No catalog entry found for table '{table}'.")
        else:
            message_parts.append(
                "SELECT SINGLE not unique by primary key" +
                (f" (missing: {', '.join(missing)})" if missing else "") +
                (f"; unique index not matched" if basis == "" else "")
            )
        # Note: ORDER BY intentionally omitted to follow requested layout
        message_parts.append("Rewritten to classic SELECT ... ENDSELECT with UP TO 1 ROWS.")
        msg = " ".join(message_parts)

        finding = Finding(
            pgm_name=u.pgm_name,
            inc_name=u.inc_name,
            type=u.type,
            name=u.name or "",
            class_implementation=u.class_implementation or "",
            line=line_of_offset(code, start_off),
            issue_type="SelectSingleNotUnique",
            severity="warning",
            table=table,
            alias=alias,
            is_unique=False,
            unique_basis=basis or None,
            missing_key_fields=missing or None,
            message=msg,
            original_snippet=full.strip() + ".",
            remediated_snippet=remediated,
            meta={
                "joined": joined,
                "equal_fields_found": equal_fields,
                "catalog_table_used": normalize_table_name(table),
                "catalog_present": bool(cat),
            }
        )
        findings.append(finding)

    result = u.model_dump()
    result["findings"] = [f.model_dump() for f in findings]
    result["assessment"] = (
        f"Scanned {len(list(SELECT_BLOCK_RE.finditer(code)))} SELECT block(s). "
        f"Flagged {len(findings)} non-unique SELECT SINGLE statement(s) for remediation. "
        f"Catalog: schema={CATALOG.schema_version}, release={CATALOG.sap_release or 'n/a'}."
    )
    return result


def analyze_units(units: List[Unit]) -> List[Dict[str, Any]]:
    return [analyze_unit(u) for u in units]

# =========================
# API
# =========================

@app.post("/analyze-units")
def api_analyze_units(units: List[Unit]):
    return analyze_units(units)

@app.get("/catalog")
def api_catalog_info():
    return {
        "schema_version": CATALOG.schema_version,
        "sap_release": CATALOG.sap_release,
        "tables": list(CATALOG.tables.keys()),
        "synonyms": CATALOG.synonyms
    }

@app.get("/health")
def health():
    return {"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}
