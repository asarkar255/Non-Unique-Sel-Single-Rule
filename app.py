from fastapi import FastAPI
from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional, Dict, Any, Tuple
import os
import json
import re
from datetime import datetime
from pathlib import Path

app = FastAPI(
    title="ATC Mitigator — SELECT SINGLE not unique (offline JSON key-catalog)",
    version="1.0.1"
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
            "implicit_client_field": True  # treat client as implicit
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
    # Upper-case table/field names for consistent matching
    out = json.loads(json.dumps(cat))  # deep copy
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
      1) env var KEYS_JSON_PATH (absolute or relative)
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

    # NEW: discover JSON files placed next to this script
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
            # Fall back to the next candidate
            pass

    # default
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
    unique_basis: Optional[str] = None  # "primary_key" or "unique_index"
    missing_key_fields: Optional[List[str]] = None
    message: str
    original_snippet: str
    remediated_snippet: Optional[str] = None
    meta: Dict[str, Any] = {}


# =========================
# ABAP parsing helpers
# =========================

# Capture SELECT ... FROM <table> [AS <alias>] ... .
# We specifically care about SELECT SINGLE without joins for exact key coverage check.
SELECT_BLOCK_RE = re.compile(
    r"""(?P<full>
        SELECT\s+(?P<single>SINGLE\s+)?(?P<fields>.+?)\s+
        FROM\s+(?P<table>\w+)(?:\s+(?:AS\s+)?(?P<alias>\w+))?
        (?P<after_from>.*?)
    )\.
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)

# Find clause anchors inside a SELECT block
RE_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)
RE_ORDER = re.compile(r"\bORDER\s+BY\b", re.IGNORECASE)
RE_INTO = re.compile(r"\bINTO\b", re.IGNORECASE)
RE_UPTO = re.compile(r"\bUP\s+TO\s+\d+\s+ROWS\b", re.IGNORECASE)
RE_JOIN = re.compile(r"\bJOIN\b", re.IGNORECASE)

# Equality predicate collector: <qual?>FIELD = <expr>
# Accept forms: ALIAS~FIELD, TABLE~FIELD, FIELD (unqualified)
EQUALITY_FIELD_RE = re.compile(
    r"""(?:
            (?:(?P<q1>\w+)\s*~\s*(?P<f1>\w+))   # alias~FIELD
          | (?:(?P<f2>\w+))                     # FIELD (unqualified)
        )
        \s*=\s*
        (?!\()                                  # not beginning of parenthesized subquery
        [^,\n]+                                 # value expr (rough)
    """,
    re.IGNORECASE | re.VERBOSE
)

# Exclusion patterns: we don't count IN/BETWEEN/LIKE/IS NULL towards equality coverage
NEGATIVE_OP_RE = re.compile(r"\b(IN|BETWEEN|LIKE|IS\s+NULL|IS\s+NOT\s+NULL)\b", re.IGNORECASE)


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
    # synonyms mapping (e.g., BSEG→ACDOCA)
    mapped = CATALOG.synonyms.get(t, t)
    return mapped


def catalog_entry(table: str) -> Optional[CatalogTable]:
    t = normalize_table_name(table)
    return CATALOG.tables.get(t)


def _where_segment(full_select: str, after_from: str) -> Tuple[str, int, int]:
    """
    Return (where_text, where_start_in_full, where_end_in_full)
    or ("", -1, -1) if no WHERE.
    """
    mw = RE_WHERE.search(after_from)
    if not mw:
        return "", -1, -1

    # End at INTO|ORDER|UP TO|GROUP|HAVING or end of statement part
    end_candidates = []
    for rex in (RE_INTO, RE_ORDER, RE_UPTO, re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
                re.compile(r"\bHAVING\b", re.IGNORECASE)):
        m = rex.search(after_from, mw.end())
        if m:
            end_candidates.append(m.start())
    where_end = min(end_candidates) if end_candidates else len(after_from)
    where_text = after_from[mw.end():where_end]
    # Compute absolute positions in full text (rough)
    start_in_full = full_select.upper().find("WHERE", 0)
    end_in_full = start_in_full + 5 + len(where_text) if start_in_full >= 0 else -1
    return where_text, start_in_full, end_in_full


def has_joins(after_from: str) -> bool:
    return RE_JOIN.search(after_from) is not None


def collect_equal_fields(where_text: str, main_alias: Optional[str]) -> List[str]:
    """
    Collect equality-constrained field names that belong to the main table (by alias) or are unqualified.
    """
    out: List[str] = []
    if not where_text or NEGATIVE_OP_RE.search(where_text):
        # We still try to collect equalities, but note presence of non-equality operators separately if needed.
        pass

    for m in EQUALITY_FIELD_RE.finditer(where_text):
        q1 = m.group("q1")
        f1 = m.group("f1")
        f2 = m.group("f2")
        if f1:
            # qualified: q1~f1
            if main_alias and q1 and q1.upper() == main_alias.upper():
                out.append(f1.upper())
            elif not main_alias:
                # No alias on FROM: treat qualified with table name as acceptable (rare in old syntax)
                out.append(f1.upper())
        else:
            # unqualified field
            out.append(f2.upper())
    # Deduplicate while preserving order
    seen = set()
    res = []
    for f in out:
        if f not in seen:
            seen.add(f)
            res.append(f)
    return res


def is_unique_by_catalog(table: str, equal_fields: List[str]) -> Tuple[bool, str, List[str]]:
    """
    Returns (is_unique, basis, missing_fields)
    basis: "primary_key" | "unique_index" | ""
    """
    meta = catalog_entry(table)
    if not meta:
        return False, "", []

    pk = [f.upper() for f in meta.primary_key]
    # Drop implicit client if present in PK
    if meta.implicit_client_field:
        pk_wo_client = [f for f in pk if f not in ("MANDT", "RCLNT", "CLIENT")]
    else:
        pk_wo_client = pk

    eqset = set(f.upper() for f in equal_fields)

    # Primary key coverage (all by equality)
    missing = [f for f in pk_wo_client if f not in eqset]
    if not missing and pk_wo_client:
        return True, "primary_key", []

    # Unique index coverage (any fully matched index)
    for idx in meta.unique_indexes or []:
        idx_wo_client = [f for f in idx if f not in ("MANDT", "RCLNT", "CLIENT")]
        if idx_wo_client and all(f in eqset for f in idx_wo_client):
            return True, "unique_index", []
    return False, "", missing


def render_order_by_keys(table: str, alias: Optional[str]) -> Optional[str]:
    meta = catalog_entry(table)
    if not meta:
        return None
    keys = [f for f in meta.primary_key if f not in ("MANDT", "RCLNT", "CLIENT")] or meta.primary_key
    if not keys:
        return None
    if alias:
        parts = [f"{alias}~{k}" for k in keys]
    else:
        parts = keys
    return ", ".join(parts)


def build_remediated_select(full: str,
                            is_single: bool,
                            fields: str,
                            table: str,
                            alias: Optional[str],
                            after_from: str) -> Optional[str]:
    """
    Convert SELECT SINGLE ... to SELECT ... WHERE ... ORDER BY <pk> UP TO 1 ROWS INTO ...
    Preserve original WHERE and INTO (and existing ORDER BY if any — but if SINGLE present,
    we will drop SINGLE and add UP TO 1 ROWS if not present).
    """
    # Find subparts
    where_text, _, _ = _where_segment(full, after_from)
    m_order = RE_ORDER.search(after_from)
    m_into = RE_INTO.search(after_from)
    m_upto = RE_UPTO.search(after_from)

    # Build new header
    new_head = f"SELECT {fields.strip()} FROM {table}"
    if alias:
        new_head += f" AS {alias}"
    new_mid = ""

    # Keep original WHERE (if any)
    if where_text:
        # Ensure we reconstruct WHERE clause exactly as captured
        # Get raw WHERE with keyword from after_from
        where_match = RE_WHERE.search(after_from)
        if where_match:
            where_end = None
            end_candidates = []
            for rex in (RE_INTO, RE_ORDER, RE_UPTO,
                        re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
                        re.compile(r"\bHAVING\b", re.IGNORECASE)):
                m = rex.search(after_from, where_match.end())
                if m:
                    end_candidates.append(m.start())
            where_end = min(end_candidates) if end_candidates else len(after_from)
            new_mid += " " + after_from[where_match.start():where_end].strip()

    # ORDER BY:
    new_order = ""
    if m_order:
        # Already has ORDER BY; keep as-is
        # Capture ORDER BY ... (up to INTO/UP TO/end)
        start = m_order.start()
        end_candidates = []
        for rex in (RE_INTO, RE_UPTO,
                    re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
                    re.compile(r"\bHAVING\b", re.IGNORECASE)):
            m = rex.search(after_from, m_order.end())
            if m:
                end_candidates.append(m.start())
        o_end = min(end_candidates) if end_candidates else len(after_from)
        new_order = " " + after_from[start:o_end].strip()
    else:
        # Build from PK
        ob = render_order_by_keys(table, alias)
        if ob:
            new_order = f" ORDER BY {ob}"

    # UP TO 1 ROWS:
    new_upto = ""
    if m_upto:
        # keep original UP TO n ROWS (normalize to what they already wrote)
        start = m_upto.start()
        # end at INTO or end
        m_after = RE_INTO.search(after_from, m_upto.end())
        if m_after:
            new_upto = " " + after_from[start:m_after.start()].strip()
        else:
            new_upto = " " + after_from[start:].strip()
    else:
        new_upto = " UP TO 1 ROWS"

    # INTO (keep exact)
    new_into = ""
    if m_into:
        # INTO ... up to end (but not including final period captured outside)
        new_into = " " + after_from[m_into.start():].strip()

    # Stitch
    remediated = (new_head + new_mid + new_order + new_upto + new_into).strip() + "."
    # Remove residual double spaces
    remediated = re.sub(r"\s{2,}", " ", remediated)
    return remediated


# =========================
# Scanner
# =========================

def analyze_unit(u: Unit) -> Dict[str, Any]:
    code = u.code or ""
    findings: List[Finding] = []

    for m in SELECT_BLOCK_RE.finditer(code):
        full = m.group("full")
        start_off, end_off = m.span("full")
        is_single = bool(m.group("single"))
        fields = m.group("fields") or ""
        table = (m.group("table") or "").upper()
        alias = (m.group("alias") or "").upper() if m.group("alias") else None
        after_from = m.group("after_from") or ""

        # Only mitigate SELECT SINGLE (ATC finding scope)
        if not is_single:
            continue

        # If joins are present, we cannot guarantee uniqueness by a single table's PK
        joined = has_joins(after_from)

        # WHERE
        where_text, _, _ = _where_segment(full, after_from)

        # Catalog lookup (normalize table via synonyms)
        cat = catalog_entry(table)

        # Equality fields
        equal_fields = collect_equal_fields(where_text, alias)

        is_unique, basis, missing = (False, "", [])
        if not joined and cat:
            is_unique, basis, missing = is_unique_by_catalog(table, equal_fields)

        # If unique by catalog, we skip remediation (ATC should be satisfied)
        if is_unique:
            continue

        # Build remediation snippet: drop SINGLE, add ORDER BY PK + UP TO 1 ROWS
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
        message_parts.append("Rewrite to SELECT … ORDER BY <primary_key> UP TO 1 ROWS (do not use ORDER BY with SELECT SINGLE).")
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
    # Return minimal info for debugging
    return {
        "schema_version": CATALOG.schema_version,
        "sap_release": CATALOG.sap_release,
        "tables": list(CATALOG.tables.keys()),
        "synonyms": CATALOG.synonyms
    }


@app.get("/health")
def health():
    return {"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}
