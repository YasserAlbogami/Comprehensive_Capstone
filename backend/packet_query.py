import os
import sys
import json
from typing import List, Dict, Any, Tuple

import psycopg
from dotenv import load_dotenv
from openai import OpenAI

# -------------------- Setup --------------------
load_dotenv()

DB_URL = os.getenv("DATABASE_URL")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ATTACKS_FILE = os.getenv("ATTACKS_FILE", "./attacks.txt")
GEN_MODEL = os.getenv("GEN_MODEL", "gpt-4o")
HUMANIZE_SQL = os.getenv("HUMANIZE_SQL", "1")  # "1" to use LLM, "0" for deterministic-only

if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY missing from .env")
if not DB_URL:
    raise RuntimeError("DATABASE_URL missing from .env")

client = OpenAI(api_key=OPENAI_API_KEY)

# -------------------- Unified System Prompt --------------------
SYSTEM_PROMPT = r"""
You are PacketQA, a single RAG assistant for Wi-Fi packet analytics and attack knowledge.

First, decide the user's intent and set one MODE:

• MODE=SQL  → The user asks about database facts from the "packet" table
  (counts, lists, top IPs, time ranges, stats, filters by label/attack, etc.).
  - Output ONLY a SELECT statement (no semicolon).
  - Never write INSERT/UPDATE/DELETE/DROP/ALTER/CREATE.
  - Table: packet
  - Columns: id, timestamp, frame_time_delta, frame_time_epoch,
    frame_number, frame_len, radiotap_datarate, radiotap_dbm_antsignal,
    radiotap_channel_freq, radiotap_mactime, wlan_duration,
    wlan_fc_type, wlan_fc_subtype, wlan_bssid, wlan_sa, wlan_da,
    ip_src, ip_dst, ip_proto, tcp_srcport, tcp_dstport,
    udp_srcport, udp_dstport, arp_opcode, arp_src_proto_ipv4, arp_dst_proto_ipv4,
    label, proba_attack, attack_type
  - If the user mentions a specific attack (e.g., Deauth, Krack), filter with:
      LOWER(attack_type) = LOWER('<value>')
  - If no attack is mentioned, infer appropriate columns (ip_src, ip_dst, frame_len, timestamp…).
  - Use LIMIT when returning example rows.
  - Do NOT include a trailing semicolon.

• MODE=DOCS → The user asks conceptual questions about attacks
  (definition, how it works, harms/impact, defenses/mitigations, detection).
  Answer ONLY using the supplied CONTEXT from attacks.txt. If the answer is not
  supported by the context, say you don't have that information.

• MODE=OOS  → The question is not about packet analytics or the provided attacks.txt.
  Respond that this chatbot focuses on packet analytics and attacks knowledge only.

Return a single JSON object with EXACT keys:
{"mode": "<SQL|DOCS|OOS>", "sql": "<query or empty>", "answer": "<answer text or empty>"}

Rules:
- When MODE=SQL: "sql" must contain the SELECT query; "answer" should be "" (empty).
- When MODE=DOCS: "answer" must contain the final answer from CONTEXT; "sql" should be "".
- When MODE=OOS: set "answer" to a brief scope message and "sql" to "".
- Do not add any extra keys or text outside the JSON.
"""

# -------------------- Helpers --------------------
def _load_attacks_context() -> str:
    try:
        with open(ATTACKS_FILE, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

def _strip_code_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        parts = t.split("```")
        if len(parts) >= 3:
            inner = parts[1]
            if inner.startswith("json"):
                inner = inner.split("\n", 1)[-1]
            return inner.strip()
        return parts[-1].strip()
    return t

def _json_or_none(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None

def _run_sql(sql: str) -> Tuple[List[str], List[Tuple[Any, ...]]]:
    # Only allow SELECT defensively
    if not sql.strip().lower().startswith("select"):
        raise ValueError("Refusing to run non-SELECT SQL.")
    with psycopg.connect(DB_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            return cols, rows

def _rows_to_dicts(cols: List[str], rows: List[Tuple[Any, ...]]) -> List[Dict[str, Any]]:
    return [{cols[i]: r[i] for i in range(len(cols))} for r in rows]

# -------------------- Strict, fact-only humanization --------------------
COUNT_LIKE = {"count", "cnt", "total", "n", "num", "rows", "records"}

def _extract_facts_from_result(cols: List[str], rows: List[Tuple[Any, ...]]) -> Dict[str, Any]:
    """
    Build a 'facts' JSON strictly from the SQL result (NO derived stats).
    Only includes:
      - schema (column names)
      - row_count
      - if it's a single scalar cell, include scalar_value
      - up to first 10 rows as dictionaries (exact values)
    """
    facts: Dict[str, Any] = {
        "schema": cols[:],
        "row_count": len(rows),
        "scalar_value": None,
        "rows_sample": [],
    }

    # Single-cell result (e.g., SELECT COUNT(*) AS count)
    if len(cols) == 1 and len(rows) == 1:
        facts["scalar_value"] = {cols[0]: rows[0][0]}
        return facts

    # Otherwise, include a small sample of literal rows (no aggregation/statistics)
    for r in rows[:10]:
        facts["rows_sample"].append({cols[i]: r[i] for i in range(len(cols))})
    return facts

def _humanize_with_llm(question: str, facts: Dict[str, Any]) -> str:
    """
    Ask the model to write a short explanation using ONLY the literal 'facts'
    provided (no extra statistics or invented details).
    """
    guardrails = f"""
You are a helpful analyst. Explain the SQL result in 3–6 sentences, friendly and clear.

STRICT RULES:
- You may ONLY use facts from the JSON under "FACTS" below.
- Do NOT introduce statistics (min/max/median/percentages/time-ranges) unless those exact values
  appear explicitly in FACTS (e.g., as columns or literal row values).
- If FACTS shows a single scalar (e.g., a count), explain that number and what it represents.
- If FACTS shows multiple rows/columns, describe the columns and notable literal values from the sample.
- No hedging, no SQL jargon, no assumptions. Stay within FACTS.

FACTS:
{json.dumps(facts, ensure_ascii=False)}
"""
    resp = client.chat.completions.create(
        model=GEN_MODEL,
        temperature=0.2,
        messages=[
            {"role": "system", "content": "You produce concise, human-friendly explanations."},
            {"role": "user", "content": f"User question: {question}"},
            {"role": "user", "content": guardrails.strip()},
        ],
    )
    return resp.choices[0].message.content.strip()

def _deterministic_explanation(question: str, cols: List[str], rows: List[Tuple[Any, ...]]) -> str:
    """
    Fallback explanation with zero model calls and zero derived stats.
    """
    # Empty
    if not rows:
        return "The query returned no rows."

    # Single-cell result
    if len(cols) == 1 and len(rows) == 1:
        k, v = cols[0], rows[0][0]
        return f"The query returns a single value: {k} = {v}. In other words, this is the total based on your filter."

    # Small table result → briefly describe columns and show a couple of literal examples
    examples = []
    for r in rows[:3]:
        pairings = ", ".join(f"{cols[i]}={r[i]}" for i in range(len(cols)))
        examples.append(f"- {pairings}")
    return (
        f"The query returned {len(rows)} row(s) with columns {', '.join(cols)}. "
        "Here are a few exact examples from the result:\n" + "\n".join(examples)
    )

# -------------------- Core: one-shot classify + generate --------------------
def _route_and_generate(question: str) -> Dict[str, str]:
    attacks_ctx = _load_attacks_context()
    system_msgs = [{"role": "system", "content": SYSTEM_PROMPT.strip()}]
    if attacks_ctx:
        system_msgs.append({"role": "system", "content": f"CONTEXT (attacks.txt):\n{attacks_ctx}"})
    else:
        system_msgs.append({"role": "system", "content": "CONTEXT (attacks.txt) is empty or missing."})

    resp = client.chat.completions.create(
        model=GEN_MODEL,
        temperature=0,
        messages=system_msgs + [{"role": "user", "content": question.strip()}],
    )
    raw = resp.choices[0].message.content
    raw = _strip_code_fences(raw)
    data = _json_or_none(raw)
    if not data or not isinstance(data, dict):
        raise ValueError(f"Model did not return valid JSON. Got:\n{raw}")

    mode = (data.get("mode") or "").strip().upper()
    sql = (data.get("sql") or "").strip()
    answer = (data.get("answer") or "").strip()
    if mode not in {"SQL", "DOCS", "OOS"}:
        raise ValueError(f"Invalid mode from model: {mode}")

    if mode == "SQL" and not sql.lower().startswith("select"):
        raise ValueError("When MODE=SQL, the 'sql' must be a SELECT.")

    if mode in {"DOCS", "OOS"} and sql:
        sql = ""

    return {"mode": mode, "sql": sql, "answer": answer}

# -------------------- Public API --------------------
def packet_ask(question: str) -> Dict[str, Any]:
    """
    Unified RAG ask function.
    Returns:
      {
        "mode": "...",
        "sql": "...",
        "answer": "...",          # filled for DOCS/OOS or humanized summary for SQL
        "cols": [...],            # for SQL mode
        "rows": [ {...}, ... ],   # for SQL mode (list of dict rows)
        "error": "..."            # present if something failed
      }
    """
    try:
        routed = _route_and_generate(question)
        mode, sql, ans = routed["mode"], routed["sql"], routed["answer"]

        if mode == "SQL":
            cols, rows = _run_sql(sql)
            rows_dict = _rows_to_dicts(cols, rows)

            facts = _extract_facts_from_result(cols, rows)
            if HUMANIZE_SQL == "1":
                try:
                    summary = _humanize_with_llm(question, facts)
                except Exception:
                    summary = _deterministic_explanation(question, cols, rows)
            else:
                summary = _deterministic_explanation(question, cols, rows)

            return {
                "mode": mode,
                "sql": sql,
                "answer": summary,   # conversational summary based ONLY on literal results
                "cols": cols,
                "rows": rows_dict,
            }

        # MODE=DOCS or MODE=OOS
        return {
            "mode": mode,
            "sql": "",
            "answer": ans if ans else ("This chatbot focuses on packet analytics and attacks only." if mode == "OOS" else "I don't have that in the provided context."),
            "cols": [],
            "rows": [],
        }

    except Exception as e:
        return {
            "mode": "ERROR",
            "sql": "",
            "answer": "",
            "cols": [],
            "rows": [],
            "error": str(e),
        }

# -------------------- CLI --------------------
def _print_cli(result: Dict[str, Any]):
    if result.get("error"):
        print(f"[ERROR] {result['error']}")
        return

    mode = result.get("mode")
    if mode == "SQL":
        print(result.get("answer", ""))  # humanized explanation
        cols = result.get("cols", [])
        rows = result.get("rows", [])
        if rows:
            max_rows = min(10, len(rows))
            print(f"\nSample {max_rows} row(s):")
            print("\t".join(cols))
            for r in rows[:max_rows]:
                print("\t".join(str(r.get(c, "")) for c in cols))
    else:
        print(result.get("answer", "").strip())

def main():
    question = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else input("Question: ").strip()
    out = packet_ask(question)
    _print_cli(out)

if __name__ == "__main__":
    main()
