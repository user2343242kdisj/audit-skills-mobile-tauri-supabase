#!/usr/bin/env python3
"""
BOLA / IDOR harness for Supabase PostgREST APIs.

Schemathesis is RLS-blind by default — it tests for schema violations and
auth bypass but does not know that "user A should not see user B's row."
This harness fills that gap.

Methodology:
  1. Discover tables via PostgREST OpenAPI (/rest/v1/).
  2. As user A, list resources for each discovered table (RLS gives only A's rows).
  3. Extract primary-key candidates from each row.
  4. For each (table, pk) tuple, attempt cross-user access as user B:
       - GET    /rest/v1/{table}?{pk}=eq.{value}
       - PATCH  /rest/v1/{table}?{pk}=eq.{value}  (with no-op body)
       - DELETE /rest/v1/{table}?{pk}=eq.{value}
  5. Any non-empty response body or 2xx status from B against A's resource is a finding.

Findings are written to a JSON report; the script exits non-zero on any finding,
suitable for CI gating.

Usage:
  python3 bola-harness.py \\
      --url https://abcdefghij.supabase.co \\
      --anon-key sb_publishable_... \\
      --user-a-jwt eyJhbGciOiJSUzI1NiIs... \\
      --user-b-jwt eyJhbGciOiJSUzI1NiIs... \\
      --output /tmp/bola-report.json

Notes:
  - The harness is intentionally read-mostly. The PATCH probe sends
    `Prefer: return=minimal` and an empty payload to avoid mutation,
    then checks status codes. DELETE is dry-run by default; pass
    --enable-destructive to actually attempt DELETE.
  - The harness only attempts cross-user access — it never invents
    primary-key values.
  - Tables that anon role can already see (no RLS) are flagged but not
    tested cross-user (their visibility is the finding).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(2)


REQUEST_TIMEOUT = 15
SLEEP_BETWEEN_REQUESTS = 0.05


@dataclass
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    table: str
    operation: str  # READ | UPDATE | DELETE | ANON_VISIBLE
    pk_field: str
    pk_value: str
    user: str  # B (the attacker)
    status_code: int
    response_excerpt: str
    detail: str


@dataclass
class Report:
    target_url: str
    started_at: str
    findings: list[Finding] = field(default_factory=list)
    tables_discovered: list[str] = field(default_factory=list)
    tables_tested: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class PostgRESTClient:
    """Minimal PostgREST client. Holds anon key + optional bearer JWT."""

    def __init__(self, base_url: str, anon_key: str, jwt: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.anon_key = anon_key
        self.jwt = jwt
        self.session = requests.Session()
        self.session.headers["apikey"] = anon_key
        if jwt:
            self.session.headers["Authorization"] = f"Bearer {jwt}"

    def get_openapi(self) -> dict[str, Any]:
        url = f"{self.base_url}/rest/v1/"
        r = self.session.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def list_table(self, table: str, limit: int = 50) -> list[dict[str, Any]]:
        url = f"{self.base_url}/rest/v1/{table}"
        r = self.session.get(
            url,
            params={"limit": str(limit)},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            return r.json() if isinstance(r.json(), list) else []
        return []

    def get_one(self, table: str, pk_field: str, pk_value: Any) -> requests.Response:
        url = f"{self.base_url}/rest/v1/{table}"
        return self.session.get(
            url,
            params={pk_field: f"eq.{pk_value}"},
            timeout=REQUEST_TIMEOUT,
        )

    def patch_one(self, table: str, pk_field: str, pk_value: Any) -> requests.Response:
        """PATCH with empty body + return=minimal — non-mutating probe."""
        url = f"{self.base_url}/rest/v1/{table}"
        return self.session.patch(
            url,
            params={pk_field: f"eq.{pk_value}"},
            headers={
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            data="{}",
            timeout=REQUEST_TIMEOUT,
        )

    def delete_one(self, table: str, pk_field: str, pk_value: Any) -> requests.Response:
        url = f"{self.base_url}/rest/v1/{table}"
        return self.session.delete(
            url,
            params={pk_field: f"eq.{pk_value}"},
            headers={"Prefer": "return=minimal"},
            timeout=REQUEST_TIMEOUT,
        )


def discover_tables(openapi: dict[str, Any]) -> list[str]:
    """PostgREST OpenAPI lists every accessible table as a /<name> path.

    Filter for paths shaped like `/<identifier>` (one segment, no params)
    and that have a 'get' method. Skip RPC paths under `/rpc/`.
    """
    tables: list[str] = []
    paths: dict[str, Any] = openapi.get("paths", {}) or {}
    for path, item in paths.items():
        if not path.startswith("/") or path == "/":
            continue
        # one-segment paths only; skip /rpc/* etc.
        seg = path.lstrip("/")
        if "/" in seg:
            continue
        if seg.startswith("rpc"):
            continue
        if "get" not in (item or {}):
            continue
        tables.append(seg)
    return tables


def likely_pk_fields(rows: list[dict[str, Any]]) -> list[str]:
    """Heuristic: prefer 'id', then any field ending in '_id', else first key."""
    if not rows:
        return []
    sample = rows[0]
    keys = list(sample.keys())
    if "id" in keys:
        return ["id"]
    id_like = [k for k in keys if k.endswith("_id") or k == "uuid"]
    if id_like:
        return id_like[:1]
    return keys[:1]


def severity_for(operation: str) -> str:
    return {
        "READ": "HIGH",
        "UPDATE": "CRITICAL",
        "DELETE": "CRITICAL",
        "ANON_VISIBLE": "MEDIUM",
    }.get(operation, "LOW")


def run(args: argparse.Namespace) -> Report:
    base = args.url.rstrip("/")

    anon = PostgRESTClient(base, args.anon_key)
    user_a = PostgRESTClient(base, args.anon_key, args.user_a_jwt)
    user_b = PostgRESTClient(base, args.anon_key, args.user_b_jwt)

    report = Report(
        target_url=base,
        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    # 1. Discover tables via OpenAPI as user A (RLS-aware view).
    try:
        openapi = user_a.get_openapi()
    except Exception as exc:
        report.errors.append(f"Failed to fetch OpenAPI as user A: {exc}")
        return report
    tables = discover_tables(openapi)
    report.tables_discovered = tables

    if not tables:
        report.errors.append("No tables discovered via OpenAPI.")
        return report

    # 2. Anon-visibility check: any table the anon role can list is itself a smell.
    for t in tables:
        try:
            anon_rows = anon.list_table(t, limit=1)
            time.sleep(SLEEP_BETWEEN_REQUESTS)
            if anon_rows:
                report.findings.append(Finding(
                    severity=severity_for("ANON_VISIBLE"),
                    table=t,
                    operation="ANON_VISIBLE",
                    pk_field="-",
                    pk_value="-",
                    user="anon",
                    status_code=200,
                    response_excerpt=json.dumps(anon_rows[:1])[:200],
                    detail="Anon role can list rows — likely missing or weak RLS policy.",
                ))
        except Exception as exc:
            report.errors.append(f"anon list({t}): {exc}")

    # 3. For each table, list as user A, then probe as user B.
    for t in tables:
        try:
            rows = user_a.list_table(t, limit=20)
            time.sleep(SLEEP_BETWEEN_REQUESTS)
        except Exception as exc:
            report.errors.append(f"user_a list({t}): {exc}")
            continue
        if not rows:
            continue
        report.tables_tested.append(t)
        pk_fields = likely_pk_fields(rows)
        if not pk_fields:
            continue
        pk = pk_fields[0]

        for row in rows[: args.max_rows_per_table]:
            pk_value = row.get(pk)
            if pk_value is None:
                continue

            # READ probe
            try:
                r = user_b.get_one(t, pk, pk_value)
                if r.status_code == 200 and r.json():
                    report.findings.append(Finding(
                        severity=severity_for("READ"),
                        table=t,
                        operation="READ",
                        pk_field=pk,
                        pk_value=str(pk_value),
                        user="B",
                        status_code=r.status_code,
                        response_excerpt=r.text[:200],
                        detail="User B fetched user A's row via PostgREST eq filter.",
                    ))
            except Exception as exc:
                report.errors.append(f"user_b GET {t}#{pk_value}: {exc}")

            time.sleep(SLEEP_BETWEEN_REQUESTS)

            # UPDATE probe (non-mutating: empty body + return=minimal)
            try:
                r = user_b.patch_one(t, pk, pk_value)
                # 204 No Content from PATCH against an existing row = update accepted
                # 404 / 401 / 403 / empty 204 with no rows touched = correctly denied
                # PostgREST returns 204 with header Content-Range: 0-0/* when no rows match
                content_range = r.headers.get("Content-Range", "")
                rows_affected = (
                    int(content_range.split("/")[-1])
                    if content_range and "*" not in content_range
                    else None
                )
                if r.status_code in (200, 204) and rows_affected and rows_affected > 0:
                    report.findings.append(Finding(
                        severity=severity_for("UPDATE"),
                        table=t,
                        operation="UPDATE",
                        pk_field=pk,
                        pk_value=str(pk_value),
                        user="B",
                        status_code=r.status_code,
                        response_excerpt=f"Content-Range: {content_range}",
                        detail="User B PATCHed user A's row (rows_affected > 0).",
                    ))
            except Exception as exc:
                report.errors.append(f"user_b PATCH {t}#{pk_value}: {exc}")

            time.sleep(SLEEP_BETWEEN_REQUESTS)

            # DELETE probe (only if explicitly enabled)
            if args.enable_destructive:
                try:
                    r = user_b.delete_one(t, pk, pk_value)
                    content_range = r.headers.get("Content-Range", "")
                    if r.status_code in (200, 204) and content_range and "0-0" not in content_range:
                        report.findings.append(Finding(
                            severity=severity_for("DELETE"),
                            table=t,
                            operation="DELETE",
                            pk_field=pk,
                            pk_value=str(pk_value),
                            user="B",
                            status_code=r.status_code,
                            response_excerpt=f"Content-Range: {content_range}",
                            detail="User B DELETED user A's row.",
                        ))
                except Exception as exc:
                    report.errors.append(f"user_b DELETE {t}#{pk_value}: {exc}")

                time.sleep(SLEEP_BETWEEN_REQUESTS)

    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", required=True, help="Supabase project base URL")
    p.add_argument("--anon-key", required=True, help="Supabase anon/publishable key")
    p.add_argument("--user-a-jwt", required=True, help="JWT for test user A")
    p.add_argument("--user-b-jwt", required=True, help="JWT for test user B (attacker)")
    p.add_argument("--output", default="-", help="Path to write JSON report (or '-' for stdout)")
    p.add_argument(
        "--max-rows-per-table",
        type=int,
        default=5,
        help="Limit cross-user probes per table (default 5)",
    )
    p.add_argument(
        "--enable-destructive",
        action="store_true",
        help="Enable DELETE probes (DESTRUCTIVE — disabled by default)",
    )
    args = p.parse_args()

    report = run(args)
    payload = {
        "target_url": report.target_url,
        "started_at": report.started_at,
        "tables_discovered": report.tables_discovered,
        "tables_tested": report.tables_tested,
        "findings": [asdict(f) for f in report.findings],
        "errors": report.errors,
    }
    out = json.dumps(payload, indent=2)
    if args.output == "-":
        print(out)
    else:
        with open(args.output, "w") as f:
            f.write(out)

    # Summary to stderr for CI logs
    crit = sum(1 for f in report.findings if f.severity == "CRITICAL")
    high = sum(1 for f in report.findings if f.severity == "HIGH")
    medium = sum(1 for f in report.findings if f.severity == "MEDIUM")
    low = sum(1 for f in report.findings if f.severity == "LOW")
    print(
        f"BOLA harness: {len(report.tables_tested)}/{len(report.tables_discovered)} tables tested. "
        f"Findings: {crit} CRITICAL, {high} HIGH, {medium} MEDIUM, {low} LOW. "
        f"Errors: {len(report.errors)}.",
        file=sys.stderr,
    )

    # Exit code: 1 on any HIGH+ finding for CI gating
    if crit or high:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
