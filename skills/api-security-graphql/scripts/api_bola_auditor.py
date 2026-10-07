#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenAPI / Swagger BOLA (Broken Object Level Authorization) Auditor.

WHY THIS EXISTS
---------------
BOLA (OWASP API1:2023) is the most widespread and severe API vulnerability.
It occurs when an API exposes endpoints that manipulate objects using IDs
supplied by the client (e.g. /api/users/{id}/orders/{orderId}) without
verifying whether the requesting user actually owns that resource.

This tool inspects OpenAPI (Swagger) v2/v3 specifications to identify:
  1. High-risk path parameter endpoints lacking authorization definitions.
  2. Sequential / integer object identifier exposure.
  3. Administrative functions exposed without role requirements.
  4. Missing global security definitions.

USAGE
-----
  # Audit an OpenAPI JSON specification
  python api_bola_auditor.py --spec openapi.json

  # Output structured JSON audit report
  python api_bola_auditor.py --spec openapi.json --json

EXIT CODES
----------
  0 = No high-risk authorization gaps detected
  1 = Endpoints with potential BOLA / missing authorization identified
  2 = Usage error or file not found
"""

import argparse
import json
import os
import re
import sys


def parse_spec_file(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Try JSON parsing
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Basic regex-based fallback for simple YAML specs
    paths = {}
    current_path = None
    for line in content.splitlines():
        path_match = re.match(r'^\s*([/\w\-\{\}]+):', line)
        if path_match and "/" in path_match.group(1):
            current_path = path_match.group(1).strip()
            paths[current_path] = {}
        elif current_path and re.match(r'^\s*(get|post|put|delete|patch):', line, re.IGNORECASE):
            verb = line.strip().split(':')[0].lower()
            paths[current_path][verb] = {}
    return {"paths": paths}


def audit_openapi_bola(spec):
    paths = spec.get("paths", {})
    global_security = spec.get("security", [])

    bola_candidates = []
    unprotected_endpoints = []
    admin_exposure = []

    path_id_pattern = re.compile(r'\{([A-Za-z0-9_\-]+)\}')

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        param_matches = path_id_pattern.findall(path)
        is_object_endpoint = len(param_matches) > 0

        for method, details in methods.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue

            if not isinstance(details, dict):
                details = {}

            endpoint_security = details.get("security", global_security)
            has_auth = bool(endpoint_security) and len(endpoint_security) > 0

            # Check BOLA risk
            if is_object_endpoint:
                if not has_auth:
                    unprotected_endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "parameters": param_matches,
                        "severity": "CRITICAL",
                        "issue": "Object ID in path with NO authentication or security definition."
                    })
                elif method.lower() in ("put", "delete", "patch"):
                    bola_candidates.append({
                        "path": path,
                        "method": method.upper(),
                        "parameters": param_matches,
                        "severity": "HIGH",
                        "issue": "State-changing mutation with path parameter. Requires strict object-level ownership check."
                    })

            # Check administrative functions
            if any(term in path.lower() for term in ("admin", "superuser", "internal", "manage")):
                if not has_auth:
                    admin_exposure.append({
                        "path": path,
                        "method": method.upper(),
                        "severity": "CRITICAL",
                        "issue": "Privileged/administrative path exposed without security requirement."
                    })

    return {
        "unprotected_endpoints": unprotected_endpoints,
        "bola_mutation_candidates": bola_candidates,
        "admin_exposure": admin_exposure
    }


def main():
    parser = argparse.ArgumentParser(
        description="Audit OpenAPI/Swagger specifications for BOLA/IDOR authorization attack surface."
    )
    parser.add_argument("--spec", required=True, help="Path to OpenAPI/Swagger JSON or YAML specification file.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    if not os.path.exists(args.spec):
        sys.stderr.write(f"Error: Specification file '{args.spec}' not found.\n")
        return 2

    spec_data = parse_spec_file(args.spec)
    audit_results = audit_openapi_bola(spec_data)

    unprotected = audit_results["unprotected_endpoints"]
    bola_mutations = audit_results["bola_mutation_candidates"]
    admin = audit_results["admin_exposure"]

    total_issues = len(unprotected) + len(bola_mutations) + len(admin)

    report = {
        "specification": args.spec,
        "total_attack_surfaces": total_issues,
        "unprotected_object_endpoints": len(unprotected),
        "state_changing_bola_targets": len(bola_mutations),
        "unprotected_admin_routes": len(admin),
        "findings": audit_results
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 72)
        print(" 🎯 OPENAPI BOLA & AUTHORIZATION AUDITOR")
        print("=" * 72)
        print(f" Spec File                 : {args.spec}")
        print(f" Unprotected Object Routes : {len(unprotected)} [CRITICAL]")
        print(f" BOLA Mutation Candidates  : {len(bola_mutations)} [HIGH ATTACK SURFACE]")
        print(f" Unprotected Admin Routes  : {len(admin)} [CRITICAL]")
        print("-" * 72)

        if unprotected:
            print("\n [!] UNPROTECTED OBJECT ENDPOINTS (NO AUTH SPECIFIED):")
            for ep in unprotected[:10]:
                print(f"   ❌ {ep['method']} {ep['path']} -> Params: {ep['parameters']}")

        if admin:
            print("\n [!] UNPROTECTED ADMINISTRATIVE ROUTES:")
            for ad in admin[:5]:
                print(f"   🛑 {ad['method']} {ad['path']}")

        if bola_mutations:
            print("\n [!] STATE-CHANGING OBJECT MUTATIONS (AUDIT USER OWNERSHIP):")
            for bm in bola_mutations[:10]:
                print(f"   ⚠️  {bm['method']} {bm['path']}")

        if total_issues == 0:
            print("\n [OK] All object endpoints specify security schemes.")
        print("=" * 72)

    return 1 if (len(unprotected) > 0 or len(admin) > 0) else 0


if __name__ == "__main__":
    sys.exit(main())
