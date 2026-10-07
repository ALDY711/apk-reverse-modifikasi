#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GraphQL Introspection Schema Security Auditor.

WHY THIS EXISTS
---------------
GraphQL allows clients to request exactly what they need. However, leaving
introspection enabled in production exposes the entire backend domain model,
including deprecated fields, internal database IDs, administrative mutations,
and sensitive user attributes (passwords, salts, auth tokens).

This tool audits GraphQL introspection schema files (JSON format) or SDL schemas
to identify sensitive fields, unvalidated administrative mutations, and
unrestricted query patterns.

USAGE
-----
  # Audit a GraphQL introspection JSON file
  python graphql_schema_auditor.py --schema schema.json

  # Output structured JSON report
  python graphql_schema_auditor.py --schema schema.json --json

EXIT CODES
----------
  0 = Schema is clean or only low-risk items found
  1 = Sensitive field exposures or high-risk mutations detected
  2 = Usage error or invalid schema file
"""

import argparse
import json
import os
import re
import sys

SENSITIVE_FIELD_PATTERNS = re.compile(
    r'(password|passwd|hash|salt|secret|token|auth_token|api_key|credit_card|cvv|ssn|private_key)',
    re.IGNORECASE
)

ADMIN_MUTATION_PATTERNS = re.compile(
    r'(delete|drop|purge|truncate|makeadmin|grantrole|elevate|exec|eval|resetdb|internal)',
    re.IGNORECASE
)


def extract_schema_data(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    try:
        data = json.loads(content)
        if "data" in data and "__schema" in data["data"]:
            return data["data"]["__schema"]
        elif "__schema" in data:
            return data["__schema"]
        return data
    except json.JSONDecodeError:
        # Fallback regex parsing for raw .graphql SDL files
        return {"raw_sdl": content}


def audit_graphql_schema(schema_data):
    sensitive_fields = []
    dangerous_mutations = []

    if "raw_sdl" in schema_data:
        # SDL string analysis
        sdl = schema_data["raw_sdl"]
        for line_num, line in enumerate(sdl.splitlines(), 1):
            if SENSITIVE_FIELD_PATTERNS.search(line):
                sensitive_fields.append({
                    "name": line.strip(),
                    "type": "SDL_FIELD",
                    "line": line_num,
                    "reason": "Field name matches sensitive keyword pattern."
                })
            if "type Mutation" in line or ADMIN_MUTATION_PATTERNS.search(line):
                if any(k in line.lower() for k in ["delete", "admin", "purge", "grant"]):
                    dangerous_mutations.append({
                        "name": line.strip(),
                        "line": line_num,
                        "reason": "Administrative / destructive mutation detected in SDL."
                    })
        return sensitive_fields, dangerous_mutations

    # JSON Introspection analysis
    types = schema_data.get("types", [])
    for t in types:
        type_name = t.get("name", "")
        if type_name.startswith("__"):
            continue

        fields = t.get("fields") or []
        for field in fields:
            field_name = field.get("name", "")
            if SENSITIVE_FIELD_PATTERNS.search(field_name):
                sensitive_fields.append({
                    "parent_type": type_name,
                    "field_name": field_name,
                    "type": str(field.get("type", {}).get("name", "Unknown")),
                    "reason": f"Sensitive keyword identified in field '{field_name}' under type '{type_name}'."
                })

            if type_name.lower() in ("mutation", "mutations"):
                if ADMIN_MUTATION_PATTERNS.search(field_name):
                    dangerous_mutations.append({
                        "mutation_name": field_name,
                        "args": [a.get("name") for a in field.get("args", [])],
                        "reason": f"Privileged or destructive mutation '{field_name}' exposed."
                    })

    return sensitive_fields, dangerous_mutations


def main():
    parser = argparse.ArgumentParser(
        description="Audit GraphQL Introspection schema for sensitive data leaks and unsafe mutations."
    )
    parser.add_argument("--schema", required=True, help="Path to GraphQL schema JSON or SDL file.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    if not os.path.exists(args.schema):
        sys.stderr.write(f"Error: Schema file '{args.schema}' not found.\n")
        return 2

    schema_data = extract_schema_data(args.schema)
    sensitive_fields, dangerous_mutations = audit_graphql_schema(schema_data)

    has_critical = len(sensitive_fields) > 0 or len(dangerous_mutations) > 0

    report = {
        "schema_file": args.schema,
        "introspection_exposed": True,
        "sensitive_fields_count": len(sensitive_fields),
        "dangerous_mutations_count": len(dangerous_mutations),
        "sensitive_fields": sensitive_fields,
        "dangerous_mutations": dangerous_mutations
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 72)
        print(" 🔍 GRAPHQL SCHEMA SECURITY AUDIT REPORT")
        print("=" * 72)
        print(f" Schema File: {args.schema}")
        print(f" Introspection Status : [ACCESSIBLE] (Should be disabled in production)")
        print(f" Sensitive Fields     : {len(sensitive_fields)}")
        print(f" High-Risk Mutations  : {len(dangerous_mutations)}")
        print("-" * 72)

        if sensitive_fields:
            print("\n [!] SENSITIVE FIELDS EXPOSED IN SCHEMA:")
            for sf in sensitive_fields[:15]:
                parent = sf.get("parent_type", "Schema")
                fname = sf.get("field_name", sf.get("name"))
                print(f"   ⚠️  {parent}.{fname} -> {sf['reason']}")
            if len(sensitive_fields) > 15:
                print(f"   ... and {len(sensitive_fields) - 15} more fields.")

        if dangerous_mutations:
            print("\n [!] PRIVILEGED / DESTRUCTIVE MUTATIONS EXPOSED:")
            for dm in dangerous_mutations[:10]:
                mname = dm.get("mutation_name", dm.get("name"))
                print(f"   🛑 {mname} -> {dm['reason']}")

        if not has_critical:
            print("\n [OK] No obviously sensitive fields or unshielded mutations detected.")
        print("=" * 72)

    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
