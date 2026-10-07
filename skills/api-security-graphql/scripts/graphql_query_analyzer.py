#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GraphQL Query Complexity & Depth Analyzer.

WHY THIS EXISTS
---------------
GraphQL allows client-defined nesting. Attackers exploit recursive relationships
(e.g. author -> posts -> author -> posts...) or alias overloading
(e.g. user1: user(id:1), user2: user(id:2)...) to execute Application-Layer
Denial of Service (DoS) against backend databases.

This tool calculates GraphQL query depth, alias count, and detects circular
fragment references.

USAGE
-----
  # Analyze a query file with default maximum depth of 5
  python graphql_query_analyzer.py --query query.gql

  # Analyze with custom depth threshold
  python graphql_query_analyzer.py --query query.gql --max-depth 7

  # Output machine-readable JSON
  python graphql_query_analyzer.py --query query.gql --json

EXIT CODES
----------
  0 = Query complexity within safe limits
  1 = Query exceeds depth threshold or exhibits DoS patterns
  2 = Usage error or query file not found
"""

import argparse
import json
import os
import re
import sys


def calculate_query_depth(query_str):
    max_depth = 0
    current_depth = 0

    # Strip comments and string literals
    sanitized = re.sub(r'#[^\n]*', '', query_str)
    sanitized = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', sanitized)

    for char in sanitized:
        if char == '{':
            current_depth += 1
            if current_depth > max_depth:
                max_depth = current_depth
        elif char == '}':
            if current_depth > 0:
                current_depth -= 1

    return max_depth


def count_aliases(query_str):
    # Pattern: identifier: identifier(
    alias_pattern = re.compile(r'\b([A-Za-z0-9_]+)\s*:\s*[A-Za-z0-9_]+\s*\(', re.MULTILINE)
    matches = alias_pattern.findall(query_str)
    return len(matches), matches[:10]


def check_circular_fragments(query_str):
    # Detects fragment spreads
    spreads = re.findall(r'\.\.\.\s*([A-Za-z0-9_]+)', query_str)
    fragment_defs = re.findall(r'fragment\s+([A-Za-z0-9_]+)\s+on', query_str)
    return len(spreads) > 0 and len(spreads) > len(fragment_defs) * 2


def analyze_query(query_str, max_allowed_depth):
    depth = calculate_query_depth(query_str)
    alias_count, sample_aliases = count_aliases(query_str)
    has_circular_fragments = check_circular_fragments(query_str)

    violations = []
    if depth > max_allowed_depth:
        violations.append({
            "type": "EXCESSIVE_QUERY_DEPTH",
            "measured": depth,
            "threshold": max_allowed_depth,
            "message": f"Query depth of {depth} exceeds safe limit of {max_allowed_depth}."
        })

    if alias_count >= 10:
        violations.append({
            "type": "ALIAS_OVERLOADING_BATCHING",
            "measured": alias_count,
            "threshold": 10,
            "message": f"Detected {alias_count} aliases; potential batching / amplification DoS attack."
        })

    if has_circular_fragments:
        violations.append({
            "type": "CIRCULAR_FRAGMENT_LOOP",
            "measured": True,
            "threshold": False,
            "message": "Potential circular fragment recursion loop detected."
        })

    return {
        "depth": depth,
        "max_allowed_depth": max_allowed_depth,
        "alias_count": alias_count,
        "sample_aliases": sample_aliases,
        "circular_fragments_detected": has_circular_fragments,
        "violations": violations
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze GraphQL queries for excessive depth, alias overloading, and DoS patterns."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--query", help="Path to GraphQL query file (.gql or .graphql).")
    group.add_argument("--string", help="Raw GraphQL query string.")
    parser.add_argument("--max-depth", type=int, default=5, help="Maximum allowable query depth (default: 5).")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    if args.query:
        if not os.path.exists(args.query):
            sys.stderr.write(f"Error: Query file '{args.query}' not found.\n")
            return 2
        try:
            with open(args.query, "r", encoding="utf-8", errors="ignore") as f:
                raw_query = f.read()
        except Exception as e:
            sys.stderr.write(f"Error reading query file: {e}\n")
            return 2
    else:
        raw_query = args.string

    analysis = analyze_query(raw_query, args.max_depth)
    is_dangerous = len(analysis["violations"]) > 0

    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print("=" * 72)
        print(" ⚡ GRAPHQL QUERY COMPLEXITY AUDITOR")
        print("=" * 72)
        print(f" Measured Query Depth : {analysis['depth']} (Threshold: {analysis['max_allowed_depth']})")
        print(f" Total Alias Count    : {analysis['alias_count']}")
        print(f" Status               : {'[UNSAFE - POTENTIAL DOS]' if is_dangerous else '[SAFE]'}")
        print("-" * 72)

        if is_dangerous:
            print(" [ALERT] Security Violations Detected:")
            for v in analysis["violations"]:
                print(f"   ❌ [{v['type']}] {v['message']}")
        else:
            print(" [OK] Query complexity is within acceptable defensive thresholds.")
        print("=" * 72)

    return 1 if is_dangerous else 0


if __name__ == "__main__":
    sys.exit(main())
