#!/usr/bin/env python3
"""Merge Hadolint per-Dockerfile JSON arrays into one JSON file."""
import json
import os

raw_path = '/tmp/hadolint-raw.json'
out_path = '/tmp/hadolint-report.json'

if not os.path.exists(raw_path) or os.path.getsize(raw_path) == 0:
    print("No Hadolint raw output found — writing empty report")
    json.dump([], open(out_path, 'w'))
else:
    content = open(raw_path).read().strip()
    merged = []
    # Hadolint writes one JSON array per Dockerfile — parse each array
    # by finding balanced [ ] blocks
    depth = 0
    start = None
    for i, ch in enumerate(content):
        if ch == '[':
            if depth == 0:
                start = i
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth == 0 and start is not None:
                block = content[start:i+1]
                try:
                    items = json.loads(block)
                    merged.extend(items)
                except Exception as e:
                    print(f"Warning: could not parse block at {start}: {e}")
                start = None

    json.dump(merged, open(out_path, 'w'), indent=2)
    print(f"Merged {len(merged)} Hadolint findings into {out_path}")

# Clean up raw file
try:
    os.remove(raw_path)
except Exception:
    pass
