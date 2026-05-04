#!/usr/bin/env python3
"""Merge Checkov per-framework result files into one JSON file."""
import json
import glob
import os

results = []
files = glob.glob('/tmp/results_*.json')

if not files:
    print("No Checkov result files found — writing empty report")
    json.dump([], open('/tmp/checkov-report.json', 'w'))
else:
    for f in files:
        try:
            data = json.load(open(f))
            if isinstance(data, list):
                results.extend(data)
            else:
                results.append(data)
            print(f"Loaded: {f}")
        except Exception as e:
            print(f"Warning: could not parse {f}: {e}")

    json.dump(results, open('/tmp/checkov-report.json', 'w'), indent=2)
    print(f"Merged {len(results)} result sets into /tmp/checkov-report.json")

# Clean up individual result files
for f in files:
    try:
        os.remove(f)
    except Exception:
        pass
