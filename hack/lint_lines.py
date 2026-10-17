#!/usr/bin/env python3
"""Read linter JSON on stdin; print file-basename:line for every CFG-000 finding."""
import json
import os
import sys

for f in json.load(sys.stdin)["findings"]:
    if f["rule"] == "CFG-000":
        print(f"{os.path.basename(f['file'])}:{f['line']}")
