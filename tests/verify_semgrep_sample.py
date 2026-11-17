"""Compare this sample's Semgrep JSON with its three static reference findings."""

import json
import sys
from collections import Counter
from pathlib import Path


EXPECTED = Counter({
    ("literal-token", "app.py"): 1,
    ("concatenated-select", "static_cases.py"): 1,
    ("unescaped-markup", "static_cases.py"): 1,
})


def verify(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data["errors"]:
        raise ValueError("Semgrep reported scan errors")
    actual = Counter()
    for hit in data["results"]:
        if not 1 <= hit["start"]["line"] <= hit["end"]["line"]:
            raise ValueError("Invalid source location")
        actual[(hit["check_id"], Path(hit["path"]).name)] += 1
    if actual != EXPECTED:
        raise ValueError(f"Expected {dict(EXPECTED)}, found {dict(actual)}")
    print(f"Semgrep {data['version']}: {sum(actual.values())} sample findings verified.")


if __name__ == "__main__":
    verify(sys.argv[1])
