"""Build median test durations from directories of CI XML reports.

Pass one directory per successful main push for .NET, containing all of its
shard XMLs. Use --kind postgres for successful Python PostgreSQL matrix runs.
The resulting JSON maps .NET class names (or Python test paths) to seconds.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path
from statistics import median
import xml.etree.ElementTree as ET


def run_durations(reports: list[Path], kind: str) -> Counter:
    totals: Counter = Counter()
    for report in reports:
        root = ET.parse(report).getroot()
        if kind == "dotnet":
            assemblies = root.findall("assembly")
            if root.tag != "assemblies" or not assemblies or any(
                int(assembly.get(status, "0"))
                for assembly in assemblies
                for status in ("failed", "errors", "skipped", "not-run")
            ):
                raise ValueError(f"Expected a passing xUnit report in {report}")
            cases = root.iter("test")
            key = "type"
        else:
            if root.tag not in {"testsuite", "testsuites"}:
                raise ValueError(f"Expected a JUnit report in {report}")
            cases = root.iter("testcase")
            key = "file"

        count = 0
        for case in cases:
            if kind == "dotnet" and case.get("result") != "Pass":
                raise ValueError(f"Non-passing xUnit case in {report}")
            if kind == "postgres":
                if case.find("failure") is not None or case.find("error") is not None:
                    raise ValueError(f"Failing JUnit case in {report}")
                if case.find("skipped") is not None:
                    continue
            name = case.get(key)
            seconds = float(case.attrib["time"])
            if not name or not math.isfinite(seconds) or seconds < 0:
                raise ValueError(f"Invalid case duration or missing {key} in {report}")
            totals[name] += seconds
            count += 1
        if not count:
            raise ValueError(f"No passing test cases in {report}")
    return totals


def build_durations(runs: list[Path], kind: str) -> dict[str, float]:
    distinct_runs = {run.resolve() for run in runs}
    if len(distinct_runs) < 3 or len(distinct_runs) != len(runs):
        raise ValueError("Supply at least three distinct run directories")
    samples: dict[str, list[float]] = defaultdict(list)
    seen_reports = set()
    for run in runs:
        reports = sorted(run.rglob("*.xml"))
        paths = {report.resolve() for report in reports}
        if not reports or len(paths) != len(reports) or seen_reports & paths:
            raise ValueError(f"Expected distinct XML reports in {run}")
        seen_reports.update(paths)
        for name, seconds in run_durations(reports, kind).items():
            samples[name].append(seconds)
    return {name: round(median(seconds), 6) for name, seconds in sorted(samples.items())}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("dotnet", "postgres"), default="dotnet")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("runs", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        durations = build_durations(args.runs, args.kind)
    except (OSError, ValueError, KeyError, ET.ParseError) as error:
        parser.error(str(error))
    args.output.write_text(json.dumps(durations, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
