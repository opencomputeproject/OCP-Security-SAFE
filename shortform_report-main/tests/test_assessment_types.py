#!/usr/bin/env python3
"""
Test the assessment-type discriminator of the $assessment alternatives against
the CDDL profile.

Each fixture under Documentation/corim_profile/examples/assessment-types/ is an
issue-entry fragment in CBOR diagnostic notation. Fixtures in valid/ must be
accepted by the CDDL (this includes cvss both with and without assessment-type,
since the tag is optional there for legacy data); fixtures in invalid/ must be
rejected (jil and qualitative-rating require the tag, and a tag naming a
different type is never allowed).

Requires the Ruby tools used by the CI workflows: cddlc, cddl and diag2cbor.rb
(gem install cddl cddlc cbor-diag). Network access is needed to fetch the
upstream CoRIM CDDL unless --corim-cddl is given.

Usage:
    python tests/test_assessment_types.py [--corim-cddl corim-base-upstream.cddl]
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from OcpReportLib import JIL_FACTOR_CATEGORIES, JIL_FACTOR_KEYS, JIL_RATING_LEVELS  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_CDDL = REPO_ROOT / "Documentation/corim_profile/ocp-safe-sfr-profile.cddl"
FIXTURES = REPO_ROOT / "Documentation/corim_profile/examples/assessment-types"
CORIM_CDDL_URL = (
    "https://github.com/ietf-rats-wg/draft-ietf-rats-corim/releases/download/"
    "cddl-draft-ietf-rats-corim-08/corim-autogen.cddl"
)


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def build_schema(workdir, corim_cddl):
    """Combine the CoRIM and profile CDDL, rooted at issue-entry.

    The cddl tool validates against the first rule in the file, so a
    root rule is prepended.
    """
    if corim_cddl is None:
        corim_cddl = workdir / "corim-base-upstream.cddl"
        urllib.request.urlretrieve(CORIM_CDDL_URL, corim_cddl)

    result = run(["cddlc", "-t", "cddl", str(corim_cddl), str(PROFILE_CDDL)])
    if result.returncode != 0:
        sys.exit(f"cddlc failed:\n{result.stderr}")

    schema = workdir / "issue-entry.cddl"
    schema.write_text("issue-test = issue-entry\n" + result.stdout)
    return schema


def validates(schema, diag_file, workdir):
    """Return True if the diag fixture encodes and validates against the schema."""
    cbor_file = workdir / (diag_file.stem + ".cbor")
    encoded = subprocess.run(["diag2cbor.rb", str(diag_file)], capture_output=True)
    if encoded.returncode != 0:
        sys.exit(f"diag2cbor.rb failed for {diag_file}:\n{encoded.stderr.decode()}")
    cbor_file.write_bytes(encoded.stdout)
    return run(["cddl", str(schema), "validate", str(cbor_file)]).returncode == 0


def cddl_enum(cddl_text, rule):
    """Return {name: value} for an `rule = &(name: value, ...)` enum in the CDDL."""
    match = re.search(rf"^{re.escape(rule)} = &\((.*?)\n\)", cddl_text, re.S | re.M)
    if match is None:
        sys.exit(f"enum {rule} not found in {PROFILE_CDDL}")
    return {k: int(v) for k, v in re.findall(r"([a-z0-9-]+):\s*(\d+)", match.group(1))}


def check_library_matches_cddl():
    """The library encodes JIL categories as integers; make sure they match the CDDL enums."""
    cddl_text = PROFILE_CDDL.read_text()
    mismatches = []
    for factor, categories in JIL_FACTOR_CATEGORIES.items():
        rule = "jil-" + factor.replace("_", "-")
        library = {label: values[0] for label, values in categories.items()}
        if cddl_enum(cddl_text, rule) != library:
            mismatches.append(rule)
    ratings = {k.lower().replace(" ", "-"): v for k, v in JIL_RATING_LEVELS.items()}
    if cddl_enum(cddl_text, "jil-rating-level") != ratings:
        mismatches.append("jil-rating-level")
    for factor, key in JIL_FACTOR_KEYS.items():
        name = factor.replace("_", "-")
        found = re.findall(rf"&\({re.escape(name)}: (\d+)\)", cddl_text)
        if not found or any(int(k) != key for k in found):
            mismatches.append(f"factor key {name}")
    return mismatches


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--corim-cddl", type=Path, help="local copy of the upstream CoRIM CDDL")
    args = parser.parse_args()

    for tool in ("cddlc", "cddl", "diag2cbor.rb"):
        if shutil.which(tool) is None:
            sys.exit(f"{tool} not found; install with: gem install cddl cddlc cbor-diag")

    cases = [(f, True) for f in sorted((FIXTURES / "valid").glob("*.diag"))]
    cases += [(f, False) for f in sorted((FIXTURES / "invalid").glob("*.diag"))]
    if not cases:
        sys.exit(f"no fixtures found under {FIXTURES}")

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        schema = build_schema(workdir, args.corim_cddl)
        for diag_file, expect_valid in cases:
            ok = validates(schema, diag_file, workdir) == expect_valid
            failures += not ok
            expected = "accepted" if expect_valid else "rejected"
            print(f"{'✓' if ok else '✗'} {diag_file.parent.name}/{diag_file.name}: expected {expected}")

    drift = check_library_matches_cddl()
    print(f"{'✗' if drift else '✓'} OcpReportLib JIL enum values match the CDDL" + (f": {', '.join(drift)} differ" if drift else ""))
    failures += len(drift)

    if failures:
        sys.exit(f"{failures} assessment-type check(s) failed")
    print(f"✓ All {len(cases)} assessment-type cases and the library/CDDL enum check passed")


if __name__ == "__main__":
    main()
