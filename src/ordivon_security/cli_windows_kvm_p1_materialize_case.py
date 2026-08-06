from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation.windows_kvm import _load_object
from ordivon_security.evaluation.windows_kvm_p1_cases import (
    DerivedCaseManifest,
    materialize_derived_case,
)


def _component(value: str) -> tuple[str, Path]:
    logical, separator, source = value.partition("=")
    if not separator or not logical or not source:
        raise argparse.ArgumentTypeError("Component must be LOGICAL_PATH=SOURCE_PATH")
    return logical, Path(source)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Materialize an exact private derived evaluation payload; no installer is produced."
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--component", action="append", type=_component, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    manifest = DerivedCaseManifest.from_dict(_load_object(args.manifest, "derived Case manifest"))
    components = dict(args.component)
    if len(components) != len(args.component):
        raise ValueError("Derived component logical paths must be unique")
    result = materialize_derived_case(manifest, components, args.output_root)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
