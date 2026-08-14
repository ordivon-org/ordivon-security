from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation import SampleVault
from ordivon_security.research_corpus import ResearchCorpus
from ordivon_security.research_corpus_sources import normalize_provider_record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage the Security research corpus. Corpus manifests never grant "
            "execution authority; Sample bytes remain in a private SampleVault or provider-owned "
            "system."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)

    listing = subparsers.add_parser("list")
    listing.add_argument("--root", type=Path, required=True)
    listing.add_argument("--kind", choices=("sample", "vulnerability"))

    show = subparsers.add_parser("show")
    show.add_argument("--root", type=Path, required=True)
    show.add_argument("--record-id", required=True)
    show.add_argument("--kind", choices=("sample", "vulnerability"))

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--root", type=Path, required=True)
    inspect.add_argument("--record-id", required=True)
    inspect.add_argument("--kind", choices=("sample", "vulnerability"))

    query = subparsers.add_parser("query")
    query.add_argument("--root", type=Path, required=True)
    query.add_argument("needle")

    register = subparsers.add_parser("register-manifest")
    register.add_argument("--root", type=Path, required=True)
    register.add_argument("--manifest", type=Path, required=True)

    provider = subparsers.add_parser("register-provider-snapshot")
    provider.add_argument("--root", type=Path, required=True)
    provider.add_argument(
        "--provider",
        choices=("osv", "nvd", "cisa-kev", "malwarebazaar", "virustotal"),
        required=True,
    )
    provider.add_argument("--snapshot", type=Path, required=True)
    provider.add_argument(
        "--record-id",
        help=(
            "Select one exact record from an official provider envelope/catalog. "
            "Required for multi-record CISA KEV/NVD snapshots; this intentionally "
            "avoids bulk mirroring."
        ),
    )

    import_sample = subparsers.add_parser("import-local-sample")
    import_sample.add_argument("--root", type=Path, required=True)
    import_sample.add_argument("--vault", type=Path, required=True)
    import_sample.add_argument("--path", type=Path, required=True)
    import_sample.add_argument("--media-type", default="application/octet-stream")
    import_sample.add_argument(
        "--artifact-role",
        choices=("third-party-artifact", "owned-synthetic", "maintained-test-fixture"),
        default="third-party-artifact",
    )
    import_sample.add_argument("--source-provider", default="operator-local")
    import_sample.add_argument("--source-record-id")
    import_sample.add_argument("--max-sample-bytes", type=int, default=1024 * 1024 * 1024)
    import_sample.add_argument("--max-vault-bytes", type=int)
    return parser


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def main() -> None:
    args = build_parser().parse_args()
    corpus = ResearchCorpus(args.root)

    if args.command == "verify":
        _print(corpus.verify())
        return
    if args.command == "list":
        _print([item.to_dict() for item in corpus.list_heads(record_kind=args.kind)])
        return
    if args.command == "show":
        _print(corpus.load(args.record_id, record_kind=args.kind))
        return
    if args.command == "inspect":
        _print(corpus.inspect(args.record_id, record_kind=args.kind))
        return
    if args.command == "query":
        _print(corpus.query(args.needle))
        return
    if args.command == "register-manifest":
        value = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Corpus manifest must contain one JSON object")
        _print(corpus.register(value).to_dict())
        return
    if args.command == "register-provider-snapshot":
        value = json.loads(args.snapshot.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Provider snapshot must contain one JSON object")
        record = normalize_provider_record(args.provider, value, record_id=args.record_id)
        _print(corpus.register(record).to_dict())
        return
    if args.command == "import-local-sample":
        vault = SampleVault(
            args.vault,
            max_sample_bytes=args.max_sample_bytes,
            max_vault_bytes=args.max_vault_bytes,
        )
        sample, registration = corpus.import_local_sample(
            vault=vault,
            path=args.path,
            media_type=args.media_type,
            artifact_role=args.artifact_role,
            source_provider=args.source_provider,
            source_record_id=args.source_record_id,
        )
        _print(
            {
                "sample": sample.to_dict(),
                "corpus": registration.to_dict(),
                "executionAdmission": "denied-by-default",
            }
        )
        return
    raise RuntimeError(f"Unhandled corpus command: {args.command}")


if __name__ == "__main__":
    main()
