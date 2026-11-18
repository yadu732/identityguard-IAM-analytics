"""CLI for generation and audit exports."""
import argparse
from datetime import date
from pathlib import Path

from identityguard.data import load_data
from identityguard.generate import generate_dataset
from identityguard.scoring import analyze


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Date must be YYYY-MM-DD") from exc


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="IdentityGuard IAM analytics CLI")
    cmds = parser.add_subparsers(dest="command", required=True)
    generate = cmds.add_parser("generate", help="Generate fictional identity CSVs")
    generate.add_argument("--data-dir", type=Path, default=Path("data"))
    generate.add_argument("--users", type=int, default=300)
    generate.add_argument("--seed", type=int, default=42)
    generate.add_argument("--as-of", type=_date, default=date.today())
    report = cmds.add_parser("analyze", help="Validate inputs and export an IAM audit")
    report.add_argument("--data-dir", type=Path, default=Path("data"))
    report.add_argument("--out-dir", type=Path, default=Path("reports"))
    report.add_argument("--as-of", type=_date, default=date.today())
    args = parser.parse_args(argv)
    if args.command == "generate":
        print("Generated:", generate_dataset(args.data_dir, args.users, args.seed, args.as_of))
    else:
        users, findings = analyze(load_data(args.data_dir), as_of=args.as_of)
        args.out_dir.mkdir(parents=True, exist_ok=True)
        users.to_csv(args.out_dir / "user_risks.csv", index=False)
        findings.to_csv(args.out_dir / "audit_findings.csv", index=False)
        print(f"Analyzed {len(users)} identities; {len(findings)} findings.")
        print(f"CSV reports saved to {args.out_dir.resolve()}")


if __name__ == "__main__":
    main()
