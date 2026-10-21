import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from rehub.pipeline import load_record, run_investigation
from rehub.textreport import render_text
from rehub.tools import Executor, subprocess_executor

DEFAULT_DATA = "~/.rehub"


def _plc_ips(items: Sequence[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in items:
        name, sep, ip = item.partition("=")
        if not sep or not name or not ip:
            raise argparse.ArgumentTypeError(f"--plc-ip expects NAME=IP, got {item!r}")
        mapping[name] = ip
    return mapping


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rehub", description="Local OT investigation engine")
    parser.add_argument(
        "--data",
        default=os.environ.get("REHUB_DATA", DEFAULT_DATA),
        help="data directory (default: $REHUB_DATA or ~/.rehub)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyze evidence files and print the investigation")
    analyze.add_argument("files", nargs="+", type=Path)
    analyze.add_argument(
        "--plc-ip",
        action="append",
        default=[],
        metavar="NAME=IP",
        help="controller IP for a PLC file, matched by file name (repeatable)",
    )
    analyze.add_argument("--timeout", type=float, default=1800.0)
    show = sub.add_parser("show", help="print a stored investigation")
    show.add_argument("id")
    return parser


def main(argv: Sequence[str] | None = None, execute: Executor = subprocess_executor) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    data = Path(args.data).expanduser()
    if args.command == "show":
        record = load_record(data, args.id)
        if record is None:
            print(f"no investigation {args.id} in {data}", file=sys.stderr)
            return 1
        sys.stdout.write(render_text(record))
        return 0
    missing = [f for f in args.files if not f.is_file()]
    if missing:
        print(f"not a file: {', '.join(str(m) for m in missing)}", file=sys.stderr)
        return 2
    try:
        plc_ips = _plc_ips(args.plc_ip)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    record = run_investigation(
        args.files,
        data,
        plc_ips=plc_ips,
        execute=execute,
        timeout=args.timeout,
        on_progress=lambda msg: print(msg, file=sys.stderr),
    )
    sys.stdout.write(render_text(record))
    return 0
