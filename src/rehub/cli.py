import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from rehub.api import Config, access_url, print_doctor, serve
from rehub.auth import load_or_create_token
from rehub.doctor import run_doctor
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
    doctor = sub.add_parser("doctor", help="check that the tools and the data folder work")
    doctor.add_argument("--quick", action="store_true", help="skip the sample-capture self test")
    token = sub.add_parser("token", help="print the sign-in link for the web UI")
    token.add_argument(
        "--rotate", action="store_true", help="replace the token (signs everyone out)"
    )
    serve = sub.add_parser("serve", help="run the local web UI and API")
    serve.add_argument("--no-auth", action="store_true", help="disable sign-in (not recommended)")
    serve.add_argument(
        "--host", default=None, help="bind address (default $REHUB_HOST or 127.0.0.1)"
    )
    serve.add_argument("--port", type=int, default=None, help="port (default $REHUB_PORT or 8080)")
    return parser


def main(argv: Sequence[str] | None = None, execute: Executor = subprocess_executor) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    data = Path(args.data).expanduser()
    if args.command == "doctor":
        report = run_doctor(data, execute, auth_enabled=True, quick=args.quick)
        print_doctor(report)
        return 1 if report.status == "fail" else 0
    if args.command == "token":
        config = Config.from_env(data)
        config.token = load_or_create_token(data, rotate=args.rotate)
        print(access_url(config))
        return 0
    if args.command == "serve":
        config = Config.from_env(data)
        if args.no_auth:
            config.token = ""
        if args.host:
            config.host = args.host
        if args.port is not None:
            config.port = args.port
        data.mkdir(parents=True, exist_ok=True)
        serve(config, execute)
        return 0
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
