"""Command-line interface: phishguard URL [URL ...]"""

from __future__ import annotations

import argparse
import json
import sys

from phishguard.engine import analyze


def _print_human(result) -> None:
    bar = "=" * 64
    print(bar)
    print(f"URL:      {result.url}")
    if result.normalized:
        print(f"Normalized: {result.normalized}")
    print(f"Verdict:  {result.verdict} / {result.verdict_el}")
    print(f"Risk:     {result.risk_percent}/100")
    if result.official_brand:
        print(f"Official: {result.official_brand}")
    if result.impersonated_brand:
        print(f"Looks like: {result.impersonated_brand}")
    print()
    if not result.findings:
        print("No findings.")
        return
    for f in result.findings:
        print(f"[{f.severity.upper():8}] {f.title}")
        print(f"           {f.detail}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="Detect phishing URLs. Reads page HTML (no login, no JavaScript) unless --no-probe.",
    )
    parser.add_argument("urls", nargs="*", help="URL(s) to analyze")
    parser.add_argument("-j", "--json", action="store_true", help="JSON output")
    parser.add_argument("-f", "--file", help="File with one URL per line")
    parser.add_argument("--serve", action="store_true", help="Start the web UI")
    parser.add_argument("--desktop", action="store_true", help="Open the desktop window")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-probe", action="store_true", help="Do not fetch page HTML")
    args = parser.parse_args(argv)

    if args.desktop:
        from phishguard.desktop import main as desktop_main

        return desktop_main()

    if args.serve:
        import uvicorn

        from phishguard.api import app

        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))

    if not urls:
        parser.print_help()
        return 2

    results = [analyze(u, probe=not args.no_probe) for u in urls]
    if args.json:
        if len(results) == 1:
            print(json.dumps(results[0].to_dict(), ensure_ascii=False, indent=2))
        else:
            print(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2))
    else:
        for r in results:
            _print_human(r)

    worst = max(results, key=lambda r: r.score)
    if worst.verdict in {"phishing", "dangerous"}:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
