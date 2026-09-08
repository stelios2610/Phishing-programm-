import json
import sys
from pathlib import Path

# Allow running from the MSI runtime folder.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phishguard.engine import analyze


def _esc(value: str) -> str:
    return (value or "").replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "").replace("\t", " ")


def main() -> int:
    url = sys.stdin.read()
    result = analyze(url, probe=True)
    out = sys.stdout
    out.write("__PG__\n")
    out.write(f"verdict={_esc(result.verdict)}\n")
    out.write(f"verdict_el={_esc(result.verdict_el)}\n")
    out.write(f"score={result.risk_percent}\n")
    out.write(f"normalized={_esc(result.normalized)}\n")
    out.write(f"host={_esc(result.host_unicode or result.host)}\n")
    out.write(f"official={_esc(result.official_brand or '')}\n")
    out.write(f"impersonated={_esc(result.impersonated_brand or '')}\n")
    for finding in result.findings:
        out.write(
            "finding\t"
            + "\t".join(
                [
                    _esc(finding.severity),
                    _esc(finding.title),
                    _esc(finding.title_el),
                    _esc(finding.detail),
                    _esc(finding.detail_el),
                ]
            )
            + "\n"
        )
    out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
