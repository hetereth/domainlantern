#!/usr/bin/env python3
"""
Domain Lantern - passive OSINT helper for domain checks.

The tool uses only passive/public sources:
- DNS lookups
- WHOIS
- certificate transparency data from crt.sh
- security.txt
- robots.txt
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import dns.resolver
import requests
import whois
from domain_lantern import __version__
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text


APP_NAME = "Domain Lantern"
VERSION = __version__
DEFAULT_TIMEOUT = 5
DEFAULT_SUBDOMAIN_LIMIT = 80
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")
USER_AGENT = f"DomainLantern/{VERSION} passive-osint"

LOGO = r"""
 ____                        _          _             _
|  _ \  ___  _ __ ___   __ _(_)_ __    | | __ _ _ __ | |_ ___ _ __ _ __
| | | |/ _ \| '_ ` _ \ / _` | | '_ \   | |/ _` | '_ \| __/ _ \ '__| '_ \
| |_| | (_) | | | | | | (_| | | | | |  | | (_| | | | | ||  __/ |  | | | |
|____/ \___/|_| |_| |_|\__,_|_|_| |_|  |_|\__,_|_| |_|\__\___|_|  |_| |_|
"""

CHECK_LABELS = {
    "dns": "DNS records",
    "whois": "WHOIS",
    "subdomains": "Public subdomains",
    "security": "security.txt",
    "robots": "robots.txt",
}

def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


configure_stdio()
console = Console(legacy_windows=False, safe_box=True)
PLAIN_MODE = False


@dataclass
class Finding:
    key: str
    title: str
    status: str
    data: Any = field(default_factory=dict)
    error: str | None = None


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.netloc or parsed.path
    candidate = candidate.split("/")[0].split(":")[0].strip(".")

    if (
        not candidate
        or "." not in candidate
        or len(candidate) > 253
        or not re.fullmatch(r"[a-z0-9.-]+", candidate)
        or any(part.startswith("-") or part.endswith("-") or not part for part in candidate.split("."))
    ):
        raise ValueError("Enter a valid domain, for example example.com")

    return candidate


def json_safe(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(json_safe(item) for item in value)
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    return value


def whois_get(data: Any, key: str) -> Any:
    if hasattr(data, "get"):
        return data.get(key)
    return getattr(data, key, None)


def check_dns(domain: str, timeout: int, subdomain_limit: int = DEFAULT_SUBDOMAIN_LIMIT) -> Finding:
    records: dict[str, list[str]] = {}
    lookup_errors: dict[str, str] = {}

    def resolve_one(record_type: str) -> tuple[str, list[str], str | None]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = min(timeout, 2)
        try:
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            values = sorted({answer.to_text() for answer in answers if answer})
            return record_type, values, None
        except Exception as exc:
            return record_type, [], exc.__class__.__name__

    with ThreadPoolExecutor(max_workers=len(DNS_TYPES)) as executor:
        futures = [executor.submit(resolve_one, record_type) for record_type in DNS_TYPES]
        for future in as_completed(futures):
            record_type, values, error = future.result()
            if values:
                records[record_type] = values
            if error:
                lookup_errors[record_type] = error

    status = "ok" if records else "empty"
    return Finding("dns", CHECK_LABELS["dns"], status, {"records": records, "lookup_errors": lookup_errors})


def check_whois(domain: str, timeout: int, subdomain_limit: int = DEFAULT_SUBDOMAIN_LIMIT) -> Finding:
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        data = whois.whois(domain)
        fields = (
            "domain_name",
            "registrar",
            "creation_date",
            "expiration_date",
            "updated_date",
            "name_servers",
            "status",
            "emails",
            "country",
        )
        compact = {field_name: json_safe(whois_get(data, field_name)) for field_name in fields}
        compact = {key: value for key, value in compact.items() if value}
        return Finding("whois", CHECK_LABELS["whois"], "ok" if compact else "empty", compact)
    except Exception as exc:
        return Finding("whois", CHECK_LABELS["whois"], "error", error=str(exc))
    finally:
        socket.setdefaulttimeout(original_timeout)


def check_subdomains(domain: str, timeout: int, subdomain_limit: int = DEFAULT_SUBDOMAIN_LIMIT) -> Finding:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        rows = response.json()
        if not isinstance(rows, list):
            raise ValueError("crt.sh returned an unexpected response format")

        names: set[str] = set()
        for row in rows:
            raw_name = str(row.get("name_value", ""))
            for name in raw_name.splitlines():
                normalized = name.lower().strip().strip(".").replace("*.", "")
                if normalized == domain or normalized.endswith("." + domain):
                    names.add(normalized)

        shown = sorted(names)[:subdomain_limit]
        return Finding(
            "subdomains",
            CHECK_LABELS["subdomains"],
            "ok" if shown else "empty",
            {"source": "crt.sh certificate transparency", "count": len(names), "shown": shown},
        )
    except Exception as exc:
        return Finding(
            "subdomains",
            CHECK_LABELS["subdomains"],
            "error",
            {"source": "crt.sh certificate transparency"},
            str(exc),
        )


def fetch_text_file(key: str, title: str, domain: str, path: str, timeout: int) -> Finding:
    attempts: list[dict[str, Any]] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}{path}"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
            )
            attempts.append({"url": url, "status_code": response.status_code})
            if response.status_code == 200 and response.text.strip():
                return Finding(
                    key,
                    title,
                    "ok",
                    {
                        "url": response.url,
                        "status_code": response.status_code,
                        "preview": response.text.strip()[:3000],
                    },
                )
        except Exception as exc:
            attempts.append({"url": url, "error": str(exc)})

    return Finding(key, title, "empty", {"attempts": attempts})


def check_security_txt(domain: str, timeout: int, subdomain_limit: int = DEFAULT_SUBDOMAIN_LIMIT) -> Finding:
    return fetch_text_file("security", CHECK_LABELS["security"], domain, "/.well-known/security.txt", timeout)


def check_robots_txt(domain: str, timeout: int, subdomain_limit: int = DEFAULT_SUBDOMAIN_LIMIT) -> Finding:
    return fetch_text_file("robots", CHECK_LABELS["robots"], domain, "/robots.txt", timeout)


CHECKS: dict[str, Callable[[str, int, int], Finding]] = {
    "dns": check_dns,
    "whois": check_whois,
    "subdomains": check_subdomains,
    "security": check_security_txt,
    "robots": check_robots_txt,
}


def make_report(domain: str, findings: list[Finding]) -> dict[str, Any]:
    return {
        "tool": APP_NAME,
        "version": VERSION,
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "passive",
        "findings": [asdict(finding) for finding in findings],
    }


def run_selected_checks(domain: str, selected: list[str], timeout: int, subdomain_limit: int) -> dict[str, Any]:
    findings: list[Finding] = []
    for key in selected:
        print_status(f">>> {CHECK_LABELS[key]} ... ", end="")
        finding = CHECKS[key](domain, timeout, subdomain_limit)
        findings.append(finding)
        if PLAIN_MODE:
            print(finding.status.upper())
        else:
            color = {"ok": "green", "empty": "yellow", "error": "red"}.get(finding.status, "white")
            console.print(f"[{color}]{finding.status.upper()}[/{color}]")
    return make_report(domain, findings)


def print_status(message: str, end: str = "\n") -> None:
    if PLAIN_MODE:
        print(message, end=end)
    else:
        console.print(message, end=end)


def render_header(domain: str | None = None) -> None:
    if PLAIN_MODE:
        print()
        print("=" * 78)
        print(LOGO.strip("\n"))
        print("=" * 78)
        if domain:
            print(f"Target: {domain}")
        print("Passive domain OSINT. No port scanning. No brute force.")
        print("=" * 78)
        return

    console.clear()
    subtitle = "Passive domain OSINT. No port scanning. No brute force."
    if domain:
        subtitle = f"Target: {domain} | " + subtitle
    console.print(Panel(Align.center(f"[bold cyan]{LOGO}[/bold cyan]\n[white]{subtitle}[/white]"), border_style="cyan", box=box.DOUBLE))


def render_dns(data: dict[str, Any]) -> None:
    if PLAIN_MODE:
        print("\n[DNS records]")
        records = data.get("records") or {}
        if not records:
            print("No DNS records found.")
            return
        for record_type, values in records.items():
            print(f"\n{record_type}:")
            for value in values:
                print(f"  - {value}")
        return

    table = Table(title="DNS records", box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Values", overflow="fold")

    records = data.get("records") or {}
    if not records:
        table.add_row("-", "No DNS records found.")
    for record_type, values in records.items():
        table.add_row(record_type, "\n".join(values))
    console.print(table)


def render_key_values(title: str, data: dict[str, Any]) -> None:
    if PLAIN_MODE:
        print(f"\n[{title}]")
        if not data:
            print("No data.")
            return
        for key, value in data.items():
            if isinstance(value, list):
                print(f"{key}:")
                for item in value:
                    print(f"  - {item}")
            else:
                print(f"{key}: {value}")
        return

    table = Table(title=title, box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", overflow="fold")

    if not data:
        table.add_row("-", "No data.")
    for key, value in data.items():
        if isinstance(value, list):
            value = "\n".join(str(item) for item in value)
        table.add_row(str(key), str(value))
    console.print(table)


def render_text_file(title: str, finding: dict[str, Any]) -> None:
    if PLAIN_MODE:
        data = finding.get("data") or {}
        print(f"\n[{title}]")
        if finding["status"] == "ok":
            print(data.get("url", ""))
            print()
            print(data.get("preview", ""))
        else:
            print("File was not found or is empty.")
        return

    data = finding.get("data") or {}
    if finding["status"] == "ok":
        body = Text()
        body.append(f"{data.get('url')}\n\n", style="green")
        body.append(data.get("preview", ""))
        console.print(Panel(body, title=title, border_style="green"))
    else:
        console.print(Panel("File was not found or is empty.", title=title, border_style="yellow"))


def render_report(report: dict[str, Any]) -> None:
    if PLAIN_MODE:
        print()
        print("-" * 78)
        print(f"{APP_NAME} report")
        print(f"Target: {report['domain']}")
        print("Mode: passive")
        print("-" * 78)
    else:
        console.print()
        console.print(
            Panel.fit(
                f"[bold white]{APP_NAME}[/bold white]\n[cyan]{report['domain']}[/cyan]\n[dim]passive report[/dim]",
                border_style="cyan",
                box=box.DOUBLE,
            )
        )

    for finding in report["findings"]:
        if finding["status"] == "error":
            if PLAIN_MODE:
                print(f"\n[{finding['title']}] ERROR")
                print(finding.get("error") or "Unknown error")
            else:
                console.print(Panel(finding.get("error") or "Unknown error", title=finding["title"], border_style="red"))
            continue

        key = finding["key"]
        data = finding.get("data") or {}
        if key == "dns":
            render_dns(data)
        elif key == "whois":
            render_key_values("WHOIS", data)
        elif key == "subdomains":
            render_key_values(
                "Public subdomains",
                {
                    "Source": data.get("source"),
                    "Total found": data.get("count", 0),
                    "Shown": data.get("shown", []),
                },
            )
        elif key in ("security", "robots"):
            render_text_file(finding["title"], finding)


def save_report(report: dict[str, Any], output_path: str | None = None) -> Path:
    if output_path:
        path = Path(output_path)
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = Path("reports") / f"{report['domain']}-{stamp}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def ask_domain() -> str:
    while True:
        raw = input("Enter domain or URL: ") if PLAIN_MODE else Prompt.ask("[bold cyan]Enter domain or URL[/bold cyan]")
        try:
            return normalize_domain(raw)
        except ValueError as exc:
            if PLAIN_MODE:
                print(f"Error: {exc}")
            else:
                console.print(f"[red]{exc}[/red]")


def render_menu(domain: str) -> None:
    if PLAIN_MODE:
        print()
        print(f"Menu for {domain}")
        print("-" * 40)
        print("1 - DNS records")
        print("2 - WHOIS")
        print("3 - Public subdomains via crt.sh")
        print("4 - Check security.txt")
        print("5 - Check robots.txt")
        print("6 - Run full passive report")
        print("7 - Save last report to JSON")
        print("8 - Change target domain")
        print("0 - Exit")
        print("-" * 40)
        return

    table = Table(title=f"Menu for {domain}", box=box.ROUNDED)
    table.add_column("#", style="cyan", justify="right", no_wrap=True)
    table.add_column("Action", style="white")
    table.add_row("1", "DNS records")
    table.add_row("2", "WHOIS")
    table.add_row("3", "Find public subdomains via crt.sh")
    table.add_row("4", "Check security.txt")
    table.add_row("5", "Check robots.txt")
    table.add_row("6", "Run full passive report")
    table.add_row("7", "Save last report to JSON")
    table.add_row("8", "Change target domain")
    table.add_row("0", "Exit")
    console.print(table)


def wait_for_enter() -> None:
    print()
    if PLAIN_MODE:
        input("Press Enter to return to menu...")
    else:
        Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")


def interactive_mode(timeout: int, subdomain_limit: int) -> int:
    domain = ask_domain()
    last_report: dict[str, Any] | None = None

    while True:
        render_header(domain)
        render_menu(domain)
        if PLAIN_MODE:
            raw_choice = input("Choose action [0-8]: ").strip()
            if raw_choice not in [str(item) for item in range(0, 9)]:
                print("Choose a number from 0 to 8.")
                wait_for_enter()
                continue
            choice = int(raw_choice)
        else:
            choice = IntPrompt.ask("[bold cyan]Choose action[/bold cyan]", choices=[str(item) for item in range(0, 9)])

        if choice == 0:
            print("Done. Bye!") if PLAIN_MODE else console.print("[green]Done. Bye![/green]")
            return 0
        if choice == 8:
            domain = ask_domain()
            continue
        if choice == 7:
            if not last_report:
                print("Run any check first.") if PLAIN_MODE else console.print("[yellow]Run any check first.[/yellow]")
            else:
                saved_to = save_report(last_report)
                print(f"Report saved: {saved_to}") if PLAIN_MODE else console.print(f"[green]Report saved:[/green] {saved_to}")
            wait_for_enter()
            continue

        selected_map = {
            1: ["dns"],
            2: ["whois"],
            3: ["subdomains"],
            4: ["security"],
            5: ["robots"],
            6: ["dns", "whois", "subdomains", "security", "robots"],
        }
        selected = selected_map[choice]
        console.print()
        last_report = run_selected_checks(domain, selected, timeout, subdomain_limit)
        render_report(last_report)
        save_answer = input("\nSave this report to JSON? [y/N]: ").strip().lower() if PLAIN_MODE else None
        should_save = save_answer in ("y", "yes") if PLAIN_MODE else Confirm.ask("\nSave this report to JSON?", default=False)
        if should_save:
            saved_to = save_report(last_report)
            print(f"Report saved: {saved_to}") if PLAIN_MODE else console.print(f"[green]Report saved:[/green] {saved_to}")
        wait_for_enter()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"{APP_NAME}: passive domain OSINT CLI.")
    parser.add_argument("domain", nargs="?", help="Domain or URL, for example example.com")
    parser.add_argument(
        "-c",
        "--check",
        choices=("all", "dns", "whois", "subdomains", "security", "robots"),
        default="all",
        help="Run one check without opening the menu.",
    )
    parser.add_argument("-i", "--interactive", action="store_true", help="Open interactive menu.")
    parser.add_argument("-o", "--output", help="Save JSON report to this path.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds.")
    parser.add_argument("--subdomain-limit", type=int, default=DEFAULT_SUBDOMAIN_LIMIT, help="Subdomains to display.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("--plain", action="store_true", help="Use simple ASCII output for Windows Command Prompt.")
    return parser


def main() -> int:
    global PLAIN_MODE
    parser = build_parser()
    args = parser.parse_args()

    PLAIN_MODE = args.plain

    if args.no_color or args.plain:
        console.no_color = True

    timeout = max(1, args.timeout)
    subdomain_limit = max(1, args.subdomain_limit)

    if args.interactive or not args.domain:
        render_header()
        return interactive_mode(timeout, subdomain_limit)

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"Error: {exc}") if PLAIN_MODE else console.print(f"[red]Error:[/red] {exc}")
        return 2

    selected = list(CHECKS) if args.check == "all" else [args.check]
    render_header(domain)
    report = run_selected_checks(domain, selected, timeout, subdomain_limit)
    render_report(report)

    if args.output:
        saved_to = save_report(report, args.output)
        print(f"\nJSON report saved: {saved_to}") if PLAIN_MODE else console.print(f"\n[green]JSON report saved:[/green] {saved_to}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
