[README.md](https://github.com/user-attachments/files/29561548/README.md)
# Domain Lantern

Domain Lantern is a small passive OSINT CLI for checking public domain information.

It is designed to be friendly in Windows Command Prompt: the default `RUN.cmd` launcher uses clean ASCII output with no ANSI color codes, no broken `36m` sequences, and no unusual frame characters.

```text
 ____                        _          _             _
|  _ \  ___  _ __ ___   __ _(_)_ __    | | __ _ _ __ | |_ ___ _ __ _ __
| | | |/ _ \| '_ ` _ \ / _` | | '_ \   | |/ _` | '_ \| __/ _ \ '__| '_ \
| |_| | (_) | | | | | | (_| | | | | |  | | (_| | | | | ||  __/ |  | | | |
|____/ \___/|_| |_| |_|\__,_|_|_| |_|  |_|\__,_|_| |_|\__\___|_|  |_| |_|
```

## Features

- DNS records: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`, `SOA`
- WHOIS summary
- Public subdomains from certificate transparency via `crt.sh`
- `/.well-known/security.txt`
- `/robots.txt`
- Interactive menu
- JSON report export
- Plain ASCII mode for Windows CMD

Domain Lantern does not perform port scanning, directory brute forcing, password guessing, vulnerability exploitation, or aggressive traffic generation.

## Quick Start on Windows CMD

Open Command Prompt in the project folder:

```cmd
cd C:\path\to\domain-lantern
```

Install once:

```cmd
install.cmd
```

Start:

```cmd
RUN.cmd
```

You can also double-click `RUN.cmd` in Explorer.

## Menu

```text
1 - DNS records
2 - WHOIS
3 - Public subdomains via crt.sh
4 - Check security.txt
5 - Check robots.txt
6 - Run full passive report
7 - Save last report to JSON
8 - Change target domain
0 - Exit
```

## Command-Line Usage

After running `install.cmd`, you can use the installed command:

```cmd
.venv\Scripts\domain-lantern.exe example.com --plain
```

Run only one check:

```cmd
.venv\Scripts\domain-lantern.exe example.com --check dns --plain
.venv\Scripts\domain-lantern.exe example.com --check whois --plain
.venv\Scripts\domain-lantern.exe example.com --check subdomains --plain
```

Save a JSON report:

```cmd
.venv\Scripts\domain-lantern.exe example.com --output reports\example.json --plain
```

Fancy terminal mode:

```cmd
.venv\Scripts\domain-lantern.exe --interactive
```

## Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
domain-lantern --interactive
```

## Repository Layout

```text
domain-lantern/
  src/domain_lantern/       Python package
  tests/                    Offline unit tests
  .github/workflows/        GitHub Actions CI
  RUN.cmd                   Easy Windows CMD launcher
  install.cmd               Easy Windows installer
  pyproject.toml            Package metadata
  CHANGELOG.md              Public change history
  SECURITY.md               Security and responsible-use notes
```

## Development

Install in editable mode:

```bash
python -m pip install -e .
```

Run tests:

```bash
python -m unittest discover -s tests
```

Run from source:

```bash
python -m domain_lantern example.com --check dns --plain
```

## Responsible Use

Use Domain Lantern only for domains you own, administer, or have permission to assess. The tool is for passive discovery and basic inventory, not offensive scanning.
