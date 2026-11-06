# Ghost-Cloud

> Cloud security auditor - AWS, Azure and GCP misconfiguration scanner.

```
  GHOST-CLOUD  v1.0.0  |  Cloud Security Misconfiguration Scanner
  By Gh0st-Bx1         |  github.com/Ghost-Bx1
```

![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cloud%20Security-orange?style=flat-square)
![By Gh0st-Bx1](https://img.shields.io/badge/By-Gh0st--Bx1-black?style=flat-square&logo=github)

---

## Overview

Ghost-Cloud identifies misconfigurations across the three major cloud providers. It checks for publicly accessible storage buckets, exposed container registries, IMDS metadata endpoints, and leaked IaC files.

| Module      | Description                                                         |
|-------------|---------------------------------------------------------------------|
| `--aws`     | S3 public bucket enumeration, ECR public registry                   |
| `--azure`   | Blob container access, SAS token leaks, ACR public access          |
| `--gcp`     | GCS bucket enumeration, GCR registry, service account key files     |
| `--imds`    | IMDSv1/v2 metadata access and IAM role extraction                  |
| `--registry`| Container registry checks across providers                          |
| `--iac`     | IaC file exposure: .env, terraform.tfstate, .aws/credentials       |
| `--all`     | Run all modules                                                     |

---

## Requirements

```
Python 3.6+
No external dependencies (stdlib only)
```

---

## Installation

```bash
git clone https://github.com/Ghost-Bx1/ghost-cloud
cd ghost-cloud
python ghost-cloud.py --help
```

---

## Usage

```bash
# Run all checks against a domain
python ghost-cloud.py --target example.com --all

# AWS and IaC checks only
python ghost-cloud.py --target example.com --aws --iac

# Azure checks
python ghost-cloud.py --target example.com --azure

# GCP checks
python ghost-cloud.py --target example.com --gcp

# IMDS metadata endpoint check
python ghost-cloud.py --ip 169.254.169.254 --imds

# Check a specific S3/GCS bucket by name
python ghost-cloud.py --bucket my-bucket-name --aws

# Full scan with JSON output
python ghost-cloud.py --target example.com --all -o results.json
```

### Chaining with ghost-report

```bash
python ghost-cloud.py -t example.com --all -o cloud.json
python ghost-report.py --input cloud.json --output report.html
```

---

## Reference

| Flag                | Description                                      |
|---------------------|--------------------------------------------------|
| `--target / -t`     | Target domain                                    |
| `--bucket`          | Specific S3/GCS bucket name to check             |
| `--ip`              | IP address for IMDS check                        |
| `--aws`             | AWS checks (S3, ECR)                             |
| `--azure`           | Azure checks (Blob, ACR, SAS)                    |
| `--gcp`             | GCP checks (GCS, GCR, service account keys)      |
| `--imds`            | IMDS metadata endpoint check                     |
| `--registry`        | Container registry checks                        |
| `--iac`             | IaC file leak detection                          |
| `--all / -a`        | Run all modules                                  |
| `--output / -o`     | Save results as JSON                             |
| `--timeout`         | HTTP timeout in seconds (default: 10)            |
| `--no-ssl-verify`   | Disable SSL certificate verification             |

## Ghost Toolkit

| Tool | Description |
|------|-------------|
| [ghost-ad](https://github.com/Ghost-Bx1/ghost-ad) | Active Directory - LDAP, Kerberoasting, AS-REP Roasting, BloodHound-lite |
| [ghost-cloud](https://github.com/Ghost-Bx1/ghost-cloud) | Cloud Security - AWS, Azure and GCP misconfiguration scanner |
| [ghost-fuzz](https://github.com/Ghost-Bx1/ghost-fuzz) | Web Fuzzing - directory brute-force, parameter fuzzing, vhost enumeration |
| [ghost-osint](https://github.com/Ghost-Bx1/ghost-osint) | OSINT - domain, email and IP intelligence from public sources |
| [ghost-privesc](https://github.com/Ghost-Bx1/ghost-privesc) | Privilege Escalation - Linux privesc checker, 17 vectors, GTFOBins |
| [ghost-recon](https://github.com/Ghost-Bx1/ghost-recon) | Reconnaissance - DNS, SSL, WAF, subdomain enumeration, email security |
| [ghost-report](https://github.com/Ghost-Bx1/ghost-report) | Reporting - pentest report generator from any ghost-* JSON output |
| [ghost-scan](https://github.com/Ghost-Bx1/ghost-scan) | Port Scanner - async TCP/UDP scanner with banner grabbing and CVE correlation |
| [ghost-shell](https://github.com/Ghost-Bx1/ghost-shell) | Payload Generation - reverse shell and web shell generator, 25+ languages |
| [ghost-spray](https://github.com/Ghost-Bx1/ghost-spray) | Credential Attacks - password spraying, stuffing, default credential testing |
| [ghost-wifi](https://github.com/Ghost-Bx1/ghost-wifi) | WiFi Attacks - monitor mode, deauth, WPA/WPA2 capture, PMKID, WPS, Evil Twin |

---

## Disclaimer

For use in authorized environments only. Penetration testing, CTF competitions, and offensive security research with explicit permission from the environment owner. The author is not responsible for misuse.

---

**By [Gh0st-Bx1](https://github.com/Ghost-Bx1)**
