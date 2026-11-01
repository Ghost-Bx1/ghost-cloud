#!/usr/bin/env python3
"""
Ghost-Cloud v1.0.0 - Cloud Security Assessment Framework
=========================================================
Verifica misconfigurações em ambientes AWS, Azure e GCP.
Detecta buckets/blobs publicos, IAM expostos, metadata IMDS,
credenciais vazadas, registries expostos e leaks de IaC.

Modulos:
  --aws            Checks AWS: S3, IAM, Lambda, EC2, ECR
  --azure          Checks Azure: Blob, AD Apps, SAS tokens, ACR
  --gcp            Checks GCP: GCS, Service Accounts, GCR
  --imds           IMDS metadata exploitation check (v1 vs v2)
  --registry       Container registry exposure (ECR/GCR/DockerHub)
  --iac            Terraform state / CloudFormation template leaks
  --all            Executa todos os modulos

Exemplos:
  python ghost-cloud.py --target exemplo.com --aws
  python ghost-cloud.py --target exemplo.com --azure --gcp
  python ghost-cloud.py --target exemplo.com --all
  python ghost-cloud.py --bucket meu-bucket --aws
  python ghost-cloud.py --target 10.0.0.1 --imds
  python ghost-cloud.py --target exemplo.com --all --output resultado.json

Autor: By Gh0st-Bx1 | github.com/Ghost-Bx1
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

VERSAO = "1.0.0"


def _build_banner():
    import re as _re
    G = "\033[92m"; Cy = "\033[96m"; D = "\033[2m"; N = "\033[1m"
    W = "\033[97m"; X = "\033[0m"
    IW = 68; eq = "═" * IW; sp = " " * IW
    TL = "╔"; TR = "╗"; BL = "╚"; BR = "╝"; VB = "║"
    hl = "─" * 44; bar = "│"
    vl = lambda s: len(_re.sub(r"\x1b\[[0-9;]*m", "", s))

    def _row(s):
        n = vl(s); p = max(0, IW - n); l = p // 2; r = p - l
        return f"{G}{VB}{X}{' ' * l}{s}{' ' * r}{G}{VB}{X}"

    def _row_l(s):
        n = vl(s); p = max(0, IW - n - 2)
        return f"{G}{VB}{X}  {s}{' ' * p}{G}{VB}{X}"

    ga = [
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠛⠿⠟⠉⠛⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⢀⣠⣤⣶⣶⣶⣶⣶⣶⣤⣀⠢⢝⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⡡⢀⣴⡿⢋⡴⢿⣿⣿⣿⣿⣿⣿⣿⢷⣦⡑⠈⡛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⡜⢠⣾⣿⣤⣋⣴⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⠻⣶⣦⣤⣤⣀⠉⠻⣿⣿⣿⡿⠿⢛⢛⡻⠿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⠿⠟⠟⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⢀⣿⣿⣿⡿⠛⠛⠻⣿⣿⣿⡿⠛⠛⢿⣿⣿⣧⠉⠉⣁⣈⣉⣁⢀⣿⣿⢋⠄⣁⣴⣶⣄⠐⢌⢻⣿⣿{X}", ""),
        ("", f"{G}⡏⠀⣴⣦⣄⠢⡙⢿⣿⣿⣿⣿⣿⣿⡇⠀⣼⣿⣿⣿⠅⠀⠀  ⢹⣿⡿⠁⠀⠀⠀⢹⣿⣿⡆⠀⣿⣿⣿⣿⣿⡟⠁⢀⣴⣿⣿⣿⣿⣷⡈⠎⢿⣿{X}", ""),
        ("", f"{G}⡇⠀⣿⣿⣿⣷⣌⠀⠙⢿⣿⣿⣿⣿⠀⢀⣿⣿⣿⣿⠀⠀⠀  ⠀⠈⣿⡇⠀⠀⠀⠀⠈⢿⣿⡇⠁⢻⣿⣿⣿⡿⠁⢠⣾⣿⣿⣿⡿⢿⣿⣷⠀⠘⣿{X}", ""),
        ("", f"{G}⣇⠀⢿⣿⣿⡟⣿⣷⣄⠀⠙⢿⣿⡇⠀⣸⣿⣿⡿⣿⡀⠀⠀⠀  ⢸⣿⣧⠀⠀⠀⠀⣸⡈⣿⣷⠀⡈⣿⣿⡿⠁⢀⣾⣿⣿⢩⣿⠁⣾⣿⣿⡆⠀⢿{X}", ""),
        ("", f"{G}⣿⡀⠘⣿⣿⣿⡘⣿⣿⣷⣌⠂⠉⠁⢠⣿⣿⡟⣰⢿⣷⣤⣤⣴⣿⣿⣿⣷⣄⣠⣴⣿⣧⠸⣿⣧⡐⠢⠉⠁⢀⣾⣿⣿⡇⣼⣿⢸⣿⣿⣿⣇⠀⢸{X}", ""),
        ("", f"{G}⣿⣷⡀⠸⣿⣿⣧⠸⣿⣿⣿⣿⣶⣶⣿⣿⠏⡰⢃⣾⣿⣿⣿⣿⡏⠀⠈⣿⣿⣿⣿⣿⣏⠳⣘⣿⣿⣷⣶⣾⣿⣿⣿⣿⢠⣿⣿⣿⣿⣿⣿⣿⠀⢸{X}", ""),
        ("", f"{G}⣿⣿⡇⠀⣿⣿⣿⡄⡿⢿⣿⣿⣿⣿⣿⣷⣾⣷⣿⣿⣿⣿⣿⣿⣧⣀⣠⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠸⠋⢉⠉⡉⠛⠿⣿⠀⢸{X}", ""),
        ("", f"{G}⣿⣿⡇⢀⣿⣿⣿⣧⢸⡘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⢠⣾⣿⡄⠈⠀⠀⠀⠀ ⣾{X}", ""),
        ("", f"{G}⣿⡟⠀⣸⣿⣿⣿⣿⣜⡇⢿⣧⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡉⠻⠇⠀⠰⠀⠀ ⣀⣾{X}", ""),
        ("", f"{G}⣿⠃⢠⣿⣿⠿⠿⠿⢿⣿⠸⣿⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⢣⢸⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⢰⠜⠋⠀⢀⡄⢰⣤⡀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠃⢻⣿⣿{X}", ""),
        ("", f"{G}⣿⣆⠠⠀⡀⠀⠁⣿⣿⠟⠀⣽⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢻⣿⣿⣿⣿⣿⢃⣿⣿⣿⡟⣸⣿⣿⣿⣿⡿⠋⢠⢃⣾⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣷⣶⠆⡄⠈⢉⣠⣴⣾⣿⢿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢋⣴⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⠇⠛⢏⠉⠉⠁⠤⢊⣥⣾⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⢄⠀⢾⣿⣿⣿⣿⡇⢸⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣶⣬⣭⣶⣾⣿⣿⠏⣼⣿⣿⣿⡇⣸⣿⣿⣿⠀⣰⣿⡁⢠⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣤⣀⡀⠀⠀⠉⠉⠁⢸⣿⣿⣿⢸⣿⣿⣿⣿⡹⣿⣿⣿⣿⣿⣿⣿⣿⠋⣼⣿⣿⣿⣿⠇⣿⣿⣿⣿⡀⠹⢿⡇⠀⢿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠛⠀⣼⣿⣿⣿⢸⣿⣿⢻⣿⣷⣌⠻⣿⣿⣿⣿⠟⣡⣾⣿⡟⣼⣿⣿⠀⣿⣿⣿⣿⣿⣶⣤⡀⠀⢸⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⠈⠀⣴⣾⣿⣿⣿⡇⢸⣿⣿⣇⢻⣿⣿⣷⣦⣭⣭⣴⣾⣿⣿⣿⢡⣿⣿⣿⠀⣿⣿⣿⣿⣿⠿⠟⠃⡀⢸⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⡐⠠⢈⡉⠛⠛⠿⡇⢸⣿⣿⣿⡜⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣼⣿⣿⣿⠀⣁⣤⡄⠀⣀⣒⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⡌⠀⣦⠀⣼⣿⣿⣿⣇⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⣿⣿⣿⣿⣄⡈⠛⠃⠐⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⢁⣤⣿⣿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣿⣿⣿⡟⢸⣿⣿⣿⣿⣿⣿⣦⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠠⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇⢼⠿⠿⣿⣿⣿⣿⠟⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠈⣙⠛⠛⣛⣛⠛⠀⠻⢿⣿⣿⣿⣿⣿⣿⡃⢠⣤⠀⠀⣀⣉⣁⣀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣶⣶⣤⡀⢀⠈⢿⣿⣿⣿⣿⣷⣄⠁⠀⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠁⠈⣿⣿⣿⣿⣿⣿⡆⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠠⢠⣿⣿⣿⣿⣿⠟⢀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡗⠀⢸⣿⣿⣿⡿⢁⡄⣡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠰⠘⣿⣿⣿⠁⠎⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡑⠈⠻⠇⠈⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
    ]

    info = [
        f"{G}{N}GHOST-CLOUD{X}",
        f"{Cy}v{VERSAO}  {D}Cloud Security Assessment Framework{X}",
        f"{D}{hl}{X}",
        f"{W}By Gh0st-Bx1  {D}{bar}  github.com/Ghost-Bx1{X}",
        f"{D}{hl}{X}",
        f"{D}--aws  --azure  --gcp  --imds  --registry  --iac{X}",
        f"{D}AWS / Azure / GCP misconfiguration checks{X}",
    ]

    out = [f"{G}{TL}{eq}{TR}{X}", f"{G}{VB}{sp}{VB}{X}"]
    for left, center, right in ga:
        combined = left + center + right
        out.append(_row(combined))
    out.append(f"{G}{VB}{sp}{VB}{X}")
    for i in info:
        out.append(_row_l(i))
    out += [f"{G}{VB}{sp}{VB}{X}", f"{G}{BL}{eq}{BR}{X}"]
    return "\n".join(out)


BANNER = _build_banner()

C = {
    "R": "\033[91m", "G": "\033[92m", "Y": "\033[93m",
    "B": "\033[94m", "M": "\033[95m", "C": "\033[96m",
    "W": "\033[97m", "X": "\033[0m",  "N": "\033[1m", "D": "\033[2m",
}

TIMEOUT = 10

# ─── HTTP helper ──────────────────────────────────────────────────────────────

def _get(url, headers=None, timeout=TIMEOUT, verify=True):
    """Requisicao GET simples, retorna (status, headers_dict, body_str)."""
    try:
        if REQUESTS_OK:
            r = requests.get(url, headers=headers, timeout=timeout,
                             verify=verify, allow_redirects=True)
            return r.status_code, dict(r.headers), r.text
        req = urllib.request.Request(url, headers=headers or {})
        ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, {}, str(e)


def _log(tag, msg, color="G"):
    ts = datetime.now().strftime("%H:%M:%S")
    c = C.get(color, C["G"])
    print(f"  {C['D']}[{ts}]{C['X']} {c}[{tag}]{C['X']} {msg}")


# ─── AWS checks ───────────────────────────────────────────────────────────────

S3_REGIONS = ["s3", "s3.us-east-1", "s3.us-east-2", "s3.us-west-1",
               "s3.us-west-2", "s3.eu-west-1", "s3.ap-southeast-1"]


def check_s3_bucket(bucket_name: str) -> dict:
    """Verifica se um bucket S3 e publicamente acessivel."""
    result = {"bucket": bucket_name, "public": False, "listable": False,
              "url": None, "files": []}

    for region in S3_REGIONS:
        url = f"https://{bucket_name}.{region}.amazonaws.com/"
        status, hdrs, body = _get(url)
        if status in (200, 403):
            result["url"] = url
            if status == 200:
                result["public"] = True
                result["listable"] = "<ListBucketResult" in body or "<Key>" in body
                if result["listable"]:
                    keys = re.findall(r"<Key>([^<]+)</Key>", body)
                    result["files"] = keys[:20]
            else:
                result["public"] = False
                result["note"] = "Bucket existe mas access denied (403)"
            break

    return result


def enum_s3_buckets(domain: str) -> list:
    """Gera variantes de nomes de bucket a partir do dominio e testa."""
    base = domain.replace(".", "-").replace("_", "-")
    candidates = [
        base, f"{base}-backup", f"{base}-backups", f"{base}-data",
        f"{base}-static", f"{base}-assets", f"{base}-media", f"{base}-dev",
        f"{base}-staging", f"{base}-prod", f"{base}-logs", f"{base}-uploads",
        f"{base}-files", f"backup-{base}", f"static-{base}", f"assets-{base}",
        f"dev-{base}", f"staging-{base}",
    ]
    findings = []
    _log("S3", f"Testando {len(candidates)} variantes de bucket para {domain}", "C")
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(check_s3_bucket, b): b for b in candidates}
        for fut in as_completed(futs):
            r = fut.result()
            if r.get("url"):
                findings.append(r)
                icon = C["R"] + "[PUBLICO]" + C["X"] if r["public"] else C["Y"] + "[EXISTS]" + C["X"]
                _log("S3", f"{icon} {r['url']}", "G")
                if r.get("files"):
                    _log("S3", f"  Arquivos: {', '.join(r['files'][:5])}", "Y")
    return findings


def check_cloudformation_leaks(domain: str) -> list:
    """Procura templates CloudFormation / Terraform state vazados em S3."""
    suspects = [
        f"https://{domain.replace('.', '-')}-terraform-state.s3.amazonaws.com/terraform.tfstate",
        f"https://{domain.replace('.', '-')}.s3.amazonaws.com/terraform.tfstate",
        f"https://{domain.replace('.', '-')}-cf-templates.s3.amazonaws.com/",
    ]
    findings = []
    for url in suspects:
        status, _, body = _get(url)
        if status == 200:
            findings.append({"url": url, "type": "terraform_state" if "tfstate" in url else "cf_template"})
            _log("IAC", f"[VAZADO] {url}", "R")
    return findings


def check_aws_metadata(ip: str = "169.254.169.254") -> dict:
    """Verifica acesso ao IMDS AWS (IMDSv1 sem token)."""
    result = {"reachable": False, "imdsv1": False, "imdsv2": False,
              "role": None, "keys": None}
    url_v1 = f"http://{ip}/latest/meta-data/"
    status, _, body = _get(url_v1, timeout=3)
    if status == 200:
        result["reachable"] = True
        result["imdsv1"] = True
        _log("IMDS", f"IMDSv1 ACESSIVEL em {ip} - CRITICO", "R")
        role_status, _, role_body = _get(f"http://{ip}/latest/meta-data/iam/security-credentials/", timeout=3)
        if role_status == 200 and role_body.strip():
            role = role_body.strip().splitlines()[0]
            result["role"] = role
            _log("IMDS", f"Role IAM encontrada: {role}", "R")
            cred_status, _, cred_body = _get(
                f"http://{ip}/latest/meta-data/iam/security-credentials/{role}", timeout=3)
            if cred_status == 200:
                result["keys"] = cred_body[:200]
                _log("IMDS", "Credenciais IAM EXPOSTAS", "R")
    else:
        status2, _, body2 = _get(url_v1, headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, timeout=3)
        if status2 == 400:
            result["reachable"] = True
            result["imdsv2"] = True
            _log("IMDS", f"IMDSv2 ativo em {ip} (token requerido)", "Y")
    return result


def check_ecr_public(domain: str) -> list:
    """Verifica registries ECR publicos baseados no dominio."""
    findings = []
    base = domain.split(".")[0]
    urls = [
        f"https://public.ecr.aws/v2/{base}/tags/list",
        f"https://public.ecr.aws/v2/{base.replace('-', '')}/tags/list",
    ]
    for url in urls:
        status, _, body = _get(url)
        if status == 200 and "tags" in body:
            findings.append({"url": url, "body": body[:200]})
            _log("ECR", f"[PUBLICO] {url}", "R")
    return findings


# ─── Azure checks ─────────────────────────────────────────────────────────────

def check_azure_blob(domain: str) -> list:
    """Verifica storage accounts Azure com blob containers publicos."""
    base = domain.replace(".", "").replace("-", "")[:24]
    candidates = [base, f"{base}storage", f"{base}backup", f"{base}static",
                  f"{base}media", f"{base}assets", f"{base}data"]
    findings = []
    _log("Azure", f"Testando {len(candidates)} storage accounts", "C")
    for name in candidates:
        for container in ["$web", "files", "backup", "data", "uploads", "public", "static"]:
            url = f"https://{name}.blob.core.windows.net/{container}?restype=container&comp=list"
            status, _, body = _get(url)
            if status == 200 and "<EnumerationResults" in body:
                findings.append({"account": name, "container": container, "url": url})
                _log("Blob", f"[PUBLICO] {url}", "R")
            elif status == 403:
                findings.append({"account": name, "container": container,
                                  "url": url, "note": "Existe mas acesso negado"})
                _log("Blob", f"[EXISTS/403] {name}/{container}", "Y")
    return findings


def check_azure_sas_leak(domain: str) -> list:
    """Procura SAS tokens expostos em URLs do dominio via paths comuns."""
    suspects = [
        f"https://{domain}/robots.txt",
        f"https://{domain}/sitemap.xml",
        f"https://{domain}/.env",
        f"https://{domain}/config.json",
    ]
    findings = []
    sas_pattern = re.compile(r"(https://[a-z0-9]+\.blob\.core\.windows\.net[^\s\"']+sig=[^&\s\"']+)", re.I)
    for url in suspects:
        status, _, body = _get(url)
        if status == 200:
            matches = sas_pattern.findall(body)
            for m in matches:
                findings.append({"source": url, "sas_url": m})
                _log("SAS", f"[VAZADO] SAS token em {url}", "R")
    return findings


def check_acr_public(domain: str) -> list:
    """Verifica Azure Container Registry publico."""
    base = domain.replace(".", "").replace("-", "")[:50]
    findings = []
    url = f"https://{base}.azurecr.io/v2/_catalog"
    status, _, body = _get(url)
    if status == 200 and "repositories" in body:
        findings.append({"url": url, "body": body[:200]})
        _log("ACR", f"[PUBLICO] {url}", "R")
    elif status == 401:
        findings.append({"url": url, "note": "Requer auth (registry existe)"})
        _log("ACR", f"[EXISTS/401] {url}", "Y")
    return findings


# ─── GCP checks ───────────────────────────────────────────────────────────────

def check_gcs_bucket(bucket_name: str) -> dict:
    """Verifica bucket GCS publico."""
    result = {"bucket": bucket_name, "public": False, "listable": False, "files": []}
    url = f"https://storage.googleapis.com/{bucket_name}"
    status, _, body = _get(url)
    if status == 200:
        result["public"] = True
        result["listable"] = "<ListBucketResult" in body or "prefixes" in body
        keys = re.findall(r"<Key>([^<]+)</Key>", body)
        result["files"] = keys[:10]
        _log("GCS", f"[PUBLICO] {url}", "R")
    elif status == 403:
        result["note"] = "Existe mas acesso negado (403)"
        _log("GCS", f"[EXISTS/403] {bucket_name}", "Y")
    return result


def enum_gcs_buckets(domain: str) -> list:
    base = domain.replace(".", "-").replace("_", "-")
    candidates = [
        base, f"{base}-backup", f"{base}-static", f"{base}-assets",
        f"{base}-data", f"{base}-media", f"{base}-dev", f"{base}-prod",
        f"backup-{base}", f"static-{base}",
    ]
    findings = []
    _log("GCS", f"Testando {len(candidates)} buckets GCS", "C")
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(check_gcs_bucket, b): b for b in candidates}
        for fut in as_completed(futs):
            r = fut.result()
            if r.get("public") or r.get("note"):
                findings.append(r)
    return findings


def check_gcp_service_account_keys(domain: str) -> list:
    """Procura chaves de service account GCP expostas em paths comuns."""
    suspects = [
        f"https://{domain}/service-account.json",
        f"https://{domain}/credentials.json",
        f"https://{domain}/gcp-key.json",
        f"https://{domain}/.gcloud/credentials",
        f"https://{domain}/google-credentials.json",
    ]
    findings = []
    sa_pattern = re.compile(r'"type"\s*:\s*"service_account"')
    for url in suspects:
        status, _, body = _get(url)
        if status == 200 and sa_pattern.search(body):
            findings.append({"url": url, "snippet": body[:100]})
            _log("GCP", f"[CRITICO] Service account key em {url}", "R")
    return findings


def check_gcr_public(domain: str) -> list:
    """Verifica Google Container Registry publico."""
    base = domain.split(".")[0]
    findings = []
    for registry in ["gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"]:
        url = f"https://{registry}/v2/{base}/tags/list"
        status, _, body = _get(url)
        if status == 200 and "tags" in body:
            findings.append({"url": url, "body": body[:200]})
            _log("GCR", f"[PUBLICO] {url}", "R")
    return findings


# ─── IaC leaks ────────────────────────────────────────────────────────────────

def check_iac_leaks(domain: str) -> list:
    """Procura arquivos IaC / segredos expostos em paths comuns."""
    paths = [
        "/.git/config", "/.env", "/.env.production", "/.env.local",
        "/terraform.tfstate", "/terraform.tfvars", "/.terraform/terraform.tfstate",
        "/cloudformation.json", "/sam-template.json", "/serverless.yml",
        "/docker-compose.yml", "/docker-compose.prod.yml",
        "/.aws/credentials", "/.aws/config",
    ]
    findings = []
    secret_patterns = [
        re.compile(r"(AKIA[0-9A-Z]{16})", re.I),
        re.compile(r"(aws_secret_access_key\s*=\s*[^\s\n]+)", re.I),
        re.compile(r"(client_secret\s*[=:]\s*[^\s\n]+)", re.I),
        re.compile(r"(private_key\s*[=:]\s*-----BEGIN)", re.I),
    ]
    _log("IaC", f"Procurando leaks em {domain}", "C")
    for path in paths:
        url = f"https://{domain}{path}"
        status, _, body = _get(url)
        if status == 200 and len(body) > 20:
            secrets_found = []
            for pat in secret_patterns:
                matches = pat.findall(body)
                secrets_found.extend(matches)
            findings.append({"url": url, "size": len(body),
                              "secrets": secrets_found[:5]})
            if secrets_found:
                _log("IaC", f"[CRITICO] Segredos em {url}: {secrets_found[0][:40]}", "R")
            else:
                _log("IaC", f"[EXPOSTO] {url} ({len(body)}b)", "Y")
    return findings


# ─── Relatorio ────────────────────────────────────────────────────────────────

def _print_summary(all_findings: dict):
    G = C["G"]; R = C["R"]; Y = C["Y"]; X = C["X"]; N = C["N"]; D = C["D"]
    print(f"\n  {G}{'=' * 60}{X}")
    print(f"  {N}RESUMO{X}")
    print(f"  {G}{'=' * 60}{X}")
    total = 0
    for category, items in all_findings.items():
        if items:
            critical = [i for i in items if i.get("public") or i.get("keys") or i.get("secrets")]
            exist = [i for i in items if not i.get("public") and not i.get("keys")]
            total += len(items)
            print(f"  {Y}[{category}]{X}  {len(items)} finding(s)  "
                  f"{R}{len(critical)} critico(s){X}  {D}{len(exist)} baixo{X}")
    print(f"\n  Total: {N}{total}{X} findings\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():

    ap = argparse.ArgumentParser(
        description="Ghost-Cloud - Cloud Security Assessment",
        formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("-t", "--target", metavar="HOST",
                    help="Dominio ou hostname alvo")
    ap.add_argument("--bucket", metavar="BUCKET",
                    help="Nome exato de bucket para testar diretamente")
    ap.add_argument("--ip", metavar="IP", default="169.254.169.254",
                    help="IP do IMDS (padrao: 169.254.169.254)")
    ap.add_argument("--aws", action="store_true", help="Checks AWS (S3, ECR, IMDS)")
    ap.add_argument("--azure", action="store_true", help="Checks Azure (Blob, ACR, SAS)")
    ap.add_argument("--gcp", action="store_true", help="Checks GCP (GCS, GCR, SA keys)")
    ap.add_argument("--imds", action="store_true", help="IMDS metadata check")
    ap.add_argument("--registry", action="store_true", help="Container registry checks")
    ap.add_argument("--iac", action="store_true", help="Terraform/CF/IaC leak checks")
    ap.add_argument("--all", action="store_true", help="Executar todos os modulos")
    ap.add_argument("--output", "-o", metavar="FILE", help="Salvar JSON em arquivo")
    ap.add_argument("--timeout", type=int, default=10, help="Timeout HTTP (padrao: 10s)")
    ap.add_argument("--no-ssl-verify", action="store_true", help="Desabilitar verificacao SSL")
    ap.add_argument("--proxy", help="Proxy HTTP/HTTPS (ex: http://127.0.0.1:8080)")
    ap.add_argument("--no-banner", action="store_true", help="Suprimir banner")
    args = ap.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout

    if not getattr(args, "no_banner", False):
        print(BANNER)

    if getattr(args, "proxy", None):
        os.environ["http_proxy"] = args.proxy
        os.environ["https_proxy"] = args.proxy

    if not args.target and not args.bucket:
        ap.print_help()
        sys.exit(1)

    run_all = args.all
    target = args.target or ""

    all_findings = {}

    if run_all or args.bucket:
        if args.bucket:
            _log("S3", f"Testando bucket: {args.bucket}", "C")
            r = check_s3_bucket(args.bucket)
            all_findings["s3_direct"] = [r]

    if target:
        if run_all or args.aws:
            _log("AWS", f"Iniciando checks AWS para {target}", "C")
            all_findings["s3"] = enum_s3_buckets(target)
            all_findings["ecr"] = check_ecr_public(target)
            all_findings["cloudformation"] = check_cloudformation_leaks(target)

        if run_all or args.imds:
            _log("IMDS", f"Verificando IMDS em {args.ip}", "C")
            all_findings["imds"] = [check_aws_metadata(args.ip)]

        if run_all or args.azure:
            _log("Azure", f"Iniciando checks Azure para {target}", "C")
            all_findings["blob"] = check_azure_blob(target)
            all_findings["sas"] = check_azure_sas_leak(target)
            all_findings["acr"] = check_acr_public(target)

        if run_all or args.gcp:
            _log("GCP", f"Iniciando checks GCP para {target}", "C")
            all_findings["gcs"] = enum_gcs_buckets(target)
            all_findings["gcr"] = check_gcr_public(target)
            all_findings["gcp_sa"] = check_gcp_service_account_keys(target)

        if run_all or args.iac:
            _log("IaC", f"Verificando leaks de IaC em {target}", "C")
            all_findings["iac"] = check_iac_leaks(target)

    _print_summary(all_findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"target": target, "timestamp": datetime.utcnow().isoformat(),
                       "findings": all_findings}, f, indent=2)
        _log("OUT", f"Resultado salvo em {args.output}", "C")


if __name__ == "__main__":
    main()
