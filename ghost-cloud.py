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

VERSAO = "2.1.0"


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


# ─── Elasticsearch / OpenSearch ──────────────────────────────────────────────

def check_elasticsearch(domain: str) -> list:
    """Verifica Elasticsearch/OpenSearch sem autenticacao."""
    findings = []
    for port, scheme in [(9200, "http"), (9243, "https"), (443, "https")]:
        url = f"{scheme}://{domain}:{port}/"
        status, _, body = _get(url, timeout=5)
        if status == 200 and ('"cluster_name"' in body or '"version"' in body):
            entry = {"url": url, "body": body[:300], "severity": "critical"}
            idx_url = f"{scheme}://{domain}:{port}/_cat/indices?v"
            s2, _, b2 = _get(idx_url, timeout=5)
            if s2 == 200:
                entry["indices"] = b2[:500]
                _log("ES", f"[INDICES] {b2[:200]}", "Y")
            findings.append(entry)
            _log("ES", f"[EXPOSTO] Elasticsearch sem auth em {url}", "R")
            break
    return findings


# ─── Firebase ─────────────────────────────────────────────────────────────────

def check_firebase(domain: str) -> list:
    """Verifica Firebase Realtime Database exposto."""
    findings = []
    base = domain.split(".")[0]
    if base in ("www", "api", "app", "web"):
        parts = domain.split(".")
        base = parts[1] if len(parts) > 2 else parts[0]
    for proj in [base, domain.replace(".", "-"),
                 f"{base}-default-rtdb"]:
        for fb_host in [f"{proj}.firebaseio.com",
                        f"{proj}-default-rtdb.firebaseio.com"]:
            url = f"https://{fb_host}/.json"
            status, _, body = _get(url, timeout=5)
            if status == 200 and body not in ("null", ""):
                findings.append({"url": url, "body": body[:300], "severity": "critical"})
                _log("Firebase", f"[EXPOSTO] DB publico: {url}", "R")
            elif status == 200:
                findings.append({"url": url, "note": "Acessivel mas vazio", "severity": "medium"})
                _log("Firebase", f"[VAZIO] {url}", "Y")
    return findings


# ─── Kubernetes ───────────────────────────────────────────────────────────────

def check_k8s_anon(domain: str) -> list:
    """Verifica API Kubernetes com acesso anonimo."""
    findings = []
    for port, scheme in [(6443, "https"), (8443, "https"), (8080, "http"), (443, "https")]:
        base_url = f"{scheme}://{domain}:{port}"
        status, _, body = _get(f"{base_url}/version", verify=False, timeout=4)
        if status == 200 and '"major"' in body:
            _log("K8s", f"[DETECTADO] API server em {base_url}", "Y")
            for path in ["/api/v1/namespaces", "/api/v1/pods",
                         "/api/v1/secrets", "/apis/apps/v1/deployments"]:
                s, _, b = _get(f"{base_url}{path}", verify=False, timeout=4)
                if s == 200 and '"items"' in b:
                    findings.append({
                        "url": f"{base_url}{path}",
                        "severity": "critical",
                        "note": f"Acesso anonimo: {path}"
                    })
                    _log("K8s", f"[CRITICO] Acesso anonimo: {path}", "R")
            break
    return findings


# ─── S3 sensitive files ───────────────────────────────────────────────────────

_SENSITIVE_PATS = [".env", ".pem", ".key", "id_rsa", "id_dsa",
                   "terraform.tfstate", ".p12", ".pfx",
                   "credentials", "secret", "password", ".htpasswd"]


def check_s3_sensitive_files(s3_findings: list) -> list:
    """Verifica arquivos sensiveis em buckets S3 publicos listados."""
    extra = []
    for r in s3_findings:
        if not r.get("listable") or not r.get("files"):
            continue
        url_base = r.get("url", "").rstrip("/")
        for fname in r["files"]:
            if any(pat in fname.lower() for pat in _SENSITIVE_PATS):
                file_url = f"{url_base}/{fname}"
                status, _, body = _get(file_url, timeout=5)
                if status == 200:
                    extra.append({
                        "url": file_url, "file": fname,
                        "size": len(body), "severity": "critical",
                        "snippet": body[:200]
                    })
                    _log("S3", f"[ARQUIVO SENSIVEL] {file_url}", "R")
    return extra


# ─── EC2 user-data ────────────────────────────────────────────────────────────

def check_ec2_user_data(ip: str = "169.254.169.254") -> dict:
    """Verifica user-data EC2 para segredos expostos via IMDS."""
    result = {"reachable": False, "has_secrets": False, "data": None}
    status, _, body = _get(f"http://{ip}/latest/user-data", timeout=3)
    if status == 200 and body.strip():
        result["reachable"] = True
        result["data"] = body[:500]
        secret_pats = [
            re.compile(r"AKIA[0-9A-Z]{16}", re.I),
            re.compile(r"password\s*[=:]\s*\S+", re.I),
            re.compile(r"secret\s*[=:]\s*\S+", re.I),
            re.compile(r"token\s*[=:]\s*\S+", re.I),
        ]
        result["has_secrets"] = any(p.search(body) for p in secret_pats)
        if result["has_secrets"]:
            _log("IMDS", "[CRITICO] Segredos em user-data EC2", "R")
        else:
            _log("IMDS", f"[INFO] user-data acessivel ({len(body)}b)", "Y")
    return result


# ─── SQS enumeration ─────────────────────────────────────────────────────────

def check_sqs_public(domain: str) -> list:
    """Detecta filas SQS e orienta testes de acesso publico."""
    findings = []
    checked = set()
    for region in ["us-east-1", "us-east-2", "us-west-2", "eu-west-1"]:
        url = f"https://sqs.{region}.amazonaws.com/"
        status, _, _ = _get(url, timeout=4)
        if status in (400, 403, 404) and region not in checked:
            checked.add(region)
            findings.append({
                "region": region,
                "severity": "info",
                "note": (f"SQS ativo em {region} - "
                         f"testar: aws sqs list-queues --region {region}")
            })
            _log("SQS", f"SQS endpoint ativo em {region}", "D")
    return findings


# ─── AWS API Checks (boto3) ───────────────────────────────────────────────────

def check_lambda_env_leaks(domain: str, region: str = "us-east-1",
                            aws_key: str = None, aws_secret: str = None) -> list:
    """Detecta variaveis de ambiente sensiveis em funcoes Lambda."""
    findings = []
    _log("Lambda", "Verificando env vars de funcoes Lambda...", "C")
    try:
        import boto3
        kwargs = {"region_name": region}
        if aws_key and aws_secret:
            kwargs["aws_access_key_id"] = aws_key
            kwargs["aws_secret_access_key"] = aws_secret
        client = boto3.client("lambda", **kwargs)
        paginator = client.get_paginator("list_functions")
        secret_patterns = ["password", "passwd", "secret", "token", "key", "api_key",
                           "access_key", "private", "credentials", "auth"]
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = fn.get("FunctionName", "")
                env = fn.get("Environment", {}).get("Variables", {})
                for var, val in env.items():
                    for pat in secret_patterns:
                        if pat in var.lower():
                            findings.append({
                                "function": name,
                                "variable": var,
                                "value_preview": val[:20] + "..." if len(val) > 20 else val,
                                "severity": "critical",
                                "note": "Variavel de ambiente sensivel em Lambda"
                            })
                            _log("Lambda", f"LEAK: {name} -> {var}", "C")
                            break
    except ImportError:
        findings.append({
            "note": "boto3 nao instalado - pip install boto3",
            "severity": "info",
            "dica": f"aws lambda list-functions --region {region} --query "
                    "'Functions[].Environment.Variables'"
        })
        _log("Lambda", "boto3 nao disponivel", "W")
    except Exception as e:
        _log("Lambda", f"Erro: {e}", "W")
    return findings


def check_iam_policy_wildcard(domain: str, region: str = "us-east-1",
                               aws_key: str = None, aws_secret: str = None) -> list:
    """Detecta policies IAM com wildcards perigosos (Action:* ou Resource:*)."""
    findings = []
    _log("IAM", "Verificando policies IAM com wildcards...", "C")
    try:
        import boto3
        import json as _json
        kwargs = {"region_name": region}
        if aws_key and aws_secret:
            kwargs["aws_access_key_id"] = aws_key
            kwargs["aws_secret_access_key"] = aws_secret
        client = boto3.client("iam", **kwargs)
        paginator = client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                pol_arn = policy["Arn"]
                pol_ver = policy.get("DefaultVersionId", "v1")
                try:
                    doc = client.get_policy_version(
                        PolicyArn=pol_arn, VersionId=pol_ver
                    )["PolicyVersion"]["Document"]
                    stmts = doc.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for stmt in stmts:
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        if "*" in actions or "*" in resources:
                            findings.append({
                                "policy_arn": pol_arn,
                                "effect": stmt.get("Effect", ""),
                                "action_wildcard": "*" in actions,
                                "resource_wildcard": "*" in resources,
                                "severity": "critical",
                                "note": "Policy IAM com wildcard Action ou Resource"
                            })
                            _log("IAM", f"WILDCARD: {pol_arn}", "C")
                except Exception:
                    pass
    except ImportError:
        findings.append({
            "note": "boto3 nao instalado - pip install boto3",
            "severity": "info",
            "dica": "aws iam list-policies --scope Local && aws iam get-policy-version ..."
        })
        _log("IAM", "boto3 nao disponivel", "W")
    except Exception as e:
        _log("IAM", f"Erro: {e}", "W")
    return findings


def check_cloudtrail_disabled(domain: str, region: str = "us-east-1",
                               aws_key: str = None, aws_secret: str = None) -> list:
    """Verifica se CloudTrail esta desabilitado em regioes AWS."""
    findings = []
    _log("CloudTrail", "Verificando status do CloudTrail...", "C")
    regions_to_check = [region, "us-east-2", "us-west-2", "eu-west-1"]
    try:
        import boto3
        for reg in regions_to_check:
            try:
                kwargs = {"region_name": reg}
                if aws_key and aws_secret:
                    kwargs["aws_access_key_id"] = aws_key
                    kwargs["aws_secret_access_key"] = aws_secret
                client = boto3.client("cloudtrail", **kwargs)
                trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
                if not trails:
                    findings.append({
                        "region": reg,
                        "severity": "critical",
                        "note": f"CloudTrail SEM trilhas configuradas em {reg}"
                    })
                    _log("CloudTrail", f"DESABILITADO em {reg}", "C")
                else:
                    for trail in trails:
                        status = client.get_trail_status(Name=trail["TrailARN"])
                        if not status.get("IsLogging"):
                            findings.append({
                                "region": reg,
                                "trail": trail.get("Name"),
                                "severity": "critical",
                                "note": f"CloudTrail '{trail.get('Name')}' existe mas NAO esta logando em {reg}"
                            })
                            _log("CloudTrail", f"IsLogging=False: {trail.get('Name')}", "C")
            except Exception:
                pass
    except ImportError:
        findings.append({
            "note": "boto3 nao instalado - pip install boto3",
            "severity": "info",
            "dica": "aws cloudtrail describe-trails && aws cloudtrail get-trail-status --name TRAIL"
        })
        _log("CloudTrail", "boto3 nao disponivel", "W")
    except Exception as e:
        _log("CloudTrail", f"Erro: {e}", "W")
    return findings


def check_ec2_imdsv1_enabled(domain: str, region: str = "us-east-1",
                              aws_key: str = None, aws_secret: str = None) -> list:
    """Detecta instancias EC2 com IMDSv1 habilitado (HttpTokens=optional)."""
    findings = []
    _log("EC2", "Verificando instancias com IMDSv1 habilitado...", "C")
    try:
        import boto3
        kwargs = {"region_name": region}
        if aws_key and aws_secret:
            kwargs["aws_access_key_id"] = aws_key
            kwargs["aws_secret_access_key"] = aws_secret
        client = boto3.client("ec2", **kwargs)
        paginator = client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    inst_id = inst.get("InstanceId", "")
                    state = inst.get("State", {}).get("Name", "")
                    if state != "running":
                        continue
                    opts = inst.get("MetadataOptions", {})
                    http_tokens = opts.get("HttpTokens", "optional")
                    if http_tokens == "optional":
                        findings.append({
                            "instance_id": inst_id,
                            "region": region,
                            "http_tokens": http_tokens,
                            "severity": "high",
                            "note": f"EC2 {inst_id} com IMDSv1 habilitado (HttpTokens=optional) - SSRF -> credenciais AWS"
                        })
                        _log("EC2", f"IMDSv1: {inst_id}", "C")
    except ImportError:
        findings.append({
            "note": "boto3 nao instalado - pip install boto3",
            "severity": "info",
            "dica": "aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IMDS:MetadataOptions}'"
        })
        _log("EC2", "boto3 nao disponivel", "W")
    except Exception as e:
        _log("EC2", f"Erro IMDSv1 check: {e}", "W")
    return findings


def check_sg_permissive(domain: str, region: str = "us-east-1",
                         aws_key: str = None, aws_secret: str = None) -> list:
    """Detecta Security Groups com 0.0.0.0/0 em portas sensiveis."""
    findings = []
    sensitive_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                       1433: "MSSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
    _log("SG", "Verificando Security Groups permissivos...", "C")
    try:
        import boto3
        kwargs = {"region_name": region}
        if aws_key and aws_secret:
            kwargs["aws_access_key_id"] = aws_key
            kwargs["aws_secret_access_key"] = aws_secret
        client = boto3.client("ec2", **kwargs)
        paginator = client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg.get("GroupId", "")
                sg_name = sg.get("GroupName", "")
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    for cidr in perm.get("IpRanges", []):
                        if cidr.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                            for port, svc in sensitive_ports.items():
                                if from_port <= port <= to_port:
                                    findings.append({
                                        "sg_id": sg_id,
                                        "sg_name": sg_name,
                                        "port": port,
                                        "service": svc,
                                        "cidr": cidr.get("CidrIp"),
                                        "severity": "critical",
                                        "note": f"SG {sg_id}: porta {port}/{svc} aberta para {cidr.get('CidrIp')}"
                                    })
                                    _log("SG", f"OPEN: {sg_id} porta {port}/{svc}", "C")
    except ImportError:
        findings.append({
            "note": "boto3 nao instalado - pip install boto3",
            "severity": "info",
            "dica": "aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'"
        })
        _log("SG", "boto3 nao disponivel", "W")
    except Exception as e:
        _log("SG", f"Erro SG check: {e}", "W")
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
    ap.add_argument("--elasticsearch", "--es", action="store_true",
                    help="Elasticsearch/OpenSearch sem auth")
    ap.add_argument("--firebase", action="store_true",
                    help="Firebase Realtime Database exposto")
    ap.add_argument("--k8s", action="store_true",
                    help="Kubernetes API sem autenticacao")
    ap.add_argument("--all", action="store_true", help="Executar todos os modulos")
    ap.add_argument("--aws-api", action="store_true",
                    help="Checks AWS via API boto3 (Lambda, IAM, CloudTrail, EC2 IMDSv1, SG)")
    ap.add_argument("--aws-region", default="us-east-1", metavar="REGION",
                    help="Regiao AWS para checks via API (padrao: us-east-1)")
    ap.add_argument("--aws-key", metavar="KEY", help="AWS Access Key ID (opcional)")
    ap.add_argument("--aws-secret", metavar="SECRET", help="AWS Secret Access Key (opcional)")
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
            s3_res = enum_s3_buckets(target)
            all_findings["s3"] = s3_res
            all_findings["s3_sensitive"] = check_s3_sensitive_files(s3_res)
            all_findings["ecr"] = check_ecr_public(target)
            all_findings["cloudformation"] = check_cloudformation_leaks(target)
            all_findings["sqs"] = check_sqs_public(target)

        if run_all or args.imds:
            _log("IMDS", f"Verificando IMDS em {args.ip}", "C")
            all_findings["imds"] = [check_aws_metadata(args.ip)]
            ud = check_ec2_user_data(args.ip)
            if ud.get("reachable"):
                all_findings["ec2_user_data"] = [ud]

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

        if run_all or getattr(args, "elasticsearch", False):
            _log("ES", f"Verificando Elasticsearch em {target}", "C")
            all_findings["elasticsearch"] = check_elasticsearch(target)

        if run_all or getattr(args, "firebase", False):
            _log("Firebase", f"Verificando Firebase para {target}", "C")
            all_findings["firebase"] = check_firebase(target)

        if run_all or getattr(args, "k8s", False):
            _log("K8s", f"Verificando Kubernetes API em {target}", "C")
            all_findings["k8s"] = check_k8s_anon(target)

    aws_key = getattr(args, "aws_key", None)
    aws_secret = getattr(args, "aws_secret", None)
    aws_region = getattr(args, "aws_region", "us-east-1")
    if run_all or getattr(args, "aws_api", False):
        _log("AWS-API", f"Iniciando checks AWS via API (regiao: {aws_region})", "C")
        all_findings["lambda_env"] = check_lambda_env_leaks(
            target, region=aws_region, aws_key=aws_key, aws_secret=aws_secret)
        all_findings["iam_wildcard"] = check_iam_policy_wildcard(
            target, region=aws_region, aws_key=aws_key, aws_secret=aws_secret)
        all_findings["cloudtrail"] = check_cloudtrail_disabled(
            target, region=aws_region, aws_key=aws_key, aws_secret=aws_secret)
        all_findings["ec2_imdsv1"] = check_ec2_imdsv1_enabled(
            target, region=aws_region, aws_key=aws_key, aws_secret=aws_secret)
        all_findings["sg_permissive"] = check_sg_permissive(
            target, region=aws_region, aws_key=aws_key, aws_secret=aws_secret)

    _print_summary(all_findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"target": target, "timestamp": datetime.utcnow().isoformat(),
                       "findings": all_findings}, f, indent=2)
        _log("OUT", f"Resultado salvo em {args.output}", "C")


if __name__ == "__main__":
    main()
