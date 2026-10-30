# ghost-cloud

**AWS / Azure / GCP Misconfiguration Scanner**

By Gh0st-Bx1 | github.com/Ghost-Bx1

---

## Description

ghost-cloud identifies cloud misconfigurations across AWS, Azure, and GCP. It checks for publicly accessible storage buckets, exposed container registries, IMDS metadata endpoints, and leaked IaC files (terraform.tfstate, .env, AWS credentials).

## Usage

```
python ghost-cloud.py --target example.com --all
python ghost-cloud.py --target example.com --aws --iac
python ghost-cloud.py --target example.com --azure
python ghost-cloud.py --target example.com --gcp
python ghost-cloud.py --ip 169.254.169.254 --imds
python ghost-cloud.py --bucket my-bucket-name --aws
python ghost-cloud.py --target example.com --all -o results.json
```

## Options

| Flag | Description |
|------|-------------|
| `--target` / `-t` | Target domain |
| `--bucket` | Specific S3/GCS bucket name |
| `--ip` | IP for IMDS check |
| `--aws` | AWS checks (S3, ECR) |
| `--azure` | Azure checks (Blob, ACR, SAS) |
| `--gcp` | GCP checks (GCS, GCR, SA keys) |
| `--imds` | IMDS metadata endpoint check |
| `--registry` | Container registry checks |
| `--iac` | IaC file leaks (.env, tfstate, credentials) |
| `--all` / `-a` | Run all modules |
| `--output` / `-o` | Save results as JSON |
| `--timeout` | HTTP timeout in seconds (default: 10) |
| `--no-ssl-verify` | Disable SSL verification |

## Output

JSON output follows the ghost-report schema and can be fed directly to ghost-report:

```
python ghost-cloud.py -t example.com --all -o cloud.json
python ghost-report.py --input cloud.json --output report.html
```

## Checks Performed

- **AWS**: S3 public bucket enumeration, ECR public registry
- **Azure**: Blob container access, SAS token leaks, ACR public access
- **GCP**: GCS bucket enumeration, GCR registry, service account key files
- **IMDS**: IMDSv1/v2 metadata access, IAM role extraction
- **IaC**: `.env`, `terraform.tfstate`, `.aws/credentials`, `docker-compose.yml` exposure

## Requirements

- Python 3.6+
- No external dependencies (stdlib only)
