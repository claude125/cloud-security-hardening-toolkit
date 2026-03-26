<div align="center">


<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=400&size=14&pause=99999&color=7d8590&center=true&vCenter=true&width=800&height=35&lines=Automated+CIS+Benchmark+Enforcement+for+AWS+%26+Azure+%7C+Dockerized" alt="subtitle" />

<br/>

![AWS](https://img.shields.io/badge/AWS-FF9900?style=for-the-badge&logo=amazonaws&logoColor=black)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![CIS](https://img.shields.io/badge/CIS_Benchmarks-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black)

[![Author](https://img.shields.io/badge/Author-Claude_Dusengimana-00e5ff?style=flat-square)](https://github.com/claude125)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()

</div>

---

## 📌 Overview

The **Cloud Security Hardening Toolkit** is an automated framework that audits and enforces security best practices across **AWS** and **Azure** cloud environments. It scans for misconfigurations, enforces **CIS Benchmark** controls, and generates detailed remediation reports — all packaged in a portable **Docker** container for consistent, repeatable cloud security audits.

> Built by [Claude Dusengimana](https://github.com/claude125) — Senior Network & Security Engineer, Kigali, Rwanda.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **IAM Auditing** | Detects overly permissive roles, unused credentials, and missing MFA enforcement |
| 🪣 **Storage Bucket Scanner** | Flags publicly exposed S3 buckets and Azure Blob containers |
| 🔒 **Encryption Checker** | Identifies unencrypted EBS volumes, RDS instances, and Azure disks |
| 🌐 **Network Security Groups** | Reviews open inbound rules and overly permissive security groups |
| 📋 **CIS Benchmark Reports** | Maps findings to CIS AWS & Azure Benchmark controls |
| 🐳 **Dockerized** | Zero local dependency conflicts — run from any machine |
| 📊 **HTML + JSON Reports** | Human-readable and machine-parseable audit output |

---

## 🏗️ Architecture

```
cloud-security-hardening-toolkit/
│
├── 🐳 Dockerfile                  # Container definition
├── docker-compose.yml             # Multi-service orchestration
├── requirements.txt               # Python dependencies
│
├── scripts/
│   ├── aws_audit.py               # AWS environment scanner
│   ├── azure_audit.py             # Azure environment scanner
│   ├── iam_checker.py             # IAM policy analyzer
│   ├── storage_scanner.py         # S3 / Blob exposure scanner
│   ├── encryption_checker.py      # Encryption compliance checker
│   ├── network_audit.py           # Security group / NSG auditor
│   └── report_generator.py        # HTML + JSON report builder
│
├── configs/
│   ├── cis_aws_controls.json      # CIS AWS Benchmark control map
│   ├── cis_azure_controls.json    # CIS Azure Benchmark control map
│   └── remediation_templates.json # Automated fix templates
│
└── docs/
    ├── USAGE.md
    └── SAMPLE_REPORT.md
```

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose installed
- AWS CLI credentials configured (`~/.aws/credentials`) **or** Azure CLI logged in

### 1. Clone the repository
```bash
git clone https://github.com/claude125/cloud-security-hardening-toolkit.git
cd cloud-security-hardening-toolkit
```

### 2. Build the Docker image
```bash
docker build -t cloud-hardening-toolkit .
```

### 3. Run an AWS audit
```bash
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/reports:/app/reports \
  cloud-hardening-toolkit python scripts/aws_audit.py --profile default --region us-east-1
```

### 4. Run an Azure audit
```bash
docker run --rm \
  -e AZURE_SUBSCRIPTION_ID=<your-sub-id> \
  -e AZURE_TENANT_ID=<your-tenant-id> \
  -e AZURE_CLIENT_ID=<your-client-id> \
  -e AZURE_CLIENT_SECRET=<your-secret> \
  -v $(pwd)/reports:/app/reports \
  cloud-hardening-toolkit python scripts/azure_audit.py
```

### 5. View the report
```bash
open reports/audit_report.html
```

---

## 🔧 Core Scripts

### `aws_audit.py` — AWS Environment Scanner
```python
"""
AWS Cloud Security Auditor
Scans IAM, S3, EC2, RDS, and VPC configurations against CIS Benchmarks.
"""

import boto3
import json
from datetime import datetime, timezone

class AWSAuditor:
    def __init__(self, profile="default", region="us-east-1"):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.findings = []

    def check_iam_mfa(self):
        """CIS 1.5 — Ensure MFA is enabled for all IAM users with console access."""
        iam = self.session.client("iam")
        users = iam.list_users()["Users"]
        for user in users:
            devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            if not devices:
                self.findings.append({
                    "control": "CIS 1.5",
                    "severity": "HIGH",
                    "resource": user["UserName"],
                    "message": f"IAM user '{user['UserName']}' has no MFA device enabled.",
                    "remediation": "Enable MFA for this user via IAM console or CLI."
                })

    def check_s3_public_access(self):
        """CIS 2.1.5 — Ensure S3 buckets do not allow public access."""
        s3 = self.session.client("s3")
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            try:
                acl = s3.get_bucket_acl(Bucket=bucket["Name"])
                for grant in acl["Grants"]:
                    if "AllUsers" in grant["Grantee"].get("URI", ""):
                        self.findings.append({
                            "control": "CIS 2.1.5",
                            "severity": "CRITICAL",
                            "resource": bucket["Name"],
                            "message": f"S3 bucket '{bucket['Name']}' is publicly accessible.",
                            "remediation": "Remove public ACL grants and enable Block Public Access."
                        })
            except Exception:
                pass

    def check_unencrypted_ebs(self):
        """CIS 2.2.1 — Ensure EBS volumes are encrypted at rest."""
        ec2 = self.session.client("ec2")
        volumes = ec2.describe_volumes()["Volumes"]
        for vol in volumes:
            if not vol.get("Encrypted", False):
                self.findings.append({
                    "control": "CIS 2.2.1",
                    "severity": "MEDIUM",
                    "resource": vol["VolumeId"],
                    "message": f"EBS volume '{vol['VolumeId']}' is NOT encrypted.",
                    "remediation": "Create an encrypted snapshot and replace the volume."
                })

    def run_full_audit(self):
        """Execute all audit checks and return findings."""
        print("[*] Starting AWS Security Audit...")
        self.check_iam_mfa()
        self.check_s3_public_access()
        self.check_unencrypted_ebs()
        print(f"[+] Audit complete. {len(self.findings)} findings detected.")
        return self.findings


if __name__ == "__main__":
    auditor = AWSAuditor()
    findings = auditor.run_full_audit()
    with open("reports/aws_findings.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)
```

---

### `storage_scanner.py` — Exposed Bucket Detector
```python
"""
Cloud Storage Exposure Scanner
Detects publicly accessible S3 buckets and Azure Blob containers.
"""

import boto3
from azure.storage.blob import BlobServiceClient

def scan_s3_buckets(session):
    s3 = session.client("s3")
    exposed = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
            if policy_status["PolicyStatus"]["IsPublic"]:
                exposed.append({"provider": "AWS", "resource": name, "type": "S3 Bucket"})
        except s3.exceptions.NoSuchBucketPolicy:
            pass
    return exposed

def scan_azure_blobs(connection_string):
    client = BlobServiceClient.from_connection_string(connection_string)
    exposed = []
    for container in client.list_containers(include_metadata=True):
        access = container.get("public_access")
        if access in ["container", "blob"]:
            exposed.append({
                "provider": "Azure",
                "resource": container["name"],
                "type": "Blob Container",
                "access_level": access
            })
    return exposed
```

---

## 📊 Sample Report Output

```json
{
  "audit_date": "2025-03-15T10:30:00Z",
  "cloud_provider": "AWS",
  "total_findings": 7,
  "critical": 2,
  "high": 3,
  "medium": 2,
  "findings": [
    {
      "control": "CIS 1.5",
      "severity": "HIGH",
      "resource": "dev-user-john",
      "message": "IAM user 'dev-user-john' has no MFA device enabled.",
      "remediation": "Enable MFA for this user via IAM console or CLI."
    },
    {
      "control": "CIS 2.1.5",
      "severity": "CRITICAL",
      "resource": "company-assets-bucket",
      "message": "S3 bucket 'company-assets-bucket' is publicly accessible.",
      "remediation": "Remove public ACL grants and enable Block Public Access."
    }
  ]
}
```

---

## 🐳 Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip && ./aws/install && rm -rf awscliv2.zip aws/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports

ENTRYPOINT ["python"]
CMD ["scripts/aws_audit.py"]
```

---

## 📦 Requirements

```txt
boto3>=1.34.0
azure-identity>=1.15.0
azure-mgmt-compute>=30.0.0
azure-mgmt-storage>=21.0.0
azure-storage-blob>=12.19.0
jinja2>=3.1.0
rich>=13.7.0
click>=8.1.0
```

---

## 🛡️ CIS Controls Coverage

| # | Control | AWS | Azure |
|---|---------|-----|-------|
| 1.5 | MFA enabled for all IAM users | ✅ | ✅ |
| 1.16 | IAM policies attached only to groups or roles | ✅ | — |
| 2.1.5 | S3/Blob public access blocked | ✅ | ✅ |
| 2.2.1 | EBS/Disk encryption at rest | ✅ | ✅ |
| 3.1 | CloudTrail/Activity Logs enabled | ✅ | ✅ |
| 4.1 | No unrestricted inbound SSH (0.0.0.0/0) | ✅ | ✅ |
| 4.2 | No unrestricted inbound RDP | ✅ | ✅ |

---

## 👤 Author

**Claude Dusengimana** — Senior Network & Security Engineer | IoT Researcher  
📍 Kigali, Rwanda  
📧 [dusenge125@gmail.com](mailto:dusenge125@gmail.com)  
🔗 [LinkedIn](https://linkedin.com/in/dusengimana-claude) | [GitHub](https://github.com/claude125)

---
