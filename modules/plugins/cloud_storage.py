"""Publicly listable cloud storage buckets named after the domain (S3 and Google Cloud Storage).

ACTIVE: it probes a few guessed bucket names on the cloud providers (not on the target
itself). A listable bucket named like the domain is not proof that the domain owns it,
so findings say so.
"""
import re
import time

from modules.registry import module
from utils import webprobe

PAUSE = 0.15
SUFFIXES = ("", "-backup", "-backups", "-assets", "-static", "-media", "-uploads", "-files", "-data", "-dev", "-staging", "-prod")
_LISTING = re.compile(r"<ListBucketResult", re.I)
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def candidate_names(domain):
    """Bucket names someone might plausibly have chosen for ``domain``."""
    label = domain.split(".")[0]
    dashed = domain.replace(".", "-")
    names = []
    for base in (label, dashed):
        for suffix in SUFFIXES:
            name = f"{base}{suffix}"
            if _BUCKET.match(name) and name not in names:
                names.append(name)
    return names[:16]


PROVIDERS = (
    ("Amazon S3", "https://{name}.s3.amazonaws.com/"),
    ("Google Cloud Storage", "https://storage.googleapis.com/{name}/"),
)


@module("Cloud Storage", description="Publicly listable S3 / GCS buckets named after the domain", group="security", weight="light", active=True, order=181)
def cloud_storage(domain, get=None, sleep=time.sleep):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    get = get or webprobe.default_get
    findings, checked = [], 0
    for name in candidate_names(domain):
        for provider, template in PROVIDERS:
            sleep(PAUSE)
            checked += 1
            url = template.format(name=name)
            try:
                response = get(url, method="GET", headers=None)
            except Exception:  # noqa: BLE001
                continue
            if response.status_code == 200 and _LISTING.search(webprobe.text(response, 4096)):
                findings.append({
                    "title": f"Public {provider} bucket: {name}", "severity": "medium", "location": url,
                    "description": f"The bucket '{name}' lists its contents to anyone. It is named like this domain, but ownership is not verified.",
                    "recommendation": "If the bucket is yours, disable public listing and review what it exposes. If not, it is unrelated to this domain.",
                })
    return {"names_checked": len(candidate_names(domain)), "requests": checked, "findings": findings}
