"""Exposed Files, Cloud Storage, DNS Zone Transfer (active) and Asset Inventory."""
from modules import registry
from modules.plugins import asset_inventory as ai
from modules.plugins import cloud_storage as cs
from modules.plugins import dns_zone_transfer as zt
from modules.plugins import exposed_files as ef


class Resp:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else body.encode()
        self.headers = headers or {}


def titles(out):
    return {f["title"]: f["severity"] for f in out["findings"]}


def no_sleep(_):
    return None


# ───────────────────────── Exposed Files ─────────────────────────

def serve(files):
    def get(url, method="GET", headers=None):
        path = "/" + url.split("/", 3)[3]
        return files.get(path, Resp(404))
    return get


def test_files_are_reported_when_their_content_matches():
    out = ef.exposed_files("example.org", sleep=no_sleep, get=serve({
        "/.git/HEAD": Resp(200, "ref: refs/heads/main\n"),
        "/.env": Resp(200, "APP_KEY=base64:abc\nDB_PASSWORD=secret\n"),
        "/backup.zip": Resp(200, b"PK\x03\x04rest"),
        "/server-status": Resp(200, "<h1>Apache Server Status for example.org</h1>"),
    }))
    assert titles(out) == {"Git repository exposed": "high", "Environment file exposed": "critical",
                           "Backup archive exposed": "high", "Apache server-status exposed": "medium"}
    assert out["paths_checked"] == len(ef.CHECKS)


def test_a_catch_all_page_that_answers_200_everywhere_is_not_a_finding():
    page = Resp(200, "<!DOCTYPE html><html><body>Welcome! Page not found, try the home page.</body></html>")
    assert ef.exposed_files("example.org", sleep=no_sleep, get=lambda url, method="GET", headers=None: page)["findings"] == []


def test_an_html_page_at_env_is_not_an_env_file():
    out = ef.exposed_files("example.org", sleep=no_sleep, get=serve({"/.env": Resp(200, "<html>DB_HOST=x</html>")}))
    assert out["findings"] == []


def test_redirects_are_not_followed_and_errors_are_ignored():
    def get(url, method="GET", headers=None):
        if "env" in url:
            raise OSError("boom")
        return Resp(302, "", {"Location": "https://elsewhere.example/"})
    assert ef.exposed_files("example.org", sleep=no_sleep, get=get)["findings"] == []


def test_exposed_files_is_an_active_module_and_cloud_and_zone_transfer_too():
    from modules import builtin  # noqa: F401
    registry.discover_plugins()
    for name in ("Exposed Files", "Cloud Storage", "DNS Zone Transfer"):
        assert registry.get(name).active is True
    for name in ("Email Security", "TLS Health", "Cookies & CORS", "Privacy & Trackers", "JS Library Vulnerabilities",
                 "DNS Health", "HTTP Methods & Redirects", "Asset Inventory"):
        assert registry.get(name).active is False, name


# ───────────────────────── Cloud Storage ─────────────────────────

def test_candidate_names_are_valid_bucket_names():
    names = cs.candidate_names("my-shop.example.com")
    assert "my-shop" in names and "my-shop-example-com" in names and "my-shop-backup" in names
    assert all(cs._BUCKET.match(n) for n in names) and len(names) <= 16


def test_only_listable_buckets_are_reported_with_an_ownership_caveat():
    listing = Resp(200, '<?xml version="1.0"?><ListBucketResult><Name>shop</Name></ListBucketResult>')

    def get(url, method="GET", headers=None):
        if url == "https://shop.s3.amazonaws.com/":
            return listing
        if "storage.googleapis.com/shop-backup/" in url:
            return Resp(403, "<Error>AccessDenied</Error>")
        return Resp(404, "<Error>NoSuchBucket</Error>")
    out = cs.cloud_storage("shop.example.com", get=get, sleep=no_sleep)
    assert titles(out) == {"Public Amazon S3 bucket: shop": "medium"}
    assert "not verified" in out["findings"][0]["description"]


# ───────────────────────── DNS Zone Transfer ─────────────────────────

def test_zone_transfer_allowed_is_high_and_refusal_is_quiet():
    answers = {("example.org", "NS"): ["open.ns.test.", "closed.ns.test."], ("open.ns.test", "A"): ["192.0.2.1"], ("closed.ns.test", "A"): ["192.0.2.2"]}
    out = zt.dns_zone_transfer("example.org", resolve=lambda n, t="A": answers.get((n, t), []),
                               axfr=lambda ip, domain: 42 if ip == "192.0.2.1" else 0)
    assert titles(out) == {"Zone transfer allowed by open.ns.test": "high"}
    assert {r["nameserver"]: r["transfer_allowed"] for r in out["results"]} == {"open.ns.test": True, "closed.ns.test": False}


def test_nameservers_without_addresses_are_skipped():
    out = zt.dns_zone_transfer("example.org", resolve=lambda n, t="A": ["ghost.ns.test."] if t == "NS" else [], axfr=lambda ip, d: 1 / 0)
    assert out["findings"] == []


# ───────────────────────── Asset Inventory ─────────────────────────

def cymru(name, rtype="A"):
    table = {
        ("example.org", "A"): ["93.184.216.34"], ("example.org", "AAAA"): ["2606:2800:220:1::1"],
        ("34.216.184.93.origin.asn.cymru.com", "TXT"): ['"15133 | 93.184.216.0/24 | US | arin | 2008-06-02"'],
        ("AS15133.asn.cymru.com", "TXT"): ['"15133 | US | arin | 2008-06-02 | EDGECAST, US"'],
    }
    return table.get((name, rtype), [])


CT = [{"name_value": "example.org\n*.example.org"}, {"name_value": "dev.example.org"}, {"name_value": "www.example.org"},
      {"name_value": "vpn-eu.example.org"}, {"name_value": "evil.com"}, {"name_value": "github.example.org"}]


def test_inventory_collects_addresses_asn_and_ct_names():
    out = ai.asset_inventory("example.org", resolve=cymru, fetch_json=lambda url: CT)
    assert out["addresses"] == ["93.184.216.34", "2606:2800:220:1::1"]
    assert out["networks"] == [{"ip": "93.184.216.34", "asn": "AS15133", "prefix": "93.184.216.0/24", "country": "US", "name": "EDGECAST, US"}]
    assert out["ct_subdomains"] == ["dev.example.org", "example.org", "github.example.org", "vpn-eu.example.org", "www.example.org"]
    assert "evil.com" not in out["ct_subdomains"]


def test_internal_sounding_names_are_a_low_finding_but_github_is_not():
    out = ai.asset_inventory("example.org", resolve=cymru, fetch_json=lambda url: CT)
    assert len(out["findings"]) == 1 and out["findings"][0]["severity"] == "low"
    assert "dev.example.org" in out["findings"][0]["description"] and "github.example.org" not in out["findings"][0]["description"]


def test_crtsh_outage_is_not_a_scan_failure():
    def down(url):
        raise TimeoutError("crt.sh is slow")
    out = ai.asset_inventory("example.org", resolve=cymru, fetch_json=down)
    assert out["ct_error"] == "TimeoutError" and out["findings"] == [] and out["addresses"]
