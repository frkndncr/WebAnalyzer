from modules.plugins import dns_health as dh
from modules.plugins import http_methods as hm
from modules.plugins import js_library_vulns as js


class Resp:
    def __init__(self, status=200, body="", headers=None):
        self.status_code, self.content, self.headers = status, body.encode(), headers or {}


def titles(out):
    return {f["title"]: f["severity"] for f in out["findings"]}


# ───────────────────────── JS libraries ─────────────────────────

HTML = """<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.1.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="/wp-includes/js/jquery/jquery-ui.min.js?ver=1.13.2"></script>
<script src="/assets/app-2.0.1.js"></script>"""


def test_libraries_are_found_by_the_version_in_their_url():
    libs = {(l["package"], l["version"]) for l in js.find_libraries(HTML)}
    assert libs == {("jquery", "1.12.4"), ("bootstrap", "4.1.0"), ("jquery-ui", "1.13.2")}      # app-2.0.1.js is not a known library


def test_each_library_is_reported_once():
    again = HTML + HTML
    assert len(js.find_libraries(again)) == 3


def vulns(package, version):
    if package == "jquery":
        return [{"id": "GHSA-aaaa", "aliases": ["CVE-2020-11022"], "database_specific": {"severity": "MODERATE"}},
                {"id": "GHSA-bbbb", "aliases": ["CVE-2019-11358"], "database_specific": {"severity": "HIGH"}}]
    return []


def test_vulnerable_libraries_become_one_finding_with_the_worst_severity():
    out = js.js_library_vulns("example.org", get=lambda u, method="GET", headers=None: Resp(200, HTML), query=vulns)
    assert titles(out) == {"jquery 1.12.4 has 2 known vulnerabilities": "high"}
    finding = out["findings"][0]
    assert "CVE-2020-11022" in finding["description"] and finding["location"].endswith("jquery.min.js")
    assert [l["vulnerabilities"] for l in out["libraries"]] == [2, 0, 0]


def test_an_osv_outage_reports_libraries_but_no_false_alarm():
    def down(package, version):
        raise OSError("offline")
    out = js.js_library_vulns("example.org", get=lambda u, method="GET", headers=None: Resp(200, HTML), query=down)
    assert out["lookup_failed"] is True and out["findings"] == [] and len(out["libraries"]) == 3


def test_osv_query_shape():
    seen = {}
    js.osv_query("jquery", "1.12.4", post=lambda payload: seen.update(payload) or [])
    assert seen == {"version": "1.12.4", "package": {"name": "jquery", "ecosystem": "npm"}}


# ───────────────────────── DNS health ─────────────────────────

def table(answers):
    return lambda name, rtype="A": answers.get((name, rtype), [])


def test_a_healthy_zone_only_gets_the_informational_note():
    out = dh.dns_health("example.org", resolve=table({
        ("example.org", "NS"): ["a.ns.test.", "b.ns.test."], ("a.ns.test", "A"): ["192.0.2.1"], ("b.ns.test", "A"): ["192.0.2.2"],
        ("example.org", "CAA"): ['0 issue "letsencrypt.org"'], ("example.org", "DS"): ["1 13 2 abc"]}))
    assert out["findings"] == [] and out["dnssec"] is True


def test_single_nameserver_missing_caa_and_dnssec():
    out = dh.dns_health("example.org", resolve=table({("example.org", "NS"): ["a.ns.test."], ("a.ns.test", "A"): ["192.0.2.1"]}))
    assert titles(out) == {"Only one nameserver": "medium", "No CAA record": "low", "DNSSEC is not enabled": "info"}


def test_a_nameserver_that_does_not_exist_is_high():
    answers = {("example.org", "NS"): ["a.ns.test.", "gone.example.net."], ("a.ns.test", "A"): ["192.0.2.1"],
               ("example.org", "CAA"): ["0 issue \"x\""], ("example.org", "DS"): ["1"]}

    def resolve(name, rtype="A"):
        if name == "gone.example.net":
            return None                      # NXDOMAIN
        return answers.get((name, rtype), [])
    out = dh.dns_health("example.org", resolve=resolve)
    assert titles(out) == {"Nameserver gone.example.net does not exist": "high"} and out["dangling"] == ["gone.example.net"]


def test_a_zone_without_ns_records_yields_nothing():
    assert dh.dns_health("example.org", resolve=table({})) == {"nameservers": [], "findings": []}


# ───────────────────────── HTTP methods ─────────────────────────

def site(http=None, options="GET, HEAD", trace=None):
    def get(url, method="GET", headers=None):
        if url.startswith("http://"):
            if http is None:
                raise OSError("refused")
            return http
        if method == "OPTIONS":
            return Resp(200, "", {"Allow": options})
        if method == "TRACE":
            return trace or Resp(405)
        return Resp(200)
    return get


def test_a_clean_site_has_no_findings():
    out = hm.http_methods("example.org", get=site(Resp(301, "", {"Location": "https://example.org/"})))
    assert out["findings"] == [] and out["http_redirects_to_https"] is True and out["allowed_methods"] == ["GET", "HEAD"]


def test_plain_http_without_a_redirect_is_medium():
    assert titles(hm.http_methods("example.org", get=site(Resp(200, "hello")))) == {"Site is served over plain HTTP without redirecting": "medium"}


def test_http_that_is_not_listening_is_fine():
    assert hm.http_methods("example.org", get=site(None))["findings"] == []


def test_risky_methods_and_trace():
    trace = Resp(200, "TRACE / HTTP/1.1\nX-WebAnalyzer-Trace: probe\n")
    out = hm.http_methods("example.org", get=site(Resp(301, "", {"Location": "https://example.org/"}), options="GET, PUT, DELETE", trace=trace))
    assert titles(out) == {"Risky HTTP methods advertised: PUT, DELETE": "low", "HTTP TRACE is enabled": "medium"}
