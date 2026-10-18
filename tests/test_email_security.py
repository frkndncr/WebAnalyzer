from modules.plugins import email_security as es


def dns(table):
    return lambda name: table.get(name, [])


class Resp:
    def __init__(self, status=200, body="", headers=None):
        self.status_code, self.content, self.headers = status, body.encode(), headers or {}


def titles(out):
    return {f["title"]: f["severity"] for f in out["findings"]}


GOOD = {
    "example.org": ["v=spf1 include:_spf.mail.test -all"],
    "_spf.mail.test": ["v=spf1 ip4:192.0.2.0/24 -all"],
    "_dmarc.example.org": ["v=DMARC1; p=reject; rua=mailto:d@example.org"],
    "google._domainkey.example.org": ["v=DKIM1; k=rsa; p=MIIB"],
    "_mta-sts.example.org": ["v=STSv1; id=1"],
}


def run(table, mx=("10 mail.example.org.",), get=None):
    return es.email_security("example.org", txt=dns(table), mx=lambda d: list(mx),
                             get=get or (lambda url, method="GET", headers=None: Resp(200, "version: STSv1\nmode: enforce\n")))


def test_a_well_configured_domain_has_no_findings():
    out = run(GOOD)
    assert out["findings"] == [] and out["has_mail"] and out["dkim"]["selectors"] == ["google"]
    assert out["spf"]["lookups"] == 1 and out["mta_sts"]["mode"] == "enforce"


def test_missing_spf_and_dmarc_matter_when_the_domain_has_mail():
    out = run({})
    assert titles(out)["No SPF record"] == "medium" and titles(out)["No DMARC record"] == "medium"


def test_a_domain_without_mail_is_only_a_low_severity_gap():
    out = run({}, mx=("0 .",))
    assert out["has_mail"] is False
    assert titles(out) == {"No SPF record": "low", "No DMARC record": "low"}


def test_spf_qualifiers():
    for record, title, severity in (("v=spf1 +all", "SPF allows every sender (+all)", "high"),
                                    ("v=spf1 ?all", "SPF is neutral (?all)", "medium"),
                                    ("v=spf1 ~all", "SPF uses soft fail (~all)", "low"),
                                    ("v=spf1 ip4:192.0.2.1", "SPF has no 'all' mechanism", "medium")):
        assert titles(run({**GOOD, "example.org": [record]}))[title] == severity


def test_multiple_spf_records_are_reported():
    assert "Multiple SPF records" in titles(run({**GOOD, "example.org": ["v=spf1 -all", "v=spf1 ~all"]}))


def test_spf_lookup_limit_follows_includes():
    includes = " ".join(f"include:s{i}.test" for i in range(11))
    table = {**GOOD, "example.org": [f"v=spf1 {includes} -all"]}
    out = run(table)
    assert titles(out)["SPF exceeds 10 DNS lookups"] == "medium" and out["spf"]["lookups"] > 10


def test_spf_include_loops_do_not_hang():
    table = {**GOOD, "example.org": ["v=spf1 include:a.test -all"], "a.test": ["v=spf1 include:example.org -all"]}
    assert es.count_spf_lookups("example.org", dns(table)) < 10


def test_dmarc_policy_none_and_missing_reports():
    out = run({**GOOD, "_dmarc.example.org": ["v=DMARC1; p=none"]})
    assert titles(out)["DMARC policy is 'none'"] == "medium"
    assert titles(out)["DMARC has no aggregate report address"] == "low"


def test_dmarc_partial_enforcement():
    out = run({**GOOD, "_dmarc.example.org": ["v=DMARC1; p=reject; pct=50; rua=mailto:x@y.z"]})
    assert titles(out) == {"DMARC applies to only part of the mail": "low"}


def test_mta_sts_modes_and_unreachable_policy():
    testing = run(GOOD, get=lambda url, method="GET", headers=None: Resp(200, "mode: testing\n"))
    assert titles(testing) == {"MTA-STS is not enforcing": "low"}
    gone = run(GOOD, get=lambda url, method="GET", headers=None: Resp(404))
    assert titles(gone) == {"MTA-STS policy unreachable": "low"}


def test_a_bad_domain_name_is_refused():
    assert es.email_security("not a domain; rm -rf") == {"error": "not a valid domain name"}
