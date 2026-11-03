import React, { useState } from 'react';
import { AUTHOR, COMPANY, CONTACT_EMAIL, SITE_URL } from '../lib/site';

/*
 * Legal terms for the hosted WebAnalyzer service.
 *
 * Every statement here describes what the code actually does. When behaviour changes
 * (accounts, analytics, new third-party lookups, retention jobs, paid plans), update the
 * matching section and the date below before deploying.
 */
const UPDATED = 'November 3, 2026';
const REPO_URL = 'https://github.com/frkndncr/WebAnalyzer';

const TABS = [
  { id: 'terms', label: 'Terms of Use' },
  { id: 'aup', label: 'Acceptable Use' },
  { id: 'privacy', label: 'Privacy Policy' },
  { id: 'kvkk', label: 'KVKK & GDPR Notice' },
  { id: 'cookies', label: 'Cookie Policy' },
];

const Mail = () => <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>;
const Note = ({ children }) => <div className="note">{children}</div>;
const Header = ({ title, sub }) => (
  <>
    <h2>{title}</h2>
    <div className="updated">{sub ?? `Last updated: ${UPDATED}`}</div>
  </>
);

/** Third-party services that receive the scanned domain (or data derived from it). */
const LOOKUPS = [
  ['crt.sh', 'certificate-transparency search for subdomains and certificates'],
  ['Internet Archive (web.archive.org)', 'historical URLs of the domain'],
  ['AlienVault OTX and HackerTarget', 'passive DNS and subdomain data'],
  ['whois.com and public WHOIS/RDAP servers', 'domain registration data'],
  ['Public DNS resolvers', 'DNS records of the domain'],
  ['OSV and NIST NVD', 'known vulnerabilities, queried with software names and versions found on the target'],
];

// ─────────────────────────────────────────────────────────────────────────────

function Terms() {
  return (
    <div className="legal">
      <Header title="Terms of Use" />
      <p>
        These Terms of Use (the “Terms”) govern your access to and use of the hosted WebAnalyzer service at{' '}
        {SITE_URL}, its API and the reports it produces (together, the “Service”), operated by {AUTHOR} under the
        name {COMPANY} (“we”, “us”). By submitting a scan or otherwise using the Service you accept these Terms and
        the <b>Acceptable Use Policy</b>, which forms part of them. If you do not agree, do not use the Service.
      </p>

      <h3>1. The Service</h3>
      <p>
        WebAnalyzer runs automated reconnaissance and security checks against a domain you submit and presents the
        results in a dashboard and in exportable reports. Some checks are passive (they read public sources such as
        DNS, WHOIS, certificate logs and web archives); others are <b>active</b> and send requests to the target
        (for example port scanning, content and API testing, subdomain-takeover and origin probing). The Service is
        provided free of charge, without user accounts, and may change, be limited or be discontinued at any time.
      </p>

      <h3>2. Authorization is your responsibility</h3>
      <p>
        You may only scan domains and systems that <b>you own or that you are expressly authorized in writing to
        test</b>, and only within the scope and time of that authorization. Accessing or testing a system without
        permission may be a criminal offence, including under Articles 243–244 of the Turkish Penal Code (No. 5237),
        the U.S. Computer Fraud and Abuse Act, the U.K. Computer Misuse Act 1990 and equivalent laws elsewhere. By
        starting a scan you represent that you hold the required authorization. We do not verify authorization
        except where the Service asks you to prove domain control (see section 4), and that check does not replace
        your own legal permission.
      </p>

      <h3>3. Results are shared</h3>
      <p>
        The Service has no private workspaces. <b>Submitted domains and their scan results are stored and are visible
        to every visitor</b> (for example in the recent-scans list, result pages and exported reports) until they are
        replaced by a newer scan or removed. Do not scan a target whose results you are not permitted to disclose,
        and do not submit confidential, internal or personal information. If you need private results, run your own
        copy of the open-source software instead (section 9).
      </p>

      <h3>4. Limits and verification</h3>
      <p>
        To protect third parties and the Service we may rate-limit requests, refuse private, internal or reserved
        targets, disable modules, and require proof of domain control (a DNS TXT record) before active modules run.
        We may refuse, stop or delete any scan, and block access, at our discretion and without notice, in particular
        where we suspect misuse or receive a complaint from a target’s owner.
      </p>

      <h3>5. Accuracy of results</h3>
      <p>
        Results are produced automatically from third-party data and heuristics. They can be incomplete, out of date
        or wrong, including false positives and false negatives. Security scores and findings are indicators, not a
        certification or audit, and are not professional, legal or compliance advice. Verify findings yourself
        before acting on them or sharing them, and present them with that caveat.
      </p>

      <h3>6. Your responsibilities</h3>
      <ul>
        <li>Comply with these Terms, the Acceptable Use Policy and all laws that apply to you and to the target.</li>
        <li>Handle any vulnerability you learn about responsibly: do not exploit it, and report it to the owner
          (see the Acceptable Use Policy).</li>
        <li>You are solely responsible for the scans you start, the reports you generate and how you use or
          publish them.</li>
      </ul>

      <h3>7. Removal requests</h3>
      <p>
        If you own or administer a domain and want its results removed from the Service, email <Mail /> from an
        address at that domain, or tell us so we can confirm control by DNS. We aim to act within 5 business days,
        and sooner for results that expose sensitive information. Removal from the Service does not remove copies
        that others have already exported.
      </p>

      <h3>8. Intellectual property</h3>
      <p>
        You keep any rights you have in the information you submit. You grant us a worldwide, non-exclusive,
        royalty-free licence to store, process, display and include that information and the resulting findings in
        the Service as described in these Terms. The WebAnalyzer name and logo belong to us. Facts about public
        systems are not owned by anyone; reports you export may be used by you in line with these Terms.
      </p>

      <h3>9. Open-source software and self-hosting</h3>
      <p>
        The WebAnalyzer source code is published under the{' '}
        <a href={`${REPO_URL}/blob/main/LICENSE`} target="_blank" rel="noreferrer">MIT License</a> on{' '}
        <a href={REPO_URL} target="_blank" rel="noreferrer">GitHub</a>. That licence, not these Terms, governs the
        code. These Terms cover only the Service we host. If you run your own copy, you are the operator of that
        instance and solely responsible for how it is used, for its legal notices and for the data it processes.
      </p>

      <h3>10. No warranty</h3>
      <p>
        To the maximum extent permitted by law, the Service is provided <b>“as is” and “as available”</b>, without
        any warranty, express or implied, including fitness for a particular purpose, accuracy, availability,
        security or non-infringement. We do not guarantee that the Service is uninterrupted or error-free, or that
        it will find every issue.
      </p>

      <h3>11. Limitation of liability</h3>
      <p>
        To the maximum extent permitted by law, we are not liable for any indirect, incidental, special,
        consequential or punitive damages, or for loss of profits, revenue, data, business or goodwill, arising out
        of or in connection with the Service, the results or their use, even if we were told such damage was
        possible. We are not liable for claims arising from scans you start, from your failure to obtain
        authorization, or from your use or publication of results. Nothing in these Terms excludes or limits
        liability that cannot be excluded or limited by law, including liability for intent or gross negligence
        (Article 115 of the Turkish Code of Obligations No. 6098) or for death or personal injury.
      </p>

      <h3>12. Indemnity</h3>
      <p>
        You will indemnify and hold us harmless from any claim, demand, fine, loss, damage, cost or expense
        (including reasonable legal fees) brought by a third party or authority and arising from your scans, your
        breach of these Terms or of any law, or your use or publication of results.
      </p>

      <h3>13. Changes and termination</h3>
      <p>
        We may update these Terms. The date at the top shows the latest version, and material changes take effect
        when published on this page. Continuing to use the Service after a change means you accept it. You may stop
        using the Service at any time; sections 2, 3, 5 and 7 to 14 survive.
      </p>

      <h3>14. Governing law and disputes</h3>
      <p>
        These Terms are governed by the laws of the Republic of Türkiye, excluding its conflict-of-law rules. The
        courts and enforcement offices of Türkiye have jurisdiction over any dispute. If you use the Service as a
        consumer, nothing in these Terms limits the mandatory rights or remedies available to you under the law of
        your place of residence. If a provision is held invalid, the rest remains in force. Our failure to enforce
        a provision is not a waiver. These Terms and the policies they reference are the entire agreement between
        you and us about the Service; if a translation differs, the English version prevails unless the law
        requires otherwise.
      </p>

      <h3>15. Contact</h3>
      <p>
        {AUTHOR} · {COMPANY} · <Mail /> · {SITE_URL}
      </p>
    </div>
  );
}

function AcceptableUse() {
  return (
    <div className="legal">
      <Header title="Acceptable Use Policy" />
      <p>This policy is part of the Terms of Use. Breaching it may lead to blocked access, deleted scans and reports to the competent authorities.</p>

      <h3>1. Permitted use</h3>
      <ul>
        <li>Assessing domains and systems you own or are authorized in writing to test.</li>
        <li>Authorized bug-bounty work, within the program’s published scope and rules.</li>
        <li>Learning and research on targets that explicitly allow it.</li>
      </ul>

      <h3>2. Prohibited use</h3>
      <ul>
        <li>Scanning, probing or testing any system without authorization, or outside its authorized scope.</li>
        <li>Attempting to exploit, gain access to, disrupt, overload or damage any system, including through denial of service.</li>
        <li>Using results to attack, extort, harass, defame or publicly shame a target or its owner.</li>
        <li>Collecting or using personal data from results (for example names, email addresses or phone numbers) for spam,
          profiling, sale or any purpose other than authorized security work.</li>
        <li>Bypassing or attempting to bypass rate limits, target restrictions or domain verification, including by
          using multiple clients or automated submissions.</li>
        <li>Testing, attacking or reverse-engineering the Service’s own infrastructure. Report suspected
          vulnerabilities in WebAnalyzer instead (section 4).</li>
        <li>Any use that violates applicable law, sanctions or export-control rules.</li>
      </ul>

      <h3>3. Responsible disclosure</h3>
      <p>
        If a scan reveals a weakness in a system you do not own, do not exploit it or disclose its details publicly.
        Report it privately to the owner through their security contact, their <code>security.txt</code> file or their
        bug-bounty program, and give them reasonable time to fix it.
      </p>

      <h3>4. Vulnerabilities in WebAnalyzer</h3>
      <p>
        Report security issues in WebAnalyzer privately to <Mail /> with a description, reproduction steps and the
        potential impact. We acknowledge reports within 48 hours. Good-faith research that follows this policy, avoids
        harm to users and data, and gives us time to fix the issue will not be pursued by us.
      </p>

      <h3>5. Reporting abuse</h3>
      <p>
        If you believe the Service was used against your systems without authorization, email <Mail /> with the domain
        and the approximate time. We will review the case, stop or remove the related scans where appropriate, and
        cooperate with lawful requests from the competent authorities.
      </p>
    </div>
  );
}

function Privacy() {
  return (
    <div className="legal">
      <Header title="Privacy Policy" />
      <p>
        This policy explains what personal data the hosted WebAnalyzer Service at {SITE_URL} processes, why, with whom it
        is shared and what rights you have. The data controller is {AUTHOR} ({COMPANY}), reachable at <Mail />. The
        statutory notice under Turkish and EU law is in the <b>KVKK &amp; GDPR Notice</b> tab.
      </p>

      <h3>1. What we process</h3>
      <ul>
        <li><b>Scan requests:</b> the domain you submit, the modules you select and the time of the request.</li>
        <li><b>Scan results:</b> the technical output for that domain (DNS, certificates, technologies, findings, scores).
          Results can contain personal data of third parties that is already public, such as WHOIS registrant contacts or
          names, email addresses and phone numbers published on the scanned website.</li>
        <li><b>Connection data:</b> for every scan you start, your IP address, any proxy (X-Forwarded-For) chain and your
          browser’s user-agent string. They are used in memory for rate limiting and written to the server’s audit log so misuse
          can be traced. Our application database does not store them.</li>
        <li><b>Browser storage:</b> one local flag that remembers you dismissed the cookie notice (see the Cookie Policy).</li>
      </ul>
      <p>
        There are no user accounts. We do not ask for your name, contact details or payment information, and we do not use
        advertising, analytics or tracking tools.
      </p>

      <h3>2. Why we process it</h3>
      <ul>
        <li>To run the scans you request and show the results (performance of the service you ask for).</li>
        <li>To keep the Service secure and prevent misuse, for example rate limiting and blocking internal targets (our
          legitimate interest).</li>
        <li>To publish security findings about public systems as part of the Service (our legitimate interest in security
          research, balanced by the removal process in section 6).</li>
        <li>To answer requests and meet legal obligations.</li>
      </ul>

      <h3>3. Results are public</h3>
      <p>
        Results are stored in our database and are visible to every visitor of the Service until they are replaced by a newer
        scan of the same domain or removed. Do not submit a domain whose results you are not allowed to make public.
      </p>

      <h3>4. Who receives data</h3>
      <ul>
        <li><b>Data sources queried during a scan.</b> To produce results, the submitted domain (or data derived from it) is
          sent to the target itself and to these services:
          <ul>
            {LOOKUPS.map(([name, why]) => (
              <li key={name}>{name}: {why}</li>
            ))}
          </ul>
          They receive the domain, not your identity: requests come from our servers, not from your browser.
        </li>
        <li><b>Hosting and infrastructure providers</b> that run the dashboard, API and database on our behalf.</li>
        <li><b>Operational notifications.</b> When enabled, the operator receives a message for each scan (via Telegram, Slack
          or a webhook) with the scanned domain, your IP address, your browser’s user-agent string, module status and finding
          counts. These services process the message on our behalf.</li>
        <li><b>Authorities</b>, only where the law requires it or to respond to abuse.</li>
      </ul>
      <p>We do not sell personal data or share it for marketing.</p>

      <h3>5. International transfers</h3>
      <p>
        Our hosting providers and several of the data sources above are located outside Türkiye, including in the European
        Union and the United States. Personal data sent to them is transferred abroad in accordance with Article 9 of KVKK and
        Chapter V of the GDPR.
      </p>

      <h3>6. How long we keep it</h3>
      <ul>
        <li><b>Scan results:</b> until replaced by a newer scan of the same domain, removed on request, or deleted when we clean
          up the Service.</li>
        <li><b>Rate-limit data:</b> in memory only, for the length of the rate-limit window (minutes), and lost on restart.</li>
        <li><b>Audit and hosting logs</b> (including the per-scan IP address, proxy chain and user-agent): for the retention
          period of our hosting provider’s logs, and longer only when needed to investigate or report misuse.</li>
        <li><b>Notification messages:</b> in the operator’s Telegram, Slack or webhook inbox until deleted.</li>
        <li><b>Emails you send us:</b> as long as needed to handle your request and any follow-up.</li>
      </ul>
      <p>
        Domain owners and people whose personal data appears in results can ask us to remove it (see the Terms of Use,
        section 7).
      </p>

      <h3>7. Security</h3>
      <p>
        We use reasonable technical and organizational measures for a free, public service, including transport encryption,
        restricted database access and abuse controls. No system is completely secure, and the results are public by design.
      </p>

      <h3>8. Your rights</h3>
      <p>
        You can ask to access, correct or delete your personal data, restrict or object to its processing, and receive it in a
        portable format, and you can complain to a supervisory authority. Details and how to apply are in the KVKK &amp; GDPR
        Notice. We answer within 30 days.
      </p>

      <h3>9. Children</h3>
      <p>The Service is a professional security tool and is not directed at children under 18.</p>

      <h3>10. Changes</h3>
      <p>We will update this policy and the date above before we change how personal data is processed.</p>
    </div>
  );
}

function Kvkk() {
  return (
    <div className="legal">
      <Header
        title="KVKK & GDPR Notice"
        sub={`Notice under Article 10 of the Turkish Personal Data Protection Law No. 6698 (KVKK) and Articles 13–14 of Regulation (EU) 2016/679 (GDPR) · ${UPDATED}`}
      />

      <h3>1. Data controller</h3>
      <p>
        {AUTHOR} ({COMPANY}), operator of {SITE_URL}. Contact: <Mail />.
      </p>

      <h3>2. Categories of personal data</h3>
      <ul>
        <li><b>Transaction security:</b> IP address, proxy chain, browser user-agent and request time for each scan (rate
          limiting, audit log, abuse prevention, operator notifications).</li>
        <li><b>Customer transaction:</b> submitted domains, selected modules and request times.</li>
        <li><b>Third-party public data in results:</b> WHOIS registrant contacts and names, email addresses and phone numbers
          published on scanned websites.</li>
        <li><b>Communication:</b> the content of emails you send us.</li>
      </ul>

      <h3>3. Purposes and legal grounds</h3>
      <ul>
        <li>Providing the requested scan and its results: necessary for the performance of the service you request
          (KVKK Art. 5(2)(c); GDPR Art. 6(1)(b)).</li>
        <li>Security of the Service and prevention of misuse: our legitimate interests (KVKK Art. 5(2)(f); GDPR Art. 6(1)(f)).</li>
        <li>Publishing security findings that include data already made public by the data subject or registrar: data made
          public by the data subject and our legitimate interests (KVKK Art. 5(2)(d) and (f); GDPR Art. 6(1)(f)).</li>
        <li>Meeting legal obligations and responding to authorities (KVKK Art. 5(2)(ç); GDPR Art. 6(1)(c)), and establishing,
          exercising or defending legal claims (KVKK Art. 5(2)(e)).</li>
      </ul>
      <p>We do not process special categories of personal data and do not make decisions about you by automated means that have legal effects.</p>

      <h3>4. Method of collection</h3>
      <p>
        By automated means: through the dashboard and API when you submit a scan, from your connection, and from public sources
        (DNS, WHOIS, certificate logs, web archives and the scanned website) during the scan.
      </p>

      <h3>5. Recipients and transfers abroad</h3>
      <p>
        Hosting and infrastructure providers, the public data sources listed in the Privacy Policy, operational notification
        services when enabled (Telegram, Slack or a webhook, which receive the per-scan IP address and user-agent), and competent
        authorities where required by law. Some recipients are located outside Türkiye
        (including the EU and the United States); such transfers are made in accordance with KVKK Art. 9 and GDPR Chapter V.
      </p>

      <h3>6. Your rights (KVKK Art. 11; GDPR Arts. 15–22)</h3>
      <ul>
        <li>Learn whether your personal data is processed and, if so, request information about it and its purpose.</li>
        <li>Know the recipients in Türkiye and abroad to whom it is transferred.</li>
        <li>Request correction of incomplete or inaccurate data, and erasure or destruction under KVKK Art. 7 and GDPR Art. 17.</li>
        <li>Request that recipients are notified of a correction or erasure.</li>
        <li>Object to a result against you arising exclusively from automated analysis.</li>
        <li>Claim compensation for damage caused by unlawful processing.</li>
        <li>Under the GDPR, also restrict processing, object to processing based on legitimate interests, and receive your data
          in a portable format.</li>
      </ul>

      <h3>7. How to apply</h3>
      <p>
        Send your request in Turkish or English to <Mail />, stating your name, the domain or data concerned and the right you
        wish to exercise; we may ask for information needed to verify your identity or your control of a domain. Requests are
        answered free of charge within 30 days at the latest (KVKK Art. 13). If the request is rejected, the answer is
        insufficient or we do not reply in time, you may complain to the Turkish Personal Data Protection Board within 30 days of
        our answer and in any case within 60 days of your application (KVKK Art. 14). In the EU or EEA you may also lodge a
        complaint with the supervisory authority of your residence, workplace or the place of the alleged infringement
        (GDPR Art. 77).
      </p>
    </div>
  );
}

function Cookies() {
  return (
    <div className="legal">
      <Header title="Cookie Policy" />
      <p>
        The Service sets <b>no cookies</b> and uses no advertising, analytics or third-party tracking. It stores a single item in
        your browser’s local storage, which is strictly necessary for the interface:
      </p>
      <ul>
        <li>
          <code>wa_cookie_ok</code> (local storage, first party): remembers that you dismissed the storage notice so it is not
          shown again. It contains only the value <code>1</code>, is never sent to our servers, and stays until you clear your
          browser data.
        </li>
      </ul>
      <p>
        Because this item is strictly necessary, it does not require consent. You can delete it at any time in your browser
        settings; the notice will then appear again. Pages that you open from the Service (for example GitHub or a scanned
        website) are governed by their own cookie policies.
      </p>
      <Note>If analytics or other non-essential storage is ever added, this policy will be updated and your consent asked for first.</Note>
    </div>
  );
}

export default function Legal() {
  const [tab, setTab] = useState('terms');
  return (
    <div className="fade">
      <div className="flex wrap" role="tablist" aria-label="Legal documents" style={{ gap: 8, marginBottom: 22 }}>
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={`btn sm ${tab === t.id ? 'primary' : 'ghost'}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === 'terms' && <Terms />}
      {tab === 'aup' && <AcceptableUse />}
      {tab === 'privacy' && <Privacy />}
      {tab === 'kvkk' && <Kvkk />}
      {tab === 'cookies' && <Cookies />}
    </div>
  );
}
