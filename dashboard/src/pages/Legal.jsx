import React, { useState } from 'react';
import { AUTHOR, COMPANY, CONTACT_EMAIL, SITE_URL } from '../lib/site';

const UPDATED = 'October 11, 2026';
const TABS = [
  { id: 'privacy', label: 'Privacy Policy' },
  { id: 'kvkk', label: 'KVKK & GDPR Notice' },
  { id: 'terms', label: 'Terms of Use' },
  { id: 'cookies', label: 'Cookie Policy' },
];

const Disclaimer = ({ children }) => <div className="note">{children}</div>;

function Privacy() {
  return (
    <div className="legal">
      <h2>Privacy Policy</h2>
      <div className="updated">Last updated: {UPDATED}</div>
      <p>
        {COMPANY} (“we”) operates the WebAnalyzer platform at {SITE_URL}. This policy explains what
        data we process when you use it, why, and what rights you have.
      </p>

      <h3>1. Data we process</h3>
      <ul>
        <li><b>Scan inputs:</b> the domain names you submit and the modules you select.</li>
        <li><b>Scan results:</b> the technical output produced for those domains, stored so you can revisit it.</li>
        <li><b>Technical data:</b> IP address, browser type and access time, used for security and rate limiting.</li>
        <li><b>Local storage:</b> a single flag remembering your cookie notice choice.</li>
      </ul>
      <p>We do not ask for names, phone numbers, government IDs or payment details, and we do not run advertising or analytics trackers.</p>

      <h3>2. Why we process it</h3>
      <ul>
        <li>To run the analysis you request and show you the results.</li>
        <li>To keep the service secure and prevent abuse (rate limiting, blocking internal targets).</li>
        <li>To maintain and improve the platform.</li>
      </ul>

      <h3>3. Storage and sharing</h3>
      <p>
        Scan results are kept for as long as needed to operate the service. We do not sell your data or
        share it with third parties for marketing. Data may be disclosed to the competent authorities only
        where the law requires it.
      </p>

      <h3>4. Your rights</h3>
      <p>
        You may ask what data we hold about you, request correction or deletion, and object to processing.
        Write to <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> and we will respond within 30 days.
      </p>

      <Disclaimer>
        This text is a general-purpose template and is not legal advice. Have a qualified lawyer review it
        before relying on it for a commercial or enterprise deployment.
      </Disclaimer>
    </div>
  );
}

function Kvkk() {
  return (
    <div className="legal">
      <h2>KVKK &amp; GDPR Notice</h2>
      <div className="updated">
        Under Turkish Personal Data Protection Law No. 6698 (KVKK) and Regulation (EU) 2016/679 (GDPR) · {UPDATED}
      </div>
      <p>
        This notice is provided in line with Article 10 of KVKK and Articles 13–14 of the GDPR by the data
        controller named below.
      </p>

      <h3>1. Data controller</h3>
      <p>{AUTHOR} / {COMPANY} — contact: <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a></p>

      <h3>2. Personal data and purposes</h3>
      <ul>
        <li><b>Transaction-security data</b> (IP address, access logs): to secure the service and meet legal obligations.</li>
        <li><b>Usage data</b> (submitted domains, selected modules): to deliver the analysis you request.</li>
      </ul>

      <h3>3. Legal basis (KVKK Art. 5 / GDPR Art. 6)</h3>
      <p>
        Processing is necessary to provide the requested service, is based on our legitimate interest in
        keeping the platform secure, and is required to meet legal obligations.
      </p>

      <h3>4. Your rights (KVKK Art. 11 / GDPR Arts. 15–21)</h3>
      <ul>
        <li>Learn whether your personal data is processed and request information about it.</li>
        <li>Request correction or erasure of your data.</li>
        <li>Request restriction of processing, or object to it.</li>
        <li>Lodge a complaint with the Turkish Personal Data Protection Authority (KVKK) or your local EU supervisory authority.</li>
      </ul>
      <p>Send requests to the contact address above.</p>

      <Disclaimer>
        This is an informational template, not legal advice. It should be reviewed by a qualified lawyer
        before the platform is used in a commercial setting.
      </Disclaimer>
    </div>
  );
}

function Terms() {
  return (
    <div className="legal">
      <h2>Terms of Use</h2>
      <div className="updated">Last updated: {UPDATED}</div>

      <h3>1. Authorized use only</h3>
      <p>
        WebAnalyzer may only be used on systems that you <b>own or have explicit written permission to
        test</b>. Unauthorized security testing is illegal in many jurisdictions.
      </p>

      <h3>2. No warranty and limitation of liability</h3>
      <p>
        The platform is provided “as is”. {COMPANY} is not liable for any damage resulting from its use or
        misuse. If you discover a vulnerability, follow responsible-disclosure practices.
      </p>

      <h3>3. Acceptable use</h3>
      <ul>
        <li>Respect rate limits and the terms of the systems you test.</li>
        <li>Do not use the service to harm third parties.</li>
        <li>Comply with the laws that apply to you.</li>
      </ul>

      <h3>4. Open source</h3>
      <p>
        WebAnalyzer is open source under the MIT license. The source code is available on{' '}
        <a href="https://github.com/frkndncr/WebAnalyzer" target="_blank" rel="noreferrer">GitHub</a>.
      </p>

      <Disclaimer>These terms are a template and are not a substitute for legal advice.</Disclaimer>
    </div>
  );
}

function Cookies() {
  return (
    <div className="legal">
      <h2>Cookie Policy</h2>
      <div className="updated">Last updated: {UPDATED}</div>
      <p>
        WebAnalyzer only uses <b>strictly necessary</b> browser storage so the interface works. There are no
        advertising, marketing or third-party analytics cookies.
      </p>

      <h3>What we store</h3>
      <ul>
        <li><b>Cookie notice choice</b> — a single localStorage flag so the banner is not shown again.</li>
        <li><b>Analytics / marketing</b> — none.</li>
      </ul>
      <p>You can clear this storage in your browser settings at any time; only the notice choice is reset.</p>

      <Disclaimer>If analytics or marketing cookies are ever added, this policy and the consent flow must be updated first.</Disclaimer>
    </div>
  );
}

export default function Legal() {
  const [tab, setTab] = useState('privacy');
  return (
    <div className="fade">
      <div className="flex wrap" style={{ gap: 8, marginBottom: 22 }}>
        {TABS.map((t) => (
          <button key={t.id} className={`btn sm ${tab === t.id ? 'primary' : 'ghost'}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === 'privacy' && <Privacy />}
      {tab === 'kvkk' && <Kvkk />}
      {tab === 'terms' && <Terms />}
      {tab === 'cookies' && <Cookies />}
    </div>
  );
}
