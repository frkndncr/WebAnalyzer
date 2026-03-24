import React, { useState } from 'react';

const DATA_CLASSES = [
  {
    name: 'SecretFinding', lines: '76-96', hashFields: 'type + source_url + masked_value',
    fields: [
      { name: 'id', type: 'int', desc: 'Benzersiz bulgu numarası' },
      { name: 'type', type: 'str', desc: 'Gizli bilgi türü (ör: AWS Access Key ID)' },
      { name: 'source_url', type: 'str', desc: 'Bulunduğu sayfa/dosya URL' },
      { name: 'line', type: 'int', desc: 'Satır numarası' },
      { name: 'masked_value', type: 'str', desc: 'Maskelenmiş değer (ör: AKIA****WXYZ)' },
      { name: 'raw_length', type: 'int', desc: 'Ham değer uzunluğu' },
      { name: 'entropy', type: 'float', desc: 'Shannon entropi değeri' },
      { name: 'context', type: 'str', desc: 'Çevresel bağlam metni' },
      { name: 'severity', type: 'str', desc: 'Critical / High / Medium / Low' },
      { name: 'confidence', type: 'str', desc: 'HIGH / MEDIUM / LOW' },
      { name: 'risk_score', type: 'float', desc: 'CVSS tabanlı risk puanı (0-10)' },
      { name: 'recommendation', type: 'str', desc: 'Düzeltme önerisi' },
      { name: 'hash', type: 'str', desc: 'Auto-generated deduplikasyon hash' },
    ]
  },
  {
    name: 'JSVulnFinding', lines: '99-120', hashFields: 'type + source_url + matched_code',
    fields: [
      { name: 'id', type: 'int', desc: 'Benzersiz bulgu numarası' },
      { name: 'type', type: 'str', desc: 'Zafiyet türü (DOM XSS, Open Redirect vb.)' },
      { name: 'source_url', type: 'str', desc: 'JS dosyası URL' },
      { name: 'line', type: 'int', desc: 'Satır numarası' },
      { name: 'matched_code', type: 'str', desc: 'Eşleşen zararlı kod parçası' },
      { name: 'code_context', type: 'str', desc: 'Çevresel kod bağlamı' },
      { name: 'taint_chain', type: 'List[str]', desc: 'Taint akış zinciri adımları' },
      { name: 'severity', type: 'str', desc: 'Ciddiyet seviyesi' },
      { name: 'confidence', type: 'str', desc: 'Güven seviyesi' },
      { name: 'risk_score', type: 'float', desc: 'Risk puanı (0-10)' },
      { name: 'description', type: 'str', desc: 'Açıklama' },
      { name: 'recommendation', type: 'str', desc: 'Düzeltme önerisi' },
      { name: 'poc', type: 'str', desc: 'Proof of Concept' },
      { name: 'hash', type: 'str', desc: 'Auto-generated deduplikasyon hash' },
    ]
  },
  {
    name: 'SSRFVulnFinding', lines: '123-144', hashFields: 'type + source_url + sorted(vulnerable_parameters)',
    fields: [
      { name: 'id', type: 'int', desc: 'Benzersiz bulgu numarası' },
      { name: 'type', type: 'str', desc: 'SSRF türü' },
      { name: 'source_url', type: 'str', desc: 'Tespit URL' },
      { name: 'vulnerable_parameters', type: 'List[str]', desc: 'Zafiyet içeren parametreler' },
      { name: 'form_action', type: 'str', desc: 'Form action URL' },
      { name: 'method', type: 'str', desc: 'HTTP metodu' },
      { name: 'confirmed', type: 'bool', desc: 'Doğrulanmış mı?' },
      { name: 'poc', type: 'str', desc: 'Proof of Concept' },
      { name: 'severity / confidence / risk_score', type: '—', desc: 'Standart alanlar' },
      { name: 'hash', type: 'str', desc: 'Auto-generated deduplikasyon hash' },
    ]
  },
  {
    name: 'ActiveVulnFinding', lines: '147-168', hashFields: 'type + source_url + parameter + payload',
    fields: [
      { name: 'id', type: 'int', desc: 'Benzersiz bulgu numarası' },
      { name: 'type', type: 'str', desc: 'Zafiyet türü (SQLi, XSS, SSTI, CORS vb.)' },
      { name: 'source_url', type: 'str', desc: 'Test edilen URL' },
      { name: 'parameter', type: 'str', desc: 'Test edilen parametre' },
      { name: 'payload', type: 'str', desc: 'Kullanılan payload' },
      { name: 'evidence', type: 'str', desc: 'Kanıt' },
      { name: 'cvss_vector', type: 'str', desc: 'CVSS vektör dizesi' },
      { name: 'description / recommendation / poc', type: '—', desc: 'Standart alanlar' },
      { name: 'hash', type: 'str', desc: 'Auto-generated deduplikasyon hash' },
    ]
  },
  {
    name: 'SecurityHeaderFinding', lines: '171-179', hashFields: 'Hash yok — origin bazlı deduplikasyon',
    fields: [
      { name: 'id', type: 'int', desc: 'Benzersiz bulgu numarası' },
      { name: 'type', type: 'str', desc: '"Missing/Weak Security Header"' },
      { name: 'source_url', type: 'str', desc: 'Kontrol edilen URL' },
      { name: 'header_name', type: 'str', desc: 'Başlık adı' },
      { name: 'header_value', type: 'str', desc: 'Mevcut değer veya "(not present)"' },
      { name: 'severity', type: 'str', desc: 'Ciddiyet seviyesi' },
      { name: 'recommendation', type: 'str', desc: 'Önerilen değer' },
    ]
  },
  {
    name: 'ExposedEndpoint', lines: '182-191', hashFields: 'Hash yok — URL+status bazlı',
    fields: [
      { name: 'id', type: 'int', desc: 'Benzersiz bulgu numarası' },
      { name: 'url', type: 'str', desc: 'Endpoint URL' },
      { name: 'status_code', type: 'int', desc: 'HTTP durum kodu' },
      { name: 'content_type', type: 'str', desc: 'Content-Type' },
      { name: 'endpoint_type', type: 'str', desc: 'Tür (Git Exposure, API Docs vb.)' },
      { name: 'severity', type: 'str', desc: 'Ciddiyet seviyesi' },
      { name: 'evidence', type: 'str', desc: 'Kanıt (HTTP kodu + gövde önizleme)' },
      { name: 'recommendation', type: 'str', desc: 'Düzeltme önerisi' },
    ]
  },
];

const DataClassesSection = ({ status, results }) => {
  const [expanded, setExpanded] = useState(null);

  return (
    <div className="acs-section-content">
      <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
        Modül, 6 adet <code>@dataclass</code> ile güvenlik bulgularını yapılandırılmış şekilde saklar. 
        Her bulgu hash ile deduplike edilir — aynı bulgu iki kez kaydedilmez.
      </p>

      {DATA_CLASSES.map((dc, i) => (
        <div key={dc.name} className="acs-dataclass-card" style={{ marginBottom: '1rem' }}>
          <div 
            className="acs-dataclass-header" 
            onClick={() => setExpanded(expanded === i ? null : i)}
            style={{ cursor: 'pointer' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{dc.name}</span>
              <span className="acs-badge" style={{ fontSize: '0.7rem' }}>Satır {dc.lines}</span>
            </div>
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', transform: expanded === i ? 'rotate(180deg)' : 'rotate(0)', transition: '0.2s' }}>▼</span>
          </div>
          
          {expanded === i && (
            <div className="acs-dataclass-body">
              <div style={{ marginBottom: '0.8rem', padding: '0.5rem 0.8rem', background: 'rgba(88, 166, 255, 0.08)', borderRadius: '6px', fontSize: '0.8rem' }}>
                <strong style={{ color: 'var(--accent-purple)' }}>Hash: </strong>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{dc.hashFields}</span>
              </div>
              <table className="acs-table">
                <thead><tr><th>Alan</th><th>Tip</th><th>Açıklama</th></tr></thead>
                <tbody>
                  {dc.fields.map(f => (
                    <tr key={f.name}>
                      <td style={{ fontFamily: 'var(--font-mono)', color: '#a5d6ff' }}>{f.name}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-purple)', fontSize: '0.8rem' }}>{f.type}</td>
                      <td>{f.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}

      {results && (
        <div className="acs-results-box">
          <h4>Sonuçlar</h4>
          <pre className="json-view">{JSON.stringify(results, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

DataClassesSection.meta = {
  id: 'data_classes',
  title: 'Veri Sınıfları',
  icon: '🏗️',
  layer: 'CORE',
  description: '6 data class yapısı, alan tanımları, hash deduplikasyon mekanizması',
  docFile: '02-veri-siniflari.md',
};

export default DataClassesSection;
