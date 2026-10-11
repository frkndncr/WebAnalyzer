import React, { useState } from 'react';
import { AUTHOR, COMPANY, CONTACT_EMAIL, SITE_URL } from '../lib/site';

const UPDATED = '11 Ekim 2026';
const TABS = [
  { id: 'privacy', label: 'Gizlilik Politikası' },
  { id: 'kvkk', label: 'KVKK Aydınlatma Metni' },
  { id: 'terms', label: 'Kullanım Şartları' },
  { id: 'cookies', label: 'Çerez Politikası' },
];

function Privacy() {
  return (
    <div className="legal">
      <h2>Gizlilik Politikası</h2>
      <div className="updated">Son güncelleme: {UPDATED}</div>
      <p>
        {COMPANY} (“biz”) olarak, WebAnalyzer platformunu ({SITE_URL}) kullanımınız sırasında
        gizliliğinize önem veriyoruz. Bu politika, hangi verileri işlediğimizi, nasıl
        kullandığımızı ve haklarınızı açıklar.
      </p>

      <h3>1. İşlenen Veriler</h3>
      <ul>
        <li><b>Tarama girdileri:</b> Analiz için girdiğiniz alan adları ve seçtiğiniz modüller.</li>
        <li><b>Teknik veriler:</b> IP adresi, tarayıcı türü ve erişim zamanı (güvenlik ve hız sınırlama amacıyla).</li>
        <li><b>Çerezler:</b> Yalnızca oturum tercihleri için zorunlu çerezler; pazarlama çerezi kullanmıyoruz.</li>
      </ul>
      <p>Platform üzerinden ad, telefon, kimlik veya ödeme bilgisi talep etmiyoruz.</p>

      <h3>2. Kullanım Amaçları</h3>
      <ul>
        <li>Talep ettiğiniz güvenlik analizini gerçekleştirmek,</li>
        <li>Hizmetin güvenliğini sağlamak ve kötüye kullanımı önlemek,</li>
        <li>Platformu iyileştirmek ve hataları gidermek.</li>
      </ul>

      <h3>3. Saklama ve Paylaşım</h3>
      <p>
        Tarama sonuçları hizmetin çalışması için gereken süre boyunca saklanır. Verilerinizi
        üçüncü taraflarla pazarlama amacıyla <b>paylaşmayız</b>; yalnızca yasal yükümlülük
        halinde yetkili mercilerle paylaşılabilir.
      </p>

      <h3>4. Haklarınız</h3>
      <p>
        İşlenen verileriniz hakkında bilgi talep etme, düzeltme veya silme haklarınızı kullanmak
        için <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> adresine yazabilirsiniz.
      </p>

      <div className="note">
        Bu metin bilgilendirme amaçlı bir şablondur ve bağlayıcı hukuki görüş niteliği taşımaz.
        Yayına almadan önce bir hukuk danışmanına inceletmeniz önerilir.
      </div>
    </div>
  );
}

function Kvkk() {
  return (
    <div className="legal">
      <h2>KVKK Aydınlatma Metni</h2>
      <div className="updated">6698 sayılı Kişisel Verilerin Korunması Kanunu kapsamında · {UPDATED}</div>
      <p>
        Bu aydınlatma metni, 6698 sayılı Kişisel Verilerin Korunması Kanunu’nun (“KVKK”) 10.
        maddesi uyarınca veri sorumlusu sıfatıyla {AUTHOR} / {COMPANY} tarafından hazırlanmıştır.
      </p>

      <h3>1. Veri Sorumlusu</h3>
      <p>{AUTHOR} / {COMPANY} — İletişim: <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a></p>

      <h3>2. İşlenen Kişisel Veriler ve Amaç</h3>
      <ul>
        <li><b>İşlem güvenliği verileri</b> (IP adresi, erişim kayıtları): hizmet güvenliği ve hukuki yükümlülüklerin yerine getirilmesi amacıyla.</li>
        <li><b>Kullanım verileri</b> (girilen alan adları, seçilen modüller): talep ettiğiniz analizin sunulması amacıyla.</li>
      </ul>

      <h3>3. Hukuki Sebep (KVKK m.5)</h3>
      <p>
        Verileriniz; bir hizmetin ifası için gerekli olması, veri sorumlusunun meşru menfaati ve
        hukuki yükümlülüklerin yerine getirilmesi hukuki sebeplerine dayanılarak işlenmektedir.
      </p>

      <h3>4. İlgili Kişinin Hakları (KVKK m.11)</h3>
      <p>
        Kişisel verilerinizin işlenip işlenmediğini öğrenme, bilgi talep etme, düzeltilmesini veya
        silinmesini isteme ve işlemenin kısıtlanmasını talep etme haklarına sahipsiniz. Başvurularınızı
        yukarıdaki iletişim adresine iletebilirsiniz.
      </p>

      <div className="note">
        Bu metin örnek bir KVKK aydınlatma şablonudur. Kurumsal yayına almadan önce mutlaka bir
        hukuk danışmanı tarafından gözden geçirilmelidir.
      </div>
    </div>
  );
}

function Terms() {
  return (
    <div className="legal">
      <h2>Kullanım Şartları</h2>
      <div className="updated">Son güncelleme: {UPDATED}</div>

      <h3>1. Yetkili Kullanım</h3>
      <p>
        WebAnalyzer, yalnızca <b>sahibi olduğunuz veya test etmek için açık yazılı izne sahip
        olduğunuz</b> sistemlerde kullanılabilir. İzinsiz güvenlik testi birçok ülkede suç teşkil eder.
      </p>

      <h3>2. Sorumluluğun Sınırlandırılması</h3>
      <p>
        Platform “olduğu gibi” sunulur. Aracın kullanımından veya kötüye kullanımından doğabilecek
        zararlardan {COMPANY} sorumlu tutulamaz. Keşfedilen zafiyetlerde sorumlu ifşa (responsible
        disclosure) ilkelerine uymanız beklenir.
      </p>

      <h3>3. Kabul Edilebilir Kullanım</h3>
      <ul>
        <li>Hız sınırlarına ve hizmet şartlarına saygı gösterin.</li>
        <li>Üçüncü taraflara zarar verecek şekilde kullanmayın.</li>
        <li>Yürürlükteki yasalara uyun.</li>
      </ul>

      <h3>4. Açık Kaynak</h3>
      <p>
        WebAnalyzer MIT lisansı altında açık kaynaktır. Kaynak kodu
        {' '}<a href="https://github.com/frkndncr/WebAnalyzer" target="_blank" rel="noreferrer">GitHub</a>
        {' '}üzerinden erişilebilir.
      </p>

      <div className="note">
        Bu şartlar örnek niteliğindedir ve hukuki görüş yerine geçmez.
      </div>
    </div>
  );
}

function Cookies() {
  return (
    <div className="legal">
      <h2>Çerez Politikası</h2>
      <div className="updated">Son güncelleme: {UPDATED}</div>
      <p>
        WebAnalyzer yalnızca platformun çalışması için gerekli olan <b>zorunlu çerezleri</b> ve
        tarayıcı yerel depolamasını (ör. tema/sekme tercihi, çerez onayınız) kullanır.
      </p>
      <h3>Kullanılan Depolama Türleri</h3>
      <ul>
        <li><b>Zorunlu:</b> Oturum ve arayüz tercihlerini hatırlamak için (localStorage).</li>
        <li><b>Analitik/Pazarlama:</b> Kullanılmıyor. Üçüncü taraf takip çerezi yoktur.</li>
      </ul>
      <p>
        Tarayıcı ayarlarınızdan yerel depolamayı dilediğiniz zaman temizleyebilirsiniz; bu durumda
        yalnızca tercihleriniz sıfırlanır.
      </p>
      <div className="note">
        Pazarlama veya üçüncü taraf analitik çerezleri eklenirse bu politika ve çerez onay akışı
        güncellenmelidir.
      </div>
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
