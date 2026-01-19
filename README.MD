# 🛡️ Cloudflared Tunnel Auditor  

Cloudflared Tunnel Auditor, bir sistemde çalışan **Cloudflare Tunnel (cloudflared)** yapılandırmalarını  
**güvenlik, sürdürülebilirlik ve yanlış yapılandırma riskleri** açısından analiz eden, odak noktası “çalışıyor mu?” değil  
**“güvenli mi, kontrol altında mı?”** olan bir **audit aracıdır**.  

Bu proje, özellikle fark edilmeden üretime taşınan hatalı Cloudflare Tunnel kurulumlarını görünür kılmayı hedefler.

# 🌟 Özellikler

- **Tunnel Türü Analizi**
  - Named Tunnel
  - Quick Tunnel / `trycloudflare`
  - Geçici ve belirsiz oturumlar

- **Kimlik & Yetkilendirme Denetimi**
  - `cert.pem` varlığı ve konumu
  - `credentials-file` kullanımı
  - Tunnel–credential uyumsuzlukları

- **Yapılandırma Kontrolleri**
  - `config.yml / config.yaml` tespiti
  - Parse edilebilirlik kontrolleri
  - Riskli veya hard-coded path kullanımı

- **Çalışma ve Servis Durumu**
  - cloudflared process kontrolü
  - systemd servis denetimi
  - Manuel başlatılmış süreçler
  - Reboot sonrası ayağa kalkabilirlik

- **Exposure (Dışa Açıklık) Analizi**
  - HTTP / HTTPS / SSH / TCP servisleri
  - Localhost dışı riskli binding’ler
  - Gereksiz dışa açık servisler

- **Severity Tabanlı Raporlama**
  - CRITICAL / WARN / INFO ayrımı
  - Sessiz riskleri açık ve net şekilde işaretleme

# 🎯 Projenin Amacı

Cloudflared Tunnel Auditor;

- Yanlış veya eksik yapılandırmaları **erken aşamada yakalamak**
- Quick Tunnel gibi **üretim için riskli kullanım alışkanlıklarını** ortaya çıkarmak
- Sertifika, credential ve servis yönetimi kaynaklı **sessiz güvenlik açıklarını** görünür kılmak
- Tek seferlik script değil, **sürekli denetlenebilir bir kontrol noktası** sunmak

amacıyla geliştirilmiştir.

# 🧠 Çıktı Mantığı (Severity Model)

Denetim sonuçları önem seviyesine göre raporlanır:

- **CRITICAL**  
  Üretim ortamı için ciddi güvenlik, erişim veya sürdürülebilirlik riski

- **WARN**  
  Potansiyel problem, teknik borç veya yanlış yapılandırma alışkanlığı

- **INFO**  
  Bilgilendirme, iyi uygulama notları veya düşük riskli durumlar

Amaç korkutmak değil, **bilinçli karar aldırmak**tır.

# 🧩 Tasarım Felsefesi

- Otomatik ama kör değil  
- “Her şey yolunda” demek yerine **neden yolunda olduğunu** açıklar  
- Gri alanları gizlemez, **açıkça uyarır**  
- Minimal bağımlılık, maksimum okunabilirlik  
- Denetlenen sistem hakkında **şeffaf ve yorumlanabilir çıktı** üretir  

# ⚠️ Önemli Notlar

- Bu araç **Cloudflare Tunnel güvenliğini garanti etmez**
- Mevcut yapılandırmanın **risk profilini** analiz eder
- Quick Tunnel kullanımı otomatik olarak hata sayılmaz  
  ancak **üretim ortamı için yüksek risk** olarak işaretlenir

# 📂 Dosya Yapısı

```

/cloudflared-tunnel-auditor
├── docs/                   # Proje dökümantasyonu ve rehberler
├── researchs/              # Derin araştırma çıktıları
├── specs/                  # Teknik analizler
└── src/                    # Script kaynak kodları
    └── auditor.sh          # Scriptin kendisi

```

# 👥 Hedef Kitle

- Sistem yöneticileri  
- Self-hosted servis sahipleri  
- ISP / Network mühendisleri  
- Home-lab kullanıcıları  
- “Cloudflared çalışıyor ama içim rahat mı?” diyen herkes  

# 📝 Lisans & Sorumluluk Reddi

Bu araç **bilgilendirme ve denetim** amacıyla sunulur, GPL-3.0 lisansıyla lisanslanmıştır.  
Yanlış yapılandırmalardan veya alınan aksiyonlardan doğabilecek sonuçların sorumluluğu kullanıcıya aittir.

# 🤝 Katkıda Bulun / Bağış
  - Yanlış gördüğünüz veya eklemek istediğiniz şeyleri PR/Issue açarak iletebilirsiniz.  
  - Faydalı bulduysanız [🍻 bir bira ısmarlayarak](https://coff.ee/frudotz) bana destek olabilirsiniz.
   
-----------
🎀 Vakit ayırdığınız için teşekkür ederiz!  
⭐ İçeriği faydalı bulduysanız desteklemek için **Star** verebilirsiniz.  
