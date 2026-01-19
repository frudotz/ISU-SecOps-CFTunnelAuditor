# Prompts for chatgpt

# Cloudflare Tunnel Auditor – Master Prompt

Aşağıdaki projeyi, yüzeysel anlatım yapmadan; **güvenlik mimarisi**, **tehdit modelleme**, **yanlış yapılandırma analizi** ve **ürün tasarımı** perspektifleriyle ele al.

---

## 📌 Proje Tanımı

“Cloudflare Tunnel Auditor” adında bir araç geliştiriyorum. Amaç:

- Cloudflare Tunnel (`cloudflared`) kullanılan sistemlerde **güvenlik denetimi (audit)** yapmak  
- Yanlış yapılandırmaları, riskleri ve zayıf noktaları tespit etmek  
- Teknik olarak **nasıl düzeltileceğini** net ve uygulanabilir şekilde sunmak  
- Çıktı olarak: **risk skoru**, **kontrol listesi**, **JSON + insan okunur rapor** üretmek  

### 🎯 Hedef Ortamlar
- Linux sunucular (bare metal / VM)
- Docker ve opsiyonel Kubernetes
- Edge cihazlar (ör. OpenWRT)
- Tunnel üzerinden yayınlanan servisler:
  - HTTP paneller
  - SSH
  - Admin arayüzleri

> Varsayımlar hatalıysa, önce bunu belirt ve **alternatif senaryolar** üret.

---

## 1️⃣ Tehdit Modeli & Güvenlik Yüzeyi

Cloudflare Tunnel’ın aşağıdaki bileşenlerini detaylı analiz et:

- Kimlik doğrulama modeli
- Sertifika / token / credential yapısı
- Origin – Cloudflare arasındaki güvenlik sınırları

### Özellikle İncelenecek Riskler
- Credential sızıntısı
- Yanlış `ingress` tanımları
- Origin servislerin internete açık kalması
- Cloudflare Access / Zero Trust yanlış kullanımı
- SSH publish riskleri
- Container & secret yönetimi hataları

### Çıktı
Aşağıdaki sütunları içeren bir tablo oluştur:

Tehdit | Etki | Olasılık | Tespit Yöntemi | Mitigasyon

---

## 2️⃣ En Yaygın Yanlış Yapılandırmalar (Gerçekçi ve Sert)

Cloudflare resmi dokümanları + saha örnekleri yaklaşımıyla:

- En az **15 kritik misconfiguration** listele
- Her biri için şu başlıkları kullan:

- Nasıl tespit edilir?
- Neden tehlikelidir?
- Doğru yapılandırma nasıl olmalı?
- Öncelik seviyesi (High / Medium / Low)

> “Çok sık görülür ama genelde konuşulmaz” olan detayları özellikle vurgula.

---

## 3️⃣ Auditor Kontrol Listesi Tasarımı

Bu aracı sen yazıyor olsaydın:

- Hangi kontrolleri eklersin?
- Hangileri **local config parsing** ile yapılmalı?
- Hangileri **Cloudflare API** üzerinden yapılmalı?

### Kategoriler
- Tunnel & ingress config
- Cloudflare Access / Zero Trust
- API token & permission scope
- Local sistem hardening
- Network isolation & firewall
- Loglama & incident response

### Çıktı
- **Auditor Control Catalog** (tablo)
- MVP için **en kritik 20–25 kontrol**

---

## 4️⃣ Cloudflare API & Yetkilendirme Stratejisi

Aşağıdakileri analiz et:

- Gerekli API endpoint grupları
- Least-privilege için token tasarımı
- Rate limit ve audit log erişimi riskleri
- Auditor’ın **kesinlikle yapmaması gereken** işlemler

> Gri alanları açıkça **“Dikkat”** olarak işaretle.

---

## 5️⃣ Risk Skorlama Modeli

Auditor için:

- Mantıklı bir risk puanlama formülü öner
- Ağırlıklandırma örneği ver
- Tek bir örnek bulgu üzerinden skor hesaplamasını göster

> Marketing dili kullanma, **mühendis kafasıyla** anlat.

---

## 6️⃣ Rapor & Çıktı Tasarımı

Öneriler üret:

- JSON output schema (örnek alanlar)
- İnsan okunur rapor başlıkları (Markdown / PDF mantığı)

Amaç:
> Bu rapor bir sysadmin’e verildiğinde **aksiyon aldırabilmeli**.

---

## 7️⃣ Benzer Araçlar & Boşluk Analizi

- Cloudflare Tunnel özelinde audit yapan araç var mı?
- Yakın alan araçları (IaC scanner, posture management vb.) neden yetersiz?
- Bu projeyi **gerçekten farklılaştıracak** 5 özellik öner

---

## ⚠️ Çalışma Kuralları

- Emin olmadığın yerde bunu açıkça belirt
- “Best practice” diye ezber konuşma
- Gerekirse “bu gri bir alan” de
- Gereksiz süsleme yapma, teknik derinlikten kaçma
- Kırmızı takım bakışıyla düşün:
  > “Ben saldırgan olsam bunu nasıl suistimal ederdim?”
