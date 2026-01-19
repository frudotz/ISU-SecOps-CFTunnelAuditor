# Prompts for deepseek

# ÇIKTI DİLİ VE FORMAT ZORUNLULUĞU
Bu prompt’a verilecek TÜM yanıtlar:
- Tamamen TÜRKÇE olmalıdır
- GitHub Markdown formatına uygun olmalıdır
- Başlıklar, tablolar ve madde işaretleri düzenli kullanılmalıdır
- Dil değiştirilmemelidir

---

# Cloudflare Tunnel Auditor – Derin Teknik Analiz ve Güvenlik Denetimi
## DeepSeek (Analitik Akıl Yürütme ve Sistematik İnceleme)

Aşağıdaki görevi yerine getirirken sen deneyimli bir:
- Güvenlik mimarı
- Bulut altyapı uzmanı
- Tehdit modelleme analisti
- Teknik ürün tasarımcısı

gibi düşün.

Yüzeysel özetlerden kaçın.  
Her başlık altında **neden–sonuç ilişkisi kur**, teknik varsayımlarını açıkça belirt ve belirsiz alanları “bu gri bir alan” şeklinde dürüstçe işaretle.

---

## 📌 Proje Tanımı

“Cloudflare Tunnel Auditor” adında bir güvenlik denetim aracı tasarlanıyor.

Bu aracın amaçları:
- Cloudflare Tunnel (`cloudflared`) kullanılan sistemlerde **güvenlik denetimi (audit)** yapmak
- Yanlış yapılandırmaları, zayıf noktaları ve riskli mimari kararları tespit etmek
- Her bulgu için:
  - Neden riskli olduğunu
  - Gerçek dünyada nasıl istismar edilebileceğini
  - Nasıl düzeltileceğini
  net şekilde açıklamak
- Çıktı olarak:
  - Risk skoru
  - Denetim kontrol listesi
  - JSON + insan tarafından okunabilir (Markdown/PDF) rapor üretmek

### Hedef ortamlar
- Linux sunucular (VM / bare metal)
- Docker tabanlı kurulumlar
- Opsiyonel Kubernetes
- Edge cihazlar (ör. OpenWRT)
- Tunnel üzerinden yayınlanan servisler:
  - HTTP paneller
  - SSH
  - Yönetim / admin arayüzleri

Eğer bu varsayımlar teknik olarak hatalı, eksik veya riskliyse:
- Önce bunu açıkça belirt
- Ardından daha doğru alternatifleri öner

---

## 1️⃣ Cloudflare Tunnel Güvenlik Modeli ve Saldırı Yüzeyi

Cloudflare Tunnel mimarisini şu açılardan **derinlemesine** analiz et:

- Kimlik doğrulama ve yetkilendirme mekanizmaları
- Sertifika, token ve credential yönetimi
- Origin sistem ile Cloudflare arasındaki güven sınırı
- Control-plane ve data-plane ayrımı

### Özellikle değerlendir:
- Credential veya token sızıntısı senaryoları
- Yanlış veya aşırı geniş `ingress` tanımları
- Tunnel kullanılsa bile origin servislerin internete açık kalması
- Cloudflare Access / Zero Trust yapılandırma hataları
- SSH servislerinin Tunnel üzerinden yayınlanmasının riskleri
- Container ve secret yönetimi problemleri

### Çıktı
Aşağıdaki sütunları içeren bir **Tehdit Modeli Tablosu** oluştur:

```

Tehdit | Olası Etki | Gerçekleşme Olasılığı | Nasıl Tespit Edilir | Önerilen Önlem

```

---

## 2️⃣ En Yaygın ve Tehlikeli Yanlış Yapılandırmalar

Cloudflare dokümantasyonu + gerçek dünya kullanım pratikleri üzerinden:

- En az **15 kritik veya sık yapılan yanlış yapılandırma** tespit et
- Her biri için aşağıdaki başlıkları kullan:

- Bu yapılandırma hatası nedir?
- Neden tehlikelidir?
- Gerçek dünyada nasıl istismar edilebilir?
- Nasıl tespit edilir?
- Güvenli yapılandırma nasıl olmalıdır?
- Risk seviyesi (Yüksek / Orta / Düşük)

Özellikle:
> “Çoğu kişinin fark etmediği ama yüksek etki doğuran” örnekleri vurgula.

---

## 3️⃣ Cloudflare Tunnel Auditor için Kontrol Listesi Tasarımı

Bu aracı sen tasarlıyor olsaydın:

- Hangi güvenlik kontrollerini mutlaka eklersin?
- Hangileri **local config analizi** ile yapılmalı?
- Hangileri **Cloudflare API** üzerinden yapılmalı?

### Kontrol kategorileri
- Tunnel ve ingress yapılandırmaları
- Cloudflare Access / Zero Trust politikaları
- API token ve yetki kapsamları
- Local sistem hardening
- Network izolasyonu ve firewall
- Loglama, izleme ve olay müdahalesi

### Çıktı
1. **Auditor Kontrol Kataloğu** tablosu:
```

Kategori | Kontrol Adı | Denetim Yöntemi (Local/API) | Ele Alınan Risk | Öneri

```

2. MVP sürüm için **en kritik 20–25 kontrolün**, neden gerekli olduklarını açıklayan listesi

---

## 4️⃣ Cloudflare API ve Yetkilendirme Stratejisi

Auditor perspektifinden şu soruları yanıtla:

- Hangi Cloudflare API grupları gereklidir?
- Least-privilege prensibiyle API token nasıl tasarlanmalı?
- Rate limit ve audit log erişimi hangi riskleri doğurur?
- Auditor’ın **asla yapmaması gereken** işlemler nelerdir?

Gri alanları açıkça:
> “Bu noktada dikkat edilmeli”  
şeklinde işaretle.

---

## 5️⃣ Risk Skorlama Modeli

Bu denetim aracı için:

- Mantıklı, teknik ve gerekçeli bir risk skorlama modeli öner
- Etki, maruziyet ve istismar edilebilirlik faktörlerini kullan
- Tek bir örnek bulgu üzerinden skorun **adım adım** nasıl hesaplandığını göster

Nitel değil, mümkün olduğunca **nicel düşün**.

---

## 6️⃣ Raporlama ve Çıktı Tasarımı

Öneriler üret:

- JSON rapor yapısı (alanlar ve anlamları)
- İnsan tarafından okunabilir rapor bölümleri (Markdown / PDF)

Amaç:
> Bu raporu alan bir sistem yöneticisi, ek açıklamaya ihtiyaç duymadan aksiyon alabilsin.

---

## 7️⃣ Benzer Araçlar ve Boşluk Analizi

- Cloudflare Tunnel özelinde denetim yapan bir araç var mı?
- Genel güvenlik araçları (IaC tarayıcıları, posture management vb.) neden bu ihtiyacı tam karşılamıyor?
- Bu projeyi gerçekten değerli ve farklı kılacak **5 somut özellik** öner

---

## ⚠️ Analiz Kuralları

- Emin olmadığın yerde bunu açıkça belirt
- Ezbere “best practice” tekrarlama
- Gerekirse “bu gri bir alan” diyerek uyar
- Gereksiz süsleme yapma, teknik derinlikten kaçma
- Kırmızı takım bakışıyla düşün:
  “Ben saldırgan olsam bunu nasıl istismar ederdim?”
