# Prompts for claude

# ÇIKTI DİLİ ZORUNLULUĞU
Bu prompt’a verilen tüm yanıtlar, tablolar, açıklamalar, örnekler ve öneriler TÜRKÇE olmalıdır.
Dil değiştirme.

---

# Cloudflare Tunnel Auditor – Derin Teknik Analiz ve Ürün Tasarımı
## Claude (Security Architecture, Threat Modeling & Reasoned Analysis)

Aşağıdaki görevde, sen deneyimli bir:
- Güvenlik mimarı
- Bulut güvenliği analisti
- Tehdit modelleme uzmanı
- Teknik ürün danışmanı

gibi düşünerek hareket et.

Yüzeysel özetlerden kaçın.  
Her başlık altında **neden–sonuç ilişkisi kur**, varsayımlarını belirt ve gerekirse “bu gri bir alan” diyerek açıkça uyar.

---

## 📌 Proje Bağlamı

“Cloudflare Tunnel Auditor” adlı bir araç tasarlanıyor.

Bu aracın amacı:
- Cloudflare Tunnel (`cloudflared`) kullanılan sistemlerde **güvenlik denetimi (audit)** yapmak
- Yanlış yapılandırmaları, zayıf noktaları ve riskli tasarım kararlarını tespit etmek
- Her bulgu için **neden riskli olduğu** ve **nasıl düzeltileceği** bilgisini sunmak
- Çıktı olarak:
  - Risk skoru
  - Denetim kontrol listesi
  - JSON + insan tarafından okunabilir rapor üretmek

### Hedef ortamlar
- Linux sunucular (VM / bare metal)
- Docker tabanlı kurulumlar
- Opsiyonel Kubernetes
- Edge cihazlar (örn. OpenWRT)
- Tunnel üzerinden yayınlanan servisler:
  - HTTP paneller
  - SSH
  - Yönetim arayüzleri

Eğer bu varsayımlardan biri teknik olarak eksik, hatalı veya riskliyse:
- Önce bunu açıkça belirt
- Ardından daha doğru alternatifleri öner

---

## 1️⃣ Cloudflare Tunnel Güvenlik Modeli ve Saldırı Yüzeyi

Cloudflare Tunnel mimarisini aşağıdaki açılardan detaylı analiz et:

- Kimlik doğrulama ve yetkilendirme mekanizmaları
- Sertifika, token ve credential yaşam döngüsü
- Origin sistem ile Cloudflare arasındaki güven sınırı
- Control-plane ve data-plane ayrımı

### Özellikle şu riskleri değerlendir:
- Credential veya token sızıntısı
- Yanlış veya aşırı geniş `ingress` kuralları
- Origin servislerin Tunnel var olmasına rağmen internete açık kalması
- Cloudflare Access / Zero Trust’ın yanlış veya eksik kullanımı
- SSH servislerinin Tunnel üzerinden yayınlanması
- Container ve secret yönetimi hataları

### Çıktı
Aşağıdaki sütunları içeren bir **Tehdit Modeli Tablosu** oluştur:

```

Tehdit | Olası Etki | Gerçekleşme Olasılığı | Nasıl Tespit Edilir | Önerilen Önlem

```

---

## 2️⃣ En Yaygın ve Tehlikeli Yanlış Yapılandırmalar

Cloudflare dokümantasyonu + gerçek dünya kullanım kalıpları üzerinden:

- En az **15 kritik veya sık yapılan yanlış yapılandırma** tespit et
- Her biri için şu başlıkları kullan:

- Bu yapılandırma hatası nedir?
- Neden tehlikelidir?
- Gerçek dünyada nasıl suistimal edilebilir?
- Nasıl tespit edilebilir?
- Güvenli yapılandırma nasıl olmalı?
- Risk seviyesi (Yüksek / Orta / Düşük)

Özellikle:
> “Çoğu kişinin farkında olmadığı ama ciddi risk doğuran” örnekleri vurgula.

---

## 3️⃣ Cloudflare Tunnel Auditor için Kontrol Listesi Tasarımı

Bu aracı sen tasarlıyor olsaydın:

- Hangi güvenlik kontrollerini mutlaka eklersin?
- Hangileri local config analizi ile yapılmalı?
- Hangileri Cloudflare API üzerinden yapılmalı?

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

2. MVP sürüm için **en kritik 20–25 kontrolün** gerekçeli listesi

---

## 4️⃣ Cloudflare API ve Yetkilendirme Stratejisi

Auditor perspektifinden:

- Hangi Cloudflare API grupları gereklidir?
- Least-privilege prensibiyle token nasıl tasarlanmalı?
- Rate limit ve audit log erişim kısıtları nelerdir?
- Auditor’ın **asla yapmaması gereken** işlemler nelerdir?

Gri alanları:
> “Burada dikkat edilmeli” şeklinde açıkça işaretle.

---

## 5️⃣ Risk Skorlama Modeli

Bu denetim aracı için:

- Mantıklı ve teknik bir risk skorlama modeli öner
- Etki, maruziyet ve suistimal edilebilirlik gibi faktörleri kullan
- Bir örnek bulgu üzerinden skorun adım adım nasıl hesaplandığını göster

Nicel düşün, ezbere “yüksek/düşük” deme.

---

## 6️⃣ Raporlama ve Çıktı Tasarımı

Öner:

- JSON rapor yapısı (alanlar ve anlamları)
- İnsan okunur rapor bölümleri (Markdown / PDF mantığı)

Amaç:
> Bu raporu alan bir sistem yöneticisi, ek açıklama istemeden aksiyon alabilsin.

---

## 7️⃣ Benzer Araçlar ve Boşluk Analizi

- Cloudflare Tunnel özelinde denetim yapan bir araç var mı?
- Genel güvenlik tarayıcıları (IaC, posture management vb.) neden bu ihtiyacı tam karşılamıyor?
- Bu projeyi gerçekten değerli kılacak **5 somut fark** öner

---

## ⚠️ Analiz Kuralları

- Emin olmadığın yerde bunu açıkça belirt
- “Best practice” kalıbını sorgula
- Gerekirse “bu gri bir alan” diyerek uyar
- Gereksiz süsleme yapma, derinlikten kaçma
- Kırmızı takım bakışıyla düşün:
  “Ben saldırgan olsam bunu nasıl istismar ederdim?”
