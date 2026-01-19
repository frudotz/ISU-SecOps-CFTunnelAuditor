# Prompts for gemini-pro

Aşağıdaki görevi “Deep Research” standardında ele al: Çok kaynaklı web araştırması yap, iddiaları çapraz doğrula, pratik uygulanabilir teknik öneriler üret, her kritik cümleyi kaynakla destekle ve belirsizlikleri açıkça belirt.

1) Proje Bağlamı (Varsayım Seti)
Ben “Cloudflare Tunnel Auditor” adında bir proje geliştiriyorum. Amaç:

Cloudflare Tunnel (cloudflared) kurulumlarının güvenlik/durum denetimini yapmak
Yanlış yapılandırmaları tespit edip düzeltme önerileri sunmak
Çıktı: rapor (JSON + insan okunur Markdown/PDF), risk skoru, önerilen aksiyon planı
Hedef ortamlar:

Linux sunucular, Docker, Kubernetes (opsiyonel)
OpenWRT gibi edge cihazlar (opsiyonel)
Self-hosted servisler (SSH, HTTP, admin panelleri) tünel üzerinden yayınlanıyor olabilir
Araç muhtemel çalışma şekli:

Yerelde config/log analizi + Cloudflare API üzerinden account/tunnel/route/ingress incelemesi
CIS benzeri hardening checklist yaklaşımı
“High/Medium/Low” risk sınıflaması
Eğer bu varsayımlar yanlışsa, önce hangi kısımların belirsiz olduğunu belirt ve alternatif senaryolar sun.
2) Araştırma Hedefleri (Çok Net Deliverable İstiyorum)
A) Cloudflare Tunnel Güvenlik Yüzeyi Haritası
Cloudflare Tunnel’ın güvenlik modeli: kimlik doğrulama, bağlantı kurulumu, sertifikalar, token/credential türleri
Attack surface: credential sızıntısı, misconfigured ingress, origin exposure, yanlış DNS/route, local service discovery riskleri, log/telemetry riskleri
Tehdit modeli: kötü niyetli dış aktör, compromised workstation, iç kullanıcı hatası, supply-chain (container image), yanlış RBAC
Çıktı: “Threat Model Matrix” tablosu (tehdit → etki → olasılık → tespit sinyalleri → mitigasyon)

B) En Sık Yapılan Yanlış Yapılandırmalar
Cloudflare dokümantasyonu + saha örnekleri + güvenlik blogları üzerinden:

ingress kural hataları (wildcard host, catch-all yanlış yönlendirme, yanlış 404 service, yanlış path)
Origin servislerin internete açık kalması (tünel var ama firewall yok)
cloudflared’ın token/credential saklama hataları
Access / Zero Trust ayarlarının yanlış kullanımı (bypass senaryoları)
SSH yayınlama “en riskli” paternlere örnekler ve doğru yaklaşım
Docker/K8s’te secret yönetimi hataları
Çıktı: En az 15 madde, her madde için:

“Nasıl tespit edilir?” (log, config, API check)
“Neden tehlikeli?”
“Doğru yapılandırma / fix”
“Öncelik” (P0/P1/P2)
C) Auditor için Kontrol Listesi + Otomatik Test Tasarımı
Benim aracım hangi kontrolleri yapmalı? Örnek kategoriler:

Tunnel config (ingress, originRequest, noTLSVerify vs)
Local machine hardening (file permissions, service user, systemd unit)
Cloudflare side (routes, DNS records, Access policies, service tokens, device posture opsiyonları)
Network hardening (origin firewall, allowlist, mTLS opsiyonları)
Observability (log retention, SIEM entegrasyonu, audit trails)
Incident response (credential rotation, revoke, tunnel disable)
Çıktı:

“Auditor Control Catalog” (kategori → kontrol adı → nasıl ölçülür → risk → öneri)
Kontrolleri API ile mi yoksa local parsing ile mi yapılacağına dair karar tablosu
Minimum viable sürüm için öncelikli 25 kontrol
D) Cloudflared Güncel En İyi Pratikler
cloudflared’ın güncel önerilen kurulum biçimleri (token, cert, named tunnel, vs)
Versiyonlama, auto-update riskleri
Docker image güvenliği (official image, digest pinning)
K8s: helm chart / manifest güvenlik noktaları
Çıktı: “Best Practices Cheatsheet” + kaynaklar

E) Rakip/Benzer Araçlar ve Boşluk Analizi
Piyasada Cloudflare Tunnel denetimi yapan araç var mı? (open source/paid)
Yoksa yakın alan: Cloudflare security posture mgmt, IaC scanners (tfsec, checkov) ile tunnel config tarama vb.
Benim aracı farklılaştıracak 5 güçlü özellik öner
Çıktı: Competitive landscape + “Gap & Differentiation” bölümü
3) Teknik Derinlik İstiyorum (Özellikle Bunları İncele)
Cloudflare API endpoint grupları (Zero Trust / Tunnel / DNS / Access) ve gerekli izin kapsamları (scopes)
Rate limit, pagination, audit log erişimi
“Least privilege” için önerilen API token tasarımı
Risk scoring modeli öner: ağırlıklandırma örneği ve puanlama formülü
Çıktı formatı öner: JSON schema + rapor şablonu başlıkları
4) Araştırma Kuralları
Her önemli teknik iddiayı en az 2 bağımsız kaynakla doğrula (mümkünse resmi doküman + güvenilir güvenlik yazısı)
Kaynakları link + kısa alıntı/özet ile ver; tarihlerini belirt
Belirsiz/çelişkili noktaları “Unknown/Disputed” diye işaretle
Mümkünse doğrudan Cloudflare resmi dokümanları önceliklendir
Sonuç bölümünde: “Ne kesin, ne muhtemel, ne belirsiz” ayrımı yap
5) Çıktı Formatı
Aşağıdaki sırayla yaz:

Executive Summary (maks 15 madde)
Threat Model Matrix (tablo)
Misconfiguration Top List (15+ madde)
Auditor Control Catalog (tablo) + MVP 25 kontrol
Best Practices Cheatsheet
API/Permissions Plan (scopes, least privilege, rate limit notları)
Risk Scoring Model (formül + örnek)
Report Output Tasarımı (JSON schema taslağı + Markdown rapor şablonu)
Competitive Landscape & Differentiation
Kaynakça (link + tarih + kısa not)
Başla.
