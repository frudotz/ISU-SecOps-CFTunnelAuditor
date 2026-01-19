# Risk ve Önem Derecesi Modeli (Severity Model)

Bulgular, potansiyel etkilerine göre üç ana kategoriye ayrılır:

| Seviye | Tanım | Örnek Durum |
| :--- | :--- | :--- |
| **CRITICAL** | Doğrudan veri sızıntısı veya yetkisiz erişim riski. | `cert.pem` dosyasının herkes tarafından okunabilir olması (777). |
| **WARN** | En iyi uygulamalara (best practices) aykırı, dolaylı risk. | Catch-all kuralının eksik olması veya zayıf TLS ayarları. |
| **INFO** | Bilgilendirme amaçlı veya düşük öncelikli iyileştirmeler. | Güncel olmayan cloudflared sürümü veya sadece HTTP kullanımı. |

### Skorlama Mantığı
- **Kritik:** Hemen müdahale gerektirir.
- **Uyarı:** İlk bakım penceresinde düzeltilmelidir.
- **Bilgi:** Sistem sıkılaştırma için önerilir.
