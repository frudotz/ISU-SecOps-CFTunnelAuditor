# Tehdit Modeli (Threat Model)

Cloudflare Tunnel Auditor, aşağıdaki tehdit senaryolarına karşı savunma hattı oluşturmayı hedefler:

## 1. Kimlik Bilgisi Hırsızlığı (Credential Theft)
- **Tehdit:** Yerel sunucuda düşük yetkili bir kullanıcının `cert.pem` dosyasını okuyarak yeni tüneller oluşturması veya mevcut olanları silmesi.
- **Kontrol:** L-001 (Dosya İzin Denetimi).

## 2. Origin Bypass
- **Tehdit:** Saldırganın Cloudflare korumalarını aşarak doğrudan sunucunun IP adresine veya açık portuna erişmesi.
- **Kontrol:** C-003 (DNS Proxy Denetimi).

## 3. Yanlış Yapılandırılmış Giriş Kuralları (Ingress Misconfiguration)
- **Tehdit:** Bir tünel kuralının (`*`) tüm trafiği yanlışlıkla hassas bir iç servise yönlendirmesi.
- **Kontrol:** C-001 (Ingress Validation).

## 4. Kimlik Doğrulama Eksikliği
- **Tehdit:** Tünelin internete açık olması ancak uygulama katmanında (Access) bir doğrulama bulunmaması.
- **Kontrol:** C-002 (Access Policy Check).
