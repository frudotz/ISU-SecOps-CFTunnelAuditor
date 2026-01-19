# Denetim Kontrol Kataloğu (Control Catalog)

Bu doküman, aracın gerçekleştirdiği teknik kontrolleri listeler.

## Yerel Kontroller (Local Checks)
- **L-001 (Secret Permissions):** `cert.pem` ve `credentials.json` izinlerinin `400` veya `600` olduğu doğrulanır.
- **L-002 (Config Security):** Yapılandırma dosyalarında (YAML/JSON) şifrelenmemiş hassas veri kontrolü yapılır.
- **L-003 (Orphaned Configs):** Aktif olmayan veya tünel ile eşleşmeyen eski yapılandırmalar aranır.

## Bulut API Kontrolleri (Cloud API Checks)
- **C-001 (Ingress Validation):** Tünel ingress kurallarında "catch-all" (404) kuralının varlığı denetlenir.
- **C-002 (Access Integration):** Kritik uç noktaların (SSH, RDP, Admin Panelleri) Cloudflare Access ile korunup korunmadığı kontrol edilir.
- **C-003 (DNS Exposure):** Origin IP adresinin DNS kayıtlarında sızıp sızmadığı (Proxy status) kontrol edilir.
