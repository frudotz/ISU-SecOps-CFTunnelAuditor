# Kullanım Kılavuzu (Usage Guide)

Cloudflare Tunnel Auditor, Cloudflare Tunnel (cloudflared) kurulumlarını hem yerel yapılandırma hem de Cloudflare API düzeyinde güvenlik açıklarına karşı denetleyen bir araçtır.

## Kurulum ve Çalıştırma
Araca çalıştırma izni verin:
```bash
chmod +x /auditor.sh
```

## 1. Yerel Denetim (Local Audit)
Sadece makine üzerindeki yapılandırma dosyalarını ve izinleri denetler:

```bash
./auditor.sh
```

## 2. Otomatik Düzeltme (Fix Mode)
Dosya izinleri gibi düzeltilebilir hataları otomatik onarmak için:

```bash
./auditor.sh --fix
```

## Raporlama
Denetim sonunda bulgular terminale yazdırılır. İsteğe bağlı olarak JSON formatında çıktı alınabilir.
