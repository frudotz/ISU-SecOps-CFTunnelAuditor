# Research Result for gemini-pro


Cloudflare Tunnel Denetçisi (Auditor): Kapsamlı Güvenlik Araştırma ve Teknik Tasarım Raporu

Yönetici Özeti

Kurumsal ağ güvenliği paradigmaları, geleneksel çevre güvenliği (perimeter security) yaklaşımından kimlik tabanlı Sıfır Güven (Zero Trust) mimarisine doğru evrilirken, Cloudflare Tunnel (eski adıyla Argo Tunnel) bu dönüşümün merkezinde kritik bir altyapı bileşeni olarak konumlanmıştır. Geleneksel VPN ve güvenlik duvarı kurallarının aksine, Cloudflare Tunnel, iç ağdaki kaynakların doğrudan genel internete açık portlar barındırmadan, yalnızca dışa doğru (outbound) şifreli bağlantılar başlatarak Cloudflare Edge ağı üzerinden erişilebilir olmasını sağlar. Bu mimari, teorik olarak saldırı yüzeyini minimize etse de, pratikte yapılan yanlış yapılandırmalar, yetersiz izolasyon ve denetim eksiklikleri, kuruluşları geleneksel yöntemlerden daha karmaşık ve tespit edilmesi zor güvenlik riskleriyle karşı karşıya bırakmaktadır.

Bu rapor, "Cloudflare Tunnel Auditor" projesinin araştırma, tasarım ve teknik özelliklerini belirlemek amacıyla hazırlanmıştır. Hedeflenen Auditor aracı, Linux, Docker, Kubernetes ve Edge cihazları üzerinde çalışan tünel kurulumlarının güvenlik durumunu denetlemek, yapılandırma hatalarını tespit etmek ve operasyonel riskleri nicel bir skorlama modeli ile raporlamak üzere tasarlanmıştır. Araştırmamız, tünel protokolünün kendisinin sağlam olmasına rağmen, onu çevreleyen yapılandırma ekosisteminin (Origin sunucu ayarları, Ingress kuralları, Token izinleri) insan hatasına son derece açık olduğunu ortaya koymaktadır. Özellikle, "Origin Exposure" (Köken Sunucu İfşası) olarak adlandırılan ve tünelin arkasındaki sunucunun doğrudan IP adresinin keşfedilmesine olanak tanıyan yapılandırma hataları, Zero Trust mimarisinin temel vaatlerini geçersiz kılmaktadır.

Rapor, tehdit aktörlerinin meşru tünel araçlarını komuta-kontrol (C2) ve kalıcılık sağlamak amacıyla giderek daha fazla kullandığını vurgulamaktadır. Bu nedenle, geliştirilecek olan Auditor aracı, sadece statik bir yapılandırma denetleyicisi olarak değil, aynı zamanda anomali tespiti yapabilen dinamik bir güvenlik aracı olarak kurgulanmalıdır. Bu doküman, hibrit bir tehdit modeli matrisi, 25 maddelik kritik kontrol kataloğu, nicel risk skorlama algoritmaları ve Cloudflare API v4 entegrasyonu için detaylı teknik yol haritasını içermektedir.

1. Giriş ve Proje Bağlamı

1.1 Sıfır Güven Mimarisi ve Tünelleme Paradoksu

Geleneksel ağ güvenliği, kale-hendek (castle-and-moat) analojisine dayanır; dışarıdaki herkes kötü, içerideki herkes güvenilirdir. Ancak modern dağıtık sistemler ve uzaktan çalışma dinamikleri bu modeli geçersiz kılmıştır. Cloudflare Tunnel, bu bağlamda bir "tersine çevrilmiş" bağlantı modeli sunar. Sunucular, gelen bağlantıları dinlemek (listen) yerine, Cloudflare'in küresel ağına doğru giden (outbound) bir bağlantı başlatır. Bu durum, "Hole Punching" paradoksunu doğurur: Güvenlik duvarında gelen portları kapatmak güvenliği artırır, ancak tünel yazılımının (cloudflared) kendisi, eğer yanlış yapılandırılırsa, iç ağa açılan denetimsiz bir arka kapı haline gelebilir.

Bir sistem yöneticisi, Cloudflare Tunnel kullanarak 80 ve 443 numaralı portları internete kapatıp kendini güvende hissedebilir. Ancak, cloudflared sürecinin kendisi, yapılandırma dosyalarında belirtilen kurallara (ingress rules) göre trafiği iç ağdaki diğer servislere yönlendirme yeteneğine sahiptir. Eğer bu kurallar gevşek tanımlanmışsa veya tünel token'ı çalınırsa, saldırganlar sadece web sunucusuna değil, tünelin erişebildiği tüm iç ağa (Private Network routing aktifse) erişim sağlayabilirler. Bu durum, tünel denetiminin (auditing) sadece bir "nice-to-have" özellik değil, kritik bir güvenlik zorunluluğu olduğunu göstermektedir.

1.2 Hedef Ortamlar ve Kapsam

Geliştirilecek Auditor aracı, heterojen modern altyapıları desteklemelidir. Araştırma bulgularına göre, cloudflared dağıtımları şu dört ana ortamda yoğunlaşmaktadır ve her birinin kendine has güvenlik zafiyetleri vardır:

Linux Sunucular (Bare Metal/VM): Genellikle systemd servisi olarak çalışır. Dosya izinleri (config.yml, cert.pem) ve süreç yetkileri (root vs. non-root) en kritik denetim noktalarıdır.

Docker Konteynerleri: En yaygın dağıtım şeklidir. Konteyner kaçışları (container escape), host network modunun kötüye kullanımı ve dosya sistemi izolasyonu burada öne çıkan risklerdir.

Kubernetes (K8s): Ölçeklenebilirlik için kullanılır ancak "Sidecar" mı yoksa "Deployment" mı olduğu güvenlik duruşunu değiştirir. Pod güvenlik politikaları (PSP/PSA) ve Secret yönetimi burada denetlenmelidir.

Edge Cihazlar (Raspberry Pi, IoT): Genellikle güncellenmeyen, fiziksel güvenliği zayıf cihazlardır. Burada eski versiyon tespiti ve kaynak tüketimi denetimi kritiktir.

1.3 Auditor Projesinin Temel Varsayımları

Bu proje şu varsayımlar üzerine inşa edilecektir:

Yetki Seviyesi: Auditor aracı, çalıştığı makinede yapılandırma dosyalarını okuyabilecek (read-only) dosya sistemi erişimine ve süreç listesini görme yetkisine sahip olacaktır.

API Erişimi: Daha derinlemesine analiz için, kullanıcı tarafından sağlanan ve "En Az Yetki" (Least Privilege) prensibine göre sınırlandırılmış bir Cloudflare API Token kullanılacaktır.

Bağımsızlık: Araç, cloudflared ikili dosyasından bağımsız çalışacak, onun durumunu dışarıdan gözlemleyecektir (Black-box ve Grey-box test yaklaşımı).

2. Cloudflare Tunnel Tehdit Modeli (Threat Model Matrix)

Güvenlik denetim aracının tasarımını yönlendirecek olan tehdit modeli, STRIDE metodolojisinin modern bulut mimarisine uyarlanmış hibrit bir versiyonunu kullanır. Bu model, saldırganın bakış açısını, sistemin güvenilen sınırlarını ve olası etki alanlarını haritalandırır.

2.1 Güvenlik Sınırları ve Varlık Analizi

Cloudflare Tunnel mimarisinde üç temel güvenlik sınırı (Trust Boundary) bulunur:

Origin (Köken) Sınırı: İç ağda çalışan uygulama ve cloudflared servisinin bulunduğu alan. Burası en yüksek güven seviyesine sahip olmalıdır.

Edge (Kenar) Sınırı: Cloudflare'in kontrolünde olan, TLS sonlandırmasının yapıldığı ve politika motorunun (Access Policy) çalıştığı alan. Yarı güvenli (semi-trusted) kabul edilir.

Public (Genel) Sınırı: Son kullanıcıların ve potansiyel saldırganların bulunduğu internet ortamı. Güvensizdir (untrusted).

Saldırganların temel hedefi, Public sınırdan Origin sınırına geçerken Edge sınırındaki güvenlik kontrollerini (WAF, DDoS koruması, Kimlik Doğrulama) atlamaktır.

2.2 Tehdit Matrisi

Aşağıdaki tablo, Cloudflare Tunnel'a özgü tehdit vektörlerini, STRIDE kategorilerini ve risk seviyelerini detaylandırmaktadır.

Tehdit ID

STRIDE Kategorisi

Saldırı Vektörü

Açıklama ve Etki Analizi

Risk Seviyesi

T-01

Spoofing (Kimlik Sahteciliği)

Origin IP Bypass

Saldırgan, Cloudflare'i tamamen bypass ederek origin sunucunun gerçek genel IP adresini (varsa) tespit eder ve doğrudan bağlanır. Bu durumda WAF ve Access politikaları devre dışı kalır.

Kritik

T-02

Elevation of Privilege

Token Theft & Replay

Saldırgan, sunucudan credentials.json veya tünel token'ını çalar. Bu token ile başka bir makinede tüneli ayağa kaldırarak trafiği kendi üzerine çeker (Traffic Hijacking) veya iç ağa erişir.

Kritik

T-03

Information Disclosure

Metrics Port Exposure

cloudflared, varsayılan olarak localhost:20241 üzerinde metrik sunar. Yanlış yapılandırma ile bu port 0.0.0.0'a bağlanırsa, saldırgan tünel ID'sini, bağlantı durumunu ve sürüm bilgisini öğrenebilir.

Yüksek

T-04

Tampering (Kurcalama)

Ingress Rule Shadowing

Yapılandırma dosyasındaki kuralların sırası hatalıdır. Örneğin, geniş kapsamlı bir wildcard kuralı (*.corp.com), özel ve korumalı bir kuraldan (admin.corp.com) önce gelerek trafiği yanlış (veya korumasız) servise yönlendirir.

Orta

T-05

Lateral Movement

WARP Routing Abuse

Tünel, "Private Network" modunda çalışmaktadır ve gereğinden geniş bir CIDR bloğunu (örn. 10.0.0.0/8) anons etmektedir. Token'ı ele geçiren saldırgan, VPN gibi tüm iç ağa erişim sağlar.

Yüksek

T-06

Denial of Service

Split-Brain Routing

Aynı UUID'ye sahip birden fazla cloudflared örneği farklı yapılandırmalarla çalıştırılır. Bu durum, Cloudflare Edge'inde yönlendirme kararsızlığına (route flapping) ve servis kesintisine yol açar.

Orta

T-07

Repudiation (İnkar)

No Logging

Tünel günlükleri (logs) diske yazılmamakta veya çok düşük seviyede (error) tutulmaktadır. Bir ihlal durumunda adli bilişim (forensics) imkansız hale gelir.

Düşük

T-08

Defense Evasion

Quick Tunnel Usage

Kurumsal politikaları aşmak isteyen bir çalışan veya saldırgan, kimlik doğrulama gerektirmeyen geçici "TryCloudflare" tünelleri (quick tunnel) açarak veri sızdırır.

Yüksek

2.3 Senaryo Analizi: Origin Bypass (T-01)

Bu, en yaygın ve en tehlikeli senaryodur. Kullanıcı, sunucusunda cloudflared kurar ancak sunucunun 80/443 portlarını internete kapatmayı unutur (iptables/UFW kullanmaz). Saldırgan, interneti tarayan araçlar (Censys, Shodan) kullanarak, hedef domain'e ait SSL sertifikasını sunan ancak Cloudflare IP aralığında olmayan bir IP adresi tespit eder. Saldırgan doğrudan bu IP adresine istek gönderdiğinde, Cloudflare üzerindeki tüm WAF kurallarını, Access (SSO) girişlerini ve Bot korumasını atlamış olur. Auditor aracı, sunucunun dinlediği arayüzleri (0.0.0.0 vs 127.0.0.1) kontrol ederek bu riski tespit etmelidir.

3. En Sık Yapılan Yanlış Yapılandırmalar (Misconfiguration Top List)

Araştırma verileri, güvenlik ihlallerinin çoğunun yazılım zafiyetinden ziyade yapılandırma hatalarından kaynaklandığını göstermektedir. Cloudflare Tunnel özelinde tespit edilen en kritik beş yapılandırma hatası aşağıda detaylandırılmıştır.

3.1 Kontrolsüz Ingress Kuralları ve "Catch-All" Eksikliği

cloudflared yapılandırma dosyası (config.yml), gelen trafiğin nereye yönlendirileceğini belirleyen bir kural setidir. Bu kurallar yukarıdan aşağıya doğru işlenir.

Hata: Kullanıcılar genellikle dosyanın en sonuna, eşleşmeyen trafik için bir http_status: 404 kuralı koymayı unutur.

Risk: Eğer son kural bir servise yönlendirme yapıyorsa (örneğin ana web uygulaması), tanımlanmamış alt alan adlarına (subdomain) gelen trafik de bu servise gider. Bu, beklenmedik host header saldırılarına veya uygulamanın yanlış bağlamda çalışmasına neden olabilir.

Auditor Hedefi: Yapılandırma dosyasının son kuralının açıkça service: http_status:404 olup olmadığını regex veya YAML parsing ile doğrulamak.

3.2 TLS Doğrulamasının Devre Dışı Bırakılması (noTLSVerify)

cloudflared ile origin sunucu arasındaki iletişim, yerel ağda olsa bile şifreli olabilir. Ancak geliştiriciler, kendi imzaladıkları sertifikalarla (self-signed certs) uğraşmamak için originRequest altında noTLSVerify: true ayarını kullanırlar.

Hata: Prodüksiyon ortamında bu ayarın açık bırakılması.

Risk: Bu, cloudflared ve origin sunucu arasındaki Man-in-the-Middle (Ortadaki Adam) saldırılarına kapı aralar. Eğer bir saldırgan yerel ağda (örneğin aynı Kubernetes cluster'ında) ise, trafiği araya girip okuyabilir.

Auditor Hedefi: Yapılandırma dosyasında noTLSVerify: true dizesini taramak ve bunu Kritik seviye bulgu olarak işaretlemek.

3.3 Access Politikası Olmayan Public Hostname

Tünel üzerinden bir web uygulaması yayınlandığında (ingress kuralı eklenerek), bu uygulama varsayılan olarak dünyadaki herkese açıktır. Güvenlik, Cloudflare Access (Zero Trust) politikaları ile sağlanır.

Hata: Tünel yapılandırmasında bir hostname tanımlamak ancak Cloudflare Dashboard'da buna karşılık gelen bir Access Application oluşturmamak.

Risk: Uygulama, hiçbir kimlik doğrulama katmanı olmadan internete açılır.

Auditor Hedefi: API kullanarak tünel konfigürasyonundaki hostname'leri çekmek ve bunları Access Application listesiyle çapraz doğrulamak. Eşleşmeyen hostname'ler "Korumasız Rota" olarak raporlanmalıdır.

3.4 Token ve Credentials Dosyalarının Güvensiz Saklanması

Tünel kimlik bilgileri (cert.pem veya JSON dosyası), tüneli yönetmek veya çalıştırmak için anahtardır.

Hata: Bu dosyaların herkesin okuyabileceği (chmod 644 veya 777) izinlerle saklanması veya Git reposuna commit edilmesi.

Risk: Yerel erişimi olan düşük yetkili bir kullanıcı veya zararlı yazılım, bu dosyaları okuyarak tüneli ele geçirebilir veya kendi tünelini oluşturabilir.

Auditor Hedefi: Dosya izinlerinin 600 (sadece sahibi okuyabilir) olduğunu ve dosya sahibinin cloudflared kullanıcısı olduğunu doğrulamak.

3.5 Geniş Kapsamlı Özel Ağ (WARP) Yönlendirmesi

Cloudflare Tunnel, VPN alternatifi olarak özel ağlara erişim sağlayabilir (warp-routing).

Hata: Yöneticilerin, sadece belirli bir sunucuya erişim vermek yerine, kolaylık olsun diye tüm subnet'i (10.0.0.0/24 veya /16) tünel üzerinden anons etmesi.

Risk: En Az Yetki (Least Privilege) prensibinin ihlali. Tünel token'ı ele geçirilirse, saldırgan tüm ağ segmentine erişim kazanır.

Auditor Hedefi: API üzerinden routes listesini çekmek ve /24'ten daha geniş CIDR bloklarını uyarı olarak işaretlemek.

4. Auditor için Kontrol Listesi ve Otomatik Test Tasarımı

Auditor aracı, hem yerel sistemden (Local) hem de Cloudflare API'sinden (Remote) veri toplayarak kapsamlı bir analiz yapmalıdır. Aşağıda, MVP (Minimum Viable Product) sürümü için belirlenen 25 kritik kontrol maddesi ve teknik uygulama detayları yer almaktadır.

4.1 Auditor Kontrol Kataloğu (MVP 25)

ID

Kontrol Adı

Tip

Önem

Teknik Doğrulama Mantığı (Algorithm)

C01

Root Yetkisi Kontrolü

Local

Yüksek

`ps -eo user,comm

C02

Config Dosya İzinleri

Local

Yüksek

stat -c %a config.yml. İzinler 600 veya 400 değilse BAŞARISIZ.

C03

Ingress 404 Fallback

Local

Orta

YAML parse et. ingress listesinin son elemanının service değeri http_status:404 mü?

C04

Ingress Gölgeleme

Local

Orta

YAML parse et. Wildcard içeren bir kuraldan sonra, o wildcard'a uyan spesifik bir kural var mı? (Örn: *.site.com sonra api.site.com).

C05

TLS Doğrulama İptali

Local

Kritik

config.yml içinde noTLSVerify: true veya komut satırında --no-tls-verify var mı?

C06

Origin Bağlantı İzolasyonu

Local

Kritik

Origin sunucusu (örn. Nginx) 0.0.0.0 mı dinliyor? Eğer evet ve sunucunun public IP'si varsa KRİTİK. 127.0.0.1 olmalı.

C07

Metrik Port İfşası

Local

Yüksek

netstat -tuln ile 20241 portunu kontrol et. Eğer 0.0.0.0:20241 ise UYARI.

C08

Quick Tunnel Tespiti

Local

Yüksek

Süreç listesinde --token veya --config parametresi olmadan çalışan cloudflared tunnel run var mı?

C09

API Token Yetki Kapsamı

API

Orta

Kullanılan API token'ın izinlerini (/user/tokens/verify) kontrol et. Zone:Edit yetkisi varsa UYARI (Fazla yetki).

C10

Atıl (Zombie) Tüneller

API

Düşük

/cfd_tunnel endpoint'inden tünel listesini çek. status: inactive ve last_seen > 30 gün olanları raporla.

C11

Sürüm Güncelliği

Local

Yüksek

cloudflared --version çıktısını GitHub API'den çekilen latest release ile karşılaştır.

C12

Yedeklilik (HA) Kontrolü

API

Yüksek

/connections endpoint'ini sorgula. Aktif bağlantı sayısı < 2 ise veya hepsi aynı colo (veri merkezi) üzerindeyse UYARI.

C13

Geniş Ağ İfşası

API

Orta

Tünel rotalarını (/teamnet/routes) kontrol et. CIDR maskesi < 24 (örn. /16, /8) olan rotaları işaretle.

C14

Korumasız Public Rota

API

Kritik

Tünel config'indeki hostname'ler ile Access Apps (/access/apps) listesini karşılaştır. Eşleşmeyen varsa KRİTİK.

C15

WAF Entegrasyonu

API

Orta

Tünelin bağlı olduğu Zone için WAF durumunu kontrol et. Kapalıysa UYARI.

C16

WARP Routing Durumu

Local

Bilgi

Config dosyasında warp-routing: enabled: true var mı? Varsa, VPN modu aktiftir, C13 kontrolü daha kritik hale gelir.

C17

Protokol Seçimi

Local

Düşük

protocol: quic veya http2 önerilir. h2mux (eski) kullanılıyorsa UYARI ver.

C18

Log Seviyesi

Local

Düşük

loglevel: debug ise prodüksiyon için gereksiz bilgi ifşası olabilir. info önerilir.

C19

Log Kalıcılığı

Local

Orta

Komut satırında veya config'de logfile parametresi var mı? Yoksa loglar kayboluyor demektir.

C20

Docker Soket Riski

Docker

Kritik

Docker inspect ile mountları kontrol et. /var/run/docker.sock mount edilmişse KRİTİK (Konteyner kaçışı riski).

C21

Host Network Modu

Docker

Yüksek

Konteyner NetworkMode: host ile çalışıyorsa izolasyon zayıftır.

C22

Read-Only Root FS

Docker

Orta

Konteyner ReadonlyRootfs: true ile mi çalışıyor? Güvenlik için true olmalı.

C23

Access Token Doğrulama

Local

Yüksek

Origin servisi, gelen isteklerdeki JWT token'ı (Cf-Access-Jwt-Assertion) doğruluyor mu? (Config analizi ile tespit zordur, manuel kontrol önerilir).

C24

Ortam Değişkeni Gizliliği

Local

Orta

TUNNEL_TOKEN ortam değişkeni olarak mı verilmiş? ps eww ile görülebilir. Dosya (credentials-file) kullanımı önerilir.

C25

Dosya Tanımlayıcı (FD) Limiti

Local

Düşük

ulimit -n kontrolü. Yüksek trafikli tüneller için limitin > 4096 olması gerekir.

4.2 Otomatik Test Tasarımı

Auditor aracı, modüler bir yapıda tasarlanmalıdır. Kullanıcı isterse sadece yerel kontrolleri (--local-only), isterse API kontrollerini (--with-api) çalıştırabilmelidir.

4.2.1 Yerel Test Motoru (Local Engine)

Bu modül, dosya sistemi ve süreç yönetimi kütüphanelerini kullanır.

Girdi: config.yml dosya yolu (varsayılan: /etc/cloudflared/config.yml veya ~/.cloudflared/config.yml).

İşlem:

Dosyanın varlığını ve izinlerini kontrol et (Stat syscall).

YAML parser ile içeriği yapısal bir nesneye dönüştür.

Regex ile ingress kurallarını analiz et. Gölgeleme (shadowing) tespiti için bir döngü algoritması kullan: Her wildcard kuralı (*.site.com) için, listede daha sonra gelen ve bu wildcard'a uyan (api.site.com) kuralları bul.

Süreç listesini (/proc dosya sistemi veya ps komutu) tarayarak çalışma zamanı argümanlarını analiz et.

4.2.2 API Entegrasyon Motoru (API Engine)

Bu modül, Cloudflare ile iletişim kurar.

Girdi: CLOUDFLARE_API_TOKEN ve CLOUDFLARE_ACCOUNT_ID.

Korelasyon Mantığı (C14 Kontrolü İçin):

Veri Toplama: Tüm tünel yapılandırmalarını çek (fetch_tunnel_configs) ve içindeki hostname listesini çıkar. Tüm Access uygulamalarını çek (fetch_access_apps) ve içindeki domain listesini çıkar.

Normalizasyon: Her iki listeyi de küçük harfe çevir ve protokol ön eklerini (https://) temizle.

Kesişim Analizi: Tünel hostname listesindeki her eleman için, Access listesinde bir eşleşme ara. Eşleşme yoksa, bu hostname "Korumasız" (Unprotected) olarak işaretlenir.

5. Teknik Derinlik: API Entegrasyonu ve Token Güvenliği

Otomasyonun kalbi Cloudflare API v4 ile yapılacak entegrasyondur. Auditor'ın güvenli bir şekilde çalışabilmesi için kullanılan token'ın yetkileri hassas bir şekilde ayarlanmalıdır.

5.1 Cloudflare API Endpoint Grupları

Auditor'ın ihtiyaç duyduğu verileri sağlamak için aşağıdaki endpoint grupları kullanılacaktır. Base URL: https://api.cloudflare.com/client/v4.

Endpoint Grubu

HTTP Metodu

Yol (Path)

Amaç ve Çekilen Veri

Tunnels (List)

GET

/accounts/{account_id}/cfd_tunnel

Tünel listesi, durum (healthy, degraded), ID ve oluşturulma tarihi.

Tunnel Config

GET

/accounts/{account_id}/cfd_tunnel/{id}/configurations

Uzaktan yönetilen tünellerin ingress kurallarını ve ayarlarını çeker.

Connections

GET

/accounts/{account_id}/cfd_tunnel/{id}/connections

Aktif bağlantı sayısı, bağlı olunan Edge lokasyonu (Colo) ve protokol tipi.

Routes

GET

/accounts/{account_id}/teamnet/routes

Private Network (VPN) rotaları ve CIDR tanımları.

Access Apps

GET

/accounts/{account_id}/access/apps

Koruma altındaki uygulamaların listesi. Korelasyon için kritiktir.

DNS Records

GET

/zones/{zone_id}/dns_records

Tünellere işaret eden CNAME kayıtlarının varlığını ve doğruluğunu kontrol eder.

5.2 Least Privilege (En Az Yetki) Token Tasarımı

Auditor aracı sadece okuma (read) işlemi yapmalıdır. Asla yazma veya silme yetkisine sahip olmamalıdır. Yanlışlıkla Global API Key kullanılması büyük bir risk oluşturur. Bu nedenle, kullanıcıya aşağıdaki yetki seti ile "Custom Token" oluşturması önerilmelidir:

İzin Verilmesi Gerekenler (Required):

Account > Cloudflare Tunnel > Read (Tünel durumunu görmek için)

Account > Access: Apps and Policies > Read (Politikaları doğrulamak için)

Zone > DNS > Read (DNS kayıtlarını doğrulamak için)

Account > Zero Trust > Read (Genel Zero Trust ayarları için)

Kesinlikle Reddedilmesi Gerekenler (Denied):

Account > Cloudflare Tunnel > Edit/Write (Tünel silmeyi önlemek için)

Zone > DNS > Edit/Write (DNS zehirlenmesini önlemek için)

Account > Access: Service Tokens > Read (Hassas secret'ları okumayı önlemek için)

6. Risk Skorlama Modeli

Auditor, tespit edilen bulguları basit bir liste olarak sunmak yerine, yöneticinin durumu bir bakışta anlamasını sağlayacak nicel bir "Risk Skoru" üretmelidir. Bu model, tespit edilen zafiyetlerin ciddiyetini ve etkisini matematiksel olarak ağırlıklandırır.

6.1 Matematiksel Model

Risk skoru 0 ile 100 arasında bir değerdir; 0 "Güvenli", 100 "Kritik Risk" anlamına gelir. Skor, "En Kötü Durum Senaryosu" mantığıyla hesaplanır. Yani, sistemdeki tek bir kritik açık, tüm skoru aşağı çeker.

$$\text{Toplam Risk Skoru} = \min \left( 100, \sum (\text{Ağırlık}_i \times \text{Durum}_i) \right)$$

Burada:

Ağırlık_i: Kontrol maddesinin risk ağırlığı.

Durum_i: Kontrol başarısız ise 1, başarılı ise 0.

6.2 Ağırlıklandırma ve Kategori Tanımları

Kategori

Ağırlık Puanı

Tanım ve Örnekler

Kritik (Critical)

100

Anında ele geçirilme veya veri sızıntısı riski. Tek bir hata skoru 100 yapar (Maksimum Risk). 



 Örn: Origin direkt erişime açık (C06), Access politikası yok (C14).

Yüksek (High)

40

Ciddi güvenlik zafiyeti, saldırganın işini kolaylaştırır. 



 Örn: Root yetkisiyle çalışma (C01), Metrik portu açık (C07).

Orta (Medium)

10

Güvenlik hijyeni sorunu veya potansiyel risk. 



 Örn: Ingress gölgeleme (C04), Log kalıcılığı yok (C19).

Düşük (Low)

2

En iyi uygulama ihlali, doğrudan saldırı vektörü oluşturmaz. 



 Örn: Eski versiyon (C11), Deprecated protokol kullanımı (C17).

Skor Yorumlama:

0: Mükemmel (Tüm kontroller geçti).

1 - 19: Düşük Risk (İyileştirme önerilir).

20 - 59: Orta Risk (Yapılandırma sertleştirilmeli).

60 - 100: Yüksek/Kritik Risk (Acil müdahale gerektirir).

7. Cloudflared Güncel En İyi Pratikler (Best Practices)

Denetim aracının referans alacağı "İdeal Durum" (Gold Standard) aşağıda ortam bazlı olarak tanımlanmıştır.

7.1 Docker ve Konteyner Güvenliği

Konteyner ortamları en sık kullanılan ancak en kolay yanlış yapılandırılan ortamlardır.

Kullanıcı İzolasyonu: Resmi imaj cloudflare/cloudflared varsayılan olarak nonroot (UID 65532) kullanıcısı ile çalışır. Asla user: root direktifi ile bu ezilmemelidir.

Soket Bağlantıları: cloudflared konteynerine asla Docker soketi (/var/run/docker.sock) mount edilmemelidir. Bu, saldırgana ana makineye (host) tam erişim verir.

Ağ Modu: --network host yerine, sadece gerekli konteynerlerin bulunduğu özel bir bridge ağı kullanılmalıdır. Bu sayede tünel ele geçirilse bile saldırgan diğer ilgisiz konteynerlere (örn. veritabanı) ulaşamaz.

7.2 Kubernetes (K8s) Dağıtım Stratejileri

Deployment vs. Sidecar: cloudflared'in bir Deployment olarak çalıştırılması önerilir. Sidecar modeli (her pod'un yanına bir tünel) kaynak israfıdır ve yönetim zorluğu yaratır. Tek bir Deployment ile küme içi (ClusterIP) servislere yönlendirme yapmak daha güvenli ve yönetilebilirdir.

Replica Yönetimi: Tek bir pod (replica=1) kullanmak risklidir. En az 2 replica çalıştırılmalı ve podAntiAffinity kuralı ile bu podların farklı node'lara dağıtılması sağlanmalıdır.

Secret Yönetimi: Tünel credentials dosyası asla ConfigMap içinde veya repo'da saklanmamalıdır. Kubernetes Secrets veya HashiCorp Vault kullanılmalı ve pod'a volume olarak mount edilmelidir.

7.3 Versiyonlama ve Güncelleme

Cloudflare sık sık güncelleme yayınlar ve eski sürümler yeni protokolleri (örn. MASQUE) desteklemeyebilir veya güvenlik açıkları barındırabilir.

Sabitleme (Pinning): Prodüksiyon ortamında latest etiketi yerine spesifik bir sürüm (örn. 2024.1.5) kullanılmalıdır. Bu, kontrolsüz güncellemelerin sistemi bozmasını engeller.

Otomasyon: Renovate veya Dependabot gibi araçlarla sürüm güncellemeleri otomatik olarak takip edilmeli ve Auditor aracı ile test edilip dağıtılmalıdır.

8. Rakip/Benzer Araçlar ve Boşluk Analizi (Competitive Landscape)

Cloudflare Tunnel güvenliği için piyasada bulunan araçlar ve Auditor'ın dolduracağı boşluk analizi aşağıdadır.

Araç

Kapsam

Yetenekler

Eksiklikler (Gap Analysis)

tfsec / Checkov

Statik Kod Analizi (IaC)

Terraform (cloudflare_tunnel) kaynaklarındaki hataları bulur.

Sadece kod reposuna bakar. Çalışan sistemdeki manuel değişiklikleri (Configuration Drift) göremez. Sunucunun ağ ayarlarını (origin exposure) bilemez.

Cloudflare Dashboard

Yönetim Arayüzü

Tünel durumunu (Healthy/Down) gösterir.

Güvenlik analizi yapmaz. "Bu tünel güvensiz bir şekilde tüm ağı ifşa ediyor mu?" sorusuna cevap vermez. Sadece bağlantı var mı ona bakar.

Nessus / Qualys

Ağ Tarayıcı

Açık portları ve zafiyetleri tarar.

Tüneller outbound çalıştığı için dışarıdan açık port görmezler. Tünel üzerinden sunulan servisin zafiyetini (uygulama katmanı hariç) tespit edemezler.

Cloudflare Tunnel Auditor

Post-Deployment Security

Çalışan konfigürasyonu, API verisini ve yerel sistem durumunu birleştirir.

Bu proje, IaC tarayıcıları ile ağ tarayıcıları arasındaki boşluğu doldurur. Hem yapılandırmayı hem de çalışma zamanı (runtime) risklerini analiz eder.

Auditor'ın Benzersiz Değeri: "Context-Aware" (Bağlam Farkındalığı) özelliğidir. Tünel konfigürasyonunu okurken, aynı zamanda Cloudflare Access politikalarını API'den çekip "Bu kapı açık ama önünde bekçi var mı?" sorusunu cevaplayabilen tek çözümdür.

9. Rapor Çıktı Tasarımı ve Uygulama

Auditor aracı, hem insan hem de makine tarafından okunabilir çıktılar üretmelidir.

9.1 JSON Çıktı Şeması (CI/CD İçin)

Otomasyon sistemleri (Jenkins, GitHub Actions) için standart bir JSON formatı kullanılmalıdır.

{  
  "audit_timestamp": "2023-10-27T10:00:00Z",  
  "tunnel_id": "c1744f8b-faa1-48a4-9e5c-02ac921467fa",  
  "risk_score": 40,  
  "risk_level": "High",  
  "controls": [  
    {  
      "id": "C01",  
      "status": "PASS",  
      "details": "Running as user: cloudflared (uid=101)"  
    },  
    {  
      "id": "C14",  
      "status": "FAIL",  
      "details": "Hostname 'admin.corp.com' has no Active Access Policy",  
      "risk_weight": 100  
    }  
  ]  
}  
 

9.2 Raporlama Arayüzü

Kullanıcılar için, yukarıdaki JSON verisini işleyen ve renkli, anlaşılır bir HTML raporu veya konsol çıktısı (ASCII tablolar ile) sunulmalıdır. Konsol çıktısında, kritik hatalar Kırmızı, uyarılar Sarı, geçilen kontroller Yeşil renk ile gösterilmelidir.

10. Sonuç

Cloudflare Tunnel, modern altyapılar için güçlü ve esnek bir bağlantı çözümü sunarken, güvenlik sorumluluğunu ağ katmanından (Firewall) uygulama ve kimlik katmanına (Zero Trust) taşımaktadır. Bu geçiş, güvenlik ekiplerinin denetim alışkanlıklarını değiştirmesini zorunlu kılmaktadır. Geliştirilen "Cloudflare Tunnel Auditor" projesi, bu yeni mimaride oluşan görünürlük boşluğunu (visibility gap) doldurmak için kritik bir araçtır.

Bu raporda sunulan Tehdit Modeli, saldırganların sadece yazılım açıklarını değil, mantıksal yapılandırma hatalarını (Ingress gölgeleme, Origin ifşası) nasıl kullandığını ortaya koymuştur. Önerilen 25 maddelik Kontrol Kataloğu ve Risk Skorlama Modeli, kuruluşlara tünel güvenliklerini ölçülebilir ve yönetilebilir bir standarda oturtma imkanı tanımaktadır. Sonuç olarak, tünel güvenliği "kur ve unut" değil, sürekli denetim ve doğrulama gerektiren dinamik bir süreçtir ve Auditor aracı bu sürecin temel taşı olacaktır.
