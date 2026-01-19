# Sources for claude

# Cloudflare Tunnel Auditor - Kaynakça

## 📚 Resmi Cloudflare Dokümantasyonu

### Cloudflare Tunnel (Argo Tunnel)
- [Cloudflare Tunnel Overview](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
- [Tunnel Configuration Reference](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/)
- [Ingress Rules Documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/routing-to-tunnel/ingress/)
- [Tunnel Deployment Best Practices](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/deploy-tunnels/)
- [Tunnel with Firewall Configuration](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/deploy-tunnels/tunnel-with-firewall/)

### Cloudflare Access (Zero Trust)
- [Cloudflare Access Documentation](https://developers.cloudflare.com/cloudflare-one/policies/access/)
- [Access Policies](https://developers.cloudflare.com/cloudflare-one/policies/access/policy-management/)
- [Service Tokens](https://developers.cloudflare.com/cloudflare-one/identity/service-tokens/)
- [Short-Lived Certificates for SSH](https://developers.cloudflare.com/cloudflare-one/identity/users/short-lived-certificates/)

### Cloudflare API
- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
- [Cloudflare Tunnel API](https://developers.cloudflare.com/api/operations/cloudflare-tunnel-get-a-cloudflare-tunnel)
- [Access Applications API](https://developers.cloudflare.com/api/operations/access-applications-list-access-applications)
- [DNS Records API](https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records)
- [API Tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
- [API Rate Limiting](https://developers.cloudflare.com/fundamentals/api/reference/limits/)

### Security & Compliance
- [Cloudflare Zero Trust Security](https://www.cloudflare.com/learning/security/glossary/what-is-zero-trust/)
- [Cloudflare Audit Logs](https://developers.cloudflare.com/fundamentals/setup/account/account-security/review-audit-logs/)
- [Certificate Transparency](https://developers.cloudflare.com/ssl/edge-certificates/custom-certificates/certificate-transparency-monitoring/)

---

## 🔒 Güvenlik Standartları & Framework'ler

### CWE (Common Weakness Enumeration)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

### OWASP
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

### NIST
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST SP 800-53: Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)

### CIS Benchmarks
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [CIS Linux Benchmark](https://www.cisecurity.org/benchmark/distribution_independent_linux)

### Compliance Standards
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
- [GDPR](https://gdpr.eu/)
- [SOC 2 Trust Service Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/socforserviceorganizations)

---

## 🛠️ Teknik Araçlar & Projekte

### IaC & Configuration Management
- [Terraform Cloudflare Provider](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs)
- [Checkov - IaC Scanner](https://github.com/bridgecrewio/checkov)
- [Terrascan](https://github.com/tenable/terrascan)
- [tfsec](https://github.com/aquasecurity/tfsec)

### Container Security
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Secrets Management](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Trivy - Container Vulnerability Scanner](https://github.com/aquasecurity/trivy)

### Secret Management
- [HashiCorp Vault](https://www.vaultproject.io/)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [TruffleHog - Secret Scanner](https://github.com/trufflesecurity/trufflehog)

### Network Security Tools
- [nmap](https://nmap.org/)
- [Shodan](https://www.shodan.io/)
- [Censys](https://censys.io/)
- [crt.sh - Certificate Transparency Search](https://crt.sh/)

### CSPM (Cloud Security Posture Management)
- [Prisma Cloud (Palo Alto)](https://www.paloaltonetworks.com/prisma/cloud)
- [Wiz](https://www.wiz.io/)
- [Orca Security](https://orca.security/)
- [AWS Security Hub](https://aws.amazon.com/security-hub/)

---

## 📖 Akademik & Araştırma Kaynakları

### Threat Modeling
- [STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)

### Zero Trust Architecture
- [Google BeyondCorp Papers](https://cloud.google.com/beyondcorp)
- [NIST Zero Trust Architecture (SP 800-207)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)

### Risk Assessment
- [FAIR (Factor Analysis of Information Risk)](https://www.fairinstitute.org/)
- [CVSS (Common Vulnerability Scoring System)](https://www.first.org/cvss/)
- [DREAD Risk Assessment Model](https://en.wikipedia.org/wiki/DREAD_(risk_assessment_model))

---

## 🎓 Best Practices & Guides

### Linux Security
- [Linux Security Hardening Guide](https://www.cisecurity.org/insights/white-papers/cis-controls-v8-guide-to-linux-hardening)
- [SELinux User Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/using_selinux/index)
- [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [systemd Security Features](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)

### SSH Security
- [Mozilla SSH Guidelines](https://infosec.mozilla.org/guidelines/openssh)
- [NIST SSH Security](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)

### Container Security
- [NIST SP 800-190: Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/security-checklist/)

### API Security
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [REST API Security Best Practices](https://restfulapi.net/security-essentials/)

---

## 🔍 CVE & Vulnerability Databases

### General Vulnerability Databases
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [CVE Details](https://www.cvedetails.com/)
- [Exploit-DB](https://www.exploit-db.com/)

### Cloudflared Specific
- [Cloudflared GitHub Releases](https://github.com/cloudflare/cloudflared/releases)
- [Cloudflared Security Advisories](https://github.com/cloudflare/cloudflared/security/advisories)

---

## 📰 Blog Posts & Technical Articles

### Cloudflare Blog
- [Cloudflare Blog - Tunnel Announcements](https://blog.cloudflare.com/tag/cloudflare-tunnel/)
- [Introducing Cloudflare Tunnel](https://blog.cloudflare.com/tunnel-for-everyone/)
- [Zero Trust Architecture](https://blog.cloudflare.com/tag/zero-trust/)

### Security Research
- [Krebs on Security](https://krebsonsecurity.com/) - General security news
- [Troy Hunt's Blog](https://www.troyhunt.com/) - Web security research
- [Hacker News Security](https://news.ycombinator.com/) - Community discussions

### DevOps & SRE
- [Google SRE Books](https://sre.google/books/)
- [HashiCorp Learn](https://learn.hashicorp.com/)

---

## 🧰 Komut Satırı Araçları & Utilities

### Network Diagnostics
```bash
# System network tools (man pages)
man ss
man netstat
man iptables
man nftables
man dig
```

### File & Process Management
```bash
man stat
man ps
man find
man grep
```

### Container Tools
```bash
docker inspect --help
kubectl explain secrets
```

---

## 📊 Risk Scoring & Metrics

### Industry Standards
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- [ISO 27005: Information Security Risk Management](https://www.iso.org/standard/75281.html)

---

## 🌐 Community Resources

### GitHub Repositories
- [Cloudflared Official Repo](https://github.com/cloudflare/cloudflared)
- [Awesome Cloudflare](https://github.com/irazasyed/awesome-cloudflare)
- [Awesome Security](https://github.com/sbilly/awesome-security)

### Forums & Communities
- [Cloudflare Community](https://community.cloudflare.com/)
- [Reddit r/Cloudflare](https://www.reddit.com/r/CloudFlare/)
- [Reddit r/netsec](https://www.reddit.com/r/netsec/)

---

## 📝 Notlar

### Kullanım Uyarısı
Bu kaynakça, **Cloudflare Tunnel Auditor** projesinin teknik analizi sırasında referans alınan veya önerilen kaynaklardan oluşmaktadır. Bazı kaynaklar:
- Genel güvenlik prensiplerini açıklar (OWASP, NIST)
- Spesifik araçların dokümantasyonudur (Cloudflare API, Docker)
- Best practice rehberleridir (CIS Benchmarks)

### Güncellik
- Cloudflare dokümantasyonu sürekli güncellenir
- CVE veritabanları real-time güncellenir
- API versiyonları değişebilir

### Lisans & Kullanım
Tüm kaynaklar kendi lisans koşullarına tabidir. Ticari kullanımdan önce ilgili lisansları kontrol ediniz.

---

**Son Güncelleme:** 19 Ocak 2026  
**Derleme:** Claude (Anthropic) - Cloudflare Tunnel Security Analysis
