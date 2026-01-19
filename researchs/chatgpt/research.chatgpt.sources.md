# Sources for chatgpt

### Cloudflare Tunnel – Core Architecture & Security
- Cloudflare Tunnel Overview  
  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
  
- cloudflared Authentication, cert.pem and Tunnel Credentials  
  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-remote-tunnel/
  
- Tunnel Credentials and Security Model  
  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/tunnel-credentials/
  
- Ingress Rules, Order, and Catch-all Behavior  
  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/local-management/ingress/

- Origin Requests and TLS Configuration  
  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/origin-configuration/

---

### Cloudflare Access / Zero Trust
- Cloudflare Access Overview  
  https://developers.cloudflare.com/cloudflare-one/identity/
  
- Access Applications and Policies  
  https://developers.cloudflare.com/cloudflare-one/identity/access/policies/
  
- Access Policy Evaluation Order & Default Deny  
  https://developers.cloudflare.com/cloudflare-one/identity/access/policies/#policy-evaluation
  
- Validating Access JWTs at the Origin (Critical for Bypass Prevention)  
  https://developers.cloudflare.com/cloudflare-one/identity/access/secure-web-apps/validate-jwt/
  
- Application Tokens & Service Tokens  
  https://developers.cloudflare.com/cloudflare-one/identity/service-auth/

---

### SSH, Infrastructure Access & Non-HTTP Services
- SSH over Cloudflare Tunnel  
  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/use-cases/ssh/
  
- Browser-based SSH & Infrastructure Access  
  https://developers.cloudflare.com/cloudflare-one/identity/users/ssh/
  
- Infrastructure Access with Short-Lived Certificates  
  https://developers.cloudflare.com/cloudflare-one/identity/users/ssh/short-lived-certificates/

---

### Logging, Audit & Incident Response
- Access Audit Logs  
  https://developers.cloudflare.com/cloudflare-one/analytics/logs/access-logs/
  
- Cloudflare Audit Logs (Account Level)  
  https://developers.cloudflare.com/fundamentals/account-and-billing/account-management/audit-logs/
  
- Logpush & SIEM Integration  
  https://developers.cloudflare.com/logs/

---

### Cloudflare API & Token Security
- Cloudflare API Tokens – Least Privilege Model  
  https://developers.cloudflare.com/api/tokens/
  
- Zero Trust API (Tunnels, Access, Policies)  
  https://developers.cloudflare.com/api/resources/zero_trust/
  
- Rate Limiting and API Usage Considerations  
  https://developers.cloudflare.com/api/limits/

---

### Kubernetes, Containers & Secret Management (Contextual)
> Cloudflare tarafı değil ama Tunnel Auditor için kritik bağlam

- Kubernetes Secrets – Security Risks  
  https://kubernetes.io/docs/concepts/configuration/secret/
  
- OWASP Kubernetes Top 10  
  https://owasp.org/www-project-kubernetes-top-ten/
  
- Docker Image Layer Leakage Risks  
  https://docs.docker.com/build/building/secrets/

---

### Misconfiguration & Bypass Awareness (Blog / Guidance)
- Cloudflare: Protecting Origins from Direct Access  
  https://developers.cloudflare.com/cloudflare-one/identity/access/secure-web-apps/origin-protection/
  
- Why Access Alone Is Not Enough Without Origin Validation  
  https://blog.cloudflare.com/secure-origin-connections-with-access/

---

### Related Security Posture & Gap Analysis
- Why CSPM/IaC Scanners Miss Runtime Tunnel Risks  
  https://www.cncf.io/blog/2022/08/16/runtime-security-is-not-static-security/
