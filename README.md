# ☁️ AWS DNS Sentinel

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![AWS](https://img.shields.io/badge/Cloud-AWS%20Route53-orange?style=for-the-badge&logo=amazon-aws)

**AWS DNS Sentinel**, bulut altyapılarında **Subdomain Takeover** ve **Dangling DNS** zafiyetlerini önlemek için geliştirilmiş, kendi kendini iyileştirebilen (Self-Healing) bir güvenlik otomasyon scriptidir.

Bu araç, **gerçek bir Bug Bounty programı (Supply Chain Vulnerability)** kapsamında keşfedilen bir zafiyet üzerine, benzer durumların tekrar yaşanmaması için geliştirilmiştir.

## 🚨 Vaka Analizi (Case Study)

Bu araç, büyük bir organizasyonun (Major Sports Organization) biletleme altyapısında keşfedilen bir **Lame Delegation** zafiyetini (Subdomain Takeover) kapatmak ve izlemek için tasarlanmıştır.

* **Tehdit:** Saldırganlar, silinmiş veya hatalı yapılandırılmış DNS kayıtlarını (Dangling DNS) tespit ederek alt alan adlarını (subdomain) ele geçirebilir.
* **Etki:** Stored XSS, Kullanıcı verilerinin çalınması, Marka itibar kaybı.
* **Çözüm:** DNS kayıtlarının "Baseline" (temel) görüntüsünü alarak sürekli izlemek ve değişiklik anında otomatik düzeltmek.

## 🛡️ Özellikler

* **Integrity Monitoring:** `boto3` kullanarak AWS Route53 kayıtlarını izler.
* **Anomaly Detection:** Baseline dosyasından sapan kayıtları (Silinme veya Değiştirilme) tespit eder.
* **Auto-Remediation:** Saldırı anında kaydı otomatik olarak güvenli yedeğe geri döndürür.

## ⚙️ Kullanım

```python
# AWS Kimlik bilgilerinin ayarlı olduğundan emin olun
scanner = DNSIntegrityScanner('ZONE_ID')
scanner.perform_audit()
