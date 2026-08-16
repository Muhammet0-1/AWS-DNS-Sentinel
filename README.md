# AWS DNS Sentinel

[![Tests](https://github.com/Muhammet0-1/AWS-DNS-Sentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/Muhammet0-1/AWS-DNS-Sentinel/actions/workflows/tests.yml)

AWS DNS Sentinel, bir AWS Route 53 hosted zone içindeki kayıtları sürümlü bir yerel baseline ile karşılaştıran komut satırı aracıdır. Eksik, değiştirilmiş ve beklenmeyen kayıtları raporlar. CNAME, NS ve alias hedeflerindeki ilgili drift olaylarını ayrıca **dangling DNS adayı** olarak işaretler; bu işaret hedefin gerçekten sahipsiz veya ele geçirilebilir olduğunu kanıtlamaz.

Araç varsayılan olarak salt okunurdur. Remediation yalnızca ayrı bir bayrak, gerçek çalıştırma bayrağı ve hedef hosted-zone kimliğinin birebir onayı birlikte verildiğinde Route 53'e UPSERT gönderir. Beklenmeyen kayıtları silmez; NS ve SOA kayıtlarını otomatik değiştirmez.

## Proje hikâyesi

AWS DNS Sentinel, yetkili bir bug bounty araştırması sırasında bir **third-party ticketing partner** entegrasyonundaki lame/dangling DNS delegasyonunu incelemek için hazırlanan IronGate Watchdog prototipinden doğdu. Program analistinin çalışan ve zararsız bir PoC talebi üzerine yalnızca sentetik `Hello world!` içeriği kullanıldı; kullanıcı verisine, üretim verisine veya başka sistemlere erişilmedi.

İlgili üçüncü taraf alan adı programın scope listesinde bulunmadığı için rapor **Informative** olarak, **out-of-scope** gerekçesiyle kapatıldı. Bu sonuç kabul edilmiş, ödüllendirilmiş veya doğrulanmış kritik bir açık anlamına gelmez. Yanlış DNS delegasyonları bağlama göre yetkisiz içerik sunumu, XSS zincirleri, CSP güven sınırlarının aşılması, ödeme akışlarının kötüye kullanılması veya üretim sistemi kontrolü gibi teorik risklere katkıda bulunabilir; ancak bu vakada bunların hiçbiri gösterilmedi veya gerçekleştirilmedi.

Çalışmanın temel mühendislik dersi; testten önce scope doğrulamak, önce pasif doğrulama kullanmak, güvenli varsayılanları korumak, DNS drift'ini izlemek ve değişiklik yapan remediation işlemlerini insan onayına bağlamaktır. AWS DNS Sentinel bu deneyimden türetilmiş, belirli bir hedefe ait ayrıntıları içermeyen savunma amaçlı ve genelleştirilmiş bir araçtır.

## Özellikler

- Route 53 sayfalandırmasını kullanarak kayıt envanteri çıkarma
- İsim, tip, routing set identifier, TTL, değer, alias ve routing policy alanlarını karşılaştırma
- Eski liste biçimindeki `dns_baseline.json` dosyalarını okuyabilme
- Sürümlü JSON baseline ve JSON denetim raporu
- Güvenli varsayılanlar: remediation kapalı, dry-run desteği, tam zone onayı
- Kimlik bilgisi, yetki, bağlantı/zaman aşımı ve bozuk veri hataları için kontrollü hata mesajları
- AWS ağına çıkmayan, enjekte edilmiş sahte istemcilerle çalışan birim testleri

## Gereksinimler ve kurulum

- Python 3.10 veya üzeri (CI matrisi: 3.10–3.13)
- Bir hosted zone okunacaksa AWS kimlik bilgileri ve uygun IAM izni

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
aws-dns-sentinel --help
```

Geliştirme araçları için:

```bash
python -m pip install -e '.[dev]'
```

AWS kimlik bilgilerini kaynak koda veya baseline dosyasına koymayın. Boto3 standart credential provider chain'i kullanır; örneğin yerel AWS profili, ortam değişkenleri veya bir IAM role.

## Kullanım

Önce yetkili ve gözden geçirilmiş bir Route 53 durumundan baseline oluşturun:

```bash
aws-dns-sentinel baseline \
  --zone-id Z123EXAMPLE \
  --baseline dns_baseline.json
```

Var olan dosyanın kasıtlı olarak yenilenmesi için `--overwrite` gerekir. Daha sonra salt okunur denetim çalıştırın:

```bash
aws-dns-sentinel audit \
  --zone-id Z123EXAMPLE \
  --baseline dns_baseline.json \
  --report audit-report.json
```

Çıkış kodları: temiz denetim için `0`, drift bulunduğunda `1`, doğrulama/AWS/dosya hatasında `2`.

### Remediation dry-run

Aşağıdaki komut yalnızca plan üretir; AWS değişikliği yapmaz:

```bash
aws-dns-sentinel audit \
  --zone-id Z123EXAMPLE \
  --baseline dns_baseline.json \
  --remediate
```

Gerçek değişiklik üç ayrı koşul ister. Önce dry-run çıktısını ve baseline'ı inceleyin:

```bash
aws-dns-sentinel audit \
  --zone-id Z123EXAMPLE \
  --baseline dns_baseline.json \
  --remediate \
  --apply \
  --confirm-zone-id Z123EXAMPLE \
  --log-file dns-sentinel.log
```

Bu işlem yalnızca baseline'da bulunan eksik/değişmiş uygun kayıtları `UPSERT` eder. Beklenmeyen kayıtlar, NS ve SOA kayıtları raporlanır fakat otomatik değiştirilmez.

## Mimari

```text
CLI / DNSIntegrityScanner
        |
        +-- Route53Service ---- boto3 Route 53 istemcisi
        +-- baseline ---------- doğrulanan, atomik JSON depolama
        +-- comparison -------- saf ve ağsız drift karşılaştırması
        +-- reporting --------- metin ve JSON çıktı
        +-- remediation ------- dry-run, izin ve zone onay kapıları
```

Paket `src/aws_dns_sentinel/` altındadır. Eski `from dns_guard import DNSIntegrityScanner` içe aktarımı, paket kurulduktan sonra uyumluluk amacıyla çalışmaya devam eder.

## Güvenlik modeli

Baseline ve JSON raporları, DNS altyapınız hakkında hassas envanter sayılmalıdır. Bu dosyalar Unix benzeri sistemlerde `0600` izinleriyle atomik yazılır; yine de depoya eklenmemeli ve uygun erişim kontrolüyle saklanmalıdır. Loglar kayıt isimlerini ve zone kimliğini içerebilir, fakat AWS hata mesajlarının ham istek bağlamını yazmaz.

Salt okunur kullanım için örnek en az ayrıcalıklı IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "route53:ListResourceRecordSets",
      "Resource": "arn:aws:route53:::hostedzone/Z123EXAMPLE"
    }
  ]
}
```

Remediation ayrı bir role/policy ile sınırlandırılmalıdır:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": "arn:aws:route53:::hostedzone/Z123EXAMPLE"
    }
  ]
}
```

Mümkünse okuma ve yazma rollerini ayırın, kısa ömürlü kimlik bilgileri kullanın ve CloudTrail üzerinden değişiklikleri izleyin. IAM koşullarını kurum politikanıza göre daraltın.

## Sınırlamalar

- Araç hedef servis kaynağının mevcut veya sahiplenilebilir olup olmadığını ağ üzerinden doğrulamaz. “Dangling DNS adayı” manuel veya yetkili bir doğrulama gerektirir.
- Drift, tek başına kötü niyet ya da güvenlik açığı kanıtı değildir.
- Baseline güvenilirliği, baseline alınan anın ve dosyanın bütünlüğüne bağlıdır.
- DNSSEC zinciri, resolver/cache davranışı, propagation ve üçüncü taraf DNS sağlayıcıları denetlenmez.
- Remediation değişiklikleri Route 53 tarafından asenkron uygulanabilir; araç değişiklik durumunu beklemez.
- Eski baseline biçimi zone kimliği taşımadığı için zone eşleşmesi doğrulanamaz. Ayrıca eski tarayıcının boş `Value` ile kaydettiği alias hedefleri geri getirilemez; bu durumda güvenilir durumdan `baseline --overwrite` ile yeni baseline alınmalıdır.

## Test

Testler sahte Route 53 istemcileri kullanır ve gerçek AWS/DNS değişikliği yapmaz:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests dns_guard.py
git diff --check
```

Geliştirme bağımlılıkları kuruluysa ayrıca:

```bash
ruff check .
mypy src/aws_dns_sentinel
python -m pytest
python -m build
```

Katkı kuralları için [CONTRIBUTING.md](CONTRIBUTING.md), güvenlik bildirimi için [SECURITY.md](SECURITY.md) dosyasına bakın.

## Yetkili ve yasal kullanım

Yalnızca sahibi olduğunuz veya denetlemek/değiştirmek için açık izniniz bulunan AWS hesaplarında ve DNS bölgelerinde kullanın. Kullanıcı; AWS hizmet koşullarına, kurum değişiklik yönetimine ve yürürlükteki mevzuata uymaktan sorumludur.

## Lisans

Bu proje MIT Lisansı altında yayımlanır. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
