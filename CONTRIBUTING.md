# Katkı Rehberi

Katkılar küçük, incelenebilir ve testlerle desteklenmiş olmalıdır. Davranış veya güvenlik varsayımlarını değiştiren önerilerde tehdit modelini ve geriye uyumluluk etkisini açıklayın.

## Yerel geliştirme

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check .
mypy src/aws_dns_sentinel
python -m pytest
python -m build
git diff --check
```

Testler hiçbir zaman gerçek AWS hesabı, DNS resolver'ı veya dış ağ gerektirmemelidir. Route 53 davranışını enjekte edilmiş mock istemci ya da botocore `Stubber` ile sınayın. Test ortamına gerçek AWS kimlik bilgileri koymayın.

## Değişiklik ilkeleri

- Remediation varsayılanını kapalı tutun.
- AWS yazmaları için açık opt-in, dry-run ve hedef zone onayını koruyun.
- Kimlik bilgisi, hesap numarası, özel hosted-zone kimliği, gerçek kurum alan adı veya baseline çıktısı commit etmeyin.
- Yeni kullanıcı girdilerini işlemden önce doğrulayın.
- Ham AWS hata bağlamını veya hassas DNS envanterini gereksiz yere loglamayın.
- Kullanıcıya dönük değişiklikleri `CHANGELOG.md` dosyasına ekleyin.

Pull request açıklamasında amaç, risk, test komutları ve varsa IAM etkisi yer almalıdır. Güvenlik açığını genel issue olarak açmayın; `SECURITY.md` içindeki özel bildirim yolunu kullanın.
