# Değişiklik Günlüğü

Biçim [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) yaklaşımını izler. Proje henüz sürümlü bir yayın yapmamıştır.

## [Unreleased]

### Added

- `src` tabanlı, tip ipuçlu Python paket yapısı ve komut satırı arayüzü.
- Sürümlü/atomik baseline depolama, alias ve routing policy desteği.
- Metin ve JSON drift raporları.
- Açık opt-in, dry-run, birebir zone onayı ve NS/SOA koruması olan remediation katmanı.
- Ağsız birim testleri ve Python 3.10–3.13 GitHub Actions matrisi.
- Katkı, güvenlik, kullanım, IAM ve yasal kullanım belgeleri.
- MIT Lisansı.

### Changed

- Kayıt karşılaştırması artık yalnızca ada değil tam Route 53 kayıt kimliği ve yapılandırmasına bakar.
- AWS, dosya ve veri hataları kontrollü uygulama hatalarına dönüştürülür.
- Otomatik remediation varsayılanı kapatıldı.

### Security

- Kaynak koddaki gerçek görünümlü hosted-zone kimliği kaldırıldı.
- Baseline dosyaları özel izinlerle yazılır; symlink üzerine yazma reddedilir.
- Remediation beklenmeyen kayıtları silmez ve açık hedef onayı olmadan AWS yazması yapmaz.

### Fixed

- JSON rapor yolunun baseline dosyasıyla aynı dosyayı göstermesi reddedilir.
- Route 53 sayfalandırmasında artık geçerli olmayan routing identifier sonraki isteğe taşınmaz.
- Hedef bilgisi eski biçimde kaybolmuş alias kayıtları için güvenli yeniden-baseline yönergesi verilir.
