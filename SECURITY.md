# Güvenlik Politikası

## Desteklenen sürüm

Proje erken geliştirme aşamasındadır. Yalnızca en güncel `main` dalı için güvenlik düzeltmeleri planlanır; yayımlanmış ve destek garantisi verilen bir sürüm serisi henüz yoktur.

## Güvenlik açığı bildirimi

Bir güvenlik açığı bulursanız herkese açık issue, log veya proof-of-concept yayımlamayın. GitHub deposunda **Security → Report a vulnerability** seçeneği sunuluyorsa bu özel kanalı kullanın. Seçenek etkin değilse hassas ayrıntıları paylaşmadan depo sahibinden özel bir bildirim kanalı isteyin. Bildirime etkilenen sürümü/commit'i, yeniden üretim adımlarını, olası etkiyi ve hassas olmayan örnekleri ekleyin.

Gerçek AWS anahtarlarını, session token'larını, hesap numaralarını, özel DNS kayıtlarını veya müşteri verisini bildirime koymayın. Gerekirse sentetik değerlerle yeniden üretin ve gerçek kimlik bilgisini derhal iptal edin/döndürün.

Bakım sorumlusu bildirimi değerlendirdikten sonra kapsam ve düzeltme planı hakkında geri dönüş yapar. Belirli bir yanıt veya düzeltme süresi taahhüt edilmemektedir.

## Operasyonel öneriler

- Denetim için salt okunur ve zone'a sınırlandırılmış IAM rolü kullanın.
- Remediation yetkisini ayrı bir role verin.
- Önce dry-run çalıştırın ve değişikliği insan incelemesinden geçirin.
- Baseline ve raporları hassas altyapı verisi olarak koruyun.
- Route 53 değişikliklerini CloudTrail ve kurum değişiklik yönetimiyle izleyin.
