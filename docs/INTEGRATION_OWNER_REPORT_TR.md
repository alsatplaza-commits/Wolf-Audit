# Wolf-Audit birleştirme kapısı (proje sahibi)

Bu rapor 16 Ekim 2026 tarihindedir. Entegrasyon kararı: **BLOCKED**.

Kod birleştirilmedi. Cherry-pick yapılmadı. PR #4, #5, #6 ve #7 değiştirilmedi. `main` değiştirilmedi. Lisans dosyası eklenmedi. P2'ye geçilmedi.

## Ne inceledim?

İki açık iş var. İkisi de `main` dalından ayrılıyor ve ikisi de henüz `main` içinde değil.

- PR #4, taramayı tek bir müşteri klasörüne bağlar. Müşteri, taraması izinli olan taraftır. Sembolik bağlantı ve dışarı taşan sabit bağlantı reddedilir. Commit iddiası, ancak klasörün temiz yerel HEAD'i ise kayda geçer. HEAD, Git'in o klasörde gördüğü son kayıttır.
- PR #7, P1 tarama kapısını kapatır. Python'daki tehlikeli çağrıları daha dikkatli işaretler, SARIF dosyasına kaynak parmak izi ekler ve resmi şema kontrolünü teste bağlar. SARIF, bulguların standart dosyasıdır. SHA-256, dosyanın parmak izidir.

Git, bu iki dalı otomatik birleştiremiyor. Çakışan dosya `wolf_auditor/engine.py`. Çakışma, dosyanın aynı yerine iki farklı ekleme yapılmasıdır. Bir taraf commit kontrolünü, diğer taraf "tarama dosya sınırında durdu" notunu ekler.

## Ne kaybolabilir?

Yanlış taraf seçilirse çalışan iş silinir.

PR #7'nin motor dosyası PR #4'ün yerine konursa kaybolanlar:

- Tek müşteri sınırı
- Sembolik bağlantının hedefinin reddi
- Dışarı taşan sabit bağlantının reddi
- Doğrulanmayan commit iddiasının reddi
- İmzalı adres sorgusunun rapora değer olarak yazılmaması

PR #4'ün motor dosyası PR #7'nin yerine konursa kaybolan:

- Dosya sınırı aşılınca yürüyüşün durduğunu söyleyen `scan_stopped_before_remaining_files` kaydı

Bu yüzden çakışma elle "ikisini de tut" diye kapatılmadı. O işlem, çalıştırılmamış bir birleştirme olurdu.

## Karar neden BLOCKED?

Birleştirme açıkça güvenli değil. Git çakışma bildiriyor. Kural, çakışmayı otomatik çözmemeyi ve güvenli değilse kodu değiştirmemeyi söylüyor.

İki taraf ayrı ayrı yeşil. Bu, birlikte de yeşil oldukları anlamına gelmez. Birleşik test çalıştırılmadı. Çalıştırılmayan teste geçmiş denmez.

## Hangi testler var, hangisi yok?

Ayrı ayrı, Ubuntu ve Windows:

- `main` `d5ffd6111ae5b495bc713b57b40ceba0266c2b08`: https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38902418561
- PR #4 `e4d74128b0f93c86cc2fafa2d0781690957fb7b7`: https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38929631646
- PR #7 `4be6d8ce208c65ca58e49763330a8bd2dd801d82`: https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942867727

Test sayıları, birleşmeden önce: `main` 57, PR #4 102, PR #7 66. Bunlar aynı ağaç değildir. Toplamları birleşik sonuç değildir.

Yapılmayanlar:

- PR #4 ve PR #7 testlerinin aynı ağaçta birlikte çalışması
- Birleşik ağaçta müşteri izolasyonu, sembolik bağlantı, dosya özeti, SARIF, SBOM ve yetkilendirme negatif testleri
- Birleşik Ubuntu ve Windows kaydı

## Bundan sonra ne yapılmamalı?

PR #4 ile PR #7 aynı anda `main`e alınmamalı. Birini alıp diğerinin motor dosyasını üstüne yazmak çalışan özelliği siler. Bu rapor birleştirme talimatı değildir.

İleride bir insan çakışmayı çözecekse iki ekleme de durmalı, sonra 102 ve 66 testin birleşimi iki işletim sisteminde de bitmelidir. O iş bu turda yapılmadı.

Teknik kayıt: `docs/INTEGRATION_TECHNICAL_AUDIT.md`
