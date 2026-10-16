# Wolf-Audit P1 kapanış raporu (proje sahibi)

Bu rapor 16 Ekim 2026 tarihindedir. Güvenlik sertifikası değildir. “Ürün bütün açıkları bulur” anlamına gelmez.

Kısa karar: **COMPLETE**. P1 aşamasının mimaride yazılı işi kanıtlarla kapatıldı. P2 bu turda başlatılmadı.

## P1'de neler tamamlandı?

P1, herkese açık tarama motorunun şu işidir: Python kaynak kodundaki belirli tehlikeli çağrıları ağaç yapısından görmek, üç kilit dosyasından çevrimdışı kütüphane listesi çıkarmak ve bu sonucu iki standart dosyaya dökmek.

- Python AST taraması sıkılaştırıldı. AST, kodun yorum ve düz metin olmayan iskeletidir. `yaml.load(..., Loader=yaml.SafeLoader)` artık gereksiz yere işaretlenmez. `import os as ...` ve `from os import system` gibi yazımlar, modül seviyesindeyse görülür.
- `Cargo.lock`, `package-lock.json` ve `requirements.txt` envanteri duruyor. Bozuk kilit dosyası ve içe aktarılan requirements satırı taramayı eksik diye işaretler.
- CycloneDX 1.6 SBOM üretilir. SBOM, kullanılan kütüphanelerin listesidir. Bağımsız şema aracı `jsonschema` 4.23.0 ile resmi CycloneDX 1.6 şemasına bakıldı.
- SARIF 2.1.0 raporu üretilir. SARIF, bulguları başka araçların okuyabileceği standart biçimdir. Aynı araçla resmi OASIS SARIF 2.1.0 şemasına bakıldı. SARIF içine kaynak dosyanın SHA-256 parmak izi de yazılır.
- Dosya yolu, satır numarası, kural kimliği ve kaynak parmak izi birbirine bağlanır. Tarama dosya sınırında kesilirse rapor, yürüyüşün durduğunu ayrıca söyler.
- Eski testler silinmedi. Yeni testler onların yerine geçmedi.

## Gerçekten çalışan özellikler neler?

Bunlar bu dalda çalışan ve test edilen davranışlardır:

- Salt okunur tarama. Hedef kod çalıştırılmaz.
- Sembolik bağlantı, yani başka bir dosyaya işaret eden kısayol, sessizce takip edilmez. Durum `INCOMPLETE` olur. Bu, “tarama eksik” demektir.
- Gizli anahtar benzeri metin rapora düz yazı olarak kopyalanmaz.
- Aynı içeriğin iki taraması aynı raporu üretir.
- Python’da `eval`, `exec`, `os.system`, `pickle.loads`, `marshal.load`, `yaml.unsafe_load`, `shell=True` anahtar sözcüğü.
- GitHub Actions, Dockerfile, Rust `unsafe` envanteri ve sabit sır gibi önceki kurallar durur.
- P1.5 durur: isteğe bağlı OSV sorgusu, politika kapısı, Kubernetes ve Terraform sezgileri, rapor karşılaştırması. OSV, açık kaynak zafiyet veritabanına paket adı ve sürüm soran isteğe bağlı adımdır. Bu turda genişletilmedi.

## Neler eksik?

Bunlar P1’in söz verdiği işler değildir. Belgeleyerek “bitti” denmiş değildir; P1 kapsamının dışında bırakılmıştır:

- SQL enjeksiyonu, XSS, dosya yolu gezintisi, SSRF ve veri akışı (taint) analizi yok. Veri akışı, bir girdinin programın içinde nereye gittiğini izlemektir.
- JavaScript, Java, Go ve C kaynakları taranmaz. Yalnızca `.js` olan bir klasör `NO_HEURISTIC_FINDINGS` verebilir. Bu, “temiz” demek değildir. “Bu motorun baktığı dosya türlerinde kural çıkmadı” demektir.
- `subprocess.run` çağrısında `shell=True` konumsal argüman olarak yazılırsa görülmez. Anahtar sözcük `shell=True` görülür.
- Fonksiyonun içinde yapılan `from os import system` takma adı çözülmez. `os.system(...)` yazımı yine görülür.
- Bütün CVE’lerin bulunduğu iddia edilmez. CVE, herkese açık zafiyet numarasıdır.
- DAST, fuzzing, bellek ve FFI yoktur. Bunlar P2’dir. DAST, programı çalıştırarak denemektir. Fuzzing, rastgele girdilerle çökertmeyi denemektir.
- Enterprise kodu ve lisans dosyası eklenmedi.

## Hangi testler yapıldı?

Yerel komut, Python 3.12.3:

`python3 -m unittest discover -s tests -q`

Sonuç: 66 test, çıkış kodu 0. Eski testler duruyor. Yeni dosya `tests/test_p1_completion.py` dokuz test ekler. Test sayısı tek başına başarı değildir.

Şema testi `jsonschema` 4.23.0 kullanır. Bu paket tarayıcının bağımlılığı değildir. Yalnızca test çalışırken kurulur. Resmi şema baytlarının özeti:

- SARIF: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`
- CycloneDX: `efc54d749e32a6e16abd19394b80b4c67d846e12c782e04505130375f94ea541`

İlk GitHub denemesi `5f13fd7267158a37f879eb0f13ed72a9c034bb91` Windows’ta düştü. Nedeni güvenlik açığı değil. Windows satır sonunu değiştirince şema parmak izi ve dosya özeti şaştı. Düzeltme `71b60811515dc069f77478f26dc49914defbc09a` içindedir. O commit için Ubuntu ve Windows kayıtları ikisi de tamamlandı:

https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942520179

## Hangi güvenlik açıkları bulunabiliyor?

Bulunan şey kanıtlanmış istismar değildir. Şüpheli kalıptır.

- Python’da dinamik kod çalıştırma: `eval`, `exec`.
- Kabuk çağrısı: `os.system` ve `subprocess` içinde `shell=True`.
- Güvensiz yükleme: `pickle`, `marshal`, `yaml.unsafe_load`, yükleyicisiz `yaml.load`.
- Sabit sır, özel anahtar bloğu ve GitHub token benzeri diziler. Değer rapora yazılmaz.
- Sabitlenmemiş Python paketi, sabitlenmemiş GitHub Action.
- Dockerfile’da `latest` ve `USER root`.
- Kubernetes ayrıcalığı ve Terraform’da herkese açık erişim işaretleri. Bunlar P1.5’tir ve bozulmadı.

## Hangileri henüz bulunamıyor?

- SQL, XSS, SSRF, yol gezintisi ve bir değişkenin içinden gelen komut.
- Yorum satırına gizlenmiş sır, tarayıcı o satırı atladığı için.
- JavaScript ve diğer dillerdeki `eval`.
- Konumsal `shell=True`.
- Kütüphane sürümünün gerçekten zafiyetli olduğu hükmü. OSV isteğe bağlıdır ve sertifika değildir.

## P1 tamamlandı mı, neden?

Evet, **COMPLETE**. Mimari belgedeki P1 işi şunlardı: Python AST sezgisi, çevrimdışı Cargo/npm/pip envanteri, SARIF 2.1.0 ve CycloneDX 1.6. Bu dördü çalışıyor, sınırları testle kilitli ve iki çıktı resmi şemaya uyuyor. Eksik bırakılan maddeler P2 veya “bütün diller ve bütün açıklar” kapsamıdır. Onları yazıp P1’i bitmiş saymadım; onları P1’in dışına koydum ve test, bulunmadıklarını gösteriyor.

## P2'ye geçmek güvenli mi?

P1 kapısı bu kanıtla kapanmıştır. P2’ye geçmek, “motor artık her açığı buluyor” anlamına gelmez. P2 ayrı iştir: FFI, bellek, fuzzing ve Windows’a özgü kontroller. Bu turda eklenmedi. Müşteriye veya yatırımcıya “tarama temiz, ürün güvenli” denemez. `NO_HEURISTIC_FINDINGS` yalnızca bakılan kuralların boş kaldığını söyler.

İlgili dosyalar:

- Bu rapor: `docs/P1_OWNER_REPORT_TR.md`
- Teknik kayıt: `docs/P1_TECHNICAL_AUDIT.md`
- Taslak PR: https://github.com/alsatplaza-commits/Wolf-Audit/pull/7
