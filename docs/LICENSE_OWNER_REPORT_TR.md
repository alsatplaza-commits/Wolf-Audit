# Wolf-Audit lisans raporu (proje sahibi)

Bu rapor 16 Ekim 2026 tarihindedir. Hukuki danışmanlık değildir. Mahkeme kararı veya “telif temiz” belgesi değildir.

Kısa sonuç: **BLOCKED**. Apache-2.0 metni hazırlandı fakat yayımlanmadı. Kök dizinde `LICENSE` dosyası yok. Yazılımı başkasına “Apache ile kullanabilirsiniz” diye sunmak için hak sahibi ve lisanslama yetkisi hâlâ belirsiz.

## 1. Ne yaptım?

Public Wolf-Audit Core’un, yani herkese açık tarama motorunun, dağıtıma giren dosyalarını inceledim. Git geçmişine baktım. Commit yazarı ile hukuki hak sahibini ayırdım. Üçüncü taraf kod var mı diye baktım. Wolf-Music APK dosyalarının bu motorun dağıtımına girip girmediğini kontrol ettim.

Resmi Apache License 2.0 metnini Apache’nin kendi adresinden indirdim ve birebir kopyasını `docs/licensing/APACHE-2.0.OFFICIAL.txt` içine koydum. Bu kopya bir izin belgesi değildir. `docs/licensing/STATUS.md` dosyası bunun yürürlükte olmadığını söyler.

ScanCode adlı tarama aracının 32.5.0 sürümünü bu ağaçta çalıştırdım. Mevcut tarama motorunun davranışını değiştirmedim. Enterprise paneli, müşteri yönetimi veya ticari lisans kodu eklemedim. PR #4 ve PR #5’e dokunmadım. Merge veya release yapmadım.

## 2. Ne buldum?

- Ana dalda (`main`) lisans dosyası yok. README hâlâ “lisans henüz seçilmedi” diyor.
- Kaynak dosyalarda “Copyright” satırı veya SPDX kısa kodu yok. SPDX, lisansın kısa standart adıdır. Örnek: `Apache-2.0`.
- ScanCode, motorun kaynak dosyalarında sıfır lisans ve sıfır telif satırı buldu. Hata sayısı sıfırdı. Bu, “ihlal yok” demek değildir. Araç yalnızca bilinen lisans cümlelerini arar.
- Dosyaları ilk yazan Git hesabı `alsatplaza-commits`. Bu bir yazar kaydıdır. “Bu kodun hukuki sahibi şudur” belgesi değildir.
- PR #4’teki ek dosyaların ilk kaydı Cursor Agent adınadır. Bot veya ajan commit’i sahiplik kanıtı sayılmadı.
- Motorun içine kopyalanmış üçüncü taraf kaynak kodu bulmadım.
- Wolf-Music APK’ları `wolf-music-downloads` dalındadır. `main` dosya listesinde yoktur. PR #4 dosya listesinde de yoktur. Yani bugünkü Core dağıtımına girmezler. Yine de aynı herkese açık deponun başka dalında dururlar ve onların hak sahibi belirsizdir.

## 3. Telif riski nedir?

Telif, eseri kimin kontrol ettiğidir. Lisans, o kişinin başkasına verdiği kullanma iznidir.

Bugün risk şudur: depo herkese açık, fakat izin belgesi yok. Başkası kodu görse bile yasal kullanma hakkı kendiliğinden doğmaz. Siz de, hak sahibi belgesi olmadan, herkese Apache izni vermiş sayılmazsınız.

Bunu **OWNERSHIP_UNKNOWN** olarak yazıyorum. Anlamı: sahip bilinmiyor. Bu bir suçlama değildir.

## 4. Apache-2.0 seçersek ne kazanırız, neyi izin veririz?

Apache-2.0, açık kaynak dünyasında sık kullanılan bir izin belgesidir. OSI onaylıdır. Resmi metin Apache sitesindedir.

Seçilip gerçekten yayımlanırsa başkası motoru kullanabilir, değiştirebilir ve kendi ürününde dağıtabilir. Karşılığında lisans metnini ve varsa bildirim dosyasını koruması gerekir. Apache-2.0 ayrıca bir patent izni cümlesi içerir. Patent, buluş üzerindeki haktır. Hak sahibi belli değilken bu cümleyi sizin adınıza kuramayız.

Marka ve logo bu iznin içinde değildir. “Wolf-Audit” adını veya bir logoyu başkasının kullanması, yazılım lisansıyla otomatik serbest olmaz. O konu ayrıdır ve bugün tescil kanıtı yoktur.

## 5. Enterprise kodu kapalı kalabilir mi?

Evet, mimari buna göre kurulabilir. Enterprise ayrı ve özel depoda, kapalı ticari lisansla durur. Apache ile lisanslanmış bir motoru, kapalı bir ürün bağımlılık olarak kullanabilir. Buna karşılık Enterprise kodunu public depoya koymayız.

Bugün iki sınır vardır:

- `alsatplaza-commits/Wolf-Audit-Enterprise` diye bir depo yoktur. Oluşturulmadı.
- Core henüz Apache ile lisanslanmadığı için Enterprise’ın bu motora yasal bağımlılığı da belirsizdir.

## 6. Ne çözüldü, ne bekliyor?

Çözülen: inceleme yapıldı, resmi metin saklandı, yanlışlıkla lisans yayımlanması test ile engellendi, APK’ların Core listesinde olmadığı gösterildi.

İlk GitHub denemesinde Ubuntu testi geçti, Windows testi geçmedi. Nedeni lisansın hukuken geçersiz olması değil. Windows, dosyayı diske yazarken satır sonlarını değiştirdi ve dosyanın parmak izi (SHA-256) resmi kopyayla eşleşmedi. Düzeltme, parmak izini diskteki kopyadan değil, Git’in sakladığı orijinal baytlardan alır. Bu düzeltmenin commit’i `4b7c05f3db759ed7b6ef42f70eee634c31ba9cce` için Ubuntu ve Windows kayıtları ikisi de tamamlandı. Bu, testlerin çalıştığı anlamına gelir. Lisansın yürürlüğe girdiği anlamına gelmez.

Bekleyen: hak sahibi adı, lisanslama yetkisi, patent bilgisi, marka bilgisi, PR #4’teki ajan katkısının sizin kontrolünüzde olduğuna dair belge, APK dalının kaderi.

## 7. Sizden gereken bilgi veya belge

1. Telif sahibi olacak gerçek kişi veya şirket unvanı.
2. Bu kişiyi lisans vermeye yetkili kılan kısa yazılı beyan. İşveren veya müşteri payı varsa o da yazılmalı.
3. Patent başvurusu var mı, yok mu.
4. Marka veya logo tescili var mı, yok mu.
5. PR #4’te Cursor Agent tarafından yazılan satırlar için hakların sizde olduğunun kabulü.
6. Wolf-Music APK’larının bu motorun lisansının dışında kalacağının kabulü.

Bu bilgiler gelince otomatik olarak “hukuken doğrulandı” sayılmayacak. Metinler gözden geçirilecek, ancak ondan sonra kök `LICENSE` düşünülecek.

## 8. Şirket, yatırımcı ve satış açısından sonuç

Bugün bir yatırımcıya veya müşteriye “proje Apache-2.0 ile lisanslıdır” denemez. Denirse belgeyle çelişir.

Kapalı Enterprise satışı için ayrı sözleşme gerekir. O sözleşme bu depoda yoktur. Core lisansı netleşmeden “açık motor + kapalı ürün” hikâyesi eksik kalır.

Bu rapor bir değerleme veya yatırım tavsiyesi değildir.

## 9. Bundan sonra ne yapmalıyız?

1. Yukarıdaki altı maddeyi yazılı verin.
2. Bu taslak PR merge edilmeden beklesin.
3. Yetki belgesi geldikten sonra, ayrı bir adımda kök `LICENSE` ve gerçek NOTICE konuşulsun.
4. PR #4 ve PR #5 kendi halinde kalsın. Bu iş onları değiştirmedi.

İlgili dosyalar:

- `docs/LICENSE_OWNER_REPORT_TR.md` (bu dosya)
- `docs/LICENSE_TECHNICAL_AUDIT.md`
- `docs/licensing/STATUS.md`
- `docs/licensing/APACHE-2.0.OFFICIAL.txt`
- `docs/licensing/NOTICE.DRAFT.txt`
- `docs/licensing/THIRD_PARTY_NOTICES.DRAFT.txt`
