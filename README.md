# Retmon-EMS-Kimlik-Dogrulamasiz-MongoDB

**CVSS 3.1 9.8 (Kritik)** · CWE-306 — Missing Authentication for Critical Function · Retmon EMS (DCT-200 Terminal)

## Genel Bakış

Retmon EMS, Retmon'un ortam izleme (Environmental Monitoring) çözümüdür; sıcaklık, nem ve benzeri çevresel değerleri izlemek amacıyla veri merkezleri, üretim tesisleri ve kritik altyapılarda kullanılır. İzleme, DCT-200 (Data Collection Terminal) adı verilen gömülü bir terminal cihazı üzerinde çalışır.

Cihaz üzerinde çalışan MongoDB veritabanı hizmeti, güvensiz varsayılan yapılandırmayla dağıtılır: tüm ağ arayüzlerine açıktır (`bindIp: 0.0.0.0`) ve kimlik doğrulaması etkinleştirilmemiştir. Ağa erişen kimliği doğrulanmamış bir kişi, veritabanı üzerinde tam okuma/yazma/yönetim denetimi elde eder. Bu, kuruma özgü bir yapılandırma hatası değil, ürünün kendi varsayılan dağıtımından kaynaklanan bir eksikliktir.

## Teknik Detay

### Kimlik doğrulaması kapalı

MongoDB hizmeti TCP/27017 portunda, kimlik doğrulaması gerektirmeden yönetim komutlarını kabul eder. Yetkisiz bir bağlantıda oturumun kimliksiz olduğu doğrulanır:

```
connectionStatus -> authInfo.authenticatedUsers: []   (ok: 1.0)
```

`authenticatedUsers` listesinin boş olması ve komutun `ok: 1.0` ile dönmesi, hizmetin kimlik doğrulaması olmadan yönetim komutlarını işlediğini gösterir.

### Güvensiz varsayılan yapılandırma

Sunucunun başlangıç yapılandırması incelendiğinde, kimlik doğrulamanın tamamen kapalı olduğu ve hizmetin tüm arayüzlere açıldığı görülür:

```
net.bindIp              : 0.0.0.0        (tüm ağ arayüzlerine açık)
security.authorization  : (tanımlı değil — kimlik doğrulama kapalı)
systemLog.path          : /dev/null      (günlükler atılıyor)
quiet                   : true
```

`security.authorization` ayarının hiç bulunmaması, MongoDB'nin kimlik doğrulamasız (varsayılan) kipte çalıştığı anlamına gelir. Ayrıca sistem günlükleri `/dev/null`'a yönlendirildiğinden, yetkisiz erişimler cihazda iz bırakmaz.

### Desteklenmeyen sürüm

Hizmet, uzun süredir desteklenmeyen (End-of-Life) MongoDB 3.0.14 sürümünü kullanır; bu sürüm kendi bilinen zafiyetlerini de barındırır.

### Erişimin doğrulanması

Kimlik doğrulaması olmadan veritabanı listesi alınabilir:

```
listDatabases -> ['local', 'admin']
```

Test sırasında yalnızca MongoDB'nin yerleşik sistem veritabanları mevcuttu. Veri gizliliğini korumak amacıyla koleksiyon/belge içeriği sorgulanmamış; yalnızca kimlik doğrulama durumu, yapılandırma, sürüm ve veritabanı listesi alınmıştır.

## Etki

Ağ üzerinden erişebilen, kimliği doğrulanmamış bir saldırgan veritabanı üzerinde tam denetim elde eder: depolanan tüm verileri okuyabilir, değiştirebilir veya silebilir; yeni (yönetici) kullanıcılar ekleyebilir; hizmeti kullanılamaz hale getirebilir ve cihazda kalıcılık oluşturabilir. Sistem günlüğü devre dışı olduğundan bu eylemler tespit edilmeden gerçekleşebilir.

Doğrulama, üretim ortamına risk vermemek amacıyla yalnızca salt-okunur olarak yapılmış; hiçbir belge okunmamış, hiçbir yazma işlemi gerçekleştirilmemiştir. Bulgular iki bağımsız yolla doğrulanmıştır: yalnızca Python standart kütüphanesini kullanan salt-okunur bir MongoDB OP_QUERY istemcisi ve nmap'in `mongodb-info`/`mongodb-databases` NSE betikleri.

## İlişkili Zayıflıklar

- CWE-306 — Missing Authentication for Critical Function (birincil)
- CWE-1188 — Insecure Default Initialization of Resource
- CWE-778 — Insufficient Logging
- CWE-1104 — Use of Unmaintained Third Party Components

## Şiddet

Kritik — CVSS 3.1 Temel Puan 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)

Saldırganın herhangi bir yetkiye veya kullanıcı etkileşimine ihtiyacı yoktur; saldırı ağ üzerinden, düşük karmaşıklıkla gerçekleştirilebilir. Yetkisiz tam veritabanı erişimi gizlilik, bütünlük ve kullanılabilirliğin tamamını yüksek seviyede etkiler.

## Etkilenen Sürümler

```
Retmon EMS (DCT-200 Terminal)

Etkilenen : 1.0.0.48
Gömülü MongoDB : 3.0.14
```

Doğrulama 1.0.0.48 üzerinde yapıldı. Güvensiz varsayılan yapılandırma ürünün ortak dağıtımından kaynaklandığından, aynı ürün ailesindeki kurulumları etkiler.

## Etkilenen Bileşen

Gömülü MongoDB hizmeti (sürüm 3.0.14, TCP/27017), kimlik doğrulaması olmadan ve `bindIp: 0.0.0.0` ile tüm arayüzlere açık olarak çalışır.

## Çözüm

1. MongoDB'de kimlik doğrulaması etkinleştirilmelidir (`security.authorization: enabled`).
2. `bindIp` yalnızca localhost/yönetim arayüzü ile sınırlandırılmalı; hizmet gereksizse dışarıya kapatılmalıdır.
3. Sistem günlüğü anlamlı bir hedefe yönlendirilmeli (`/dev/null` yerine); erişimler kayıt altına alınmalıdır.
4. Desteklenen güncel bir MongoDB sürümüne yükseltme yapılmalıdır.

## Bulan

Alkım Coşkun — Netlore Security
