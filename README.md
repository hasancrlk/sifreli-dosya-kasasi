# 🔐 Şifreli Dosya Kasası (VaultCore)

<p align="center">
  <em>Parola Korumalı, Şifreli Dosya Saklama Servisi</em><br>
  <strong>Endüstri Standardı Kriptografik Güvenlik ile Dosya Kasası Backend'i</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-red?logo=letsencrypt" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/KDF-Argon2id-orange" alt="Argon2id">
  <img src="https://img.shields.io/badge/Database-PostgreSQL-blue?logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

---

## 🧭 Kısaca: Bu Proje Ne İşe Yarar?

Dosyalarınızı **bir parolayla şifreleyip saklayan** bir sunucu servisidir.
Yüklediğiniz dosya diske yalnızca şifreli hâlde yazılır ve parolanız hiçbir
yere kaydedilmez. Sunucunun diskini ya da veritabanını ele geçiren biri
parolayı bilmiyorsa dosyayı açamaz.

Dosyayı yüklerken iki sınır koyabilirsiniz: **kaç kez indirilebileceği**
(1 verilirse bağlantı tek kullanımlık olur) ve **kaç saat geçerli olacağı**.
Süresi dolan dosyanın şifreli verisi diskten otomatik silinir. Parola tahmin
etmeye çalışanlara karşı iki önlem var: IP başına deneme sınırı ve dosya
kilidi. Aynı dosyaya art arda yanlış parola girilirse dosya bir süre
kilitlenir.

Bu proje bir **arka uç (API)** servisidir, kullanıcı arayüzü yoktur. `curl`,
Postman ya da kendi uygulamanızla kullanılır.

**Kimin işine yarar?** Hassas bir dosyayı süreli ve tek kullanımlık bir
bağlantıyla paylaşmak isteyenlerin ve AES-GCM ile Argon2id'nin pratikte
nasıl kullanıldığını görmek isteyen geliştiricilerin.

| Siz verirsiniz | Servis size verir |
|---|---|
| Dosya + parola (en az 12 karakter) | Dosya kimliği (ID). Dosya diskte yalnızca şifreli durur |
| (İsteğe bağlı) indirme sınırı ve geçerlilik süresi | Süre ya da sınır dolunca dosyanın kendiliğinden kapanması |
| Dosya kimliği + doğru parola | Dosyanın çözülmüş, orijinal hâli |

### ⚡ 3 Adımda Kullanım

1. **Kurun ve başlatın:**
   ```bash
   cp .env.example .env      # içindeki tüm change-me değerlerini değiştirin
   docker compose up --build -d
   ```
2. **Bir dosyayı en fazla bir kez indirilebilecek şekilde yükleyin:**
   ```bash
   curl -X POST http://localhost:8000/api/v1/vault/upload \
     -H "X-API-Key: $API_KEY" \
     -F "file=@belge.pdf" -F "password=uzun-ve-guclu-parola" -F "max_downloads=1"
   ```
3. **Dönen `id` ile dosyayı indirin:**
   ```bash
   curl -X POST http://localhost:8000/api/v1/vault/download/<id> \
     -H "Content-Type: application/json" \
     -d '{"password": "uzun-ve-guclu-parola"}' --output belge.pdf
   ```
   Aynı isteği ikinci kez gönderirseniz `410 Gone` döner, çünkü bağlantı tek kullanımlıktı.

---

## 📋 İçindekiler

- [Genel Bakış](#-genel-bakış)
- [Kriptografik Mimari](#-kriptografik-mimari)
- [Tehdit Modeli (Threat Model)](#-tehdit-modeli-threat-model)
- [Neden AES-GCM?](#-neden-aes-gcm)
- [Neden KDF (Key Derivation Function)?](#-neden-kdf-key-derivation-function)
- [API Referansı](#-api-referansı)
- [Kurulum](#-kurulum)
- [Testler](#-testler)
- [Proje Yapısı](#-proje-yapısı)
- [Güvenlik Politikaları](#-güvenlik-politikaları)

---

## 🏗 Genel Bakış

VaultCore, parola korumalı bir dosya şifreleme ve depolama servisidir. Kullanıcı parolalarını hiçbir zaman saklamaz; dosyaları AES-256-GCM ile şifreler ve yalnızca şifreli versiyonlarını disk üzerinde tutar.

> ℹ️ **Zero-knowledge değildir:** Şifreleme sunucu tarafında yapılır; sunucu istek süresince parolayı ve düz metni görür. Uçtan uca (E2E) gizlilik için şifrelemenin istemcide yapılması gerekir (yol haritasında).

### Temel Özellikler

| Özellik | Açıklama |
|---------|----------|
| 🔒 **AES-256-GCM** | Authenticated Encryption with Associated Data (AEAD) |
| 🔑 **Argon2id KDF** | Bellek-yoğun anahtar türetme (GPU/ASIC dirençli) |
| 🎲 **Benzersiz Salt/Nonce** | Her dosya için `os.urandom` ile CSPRNG tabanlı üretim |
| 🚫 **Parola Saklanmaz** | Parola veritabanına yazılmaz ve loglanmaz |
| 🔐 **API Key** | Yükleme, listeleme ve silme `X-API-Key` ile korunur |
| 🧱 **Dosya Başına Kilitleme** | N hatalı denemeden sonra dosya geçici olarak kilitlenir (DB tabanlı) |
| 🧹 **Otomatik Temizlik** | Süresi dolan / tükenen / silinen dosyaların şifreli verisi diskten silinir |
| ⏱️ **Rate Limiting** | Brute-force saldırılarına karşı koruma |
| 🔗 **Tek Kullanımlık Link** | `max_downloads=1` ile one-time download desteği |
| ⏰ **Süre Sınırı** | `expires_in_hours` ile otomatik dosya süresi dolumu |
| 🐳 **Docker Ready** | PostgreSQL ile tek komutla çalışan konteyner ortamı |

---

## 🔐 Kriptografik Mimari

```
┌─────────────────────────────────────────────────────────────────┐
│                     UPLOAD (Şifreleme) Akışı                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Kullanıcı Parolası ──┐                                         │
│                       ▼                                         │
│              ┌─────────────────┐                                │
│              │   Argon2id KDF  │◄── Salt (16 byte, os.urandom)  │
│              │                 │                                │
│              │  time_cost=3    │                                │
│              │  memory=64 MB   │                                │
│              │  parallelism=4  │                                │
│              └────────┬────────┘                                │
│                       │                                         │
│                       ▼                                         │
│              256-bit Encryption Key                             │
│                       │                                         │
│                       ▼                                         │
│              ┌─────────────────┐                                │
│              │  AES-256-GCM    │◄── Nonce (12 byte, os.urandom) │
│              │  Encrypt + MAC  │                                │
│              └────────┬────────┘                                │
│                       │                                         │
│                       ▼                                         │
│         Ciphertext + 16-byte Auth Tag                           │
│                       │                                         │
│           ┌───────────┴──────────┐                              │
│           ▼                      ▼                              │
│     .enc dosyası           PostgreSQL                           │
│     (disk üzerinde)        (salt, nonce,                        │
│                            metadata)                            │
│                                                                 │
│     ⚠️  Parola ASLA saklanmaz!                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Şifreleme Detayları

| Parametre | Değer | Açıklama |
|-----------|-------|----------|
| Algoritma | AES-256-GCM | NIST onaylı AEAD şifreleme |
| Anahtar Boyutu | 256 bit (32 byte) | Brute-force'a karşı 2^256 güvenlik seviyesi |
| Nonce Boyutu | 96 bit (12 byte) | NIST SP 800-38D tavsiyesi |
| Salt Boyutu | 128 bit (16 byte) | KDF için benzersiz girdi |
| Auth Tag | 128 bit (16 byte) | Bütünlük doğrulama etiketi |
| KDF | Argon2id | RFC 9106, PHC (Password Hashing Competition) kazananı |

---

## 🛡 Tehdit Modeli (Threat Model)

### Koruma Sağlanan Saldırılar

| Saldırı Türü | Koruma Mekanizması |
|--------------|-------------------|
| **Brute-force parola** | Argon2id + IP rate limiting (Redis) + dosya başına kilitleme + min. 12 karakter parola |
| **Rainbow table** | Her dosya için benzersiz 16-byte salt |
| **Nonce reuse** | Her şifrelemede `os.urandom` ile benzersiz 12-byte nonce |
| **Ciphertext tampering** | AES-GCM authentication tag doğrulaması |
| **Timing attack** | `hmac.compare_digest` ile sabit-zamanlı karşılaştırma |
| **Information leakage** | Jenerik hata mesajları (yanlış parola vs. bozuk veri ayrımı yapılmaz) |
| **Server-side parola sızıntısı** | Parola asla saklanmaz, loglanmaz, veritabanına yazılmaz |
| **Disk üzerinde plaintext** | Dosyalar yalnızca şifreli formda (.enc) saklanır |
| **Unlimited download** | Atomik (race-free) indirme sayacı, expiration desteği |
| **Ciphertext swap** | Dosya ID'si AES-GCM associated data (AAD) olarak bağlanır |
| **KDF parametre değişimi** | Argon2 parametreleri dosya başına saklanır; ayar değişikliği eski dosyaları bozmaz |
| **Header injection** | Dosya adı temizlenir, RFC 5987 `filename*` kullanılır, MIME tipi sabit |
| **Bellek tüketimi (DoS)** | Parçalı upload okuma, KDF eşzamanlılık sınırı, event loop bloklanmaz |

### Kapsam Dışı (Out of Scope)

| Konu | Açıklama |
|------|----------|
| Transport güvenliği | TLS/HTTPS reverse proxy (nginx) arkasında çalıştırılmalıdır |
| Çok kullanıcılı yetkilendirme | Tek API key vardır; kullanıcı bazlı JWT/OAuth2 ile genişletilebilir |
| Bellekten anahtar silme | Python'da güvenilir bellek temizliği mümkün değildir |
| Anahtar yönetimi | HSM/KMS entegrasyonu üretim ortamında değerlendirilmelidir |
| Dosya silme | Soft-delete uygulanmıştır; güvenli disk silme (secure wipe) eklenmeli |

---

## ❓ Neden AES-GCM?

### AES-GCM vs Alternatifler

| Özellik | AES-GCM ✅ | AES-CBC | ChaCha20-Poly1305 |
|---------|-----------|---------|-------------------|
| Authenticated Encryption | ✅ Dahili | ❌ Ayrı MAC gerekir | ✅ Dahili |
| NIST Onayı | ✅ | ✅ | ❌ (IETF standardı) |
| Donanım Hızlandırma | ✅ AES-NI | ✅ AES-NI | ❌ (yazılım) |
| Padding Oracle Saldırısı | ✅ Bağışık | ❌ Savunmasız | ✅ Bağışık |
| Paralel İşleme | ✅ CTR mode | ❌ Sıralı | ✅ |

**AES-GCM'i seçme nedenleri:**

1. **AEAD (Authenticated Encryption with Associated Data):** Hem gizlilik hem bütünlük tek operasyonda sağlanır. CBC+HMAC gibi "encrypt-then-MAC" yaklaşımlarındaki implementasyon hatası riski ortadan kalkar.

2. **Donanım hızlandırma:** Modern CPU'lardaki AES-NI ve CLMUL komut setleri sayesinde yazılım tabanlı alternatiflere göre 3-10x daha hızlıdır.

3. **Endüstri standardı:** TLS 1.3, IPsec, SSH ve birçok kritik protokolde varsayılan şifreleme algoritmasıdır.

4. **Padding oracle bağışıklığı:** GCM, CTR (Counter) modunu kullandığı için padding kavramı yoktur; bu nedenle padding oracle saldırılarına doğası gereği bağışıktır.

> ⚠️ **Kritik Not:** AES-GCM'de nonce tekrarı (nonce reuse) felaket sonuçlar doğurur — hem gizlilik hem bütünlük kaybedilir. Bu nedenle VaultCore, her dosya için `os.urandom` ile kriptografik olarak güvenli benzersiz nonce üretir.

---

## ❓ Neden KDF (Key Derivation Function)?

### Problemi Anlayalım

Kullanıcılar genellikle düşük entropi parolalar kullanır (ör: `password123`). Bu parolaları doğrudan şifreleme anahtarı olarak kullanmak, saldırganın saniyede milyarlarca deneme yapmasına olanak tanır.

### Argon2id Çözümü

```
Parola Entropisi:  ~40 bit  (zayıf)
     │
     ▼
┌──────────────┐
│  Argon2id    │
│  KDF         │  ← 64 MB RAM × 3 iterasyon × 4 thread
│              │  ← 16-byte benzersiz salt
└──────┬───────┘
       │
       ▼
AES Anahtarı:     256 bit (güçlü)
```

| Özellik | Argon2id ✅ | PBKDF2 | bcrypt | scrypt |
|---------|-----------|--------|--------|--------|
| Bellek Direnci | ✅ Yüksek | ❌ Yok | ❌ Düşük | ✅ Orta |
| GPU Direnci | ✅ | ❌ | ⚠️ Kısmen | ✅ |
| Side-channel Direnci | ✅ (id varyantı) | ⚠️ | ⚠️ | ❌ |
| PHC Kazananı | ✅ (2015) | ❌ | ❌ | ❌ |
| RFC | RFC 9106 | RFC 8018 | - | RFC 7914 |

**Argon2id seçim nedenleri:**

1. **Memory-hardness:** Her anahtar türetme işlemi 64 MB RAM gerektirir. GPU'lar sınırlı belleğe sahip olduğundan, paralel saldırı maliyeti dramatik olarak artar.

2. **Hibrit tasarım (Argon2id):** Argon2**i** (data-independent, side-channel dirençli) ve Argon2**d** (data-dependent, GPU dirençli) varyantlarının birleşimidir.

3. **Zamanlama:** OWASP tavsiye parametreleriyle (time=3, mem=64MB, par=4) her anahtar türetme ~250ms sürer. Bu, brute-force'u saniyede 4 denemeye düşürür.

---

## 📡 API Referansı

### `POST /api/v1/vault/upload`

Dosyayı şifreler ve kasada saklar. **`X-API-Key` gerekir.** Parola en az 12 karakter olmalıdır.

**Request:** `multipart/form-data`

| Alan | Tip | Zorunlu | Açıklama |
|------|-----|---------|----------|
| `file` | File | ✅ | Şifrelenecek dosya |
| `password` | string | ✅ | Şifreleme parolası |
| `max_downloads` | int | ❌ | Maks indirme sayısı (1 = tek kullanımlık) |
| `expires_in_hours` | int | ❌ | Dosya geçerlilik süresi (saat) |

**Response: `201 Created`**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "filename": "document.pdf",
  "encrypted_size": 1048592,
  "upload_date": "2026-09-17T10:00:00+00:00",
  "message": "File encrypted and stored successfully",
  "max_downloads": 1,
  "expires_at": "2026-09-18T10:00:00+00:00"
}
```

### `POST /api/v1/vault/download/{file_id}`

Dosyayı çözer ve indirir.

**Request:** `application/json`
```json
{
  "password": "your_encryption_passphrase"
}
```

**Response:** `200 OK` — Dosya içeriği (binary stream)

**Hata Durumları:**
| Kod | Durum | Açıklama |
|-----|-------|----------|
| 401 | Unauthorized | Yanlış parola veya bozuk veri |
| 404 | Not Found | Dosya bulunamadı |
| 410 | Gone | Dosya süresi dolmuş veya indirme limiti aşılmış |
| 429 | Too Many Requests | Rate limit aşıldı veya dosya kilitli |

### `GET /api/v1/vault/files`

Kasadaki dosyaların metadata listesini döner. **`X-API-Key` gerekir.**

### `DELETE /api/v1/vault/files/{file_id}`

Kaydı pasifleştirir ve şifreli dosyayı diskten siler. **`X-API-Key` gerekir.** Yanıt: `204 No Content`

**Response: `200 OK`**
```json
{
  "files": [
    {
      "id": "a1b2c3d4-...",
      "filename": "document.pdf",
      "encrypted_size": 1048592,
      "original_size": 1048576,
      "content_type": "application/pdf",
      "upload_date": "2026-09-17T10:00:00+00:00",
      "download_count": 0,
      "max_downloads": null,
      "expires_at": null,
      "is_available": true
    }
  ],
  "total": 1
}
```

> ⚠️ Bu endpoint **asla** parola, salt, nonce veya dosya içeriği döndürmez.

---

## 🚀 Kurulum

### Docker ile (Önerilen)

```bash
# Projeyi klonla
git clone https://github.com/hasancrlk/sifreli-dosya-kasasi.git
cd sifreli-dosya-kasasi

# .env dosyasını oluştur
cp .env.example .env   # tüm change-me değerlerini değiştir

# Docker ile başlat (PostgreSQL dahil)
docker compose up --build -d

# Servisin çalıştığını doğrula
curl http://localhost:8000/health
```

### Manuel Kurulum

```bash
# Python 3.12+ gerekli
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Bağımlılıkları yükle
pip install -r requirements-dev.txt

# .env dosyasını oluştur ve PostgreSQL bağlantısını ayarla
cp .env.example .env

# Uygulamayı başlat
python -m app.main
```

### Kullanım Örnekleri (cURL)

```bash
# Dosya yükle
curl -X POST http://localhost:8000/api/v1/vault/upload \
  -H "X-API-Key: $API_KEY" \
  -F "file=@secret_document.pdf" \
  -F "password=my_strong_passphrase" \
  -F "max_downloads=3" \
  -F "expires_in_hours=24"

# Dosya indir
curl -X POST http://localhost:8000/api/v1/vault/download/{file_id} \
  -H "Content-Type: application/json" \
  -d '{"password": "my_strong_passphrase"}' \
  --output decrypted_document.pdf

# Dosya listesi
curl -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/vault/files
```

---

## 🧪 Testler

```bash
# Tüm testleri çalıştır
pytest

# Detaylı çıktı ile
pytest -v

# Yalnızca kriptografik testler
pytest tests/test_vault.py::TestEncryptDecrypt -v

# Yalnızca API testleri
pytest tests/test_vault.py::TestUploadEndpoint tests/test_vault.py::TestDownloadEndpoint -v

# Coverage raporu
pytest --cov=app --cov-report=html
```

### Test Kapsamı

| Kategori | Testler |
|----------|---------|
| **Anahtar Türetme** | Deterministik çıktı, farklı parola/salt → farklı anahtar |
| **Şifreleme/Çözme** | Roundtrip doğruluk, benzersiz salt/nonce, boş/büyük dosya |
| **Güvenlik** | Yanlış parola → `InvalidTag`, manipüle veri → `InvalidTag` |
| **API Upload** | Başarılı yükleme, boş dosya reddi, parametresiz red |
| **API Download** | Doğru parola, yanlış parola (401), olmayan dosya (404) |
| **One-Time Download** | İlk indirme → 200, ikinci indirme → 410 |
| **Dosya Listesi** | Boş liste, metadata alanları, hassas veri sızıntısı kontrolü |
| **Güvenlik Başlıkları** | X-Content-Type-Options, X-Frame-Options, HSTS |

---

## 📁 Proje Yapısı

```
sifreli-dosya-kasasi/
├── app/
│   ├── __init__.py              # Paket tanımı ve versiyon
│   ├── main.py                  # FastAPI uygulama fabrikası
│   ├── config.py                # Pydantic settings (env vars)
│   ├── database.py              # Async SQLAlchemy yapılandırması
│   ├── crypto/
│   │   ├── __init__.py
│   │   └── engine.py            # AES-256-GCM + Argon2id implementasyonu
│   ├── api/
│   │   ├── __init__.py
│   │   ├── dependencies.py      # Rate limiter ve DI bileşenleri
│   │   └── routes.py            # REST endpoint tanımları
│   ├── models/
│   │   ├── __init__.py
│   │   └── vault.py             # SQLAlchemy ORM modelleri
│   └── services/
│       ├── __init__.py
│       └── vault_service.py     # İş mantığı katmanı
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Test fixture'ları
│   └── test_vault.py            # Kapsamlı test süiti
├── encrypted_files/             # Şifreli dosya deposu (.enc)
├── Dockerfile                   # Multi-stage production build
├── docker-compose.yml           # PostgreSQL + Redis + App
├── requirements.txt             # Python bağımlılıkları
├── pyproject.toml               # Pytest yapılandırması
├── .env.example                 # Ortam değişkenleri şablonu
├── .gitignore
└── README.md                    # Bu dosya
```

---

## 🔒 Güvenlik Politikaları

### Uygulanan Güvenlik Önlemleri

1. **Parola Saklanmaz:** Sunucu parolayı veritabanına yazmaz veya loglamaz; yalnızca istek süresince anahtar türetmek için kullanır.

2. **Jenerik Hata Mesajları:** Yanlış parola ve bozuk veri arasında ayrım yapılmaz. Bu, **oracle attack** vektörünü ortadan kaldırır.

3. **Rate Limiting + Kilitleme:** İndirme IP başına dakikada 5 denemeyle sınırlıdır (çoklu worker için Redis). Ayrıca aynı dosyaya 5 hatalı denemede dosya 15 dakika kilitlenir; dağıtık saldırılara karşı da çalışır.

4. **Güvenlik Başlıkları:** Tüm yanıtlarda `X-Content-Type-Options`, `X-Frame-Options`, `HSTS`, `CSP`, `Referrer-Policy` başlıkları ayarlanır.

5. **Non-Root Container:** Docker imajı `vaultcore` kullanıcısı ile çalışır (root değil).

6. **Minimal Attack Surface:** Üretim modunda Swagger/ReDoc belgeleri devre dışıdır.

### Üretim Ortamı İçin Tavsiyeler

- [ ] TLS/HTTPS için reverse proxy (nginx/Caddy) kullanın
- [ ] `.env` içindeki tüm `change-me` değerlerini güçlü rastgele değerlerle değiştirin
- [ ] `ARGON2_MEMORY_COST` değerini sunucu kapasitesine göre artırın
- [ ] Dosya boyut limitini (`MAX_FILE_SIZE_MB`) ihtiyaca göre ayarlayın
- [ ] Log seviyesini `WARNING` olarak ayarlayın
- [ ] WAF (Web Application Firewall) kullanın
- [ ] Güvenlik denetimi (pentest) yaptırın

---

## 📄 Lisans

MIT License — Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

<p align="center">
  <sub>🛡 <em>VaultCore — Dosyalarınızı kriptografik güvence ile saklayın.</em></sub>
</p>
