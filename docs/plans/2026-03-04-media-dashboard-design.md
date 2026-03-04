# Media Dashboard Design (Mode 3)

## Context

Dashboard saat ini belum punya jalur presentasi media end-to-end. Thread UI hanya merender teks, sementara payload backend belum menormalisasi metadata media untuk kebutuhan render, proxy, dan cache.

Dokumen ini mengunci desain untuk scope berikut:

- **Display full media** di dashboard (image, video, audio, sticker, document)
- **Preview via backend proxy + disk cache (TTL)**
- **Send media** dari dashboard
- **Sticker input: WEBP-only** (tanpa auto-conversion)

## Goals

1. Media incoming/outgoing tampil konsisten di thread dashboard.
2. Preview media tetap stabil walau URL WA langsung expired.
3. Pengiriman media dari dashboard tersedia untuk tipe utama.
4. Perubahan tetap YAGNI: tidak menambah kompleksitas yang belum dibutuhkan.

## Non-Goals

- Konversi sticker dari JPG/PNG/MP4 (ditunda, WEBP-only).
- Prefetch semua media secara agresif saat message masuk.
- Fitur editor media/thumbnail generator lanjutan.

---

## Chosen Architecture

Dipilih pendekatan **Unified proxy cache**:

- Frontend merender media melalui endpoint backend (`/api/media/<message_id>`), bukan URL WA mentah.
- Backend melakukan **lazy download + decrypt + disk cache** saat media pertama kali diminta.
- Request berikutnya dilayani dari cache selama belum lewat TTL dan budget ukuran.

Alasan:

- Lebih tahan terhadap URL expired/CORS dibanding direct-url first.
- Lebih hemat bandwidth/disk dibanding prefetch-all.
- Kompleksitas tetap terkontrol untuk kebutuhan saat ini.

---

## Backend Design

### 1) Message normalization in runtime

Saat incoming message diproses, runtime menyimpan message row yang diperkaya metadata media:

- `media.kind`: `image | video | audio | sticker | document | null`
- `media.mimetype`
- `media.caption`
- `media.seconds`
- `media.width`, `media.height`
- `media.file_name`
- `media.is_animated`
- `media.preview_url` (internal dashboard URL)
- `media.is_available` (bool)

Selain itu, runtime menyimpan metadata decrypt internal (tidak diekspor ke UI):

- `url`
- `direct_path`
- `media_key_b64`
- `media_type`

### 2) Parser enrichment

Parser payload media perlu mengekstrak field `mediaKey` (base64) dan metadata yang sudah tersedia (`url`, `mimetype`, `direct_path`, caption/dimensi/durasi).

Decoder yang disentuh:

- image
- document
- audio
- video
- sticker

### 3) Media cache store (disk + TTL)

Tambahkan komponen cache lokal untuk hasil decrypt media:

- Path default: `.cache/dashboard-media/` (configurable via env)
- Index metadata (JSON): message_id, mime, file path, size, created_at, expires_at, last_access
- Eviction:
  - TTL expiry
  - Size budget overflow (LRU-like by `last_access`)

Konfigurasi env yang disarankan:

- `WATON_DASHBOARD_MEDIA_CACHE_DIR`
- `WATON_DASHBOARD_MEDIA_CACHE_TTL_SECONDS` (default 86400)
- `WATON_DASHBOARD_MEDIA_CACHE_MAX_BYTES` (default konservatif)

### 4) Media proxy service

Endpoint `GET /api/media/<message_id>`:

1. Lookup message + decrypt metadata internal.
2. Jika cache hit dan valid TTL -> stream file cache.
3. Jika miss -> download encrypted bytes, decrypt via `MediaManager`, write cache, stream response.
4. Set `Content-Type` dari mimetype terbaik yang tersedia.

Error contract:

- `404`: message id tidak ditemukan
- `409`: metadata media/decrypt tidak cukup
- `502`: fetch/decrypt upstream gagal

### 5) Send media API

Endpoint baru: `POST /api/send/media` (multipart form-data)

Input:

- `to` (required)
- `kind` in `{image, video, audio, document, sticker}`
- `file` (required)
- optional `caption` (image/video/document)
- optional `mimetype`
- optional `file_name` (document)

Dispatch ke `MessagesAPI`:

- `send_image`
- `send_video`
- `send_audio`
- `send_document`
- `send_sticker`

Kebijakan sticker:

- hanya `.webp`
- validasi extension + signature dasar

---

## Frontend Design

### 1) Thread renderer

`renderThread()` diubah dari text-only menjadi conditional renderer:

- image/sticker -> `<img loading="lazy">`
- video -> `<video controls preload="metadata">`
- audio -> `<audio controls>`
- document -> card + tombol open/download
- text/caption -> tetap dirender sebagai teks bubble

Jika media gagal dimuat, tampil fallback bubble dengan status yang jelas.

### 2) Composer media UX

Aktifkan attach di composer:

- Pilihan tipe: image, video, audio, document, sticker
- File picker sesuai tipe
- Caption opsional untuk image/video/document
- Upload state: disable tombol + indikator progress sederhana

Sesudah sukses:

- refresh chat list
- refresh active thread

### 3) Styling

Tambahkan kelas CSS baru untuk:

- media container dalam bubble
- ukuran sticker
- document tile
- error state media

Layout utama dashboard tetap dipertahankan.

---

## Data Flow

### Incoming media flow

1. Node message diterima runtime.
2. `process_incoming_message` parse payload media.
3. Runtime normalisasi message + media descriptor.
4. Message disimpan ke in-memory chat buffer.
5. Frontend render thread; saat media element butuh source, hit `/api/media/<message_id>`.
6. Backend proxy melayani dari cache atau fetch+decrypt+cache.

### Outgoing media flow

1. User pilih file dari composer.
2. Frontend kirim multipart ke `/api/send/media`.
3. Backend validasi + dispatch ke `MessagesAPI` sesuai kind.
4. Runtime append outgoing row dengan descriptor media.
5. Thread update menampilkan media yang baru dikirim.

---

## Error Handling & Security Boundaries

- Jangan expose `media_key` ke frontend.
- Endpoint media berbasis `message_id`, bukan path arbitrary.
- Validasi `kind` dan ukuran file upload.
- Sanitasi nama file untuk document response headers.
- Fallback UI wajib untuk metadata tidak lengkap/decrypt gagal.
- Logging error cukup informatif tanpa membocorkan material sensitif.

---

## Testing Plan

## Unit tests

1. `message_content` decoders mengekstrak `media_key_b64` + metadata tiap media type.
2. Runtime normalizer menghasilkan `media` descriptor yang konsisten.
3. Cache store:
   - hit/miss
   - TTL expiry
   - max-bytes pruning
4. API `/api/media/<id>`:
   - 200 hit
   - 404 unknown message
   - 409 missing decrypt metadata
   - 502 decrypt/fetch failure
5. API `/api/send/media`:
   - validation errors
   - method dispatch sesuai kind
   - sticker webp-only enforcement

## Dashboard API regression

Perbarui `tests/unit/test_dashboard.py` agar endpoint message tetap backward-compatible untuk text-only dan mulai mencakup row yang memiliki `media`.

---

## Rollout Plan

1. Implement parser enrichment + runtime normalization.
2. Implement media proxy + disk cache + env config.
3. Implement send media endpoint.
4. Update frontend thread render + composer attach flow.
5. Tambahkan/upgrade unit test dashboard/media.
6. Verifikasi manual E2E:
   - incoming image/video/audio/document/sticker
   - outgoing image/video/audio/document/sticker(webp)
   - cache hit setelah reload dashboard

---

## Implementation Notes

- Keep changes scoped to dashboard/media surface; hindari refactor global yang tidak diminta.
- Prioritaskan reliability path (`display + proxy`) sebelum polish UI tambahan.
- Jika metadata decrypt tertentu tidak tersedia dari payload tertentu, tetap tampilkan fallback text dan status, jangan blok thread rendering.